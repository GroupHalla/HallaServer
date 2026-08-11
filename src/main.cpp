#include <QCoreApplication>
#include <QCommandLineParser>
#include <QSettings>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QTimer>
#include <QJsonArray>
#include <QJsonObject>
#include <QHostAddress>
#include <QTextStream>
#include <csignal>
#include "ServerCore.h"
#include "ServerQuery.h"
#include "Version.h"

// Halla Server — servidor de voz/chat hospedável, compatível com o cliente Halla.
// Uso:  halla-server [--config halla-server.ini] [--port 9987]

static QCoreApplication* g_app = nullptr;
static void handleSignal(int) { if (g_app) g_app->quit(); }

int main(int argc, char* argv[]) {
    QCoreApplication app(argc, argv);
    g_app = &app;
    QCoreApplication::setApplicationName("Halla Server");
    QCoreApplication::setApplicationVersion(QStringLiteral(HALLA_SERVER_VERSION));

    QCommandLineParser parser;
    parser.setApplicationDescription(
        "Servidor de voz e chat Halla (protocolo aberto — ver PROTOCOL.md).\n"
        "Hospede seu próprio servidor e conecte-se com o cliente Halla.");
    parser.addHelpOption();
    parser.addVersionOption();
    QCommandLineOption configOpt(QStringList() << "c" << "config",
                                 "Arquivo de configuração INI", "arquivo", "halla-server.ini");
    QCommandLineOption portOpt(QStringList() << "p" << "port",
                               "Porta de controle/voz (TCP/UDP)", "porta");
    QCommandLineOption nameOpt(QStringList() << "n" << "name", "Nome do servidor", "nome");
    QCommandLineOption passOpt(QStringList() << "password", "Senha do servidor", "senha");
    QCommandLineOption maxOpt(QStringList() << "max", "Máximo de clientes (slots)", "n");
    parser.addOption(configOpt);
    parser.addOption(portOpt);
    parser.addOption(nameOpt);
    parser.addOption(passOpt);
    parser.addOption(maxOpt);
    parser.process(app);

    // localização do config: ao lado do executável ou o passado por parâmetro
    QString configPath = parser.value(configOpt);
    if (configPath.isEmpty() || !QFile::exists(configPath))
        configPath = QCoreApplication::applicationDirPath() + "/halla-server.ini";

    QSettings cfg(configPath, QSettings::IniFormat);
#ifndef Q_OS_WIN
    QFile::setPermissions(configPath, QFileDevice::ReadOwner | QFileDevice::WriteOwner);
#endif
    cfg.beginGroup("server");

    const quint16 port = parser.isSet(portOpt)
            ? quint16(parser.value(portOpt).toUShort())
            : quint16(cfg.value("port", 9987).toUInt());
    const QString name = parser.isSet(nameOpt)
            ? parser.value(nameOpt)
            : cfg.value("name", "Servidor Halla").toString();
    const QString motd = cfg.value("motd", "Bem-vindo ao servidor Halla!").toString();
    const int parsedMax = parser.isSet(maxOpt) ? parser.value(maxOpt).toInt() : 0;
    const int maxClients = (parsedMax <= 0) ? cfg.value("maxClients", 32).toInt() : parsedMax;
    QString password = parser.isSet(passOpt)
            ? parser.value(passOpt)
            : cfg.value("password", "").toString();
    QString adminPassword = cfg.value("adminPassword", "").toString();
    if (qEnvironmentVariableIsSet("HALLA_SERVER_PASSWORD"))
        password = qEnvironmentVariable("HALLA_SERVER_PASSWORD");
    if (qEnvironmentVariableIsSet("HALLA_ADMIN_PASSWORD"))
        adminPassword = qEnvironmentVariable("HALLA_ADMIN_PASSWORD");
    QStringList privKeys = cfg.value("privilegeKeys").toStringList();
    for (QString& k : privKeys) k = k.trimmed();
    privKeys.removeAll(QString());
    const bool privKeyReuse = cfg.value("privilegeKeyReuse", false).toBool();
    const bool allowScreenShare = cfg.value("allowScreenShare", false).toBool();
    const int ssWidth = cfg.value("screenshareWidth", 800).toInt();
    const int ssHeight = cfg.value("screenshareHeight", 450).toInt();
    const int ssFps = cfg.value("screenshareFps", 20).toInt();
    const QString certFile = cfg.value("certFile", "").toString();
    const QString keyFile = cfg.value("keyFile", "").toString();
    cfg.endGroup();

    cfg.beginGroup("database");
    const QString dbType = cfg.value("type", "sqlite").toString().toLower();
    const QString dbHost = cfg.value("host", "localhost").toString();
    const int dbPort = cfg.value("port", 3306).toInt();
    const QString dbName = cfg.value("name", "halla_db").toString();
    const QString dbUser = cfg.value("user", "root").toString();
    QString dbPassword = cfg.value("password", "").toString();
    if (qEnvironmentVariableIsSet("HALLA_DATABASE_PASSWORD"))
        dbPassword = qEnvironmentVariable("HALLA_DATABASE_PASSWORD");
    cfg.endGroup();

    cfg.beginGroup("webrtc");
    QStringList stunUrls = cfg.value("stunUrls", QStringLiteral("stun:stun.l.google.com:19302")).toStringList();
    QString turnUrl = cfg.value("turnUrl").toString().trimmed();
    QString turnUsername = cfg.value("turnUsername").toString();
    QString turnPassword = cfg.value("turnPassword").toString();
    cfg.endGroup();
    if (qEnvironmentVariableIsSet("HALLA_TURN_URL")) turnUrl = qEnvironmentVariable("HALLA_TURN_URL").trimmed();
    if (qEnvironmentVariableIsSet("HALLA_TURN_USERNAME")) turnUsername = qEnvironmentVariable("HALLA_TURN_USERNAME");
    if (qEnvironmentVariableIsSet("HALLA_TURN_PASSWORD")) turnPassword = qEnvironmentVariable("HALLA_TURN_PASSWORD");
    QJsonArray iceServers;
    for (const QString& url : stunUrls) {
        if (!url.trimmed().isEmpty()) iceServers.append(QJsonObject{{"urls", url.trimmed()}});
    }
    if (!turnUrl.isEmpty()) {
        iceServers.append(QJsonObject{{"urls", turnUrl}, {"username", turnUsername},
                                      {"credential", turnPassword}});
    }

    const QString dir = QFileInfo(configPath).absolutePath();
    if (adminPassword.compare(QStringLiteral("troque-esta-senha"), Qt::CaseInsensitive) == 0
        || adminPassword.compare(QStringLiteral("changeme"), Qt::CaseInsensitive) == 0) {
        QTextStream(stderr) << "FALHA: adminPassword usa um placeholder inseguro. Configure HALLA_ADMIN_PASSWORD ou deixe vazio." << Qt::endl;
        return 2;
    }

    ServerCore core;
    core.setServerName(name);
    core.setMotd(motd);
    core.setMaxClients(maxClients);
    core.setPassword(password);
    core.setAdminPassword(adminPassword);
    core.setPrivilegeKeys(privKeys);
    core.setPrivilegeKeyReuse(privKeyReuse);
    core.setAllowScreenShare(allowScreenShare);
    core.setScreenshareWidth(ssWidth);
    core.setScreenshareHeight(ssHeight);
    core.setScreenshareFps(ssFps);
    core.setWebRtcIceServers(iceServers);
    if (!certFile.trimmed().isEmpty()) core.setCertificateFile(QFileInfo(certFile).isRelative() ? dir + "/" + certFile : certFile);
    if (!keyFile.trimmed().isEmpty()) core.setPrivateKeyFile(QFileInfo(keyFile).isRelative() ? dir + "/" + keyFile : keyFile);
    core.setVersion(QStringLiteral(HALLA_SERVER_VERSION));
    core.setDataFile(dir + "/halla-data.json");
    core.setBanFile(dir + "/halla-bans.json");
    core.setDatabaseFile(dir + "/halla-data.db");
    core.setDatabaseType(dbType);
    core.setDatabaseHost(dbHost);
    core.setDatabasePort(dbPort);
    core.setDatabaseName(dbName);
    core.setDatabaseUser(dbUser);
    core.setDatabasePassword(dbPassword);

    QTextStream out(stdout);
    QObject::connect(&core, &ServerCore::logLine, &app,
                     [&out](const QString& line) { out << line << Qt::endl; });

    std::signal(SIGINT, handleSignal);
    std::signal(SIGTERM, handleSignal);

    if (!core.start(port, port)) return 1;

    // ---- ServerQuery (administração remota em texto, estilo Halla)
    cfg.beginGroup("query");
    const quint16 queryPort = quint16(cfg.value("port", 0).toUInt());
    const QHostAddress queryBind(cfg.value("bind", "127.0.0.1").toString());
    const QString queryUser = cfg.value("user", "serveradmin").toString();
    QString queryPass = cfg.value("password", "").toString();
    cfg.endGroup();
    if (qEnvironmentVariableIsSet("HALLA_QUERY_PASSWORD"))
        queryPass = qEnvironmentVariable("HALLA_QUERY_PASSWORD");
    if (queryPass.isEmpty()) queryPass = core.queryPassword();

    if (queryPort > 0) {
        ServerQuery* query = new ServerQuery(&core, &app);
        query->setCredentials(queryUser, queryPass);
        query->setTlsConfiguration(core.tlsCertificate(), core.tlsPrivateKey());
        if (query->start(queryPort, queryBind.isNull() ? QHostAddress::LocalHost : queryBind)) {
            out << QStringLiteral("ServerQuery TLS escutando em %1:%2 (usuário: %3)\n")
                       .arg(queryBind.toString()).arg(queryPort).arg(queryUser);
            const QString generatedPass = query->generatedPassword();
            if (core.queryPassword() != query->passwordHashForStorage())
                core.setQueryPassword(query->passwordHashForStorage());
            if (!generatedPass.isEmpty()) {
                out << QStringLiteral("=====================================================\n"
                                      "  SENHA DO SERVERQUERY (mostrada uma única vez): %1\n"
                                      "  Somente o hash PBKDF2 fica persistido.\n"
                                      "=====================================================\n")
                           .arg(generatedPass);
            }
        } else {
            out << QStringLiteral("FALHA: ServerQuery não pôde escutar na porta %1\n")
                       .arg(queryPort);
        }
    }

    out.flush();
    return app.exec();
}
