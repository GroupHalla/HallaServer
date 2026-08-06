#include "ServerQuery.h"
#include "ServerCore.h"
#include "ClientSession.h"

#include <QTcpServer>
#include <QTcpSocket>
#include <QRandomGenerator>
#include <QDateTime>
#include <QStringList>

ServerQuery::ServerQuery(ServerCore* core, QObject* parent)
    : QObject(parent), m_core(core) {}

void ServerQuery::setCredentials(const QString& user, const QString& pass) {
    if (!user.isEmpty()) m_user = user;
    if (!pass.isEmpty()) m_pass = pass;
}

bool ServerQuery::start(quint16 port) {
    if (port == 0) return true; // desligado

    if (m_pass.isEmpty()) {
        // estilo Halla: primeira execução gera uma senha e a mostra no log
        const QString chars = QStringLiteral("abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789");
        QString pw;
        for (int i = 0; i < 12; ++i)
            pw += chars.at(int(QRandomGenerator::global()->bounded(chars.size())));
        m_pass = pw;
        m_passGenerated = true;
    }

    m_srv = new QTcpServer(this);
    connect(m_srv, &QTcpServer::newConnection, this, &ServerQuery::onNew);
    if (!m_srv->listen(QHostAddress::Any, port)) {
        delete m_srv;
        m_srv = nullptr;
        return false;
    }
    return true;
}

// ------------------------------------------------------------------- utilidades
QString ServerQuery::escape(const QString& v) {
    QString r = v;
    r.replace(QLatin1Char('\\'), QStringLiteral("\\\\"));
    r.replace(QLatin1Char(' '),  QStringLiteral("\\s"));
    r.replace(QLatin1Char('|'),  QStringLiteral("\\p"));
    r.replace(QLatin1Char('/'),  QStringLiteral("\\/"));
    r.replace(QLatin1Char('\n'), QStringLiteral("\\n"));
    r.replace(QLatin1Char('\r'), QStringLiteral("\\r"));
    return r;
}

QString ServerQuery::unescape(const QString& v) {
    QString r;
    r.reserve(v.size());
    for (int i = 0; i < v.size(); ++i) {
        if (v[i] == QLatin1Char('\\') && i + 1 < v.size()) {
            const QChar c = v[++i];
            if (c == QLatin1Char('s')) r += QLatin1Char(' ');
            else if (c == QLatin1Char('p')) r += QLatin1Char('|');
            else if (c == QLatin1Char('n')) r += QLatin1Char('\n');
            else if (c == QLatin1Char('r')) r += QLatin1Char('\r');
            else if (c == QLatin1Char('/')) r += QLatin1Char('/');
            else if (c == QLatin1Char('\\')) r += QLatin1Char('\\');
            else { r += QLatin1Char('\\'); r += c; }
        } else r += v[i];
    }
    return r;
}

QMap<QString, QString> ServerQuery::parseArgs(const QString& rest) {
    QMap<QString, QString> out;
    for (const QString& tok : rest.split(QLatin1Char(' '), Qt::SkipEmptyParts)) {
        const int eq = tok.indexOf(QLatin1Char('='));
        if (eq > 0) out[tok.left(eq)] = unescape(tok.mid(eq + 1));
        else out[unescape(tok)] = QString(); // flag sem valor
    }
    return out;
}

void ServerQuery::sendLine(QTcpSocket* s, const QString& line) {
    s->write(line.toUtf8() + "\n\r");
}

void ServerQuery::ok(QTcpSocket* s) {
    sendLine(s, QStringLiteral("error id=0 msg=ok"));
}

void ServerQuery::error(QTcpSocket* s, int id, const QString& msg) {
    sendLine(s, QStringLiteral("error id=%1 msg=%2").arg(id).arg(escape(msg)));
}

// ------------------------------------------------------------------- conexão
void ServerQuery::onNew() {
    while (m_srv->hasPendingConnections()) {
        QTcpSocket* s = m_srv->nextPendingConnection();
        connect(s, &QTcpSocket::readyRead, this, [this, s] { onRead(s); });
        connect(s, &QTcpSocket::disconnected, this, [this, s] {
            m_authed.remove(s);
            m_bufs.remove(s);
        });
        connect(s, &QTcpSocket::disconnected, s, &QObject::deleteLater);
        sendLine(s, QStringLiteral("Halla Server Query v%1").arg(m_core->version()));
        sendLine(s, QStringLiteral("identifique-se com 'login client_login_name=<usuario> client_login_password=<senha>'"));
        sendLine(s, QStringLiteral("digite 'help' para ver os comandos"));
    }
}

void ServerQuery::onRead(QTcpSocket* s) {
    QByteArray& buf = m_bufs[s];
    buf += s->readAll();
    int idx;
    while ((idx = buf.indexOf('\n')) >= 0) {
        QByteArray line = buf.left(idx);
        buf.remove(0, idx + 1);
        if (line.endsWith('\r')) line.chop(1);
        handleLine(s, QString::fromUtf8(line).trimmed());
        if (!s->isOpen()) { m_bufs.remove(s); return; }
    }
}

bool ServerQuery::needAuth(QTcpSocket* s, const QString& cmd) {
    static const QSet<QString> open = { QStringLiteral("login"), QStringLiteral("quit"),
                                        QStringLiteral("exit"), QStringLiteral("help"),
                                        QStringLiteral("version") };
    if (open.contains(cmd)) return false;
    if (m_authed.contains(s)) return false;
    error(s, 2568, QStringLiteral("Voce precisa se identificar primeiro (login)"));
    return true;
}

void ServerQuery::handleLine(QTcpSocket* s, const QString& line) {
    if (line.isEmpty()) return;
    const int sp = line.indexOf(QLatin1Char(' '));
    const QString cmd = (sp < 0 ? line : line.left(sp)).toLower();
    const QString rest = sp < 0 ? QString() : line.mid(sp + 1);

    if (needAuth(s, cmd)) return;
    handleArgs(s, cmd, parseArgs(rest));
}

void ServerQuery::handleArgs(QTcpSocket* s, const QString& cmd,
                             const QMap<QString, QString>& args) {
    ServerCore* core = m_core;

    if (cmd == "quit" || cmd == "exit") {
        sendLine(s, QStringLiteral("error id=0 msg=ok"));
        s->disconnectFromHost();
        return;
    }
    if (cmd == "version") {
        sendLine(s, QStringLiteral("version=%1 platform=%2 build=Halla"
                                   ).arg(core->version(), core->platform()));
        ok(s);
        return;
    }
    if (cmd == "help") {
        const char* lines[] = {
            "comandos disponiveis:",
            "  login client_login_name=<u> client_login_password=<p>",
            "  logout | quit | version | serverinfo | voicestats",
            "  clientlist | channellist | gm msg=<texto>",
            "  clientkick clid=<id> reasonmsg=<texto>",
            "  banclient clid=<id> time=<min> reasonmsg=<texto>",
            "  banadd uid=<uid> time=<min> banreason=<texto>",
            "  banlist | bandel banid=<uid>",
            nullptr
        };
        for (int i = 0; lines[i]; ++i) sendLine(s, escape(QString::fromUtf8(lines[i])));
        ok(s);
        return;
    }
    if (cmd == "login") {
        const QString u = args.value(QStringLiteral("client_login_name"));
        const QString p = args.value(QStringLiteral("client_login_password"));
        if (u == m_user && p == m_pass) {
            m_authed << s;
            ok(s);
        } else {
            error(s, 1538, QStringLiteral("invalid loginname or password"));
        }
        return;
    }
    if (cmd == "logout") { m_authed.remove(s); ok(s); return; }
    if (cmd == "use") { ok(s); return; } // um único servidor virtual por enquanto

    if (cmd == "serverinfo") {
        int chans = 0, clients = 0;
        core->queryCounts(chans, clients);
        sendLine(s, QStringLiteral(
            "virtualserver_name=%1 virtualserver_port=%2 virtualserver_status=online "
            "virtualserver_clientsonline=%3 virtualserver_maxclients=%4 "
            "virtualserver_channelsonline=%5 virtualserver_version=%6 "
            "virtualserver_motd=%7")
            .arg(escape(core->serverName()))
            .arg(core->port())
            .arg(clients)
            .arg(core->maxClients())
            .arg(chans)
            .arg(core->version())
            .arg(escape(core->motd())));
        ok(s);
        return;
    }
    if (cmd == "voicestats") {
        const QJsonObject v = core->voiceStats();
        sendLine(s, QStringLiteral("voice_udp_in=%1 voice_opus_frames_in=%2 voice_opus_bytes_in=%3 "
                                   "voice_udp_out=%4 voice_opus_bytes_out=%5 voice_invalid=%6 "
                                   "voice_unknown_token=%7 voice_send_errors=%8")
            .arg(v["udpIn"].toVariant().toLongLong())
            .arg(v["opusFramesIn"].toVariant().toLongLong())
            .arg(v["opusBytesIn"].toVariant().toLongLong())
            .arg(v["udpOut"].toVariant().toLongLong())
            .arg(v["opusBytesOut"].toVariant().toLongLong())
            .arg(v["invalid"].toVariant().toLongLong())
            .arg(v["unknownToken"].toVariant().toLongLong())
            .arg(v["sendErrors"].toVariant().toLongLong()));
        ok(s);
        return;
    }

    if (cmd == "clientlist" || cmd == "channellist" || cmd == "banlist" ||
        cmd == "clientkick" || cmd == "banclient" || cmd == "banadd" ||
        cmd == "bandel" || cmd == "gm") {
        // toda a lógica destes comandos vive em ServerCore (friend)
        core->queryCommand(s, cmd, args, [this](QTcpSocket* ss) { ok(ss); },
                           [this](QTcpSocket* ss, int id, const QString& msg) { error(ss, id, msg); });
        return;
    }

    error(s, 256, QStringLiteral("comando desconhecido (digite help)"));
}
