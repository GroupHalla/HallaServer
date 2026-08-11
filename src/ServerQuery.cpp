#include "ServerQuery.h"
#include "ServerCore.h"
#include "ClientSession.h"
#include "PasswordHash.h"

#include <QTcpServer>
#include <QTcpSocket>
#include <QSslSocket>
#include <QSslError>
#include <QCryptographicHash>
#include <openssl/crypto.h>
#include <QRandomGenerator>
#include <QDateTime>
#include <QStringList>


namespace {
class QueryTlsServer final : public QTcpServer {
public:
    QueryTlsServer(const QSslCertificate& certificate, const QSslKey& privateKey, QObject* parent)
        : QTcpServer(parent), m_certificate(certificate), m_privateKey(privateKey) {}
protected:
    void incomingConnection(qintptr descriptor) override {
        auto* socket = new QSslSocket(this);
        if (!socket->setSocketDescriptor(descriptor)) { socket->deleteLater(); return; }
        socket->setLocalCertificate(m_certificate);
        socket->setPrivateKey(m_privateKey);
        socket->startServerEncryption();
        addPendingConnection(socket);
    }
private:
    QSslCertificate m_certificate;
    QSslKey m_privateKey;
};
}

ServerQuery::ServerQuery(ServerCore* core, QObject* parent)
    : QObject(parent), m_core(core) {}

void ServerQuery::setCredentials(const QString& user, const QString& pass) {
    if (!user.isEmpty()) m_user = user;
    if (!pass.isEmpty())
        m_passHash = PasswordHash::isEncoded(pass) ? pass : PasswordHash::create(pass);
}

void ServerQuery::setTlsConfiguration(const QSslCertificate& certificate, const QSslKey& privateKey) {
    m_certificate = certificate;
    m_privateKey = privateKey;
}

bool ServerQuery::start(quint16 port, const QHostAddress& bindAddress) {
    if (port == 0) return true;
    if (m_certificate.isNull() || m_privateKey.isNull()) return false;

    if (m_passHash.isEmpty()) {
        const QString chars = QStringLiteral("abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#%+=");
        for (int i = 0; i < 24; ++i)
            m_generatedPlaintext += chars.at(int(QRandomGenerator::system()->bounded(chars.size())));
        m_passHash = PasswordHash::create(m_generatedPlaintext);
        if (m_passHash.isEmpty()) return false;
        m_passGenerated = true;
    }

    m_srv = new QueryTlsServer(m_certificate, m_privateKey, this);
    connect(m_srv, &QTcpServer::newConnection, this, &ServerQuery::onNew);
    if (!m_srv->listen(bindAddress, port)) {
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
        if (m_bufs.size() >= 32) {
            s->disconnectFromHost();
            s->deleteLater();
            continue;
        }
        m_bufs.insert(s, {});
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
    static constexpr int kMaxBuffer = 64 * 1024;
    static constexpr int kMaxLine = 8 * 1024;
    QByteArray& buf = m_bufs[s];
    buf += s->readAll();
    if (buf.size() > kMaxBuffer) {
        error(s, 256, QStringLiteral("buffer excede 64 KiB"));
        s->disconnectFromHost();
        return;
    }
    int idx;
    while ((idx = buf.indexOf('\n')) >= 0) {
        QByteArray line = buf.left(idx);
        buf.remove(0, idx + 1);
        if (line.size() > kMaxLine) {
            error(s, 256, QStringLiteral("linha excede 8 KiB"));
            s->disconnectFromHost();
            return;
        }
        if (line.endsWith('\r')) line.chop(1);
        handleLine(s, QString::fromUtf8(line).trimmed());
        if (!s->isOpen()) { m_bufs.remove(s); return; }
    }
}

bool ServerQuery::allowLoginAttempt(QTcpSocket* s) {
    const QString ip = s->peerAddress().toString();
    QList<qint64>& attempts = m_loginAttemptsByIp[ip];
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    for (int i = attempts.size() - 1; i >= 0; --i)
        if (now - attempts[i] > 60'000) attempts.removeAt(i);
    if (attempts.size() >= 5) return false;
    attempts << now;
    return true;
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
            // Pilar 1: Hierarquia de Cargos (Position)
            "  servergroupsetposition sgid=<id> position=<n>  -- Define position hierarquica do grupo",
            "  channelgroupsetpositionreq cid=<id> gid=<id> min_position=<n>  -- Requisito de position por canal",
            // Pilar 3: Overrides de Canal (Allow/Deny/Inherit)
            "  channelgroupsetperm cid=<id> gid=<id> perm=<chave> state=<1|0|-1>",
            "     state: 1=Allow (permitir), 0=Deny (negar), -1=Inherit (herdar)",
            "  channelpermlist cid=<id>  -- Lista permissoes de canal",
            nullptr
        };
        for (int i = 0; lines[i]; ++i) sendLine(s, escape(QString::fromUtf8(lines[i])));
        ok(s);
        return;
    }
    if (cmd == "login") {
        if (!allowLoginAttempt(s)) {
            error(s, 1539, QStringLiteral("muitas tentativas; aguarde 60 segundos"));
            s->disconnectFromHost();
            return;
        }
        const QByteArray suppliedUser = QCryptographicHash::hash(
            args.value(QStringLiteral("client_login_name")).toUtf8(), QCryptographicHash::Sha256);
        const QByteArray expectedUser = QCryptographicHash::hash(m_user.toUtf8(), QCryptographicHash::Sha256);
        const bool userMatches = suppliedUser.size() == expectedUser.size()
            && CRYPTO_memcmp(suppliedUser.constData(), expectedUser.constData(), size_t(expectedUser.size())) == 0;
        const bool matches = userMatches && PasswordHash::verify(
            args.value(QStringLiteral("client_login_password")), m_passHash);
        if (matches) {
            m_loginAttemptsByIp.remove(s->peerAddress().toString());
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
        cmd == "bandel" || cmd == "gm" ||
        cmd == "servergroupsetposition" || cmd == "channelgroupsetpositionreq" ||
        cmd == "channelgroupsetperm" || cmd == "channelpermlist") {
        // toda a lógica destes comandos vive em ServerCore (friend)
        core->queryCommand(s, cmd, args, [this](QTcpSocket* ss) { ok(ss); },
                           [this](QTcpSocket* ss, int id, const QString& msg) { error(ss, id, msg); });
        return;
    }

    error(s, 256, QStringLiteral("comando desconhecido (digite help)"));
}
