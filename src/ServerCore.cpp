#include "ServerCore.h"
#include "ClientSession.h"
#include "VoiceRelay.h"
#include "HallaProtocol.h"
#include "PasswordHash.h"

#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonArray>
#include <QDateTime>
#include <QDir>
#include <QCryptographicHash>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlError>
#include <QRandomGenerator>
#include <QSslSocket>
#include <QSslKey>
#include <QSslCertificate>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <QProcess>
#include <algorithm>

class SslServer : public QTcpServer {
public:
    explicit SslServer(QObject* parent = nullptr) : QTcpServer(parent) {}
    
    void setSslConfig(const QSslCertificate& cert, const QSslKey& key) {
        m_cert = cert;
        m_key = key;
    }

protected:
    void incomingConnection(qintptr socketDescriptor) override {
        QSslSocket* socket = new QSslSocket(this);
        if (socket->setSocketDescriptor(socketDescriptor)) {
            socket->setLocalCertificate(m_cert);
            socket->setPrivateKey(m_key);
            socket->startServerEncryption();
            addPendingConnection(socket);
        } else {
            delete socket;
        }
    }

private:
    QSslCertificate m_cert;
    QSslKey m_key;
};

static QString uidForIdentityPublicKey(const QByteArray& publicDer) {
    return QString::fromLatin1(QCryptographicHash::hash(publicDer, QCryptographicHash::Sha256).toBase64());
}

static bool verifyIdentitySignature(const QByteArray& publicDer, const QByteArray& nonce, const QByteArray& sig) {
    if (publicDer.isEmpty() || nonce.isEmpty() || sig.isEmpty()) return false;
    const unsigned char* p = reinterpret_cast<const unsigned char*>(publicDer.constData());
    EVP_PKEY* key = d2i_PUBKEY(nullptr, &p, publicDer.size());
    if (!key) return false;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    bool ok = false;
    if (ctx && EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, key) == 1) {
        ok = EVP_DigestVerify(ctx,
                              reinterpret_cast<const unsigned char*>(sig.constData()), sig.size(),
                              reinterpret_cast<const unsigned char*>(nonce.constData()), nonce.size()) == 1;
    }
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    return ok;
}

static QHostAddress normalizedAddress(QHostAddress a) {
    if (a.protocol() == QAbstractSocket::IPv6Protocol) {
        bool ok = false;
        const QHostAddress v4(a.toIPv4Address(&ok));
        if (ok) return v4;
    }
    return a;
}

static bool allowStaticRate(QMap<QString, QList<qint64>>& buckets, const QString& key,
                            int maxEvents, int windowMs) {
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    QList<qint64>& bucket = buckets[key];
    for (int i = bucket.size() - 1; i >= 0; --i)
        if (now - bucket[i] > windowMs) bucket.removeAt(i);
    if (bucket.size() >= maxEvents) return false;
    bucket << now;
    return true;
}

static bool containsBadControl(const QString& s, bool allowNewline = false) {
    for (QChar ch : s) {
        const ushort u = ch.unicode();
        if (u < 0x20) {
            if (allowNewline && (ch == QLatin1Char('\n') || ch == QLatin1Char('\r') || ch == QLatin1Char('\t')))
                continue;
            return true;
        }
    }
    return false;
}

static bool validHumanText(const QString& s, int maxLen, bool allowNewline = false) {
    return !s.trimmed().isEmpty() && s.size() <= maxLen && !containsBadControl(s, allowNewline);
}

static bool validOptionalText(const QString& s, int maxLen, bool allowNewline = false) {
    return s.size() <= maxLen && !containsBadControl(s, allowNewline);
}

static void messageRateLimitFor(const QString& type, int& maxEvents, int& windowMs) {
    windowMs = 10'000;
    maxEvents = 60;
    if (type == QLatin1String("chat")) { maxEvents = 20; return; }
    if (type == QLatin1String("move") || type == QLatin1String("move_other")) { maxEvents = 15; return; }
    // talking é controle de VAD/PTT, não chat. Em microfones ruidosos o Mobile
    // pode alternar fala/silêncio muitas vezes; não avise o usuário como spam.
    if (type == QLatin1String("talking")) { maxEvents = 0; return; }
    if (type == QLatin1String("status") || type == QLatin1String("ping")) { maxEvents = 30; return; }
    if (type.startsWith(QLatin1String("ft_"))) { maxEvents = 8; windowMs = 60'000; return; }
    if (type == QLatin1String("identity_proof")) { maxEvents = 5; windowMs = 15'000; return; }
    if (type == QLatin1String("server_probe")) { maxEvents = 6; windowMs = 60'000; return; }
}

ServerCore::ServerCore(QObject* parent) : QObject(parent) {
    m_idleTimer = new QTimer(this);
    m_idleTimer->setInterval(5000);
    connect(m_idleTimer, &QTimer::timeout, this, &ServerCore::checkIdleClients);
    setupBuiltinGroups();
}

ServerCore::~ServerCore() {
    saveData();
    saveBans();
    qDeleteAll(m_clients);
}

bool ServerCore::start(quint16 controlPort, quint16 voicePort) {
    // Não remova libssl/libcrypto do diretório da aplicação: em containers
    // mínimos (Pterodactyl) o pacote da release leva o backend TLS do Qt e as
    // bibliotecas OpenSSL ao lado do binário para que QSslSocket funcione.

    m_controlPort = controlPort;
    loadData();
    loadBans();
    loadServerBanner();
    loadAvatars();

    const bool customCertificate = !m_certFile.trimmed().isEmpty() || !m_keyFile.trimmed().isEmpty();
    if (customCertificate && (m_certFile.trimmed().isEmpty() || m_keyFile.trimmed().isEmpty())) {
        log("FALHA TLS: certFile e keyFile devem ser configurados juntos");
        return false;
    }
    const QString certPath = customCertificate ? m_certFile : dataDir() + "/cert.pem";
    const QString keyPath = customCertificate ? m_keyFile : dataDir() + "/key.pem";
    if (!customCertificate && (!QFile::exists(certPath) || !QFile::exists(keyPath))) {
        log("Gerando certificado TLS autoassinado para o canal de controle...");
        QDir().mkpath(QFileInfo(certPath).absolutePath());
        QStringList args;
        args << "req" << "-x509" << "-newkey" << "rsa:3072" << "-nodes"
             << "-keyout" << keyPath << "-out" << certPath
             << "-subj" << "/CN=HallaServer" << "-days" << "825";
        const int result = QProcess::execute("openssl", args);
        if (result != 0 || !QFile::exists(certPath) || !QFile::exists(keyPath)) {
            log("FALHA TLS: openssl não conseguiu gerar cert.pem/key.pem");
            return false;
        }
        QFile::setPermissions(keyPath, QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    }

    QFile certFile(certPath);
    QFile keyFile(keyPath);
    if (!certFile.open(QIODevice::ReadOnly) || !keyFile.open(QIODevice::ReadOnly)) {
        log(QStringLiteral("FALHA TLS: não foi possível abrir certificado/chave (%1, %2)")
                .arg(certPath, keyPath));
        return false;
    }
    const QSslCertificate cert(&certFile, QSsl::Pem);
    QByteArray keyPem = keyFile.readAll();
    QSslKey key(keyPem, QSsl::Rsa, QSsl::Pem, QSsl::PrivateKey);
    if (key.isNull()) key = QSslKey(keyPem, QSsl::Ec, QSsl::Pem, QSsl::PrivateKey);
    if (cert.isNull() || key.isNull()) {
        log("FALHA TLS: certificado ou chave privada inválidos");
        return false;
    }
    m_activeCertificate = cert;
    m_activePrivateKey = key;
    log(QStringLiteral("TLS: usando certificado %1").arg(certPath));

    SslServer* sslServer = new SslServer(this);
    sslServer->setSslConfig(cert, key);
    m_tcp = sslServer;

    connect(m_tcp, &QTcpServer::newConnection, this, &ServerCore::onNewConnection);
    if (!m_tcp->listen(QHostAddress::Any, controlPort)) {
        log(QStringLiteral("FALHA: não foi possível escutar na porta TCP %1: %2")
                .arg(controlPort).arg(m_tcp->errorString()));
        return false;
    }
    log(QStringLiteral("Controle TCP escutando na porta %1").arg(controlPort));

    m_voice = new VoiceRelay(this, this);
    if (!m_voice->bind(voicePort)) return false;

    m_idleTimer->start();
    log(QStringLiteral("Servidor \"%1\" v%2 iniciado (slots: %3, protocolo v%4)")
            .arg(m_name, m_version).arg(m_maxClients).arg(HProto::kProtoVersion));
    return true;
}

void ServerCore::log(const QString& msg) {
    const QString line = QStringLiteral("[%1] %2")
        .arg(QDateTime::currentDateTime().toString("dd/MM/yyyy HH:mm:ss"), msg);
    emit logLine(line);
}

void ServerCore::sendError(ClientSession* c, const QString& code, const QString& msg) {
    QJsonObject e = HProto::msg("error");
    e["code"] = code;
    e["msg"] = msg;
    c->send(e);
}

// ================================================== grupos e permissões (v2)
void ServerCore::setupBuiltinGroups() {
    // Pilar 1: Position/Hierarchy - Quanto maior o número, mais alto na hierarquia
    // Guest (position 0) < Normal (position 10) < Admin (position 100)
    GroupDef guest;  guest.id = 1;  guest.name = "guest";
    guest.position = 0;  // Nível mais baixo
    guest.order = 20;    // Aparece em último na lista (maior índice)
    guest.perms = QJsonObject{
        {"join", true}, {"listen", true}, {"talk", true}, {"text_chat", true},
        {"poke", true}, {"privmsg", true}, {"whisper", true}, {"talkPower", 10}
    };
    GroupDef normal; normal.id = 2; normal.name = "normal";
    normal.position = 10;  // Nível médio
    normal.order = 10;     // Aparece no meio
    normal.perms = QJsonObject{
        {"join", true}, {"listen", true}, {"talk", true}, {"text_chat", true},
        {"poke", true}, {"privmsg", true}, {"whisper", true}, {"chanCreateTemp", true},
        {"talkPower", 25}
    };
    GroupDef admin;  admin.id = 3;  admin.name = "admin";
    admin.position = 100;  // Nível administrativo mais alto
    admin.order = 0;       // Aparece em primeiro (menor índice)
    admin.perms = QJsonObject{
        {"*", true}, {"kick", true}, {"ban", true}, {"banList", true},
        {"move", true}, {"setCommander", true}, {"selfCommander", true},
        {"b_client_set_channel_commander", true},
        {"b_client_is_channel_commander", true},
        {"chanCreateTemp", true}, {"chanCreateSemi", true},
        {"chanCreatePerm", true}, {"chanEdit", true}, {"chanDelete", true},
        {"serverEdit", true}, {"groupEdit", true}, {"poke", true},
        {"privmsg", true}, {"whisper", true}, {"ignoreChanPass", true}, {"ignoreTalkPower", true},
        {"text_chat", true}, {"listen", true}, {"talkPower", 75}
    };
    m_groups[1] = guest;
    m_groups[2] = normal;
    m_groups[3] = admin;
}

bool ServerCore::hasPerm(const ClientSession* c, const char* key) const {
    if (!c) return false;
    
    if (c->name() == QStringLiteral("serveradmin")) {
        return true;
    }
    
    if (m_privilegedUids.contains(c->uniqueId())) {
        return true;
    }

    QList<int> gids = m_assignByUid.value(c->uniqueId());
    if (gids.isEmpty()) {
        gids << 2;
    } else if (!gids.contains(1) && !gids.contains(2)) {
        gids.prepend(2);
    }
    
    for (int gid : gids) {
        const GroupDef g = m_groups.value(gid, m_groups.value(1));
        if (g.id == 3 || g.name.toLower() == "admin" || g.perms.value(QStringLiteral("*")).toBool()) {
            return true;
        }
        const QJsonValue value = g.perms.value(QString::fromLatin1(key));
        if (value.toBool() || value.toInt(0) > 0) {
            return true;
        }
    }
    return false;
}

// Pilar 1: Retorna a posição hierárquica do cliente (quanto maior, mais autoridade)
int ServerCore::clientPosition(const ClientSession* c) const {
    if (!c) return 0;
    QList<int> gids = m_assignByUid.value(c->uniqueId());
    if (gids.isEmpty()) {
        gids << 2;
    } else if (!gids.contains(1) && !gids.contains(2)) {
        gids.prepend(2);
    }
    int maxPos = 0;
    for (int gid : gids) {
        const GroupDef g = m_groups.value(gid, m_groups.value(1));
        maxPos = qMax(maxPos, g.position);
    }
    return maxPos;
}

// Pilar 1: Verifica se executor pode gerenciar (kick/ban/edit) o alvo baseado na hierarquia
// Regra: Só pode gerenciar quem está abaixo (position menor) - igual também não pode
bool ServerCore::canManageClient(const ClientSession* executor, const ClientSession* target) const {
    if (!executor || !target) return false;
    
    // Super-admin sempre pode
    if (executor->groupId() == 3 || executor->group().toLower() == "admin" 
        || executor->name() == QStringLiteral("serveradmin")) {
        return true;
    }
    if (m_privilegedUids.contains(executor->uniqueId())) {
        return true;
    }
    
    // Alvo com privilégio individual ou super-admin não pode ser gerenciado por não-super-admin
    if (m_privilegedUids.contains(target->uniqueId()) || target->groupId() == 3 
        || target->group().toLower() == "admin" || target->name() == QStringLiteral("serveradmin")) {
        return false;
    }
    
    // Pilar 1: O executor só pode gerenciar se sua posição for MAIOR que a do alvo
    // Posições iguais também impedem o gerenciamento do alvo
    int executorPos = clientPosition(executor);
    int targetPos = clientPosition(target);
    
    return executorPos > targetPos;
}

// Pilar 1: Verifica se um grupo pode gerenciar outro grupo baseado no position
bool ServerCore::canManageGroup(int executorGroupId, int targetGroupId) const {
    if (executorGroupId <= 0 || targetGroupId <= 0) return false;
    
    GroupDef executorGroup = m_groups.value(executorGroupId);
    GroupDef targetGroup = m_groups.value(targetGroupId);
    
    // Se executor é admin (id 3), pode gerenciar todos
    if (executorGroup.id == 3 || executorGroup.name.toLower() == "admin") {
        return true;
    }
    
    // Regra de position: executor precisa ter position > target
    return executorGroup.position > targetGroup.position;
}

// Pilar 3: Retorna o estado da permissão no canal (Allow=1, Deny=0, Inherit=-1, NotSet=-2)
int ServerCore::getChannelPermState(const ClientSession* c, int channelId, const QString& permKey) const {
    if (!c || !m_channels.contains(channelId)) return -2; // NotSet
    
    const SvrChan& ch = m_channels[channelId];
    QList<int> gids = m_assignByUid.value(c->uniqueId());
    if (gids.isEmpty()) {
        gids << 2;
    } else if (!gids.contains(1) && !gids.contains(2)) {
        gids.prepend(2);
    }
    
    int resolvedState = -2;
    
    for (int gid : gids) {
        const QString gidStr = QString::number(gid);
        if (ch.groupPerms.contains(gidStr)) {
            const QJsonObject gPerms = ch.groupPerms[gidStr].toObject();
            
            if (permKey == QStringLiteral("join") && gPerms.contains("traverse")) {
                bool traverse = gPerms.value("traverse").toBool();
                if (!traverse) return 0; // Deny total de travessia tem precedência absoluta
            }
            
            if (gPerms.contains(permKey)) {
                QJsonValue val = gPerms.value(permKey);
                int state = -1;
                if (val.isBool()) state = val.toBool() ? 1 : 0;
                else if (val.isDouble()) state = val.toInt();
                
                if (state == 1) {
                    resolvedState = 1;
                } else if (state == 0 && resolvedState != 1) {
                    resolvedState = 0;
                } else if (state == -1 && resolvedState == -2) {
                    resolvedState = -1;
                }
            }
        }
        
        if (ch.groupPositionReqs.contains(gidStr)) {
            int requiredPos = ch.groupPositionReqs[gidStr].toInt();
            int clientPos = m_groups.value(gid).position;
            if (clientPos < requiredPos) {
                return 0; // Deny - posição insuficiente
            }
        }
    }
    
    return resolvedState;
}

// Pilar 3: Verifica permissão efetiva de canal considerando Allow/Deny/Inherit
bool ServerCore::hasEffectiveChannelPerm(const ClientSession* c, int channelId, const QString& permKey) const {
    if (!c) return false;
    
    // Bypass absoluto de administrador / serveradmin
    if (m_privilegedUids.contains(c->uniqueId()) || c->groupId() == 3 
        || c->group().toLower() == "admin" || c->name() == QStringLiteral("serveradmin")) {
        return true;
    }
    
    // Se o canal não existe, retorna true por padrão (usa permissões globais)
    if (!m_channels.contains(channelId)) return true;
    
    int state = getChannelPermState(c, channelId, permKey);
    
    // Pilar 3: Lógica dos 3 estados
    if (state == 1) return true;   // Allow - forçado a true
    if (state == 0) return false;  // Deny - forçado a false
    // state == -1 (Inherit) ou -2 (NotSet): usa permissão do servidor
    return hasPerm(c, permKey.toLatin1().constData());
}

// Compatibilidade: hasChannelPerm agora usa hasEffectiveChannelPerm
bool ServerCore::hasChannelPerm(const ClientSession* c, int channelId, const QString& permKey) const {
    return hasEffectiveChannelPerm(c, channelId, permKey);
}

int ServerCore::talkPower(const ClientSession* c) const {
    if (!c) return 0;
    QList<int> gids = m_assignByUid.value(c->uniqueId());
    if (gids.isEmpty()) {
        gids << 2;
    } else if (!gids.contains(1) && !gids.contains(2)) {
        gids.prepend(2);
    }
    int maxPower = 0;
    for (int gid : gids) {
        const GroupDef g = m_groups.value(gid, m_groups.value(1));
        int power = g.perms.value(QStringLiteral("talkPower")).toInt(0);
        maxPower = qMax(maxPower, power);
    }
    return maxPower;
}

QJsonObject ServerCore::myPermsOf(const GroupDef& g) { return g.perms; }

int ServerCore::groupIdByName(const QString& name) const {
    for (const GroupDef& g : m_groups)
        if (g.name.compare(name, Qt::CaseInsensitive) == 0) return g.id;
    return 0;
}

QJsonObject ServerCore::groupToJson(const GroupDef& g) const {
    QJsonObject o;
    o["id"] = g.id;
    o["name"] = g.name;
    o["perms"] = g.perms;
    o["sigla"] = g.sigla;
    o["order"] = g.order;
    o["icon"] = g.icon;
    o["position"] = g.position;  // Pilar 1: posição hierárquica
    return o;
}

void ServerCore::applyGroup(ClientSession* c, int groupId, bool announce) {
    QList<int> gids = m_assignByUid.value(c->uniqueId());
    if (!gids.contains(groupId) && groupId > 0) {
        gids << groupId;
    }
    if (gids.isEmpty()) {
        gids << 2;
    } else if (!gids.contains(1) && !gids.contains(2)) {
        gids.prepend(2);
    }
    
    QList<int> validIds;
    for (int gid : gids) {
        if (m_groups.contains(gid)) {
            validIds << gid;
        }
    }
    if (validIds.isEmpty()) {
        validIds << 2;
    }
    
    // Ordena por posição decrescente (maior poder no topo)
    std::sort(validIds.begin(), validIds.end(), [this](int a, int b) {
        return m_groups[a].position > m_groups[b].position;
    });
    
    int primaryGid = validIds.first();
    c->setGroupId(primaryGid);
    
    QStringList names;
    QStringList siglas;
    int maxPos = 0;
    int minOrder = 9999;
    QString firstIcon;
    
    for (int gid : validIds) {
        const GroupDef& g = m_groups[gid];
        QString nameWithIcon = g.icon.isEmpty() ? g.name : g.icon + QStringLiteral(" ") + g.name;
        names << nameWithIcon;
        if (!g.sigla.isEmpty()) siglas << g.sigla;
        maxPos = qMax(maxPos, g.position);
        minOrder = qMin(minOrder, g.order);
        if (firstIcon.isEmpty() && !g.icon.isEmpty()) firstIcon = g.icon;
    }
    
    c->setGroup(names.join(QStringLiteral("\n")));
    c->setSigla(siglas.join(QStringLiteral(" ")));
    c->setIcon(firstIcon);
    c->setGroupOrder(minOrder);
    c->setGroupPosition(maxPos);
    
    if (announce) {
        QJsonObject m = HProto::msg("user_group");
        m["id"] = c->id();
        m["group"] = c->group();
        m["gid"] = primaryGid;
        m["sigla"] = c->sigla();
        m["icon"] = c->icon();
        m["order"] = minOrder;
        m["position"] = maxPos;
        broadcast(m);
    }
}

void ServerCore::broadcastGroups() {
    QJsonObject m = HProto::msg("group_list");
    QJsonArray arr;
    for (const GroupDef& g : m_groups) arr << groupToJson(g);
    m["groups"] = arr;
    broadcast(m);
}

// ==================================================================== dados
// ==================================================================== conexões
void ServerCore::onNewConnection() {
    static constexpr int kMaxConnectionsPerIp = 8;
    while (m_tcp->hasPendingConnections()) {
        QTcpSocket* s = m_tcp->nextPendingConnection();
        const QHostAddress ip = normalizedAddress(s->peerAddress());
        int fromIp = 0;
        for (ClientSession* existing : findChildren<ClientSession*>()) {
            if (existing && existing->ip() == ip) ++fromIp;
        }
        if (fromIp >= kMaxConnectionsPerIp) {
            log(QStringLiteral("Conexão recusada de %1: limite por IP excedido").arg(ip.toString()));
            s->disconnectFromHost();
            s->deleteLater();
            continue;
        }
        ClientSession* c = new ClientSession(s, this, this);
        connect(c, &ClientSession::messageReceived, this, &ServerCore::onClientMessage);
        connect(c, &ClientSession::disconnected, this, &ServerCore::onClientDisconnected);
        log(QStringLiteral("Nova conexão de %1").arg(s->peerAddress().toString()));
    }
}

void ServerCore::onClientDisconnected(ClientSession* client) {
    if (!client) return;
    if (client->id() > 0 && m_clients.contains(client->id())) {
        QJsonObject left = HProto::msg("user_left");
        left["id"] = client->id();
        left["reason"] = "dropped";
        broadcast(left, client->id());
        removeFromChannels(client->id());
        m_clients.remove(client->id());
        releaseVoiceToken(client);
        log(QStringLiteral("Cliente #%1 (%2) desconectou").arg(client->id()).arg(client->name()));
    }
    client->deleteLater();
}

void ServerCore::checkIdleClients() {
    const QDateTime now = QDateTime::currentDateTimeUtc();
    for (ClientSession* c : findChildren<ClientSession*>()) {
        if (!c) continue;
        const qint64 idleMs = c->lastActivityAt().msecsTo(now);
        if ((c->id() == 0 && idleMs > 15'000) || (c->id() > 0 && idleMs > 5 * 60'000)) {
            log(QStringLiteral("Fechando conexão ociosa de %1").arg(c->ip().toString()));
            c->closeAndDelete();
            continue;
        }
        if (c->udpPort() != 0 && c->lastUdpSeenAt().isValid()
                && c->lastUdpSeenAt().msecsTo(now) > 2 * 60'000) {
            c->clearUdpEndpoint();
        }
    }

    // limpa canais temporários vazios
    QList<int> toRemove;
    for (const SvrChan& c : m_channels)
        if (c.type == 0 && c.users.isEmpty()) toRemove << c.id;
    QList<int> linkAffected;
    for (int id : toRemove) {
        m_channels.remove(id);
        for (SvrChan& other : m_channels) {
            if (other.linkedChannels.removeAll(id) > 0 && !linkAffected.contains(other.id))
                linkAffected << other.id;
        }
        QJsonObject m = HProto::msg("chan_removed");
        m["id"] = id;
        broadcast(m);
    }
    for (int affectedId : linkAffected) {
        if (!m_channels.contains(affectedId)) continue;
        QJsonObject update = HProto::msg("chan_update");
        update["chan"] = chanToJson(m_channels[affectedId]);
        broadcast(update);
    }
    if (!toRemove.isEmpty()) saveData();
}

void ServerCore::registerClient(ClientSession* c) {
    if (c->uniqueId().isEmpty()) return;
    RegClient& rc = m_registry[c->uniqueId()];
    if (!rc.firstSeen.isValid()) rc.firstSeen = QDateTime::currentDateTime();
    rc.name = c->name();
    rc.lastSeen = QDateTime::currentDateTime();
    saveData();
}

// ==================================================================== mensagens
void ServerCore::onClientMessage(ClientSession* c, const QJsonObject& obj) {
    const QString t = obj["t"].toString();
    if (t.isEmpty() || t.size() > 40 || containsBadControl(t)) {
        sendError(c, "bad_type", "Tipo de mensagem inválido");
        return;
    }

    // Consulta leve usada pela tela inicial do Mobile. Não cria uma sessão,
    // não consome vaga e permite mostrar o limite configurado no servidor
    // antes de o usuário tocar no cartão para entrar.
    if (c->id() == 0 && t == "server_probe") {
        static QMap<QString, QList<qint64>> probeBuckets;
        if (!allowStaticRate(probeBuckets, c->ip().toString(), 6, 60'000)) {
            sendError(c, "rate_limited", "Muitas consultas server_probe deste IP");
            c->closeAndDelete();
            return;
        }
        QJsonObject response = HProto::msg("server_probe");
        QJsonObject server;
        server["name"] = m_name;
        server["motd"] = m_motd;
        server["ver"] = m_version;
        server["maxClients"] = m_maxClients;
        response["server"] = server;
        response["clients"] = m_clients.size();
        response["maxClients"] = m_maxClients;
        c->send(response);
        c->closeAndDelete();
        return;
    }

    int maxEvents = 0, windowMs = 0;
    messageRateLimitFor(t, maxEvents, windowMs);
    if (maxEvents > 0 && !c->allowRate(t, maxEvents, windowMs)) {
        sendError(c, "rate_limited", "Você está enviando mensagens rápido demais");
        return;
    }

    if (c->id() == 0 && t == "identity_proof") { handleIdentityProof(c, obj); return; }
    if (c->id() == 0 && t != "hello") return; // exige login antes de tudo

    if (t == "hello")           handleHello(c, obj);
    else if (t == "ping")        { QJsonObject p = HProto::msg("pong"); p["ts"] = obj["ts"]; c->send(p); }
    else if (t == "chat")        handleChat(c, obj);
    else if (t == "move")        handleMove(c, obj);
    else if (t == "move_other")  handleMoveOther(c, obj);
    else if (t == "commander")    handleCommander(c, obj);
    else if (t == "voice_hello") {
        ensureVoiceToken(c);
        QJsonObject v = HProto::msg("voice_token");
        if (c->protocolVersion() >= 4) {
            v["token"] = QString::fromLatin1(c->voiceToken().toHex());
            v["format"] = "hex128";
        } else {
            v["token"] = QString::number(c->legacyVoiceToken());
            v["format"] = "u32";
        }
        v["udp"] = m_voice ? m_voice->port() : 0;
        c->send(v);
    }
    else if (t == "talking")     handleTalking(c, obj);
    else if (t == "status")      handleStatus(c, obj);
    else if (t == "nick")        handleNick(c, obj);
    else if (t == "desc")        handleDesc(c, obj);
    else if (t == "poke")        handlePoke(c, obj);
    else if (t == "chan_create") handleChanCreate(c, obj);
    else if (t == "chan_edit")   handleChanEdit(c, obj);
    else if (t == "chan_move")   handleChanMove(c, obj);
    else if (t == "chan_link")   handleChanLink(c, obj);
    else if (t == "chan_delete") handleChanDelete(c, obj);
    else if (t == "kick")        handleKick(c, obj);
    else if (t == "ban")         handleBan(c, obj);
    else if (t == "banlist")     handleBanList(c);
    else if (t == "unban")       handleUnban(c, obj);
    else if (t == "privkey")     handlePrivkey(c, obj);
    else if (t == "volume")      handleVolume(c, obj);
    else if (t == "group_list")  handleGroupList(c);
    else if (t == "group_set")   handleGroupSet(c, obj);
    else if (t == "group_delete") handleGroupDelete(c, obj);
    else if (t == "client_set_group") handleClientSetGroup(c, obj);
    else if (t == "server_edit") handleServerEdit(c, obj);
    else if (t == "avatar_set")     handleAvatarSet(c, obj);
    else if (t == "avatar_get")     handleAvatarGet(c, obj);
    else if (t == "icon_get")       handleIconGet(c, obj);
    else if (t == "icon_set")       handleIconSet(c, obj);
    else if (t == "offline_send")   handleOfflineSend(c, obj);
    else if (t == "complaint_add")  handleComplaintAdd(c, obj);
    else if (t == "complaint_list") handleComplaintList(c);
    else if (t == "complaint_clear") handleComplaintClear(c, obj);
    else if (t == "whisper")        handleWhisper(c, obj);
    else if (t == "ft_upload")      handleFtUpload(c, obj);
    else if (t == "ft_list")        handleFtList(c, obj);
    else if (t == "ft_download")    handleFtDownload(c, obj);
    else if (t == "ft_delete")      handleFtDelete(c, obj);
    else if (t == "webrtc_stream_start") handleWebRtcStreamState(c, true);
    else if (t == "webrtc_stream_stop") handleWebRtcStreamState(c, false);
    else if (t == "webrtc_watch_request" || t == "webrtc_watch_stop" ||
             t == "webrtc_offer" || t == "webrtc_answer" || t == "webrtc_ice") handleWebRtcSignal(c, obj);
    else if (t == "screenshare_start") {
        if (!m_allowScreenShare) {
            sendError(c, "screenshare_disabled", "O compartilhamento de tela está desativado pelo servidor");
            return;
        }
        log(QStringLiteral("Cliente #%1 (%2) iniciou compartilhamento de tela").arg(c->id()).arg(c->name()));
        c->setScreensharing(true);
        QJsonObject m = HProto::msg("user_screenshare_state");
        m["id"] = c->id();
        m["on"] = true;
        broadcast(m);
    }
    else if (t == "screenshare_stop") {
        log(QStringLiteral("Cliente #%1 (%2) parou compartilhamento de tela").arg(c->id()).arg(c->name()));
        c->setScreensharing(false);
        QJsonObject m = HProto::msg("user_screenshare_state");
        m["id"] = c->id();
        m["on"] = false;
        broadcast(m);
    }
    else if (t == "quit") {
        // desconexão graciosa: notifica os demais antes de fechar
        QJsonObject left = HProto::msg("user_left");
        left["id"] = c->id();
        left["reason"] = "quit";
        broadcast(left, c->id());
        removeFromChannels(c->id());
        m_clients.remove(c->id());
        releaseVoiceToken(c);
        log(QStringLiteral("Cliente #%1 (%2) saiu").arg(c->id()).arg(c->name()));
        c->closeAndDelete();
    }
}

void ServerCore::handleWebRtcStreamState(ClientSession* c, bool on) {
    if (!c) return;
    if (on && !m_allowScreenShare) {
        sendError(c, "screenshare_disabled", "O compartilhamento de tela está desativado pelo servidor");
        return;
    }
    c->setScreensharing(on);
    QJsonObject m = HProto::msg("user_screenshare_state");
    m["id"] = c->id();
    m["on"] = on;
    m["mode"] = QStringLiteral("webrtc");
    broadcast(m);
    log(QStringLiteral("Cliente #%1 (%2) %3 transmissão WebRTC")
            .arg(c->id()).arg(c->name(), on ? QStringLiteral("iniciou") : QStringLiteral("parou")));
}

void ServerCore::handleWebRtcSignal(ClientSession* c, const QJsonObject& obj) {
    if (!c) return;
    const QString t = obj["t"].toString();
    const int to = obj["to"].toInt();
    ClientSession* target = m_clients.value(to, nullptr);
    if (!target || target == c) {
        sendError(c, "webrtc_target", "Cliente de destino inválido");
        return;
    }

    const int fromChan = channelOfUser(c->id());
    const int toChan = channelOfUser(target->id());
    if (fromChan == 0 || fromChan != toChan) {
        sendError(c, "webrtc_channel", "WebRTC permitido apenas entre usuários do mesmo canal");
        return;
    }
    if (!hasChannelPerm(c, fromChan, QStringLiteral("listen"))
            || !hasChannelPerm(target, toChan, QStringLiteral("listen"))) {
        sendError(c, "no_permission", "Sem permissão para sinalização WebRTC neste canal");
        return;
    }
    if (t == QLatin1String("webrtc_watch_request") && !target->screensharing()) {
        sendError(c, "webrtc_not_streaming", "Este usuário não está transmitindo");
        return;
    }

    if ((t == QLatin1String("webrtc_offer") || t == QLatin1String("webrtc_answer"))
        && obj.value(QStringLiteral("sdp")).toString().size() > 256 * 1024) {
        sendError(c, "webrtc_sdp_too_big", "SDP WebRTC excede 256 KiB");
        return;
    }
    if (t == QLatin1String("webrtc_ice")
        && obj.value(QStringLiteral("candidate")).toString().size() > 16 * 1024) {
        sendError(c, "webrtc_ice_too_big", "ICE candidate excede 16 KiB");
        return;
    }

    QJsonObject out = obj;
    out["iceServers"] = m_webRtcIceServers;
    out["from"] = c->id();
    out["fromName"] = c->name();
    out["to"] = target->id();
    target->send(out);
}

void ServerCore::handleIdentityProof(ClientSession* c, const QJsonObject& obj) {
    if (!c || c->id() != 0) return;
    const QByteArray sig = QByteArray::fromBase64(obj["sig"].toString().toLatin1());
    const QByteArray pub = c->pendingIdentityPub();
    const QByteArray nonce = c->pendingIdentityNonce();
    if (!verifyIdentitySignature(pub, nonce, sig)) {
        sendError(c, "bad_identity", "Assinatura da identidade inválida");
        c->closeAndDelete();
        return;
    }
    QJsonObject hello = c->pendingIdentityHello();
    hello["uid"] = uidForIdentityPublicKey(pub);
    c->setIdentityVerified(true);
    c->clearPendingIdentity();
    handleHello(c, hello);
}

void ServerCore::handleHello(ClientSession* c, const QJsonObject& obj) {
    if (c->id() != 0) return; // já logado

    const QString nick = obj["nick"].toString().trimmed().left(30);
    QString uid = obj["uid"].toString().left(64);
    const QString pass = obj["pass"].toString();
    const QString adminPass = obj["adminPass"].toString();
    const int clientProto = obj["proto"].toInt();

    if (clientProto < HProto::kProtoMin || clientProto > HProto::kProtoVersion) {
        sendError(c, "bad_proto",
                  QStringLiteral("Versão do protocolo incompatível (servidor aceita v%1-v%2)")
                      .arg(HProto::kProtoMin).arg(HProto::kProtoVersion));
        c->closeAndDelete();
        return;
    }
    c->setProtocolVersion(clientProto);

    if (!validHumanText(nick, 30, false)) {
        sendError(c, "bad_nick", "Apelido inválido");
        c->closeAndDelete();
        return;
    }

    if (!c->identityVerified()) {
        const QByteArray pub = QByteArray::fromBase64(obj["idPub"].toString().toLatin1());
        if (pub.isEmpty()) {
            sendError(c, "bad_identity", "Identidade criptográfica ausente — atualize o cliente");
            c->closeAndDelete();
            return;
        }
        QByteArray nonce(32, '\0');
        QRandomGenerator* rng = QRandomGenerator::system();
        for (int i = 0; i < nonce.size(); ++i) nonce[i] = char(rng->bounded(256));
        c->setPendingIdentity(obj, pub, nonce);
        QJsonObject challenge = HProto::msg("identity_challenge");
        challenge["nonce"] = QString::fromLatin1(nonce.toBase64());
        c->send(challenge);
        return;
    }

    if (uid.isEmpty()) {
        sendError(c, "bad_uid", "Identidade (ID único) ausente — atualize o cliente");
        c->closeAndDelete();
        return;
    }

    // banido? (por UID ou por IP)
    const QString ip = c->ip().toString();
    for (const BanEntry& b : m_bans) {
        const bool match = (!b.uid.isEmpty() && b.uid == uid)
                        || (!b.ip.isEmpty() && b.ip == ip);
        if (match && (!b.expires.isValid() || b.expires > QDateTime::currentDateTime())) {
            sendError(c, "banned",
                      b.reason.isEmpty() ? QStringLiteral("Você está banido deste servidor")
                                         : QStringLiteral("Banido: %1").arg(b.reason));
            c->closeAndDelete();
            return;
        }
    }

    // servidor cheio
    if (m_clients.size() >= m_maxClients) {
        sendError(c, "server_full", "Servidor cheio");
        c->closeAndDelete();
        return;
    }

    // senha do servidor
    if (!m_password.isEmpty() && !PasswordHash::verify(pass, m_password)) {
        sendError(c, "bad_password", "Senha do servidor incorreta");
        c->closeAndDelete();
        return;
    }

    // Remove qualquer sessão zumbi/duplicada do mesmo usuário (por apelido ou UID)
    for (ClientSession* other : m_clients) {
        if (other->uniqueId() == uid || other->name().compare(nick, Qt::CaseInsensitive) == 0) {
            log(QStringLiteral("Sessão duplicada/zumbi de %1 (#%2) removida para nova conexão").arg(other->name()).arg(other->id()));
            
            QJsonObject kicked = HProto::msg("kicked");
            kicked["reason"] = "Nova sessão iniciada";
            kicked["ban"] = false;
            other->send(kicked);
            
            doKick(other, "Nova sessão iniciada", true, false);
            break;
        }
    }

    c->setId(m_nextId++);
    c->setName(nick);
    c->setUid(uid);
    c->setVersion(obj["ver"].toString().left(20));
    c->setPlatform(obj["platform"].toString().left(20));

    // grupo: atribuição persistente por UID tem prioridade; senão "normal"
    QList<int> gids = m_assignByUid.value(uid);
    int gid = gids.isEmpty() ? 2 : gids.first();
    log(QStringLiteral("DEBUG: Cliente \"%1\" com UID \"%2\" conectando. GID mapeado recuperado: %3")
            .arg(nick, uid, QString::number(gid)));
    if (!m_groups.contains(gid)) gid = 2; // normal
    applyGroup(c, gid, false);
    // senha de administrador eleva a admin (mesmo com atribuição salva)
    if (!adminPass.isEmpty() && !m_adminPassword.isEmpty()
        && PasswordHash::verify(adminPass, m_adminPassword))
        applyGroup(c, 3, false);

    m_clients[c->id()] = c;
    addToChannel(c->id(), 1); // entra no canal padrão
    log(QStringLiteral("Cliente #%1 (%2) entrou [grupo: %3]")
            .arg(c->id()).arg(nick, c->group()));

    c->setAvatarHash(m_avatarHash.value(uid)); // v3: avatar salvo
    sendWelcome(c);
    registerClient(c);

    // v3: entrega mensagens offline pendentes
    if (m_offline.contains(uid) && !m_offline[uid].isEmpty()) {
        for (const OfflineMsg& om : m_offline[uid]) {
            QJsonObject m = HProto::msg("offline_msg");
            m["fromUid"] = om.fromUid;
            m["fromName"] = om.fromName;
            m["text"] = om.text;
            m["ts"] = om.ts.toString(Qt::ISODate);
            c->send(m);
        }
        m_offline.remove(uid);
        saveData();
    }

    QJsonObject joined = HProto::msg("user_joined");
    joined["user"] = c->toJson();
    broadcast(joined, c->id());

    // v3: Envia uma sinalização explícita de movimento para o canal padrão (1) 
    // para que todos os outros clientes saibam onde colocar o novo usuário na árvore.
    QJsonObject moved = HProto::msg("user_moved");
    moved["id"] = c->id();
    moved["channel"] = 1;
    broadcast(moved);
}

void ServerCore::ensureVoiceToken(ClientSession* c) {
    if (!c || c->hasVoiceToken()) return;
    if (c->protocolVersion() >= 4) {
        QByteArray token(HProto::kVoiceTokenBytes, '\0');
        do {
            if (RAND_bytes(reinterpret_cast<unsigned char*>(token.data()), token.size()) != 1) {
                token.clear();
                break;
            }
        } while (m_byVoiceToken.contains(token));
        if (!token.isEmpty()) {
            c->setVoiceToken(token);
            m_byVoiceToken[token] = c;
        }
    } else {
        quint32 token = 0;
        do {
            if (RAND_bytes(reinterpret_cast<unsigned char*>(&token), sizeof(token)) != 1) {
                token = QRandomGenerator::system()->generate();
            }
        } while (token == 0 || m_byLegacyVoiceToken.contains(token));
        c->setLegacyVoiceToken(token);
        m_byLegacyVoiceToken[token] = c;
    }
}

void ServerCore::releaseVoiceToken(ClientSession* c) {
    if (!c) return;
    if (!c->voiceToken().isEmpty()) m_byVoiceToken.remove(c->voiceToken());
    if (c->legacyVoiceToken()) m_byLegacyVoiceToken.remove(c->legacyVoiceToken());
    c->setVoiceToken({});
    c->setLegacyVoiceToken(0);
}

void ServerCore::sendWelcome(ClientSession* c) {
    QJsonObject w = HProto::msg("welcome");
    w["selfId"] = c->id();
    w["proto"] = HProto::kProtoVersion;

    QJsonObject server;
    server["name"] = m_name;
    server["motd"] = m_motd;
    server["ver"] = m_version;
#ifdef Q_OS_WIN
    server["platform"] = "Windows";
#else
    server["platform"] = "Linux";
#endif
    server["maxClients"] = m_maxClients;
    server["screenshare"] = m_allowScreenShare;
    server["screenshare_w"] = m_screenshareWidth;
    server["screenshare_h"] = m_screenshareHeight;
    server["screenshare_fps"] = m_screenshareFps;
    if (!m_serverBanner.isEmpty())
        server["banner"] = QString::fromLatin1(m_serverBanner.toBase64());
    w["server"] = server;

    QJsonArray users;
    for (ClientSession* o : m_clients) users << o->toJson();
    w["users"] = users;

    QJsonArray chans;
    for (const SvrChan& ch : m_channels) chans << chanToJson(ch);
    w["channels"] = chans;

    // v2: lista de grupos + minhas permissões
    QJsonArray groups;
    for (const GroupDef& g : m_groups) groups << groupToJson(g);
    w["groups"] = groups;
    w["myPerms"] = myPermsOf(m_groups.value(c->groupId(), m_groups.value(1)));

    ensureVoiceToken(c);
    QJsonObject voice;
    voice["udp"] = m_voice ? m_voice->port() : 0;
    if (c->protocolVersion() >= 4) {
        voice["token"] = QString::fromLatin1(c->voiceToken().toHex());
        voice["format"] = "hex128";
    } else {
        voice["token"] = QString::number(c->legacyVoiceToken());
        voice["format"] = "u32";
    }
    w["voice"] = voice;
    w["iceServers"] = m_webRtcIceServers;

    // Chaves atuais dos canais aos quais o cliente precisa ter acesso chegam
    // dentro do welcome. Isso evita a corrida em que channel_key era enviado
    // antes de o cliente marcar a sessão como pronta e acabava ignorado.
    QJsonObject keys;
    const int myChannel = channelOfUser(c->id());
    if (myChannel > 0 && m_channels.contains(myChannel)) {
        QSet<int> component;
        QList<int> pending;
        component.insert(myChannel);
        pending << myChannel;
        while (!pending.isEmpty()) {
            const int current = pending.takeFirst();
            if (!m_channels.contains(current)) continue;
            for (int next : m_channels[current].linkedChannels) {
                if (m_channels.contains(next) && !component.contains(next)) {
                    component.insert(next);
                    pending << next;
                }
            }
            for (const SvrChan& candidate : m_channels) {
                if (candidate.linkedChannels.contains(current) && !component.contains(candidate.id)) {
                    component.insert(candidate.id);
                    pending << candidate.id;
                }
            }
        }
        for (int id : component) {
            if (!m_channelKeys.contains(id)) rotateChannelKey(id);
            if (m_channelKeys.contains(id))
                keys[QString::number(id)] = QString::fromLatin1(m_channelKeys[id].toBase64());
        }
    }
    if (!keys.isEmpty()) w["channelKeys"] = keys;

    c->send(w);
}

void ServerCore::handleChat(ClientSession* c, const QJsonObject& obj) {
    const QString scope = obj["scope"].toString();
    const QString text = obj["text"].toString();
    if (scope != QLatin1String("server") && scope != QLatin1String("channel") && scope != QLatin1String("private")) {
        sendError(c, "bad_scope", "Escopo de chat inválido");
        return;
    }
    if (!validHumanText(text, 1024, true)) return;
    if (scope == "private" && !hasPerm(c, "privmsg")) {
        sendError(c, "no_permission", "Sem permissão para mensagens privadas");
        return;
    }

    QJsonObject m = HProto::msg("chat");
    m["scope"] = scope;
    m["from"] = c->id();
    m["fromName"] = c->name();
    m["text"] = text;

    if (scope == "server")         broadcast(m);
    else if (scope == "channel") {
        const int chan = channelOfUser(c->id());
        if (!hasChannelPerm(c, chan, "text_chat")) {
            sendError(c, "no_permission", "Sem permissão para enviar chat de texto neste canal");
            return;
        }
        for (ClientSession* o : m_clients)
            if (channelOfUser(o->id()) == chan) o->send(m);
    } else if (scope == "private") {
        const int to = obj["to"].toInt();
        if (m_clients.contains(to)) {
            m["to"] = to;
            m_clients[to]->send(m);
            c->send(m); // eco para o remetente
        }
    }
}

void ServerCore::handleMove(ClientSession* c, const QJsonObject& obj) {
    const int target = obj["channel"].toInt();
    if (target <= 0 || !m_channels.contains(target)) {
        sendError(c, "invalid_channel", "Você só pode se mover para um canal existente");
        return;
    }

    if (!hasChannelPerm(c, target, "join")) {
        sendError(c, "no_permission", "Sem permissão para entrar neste canal");
        return;
    }

    SvrChan& ch = m_channels[target];
    const int oldChan = channelOfUser(c->id());
    if (oldChan == target) return;

    if (ch.maxClients >= 0 && ch.users.size() >= ch.maxClients) {
        sendError(c, "channel_full",
                  QStringLiteral("O canal \"%1\" está cheio").arg(ch.name));
        return;
    }
    if (!ch.password.isEmpty() && !hasPerm(c, "ignoreChanPass")
            && !PasswordHash::verify(obj["pass"].toString(), ch.password)) {
        sendError(c, "bad_channel_pass", "Senha do canal incorreta");
        return;
    }
    if (!ch.password.isEmpty() && !PasswordHash::isEncoded(ch.password)) {
        ch.password = PasswordHash::create(obj["pass"].toString());
        saveData();
    }

    removeFromChannels(c->id());
    ch.users << c->id();

    QJsonObject m = HProto::msg("user_moved");
    m["id"] = c->id();
    m["channel"] = target;
    m["by"] = c->id();
    broadcast(m);
}

void ServerCore::handleMoveOther(ClientSession* c, const QJsonObject& obj) {
    if (!hasPerm(c, "move") && !hasPerm(c, "i_client_move_power")) {
        sendError(c, "no_permission", "Sem permissão para mover clientes");
        return;
    }
    const int id = obj["id"].toInt();
    const int target = obj["channel"].toInt();
    if (target <= 0 || !m_clients.contains(id) || !m_channels.contains(target)) {
        sendError(c, "invalid_channel", "O destino precisa ser um canal existente");
        return;
    }
    if (!hasChannelPerm(c, target, QStringLiteral("move"))) {
        sendError(c, "no_permission", "Sem permissão para mover clientes para este canal");
        return;
    }
    removeFromChannels(id);
    m_channels[target].users << id;
    QJsonObject m = HProto::msg("user_moved");
    m["id"] = id; m["channel"] = target; m["by"] = c->id();
    broadcast(m);
}

void ServerCore::handleCommander(ClientSession* c, const QJsonObject& obj) {
    const int targetId = obj["id"].toInt(c->id());
    const bool on = obj["on"].toBool();
    if (!m_clients.contains(targetId)) return;

    const bool selfPower = hasPerm(c, "selfCommander")
        || hasPerm(c, "b_client_is_channel_commander")
        || hasPerm(c, "setCommander")
        || hasPerm(c, "b_client_set_channel_commander");
    const bool otherPower = hasPerm(c, "setCommander")
        || hasPerm(c, "b_client_set_channel_commander");
    const bool allowed = targetId == c->id() ? selfPower : otherPower;
    if (!allowed) {
        sendError(c, "no_permission",
                  targetId == c->id()
                      ? "Sem permissão para ser comandante do canal"
                      : "Sem permissão para definir o comandante de outro cliente");
        return;
    }

    // O comando continua sendo uma ação de servidor, não um estado local
    // falsificável enviado em "status". A mudança é refletida para todos.
    ClientSession* target = m_clients.value(targetId);
    target->setCommander(on);
    QJsonObject u = HProto::msg("user_state");
    u["id"] = targetId;
    u["cc"] = on;
    u["by"] = c->id();
    broadcast(u);
}

void ServerCore::handleTalking(ClientSession* c, const QJsonObject& obj) {
    const bool on = obj["on"].toBool();
    if (on && !canTalkIn(c, channelOfUser(c->id()))) {
        sendError(c, "no_talk_power",
                  "Você não tem poder de fala suficiente neste canal");
        return; // não propaga: ninguém vê o indicador de fala
    }
    if (c->talking() != on) {
        c->setTalking(on);
        QJsonObject u = HProto::msg("user_state");
        u["id"] = c->id();
        u["talking"] = on;
        u["whispering"] = (on && !c->whisperIds().isEmpty());
        broadcast(u, c->id());
    }
}

bool ServerCore::canTalkIn(const ClientSession* c, int channelId) const {
    if (!m_channels.contains(channelId)) return false;
    if (!hasChannelPerm(c, channelId, "talk")) return false;
    const SvrChan& ch = m_channels[channelId];
    int need = ch.ntalk;
    if (need <= 0 && ch.moderated) need = 25;
    if (need <= 0) return true;
    if (hasPerm(c, "ignoreTalkPower")) return true;
    return talkPower(c) >= need;
}

void ServerCore::handleStatus(ClientSession* c, const QJsonObject& obj) {
    if (obj.contains("mic"))  c->setMicMuted(obj["mic"].toBool());
    if (obj.contains("spk"))  c->setSpkMuted(obj["spk"].toBool());
    if (obj.contains("away")) c->setAway(obj["away"].toBool());
    if (obj.contains("rec"))  c->setRecording(obj["rec"].toBool());
    if (obj.contains("cc")) {
        const bool requested = obj["cc"].toBool();
        const bool selfPower = hasPerm(c, "selfCommander")
            || hasPerm(c, "b_client_is_channel_commander")
            || hasPerm(c, "setCommander")
            || hasPerm(c, "b_client_set_channel_commander");
        if (!requested || selfPower) {
            c->setCommander(requested);
        } else {
            sendError(c, "no_permission", "Sem permissão para ser comandante do canal");
        }
    }

    QJsonObject u = HProto::msg("user_state");
    u["id"] = c->id();
    u["mic"] = c->micMuted();
    u["spk"] = c->spkMuted();
    u["away"] = c->away();
    u["rec"] = c->recording();
    u["cc"] = c->commander();
    broadcast(u);
}

void ServerCore::handleNick(ClientSession* c, const QJsonObject& obj) {
    const QString name = obj["name"].toString().trimmed();
    if (!validHumanText(name, 30, false)) { sendError(c, "bad_nick", "Apelido inválido"); return; }
    if (name == c->name()) return;
    for (ClientSession* other : m_clients)
        if (other != c && other->name().compare(name, Qt::CaseInsensitive) == 0) {
            sendError(c, "name_in_use", "Apelido já em uso");
            return;
        }
    c->setName(name);
    if (!c->uniqueId().isEmpty() && m_registry.contains(c->uniqueId()))
        m_registry[c->uniqueId()].name = name;
    QJsonObject m = HProto::msg("user_nick");
    m["id"] = c->id();
    m["name"] = name;
    broadcast(m);
}

void ServerCore::handleDesc(ClientSession* c, const QJsonObject& obj) {
    const QString text = obj["text"].toString();
    if (!validOptionalText(text, 200, true)) { sendError(c, "bad_text", "Descrição inválida"); return; }
    c->setDescription(text);
    QJsonObject m = HProto::msg("user_desc");
    m["id"] = c->id();
    m["text"] = c->description();
    broadcast(m);
}

void ServerCore::handlePoke(ClientSession* c, const QJsonObject& obj) {
    if (!hasPerm(c, "poke")) {
        sendError(c, "no_permission", "Sem permissão para cutucar");
        return;
    }
    const int to = obj["to"].toInt();
    if (!m_clients.contains(to)) return;
    const QString pokeMsg = obj["msg"].toString();
    if (!validOptionalText(pokeMsg, 100, false)) { sendError(c, "bad_text", "Mensagem inválida"); return; }
    QJsonObject m = HProto::msg("poke");
    m["from"] = c->id();
    m["fromName"] = c->name();
    m["msg"] = pokeMsg;
    m_clients[to]->send(m);
    c->send(m); // eco
}

void ServerCore::handleVolume(ClientSession*, const QJsonObject&) {
    // volume local — o cliente aplica localmente; nada a fazer no servidor
}

void ServerCore::handleChanCreate(ClientSession* c, const QJsonObject& obj) {
    const int type = obj["type"].toInt(2);
    // permissão granular por tipo de canal
    const char* perm = (type == 0) ? "chanCreateTemp"
                     : (type == 1) ? "chanCreateSemi" : "chanCreatePerm";
    if (!hasPerm(c, perm)) {
        sendError(c, "no_permission",
                  QStringLiteral("Sem permissão para criar canais do tipo %1")
                      .arg(type == 0 ? "temporário" : (type == 1 ? "semi-permanente" : "permanente")));
        return;
    }

    const QString name = obj["name"].toString();
    // Aceita espaços iniciais/finais decorativos, mas rejeita nome composto
    // somente de espaço.
    if (!validHumanText(name, 80, false)) { sendError(c, "bad_channel_name", "Nome de canal inválido"); return; }

    SvrChan ch;
    ch.id = m_nextChanId++;
    ch.parent = obj["parent"].toInt(0);
    if (ch.parent != 0 && !m_channels.contains(ch.parent)) ch.parent = 0;
    if (ch.parent != 0 && !hasChannelPerm(c, ch.parent, QStringLiteral("channel_create"))) {
        sendError(c, "no_permission", "Sem permissão para criar canais neste canal");
        return;
    }
    if (ch.parent != 0 && type == 0
            && !hasChannelPerm(c, ch.parent, QStringLiteral("chan_create_temp"))) {
        sendError(c, "no_permission", "Sem permissão para criar canais temporários aqui");
        return;
    }
    ch.name = name;
    ch.noSymbol = obj["noSymbol"].toBool(false);
    if (obj.contains("order")) {
        ch.order = qMax(0, obj["order"].toInt());
    } else {
        for (const SvrChan& sibling : m_channels)
            if (sibling.parent == ch.parent) ch.order = qMax(ch.order, sibling.order + 10);
    }
    ch.topic = obj["topic"].toString();
    ch.desc = obj["desc"].toString();
    const QString channelPassword = obj["pass"].toString();
    if (!validOptionalText(ch.topic, 80, false)
            || !validOptionalText(ch.desc, 4096, true)
            || !validOptionalText(channelPassword, 128, false)) {
        sendError(c, "bad_channel_fields", "Campos do canal inválidos");
        return;
    }
    ch.password = channelPassword.isEmpty() ? QString() : PasswordHash::create(channelPassword);
    if (!channelPassword.isEmpty() && ch.password.isEmpty()) {
        sendError(c, "crypto_error", "Não foi possível proteger a senha do canal");
        return;
    }
    ch.def = false;
    ch.moderated = obj["moderated"].toBool(false);
    ch.ntalk = qBound(0, obj["ntalk"].toInt(0), 100);
    ch.type = type;
    ch.codec = qBound(0, obj["codec"].toInt(4), 5);
    ch.quality = qBound(0, obj["quality"].toInt(6), 10);
    ch.bitrate = qBound(16, obj["bitrate"].toInt(96), 384);
    if (obj.contains("groupPerms")) ch.groupPerms = obj["groupPerms"].toObject();
    ch.maxClients = obj["max"].toInt(-1);
    ch.ops << c->uniqueId(); // v3: criador vira operador do canal
    m_channels[ch.id] = ch;
    saveData();

    QJsonObject m = HProto::msg("chan_update");
    m["chan"] = chanToJson(ch);
    broadcast(m);
}

void ServerCore::handleChanMove(ClientSession* c, const QJsonObject& obj) {
    const int id = obj["id"].toInt();
    const int parent = obj["parent"].toInt(0);
    if (!m_channels.contains(id) || id == 1) return;
    if (parent != 0 && !m_channels.contains(parent)) return;
    if (!hasPerm(c, "chanEdit") && !isChanOp(c, id)) {
        sendError(c, "no_permission", "Sem permissão para reordenar canais");
        return;
    }
    // Impede colocar um canal dentro de si mesmo ou de um descendente.
    for (int p = parent; p != 0 && m_channels.contains(p); p = m_channels[p].parent) {
        if (p == id) {
            sendError(c, "invalid_parent", "Um canal não pode ser colocado dentro de sua própria árvore");
            return;
        }
    }

    QList<int> siblings;
    for (const SvrChan& sibling : m_channels)
        if (sibling.parent == parent && sibling.id != id) siblings << sibling.id;
    std::sort(siblings.begin(), siblings.end(), [&](int a, int b) {
        if (m_channels[a].order != m_channels[b].order)
            return m_channels[a].order < m_channels[b].order;
        return m_channels[a].name.localeAwareCompare(m_channels[b].name) < 0;
    });
    const int position = qBound(0, obj["order"].toInt(siblings.size()), siblings.size());
    siblings.insert(position, id);
    for (int i = 0; i < siblings.size(); ++i) {
        m_channels[siblings[i]].parent = parent;
        m_channels[siblings[i]].order = i * 10;
    }
    saveData();
    for (int siblingId : siblings) {
        QJsonObject m = HProto::msg("chan_update");
        m["chan"] = chanToJson(m_channels[siblingId]);
        broadcast(m);
    }
}

void ServerCore::handleChanLink(ClientSession* c, const QJsonObject& obj) {
    QList<int> ids;
    QSet<int> seen;
    for (const QJsonValue& value : obj["ids"].toArray()) {
        const int id = value.toInt();
        if (id > 0 && !seen.contains(id)) {
            seen.insert(id);
            ids << id;
        }
    }
    if (ids.size() < 2) {
        sendError(c, "invalid_channels", "Selecione pelo menos dois canais para vincular");
        return;
    }
    for (int id : ids) {
        if (!m_channels.contains(id)) {
            sendError(c, "invalid_channel", "Um dos canais selecionados não existe mais");
            return;
        }
    }

    // Vincular canais altera a rota de áudio de cada canal. A permissão
    // existente de edição de canal é usada; operadores só podem fazer isso
    // quando controlam todos os canais selecionados (e não o canal padrão).
    bool operatorOfAll = true;
    for (int id : ids) {
        if (id == 1 || !isChanOp(c, id)) {
            operatorOfAll = false;
            break;
        }
    }
    if (!hasPerm(c, "chanEdit") && !operatorOfAll) {
        sendError(c, "no_permission", "Sem permissão para vincular canais");
        return;
    }

    const bool link = obj.contains("link") ? obj["link"].toBool() : true;
    for (int i = 0; i < ids.size(); ++i) {
        for (int j = i + 1; j < ids.size(); ++j) {
            SvrChan& a = m_channels[ids[i]];
            SvrChan& b = m_channels[ids[j]];
            if (link) {
                if (!a.linkedChannels.contains(b.id)) a.linkedChannels << b.id;
                if (!b.linkedChannels.contains(a.id)) b.linkedChannels << a.id;
            } else {
                a.linkedChannels.removeAll(b.id);
                b.linkedChannels.removeAll(a.id);
            }
        }
    }

    // Alterar vínculos muda o conjunto de ouvintes; rotaciona a chave dos
    // componentes afetados para manter forward secrecy básica.
    for (int id : ids) rotateChannelKey(id);

    saveData();
    for (int id : ids) {
        QJsonObject update = HProto::msg("chan_update");
        update["chan"] = chanToJson(m_channels[id]);
        broadcast(update);
    }
    log(QStringLiteral("Canais %1 %2 foram %3")
            .arg(ids.size())
            .arg(link ? QStringLiteral("vinculados") : QStringLiteral("desvinculados"))
            .arg(c->name()));
}

void ServerCore::handleChanEdit(ClientSession* c, const QJsonObject& obj) {
    const int id = obj["id"].toInt();
    if (!m_channels.contains(id)) return;
    // v3: operador do canal pode editar o próprio canal (exceto o padrão)
    if (!hasPerm(c, "chanEdit") && !(id != 1 && isChanOp(c, id))) {
        sendError(c, "no_permission", "Sem permissão para editar canais");
        return;
    }
    // operadores de canal podem promover/rebaixar outros operadores (por UID)
    if (obj.contains("op_add") || obj.contains("op_del")) {
        if (!hasPerm(c, "chanEdit") && !isChanOp(c, id)) {
            sendError(c, "no_permission", "Sem permissão para gerenciar operadores");
            return;
        }
        const QString targetUid = obj["uid"].toString();
        SvrChan& chan = m_channels[id];
        if (obj.contains("op_add") && !targetUid.isEmpty() && !chan.ops.contains(targetUid))
            chan.ops << targetUid;
        if (obj.contains("op_del")) chan.ops.removeAll(targetUid);
        saveData();
        QJsonObject m = HProto::msg("chan_update");
        m["chan"] = chanToJson(chan);
        broadcast(m);
        return;
    }
    SvrChan& ch = m_channels[id];
    if (obj.contains("name")) {
        const QString name = obj["name"].toString();
        if (!validHumanText(name, 80, false)) { sendError(c, "bad_channel_name", "Nome de canal inválido"); return; }
        ch.name = name;
    }
    if (obj.contains("noSymbol")) ch.noSymbol = obj["noSymbol"].toBool();
    if (obj.contains("topic")) {
        const QString topic = obj["topic"].toString();
        if (!validOptionalText(topic, 80, false)) { sendError(c, "bad_channel_fields", "Tópico inválido"); return; }
        ch.topic = topic;
    }
    if (obj.contains("desc")) {
        const QString desc = obj["desc"].toString();
        if (!validOptionalText(desc, 4096, true)) { sendError(c, "bad_channel_fields", "Descrição de canal inválida"); return; }
        ch.desc = desc;
    }
    if (obj.contains("pass")) {
        const QString pass = obj["pass"].toString();
        if (!validOptionalText(pass, 128, false)) { sendError(c, "bad_channel_fields", "Senha de canal inválida"); return; }
        ch.password = pass.isEmpty() ? QString() : PasswordHash::create(pass);
        if (!pass.isEmpty() && ch.password.isEmpty()) { sendError(c, "crypto_error", "Não foi possível proteger a senha do canal"); return; }
    }
    if (obj.contains("moderated")) ch.moderated = obj["moderated"].toBool();
    if (obj.contains("ntalk")) ch.ntalk = qBound(0, obj["ntalk"].toInt(), 100);
    if (obj.contains("type") && id != 1) ch.type = obj["type"].toInt();
    if (obj.contains("codec")) ch.codec = qBound(0, obj["codec"].toInt(), 5);
    if (obj.contains("quality")) ch.quality = qBound(0, obj["quality"].toInt(), 10);
    if (obj.contains("bitrate")) ch.bitrate = qBound(16, obj["bitrate"].toInt(96), 384);
    if (obj.contains("groupPerms")) ch.groupPerms = obj["groupPerms"].toObject();
    if (obj.contains("max")) ch.maxClients = obj["max"].toInt();
    saveData();

    QJsonObject m = HProto::msg("chan_update");
    m["chan"] = chanToJson(ch);
    broadcast(m);
}

void ServerCore::handleChanDelete(ClientSession* c, const QJsonObject& obj) {
    const int id = obj["id"].toInt();
    if (!m_channels.contains(id) || id == 1) return;
    if (!hasPerm(c, "chanDelete")) {
        sendError(c, "no_permission", "Sem permissão para excluir canais");
        return;
    }
    // sub-canais impedem exclusão
    for (const SvrChan& ch : m_channels)
        if (ch.parent == id) {
            sendError(c, "has_children", "Exclua primeiro os sub-canais");
            return;
        }
    // move usuários para o padrão
    for (int uid : m_channels[id].users) {
        removeFromChannels(uid);
        m_channels[1].users << uid;
        QJsonObject m = HProto::msg("user_moved");
        m["id"] = uid; m["channel"] = 1; m["by"] = 0;
        broadcast(m);
    }
    m_channels.remove(id);
    QList<int> linkAffected;
    for (SvrChan& other : m_channels) {
        if (other.linkedChannels.removeAll(id) > 0) linkAffected << other.id;
    }
    removeChannelFiles(id); // v3: apaga arquivos do canal
    saveData();
    QJsonObject m = HProto::msg("chan_removed");
    m["id"] = id;
    broadcast(m);
    for (int affectedId : linkAffected) {
        QJsonObject update = HProto::msg("chan_update");
        update["chan"] = chanToJson(m_channels[affectedId]);
        broadcast(update);
    }
}

void ServerCore::handleKick(ClientSession* c, const QJsonObject& obj) {
    const int id = obj["id"].toInt();
    const bool fromServer = obj["from"].toString() == "server";
    // v3: kick de CANAL também é permitido ao operador do canal da vítima
    const bool chanKickByOp = !fromServer && m_clients.contains(id)
                              && isChanOp(c, channelOfUser(id));
    if (!hasPerm(c, "kick") && !chanKickByOp) {
        sendError(c, "no_permission", "Sem permissão para expulsar");
        return;
    }
    if (!m_clients.contains(id) || id == c->id()) return;
    // operador não expulsa outro operador do mesmo canal
    if (chanKickByOp && !hasPerm(c, "kick")
            && m_channels[channelOfUser(id)].ops.contains(m_clients[id]->uniqueId())) {
        sendError(c, "no_permission", "Você não pode expulsar outro operador");
        return;
    }
    // não-administrador supremo não expulsa administrador supremo
    if (!hasPerm(c, "*") && hasPerm(m_clients[id], "*")) {
        sendError(c, "no_permission", "Você não pode expulsar este cliente");
        return;
    }
    // Pilar 1: Verificação de hierarquia - só pode kickar quem está abaixo na hierarquia
    if (!canManageClient(c, m_clients[id])) {
        sendError(c, "no_permission", "Você não tem posição hierárquica suficiente para expulsar este cliente");
        return;
    }
    doKick(m_clients[id], obj["reason"].toString(), fromServer, false);
}

void ServerCore::handleBan(ClientSession* c, const QJsonObject& obj) {
    if (!hasPerm(c, "ban")) {
        sendError(c, "no_permission", "Sem permissão para banir");
        return;
    }
    const int id = obj["id"].toInt();
    if (!m_clients.contains(id) || id == c->id()) return;
    if (!hasPerm(c, "*") && hasPerm(m_clients[id], "*")) {
        sendError(c, "no_permission", "Você não pode banir este cliente");
        return;
    }
    // Pilar 1: Verificação de hierarquia - só pode banir quem está abaixo na hierarquia
    if (!canManageClient(c, m_clients[id])) {
        sendError(c, "no_permission", "Você não tem posição hierárquica suficiente para banir este cliente");
        return;
    }
    const int minutes = obj["minutes"].toInt(0);

    BanEntry b;
    b.uid = m_clients[id]->uniqueId();
    b.ip = m_clients[id]->ip().toString();
    b.name = m_clients[id]->name();
    b.reason = obj["reason"].toString();
    if (minutes > 0) b.expires = QDateTime::currentDateTime().addSecs(qint64(minutes) * 60);
    m_bans << b;
    saveBans();

    doKick(m_clients[id], b.reason, true, true, minutes);
}

void ServerCore::handleBanList(ClientSession* c) {
    if (!hasPerm(c, "banList")) {
        sendError(c, "no_permission", "Sem permissão para ver a lista de banidos");
        return;
    }
    QJsonObject m = HProto::msg("banlist");
    QJsonArray arr;
    for (const BanEntry& b : m_bans) {
        QJsonObject o;
        o["uid"] = b.uid; o["ip"] = b.ip; o["name"] = b.name; o["reason"] = b.reason;
        if (b.expires.isValid()) o["expires"] = b.expires.toString(Qt::ISODate);
        arr << o;
    }
    m["bans"] = arr;
    c->send(m);
}

void ServerCore::handleUnban(ClientSession* c, const QJsonObject& obj) {
    if (!hasPerm(c, "ban")) {
        sendError(c, "no_permission", "Sem permissão para remover banimentos");
        return;
    }
    const QString uid = obj["uid"].toString();
    int removed = 0;
    for (int i = m_bans.size() - 1; i >= 0; --i)
        if (m_bans[i].uid == uid) { m_bans.removeAt(i); ++removed; }
    if (removed > 0) {
        saveBans();
        QJsonObject m = HProto::msg("ban_removed");
        m["uid"] = uid;
        c->send(m);
        log(QStringLiteral("%1 removeu banimento de %2").arg(c->name(), uid.left(16)));
    } else {
        sendError(c, "not_found", "Banimento não encontrado");
    }
}

void ServerCore::handlePrivkey(ClientSession* c, const QJsonObject& obj) {
    const QString key = obj["key"].toString();
    if (!m_privKeyGroup.contains(key)) {
        sendError(c, "bad_privkey", "Chave de privilégio inválida");
        return;
    }
    if (!m_privKeyReuse && m_usedKeys.contains(key)) {
        sendError(c, "privkey_used",
                  "Esta chave de privilégio já foi utilizada");
        return;
    }
    m_usedKeys.insert(key);
    // Chave de privilégio concede poder individual total sem trocar cargo,
    // grupo, ícone ou ordem do usuário.
    m_privilegedUids.insert(c->uniqueId());
    saveData();
    QJsonObject granted = HProto::msg("privilege_granted");
    granted["individual"] = true;
    c->send(granted);
    log(QStringLiteral("Cliente #%1 (%2) usou chave de privilégio -> permissões individuais totais")
            .arg(c->id()).arg(c->name()));
}

// ------------------------------------------------- grupos via protocolo (v2)
void ServerCore::handleGroupList(ClientSession* c) {
    QJsonObject m = HProto::msg("group_list");
    QJsonArray arr;
    for (const GroupDef& g : m_groups) {
        QJsonObject group = groupToJson(g);
        QJsonArray members;
        for (auto it = m_registry.cbegin(); it != m_registry.cend(); ++it) {
            const QString uid = it.key();
            QList<int> assigned = m_assignByUid.value(uid);
            if (assigned.isEmpty()) {
                assigned << 2;
            } else if (!assigned.contains(1) && !assigned.contains(2)) {
                assigned.prepend(2);
            }
            bool hasGroup = assigned.contains(g.id);
            if (!hasGroup) continue;
            QJsonObject member;
            member["uid"] = uid;
            member["name"] = it.value().name;
            member["online"] = false;
            members << member;
        }
        for (ClientSession* online : m_clients) {
            QList<int> assigned = m_assignByUid.value(online->uniqueId());
            if (assigned.isEmpty()) {
                assigned << 2;
            } else if (!assigned.contains(1) && !assigned.contains(2)) {
                assigned.prepend(2);
            }
            bool hasGroup = assigned.contains(g.id);
            if (!hasGroup) continue;
            bool already = false;
            for (const QJsonValue& v : members)
                if (v.toObject().value("uid").toString() == online->uniqueId()) already = true;
            if (already) continue;
            QJsonObject member;
            member["id"] = online->id();
            member["uid"] = online->uniqueId();
            member["name"] = online->name();
            member["online"] = true;
            members << member;
        }
        group["members"] = members;
        arr << group;
    }
    m["groups"] = arr;
    c->send(m);
}

void ServerCore::handleGroupSet(ClientSession* c, const QJsonObject& obj) {
    if (!hasPerm(c, "groupEdit")) {
        sendError(c, "no_permission", "Sem permissão para gerenciar grupos");
        return;
    }
    const QString name = obj["name"].toString().trimmed().left(30);
    const QJsonObject perms = obj["perms"].toObject();

    GroupDef g;
    const int id = obj["id"].toInt(0);
    if (id > 0) {
        // edição: name é opcional (permite mudar só permissões)
        if (!m_groups.contains(id)) { sendError(c, "not_found", "Grupo não encontrado"); return; }
        g = m_groups[id];
        // proteção anti-lockout: não deixar remover "*" de grupo que tinha "*"
        if (obj.contains("perms") && g.perms.value("*").toBool() && !perms.value("*").toBool()) {
            sendError(c, "locked", "Não é possível remover a permissão total (*) deste grupo");
            return;
        }
        if (obj.contains("name") && !name.isEmpty()) g.name = name;
        if (obj.contains("perms")) g.perms = perms;
        if (obj.contains("sigla")) g.sigla = obj["sigla"].toString();
        if (obj.contains("order")) g.order = obj["order"].toInt(0);
        if (obj.contains("icon")) g.icon = obj["icon"].toString();
        // Pilar 1: position hierárquica
        if (obj.contains("position")) g.position = obj["position"].toInt(0);
        m_groups[id] = g;
    } else {
        if (name.isEmpty()) return; // criação exige nome
        g.id = m_nextGroupId++;
        g.name = name;
        g.perms = perms;
        g.sigla = obj["sigla"].toString();
        g.order = obj["order"].toInt(0);
        g.icon = obj["icon"].toString();
        // Pilar 1: position hierárquica (padrão baseado no próximo grupo)
        g.position = obj["position"].toInt(g.order * 10);
        if (g.perms.value("*").toBool() && !hasPerm(c, "*")) {
            sendError(c, "no_permission", "Apenas administradores (*) criam grupos com *");
            return;
        }
        m_groups[g.id] = g;
    }
    saveData();
    // clientes com este grupo mudam de rótulo se as propriedades mudaram
    for (ClientSession* o : m_clients)
        if (o->groupId() == g.id) {
            o->setGroup(g.name);
            o->setSigla(g.sigla);
            o->setIcon(g.icon);
            o->setGroupOrder(g.order);
            o->setGroupPosition(g.position);  // Pilar 1
            QJsonObject m = HProto::msg("user_group");
            m["id"] = o->id(); 
            m["group"] = o->group(); 
            m["gid"] = g.id;
            m["sigla"] = g.sigla;
            m["icon"] = g.icon;
            m["order"] = g.order;
            m["position"] = g.position;  // Pilar 1
            broadcast(m);
        }
    broadcastGroups();
    log(QStringLiteral("Grupo \"%1\" (#%2) %3 por %4")
            .arg(g.name).arg(g.id).arg(id > 0 ? "atualizado" : "criado", c->name()));
}

void ServerCore::handleGroupDelete(ClientSession* c, const QJsonObject& obj) {
    if (!hasPerm(c, "groupEdit")) {
        sendError(c, "no_permission", "Sem permissão para gerenciar grupos");
        return;
    }
    const int id = obj["id"].toInt();
    if (id < 100 || !m_groups.contains(id)) {
        sendError(c, "locked", "Grupos internos não podem ser excluídos");
        return;
    }
    m_groups.remove(id);
    for (auto it = m_assignByUid.begin(); it != m_assignByUid.end(); ++it) {
        it.value().removeAll(id);
        if (it.value().isEmpty()) {
            it.value() << 2; // normal por padrão se ficou sem nenhum
        }
    }
    for (ClientSession* o : m_clients) {
        QList<int> gids = m_assignByUid.value(o->uniqueId());
        if (gids.contains(id) || o->groupId() == id) {
            applyGroup(o, 0, true);
        }
    }
    saveData();
    broadcastGroups();
}

void ServerCore::handleClientSetGroup(ClientSession* c, const QJsonObject& obj) {
    if (!hasPerm(c, "groupEdit")) {
        sendError(c, "no_permission", "Sem permissão para atribuir grupos");
        return;
    }
    const int gid = obj["gid"].toInt();
    if (!m_groups.contains(gid)) { sendError(c, "not_found", "Grupo não encontrado"); return; }
    // só super-admin (*) eleva outros ao grupo *
    if (m_groups[gid].perms.value("*").toBool() && !hasPerm(c, "*")) {
        sendError(c, "no_permission", "Apenas administradores (*) atribuem este grupo");
        return;
    }

    // alvo por id online ou por uid offline
    QString targetUid = obj["uid"].toString();
    if (obj.contains("id")) {
        const int cid = obj["id"].toInt();
        if (!m_clients.contains(cid)) return;
        ClientSession* t = m_clients[cid];
        targetUid = t->uniqueId();
    } else if (m_registry.contains(targetUid)) {
        // offline: só persiste
    } else if (targetUid.isEmpty()) {
        return;
    }
    if (!targetUid.isEmpty()) {
        QList<int>& list = m_assignByUid[targetUid];
        if (list.contains(gid)) {
            if (list.size() > 1) {
                list.removeAll(gid);
            } else if (gid != 2) {
                list.clear();
                list << 2;
            }
        } else {
            // Remove o cargo "normal" se o usuário estiver ganhando outro cargo que não seja ele,
            // ou apenas adicione. Vamos apenas adicionar para que eles possam ter múltiplos cargos!
            list << gid;
        }
        
        // Aplica o novo estado ao cliente online se conectado
        if (obj.contains("id")) {
            const int cid = obj["id"].toInt();
            if (m_clients.contains(cid)) {
                ClientSession* t = m_clients[cid];
                applyGroup(t, 0, true);
            }
        }
        
        saveData();
        log(QStringLiteral("%1 alterou cargos do UID %2: %3")
                .arg(c->name(), targetUid.left(16), QString::number(gid)));
        broadcastGroups();
    }
}

void ServerCore::handleServerEdit(ClientSession* c, const QJsonObject& obj) {
    if (!hasPerm(c, "serverEdit")) {
        sendError(c, "no_permission", "Sem permissão para editar o servidor");
        return;
    }
    if (obj.contains("name")) {
        const QString n = obj["name"].toString().trimmed().left(40);
        if (!n.isEmpty() && n != m_name) {
            m_name = n;
            log(QStringLiteral("Nome do servidor alterado para \"%1\" por %2").arg(n, c->name()));
        }
    }
    if (obj.contains("motd")) m_motd = obj["motd"].toString().left(200);

    bool bannerChanged = false;
    if (obj.contains("banner")) {
        const QString encoded = obj["banner"].toString();
        const QByteArray decoded = QByteArray::fromBase64(encoded.toLatin1());
        if (!encoded.isEmpty() && decoded.isEmpty()) {
            sendError(c, "invalid_banner", "Imagem de banner inválida");
            return;
        }
        if (decoded.size() > 512 * 1024) {
            sendError(c, "banner_too_big", "O banner excede o limite de 512 KiB");
            return;
        }
        const bool isPng = decoded.startsWith(QByteArray("\x89PNG\x0D\x0A\x1A\x0A", 8));
        const bool isJpeg = decoded.startsWith(QByteArray("\xFF\xD8\xFF", 3));
        const bool isGif = decoded.startsWith("GIF8");
        const bool isWebp = decoded.size() >= 12 && decoded.left(4) == "RIFF"
                         && decoded.mid(8, 4) == "WEBP";
        if (!decoded.isEmpty() && !(isPng || isJpeg || isGif || isWebp)) {
            sendError(c, "invalid_banner", "Use uma imagem PNG, JPEG, GIF ou WebP");
            return;
        }
        m_serverBanner = decoded;
        if (!saveServerBanner()) {
            sendError(c, "io_error", "Não foi possível salvar o banner do servidor");
            return;
        }
        bannerChanged = true;
    }

    saveData();
    QJsonObject m = HProto::msg("server_edit");
    m["name"] = m_name;
    m["motd"] = m_motd;
    if (bannerChanged)
        m["banner"] = QString::fromLatin1(m_serverBanner.toBase64());
    broadcast(m);
}

void ServerCore::doKick(ClientSession* c, const QString& reason, bool fromServer,
                        bool ban, int minutes) {
    QJsonObject k = HProto::msg("kicked");
    k["reason"] = reason;
    k["ban"] = ban;
    if (ban && minutes > 0) k["minutes"] = minutes;
    c->send(k);

    log(QStringLiteral("Cliente #%1 (%2) %3%4")
            .arg(c->id()).arg(c->name())
            .arg(ban ? "foi banido" : (fromServer ? "foi expulso do servidor" : "foi expulso do canal"))
            .arg(reason.isEmpty() ? QString() : QStringLiteral(" (%1)").arg(reason)));

    removeFromChannels(c->id());
    if (!fromServer && !ban) {
        // kick de canal: usuário continua conectado, volta ao padrão
        m_channels[1].users << c->id();
        QJsonObject m = HProto::msg("user_moved");
        m["id"] = c->id(); m["channel"] = 1; m["by"] = 0;
        m["reason"] = reason;
        broadcast(m);
    } else {
        QJsonObject left = HProto::msg("user_left");
        left["id"] = c->id();
        left["reason"] = ban ? "banned" : "kicked";
        broadcast(left, c->id());
        m_clients.remove(c->id());
        releaseVoiceToken(c);
        c->closeAndDelete();
    }
}

// ==================================================================== util
void ServerCore::broadcast(const QJsonObject& obj, int exceptId) {
    for (ClientSession* c : m_clients)
        if (c->id() != exceptId) c->send(obj);
}

int ServerCore::channelOfUser(int userId) const {
    for (const SvrChan& c : m_channels)
        if (c.users.contains(userId)) return c.id;
    return 0;
}

void ServerCore::removeFromChannels(int userId) {
    for (SvrChan& c : m_channels) {
        if (c.users.contains(userId)) {
            c.users.removeAll(userId);
            rotateChannelKey(c.id);
        }
    }
}

void ServerCore::addToChannel(int userId, int channelId) {
    removeFromChannels(userId);
    if (m_channels.contains(channelId)) {
        m_channels[channelId].users << userId;
        rotateChannelKey(channelId);
    }
}

ServerCore::SvrChan ServerCore::chanFromJson(const QJsonObject& o) const {
    SvrChan c;
    c.id = o["id"].toInt(1);
    c.parent = o["parent"].toInt(0);
    c.name = o["name"].toString();
    c.topic = o["topic"].toString();
    c.desc = o["desc"].toString();
    c.password = o["password"].toString();
    c.def = o["def"].toBool(false);
    c.moderated = o["moderated"].toBool(false);
    c.ntalk = o["ntalk"].toInt(0);
    c.type = o["type"].toInt(2);
    c.codec = o["codec"].toInt(4);
    c.quality = o["quality"].toInt(6);
    c.maxClients = o["max"].toInt(-1);
    c.bitrate = qBound(16, o["bitrate"].toInt(96), 384);
    c.noSymbol = o["noSymbol"].toBool(false);
    c.order = o["order"].toInt(0);
    for (const QJsonValue& v : o["linked"].toArray()) {
        const int linkedId = v.toInt();
        if (linkedId > 0 && linkedId != c.id && !c.linkedChannels.contains(linkedId))
            c.linkedChannels << linkedId;
    }
    for (const QJsonValue& v : o["ops"].toArray()) c.ops << v.toString();
    // Pilar 1: Carrega requisitos de position por grupo do canal
    if (o.contains("groupPositionReqs")) {
        c.groupPositionReqs = o["groupPositionReqs"].toObject();
    }
    // Pilar 3: Carrega groupPerms (pode conter estados Allow/Deny/Inherit)
    if (o.contains("groupPerms")) {
        c.groupPerms = o["groupPerms"].toObject();
    }
    return c;
}

QJsonObject ServerCore::chanToJson(const SvrChan& c) const {
    QJsonObject j = HProto::chanJson(c.id, c.parent, c.name, c.topic, c.desc,
                                     !c.password.isEmpty(), c.id == 1, c.type, c.moderated,
                                     c.codec, c.quality, c.maxClients, c.users);
    j["ntalk"] = c.ntalk;
    j["bitrate"] = c.bitrate;
    j["noSymbol"] = c.noSymbol;
    j["order"] = c.order;
    QJsonArray linked;
    for (int linkedId : c.linkedChannels) linked << linkedId;
    j["linked"] = linked;
    QJsonArray ops;
    for (const QString& u : c.ops) ops << u;
    j["ops"] = ops;
    // Pilar 1: Requisitos de position por grupo no canal
    if (!c.groupPositionReqs.isEmpty()) {
        j["groupPositionReqs"] = c.groupPositionReqs;
    }
    // Pilar 3: Permissões de canal com estados Allow/Deny/Inherit
    if (!c.groupPerms.isEmpty()) {
        j["groupPerms"] = c.groupPerms;
    }
    return j;
}

// ================================================== helpers v3
QString ServerCore::dataDir() const {
    if (m_dataFile.isEmpty()) return QDir::currentPath();
    return QFileInfo(m_dataFile).absolutePath();
}

QString ServerCore::serverBannerPath() const {
    return dataDir() + QStringLiteral("/server-banner.bin");
}

void ServerCore::loadServerBanner() {
    m_serverBanner.clear();
    QFile f(serverBannerPath());
    if (!f.exists()) return;
    if (!f.open(QIODevice::ReadOnly)) {
        log(QStringLiteral("Não foi possível abrir o banner do servidor"));
        return;
    }
    const QByteArray bytes = f.read(512 * 1024 + 1);
    if (bytes.size() > 512 * 1024) {
        log(QStringLiteral("Banner do servidor ignorado: arquivo maior que 512 KiB"));
        return;
    }
    m_serverBanner = bytes;
}

bool ServerCore::saveServerBanner() {
    if (m_serverBanner.isEmpty()) {
        return !QFile::remove(serverBannerPath()) || !QFile::exists(serverBannerPath());
    }
    QDir().mkpath(dataDir());
    QFile f(serverBannerPath());
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) return false;
    return f.write(m_serverBanner) == m_serverBanner.size();
}

QString ServerCore::avatarPath(const QString& uid) const {
    // uid é base64: trocar caracteres problemáticos de nome de arquivo
    QString safe = uid;
    safe.replace('/', '_').replace('+', '-');
    return dataDir() + QStringLiteral("/avatars/%1.avt").arg(safe);
}

QString ServerCore::iconPath(const QString& name) const {
    QString safe = sanitizeFileName(name);
    return dataDir() + QStringLiteral("/icons/%1").arg(safe);
}

QString ServerCore::filesDir(int chan) const {
    return dataDir() + QStringLiteral("/files/%1").arg(chan);
}

QString ServerCore::sanitizeFileName(const QString& n) {
    QString out;
    for (const QChar& ch : n.left(60))
        if (ch.isLetterOrNumber() || ch == QLatin1Char('.') || ch == QLatin1Char('_')
                || ch == QLatin1Char('-') || ch == QLatin1Char(' '))
            out += ch;
    if (out.isEmpty() || out.startsWith(QLatin1Char('.'))) out.prepend(QLatin1Char('_'));
    return out;
}

bool ServerCore::isChanOp(const ClientSession* c, int channelId) const {
    if (!c || !m_channels.contains(channelId)) return false;
    return m_channels[channelId].ops.contains(c->uniqueId());
}

void ServerCore::removeChannelFiles(int chan) {
    for (int i = m_files.size() - 1; i >= 0; --i)
        if (m_files[i].chan == chan) m_files.removeAt(i);
    QDir(filesDir(chan)).removeRecursively();
}

void ServerCore::loadAvatars() {
    m_avatarHash.clear();
    QDir d(dataDir() + QStringLiteral("/avatars"));
    for (const QFileInfo& fi : d.entryInfoList({QStringLiteral("*.avt")}, QDir::Files)) {
        QString uid = fi.completeBaseName();
        uid.replace('_', '/').replace('-', '+');
        // hash = sha1 do conteúdo
        QFile f(fi.absoluteFilePath());
        if (f.open(QIODevice::ReadOnly))
            m_avatarHash[uid] = QString::fromLatin1(
                QCryptographicHash::hash(f.readAll(), QCryptographicHash::Sha1).toHex());
    }
}

QJsonObject ServerCore::voiceStats() const {
    return m_voice ? m_voice->stats() : QJsonObject{};
}

void ServerCore::relayVoice(ClientSession* sender, quint16 seq, const QByteArray& payload) {
    if (!sender || !m_voice || payload.isEmpty()) return;
    const int chan = channelOfUser(sender->id());
    if (chan == 0 || !m_channels.contains(chan)) return;

    // A permissão de fala continua sendo avaliada no canal em que o remetente
    // está. O vínculo somente amplia os canais que escutam esse áudio.
    if (!canTalkIn(sender, chan)) return;

    // Monta o componente conectado do canal de origem. Isso permite que uma
    // seleção A+B+C continue funcionando mesmo que os vínculos tenham sido
    // criados em operações diferentes (A-B e depois B-C).
    QSet<int> linked;
    QList<int> pending;
    linked.insert(chan);
    pending << chan;
    while (!pending.isEmpty()) {
        const int current = pending.takeFirst();
        if (!m_channels.contains(current)) continue;
        for (int next : m_channels[current].linkedChannels) {
            if (m_channels.contains(next) && !linked.contains(next)) {
                linked.insert(next);
                pending << next;
            }
        }
        // Aceita também bancos antigos eventualmente assimétricos e corrige a
        // entrega sem exigir que o administrador refaça os vínculos.
        for (const SvrChan& candidate : m_channels) {
            if (candidate.linkedChannels.contains(current) && !linked.contains(candidate.id)) {
                linked.insert(candidate.id);
                pending << candidate.id;
            }
        }
    }

    const QSet<int> whisper = sender->whisperIds();   // v3: sussurro para alvos específicos
    const QByteArray packet = HProto::encodeVoiceServer(quint32(sender->id()), seq, payload);
    for (ClientSession* c : m_clients) {
        if (c == sender) continue;
        if (c->udpPort() == 0) continue;
        const int targetChan = channelOfUser(c->id());
        if (targetChan == 0) continue;
        if (!whisper.isEmpty()) {
            if (!whisper.contains(c->id())) continue;        // sussurro: só os alvos
        } else if (!linked.contains(targetChan)) continue;   // canal ou vínculo
        if (!hasChannelPerm(c, targetChan, QStringLiteral("listen"))) continue;
        m_voice->sendTo(c->udpAddress(), c->udpPort(), packet);
    }
}

void ServerCore::relayScreenShare(ClientSession* sender, quint16 seq, const QByteArray& payload) {
    if (!sender || !m_voice || !m_allowScreenShare || payload.isEmpty()) return;

    QByteArray p;
    p.reserve(10 + payload.size());
    p.append("HALF", 4);
    quint32 sid = sender->id();
    p.append(reinterpret_cast<const char*>(&sid), 4);
    p.append(reinterpret_cast<const char*>(&seq), 2);
    p.append(payload);

    const int sourceChannel = channelOfUser(sender->id());
    for (ClientSession* target : m_clients) {
        if (target == sender || target->udpPort() == 0) continue;
        const int targetChannel = channelOfUser(target->id());
        if (sourceChannel <= 0 || targetChannel != sourceChannel) continue;
        if (!hasChannelPerm(target, targetChannel, QStringLiteral("listen"))) continue;
        m_voice->sendTo(target->udpAddress(), target->udpPort(), p);
    }
}

void ServerCore::rotateChannelKey(int channelId) {
    if (!m_channels.contains(channelId)) return;

    // A cifra é ponta-a-ponta no nível do canal e o servidor continua sendo
    // relay puro. Para canais vinculados, todos os canais do componente de
    // áudio precisam compartilhar a mesma chave; caso contrário, usuários em
    // canais linkados receberiam frames cifrados com uma chave que não possuem.
    QSet<int> component;
    QList<int> pending;
    component.insert(channelId);
    pending << channelId;
    while (!pending.isEmpty()) {
        const int current = pending.takeFirst();
        if (!m_channels.contains(current)) continue;
        for (int next : m_channels[current].linkedChannels) {
            if (m_channels.contains(next) && !component.contains(next)) {
                component.insert(next);
                pending << next;
            }
        }
        for (const SvrChan& candidate : m_channels) {
            if (candidate.linkedChannels.contains(current) && !component.contains(candidate.id)) {
                component.insert(candidate.id);
                pending << candidate.id;
            }
        }
    }

    QByteArray key(32, '\0');
    QRandomGenerator* rng = QRandomGenerator::system();
    for (int i = 0; i < key.size(); ++i)
        key[i] = char(rng->bounded(256));

    for (int id : component)
        m_channelKeys[id] = key;

    QSet<int> componentUsers;
    for (int id : component) {
        if (!m_channels.contains(id)) continue;
        for (int uid : m_channels[id].users) componentUsers.insert(uid);
    }

    // Todos no componente recebem a chave de todos os canais do componente.
    // Assim, quando A escuta B por link de canais, o cliente consegue escolher
    // a chave pelo canal real do remetente sem o servidor decodificar nada.
    for (int id : component) {
        if (!m_channels.contains(id)) continue;
        QJsonObject m = HProto::msg("channel_key");
        m["channel"] = id;
        m["key"] = QString::fromLatin1(key.toBase64());
        for (int uid : componentUsers) {
            ClientSession* target = m_clients.value(uid, nullptr);
            if (target) target->send(m);
        }
    }
}
