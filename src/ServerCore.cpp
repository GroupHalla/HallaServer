#include "ServerCore.h"
#include "ClientSession.h"
#include "VoiceRelay.h"
#include "HallaProtocol.h"

#include <QFile>
#include <QJsonDocument>
#include <QJsonArray>
#include <QDateTime>
#include <QDir>

ServerCore::ServerCore(QObject* parent) : QObject(parent) {
    m_nextToken = 1024;
    m_idleTimer = new QTimer(this);
    m_idleTimer->setInterval(5000);
    connect(m_idleTimer, &QTimer::timeout, this, &ServerCore::checkIdleClients);
}

ServerCore::~ServerCore() {
    qDeleteAll(m_clients);
}

bool ServerCore::start(quint16 controlPort, quint16 voicePort) {
    loadData();
    loadBans();

    m_tcp = new QTcpServer(this);
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
    log(QStringLiteral("Servidor \"%1\" iniciado (slots: %2)").arg(m_name).arg(m_maxClients));
    return true;
}

void ServerCore::log(const QString& msg) {
    const QString line = QStringLiteral("[%1] %2")
        .arg(QDateTime::currentDateTime().toString("dd/MM/yyyy HH:mm:ss"), msg);
    emit logLine(line);
}

// ==================================================================== dados
void ServerCore::loadData() {
    // canal padrão sempre existe
    SvrChan def{1, 0, QStringLiteral("Canal padrão"), QString(), QString(), QString(),
                true, false, 2, 4, 6, -1, {}};
    m_channels.insert(1, def);
    m_nextChanId = 2;

    if (m_dataFile.isEmpty()) return;
    QFile f(m_dataFile);
    if (!f.open(QIODevice::ReadOnly)) return;
    QJsonDocument doc = QJsonDocument::fromJson(f.readAll());
    if (!doc.isObject()) return;
    QJsonObject root = doc.object();
    QJsonArray chans = root["channels"].toArray();
    for (const QJsonValue& v : chans) {
        SvrChan c = chanFromJson(v.toObject());
        if (c.id == 1) { // mescla o padrão mantendo id 1
            def.name = c.name; def.topic = c.topic; def.desc = c.desc;
            def.password = c.password; def.def = true; def.moderated = c.moderated;
            def.type = 2; def.codec = c.codec; def.quality = c.quality;
            def.maxClients = c.maxClients;
            m_channels[1] = def;
            continue;
        }
        m_channels.insert(c.id, c);
        m_nextChanId = qMax(m_nextChanId, c.id + 1);
    }
    if (root.contains("name")) m_name = root["name"].toString();
    log(QStringLiteral("Dados carregados: %1 canais").arg(m_channels.size()));
}

void ServerCore::saveData() {
    if (m_dataFile.isEmpty()) return;
    QJsonArray chans;
    for (const SvrChan& c : m_channels)
        if (c.type != 0) // temporários não persistem
            chans << chanToJson(c);
    QJsonObject root;
    root["name"] = m_name;
    root["channels"] = chans;
    QFile f(m_dataFile);
    if (f.open(QIODevice::WriteOnly)) f.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
}

void ServerCore::loadBans() {
    m_bans.clear();
    if (m_banFile.isEmpty()) return;
    QFile f(m_banFile);
    if (!f.open(QIODevice::ReadOnly)) return;
    QJsonDocument doc = QJsonDocument::fromJson(f.readAll());
    if (!doc.isArray()) return;
    for (const QJsonValue& v : doc.array()) {
        QJsonObject o = v.toObject();
        BanEntry b;
        b.uid = o["uid"].toString();
        b.name = o["name"].toString();
        b.reason = o["reason"].toString();
        if (o.contains("expires"))
            b.expires = QDateTime::fromString(o["expires"].toString(), Qt::ISODate);
        m_bans << b;
    }
}

void ServerCore::saveBans() {
    if (m_banFile.isEmpty()) return;
    QJsonArray arr;
    for (const BanEntry& b : m_bans) {
        QJsonObject o;
        o["uid"] = b.uid; o["name"] = b.name; o["reason"] = b.reason;
        if (b.expires.isValid()) o["expires"] = b.expires.toString(Qt::ISODate);
        arr << o;
    }
    QFile f(m_banFile);
    if (f.open(QIODevice::WriteOnly)) f.write(QJsonDocument(arr).toJson(QJsonDocument::Indented));
}

// ==================================================================== conexões
void ServerCore::onNewConnection() {
    while (m_tcp->hasPendingConnections()) {
        QTcpSocket* s = m_tcp->nextPendingConnection();
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
        if (client->voiceToken()) m_byVoiceToken.remove(client->voiceToken());
        log(QStringLiteral("Cliente #%1 (%2) desconectou").arg(client->id()).arg(client->name()));
    }
    client->deleteLater();
}

void ServerCore::checkIdleClients() {
    // limpa canais temporários vazios
    QList<int> toRemove;
    for (const SvrChan& c : m_channels)
        if (c.type == 0 && c.users.isEmpty()) toRemove << c.id;
    for (int id : toRemove) {
        m_channels.remove(id);
        QJsonObject m = HProto::msg("chan_removed");
        m["id"] = id;
        broadcast(m);
    }
}

// ==================================================================== mensagens
void ServerCore::onClientMessage(ClientSession* c, const QJsonObject& obj) {
    const QString t = obj["t"].toString();

    if (c->id() == 0 && t != "hello") return; // exige login antes de tudo

    if (t == "hello")           handleHello(c, obj);
    else if (t == "ping")        { QJsonObject p = HProto::msg("pong"); p["ts"] = obj["ts"]; c->send(p); }
    else if (t == "chat")        handleChat(c, obj);
    else if (t == "move")        handleMove(c, obj);
    else if (t == "voice_hello") {
        if (!c->voiceToken()) {
            c->setVoiceToken(m_nextToken++);
            m_byVoiceToken[c->voiceToken()] = c;
        }
        QJsonObject v = HProto::msg("voice_token");
        v["token"] = QString::number(c->voiceToken());
        v["udp"] = m_voice ? m_voice->port() : 0;
        c->send(v);
    }
    else if (t == "talking")     { bool on = obj["on"].toBool(); if (c->talking() != on) { c->setTalking(on); QJsonObject u = HProto::msg("user_state"); u["id"] = c->id(); u["talking"] = on; broadcast(u, c->id()); } }
    else if (t == "status")      handleStatus(c, obj);
    else if (t == "nick")        handleNick(c, obj);
    else if (t == "desc")        handleDesc(c, obj);
    else if (t == "poke")        handlePoke(c, obj);
    else if (t == "chan_create") handleChanCreate(c, obj);
    else if (t == "chan_edit")   handleChanEdit(c, obj);
    else if (t == "chan_delete") handleChanDelete(c, obj);
    else if (t == "kick")        handleKick(c, obj);
    else if (t == "ban")         handleBan(c, obj);
    else if (t == "privkey")     handlePrivkey(c, obj);
    else if (t == "volume")      handleVolume(c, obj);
    else if (t == "quit") {
        // desconexão graciosa: notifica os demais antes de fechar
        QJsonObject left = HProto::msg("user_left");
        left["id"] = c->id();
        left["reason"] = "quit";
        broadcast(left, c->id());
        removeFromChannels(c->id());
        m_clients.remove(c->id());
        if (c->voiceToken()) m_byVoiceToken.remove(c->voiceToken());
        log(QStringLiteral("Cliente #%1 (%2) saiu").arg(c->id()).arg(c->name()));
        c->closeAndDelete();
    }
}

void ServerCore::handleHello(ClientSession* c, const QJsonObject& obj) {
    if (c->id() != 0) return; // já logado

    const QString nick = obj["nick"].toString().trimmed().left(30);
    const QString uid = obj["uid"].toString();
    const QString pass = obj["pass"].toString();
    const QString adminPass = obj["adminPass"].toString();

    if (obj["proto"].toInt() != HProto::kProtoVersion) {
        QJsonObject e = HProto::msg("error");
        e["code"] = "bad_proto";
        e["msg"] = "Versão do protocolo incompatível";
        c->send(e);
        c->closeAndDelete();
        return;
    }
    if (nick.isEmpty()) {
        QJsonObject e = HProto::msg("error");
        e["code"] = "bad_nick";
        e["msg"] = "Apelido inválido";
        c->send(e);
        c->closeAndDelete();
        return;
    }

    // banido?
    for (const BanEntry& b : m_bans) {
        if (b.uid == uid) {
            if (!b.expires.isValid() || b.expires > QDateTime::currentDateTime()) {
                QJsonObject e = HProto::msg("error");
                e["code"] = "banned";
                e["msg"] = b.reason.isEmpty() ? QStringLiteral("Você está banido deste servidor")
                                              : QStringLiteral("Banido: %1").arg(b.reason);
                c->send(e);
                c->closeAndDelete();
                return;
            }
        }
    }

    // servidor cheio
    if (m_clients.size() >= m_maxClients) {
        QJsonObject e = HProto::msg("error");
        e["code"] = "server_full";
        e["msg"] = "Servidor cheio";
        c->send(e);
        c->closeAndDelete();
        return;
    }

    // senha do servidor
    if (!m_password.isEmpty() && pass != m_password) {
        QJsonObject e = HProto::msg("error");
        e["code"] = "bad_password";
        e["msg"] = "Senha do servidor incorreta";
        c->send(e);
        c->closeAndDelete();
        return;
    }

    // apelido duplicado
    for (ClientSession* other : m_clients)
        if (other->name().compare(nick, Qt::CaseInsensitive) == 0) {
            QJsonObject e = HProto::msg("error");
            e["code"] = "name_in_use";
            e["msg"] = "Apelido já em uso";
            c->send(e);
            c->closeAndDelete();
            return;
        }

    c->setId(m_nextId++);
    c->setName(nick);
    c->setGroup("guest");
    if (!adminPass.isEmpty() && adminPass == m_adminPassword && !m_adminPassword.isEmpty())
        c->setGroup("admin");
    else
        c->setGroup("normal");

    m_clients[c->id()] = c;
    addToChannel(c->id(), 1); // entra no canal padrão
    log(QStringLiteral("Cliente #%1 (%2) entrou").arg(c->id()).arg(nick));

    sendWelcome(c);

    QJsonObject joined = HProto::msg("user_joined");
    joined["user"] = c->toJson();
    broadcast(joined, c->id());
}

void ServerCore::sendWelcome(ClientSession* c) {
    QJsonObject w = HProto::msg("welcome");
    w["selfId"] = c->id();

    QJsonObject server;
    server["name"] = m_name;
    server["motd"] = m_motd;
    server["ver"] = "1.0.0";
    server["platform"] = "Linux";
    server["maxClients"] = m_maxClients;
    w["server"] = server;

    QJsonArray users;
    for (ClientSession* o : m_clients) users << o->toJson();
    w["users"] = users;

    QJsonArray chans;
    for (const SvrChan& ch : m_channels) chans << chanToJson(ch);
    w["channels"] = chans;

    if (!c->voiceToken()) {
        c->setVoiceToken(m_nextToken++);
        m_byVoiceToken[c->voiceToken()] = c;
    }
    QJsonObject voice;
    voice["udp"] = m_voice ? m_voice->port() : 0;
    voice["token"] = QString::number(c->voiceToken());
    w["voice"] = voice;

    c->send(w);
}

void ServerCore::handleChat(ClientSession* c, const QJsonObject& obj) {
    const QString scope = obj["scope"].toString();
    const QString text = obj["text"].toString().left(1024);
    if (text.trimmed().isEmpty()) return;

    QJsonObject m = HProto::msg("chat");
    m["scope"] = scope;
    m["from"] = c->id();
    m["fromName"] = c->name();
    m["text"] = text;

    if (scope == "server")         broadcast(m);
    else if (scope == "channel") {
        const int chan = channelOfUser(c->id());
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
    if (!m_channels.contains(target)) return;

    SvrChan& ch = m_channels[target];
    const int oldChan = channelOfUser(c->id());
    if (oldChan == target) return;

    if (ch.maxClients >= 0 && ch.users.size() >= ch.maxClients) {
        QJsonObject e = HProto::msg("error");
        e["code"] = "channel_full";
        e["msg"] = QStringLiteral("O canal \"%1\" está cheio").arg(ch.name);
        c->send(e);
        return;
    }
    if (!ch.password.isEmpty() && obj["pass"].toString() != ch.password) {
        QJsonObject e = HProto::msg("error");
        e["code"] = "bad_channel_pass";
        e["msg"] = "Senha do canal incorreta";
        c->send(e);
        return;
    }

    removeFromChannels(c->id());
    ch.users << c->id();

    QJsonObject m = HProto::msg("user_moved");
    m["id"] = c->id();
    m["channel"] = target;
    m["by"] = c->id();
    broadcast(m);
}

void ServerCore::handleStatus(ClientSession* c, const QJsonObject& obj) {
    if (obj.contains("mic"))  c->setMicMuted(obj["mic"].toBool());
    if (obj.contains("spk"))  c->setSpkMuted(obj["spk"].toBool());
    if (obj.contains("away")) c->setAway(obj["away"].toBool());
    if (obj.contains("rec"))  c->setRecording(obj["rec"].toBool());
    if (obj.contains("cc"))   c->setCommander(obj["cc"].toBool());

    QJsonObject u = HProto::msg("user_state");
    u["id"] = c->id();
    u["mic"] = c->micMuted();
    u["spk"] = c->spkMuted();
    u["away"] = c->away();
    u["rec"] = c->recording();
    u["cc"] = c->commander();
    broadcast(u, c->id());
}

void ServerCore::handleNick(ClientSession* c, const QJsonObject& obj) {
    const QString name = obj["name"].toString().trimmed().left(30);
    if (name.isEmpty() || name == c->name()) return;
    for (ClientSession* other : m_clients)
        if (other != c && other->name().compare(name, Qt::CaseInsensitive) == 0) {
            QJsonObject e = HProto::msg("error");
            e["code"] = "name_in_use";
            e["msg"] = "Apelido já em uso";
            c->send(e);
            return;
        }
    c->setName(name);
    QJsonObject m = HProto::msg("user_nick");
    m["id"] = c->id();
    m["name"] = name;
    broadcast(m);
}

void ServerCore::handleDesc(ClientSession* c, const QJsonObject& obj) {
    c->setDescription(obj["text"].toString().left(200));
    QJsonObject m = HProto::msg("user_desc");
    m["id"] = c->id();
    m["text"] = c->description();
    broadcast(m);
}

void ServerCore::handlePoke(ClientSession* c, const QJsonObject& obj) {
    const int to = obj["to"].toInt();
    if (!m_clients.contains(to)) return;
    QJsonObject m = HProto::msg("poke");
    m["from"] = c->id();
    m["fromName"] = c->name();
    m["msg"] = obj["msg"].toString().left(100);
    m_clients[to]->send(m);
    c->send(m); // eco
}

void ServerCore::handleVolume(ClientSession*, const QJsonObject&) {
    // volume local — o cliente aplica localmente; nada a fazer no servidor
}

void ServerCore::handleChanCreate(ClientSession* c, const QJsonObject& obj) {
    const QString group = c->group();
    const int type = obj["type"].toInt(2);

    // permissões: temp — normal+, semi/permanent — admin
    if (type != 0 && !isAdmin(c)) {
        QJsonObject e = HProto::msg("error");
        e["code"] = "no_permission";
        e["msg"] = "Sem permissão para criar este tipo de canal";
        c->send(e);
        return;
    }
    if (group == "guest") {
        QJsonObject e = HProto::msg("error");
        e["code"] = "no_permission";
        e["msg"] = "Convidados não podem criar canais";
        c->send(e);
        return;
    }

    const QString name = obj["name"].toString().trimmed().left(40);
    if (name.isEmpty()) return;

    SvrChan ch;
    ch.id = m_nextChanId++;
    ch.parent = obj["parent"].toInt(0);
    if (ch.parent != 0 && !m_channels.contains(ch.parent)) ch.parent = 0;
    ch.name = name;
    ch.topic = obj["topic"].toString().left(80);
    ch.desc = obj["desc"].toString();
    ch.password = obj["pass"].toString();
    ch.def = false;
    ch.moderated = obj["moderated"].toBool(false);
    ch.type = type;
    ch.codec = qBound(0, obj["codec"].toInt(4), 5);
    ch.quality = qBound(0, obj["quality"].toInt(6), 10);
    ch.maxClients = obj["max"].toInt(-1);
    m_channels[ch.id] = ch;
    saveData();

    QJsonObject m = HProto::msg("chan_update");
    m["chan"] = chanToJson(ch);
    broadcast(m);
}

void ServerCore::handleChanEdit(ClientSession* c, const QJsonObject& obj) {
    const int id = obj["id"].toInt();
    if (!m_channels.contains(id)) return;
    if (!isAdmin(c)) {
        QJsonObject e = HProto::msg("error");
        e["code"] = "no_permission";
        e["msg"] = "Sem permissão para editar canais";
        c->send(e);
        return;
    }
    SvrChan& ch = m_channels[id];
    if (obj.contains("name")) ch.name = obj["name"].toString().trimmed().left(40);
    if (obj.contains("topic")) ch.topic = obj["topic"].toString().left(80);
    if (obj.contains("desc")) ch.desc = obj["desc"].toString();
    if (obj.contains("pass")) ch.password = obj["pass"].toString();
    if (obj.contains("moderated")) ch.moderated = obj["moderated"].toBool();
    if (obj.contains("type") && id != 1) ch.type = obj["type"].toInt();
    if (obj.contains("codec")) ch.codec = qBound(0, obj["codec"].toInt(), 5);
    if (obj.contains("quality")) ch.quality = qBound(0, obj["quality"].toInt(), 10);
    if (obj.contains("max")) ch.maxClients = obj["max"].toInt();
    saveData();

    QJsonObject m = HProto::msg("chan_update");
    m["chan"] = chanToJson(ch);
    broadcast(m);
}

void ServerCore::handleChanDelete(ClientSession* c, const QJsonObject& obj) {
    const int id = obj["id"].toInt();
    if (!m_channels.contains(id) || id == 1) return;
    if (!isAdmin(c)) {
        QJsonObject e = HProto::msg("error");
        e["code"] = "no_permission";
        e["msg"] = "Sem permissão para excluir canais";
        c->send(e);
        return;
    }
    // sub-canais impedem exclusão
    for (const SvrChan& ch : m_channels)
        if (ch.parent == id) {
            QJsonObject e = HProto::msg("error");
            e["code"] = "has_children";
            e["msg"] = "Exclua primeiro os sub-canais";
            c->send(e);
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
    saveData();
    QJsonObject m = HProto::msg("chan_removed");
    m["id"] = id;
    broadcast(m);
}

void ServerCore::handleKick(ClientSession* c, const QJsonObject& obj) {
    if (!isAdmin(c)) {
        QJsonObject e = HProto::msg("error");
        e["code"] = "no_permission";
        e["msg"] = "Sem permissão para expulsar";
        c->send(e);
        return;
    }
    const int id = obj["id"].toInt();
    if (!m_clients.contains(id) || id == c->id()) return;
    const bool fromServer = obj["from"].toString() == "server";
    doKick(m_clients[id], obj["reason"].toString(), fromServer, false);
}

void ServerCore::handleBan(ClientSession* c, const QJsonObject& obj) {
    if (!isAdmin(c)) {
        QJsonObject e = HProto::msg("error");
        e["code"] = "no_permission";
        e["msg"] = "Sem permissão para banir";
        c->send(e);
        return;
    }
    const int id = obj["id"].toInt();
    if (!m_clients.contains(id) || id == c->id()) return;
    const int minutes = obj["minutes"].toInt(0);

    BanEntry b;
    b.uid = m_clients[id]->uniqueId();
    b.name = m_clients[id]->name();
    b.reason = obj["reason"].toString();
    if (minutes > 0) b.expires = QDateTime::currentDateTime().addSecs(qint64(minutes) * 60);
    m_bans << b;
    saveBans();

    doKick(m_clients[id], b.reason, true, true, minutes);
}

void ServerCore::handlePrivkey(ClientSession* c, const QJsonObject& obj) {
    const QString key = obj["key"].toString();
    if (m_privilegeKeys.contains(key)) {
        c->setGroup("admin");
        QJsonObject m = HProto::msg("user_group");
        m["id"] = c->id();
        m["group"] = "admin";
        broadcast(m);
        log(QStringLiteral("Cliente #%1 usou chave de privilégio e virou admin").arg(c->id()));
    } else {
        QJsonObject e = HProto::msg("error");
        e["code"] = "bad_privkey";
        e["msg"] = "Chave de privilégio inválida";
        c->send(e);
    }
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
        if (c->voiceToken()) m_byVoiceToken.remove(c->voiceToken());
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
    for (SvrChan& c : m_channels) c.users.removeAll(userId);
}

void ServerCore::addToChannel(int userId, int channelId) {
    removeFromChannels(userId);
    if (m_channels.contains(channelId))
        m_channels[channelId].users << userId;
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
    c.type = o["type"].toInt(2);
    c.codec = o["codec"].toInt(4);
    c.quality = o["quality"].toInt(6);
    c.maxClients = o["max"].toInt(-1);
    return c;
}

QJsonObject ServerCore::chanToJson(const SvrChan& c) const {
    QJsonArray users;
    for (int u : c.users) users << u;
    return HProto::chanJson(c.id, c.parent, c.name, c.topic, c.desc,
                            !c.password.isEmpty(), c.id == 1, c.type, c.moderated,
                            c.codec, c.quality, c.maxClients, c.users);
}

void ServerCore::dumpBansIfNeeded() {}

bool ServerCore::isAdmin(const ClientSession* c) const { return c->group() == "admin"; }

void ServerCore::relayVoice(ClientSession* sender, quint16 seq, const QByteArray& payload) {
    if (!sender || !m_voice) return;
    const int chan = channelOfUser(sender->id());
    if (chan == 0) return;

    const QByteArray packet = HProto::encodeVoiceServer(quint32(sender->id()), seq, payload);
    for (ClientSession* c : m_clients) {
        if (c == sender) continue;
        if (c->udpPort() == 0) continue;                     // ainda não falou nada
        if (channelOfUser(c->id()) != chan) continue;
        m_voice->sendTo(c->udpAddress(), c->udpPort(), packet);
    }
}
