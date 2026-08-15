#include "ServerCore.h"
#include "ClientSession.h"
#include "HallaProtocol.h"
#include "ServerQuery.h"

#include <QFile>
#include <QDir>
#include <QTcpSocket>
#include <QJsonArray>
#include <QCryptographicHash>

// ============================================================ AVATARES (v3)
void ServerCore::handleAvatarSet(ClientSession* c, const QJsonObject& obj) {
    const QByteArray data = QByteArray::fromBase64(obj["data"].toString().toLatin1());
    const QString uid = c->uniqueId();

    if (data.isEmpty()) { // apagar avatar
        QFile::remove(avatarPath(uid));
        m_avatarHash[uid].clear();
        c->setAvatarHash(QString());
    } else {
        if (data.size() > 131072) { // 128 KiB
            sendError(c, "avatar_too_big", "Avatar excede 128 KiB");
            return;
        }
        QDir().mkpath(dataDir() + QStringLiteral("/avatars"));
        QFile f(avatarPath(uid));
        if (!f.open(QIODevice::WriteOnly)) {
            sendError(c, "io_error", "Não foi possível salvar o avatar");
            return;
        }
        f.write(data);
        const QString hash = QString::fromLatin1(
            QCryptographicHash::hash(data, QCryptographicHash::Sha1).toHex());
        m_avatarHash[uid] = hash;
        c->setAvatarHash(hash);
    }
    QJsonObject m = HProto::msg("user_avatar");
    m["id"] = c->id();
    m["av"] = c->avatarHash();
    broadcast(m);
    log(QStringLiteral("Avatar de #%1 (%2) %3").arg(c->id()).arg(c->name())
            .arg(c->avatarHash().isEmpty() ? "removido" : "atualizado"));
}

void ServerCore::handleAvatarGet(ClientSession* c, const QJsonObject& obj) {
    const QString uid = obj["uid"].toString();
    QFile f(avatarPath(uid));
    if (!f.open(QIODevice::ReadOnly)) {
        sendError(c, "not_found", "Avatar não encontrado");
        return;
    }
    QJsonObject m = HProto::msg("avatar_data");
    m["uid"] = uid;
    m["data"] = QString::fromLatin1(f.readAll().toBase64());
    c->send(m);
}

void ServerCore::handleIconGet(ClientSession* c, const QJsonObject& obj) {
    const QString name = obj["name"].toString();
    QFile f(iconPath(name));
    if (!f.open(QIODevice::ReadOnly)) {
        sendError(c, "not_found", "Ícone não encontrado");
        return;
    }
    QJsonObject m = HProto::msg("icon_data");
    m["name"] = name;
    m["data"] = QString::fromLatin1(f.readAll().toBase64());
    c->send(m);
}

void ServerCore::handleIconSet(ClientSession* c, const QJsonObject& obj) {
    if (!hasPerm(c, "groupEdit")) {
        sendError(c, "no_permission", "Sem permissão para gerenciar ícones de grupos");
        return;
    }
    const QString name = obj["name"].toString();
    const QByteArray data = QByteArray::fromBase64(obj["data"].toString().toLatin1());
    
    if (name.isEmpty() || data.isEmpty()) return;
    if (data.size() > 65536) { // 64 KiB limit
        sendError(c, "icon_too_big", "O ícone excede 64 KiB");
        return;
    }
    
    QDir().mkpath(dataDir() + QStringLiteral("/icons"));
    QFile f(iconPath(name));
    if (f.open(QIODevice::WriteOnly)) {
        f.write(data);
        f.close();
        log(QStringLiteral("Ícone customizado \"%1\" enviado por %2").arg(name, c->name()));
        
        QJsonObject m = HProto::msg("icon_uploaded");
        m["name"] = name;
        broadcast(m);
    } else {
        sendError(c, "io_error", "Não foi possível salvar o ícone no servidor");
    }
}

// ===================================================== MENSAGENS OFFLINE (v3)
void ServerCore::handleOfflineSend(ClientSession* c, const QJsonObject& obj) {
    const QString toUid = obj["uid"].toString();
    const QString text = obj["text"].toString().left(500);
    if (toUid.isEmpty() || text.trimmed().isEmpty()) return;
    if (!m_registry.contains(toUid)) {
        sendError(c, "not_found", "Identidade desconhecida neste servidor");
        return;
    }
    QList<OfflineMsg>& list = m_offline[toUid];
    if (list.size() >= 20) {
        sendError(c, "inbox_full", "A caixa de entrada deste usuário está cheia");
        return;
    }
    list << OfflineMsg{c->uniqueId(), c->name(), text, QDateTime::currentDateTime()};
    saveData();

    QJsonObject ok = HProto::msg("offline_sent");
    ok["uid"] = toUid;
    c->send(ok);
    log(QStringLiteral("%1 deixou mensagem offline para %2")
            .arg(c->name(), m_registry[toUid].name));
}

// ======================================================== RECLAMAÇÕES (v3)
void ServerCore::handleComplaintAdd(ClientSession* c, const QJsonObject& obj) {
    const int id = obj["id"].toInt();
    if (!m_clients.contains(id) || id == c->id()) return;
    const QString text = obj["text"].toString().trimmed().left(300);
    if (text.isEmpty()) return;
    ClientSession* t = m_clients[id];
    m_complaints << Complaint{t->uniqueId(), t->name(), c->uniqueId(), c->name(),
                              text, QDateTime::currentDateTime()};
    saveData();
    QJsonObject ok = HProto::msg("complaint_added");
    c->send(ok);
    log(QStringLiteral("Reclamação de %1 contra %2: %3").arg(c->name(), t->name(), text));
}

void ServerCore::handleComplaintList(ClientSession* c) {
    if (!hasPerm(c, "banList")) {
        sendError(c, "no_permission", "Sem permissão para ver reclamações");
        return;
    }
    QJsonObject m = HProto::msg("complaint_list");
    QJsonArray arr;
    for (const Complaint& cp : m_complaints) {
        QJsonObject o;
        o["uid"] = cp.uid; o["name"] = cp.name; o["byUid"] = cp.byUid;
        o["byName"] = cp.byName; o["text"] = cp.text; o["ts"] = cp.ts.toString(Qt::ISODate);
        arr << o;
    }
    m["complaints"] = arr;
    c->send(m);
}

void ServerCore::handleComplaintClear(ClientSession* c, const QJsonObject& obj) {
    if (!hasPerm(c, "banList")) {
        sendError(c, "no_permission", "Sem permissão para limpar reclamações");
        return;
    }
    if (obj.contains("uid")) {
        const QString uid = obj["uid"].toString();
        for (int i = m_complaints.size() - 1; i >= 0; --i)
            if (m_complaints[i].uid == uid) m_complaints.removeAt(i);
    } else {
        m_complaints.clear();
    }
    saveData();
    QJsonObject m = HProto::msg("complaint_cleared");
    c->send(m);
}

// ============================================================= SUSSURRO (v3)
void ServerCore::handleWhisper(ClientSession* c, const QJsonObject& obj) {
    if (!hasPerm(c, "whisper")) {
        c->setWhisperIds({});
        sendError(c, "no_permission", "Você não tem permissão para usar sussurros");
        return;
    }
    QSet<int> ids;
    for (const QJsonValue& v : obj["ids"].toArray()) {
        const int id = v.toInt();
        if (m_clients.contains(id) && id != c->id()) ids.insert(id);
    }
    c->setWhisperIds(ids);
    QJsonObject m = HProto::msg("whisper_ok");
    m["count"] = ids.size();
    c->send(m);
    // avisa estilo Halla no próprio cliente (UI local mostra o modo)
}

// =============================================== DADOS DE COMPLEMENTOS (v5)
void ServerCore::handlePluginData(ClientSession* c, const QJsonObject& obj) {
    if (!c || c->protocolVersion() < 5) {
        sendError(c, "plugin_data_unsupported",
                  "Dados de complementos exigem o protocolo v5");
        return;
    }
    const QString pluginId = obj["plugin"].toString();
    const QString topic = obj["topic"].toString();
    const int target = obj["target"].toInt(-1);
    if (pluginId.size() < 3 || pluginId.size() > 64 || topic.toUtf8().size() > 64
            || target < 0 || target > 2) {
        sendError(c, "bad_plugin_data", "Metadados de complemento inválidos");
        return;
    }
    for (QChar ch : pluginId) {
        const ushort u = ch.unicode();
        if (!((u >= 'a' && u <= 'z') || (u >= '0' && u <= '9')
                || u == '.' || u == '-' || u == '_')) {
            sendError(c, "bad_plugin_data", "ID de complemento inválido");
            return;
        }
    }
    const auto decoded = QByteArray::fromBase64Encoding(
        obj["data"].toString().toLatin1(), QByteArray::AbortOnBase64DecodingErrors);
    if (!decoded || decoded.decoded.size() > 8192) {
        sendError(c, "plugin_data_too_big", "Payload de complemento inválido ou muito grande");
        return;
    }

    QSet<int> recipients;
    if (target == 0) {
        const int channelId = channelOfUser(c->id());
        if (!m_channels.contains(channelId)) {
            sendError(c, "invalid_channel", "Canal atual inválido");
            return;
        }
        for (int userId : m_channels[channelId].users)
            if (userId != c->id() && m_clients.contains(userId)) recipients.insert(userId);
    } else if (target == 1) {
        const QJsonArray ids = obj["ids"].toArray();
        if (ids.isEmpty() || ids.size() > 64) {
            sendError(c, "bad_plugin_data", "Lista de destinos inválida");
            return;
        }
        for (const QJsonValue& value : ids) {
            const int userId = value.toInt();
            if (userId != c->id() && m_clients.contains(userId)) recipients.insert(userId);
        }
    } else {
        for (ClientSession* other : m_clients)
            if (other && other->id() != c->id()) recipients.insert(other->id());
    }

    QJsonObject message = HProto::msg("plugin_data");
    message["from"] = c->id();
    message["plugin"] = pluginId;
    message["topic"] = topic;
    message["data"] = QString::fromLatin1(decoded.decoded.toBase64());
    for (int userId : recipients)
        if (ClientSession* recipient = m_clients.value(userId, nullptr);
                recipient && recipient->protocolVersion() >= 5)
            recipient->send(message);
}

// ============================================================== ARQUIVOS (v3)
void ServerCore::handleFtUpload(ClientSession* c, const QJsonObject& obj) {
    const int chan = obj["channel"].toInt();
    if (!m_channels.contains(chan)) return;
    if (!canViewChannel(c, chan)) {
        sendError(c, "no_permission", "Sem permissão para visualizar este canal");
        return;
    }
    if (!hasChannelPerm(c, chan, "file_upload")) {
        sendError(c, "no_permission", "Sem permissão para enviar arquivos neste canal");
        return;
    }
    if (c->groupId() == 1 && !hasPerm(c, "*")) { // convidado não envia arquivos
        sendError(c, "no_permission", "Convidados não podem enviar arquivos");
        return;
    }
    const QString name = sanitizeFileName(obj["name"].toString());
    const QByteArray data = QByteArray::fromBase64(obj["data"].toString().toLatin1());
    if (name.isEmpty() || data.isEmpty()) return;
    if (data.size() > 1048576) {
        sendError(c, "file_too_big", "Arquivo excede 1 MiB");
        return;
    }
    qint64 total = 0; int count = 0;
    for (const FileMeta& fm : m_files)
        if (fm.chan == chan) { total += fm.size; ++count; }
    if (count >= 50 || total + data.size() > 10ll * 1048576) {
        sendError(c, "quota", "Cota do canal excedida (50 arquivos / 10 MiB)");
        return;
    }
    QDir().mkpath(filesDir(chan));
    QFile f(filesDir(chan) + QLatin1Char('/') + name);
    if (!f.open(QIODevice::WriteOnly)) {
        sendError(c, "io_error", "Não foi possível salvar o arquivo");
        return;
    }
    f.write(data);
    // substitui metadados se já existia
    for (int i = 0; i < m_files.size(); ++i)
        if (m_files[i].chan == chan && m_files[i].name == name) m_files.removeAt(i--);
    m_files << FileMeta{chan, name, c->uniqueId(), c->name(), data.size(),
                        QDateTime::currentDateTime()};
    saveData();
    QJsonObject ok = HProto::msg("ft_uploaded");
    ok["channel"] = chan; ok["name"] = name; ok["size"] = QString::number(data.size());
    c->send(ok);
    log(QStringLiteral("%1 enviou arquivo \"%2\" (%3 bytes) para o canal #%4")
            .arg(c->name(), name).arg(data.size()).arg(chan));
}

void ServerCore::handleFtList(ClientSession* c, const QJsonObject& obj) {
    const int chan = obj["channel"].toInt();
    if (!canViewChannel(c, chan)) {
        sendError(c, "no_permission", "Sem permissão para visualizar este canal");
        return;
    }
    QJsonObject m = HProto::msg("ft_list");
    m["channel"] = chan;
    QJsonArray arr;
    for (const FileMeta& fm : m_files)
        if (fm.chan == chan) {
            QJsonObject o;
            o["name"] = fm.name; o["size"] = QString::number(fm.size);
            o["by"] = fm.by; o["ts"] = fm.ts.toString(Qt::ISODate);
            arr << o;
        }
    m["files"] = arr;
    c->send(m);
}

void ServerCore::handleFtDownload(ClientSession* c, const QJsonObject& obj) {
    const int chan = obj["channel"].toInt();
    if (!canViewChannel(c, chan)) {
        sendError(c, "no_permission", "Sem permissão para visualizar este canal");
        return;
    }
    if (!hasChannelPerm(c, chan, "file_download")) {
        sendError(c, "no_permission", "Sem permissão para baixar arquivos neste canal");
        return;
    }
    const QString name = sanitizeFileName(obj["name"].toString());
    QFile f(filesDir(chan) + QLatin1Char('/') + name);
    if (!f.open(QIODevice::ReadOnly)) {
        sendError(c, "not_found", "Arquivo não encontrado");
        return;
    }
    QJsonObject m = HProto::msg("ft_data");
    m["channel"] = chan; m["name"] = name;
    m["data"] = QString::fromLatin1(f.readAll().toBase64());
    c->send(m);
}

void ServerCore::handleFtDelete(ClientSession* c, const QJsonObject& obj) {
    const int chan = obj["channel"].toInt();
    if (!canViewChannel(c, chan)) {
        sendError(c, "no_permission", "Sem permissão para visualizar este canal");
        return;
    }
    const QString name = sanitizeFileName(obj["name"].toString());
    int idx = -1;
    for (int i = 0; i < m_files.size(); ++i)
        if (m_files[i].chan == chan && m_files[i].name == name) { idx = i; break; }
    if (idx < 0) { sendError(c, "not_found", "Arquivo não encontrado"); return; }
    const FileMeta& fm = m_files[idx];
    const bool allowed = hasPerm(c, "chanEdit") || isChanOp(c, chan)
                         || fm.byUid == c->uniqueId();
    if (!allowed) {
        sendError(c, "no_permission", "Sem permissão para excluir este arquivo");
        return;
    }
    m_files.removeAt(idx);
    QFile::remove(filesDir(chan) + QLatin1Char('/') + name);
    saveData();
    QJsonObject ok = HProto::msg("ft_deleted");
    ok["channel"] = chan; ok["name"] = name;
    c->send(ok);
}

// ============================================================================
// ServerQuery (v3.1) — execução dos comandos administrativos sobre text/TCP
// ============================================================================
void ServerCore::setQueryPassword(const QString& p) {
    m_queryPass = p;
    saveData();
}

void ServerCore::queryCounts(int& channels, int& clients) const {
    channels = int(m_channels.size());
    clients  = m_clients.size();
}

void ServerCore::queryCommand(QTcpSocket* s, const QString& cmd,
                              const QMap<QString, QString>& args,
                              const std::function<void(QTcpSocket*)>& ok,
                              const std::function<void(QTcpSocket*, int,
                                                       const QString&)>& err) {
    auto line = [&](const QString& l) { s->write(l.toUtf8() + "\n\r"); };
    auto esc  = [](const QString& v) { return ServerQuery::escape(v); };

    if (cmd == QLatin1String("clientlist")) {
        for (ClientSession* c : m_clients) {
            int cid = 1;
            for (const SvrChan& ch : m_channels)
                if (ch.users.contains(c->id())) { cid = ch.id; break; }
            line(QStringLiteral(
                "clid=%1 cid=%2 client_nickname=%3 client_unique_identifier=%4 "
                "client_version=%5 client_platform=%6")
                .arg(c->id()).arg(cid)
                .arg(esc(c->name()), esc(c->uniqueId()),
                     esc(c->version().isEmpty() ? QStringLiteral("Halla") : c->version()),
                     esc(c->platform())));
        }
        ok(s);
        return;
    }

    if (cmd == QLatin1String("channellist")) {
        for (const SvrChan& ch : m_channels)
            line(QStringLiteral("cid=%1 pid=%2 channel_name=%3 total_clients=%4")
                .arg(ch.id).arg(ch.parent).arg(esc(ch.name)).arg(ch.users.size()));
        ok(s);
        return;
    }

    if (cmd == QLatin1String("banlist")) {
        for (const BanEntry& b : m_bans)
            line(QStringLiteral(
                "banid=%1 uid=%1 ip=%2 name=%3 reason=%4 duration=%5")
                .arg(esc(b.uid), esc(b.ip), esc(b.name), esc(b.reason),
                     esc(b.expires.isValid()
                         ? QDateTime::currentDateTime().secsTo(b.expires) > 0
                           ? QStringLiteral("%1s").arg(QDateTime::currentDateTime()
                                                            .secsTo(b.expires))
                           : QStringLiteral("expirado")
                         : QStringLiteral("permanente"))));
        ok(s);
        return;
    }

    if (cmd == QLatin1String("clientkick")) {
        const int id = args.value(QStringLiteral("clid")).toInt();
        ClientSession* t = m_clients.value(id, nullptr);
        if (!t) { err(s, 512, QStringLiteral("cliente nao encontrado")); return; }
        const QString reason = args.value(QStringLiteral("reasonmsg"));
        log(QStringLiteral("ServerQuery expulsou #%1 (%2)%3")
                .arg(t->id()).arg(t->name(),
                reason.isEmpty() ? QString() : QStringLiteral(": %1").arg(reason)));
        doKick(t, reason, true, false);
        ok(s);
        return;
    }

    if (cmd == QLatin1String("banclient")) {
        const int id = args.value(QStringLiteral("clid")).toInt();
        ClientSession* t = m_clients.value(id, nullptr);
        if (!t) { err(s, 512, QStringLiteral("cliente nao encontrado")); return; }
        const int minutes = args.value(QStringLiteral("time")).toInt();
        const QString reason = args.value(QStringLiteral("reasonmsg"));
        BanEntry b;
        b.uid = t->uniqueId();
        b.ip  = t->ip().toString();
        b.name = t->name();
        b.reason = reason;
        if (minutes > 0)
            b.expires = QDateTime::currentDateTime().addSecs(qint64(minutes) * 60);
        m_bans << b;
        saveBans();
        log(QStringLiteral("ServerQuery baniu #%1 (%2)").arg(t->id()).arg(t->name()));
        doKick(t, reason, true, true, minutes);
        ok(s);
        return;
    }

    if (cmd == QLatin1String("banadd")) {
        const QString uid = args.value(QStringLiteral("uid"));
        if (uid.isEmpty()) { err(s, 1538, QStringLiteral("uid vazio")); return; }
        const int minutes = args.value(QStringLiteral("time")).toInt();
        BanEntry b;
        b.uid = uid;
        b.name = m_registry.value(uid).name;
        b.reason = args.value(QStringLiteral("banreason"));
        if (minutes > 0)
            b.expires = QDateTime::currentDateTime().addSecs(qint64(minutes) * 60);
        m_bans << b;
        saveBans();
        log(QStringLiteral("ServerQuery adicionou banimento de %1").arg(uid.left(16)));
        ok(s);
        return;
    }

    if (cmd == QLatin1String("bandel")) {
        const QString uid = args.value(QStringLiteral("banid"));
        int removed = 0;
        for (int i = m_bans.size() - 1; i >= 0; --i)
            if (m_bans[i].uid == uid) { m_bans.removeAt(i); ++removed; }
        if (removed == 0) { err(s, 512, QStringLiteral("banimento nao encontrado")); return; }
        saveBans();
        ok(s);
        return;
    }

    if (cmd == QLatin1String("gm")) {
        const QString text = args.value(QStringLiteral("msg"));
        if (text.isEmpty()) { err(s, 1538, QStringLiteral("mensagem vazia")); return; }
        QJsonObject m = HProto::msg("chat");
        m["scope"] = QStringLiteral("server");
        m["from"] = 0;
        m["fromName"] = QStringLiteral("ServerQuery (admin)");
        m["text"] = text.left(1024);
        broadcast(m);
        log(QStringLiteral("ServerQuery gm: %1").arg(text));
        ok(s);
        return;
    }

    // Pilar 1: Gerenciar position de grupos
    if (cmd == QLatin1String("servergroupsetposition")) {
        const int groupId = args.value(QStringLiteral("sgid")).toInt();
        const int position = args.value(QStringLiteral("position")).toInt();
        if (groupId <= 0) { err(s, 1538, QStringLiteral("sgid invalido")); return; }
        if (!m_groups.contains(groupId)) { err(s, 1281, QStringLiteral("grupo nao encontrado")); return; }
        GroupDef& g = m_groups[groupId];
        g.position = position;
        saveData();
        // Atualiza clientes conectados com este grupo
        for (ClientSession* o : m_clients) {
            if (o->groupId() == groupId) {
                o->setGroupPosition(position);
            }
        }
        broadcastGroups();
        log(QStringLiteral("ServerQuery: position do grupo #%1 ajustada para %2").arg(groupId).arg(position));
        ok(s);
        return;
    }

    // Pilar 1: Adicionar requisito de position para grupo em canal
    if (cmd == QLatin1String("channelgroupsetpositionreq")) {
        const int channelId = args.value(QStringLiteral("cid")).toInt();
        const int groupId = args.value(QStringLiteral("gid")).toInt();
        const int minPosition = args.value(QStringLiteral("min_position")).toInt();
        if (channelId <= 0 || !m_channels.contains(channelId)) {
            err(s, 1281, QStringLiteral("canal nao encontrado")); return;
        }
        if (groupId <= 0 || !m_groups.contains(groupId)) {
            err(s, 1281, QStringLiteral("grupo nao encontrado")); return;
        }
        SvrChan& ch = m_channels[channelId];
        QString gidStr = QString::number(groupId);
        if (minPosition < 0) {
            ch.groupPositionReqs.remove(gidStr);
        } else {
            ch.groupPositionReqs[gidStr] = minPosition;
        }
        saveData();
        // Notifica clientes sobre atualização do canal
        QJsonObject update = HProto::msg("chan_update");
        update["chan"] = chanToJson(ch);
        broadcast(update);
        log(QStringLiteral("ServerQuery: requisito de position do grupo #%1 no canal #%2 ajustado para %3")
                .arg(groupId).arg(channelId).arg(minPosition));
        ok(s);
        return;
    }

    // Pilar 3: Definir permissão de canal para grupo (Allow=1, Deny=0, Inherit=-1)
    if (cmd == QLatin1String("channelgroupsetperm")) {
        const int channelId = args.value(QStringLiteral("cid")).toInt();
        const int groupId = args.value(QStringLiteral("gid")).toInt();
        const QString permKey = args.value(QStringLiteral("perm"));
        const int state = args.value(QStringLiteral("state")).toInt(); // 1=Allow, 0=Deny, -1=Inherit
        if (channelId <= 0 || !m_channels.contains(channelId)) {
            err(s, 1281, QStringLiteral("canal nao encontrado")); return;
        }
        if (groupId <= 0 || !m_groups.contains(groupId)) {
            err(s, 1281, QStringLiteral("grupo nao encontrado")); return;
        }
        if (permKey.isEmpty()) { err(s, 1538, QStringLiteral("perm vazia")); return; }
        SvrChan& ch = m_channels[channelId];
        QString gidStr = QString::number(groupId);
        // Garante que o objeto existe
        if (!ch.groupPerms.contains(gidStr)) {
            ch.groupPerms[gidStr] = QJsonObject();
        }
        // Extrai, modifica e reatribui o QJsonObject
        QJsonObject gPerms = ch.groupPerms[gidStr].toObject();
        if (state == -1) {
            gPerms.remove(permKey); // Remove = Inherit
        } else {
            gPerms[permKey] = state; // 1=Allow, 0=Deny
        }
        ch.groupPerms[gidStr] = gPerms;
        saveData();
        // Notifica clientes sobre atualização do canal
        QJsonObject update = HProto::msg("chan_update");
        update["chan"] = chanToJson(ch);
        broadcast(update);
        log(QStringLiteral("ServerQuery: permissao %1 do grupo #%2 no canal #%3 ajustada para %4")
                .arg(permKey).arg(groupId).arg(channelId)
                .arg(state == 1 ? "Allow" : (state == 0 ? "Deny" : "Inherit")));
        ok(s);
        return;
    }

    // Pilar 3: Obter permissões de canal (debug)
    if (cmd == QLatin1String("channelpermlist")) {
        const int channelId = args.value(QStringLiteral("cid")).toInt();
        if (channelId <= 0 || !m_channels.contains(channelId)) {
            err(s, 1281, QStringLiteral("canal nao encontrado")); return;
        }
        const SvrChan& ch = m_channels[channelId];
        for (auto it = ch.groupPerms.begin(); it != ch.groupPerms.end(); ++it) {
            const QJsonObject gPerms = it.value().toObject();
            for (auto permIt = gPerms.begin(); permIt != gPerms.end(); ++permIt) {
                QJsonValue val = permIt.value();
                QString stateStr;
                if (val.isBool()) {
                    stateStr = val.toBool() ? "Allow" : "Deny";
                } else if (val.isDouble()) {
                    int s = val.toInt();
                    stateStr = s == 1 ? "Allow" : (s == 0 ? "Deny" : (s == -1 ? "Inherit" : QString::number(s)));
                } else {
                    stateStr = "unknown";
                }
                line(QStringLiteral("cid=%1 gid=%2 perm=%3 state=%4")
                    .arg(channelId).arg(it.key()).arg(permIt.key()).arg(stateStr));
            }
        }
        // Requisitos de position
        for (auto it = ch.groupPositionReqs.begin(); it != ch.groupPositionReqs.end(); ++it) {
            line(QStringLiteral("cid=%1 gid=%2 min_position=%3")
                .arg(channelId).arg(it.key()).arg(it.value().toInt()));
        }
        ok(s);
        return;
    }

    err(s, 256, QStringLiteral("comando nao implementado"));
}
