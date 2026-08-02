#include "ServerCore.h"
#include "ClientSession.h"
#include "HallaProtocol.h"

#include <QFile>
#include <QDir>
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
    QSet<int> ids;
    for (const QJsonValue& v : obj["ids"].toArray()) {
        const int id = v.toInt();
        if (m_clients.contains(id) && id != c->id()) ids.insert(id);
    }
    c->setWhisperIds(ids);
    QJsonObject m = HProto::msg("whisper_ok");
    m["count"] = ids.size();
    c->send(m);
    // avisa estilo TS3 no próprio cliente (UI local mostra o modo)
}

// ============================================================== ARQUIVOS (v3)
void ServerCore::handleFtUpload(ClientSession* c, const QJsonObject& obj) {
    const int chan = obj["channel"].toInt();
    if (!m_channels.contains(chan)) return;
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
