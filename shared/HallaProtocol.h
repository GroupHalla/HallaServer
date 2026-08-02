#pragma once

#include <QJsonObject>
#include <QJsonArray>
#include <QJsonDocument>
#include <QString>
#include <QHostAddress>
#include <QByteArray>

// ============================================================================
// Halla Protocol v2 — camada compartilhada (mesmo código no cliente e servidor)
// Vide PROTOCOL.md para a especificação completa.
// v2: permissões granulares por grupo, banlist, grupos por UID, talk power.
// O servidor aceita clientes v1 (recursos novos exigem v2).
// ============================================================================

namespace HProto {

constexpr quint16 kDefaultPort = 9987;
constexpr quint32 kVoiceMagic = 0x48414C4C; // "HALL"
constexpr int kProtoVersion = 3;    // versão máxima suportada
constexpr int kProtoMin = 1;        // versão mínima aceita pelo servidor

// ---- controle TCP: JSON compactado terminado em '\n' ----------------------
inline QByteArray encodeMsg(const QJsonObject& obj) {
    QByteArray data = QJsonDocument(obj).toJson(QJsonDocument::Compact);
    data.append('\n');
    return data;
}

inline QJsonObject msg(const QString& type) {
    QJsonObject o;
    o["t"] = type;
    return o;
}

// Monta a representação JSON de um usuário
inline QJsonObject userJson(int id, const QString& name, const QString& uid,
                            const QString& ver, const QString& platform,
                            const QString& desc, const QString& group,
                            bool mic, bool spk, bool away, bool rec, bool cc,
                            bool talking) {
    QJsonObject u;
    u["id"] = id; u["name"] = name; u["uid"] = uid; u["ver"] = ver;
    u["platform"] = platform; u["desc"] = desc; u["group"] = group;
    u["mic"] = mic; u["spk"] = spk; u["away"] = away; u["rec"] = rec;
    u["cc"] = cc; u["talking"] = talking;
    return u;
}

// Monta a representação JSON de um canal
inline QJsonObject chanJson(int id, int parent, const QString& name,
                            const QString& topic, const QString& desc, bool pw,
                            bool def, int type, bool moderated, int codec,
                            int quality, int maxClients, const QList<int>& users) {
    QJsonObject c;
    c["id"] = id; c["parent"] = parent; c["name"] = name; c["topic"] = topic;
    c["desc"] = desc; c["pw"] = pw; c["def"] = def; c["type"] = type;
    c["moderated"] = moderated; c["codec"] = codec; c["quality"] = quality;
    c["max"] = maxClients;
    QJsonArray arr;
    for (int u : users) arr << u;
    c["users"] = arr;
    return c;
}

// ---- voz UDP ---------------------------------------------------------------
// cliente -> servidor:  magic | token(u32) | seq(u16) | opus...
inline QByteArray encodeVoiceClient(quint32 token, quint16 seq, const QByteArray& opus) {
    QByteArray p;
    p.reserve(10 + opus.size());
    p.append(reinterpret_cast<const char*>(&kVoiceMagic), 4); // magic já é "HALL" LE
    p[0] = 'H'; p[1] = 'A'; p[2] = 'L'; p[3] = 'L';
    p.append(reinterpret_cast<const char*>(&token), 4);
    p.append(reinterpret_cast<const char*>(&seq), 2);
    p.append(opus);
    return p;
}

// servidor -> cliente:  magic | fromId(u32) | seq(u16) | opus...
inline QByteArray encodeVoiceServer(quint32 fromId, quint16 seq, const QByteArray& opus) {
    QByteArray p;
    p.reserve(10 + opus.size());
    p.append("HALL", 4);
    p.append(reinterpret_cast<const char*>(&fromId), 4);
    p.append(reinterpret_cast<const char*>(&seq), 2);
    p.append(opus);
    return p;
}

} // namespace HProto
