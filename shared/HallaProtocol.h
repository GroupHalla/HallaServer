#pragma once

#include <QJsonObject>
#include <QJsonArray>
#include <QJsonDocument>
#include <QString>
#include <QHostAddress>
#include <QByteArray>

// Protocolo v4: identidade Ed25519, voz AEAD e token UDP aleatório de 128 bits.
namespace HProto {

constexpr quint16 kDefaultPort = 9987;
constexpr int kProtoVersion = 5;
constexpr int kProtoMin = 1;
constexpr int kVoiceTokenBytes = 16;
constexpr int kClientMediaHeaderV4Bytes = 4 + kVoiceTokenBytes + 2;

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

inline QJsonObject userJson(int id, const QString& name, const QString& uid,
                            const QString& ver, const QString& platform,
                            const QString& desc, const QString& group,
                            bool mic, bool spk, bool away, bool rec, bool cc,
                            bool talking, int groupPosition = 0) {
    QJsonObject u;
    u["id"] = id; u["name"] = name; u["uid"] = uid; u["ver"] = ver;
    u["platform"] = platform; u["desc"] = desc; u["group"] = group;
    u["mic"] = mic; u["spk"] = spk; u["away"] = away; u["rec"] = rec;
    u["cc"] = cc; u["talking"] = talking; u["position"] = groupPosition;
    return u;
}

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

// v4 cliente -> servidor: "HAL4" | token(16 bytes) | seq(u16 LE) | AEAD payload.
inline QByteArray encodeClientMediaV4(const char magic[4], const QByteArray& token,
                                      quint16 seq, const QByteArray& payload) {
    if (token.size() != kVoiceTokenBytes) return {};
    QByteArray p;
    p.reserve(kClientMediaHeaderV4Bytes + payload.size());
    p.append(magic, 4);
    p.append(token);
    p.append(reinterpret_cast<const char*>(&seq), 2);
    p.append(payload);
    return p;
}

inline QByteArray encodeVoiceClient(const QByteArray& token, quint16 seq,
                                    const QByteArray& opus) {
    return encodeClientMediaV4("HAL4", token, seq, opus);
}

inline QByteArray encodeScreenClient(const QByteArray& token, quint16 seq,
                                     const QByteArray& payload) {
    return encodeClientMediaV4("HAF4", token, seq, payload);
}

// Compatibilidade cliente legado v1-v3: "HALL" | token(u32) | seq | payload.
inline QByteArray encodeVoiceClientLegacy(quint32 token, quint16 seq,
                                          const QByteArray& opus) {
    QByteArray p;
    p.reserve(10 + opus.size());
    p.append("HALL", 4);
    p.append(reinterpret_cast<const char*>(&token), 4);
    p.append(reinterpret_cast<const char*>(&seq), 2);
    p.append(opus);
    return p;
}

inline QByteArray encodeVoiceClient(quint32 legacyToken, quint16 seq,
                                    const QByteArray& opus) {
    return encodeVoiceClientLegacy(legacyToken, seq, opus);
}

// servidor -> cliente permanece estável: "HALL" | fromId(u32) | seq | payload.
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
