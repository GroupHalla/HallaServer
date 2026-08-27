#pragma once

#include <QObject>
#include <QTcpSocket>
#include <QJsonObject>
#include <QHostAddress>
#include <QDateTime>
#include <QSet>
#include <QMap>

class ServerCore;

// Sessão TCP de um cliente conectado (estado de controle + endpoint de voz)
class ClientSession : public QObject {
    Q_OBJECT
public:
    ClientSession(QTcpSocket* socket, ServerCore* core, QObject* parent = nullptr);

    int id() const { return m_id; }
    void setId(int id) { m_id = id; }

    QString name() const { return m_name; }
    QString uniqueId() const { return m_uid; }
    QString version() const { return m_version; }
    QString platform() const { return m_platform; }
    QString description() const { return m_desc; }
    QString group() const { return m_group; }
    // Só os NOMES dos cargos (sem "<icone> <nome>") — para o log do console
    // do servidor, que não deve exibir nome de arquivo de ícone
    // ("rota.png ROTA" virava lixo visual no terminal).
    QString groupNames() const { return m_groupNames; }
    int groupId() const { return m_groupId; }
    QString sigla() const { return m_sigla; }
    QString siglaSuffix() const { return m_siglaSuffix; }
    QString icon() const { return m_icon; }
    int groupOrder() const { return m_groupOrder; }
    bool groupOrderEnabled() const { return m_groupOrderEnabled; }
    int groupPosition() const { return m_groupPosition; }  // Pilar 1: posição hierárquica
    int siglaPosition() const { return m_siglaPosition; } // hierarquia do cargo com tag visível
    QHostAddress ip() const;

    bool micMuted() const { return m_micMuted; }
    bool spkMuted() const { return m_spkMuted; }
    bool away() const { return m_away; }
    bool recording() const { return m_recording; }
    bool commander() const { return m_commander; }
    bool talking() const { return m_talking; }
    bool screensharing() const { return m_screensharing; }

    QHostAddress udpAddress() const { return m_udpAddr; }
    quint16 udpPort() const { return m_udpPort; }

    QJsonObject toJson(bool talking = false) const;

    void send(const QJsonObject& obj);
    void sendRaw(const QByteArray& data);
    void closeAndDelete();

    void setName(const QString& n)          { m_name = n; }
    void setDescription(const QString& d)   { m_desc = d; }
    void setUid(const QString& u)           { m_uid = u; }
    void setVersion(const QString& v)       { m_version = v; }
    void setPlatform(const QString& p)      { m_platform = p; }
    void setGroup(const QString& g)         { m_group = g; }
    void setGroupNames(const QString& g)    { m_groupNames = g; }
    void setGroupId(int g)                  { m_groupId = g; }
    void setSigla(const QString& s)         { m_sigla = s; }
    void setSiglaSuffix(const QString& s)   { m_siglaSuffix = s; }
    void setIcon(const QString& i)          { m_icon = i; }
    void setGroupOrder(int o)               { m_groupOrder = o; }
    void setGroupOrderEnabled(bool enabled) { m_groupOrderEnabled = enabled; }
    void setGroupPosition(int p)            { m_groupPosition = p; }  // Pilar 1
    void setSiglaPosition(int p)            { m_siglaPosition = p; }
    void setMicMuted(bool v)                { m_micMuted = v; }
    void setSpkMuted(bool v)                { m_spkMuted = v; }
    void setAway(bool v)                    { m_away = v; }
    void setRecording(bool v)               { m_recording = v; }
    void setCommander(bool v)               { m_commander = v; }
    void setTalking(bool v)                 { m_talking = v; }
    void setScreensharing(bool v)           { m_screensharing = v; }
    void setUdpEndpoint(const QHostAddress& addr, quint16 port) {
        m_udpAddr = addr; m_udpPort = port; m_lastUdpSeen = QDateTime::currentDateTimeUtc();
    }
    void clearUdpEndpoint() { m_udpAddr = QHostAddress(); m_udpPort = 0; }
    void setProtocolVersion(int version)    { m_protocolVersion = version; }
    int protocolVersion() const             { return m_protocolVersion; }
    void setVoiceToken(const QByteArray& token) { m_voiceToken = token; }
    QByteArray voiceToken() const           { return m_voiceToken; }
    void setLegacyVoiceToken(quint32 token) { m_legacyVoiceToken = token; }
    quint32 legacyVoiceToken() const        { return m_legacyVoiceToken; }
    bool hasVoiceToken() const              { return !m_voiceToken.isEmpty() || m_legacyVoiceToken != 0; }

    // v3: sussurro (whisper) — conjunto de alvos; vazio = fala normal no canal
    QSet<int> whisperIds() const            { return m_whisperIds; }
    void setWhisperIds(const QSet<int>& s)  { m_whisperIds = s; }
    // v3: avatar
    QString avatarHash() const              { return m_avatarHash; }
    void setAvatarHash(const QString& h)    { m_avatarHash = h; }

    QDateTime connectedAt() const           { return m_connectedAt; }
    QDateTime lastActivityAt() const        { return m_lastActivity; }
    QDateTime lastUdpSeenAt() const         { return m_lastUdpSeen; }
    bool allowRate(const QString& type, int maxEvents, int windowMs);

    void setIdentityVerified(bool on) { m_identityVerified = on; }
    bool identityVerified() const { return m_identityVerified; }
    void setAdminAuthenticated(bool on) { m_adminAuthenticated = on; }
    bool adminAuthenticated() const { return m_adminAuthenticated; }
    void setPendingIdentity(const QJsonObject& hello, const QByteArray& pub, const QByteArray& nonce) {
        m_pendingIdentityHello = hello; m_pendingIdentityPub = pub; m_pendingIdentityNonce = nonce;
    }
    QJsonObject pendingIdentityHello() const { return m_pendingIdentityHello; }
    QByteArray pendingIdentityPub() const { return m_pendingIdentityPub; }
    QByteArray pendingIdentityNonce() const { return m_pendingIdentityNonce; }
    void clearPendingIdentity() { m_pendingIdentityHello = QJsonObject(); m_pendingIdentityPub.clear(); m_pendingIdentityNonce.clear(); }

signals:
    void messageReceived(ClientSession* client, const QJsonObject& obj);
    void disconnected(ClientSession* client);

private slots:
    void onReadyRead();
    void onDisconnected();

private:
    QTcpSocket* m_socket;
    ServerCore* m_core;
    QByteArray m_buffer;

    int m_id = 0;
    QString m_name;
    QString m_uid;
    QString m_version;
    QString m_platform;
    QString m_desc;
    QString m_group = "normal";
    QString m_groupNames = QStringLiteral("normal");
    int m_groupId = 2;
    QString m_sigla;
    QString m_siglaSuffix;
    QString m_icon;
    int m_groupOrder = 0;
    bool m_groupOrderEnabled = true;
    int m_groupPosition = 0;  // Pilar 1: posição hierárquica do grupo
    int m_siglaPosition = 0;  // hierarquia do cargo com sigla visível (fallback: position máxima)
    bool m_micMuted = false;
    bool m_spkMuted = false;
    bool m_away = false;
    bool m_recording = false;
    bool m_commander = false;
    bool m_talking = false;
    bool m_screensharing = false;
    QHostAddress m_udpAddr;
    quint16 m_udpPort = 0;
    int m_protocolVersion = 1;
    QByteArray m_voiceToken;       // v4: token aleatório de 128 bits
    quint32 m_legacyVoiceToken = 0; // v1-v3: compatibilidade temporária
    QSet<int> m_whisperIds;
    QString m_avatarHash;
    QDateTime m_connectedAt = QDateTime::currentDateTime();
    QDateTime m_lastActivity = QDateTime::currentDateTimeUtc();
    QDateTime m_lastUdpSeen;
    QMap<QString, QList<qint64>> m_rateBuckets;
    bool m_identityVerified = false;
    bool m_adminAuthenticated = false;
    QJsonObject m_pendingIdentityHello;
    QByteArray m_pendingIdentityPub;
    QByteArray m_pendingIdentityNonce;
};
