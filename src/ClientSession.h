#pragma once

#include <QObject>
#include <QTcpSocket>
#include <QJsonObject>
#include <QHostAddress>
#include <QDateTime>

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

    bool micMuted() const { return m_micMuted; }
    bool spkMuted() const { return m_spkMuted; }
    bool away() const { return m_away; }
    bool recording() const { return m_recording; }
    bool commander() const { return m_commander; }
    bool talking() const { return m_talking; }

    QHostAddress udpAddress() const { return m_udpAddr; }
    quint16 udpPort() const { return m_udpPort; }

    QJsonObject toJson(bool talking = false) const;

    void send(const QJsonObject& obj);
    void sendRaw(const QByteArray& data);
    void closeAndDelete();

    void setName(const QString& n)          { m_name = n; }
    void setDescription(const QString& d)   { m_desc = d; }
    void setGroup(const QString& g)         { m_group = g; }
    void setMicMuted(bool v)                { m_micMuted = v; }
    void setSpkMuted(bool v)                { m_spkMuted = v; }
    void setAway(bool v)                    { m_away = v; }
    void setRecording(bool v)               { m_recording = v; }
    void setCommander(bool v)               { m_commander = v; }
    void setTalking(bool v)                 { m_talking = v; }
    void setUdpEndpoint(const QHostAddress& addr, quint16 port) {
        m_udpAddr = addr; m_udpPort = port;
    }
    void setVoiceToken(quint32 token)       { m_voiceToken = token; }
    quint32 voiceToken() const              { return m_voiceToken; }

    QDateTime connectedAt() const           { return m_connectedAt; }

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
    bool m_micMuted = false;
    bool m_spkMuted = false;
    bool m_away = false;
    bool m_recording = false;
    bool m_commander = false;
    bool m_talking = false;
    QHostAddress m_udpAddr;
    quint16 m_udpPort = 0;
    quint32 m_voiceToken = 0;
    QDateTime m_connectedAt = QDateTime::currentDateTime();
};
