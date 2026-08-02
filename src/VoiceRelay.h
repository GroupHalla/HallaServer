#pragma once

#include <QObject>
#include <QUdpSocket>
#include <QHostAddress>

class ServerCore;

// Relay de voz UDP: recebe pacotes Opus, resolve o remetente pelo token e
// retransmite para os membros do mesmo canal. Nunca decodifica áudio.
class VoiceRelay : public QObject {
    Q_OBJECT
public:
    explicit VoiceRelay(ServerCore* core, QObject* parent = nullptr);

    bool bind(quint16 port);
    quint16 port() const { return m_socket ? m_socket->localPort() : 0; }

    void sendTo(const QHostAddress& addr, quint16 port, const QByteArray& packet);

private slots:
    void onReadyRead();

private:
    QUdpSocket* m_socket = nullptr;
    ServerCore* m_core;
};
