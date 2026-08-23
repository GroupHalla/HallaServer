#pragma once

#include <QObject>
#include <QUdpSocket>
#include <QHostAddress>
#include <QJsonObject>
#include <atomic>

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
    // Contadores agregados: nunca incluem conteúdo de voz.
    QJsonObject stats() const;

private slots:
    void onReadyRead();

private:
    QUdpSocket* m_socket = nullptr;
    ServerCore* m_core;
    std::atomic<quint64> m_datagramsIn {0}, m_invalid {0}, m_unknownToken {0};
    std::atomic<quint64> m_opusFramesIn {0}, m_opusBytesIn {0};
    std::atomic<quint64> m_datagramsOut {0}, m_opusBytesOut {0}, m_sendErrors {0};
    qint64 m_lastUnknownLogMs = 0;
};
