#include "VoiceRelay.h"
#include "ServerCore.h"
#include "ClientSession.h"
#include "HallaProtocol.h"

#include <QNetworkDatagram>

VoiceRelay::VoiceRelay(ServerCore* core, QObject* parent)
    : QObject(parent), m_core(core) {}

bool VoiceRelay::bind(quint16 port) {
    m_socket = new QUdpSocket(this);
    if (!m_socket->bind(QHostAddress::Any, port)) {
        m_core->log(QStringLiteral("FALHA: não foi possível abrir a porta UDP %1: %2")
                        .arg(port).arg(m_socket->errorString()));
        return false;
    }
    connect(m_socket, &QUdpSocket::readyRead, this, &VoiceRelay::onReadyRead);
    m_core->log(QStringLiteral("Voz UDP escutando na porta %1").arg(port));
    return true;
}

void VoiceRelay::onReadyRead() {
    while (m_socket->hasPendingDatagrams()) {
        QNetworkDatagram dg = m_socket->receiveDatagram();
        ++m_datagramsIn;
        QByteArray data = dg.data();
        bool isVoice = data.size() >= 10 && memcmp(data.constData(), "HALL", 4) == 0;
        bool isScreenShare = data.size() >= 10 && memcmp(data.constData(), "HALF", 4) == 0;
        if (!isVoice && !isScreenShare) {
            ++m_invalid;
            continue;
        }

        quint32 token;
        quint16 seq;
        memcpy(&token, data.constData() + 4, 4);
        memcpy(&seq,   data.constData() + 8, 2);

        ClientSession* sender = m_core->clientByVoiceToken(token);
        if (!sender) {
            ++m_unknownToken;
            m_core->log(QStringLiteral("UDP: token de voz desconhecido %1 vindo de %2:%3")
                            .arg(token)
                            .arg(dg.senderAddress().toString())
                            .arg(dg.senderPort()));
            continue;
        }

        // Aprende/atualiza o endpoint UDP do remetente antes de validar o
        // payload. Assim até um registro vazio mantém o caminho de retorno
        // aberto atrás de NAT/firewall.
        const bool endpointChanged = sender->udpPort() != dg.senderPort()
                                  || sender->udpAddress() != dg.senderAddress();
        sender->setUdpEndpoint(dg.senderAddress(), dg.senderPort());
        if (endpointChanged) {
            m_core->log(QStringLiteral("UDP: endpoint registrado para #%1 (%2), token %3 -> %4:%5")
                            .arg(sender->id())
                            .arg(sender->name())
                            .arg(token)
                            .arg(dg.senderAddress().toString())
                            .arg(dg.senderPort()));
        }

        const QByteArray payload = data.mid(10);
        if (payload.isEmpty()) continue;
        
        if (isVoice) {
            ++m_opusFramesIn;
            m_opusBytesIn += quint64(payload.size());
            // retransmite aos membros do mesmo canal (exceto o falante)
            m_core->relayVoice(sender, seq, payload);
        } else {
            m_core->relayScreenShare(sender, seq, payload);
        }
    }
}

void VoiceRelay::sendTo(const QHostAddress& addr, quint16 port, const QByteArray& packet) {
    if (!m_socket) return;
    const qint64 written = m_socket->writeDatagram(packet, addr, port);
    if (written < 0) { ++m_sendErrors; return; }
    ++m_datagramsOut;
    m_opusBytesOut += quint64(qMax<qint64>(0, written - 10));
}

QJsonObject VoiceRelay::stats() const {
    QJsonObject out;
    out["udpIn"] = qint64(m_datagramsIn.load());
    out["invalid"] = qint64(m_invalid.load());
    out["unknownToken"] = qint64(m_unknownToken.load());
    out["opusFramesIn"] = qint64(m_opusFramesIn.load());
    out["opusBytesIn"] = qint64(m_opusBytesIn.load());
    out["udpOut"] = qint64(m_datagramsOut.load());
    out["opusBytesOut"] = qint64(m_opusBytesOut.load());
    out["sendErrors"] = qint64(m_sendErrors.load());
    return out;
}
