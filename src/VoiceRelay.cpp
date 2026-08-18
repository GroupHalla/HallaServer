#include "VoiceRelay.h"
#include "ServerCore.h"
#include "ClientSession.h"
#include "HallaProtocol.h"

#include <QDateTime>
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
        const QNetworkDatagram dg = m_socket->receiveDatagram();
        ++m_datagramsIn;
        const QByteArray data = dg.data();
        if (data.size() > 65507) { ++m_invalid; continue; }

        const bool voiceV4 = data.size() >= HProto::kClientMediaHeaderV4Bytes
                          && memcmp(data.constData(), "HAL4", 4) == 0;
        const bool screenV4 = data.size() >= HProto::kClientMediaHeaderV4Bytes
                           && memcmp(data.constData(), "HAF4", 4) == 0;
        const bool voiceLegacy = data.size() >= 10 && memcmp(data.constData(), "HALL", 4) == 0;
        const bool screenLegacy = data.size() >= 10 && memcmp(data.constData(), "HALF", 4) == 0;
        if (!voiceV4 && !screenV4 && !voiceLegacy && !screenLegacy) {
            ++m_invalid;
            continue;
        }

        ClientSession* sender = nullptr;
        quint16 seq = 0;
        int payloadOffset = 0;
        if (voiceV4 || screenV4) {
            const QByteArray token = data.mid(4, HProto::kVoiceTokenBytes);
            memcpy(&seq, data.constData() + 4 + HProto::kVoiceTokenBytes, 2);
            payloadOffset = HProto::kClientMediaHeaderV4Bytes;
            sender = m_core->clientByVoiceToken(token);
        } else {
            quint32 token = 0;
            memcpy(&token, data.constData() + 4, 4);
            memcpy(&seq, data.constData() + 8, 2);
            payloadOffset = 10;
            sender = m_core->clientByLegacyVoiceToken(token);
        }

        if (!sender) {
            ++m_unknownToken;
            const qint64 now = QDateTime::currentMSecsSinceEpoch();
            if (now - m_lastUnknownLogMs >= 5000) {
                m_lastUnknownLogMs = now;
                m_core->log(QStringLiteral("UDP: datagrama com credencial desconhecida descartado de %1")
                                .arg(dg.senderAddress().toString()));
            }
            continue;
        }

        // A credencial aleatória recebida via TLS autentica o registro NAT.
        // O endpoint só é alterado depois de a credencial ser validada.
        const bool endpointChanged = sender->udpPort() != dg.senderPort()
                                  || sender->udpAddress() != dg.senderAddress();
        sender->setUdpEndpoint(dg.senderAddress(), dg.senderPort());
        if (endpointChanged) {
            m_core->log(QStringLiteral("UDP: endpoint autenticado para #%1 (%2) -> %3:%4")
                            .arg(sender->id()).arg(sender->name(), dg.senderAddress().toString())
                            .arg(dg.senderPort()));
        }

        const QByteArray payload = data.mid(payloadOffset);
        if (payload.isEmpty()) continue;
        if (voiceV4 || voiceLegacy) {
            ++m_opusFramesIn;
            m_opusBytesIn += quint64(payload.size());
            m_core->relayVoice(sender, seq, payload);
        } else {
            m_core->relayScreenShare(sender, seq, payload);
        }
    }
}

void VoiceRelay::sendTo(const QHostAddress& addr, quint16 port, const QByteArray& packet) {
    if (!m_socket || addr.isNull() || port == 0 || packet.isEmpty()) return;
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
