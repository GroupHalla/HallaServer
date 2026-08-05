#include "ClientSession.h"
#include "ServerCore.h"

#include <QJsonDocument>

ClientSession::ClientSession(QTcpSocket* socket, ServerCore* core, QObject* parent)
    : QObject(parent), m_socket(socket), m_core(core) {
    m_socket->setParent(this); // assume posse do socket pendente
    m_socket->setSocketOption(QAbstractSocket::KeepAliveOption, 1);
    connect(m_socket, &QTcpSocket::readyRead, this, &ClientSession::onReadyRead);
    connect(m_socket, &QTcpSocket::disconnected, this, &ClientSession::onDisconnected);
}

void ClientSession::onReadyRead() {
    m_buffer += m_socket->readAll();
    int idx;
    while ((idx = m_buffer.indexOf('\n')) >= 0) {
        QByteArray line = m_buffer.left(idx).trimmed();
        m_buffer = m_buffer.mid(idx + 1);
        if (line.isEmpty()) continue;
        QJsonParseError err;
        QJsonDocument doc = QJsonDocument::fromJson(line, &err);
        if (err.error != QJsonParseError::NoError || !doc.isObject()) {
            QJsonObject e;
            e["t"] = "error";
            e["code"] = "bad_json";
            e["msg"] = "Mensagem inválida";
            send(e);
            continue;
        }
        emit messageReceived(this, doc.object());
    }
}

void ClientSession::onDisconnected() {
    emit disconnected(this);
}

QHostAddress ClientSession::ip() const {
    QHostAddress a = m_socket->peerAddress();
    // normaliza IPv4-mapeado (::ffff:127.0.0.1) para 127.0.0.1
    if (a.protocol() == QAbstractSocket::IPv6Protocol) {
        bool ok = false;
        const QHostAddress v4(a.toIPv4Address(&ok));
        if (ok) return v4;
    }
    return a;
}

QJsonObject ClientSession::toJson(bool) const {
    QJsonObject u;
    u["id"] = m_id; u["name"] = m_name; u["uid"] = m_uid; u["ver"] = m_version;
    u["platform"] = m_platform; u["desc"] = m_desc; u["group"] = m_group;
    u["gid"] = m_groupId;
    u["sigla"] = m_sigla;
    u["icon"] = m_icon;
    u["order"] = m_groupOrder;
    u["mic"] = m_micMuted; u["spk"] = m_spkMuted; u["away"] = m_away;
    u["rec"] = m_recording; u["cc"] = m_commander; u["talking"] = m_talking;
    u["registered"] = m_registered;
    u["whispering"] = (m_talking && !m_whisperIds.isEmpty());
    if (!m_avatarHash.isEmpty()) u["av"] = m_avatarHash;
    return u;
}

void ClientSession::send(const QJsonObject& obj) {
    sendRaw(QJsonDocument(obj).toJson(QJsonDocument::Compact) + '\n');
}

void ClientSession::sendRaw(const QByteArray& data) {
    if (m_socket && m_socket->state() == QAbstractSocket::ConnectedState)
        m_socket->write(data);
}

void ClientSession::closeAndDelete() {
    disconnect(m_socket, nullptr, this, nullptr);
    m_socket->flush();
    m_socket->waitForBytesWritten(400); // garante entrega do que está no buffer
    m_socket->disconnectFromHost();
    deleteLater();
}
