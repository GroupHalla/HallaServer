#include "ClientSession.h"
#include "ServerCore.h"

#include <QJsonDocument>
#include <QDateTime>

ClientSession::ClientSession(QTcpSocket* socket, ServerCore* core, QObject* parent)
    : QObject(parent), m_socket(socket), m_core(core) {
    m_socket->setParent(this); // assume posse do socket pendente
    m_socket->setSocketOption(QAbstractSocket::KeepAliveOption, 1);
    connect(m_socket, &QTcpSocket::readyRead, this, &ClientSession::onReadyRead);
    connect(m_socket, &QTcpSocket::disconnected, this, &ClientSession::onDisconnected);
}

void ClientSession::onReadyRead() {
    static constexpr int kMaxTcpMessageBytes = 2 * 1024 * 1024;
    m_lastActivity = QDateTime::currentDateTimeUtc();
    m_buffer += m_socket->readAll();
    if (m_buffer.size() > kMaxTcpMessageBytes) {
        QJsonObject e;
        e["t"] = "error";
        e["code"] = "message_too_big";
        e["msg"] = "Mensagem TCP excede 2 MiB";
        send(e);
        closeAndDelete();
        return;
    }
    int idx;
    while ((idx = m_buffer.indexOf('\n')) >= 0) {
        QByteArray line = m_buffer.left(idx).trimmed();
        m_buffer = m_buffer.mid(idx + 1);
        if (line.size() > kMaxTcpMessageBytes) {
            QJsonObject e;
            e["t"] = "error";
            e["code"] = "message_too_big";
            e["msg"] = "Mensagem TCP excede 2 MiB";
            send(e);
            closeAndDelete();
            return;
        }
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

bool ClientSession::allowRate(const QString& type, int maxEvents, int windowMs) {
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    QList<qint64>& bucket = m_rateBuckets[type];
    for (int i = bucket.size() - 1; i >= 0; --i) {
        if (now - bucket[i] > windowMs) bucket.removeAt(i);
    }
    if (bucket.size() >= maxEvents) return false;
    bucket << now;
    return true;
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
    u["siglaSuffix"] = m_siglaSuffix;
    u["icon"] = m_icon;
    u["order"] = m_groupOrder;
    u["orderEnabled"] = m_groupOrderEnabled;
    u["position"] = m_groupPosition;  // Pilar 1: posição hierárquica
    u["mic"] = m_micMuted; u["spk"] = m_spkMuted; u["away"] = m_away;
    u["rec"] = m_recording; u["cc"] = m_commander; u["talking"] = m_talking;
    u["screensharing"] = m_screensharing;
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
