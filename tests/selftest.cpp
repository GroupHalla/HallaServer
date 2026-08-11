#include "HallaProtocol.h"
#include "PasswordHash.h"

#include <QCoreApplication>
#include <QDebug>

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    const QString encoded = PasswordHash::create(QStringLiteral("correct horse battery staple"));
    if (!PasswordHash::isEncoded(encoded) || encoded.contains(QStringLiteral("correct horse"))) return 10;
    if (!PasswordHash::verify(QStringLiteral("correct horse battery staple"), encoded)) return 11;
    if (PasswordHash::verify(QStringLiteral("wrong"), encoded)) return 12;

    const QByteArray token = QByteArray::fromHex("00112233445566778899aabbccddeeff");
    const QByteArray packet = HProto::encodeVoiceClient(token, 42, QByteArray("opus"));
    if (packet.size() != HProto::kClientMediaHeaderV4Bytes + 4) return 20;
    if (!packet.startsWith("HAL4") || packet.mid(4, 16) != token) return 21;
    if (!HProto::encodeVoiceClient(QByteArray(15, 'x'), 1, {}).isEmpty()) return 22;
    if (HProto::kProtoVersion != 4 || HProto::kVoiceTokenBytes != 16) return 23;

    qInfo() << "HallaServer self-test OK";
    return 0;
}
