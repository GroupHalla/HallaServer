#include "HallaProtocol.h"
#include "PasswordHash.h"
#include "HierarchyPolicy.h"
#include "EffectiveGroupDisplay.h"
#include "GroupMemberList.h"

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

    // groupEdit só alcança cargos e posições estritamente inferiores.
    if (!HierarchyPolicy::canManageGroup(false, 50, false, 49)) return 30;
    if (HierarchyPolicy::canManageGroup(false, 50, false, 50)) return 31;
    if (HierarchyPolicy::canManageGroup(false, 50, false, 51)) return 32;
    if (HierarchyPolicy::canManageGroup(false, 50, true, 10)) return 33;
    if (!HierarchyPolicy::canManageGroup(true, 10, true, 100)) return 34;
    if (!HierarchyPolicy::canSetGroupPosition(false, 50, 49)) return 35;
    if (HierarchyPolicy::canSetGroupPosition(false, 50, 50)) return 36;
    if (HierarchyPolicy::canSetGroupPosition(false, 50, 51)) return 37;
    if (!HierarchyPolicy::canSetGroupPosition(true, 10, 100)) return 38;
    if (!HierarchyPolicy::hasValidAdminIdentity(true, true)) return 39;
    if (!HierarchyPolicy::hasValidAdminIdentity(false, false)) return 40;
    if (HierarchyPolicy::hasValidAdminIdentity(false, true)) return 41;
    if (HierarchyPolicy::hasValidAdminIdentity(true, false)) return 42;

    // Um cargo com ordem visual desligada não pode elevar o usuário. Outro
    // cargo atribuído e habilitado fornece a ordem efetiva.
    const EffectiveGroupDisplay display = effectiveGroupDisplay({
        {QStringLiteral("[Admin]"), 0, false, false},
        {QStringLiteral("[Membro]"), 40, true, true}
    });
    if (!display.orderEnabled || display.order != 40) return 50;
    if (display.prefixSigla != QStringLiteral("[Admin]")) return 51;
    if (display.suffixSigla != QStringLiteral("[Membro]")) return 52;

    const EffectiveGroupDisplay disabledOnly = effectiveGroupDisplay({
        {QStringLiteral("[Visitante]"), 1, false, false}
    });
    if (disabledOnly.orderEnabled || disabledOnly.order != 100000) return 53;

    QJsonArray members;
    members << QJsonObject{{QStringLiteral("uid"), QStringLiteral("current-user")},
                           {QStringLiteral("name"), QStringLiteral("Nome antigo")},
                           {QStringLiteral("online"), false}};
    upsertOnlineGroupMember(members, 77, QStringLiteral("current-user"),
                            QStringLiteral("Nome atual"));
    if (members.size() != 1) return 60;
    const QJsonObject onlineMember = members.first().toObject();
    if (!onlineMember.value(QStringLiteral("online")).toBool()) return 61;
    if (onlineMember.value(QStringLiteral("id")).toInt() != 77) return 62;
    if (onlineMember.value(QStringLiteral("name")).toString() != QStringLiteral("Nome atual")) return 63;

    qInfo() << "HallaServer self-test OK";
    return 0;
}
