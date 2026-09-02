#include "HallaProtocol.h"
#include "PasswordHash.h"
#include "HierarchyPolicy.h"
#include "EffectiveGroupDisplay.h"
#include "GroupMemberList.h"
#include "GroupAssignmentPolicy.h"
#include "TemporaryChannelPolicy.h"
#include "TlsCertificate.h"

#include <QCoreApplication>
#include <QDebug>
#include <QFile>
#include <QSslCertificate>
#include <QSslKey>
#include <QTemporaryDir>

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
    if (HProto::kProtoVersion != 6 || HProto::kVoiceTokenBytes != 16) return 23;

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

    // A base implícita "normal" (ordem 10) não pode arrastar a ordem efetiva
    // quando um cargo explícito participa: patentes (Cabo/3º Sargento etc.)
    // precisam ordenar entre si pelas próprias ordens visuais.
    const EffectiveGroupDisplay cabo = effectiveGroupDisplay({
        {QStringLiteral("[Cb]"), 13, false, true, false},
        {QStringLiteral(""), 10, false, true, true}
    });
    if (!cabo.orderEnabled || cabo.order != 13) return 54;

    // Sem cargo explícito nenhum, a base implícita segue definindo a ordem.
    const EffectiveGroupDisplay semCargo = effectiveGroupDisplay({
        {QStringLiteral(""), 10, false, true, true}
    });
    if (!semCargo.orderEnabled || semCargo.order != 10) return 55;

    // Cargo explícito com ordem desligada não participa; a base implícita
    // assume (o usuário continua ordenado pelo "normal" até habilitarem).
    const EffectiveGroupDisplay baseAssume = effectiveGroupDisplay({
        {QStringLiteral("[ROTA]"), 5, false, false, false},
        {QStringLiteral(""), 10, false, true, true}
    });
    if (!baseAssume.orderEnabled || baseAssume.order != 10) return 56;

    // "Usar a ordem deste cargo na lista de nomes" desligado remove o cargo
    // da ordenação POR COMPLETO: admin (position 100, sigla [ADM]) com ordem
    // desligada não pode elevar o usuário acima do Cb (position 50) nem da
    // base normal (position 10). A hierarquia visual vem só dos cargos ativos.
    const EffectiveGroupDisplay adminDesligado = effectiveGroupDisplay({
        {QStringLiteral("[ADM]"), 0, false, false, false, 100},
        {QStringLiteral("[Cb]"), 13, false, true, false, 50},
        {QStringLiteral(""), 10, false, true, true, 10}
    });
    if (!adminDesligado.orderEnabled || adminDesligado.order != 13) return 57;
    if (adminDesligado.siglaPosition != 50) return 58;
    if (adminDesligado.visualPosition != 50) return 59;

    // Só o admin desligado + base implícita: hierarquia visual = normal (10).
    const EffectiveGroupDisplay adminSozinho = effectiveGroupDisplay({
        {QStringLiteral("[ADM]"), 0, false, false, false, 100},
        {QStringLiteral(""), 10, false, true, true, 10}
    });
    if (!adminSozinho.orderEnabled || adminSozinho.order != 10) return 60;
    if (adminSozinho.siglaPosition != 10 || adminSozinho.visualPosition != 10) return 61;

    // Cargo operacional sem sigla (ex.: ROTA) com ordem ativa: define a
    // hierarquia visual apenas quando nenhum cargo COM sigla participa.
    const EffectiveGroupDisplay rotaSemSigla = effectiveGroupDisplay({
        {QStringLiteral("[Cb]"), 13, false, true, false, 50},
        {QStringLiteral(""), 5, false, true, false, 200}
    });
    if (rotaSemSigla.siglaPosition != 50 || rotaSemSigla.visualPosition != 200) return 62;

    const EffectiveGroupDisplay soRota = effectiveGroupDisplay({
        {QStringLiteral(""), 5, false, true, false, 200}
    });
    if (soRota.siglaPosition != 200 || soRota.visualPosition != 200) return 63;

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

    // A primeira inicialização em Pterodactyl não pode depender do executável
    // /usr/bin/openssl, pois LD_LIBRARY_PATH aponta para as libs do pacote.
    QTemporaryDir tlsDirectory;
    if (!tlsDirectory.isValid()) return 70;
    const QString certificatePath = tlsDirectory.filePath(QStringLiteral("cert.pem"));
    const QString privateKeyPath = tlsDirectory.filePath(QStringLiteral("key.pem"));
    QString certificateError;
    if (!TlsCertificate::generateSelfSigned(certificatePath, privateKeyPath,
                                            &certificateError)) {
        qWarning() << certificateError;
        return 71;
    }
    QFile certificateFile(certificatePath);
    QFile privateKeyFile(privateKeyPath);
    if (!certificateFile.open(QIODevice::ReadOnly)
            || !privateKeyFile.open(QIODevice::ReadOnly)) return 72;
    const QSslCertificate generatedCertificate(&certificateFile, QSsl::Pem);
    const QSslKey generatedKey(privateKeyFile.readAll(), QSsl::Rsa, QSsl::Pem,
                               QSsl::PrivateKey);
    if (generatedCertificate.isNull() || generatedKey.isNull()) return 73;
    if (generatedCertificate.subjectInfo(QSslCertificate::CommonName)
            != QStringList{QStringLiteral("HallaServer")}) return 74;

    QList<int> assignments{3};
    GroupAssignmentPolicy::apply(assignments, 3, QStringLiteral("remove"));
    if (assignments != QList<int>{2}) return 80; // remover o próprio Admin
    GroupAssignmentPolicy::apply(assignments, 100, QStringLiteral("add"));
    GroupAssignmentPolicy::apply(assignments, 100, QStringLiteral("add"));
    if (assignments != QList<int>{2, 100}) return 81; // add idempotente
    GroupAssignmentPolicy::apply(assignments, 100, QStringLiteral("remove"));
    if (assignments != QList<int>{2}) return 82;
    GroupAssignmentPolicy::apply(assignments, 101, QStringLiteral("toggle"));
    GroupAssignmentPolicy::apply(assignments, 101, QStringLiteral("toggle"));
    if (assignments != QList<int>{2}) return 83; // compatibilidade legada

    if (TemporaryChannelPolicy::parentForNewChannel(7, 0, 42) != 42) return 90;
    if (TemporaryChannelPolicy::parentForNewChannel(7, 1, 42) != 7) return 91;
    if (TemporaryChannelPolicy::parentForNewChannel(7, 2, 42) != 7) return 92;
    if (TemporaryChannelPolicy::canBeConfiguredParent(0)) return 93;
    if (!TemporaryChannelPolicy::canBeConfiguredParent(2)) return 94;

    qInfo() << "HallaServer self-test OK";
    return 0;
}
