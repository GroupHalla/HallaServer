#pragma once

#include <QList>
#include <QString>
#include <QStringList>

// Propriedades visuais de um cargo atribuído. A posição hierárquica usada
// para permissões é deliberadamente independente desta política de exibição.
// "implicitBase" marca os cargos base adicionados automaticamente
// (guest/normal) quando o usuário não os possui explicitamente: eles só
// entram no cálculo da ordem efetiva se nenhum cargo explícito participar.
struct AssignedGroupDisplay {
    QString sigla;
    int order = 0;
    bool siglaAfter = false;
    bool orderEnabled = true;
    bool implicitBase = false;
};

struct EffectiveGroupDisplay {
    QString prefixSigla;
    QString suffixSigla;
    int order = 100000;
    bool orderEnabled = false;
};

inline EffectiveGroupDisplay effectiveGroupDisplay(const QList<AssignedGroupDisplay>& groups) {
    EffectiveGroupDisplay result;
    QStringList prefixes;
    QStringList suffixes;
    bool explicitOrder = false;

    for (const AssignedGroupDisplay& group : groups) {
        const QString sigla = group.sigla.trimmed();
        if (!sigla.isEmpty()) {
            if (group.siglaAfter) suffixes << sigla;
            else prefixes << sigla;
        }

        if (group.orderEnabled && !group.implicitBase) {
            if (!explicitOrder || group.order < result.order)
                result.order = group.order;
            explicitOrder = true;
            result.orderEnabled = true;
        }
    }

    // Nenhum cargo explícito definiu a ordem: recua para os cargos base
    // implícitos (guest/normal), preservando o comportamento de usuários
    // sem cargos personalizados. Sem isso, a base "normal" (ordem 10)
    // arrastaria todos os usuários para a mesma ordem efetiva, anulando a
    // ordem visual dos cargos reais (bug: patentes acima de cabos
    // ordenavam empatados e caíam no alfabético).
    if (!explicitOrder) {
        for (const AssignedGroupDisplay& group : groups) {
            if (group.implicitBase && group.orderEnabled) {
                if (!result.orderEnabled || group.order < result.order)
                    result.order = group.order;
                result.orderEnabled = true;
            }
        }
    }

    result.prefixSigla = prefixes.join(QLatin1Char(' '));
    result.suffixSigla = suffixes.join(QLatin1Char(' '));
    return result;
}
