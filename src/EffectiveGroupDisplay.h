#pragma once

#include <QList>
#include <QString>
#include <QStringList>

// Propriedades visuais de um cargo atribuído. A posição hierárquica usada
// para permissões é deliberadamente independente desta política de exibição.
struct AssignedGroupDisplay {
    QString sigla;
    int order = 0;
    bool siglaAfter = false;
    bool orderEnabled = true;
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

    for (const AssignedGroupDisplay& group : groups) {
        const QString sigla = group.sigla.trimmed();
        if (!sigla.isEmpty()) {
            if (group.siglaAfter) suffixes << sigla;
            else prefixes << sigla;
        }

        if (group.orderEnabled) {
            if (!result.orderEnabled || group.order < result.order)
                result.order = group.order;
            result.orderEnabled = true;
        }
    }

    result.prefixSigla = prefixes.join(QLatin1Char(' '));
    result.suffixSigla = suffixes.join(QLatin1Char(' '));
    return result;
}
