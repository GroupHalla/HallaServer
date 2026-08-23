#pragma once

#include <QList>
#include <QString>
#include <QStringList>

// Propriedades visuais de um cargo atribuído. A posição hierárquica usada
// para permissões é deliberadamente independente desta política de exibição.
// "implicitBase" marca os cargos base adicionados automaticamente
// (guest/normal) quando o usuário não os possui explicitamente: eles só
// entram no cálculo da ordem efetiva se nenhum cargo explícito participar.
// "position" é a hierarquia do cargo usada apenas para ordenar a lista de
// nomes — e apenas por cargos que participam da lista (orderEnabled).
struct AssignedGroupDisplay {
    QString sigla;
    int order = 0;
    bool siglaAfter = false;
    bool orderEnabled = true;
    bool implicitBase = false;
    int position = 0;
};

struct EffectiveGroupDisplay {
    QString prefixSigla;
    QString suffixSigla;
    int order = 100000;
    bool orderEnabled = false;
    // Hierarquia VISUAL (só cargos com orderEnabled): "Usar a ordem deste
    // cargo na lista de nomes" desligado exclui o cargo da ordenação por
    // completo — nem a ordem, nem a hierarquia dele contam na lista.
    int siglaPosition = 0;   // maior posição entre os cargos visuais com sigla
    int visualPosition = 0;  // maior posição entre os cargos visuais
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
            result.visualPosition = qMax(result.visualPosition, group.position);
            if (!sigla.isEmpty())
                result.siglaPosition = qMax(result.siglaPosition, group.position);
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
                result.visualPosition = qMax(result.visualPosition, group.position);
                if (!group.sigla.trimmed().isEmpty())
                    result.siglaPosition = qMax(result.siglaPosition, group.position);
            }
        }
    }

    // Nenhum cargo visual tem sigla: a hierarquia visual é a posição máxima
    // dos cargos visuais (ex.: cargo operacional sem tag, como ROTA).
    if (result.siglaPosition == 0)
        result.siglaPosition = result.visualPosition;

    result.prefixSigla = prefixes.join(QLatin1Char(' '));
    result.suffixSigla = suffixes.join(QLatin1Char(' '));
    return result;
}
