#pragma once

#include <QList>
#include <QString>

namespace GroupAssignmentPolicy {

// Aplica uma operação explícita de cargo. "toggle" permanece apenas para
// clientes antigos; editores atuais devem enviar "add" ou "remove".
inline void apply(QList<int>& assignments, int groupId, const QString& operation,
                  int defaultGroupId = 2) {
    if (operation == QLatin1String("add")) {
        if (!assignments.contains(groupId)) assignments << groupId;
    } else if (operation == QLatin1String("remove")) {
        assignments.removeAll(groupId);
    } else if (assignments.contains(groupId)) {
        assignments.removeAll(groupId);
    } else {
        assignments << groupId;
    }

    if (assignments.isEmpty()) assignments << defaultGroupId;
}

} // namespace GroupAssignmentPolicy
