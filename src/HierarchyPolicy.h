#pragma once

namespace HierarchyPolicy {

// Um administrador total pode gerenciar qualquer cargo. Os demais só podem
// gerenciar cargos estritamente abaixo de sua posição, nunca cargos com acesso
// total, de mesma posição ou acima.
inline bool canManageGroup(bool executorIsSuperAdmin,
                           int executorPosition,
                           bool targetIsSuperAdmin,
                           int targetPosition) {
    return executorIsSuperAdmin
        || (!targetIsSuperAdmin && executorPosition > targetPosition);
}

// Um administrador total pode definir qualquer posição. Os demais só podem
// criar ou reposicionar cargos estritamente abaixo da própria hierarquia.
inline bool canSetGroupPosition(bool executorIsSuperAdmin,
                                int executorPosition,
                                int requestedPosition) {
    return executorIsSuperAdmin || requestedPosition < executorPosition;
}

// O nome administrativo reservado pertence exclusivamente ao cargo interno.
inline bool hasValidAdminIdentity(bool isBuiltInAdminGroup, bool usesAdminName) {
    return isBuiltInAdminGroup == usesAdminName;
}

} // namespace HierarchyPolicy
