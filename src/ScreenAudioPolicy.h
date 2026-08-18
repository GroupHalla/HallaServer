#pragma once

#include <QString>

namespace ScreenAudioPolicy {

// O broadcaster Android publica a track WebRTC para viewers Mobile e também o
// fluxo HAG4 para compatibilidade com o mixer do Desktop. O servidor entrega
// HAGA somente a plataformas não Android para evitar reprodução duplicada.
inline bool shouldRelayHagaToPlatform(const QString& platform) {
    return platform.compare(QStringLiteral("Android"), Qt::CaseInsensitive) != 0;
}

} // namespace ScreenAudioPolicy
