#pragma once

namespace TemporaryChannelPolicy {

inline bool canBeConfiguredParent(int channelType) {
    return channelType != 0;
}

inline int parentForNewChannel(int requestedParent, int newChannelType,
                               int configuredParent) {
    return newChannelType == 0 && configuredParent > 0
        ? configuredParent : requestedParent;
}

} // namespace TemporaryChannelPolicy
