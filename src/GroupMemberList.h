#pragma once

#include <QJsonArray>
#include <QJsonObject>
#include <QString>

inline void upsertOnlineGroupMember(QJsonArray& members, int id,
                                    const QString& uid, const QString& name) {
    QJsonObject onlineMember;
    onlineMember[QStringLiteral("id")] = id;
    onlineMember[QStringLiteral("uid")] = uid;
    onlineMember[QStringLiteral("name")] = name;
    onlineMember[QStringLiteral("online")] = true;

    for (int i = 0; i < members.size(); ++i) {
        if (members.at(i).toObject().value(QStringLiteral("uid")).toString() == uid) {
            members[i] = onlineMember;
            return;
        }
    }
    members << onlineMember;
}
