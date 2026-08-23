#pragma once

#include <QString>

namespace PasswordHash {

QString create(const QString& password);
bool verify(const QString& password, const QString& encoded);
bool isEncoded(const QString& value);

} // namespace PasswordHash
