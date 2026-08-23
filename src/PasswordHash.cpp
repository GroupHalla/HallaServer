#include "PasswordHash.h"

#include <QByteArray>
#include <QStringList>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace {
constexpr int kIterations = 210000;
constexpr int kSaltBytes = 16;
constexpr int kHashBytes = 32;

QByteArray derive(const QString& password, const QByteArray& salt, int iterations) {
    QByteArray out(kHashBytes, '\0');
    const QByteArray utf8 = password.toUtf8();
    if (PKCS5_PBKDF2_HMAC(utf8.constData(), utf8.size(),
                          reinterpret_cast<const unsigned char*>(salt.constData()), salt.size(),
                          iterations, EVP_sha256(), out.size(),
                          reinterpret_cast<unsigned char*>(out.data())) != 1) return {};
    return out;
}
}

namespace PasswordHash {

bool isEncoded(const QString& value) {
    return value.startsWith(QStringLiteral("pbkdf2-sha256$"));
}

QString create(const QString& password) {
    if (password.isEmpty()) return {};
    QByteArray salt(kSaltBytes, '\0');
    if (RAND_bytes(reinterpret_cast<unsigned char*>(salt.data()), salt.size()) != 1) return {};
    const QByteArray hash = derive(password, salt, kIterations);
    if (hash.isEmpty()) return {};
    return QStringLiteral("pbkdf2-sha256$%1$%2$%3")
        .arg(kIterations)
        .arg(QString::fromLatin1(salt.toHex()), QString::fromLatin1(hash.toHex()));
}

bool verify(const QString& password, const QString& encoded) {
    if (password.isEmpty() || encoded.isEmpty()) return false;
    if (!isEncoded(encoded)) {
        const QByteArray supplied = password.toUtf8();
        const QByteArray expected = encoded.toUtf8();
        return supplied.size() == expected.size()
            && CRYPTO_memcmp(supplied.constData(), expected.constData(), size_t(expected.size())) == 0;
    }
    const QStringList parts = encoded.split(QLatin1Char('$'));
    if (parts.size() != 4) return false;
    bool ok = false;
    const int iterations = parts[1].toInt(&ok);
    if (!ok || iterations < 100000 || iterations > 2000000) return false;
    const QByteArray salt = QByteArray::fromHex(parts[2].toLatin1());
    const QByteArray expected = QByteArray::fromHex(parts[3].toLatin1());
    if (salt.size() < 16 || expected.size() != kHashBytes) return false;
    const QByteArray supplied = derive(password, salt, iterations);
    return supplied.size() == expected.size()
        && CRYPTO_memcmp(supplied.constData(), expected.constData(), size_t(expected.size())) == 0;
}

} // namespace PasswordHash
