#include "TlsCertificate.h"

#include <QDateTime>
#include <QFile>
#include <QFileInfo>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <memory>

namespace {

QString lastOpenSslError(const QString& fallback) {
    const unsigned long code = ERR_get_error();
    if (code == 0) return fallback;
    char buffer[256] = {};
    ERR_error_string_n(code, buffer, sizeof(buffer));
    return fallback + QStringLiteral(": ") + QString::fromLatin1(buffer);
}

bool addExtension(X509* certificate, int nid, const char* value) {
    X509V3_CTX context;
    X509V3_set_ctx_nodb(&context);
    X509V3_set_ctx(&context, certificate, certificate, nullptr, nullptr, 0);
    X509_EXTENSION* extension = X509V3_EXT_conf_nid(
        nullptr, &context, nid, const_cast<char*>(value));
    if (!extension) return false;
    const bool ok = X509_add_ext(certificate, extension, -1) == 1;
    X509_EXTENSION_free(extension);
    return ok;
}

void setError(QString* destination, const QString& message) {
    if (destination) *destination = message;
}

} // namespace

namespace TlsCertificate {

bool generateSelfSigned(const QString& certificatePath,
                        const QString& privateKeyPath,
                        QString* errorMessage) {
    if (certificatePath.trimmed().isEmpty() || privateKeyPath.trimmed().isEmpty()) {
        setError(errorMessage, QStringLiteral("Caminho de certificado/chave vazio"));
        return false;
    }

    ERR_clear_error();
    using KeyContextPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
    using KeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
    using CertificatePtr = std::unique_ptr<X509, decltype(&X509_free)>;
    using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;

    KeyContextPtr keyContext(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr),
                             &EVP_PKEY_CTX_free);
    if (!keyContext || EVP_PKEY_keygen_init(keyContext.get()) <= 0
            || EVP_PKEY_CTX_set_rsa_keygen_bits(keyContext.get(), 3072) <= 0) {
        setError(errorMessage, lastOpenSslError(QStringLiteral("Falha ao preparar chave RSA")));
        return false;
    }

    EVP_PKEY* generatedKey = nullptr;
    if (EVP_PKEY_keygen(keyContext.get(), &generatedKey) <= 0 || !generatedKey) {
        setError(errorMessage, lastOpenSslError(QStringLiteral("Falha ao gerar chave RSA")));
        return false;
    }
    KeyPtr key(generatedKey, &EVP_PKEY_free);

    CertificatePtr certificate(X509_new(), &X509_free);
    if (!certificate) {
        setError(errorMessage, lastOpenSslError(QStringLiteral("Falha ao criar certificado X.509")));
        return false;
    }

    const qint64 now = QDateTime::currentSecsSinceEpoch();
    const long serial = long((now & 0x7fffffff) == 0 ? 1 : (now & 0x7fffffff));
    if (X509_set_version(certificate.get(), 2) != 1
            || ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), serial) != 1
            || !X509_gmtime_adj(X509_get_notBefore(certificate.get()), 0)
            || !X509_gmtime_adj(X509_get_notAfter(certificate.get()), 825L * 24L * 60L * 60L)
            || X509_set_pubkey(certificate.get(), key.get()) != 1) {
        setError(errorMessage, lastOpenSslError(QStringLiteral("Falha ao preencher certificado")));
        return false;
    }

    X509_NAME* subject = X509_get_subject_name(certificate.get());
    static const unsigned char commonName[] = "HallaServer";
    if (!subject
            || X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
                                          commonName, -1, -1, 0) != 1
            || X509_set_issuer_name(certificate.get(), subject) != 1
            || !addExtension(certificate.get(), NID_basic_constraints, "critical,CA:FALSE")
            || !addExtension(certificate.get(), NID_key_usage, "critical,digitalSignature,keyEncipherment")
            || !addExtension(certificate.get(), NID_ext_key_usage, "serverAuth")
            || !addExtension(certificate.get(), NID_subject_alt_name,
                             "DNS:HallaServer,DNS:localhost,IP:127.0.0.1")
            || X509_sign(certificate.get(), key.get(), EVP_sha256()) <= 0) {
        setError(errorMessage, lastOpenSslError(QStringLiteral("Falha ao assinar certificado")));
        return false;
    }

    const QString certificateTemp = certificatePath + QStringLiteral(".tmp");
    const QString privateKeyTemp = privateKeyPath + QStringLiteral(".tmp");
    QFile::remove(certificateTemp);
    QFile::remove(privateKeyTemp);

    {
        const QByteArray path = QFile::encodeName(privateKeyTemp);
        BioPtr output(BIO_new_file(path.constData(), "wb"), &BIO_free);
        if (!output || PEM_write_bio_PrivateKey(output.get(), key.get(), nullptr,
                                                nullptr, 0, nullptr, nullptr) != 1) {
            QFile::remove(privateKeyTemp);
            setError(errorMessage, lastOpenSslError(QStringLiteral("Falha ao gravar chave privada")));
            return false;
        }
    }
    {
        const QByteArray path = QFile::encodeName(certificateTemp);
        BioPtr output(BIO_new_file(path.constData(), "wb"), &BIO_free);
        if (!output || PEM_write_bio_X509(output.get(), certificate.get()) != 1) {
            QFile::remove(privateKeyTemp);
            QFile::remove(certificateTemp);
            setError(errorMessage, lastOpenSslError(QStringLiteral("Falha ao gravar certificado")));
            return false;
        }
    }

    QFile::remove(privateKeyPath);
    QFile::remove(certificatePath);
    if (!QFile::rename(privateKeyTemp, privateKeyPath)
            || !QFile::rename(certificateTemp, certificatePath)) {
        QFile::remove(privateKeyTemp);
        QFile::remove(certificateTemp);
        QFile::remove(privateKeyPath);
        QFile::remove(certificatePath);
        setError(errorMessage, QStringLiteral("Falha ao instalar certificado/chave gerados"));
        return false;
    }

    QFile::setPermissions(privateKeyPath, QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    QFile::setPermissions(certificatePath,
                          QFileDevice::ReadOwner | QFileDevice::WriteOwner
                          | QFileDevice::ReadGroup | QFileDevice::ReadOther);
    if (errorMessage) errorMessage->clear();
    return true;
}

} // namespace TlsCertificate
