#pragma once

#include <QString>

namespace TlsCertificate {

// Gera certificado e chave RSA em PEM usando a mesma libcrypto carregada pelo
// servidor. Não invoca /usr/bin/openssl, que pode herdar LD_LIBRARY_PATH do
// pacote Pterodactyl e carregar bibliotecas incompatíveis com o executável do
// sistema.
bool generateSelfSigned(const QString& certificatePath,
                        const QString& privateKeyPath,
                        QString* errorMessage = nullptr);

} // namespace TlsCertificate
