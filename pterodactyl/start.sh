#!/bin/bash

# Halla Server - Pterodactyl Startup & Auto-Updater Script
echo "================================================================="
echo "   Iniciando Halla Server - Pterodactyl Wrapper & Auto-Updater   "
echo "================================================================="

GITHUB_REPO="farleybarbosa320-oss/HallaServer"
LOCAL_VER_FILE="version.txt"
BINARY="./halla-server"

# Função para obter a versão local atual
get_local_version() {
    if [ -f "$LOCAL_VER_FILE" ]; then
        cat "$LOCAL_VER_FILE"
    else
        echo "0.0.0"
    fi
}

echo ">> Verificando atualizações no GitHub..."
LATEST_RELEASE_JSON=$(curl -s "https://api.github.com/repos/${GITHUB_REPO}/releases/latest")
LATEST_TAG=$(echo "$LATEST_RELEASE_JSON" | grep -oP '"tag_name": "\K[^"]+')

if [ -z "$LATEST_TAG" ]; then
    echo ">> FALHA: Não foi possível conectar ao GitHub ou obter a versão mais recente."
    echo ">> Continuando com a versão local existente..."
else
    LOCAL_TAG=$(get_local_version)
    echo ">> Versão local: $LOCAL_TAG"
    echo ">> Versão mais recente no GitHub: $LATEST_TAG"

    if [ "$LATEST_TAG" != "$LOCAL_TAG" ] || [ ! -f "$BINARY" ]; then
        echo ">> Uma nova atualização ($LATEST_TAG) está disponível ou o binário está ausente!"
        echo ">> Buscando URL do download para Linux x64..."
        
        DOWNLOAD_URL=$(echo "$LATEST_RELEASE_JSON" | grep -oP '"browser_download_url": "\K[^"]+linux-x64\.tar\.gz')
        
        if [ -n "$DOWNLOAD_URL" ]; then
            echo ">> Baixando $DOWNLOAD_URL..."
            curl -L -o "halla-server-update.tar.gz" "$DOWNLOAD_URL"
            
            echo ">> Extraindo arquivos..."
            tar -xzf "halla-server-update.tar.gz" --strip-components=1
            
            # Garante que o executável tem permissão de execução
            chmod +x "$BINARY"
            
            # Limpa arquivos temporários
            rm -f halla-server-update.tar.gz
            
            # Grava a versão atualizada localmente
            echo "$LATEST_TAG" > "$LOCAL_VER_FILE"
            echo ">> Atualização para $LATEST_TAG concluída com sucesso!"
        else
            echo ">> FALHA: Não foi possível encontrar o asset linux-x64.tar.gz na release."
        fi
    else
        echo ">> O servidor já está rodando a versão mais recente ($LOCAL_TAG)."
    fi
fi

# Garante permissões
if [ -f "$BINARY" ]; then
    chmod +x "$BINARY"
    echo ">> Iniciando Halla Server..."
    echo "================================================================="
    exec "$BINARY" "$@"
else
    echo ">> ERRO CRÍTICO: O binário halla-server não foi encontrado e não pôde ser baixado!"
    exit 1
fi
