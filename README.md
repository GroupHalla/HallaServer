# Halla Server

Servidor de voz e chat auto-hospedável da família Halla — seu próprio
"TeamSpeak", com protocolo aberto e documentado
([PROTOCOL.md](PROTOCOL.md)).

- **Voz real por UDP** com relay Opus de baixíssima latência (o servidor nunca
  decodifica áudio — baixa CPU, ~0 ms adicionados)
- **Canais e sub-canais**: padrão, temporários, semi-permanentes, permanentes,
  com senha, moderados, limite de clientes
- **Chat**: servidor, canal e privado (com BBCode no cliente)
- **Cutucar (poke)**, estados (mic mudo, fones mudos, ausente, gravando,
  comandante), indicador "está falando" em tempo real
- **Permissões granulares por grupo** (v2 — Cenário 3): cada grupo é um
  conjunto de permissões (kick, ban, banList, mover outros, criar/editar/
  excluir canais por tipo, editar servidor, gerenciar grupos, poke,
  ignorar senha de canal, talk power...). Grupos embutidos: convidado,
  normal, admin — e **grupos customizados** criados via protocolo.
- **Grupos atribuídos por identidade (UID)**: a atribuição é permanente
  (persistente em `halla-data.json`), inclusive para clientes offline
- **Poder de fala (talk power)**: canais moderados exigem poder mínimo;
  quem não tem, não fala (voz nem é retransmitida)
- **Chaves de privilégio aprimoradas**: `CHAVE@grupo` no INI e uso único
  por padrão (`privilegeKeyReuse = true` para reutilizá-las)
- **Moderação**: kick de canal/servidor, banimento temporário ou permanente
  por UID **e** IP, lista de banidos via protocolo (`banlist`/`unban`),
  tudo persistente em `halla-bans.json`
- **Persistência**: canais, grupos, atribuições, chaves usadas e registro
  de identidades salvos em `halla-data.json`; temporários somem quando
  ficam vazios
- **Avatares** (v3): enviados pelos clientes, guardados por UID no disco e
  distribuídos a quem pedir
- **Mensagens offline** (v3): caixa postal por UID — quem estava ausente
  recebe as mensagens ao conectar
- **Reclamações** (v3): usuários registram queixas sobre outros; admins
  listam e limpam via protocolo
- **Operadores de canal** (v3): quem cria um canal gerencia o próprio canal
  (editar e expulsar dele) — o "channel admin" do TeamSpeak
- **Sussurro** (v3): o cliente direciona a própria voz a uma lista de
  usuários, independente dos canais
- **Transferência de arquivos por canal** (v3): upload/download/exclusão de
  arquivos por canal, persistidos no disco do servidor
- **Multi-plataforma**: Linux e Windows (64-bit)

Feito para ser usado com o cliente **[Halla](https://github.com/farleybarbosa320-oss/Halla)**,
mas o protocolo é aberto — bots e outros clientes podem ser escritos em
qualquer linguagem (JSON sobre TCP + UDP para voz).

## Início rápido

### Linux

```bash
tar xf halla-server-3.0.0-linux-x64.tar.gz
cd halla-server
./halla-server --config halla-server.ini
```

### Windows

Baixe `halla-server-3.0.0-win64.zip`, extraia e execute:

```
halla-server.exe
```

O servidor escuta na porta **9987 (TCP e UDP)** por padrão. Nos clientes,
conecte com `ip-do-servidor:9987`.

## Configuração (`halla-server.ini`)

```ini
[server]
name = Servidor Halla
motd = Bem-vindo ao servidor Halla!
port = 9987
maxClients = 32
password =                 ; vazio = público
adminPassword = senha123   ; conectar com esta senha entra como admin
privilegeKeys = HL3-AAAA-BBBB-CCCC, HL3-DDDD-EEEE-FFFF
```

Parâmetros de linha de comando sobrescrevem o INI:

```
halla-server --port 9990 --name "Meu clã" --max 64
```

## Firewall / NAT

Libere **9987 TCP** (controle) e **9987 UDP** (voz). O servidor aprende o
endereço UDP de cada cliente pelo primeiro pacote recebido, então clientes
atrás de NAT funcionam sem configuração extra.

## Rodando como serviço (Linux/systemd)

```bash
sudo cp systemd/halla-server.service /etc/systemd/system/
sudo mkdir -p /opt/halla && sudo cp halla-server halla-server.ini /opt/halla/
sudo systemctl enable --now halla-server
```

## Docker

```bash
docker build -t halla-server -f docker/Dockerfile .
docker run -d -p 9987:9987/tcp -p 9987:9987/udp -v halla-data:/data halla-server
```

## Compilação

```bash
# Linux: Qt 6 (Core + Network) e CMake
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build

# Windows (compilação cruzada a partir do Linux) — ver packaging/README
cmake -S . -B build-win -G Ninja -DCMAKE_TOOLCHAIN_FILE=cmake/win64-mingw.cmake \
  -DCMAKE_PREFIX_PATH=~/qt-win/6.8.2/mingw_64 -DCMAKE_BUILD_TYPE=Release
cmake --build build-win
```

## Testes

O repositório inclui o `halla-nettest`, que sobe vários clientes simulados e
valida **71 cenários** do protocolo (login, chat, canais, poke, permissões,
relay de voz, ban/listas, grupos, operadores de canal, avatares, mensagens
offline, reclamações, sussurro e transferência de arquivos…):

```bash
./build/halla-server --port 9987 &
./build/halla-nettest
```
