
# Halla Protocol — Especificação (v1 → v5 + Camada de Segurança + WebRTC)

Protocolo aberto do Halla (cliente ↔ servidor). Documentado para que qualquer
pessoa possa implementar clientes, bots e ferramentas compatíveis.

> **Estado atual:** servidor Halla ≥ 1.1.45 e cliente desktop ≥ 1.0.64
> implementam o protocolo v5; clientes anteriores continuam aceitos dentro do
> intervalo anunciado pelo servidor. Mobile permanece no protocolo v4. A
> camada de segurança (TLS, identidade Ed25519, voz AEAD) é **obrigatória** para todas as conexões — não é negociável por versão.

## Visão geral

| Canal | Transporte | Porta padrão | Uso |
|---|---|---|---|
| Controle | **TCP + TLS 1.2+** | 9987 | Autenticação, canais, chat, estados, moderação, sinalização WebRTC |
| Voz | UDP | 9987 | Pacotes Opus de 20 ms cifrados (ChaCha20-Poly1305), relay por canal |
| Screen share (legado) | UDP | 9987 | Frames JPEG fatiados e cifrados (pacotes `HALF`) |
| Mídia WebRTC | P2P (DTLS-SRTP) | dinâmica | Vídeo da transmissão de tela moderna |
| Áudio da tela Mobile | UDP | 9987 | Opus cifrado, entregue somente a espectadores explícitos (`HAG4`/`HAGA`) |
| ServerQuery | **TCP + TLS** (desligado por padrão) | configurável | Administração remota |

## Camada de segurança

### TLS no canal de controle

- O servidor escuta apenas TLS (`QSslServer`). Na primeira execução sem
  certificado configurado, gera `cert.pem`/`key.pem` **autoassinados**
  diretamente com a `libcrypto` carregada, sem executar o comando externo
  `/usr/bin/openssl`. Certificado próprio (ex.: Let's Encrypt) via
  `certFile`/`keyFile` no INI.
- Clientes usam **TOFU (trust on first use)**: salvam o fingerprint
  SHA-256 do certificado na primeira conexão; se o fingerprint mudar,
  a conexão é recusada com alerta de possível MITM.
- Toda mensagem de controle (incluindo `server_probe`) trafega dentro do TLS.

### Identidade Ed25519

Cada cliente possui um par de chaves **Ed25519** gerado na primeira execução
(desktop: armazenamento local; mobile: Keystore do Android quando disponível,
com fallback EdDSA). O **UID é derivado da chave pública**:

```
UID = base64( SHA-256( chave pública em DER/SubjectPublicKeyInfo ) )
```

Fluxo de login com prova de posse:

```
cliente → servidor : hello { proto, uid, nick, idPub, pass?, adminPass?, ver, platform }
servidor → cliente : identity_challenge { nonce }          (32 bytes aleatórios, base64)
cliente → servidor : identity_proof { sig }                (assinatura Ed25519 do nonce)
servidor           : valida a assinatura com idPub;
                     UID := hash(idPub)  (o uid enviado pelo cliente é ignorado)
servidor → cliente : welcome { … }                         (login concluído)
```

Regras:
- `hello` sem `idPub` (e sessão ainda não verificada) → erro `bad_identity`,
  conexão encerrada.
- Assinatura inválida → erro `bad_identity`, conexão encerrada.
- O estado "identidade verificada" vive **apenas na sessão do servidor**;
  nenhum campo enviado pelo cliente pode dispensar o desafio.
- Bans, grupos e chaves de privilégio são vinculados ao UID derivado,
  tornando spoofing de identidade impraticável.

### Chaves de voz por canal

- Cada canal possui uma chave simétrica de **32 bytes**
  (`QRandomGenerator::system()` no servidor).
- **Canais vinculados (link) compartilham a mesma chave** por componente
  conexo — quem ouve através de link precisa decifrar frames vindos de
  qualquer canal do componente, e o servidor continua sendo relay puro.
- Distribuição ao cliente:
  - `welcome.channelKeys` — mapa `{ "idCanal": base64(chave) }` para o canal
    atual do cliente e seu componente de vínculo (evita corrida com `m_ready`);
  - mensagem `channel_key { channel, key }` a qualquer momento.
- **Rotação:** a chave do componente é rotacionada quando vínculos mudam
  (`chan_link`) e quando a composição do canal muda (entrada/saída de
  usuários), provendo forward secrecy básica. Todos os membros do componente
  recebem todas as chaves do componente.

### Voz e screen share: ChaCha20-Poly1305 (AEAD)

- Algoritmo: **ChaCha20-Poly1305 (IETF)** — nonce de 12 bytes, tag de 16 bytes.
  Implementações de referência: OpenSSL (`EVP_chacha20_poly1305`) no desktop,
  mbedTLS (`mbedtls_chachapoly`) no mobile.
- Chave: chave de 32 bytes do canal do **remetente**.
- **Nonce (12 bytes, little-endian):**

```
bytes 0..3  : senderId  (id numérico de sessão do remetente)
bytes 4..7  : counter   (contador 32 bits, monotônico por remetente)
bytes 8..9  : seq       (mesmo seq u16 do cabeçalho do pacote)
bytes 10..11: 0x00 0x00
```

- **Payload cifrado** (vale para voz e para cada chunk de screen share):

```
counter (4 B, LE) | ciphertext (N B) | tag (16 B)
```

- Regras:
  - O remetente incrementa `counter` a cada pacote. Com 32 bits, o wrap
    só ocorre após ~4,3 bilhões de pacotes (~2,6 anos a 50 p/s) — na prática,
    a rotação de chave por entrada/saída acontece muito antes.
  - O destinatário reconstrói o nonce com `fromId` (cabeçalho) + `counter`
    + `seq` e **descarta o pacote se a tag não validar**.
  - Se o destinatário ainda não tem a chave do canal do remetente, o pacote
    é descartado (não há fallback de decodificação em texto puro quando
    chaves estão em uso).
  - O cabeçalho UDP (magic/id/seq) não é autenticado pelo AEAD; adulterá-lo
    causa falha de decifragem (negação de serviço pontual), nunca forja áudio.

## Controle (TCP/TLS)

Mensagens são **objetos JSON compactados, um por linha** (`\n` como
delimitador), codificados em UTF-8. Limite de **2 MiB por mensagem**.

### Handshake

| Mensagem | Direção | Campos | Descrição |
|---|---|---|---|
| `server_probe` | C→S | — | Consulta pública (via TLS); não cria sessão |
| `server_probe` | S→C | `server:{name,motd,ver,maxClients}`, `clients`, `maxClients` | Resposta |
| `hello` | C→S | `proto` (1..5), `uid`, `nick`, `idPub` (base64 DER), `pass?`, `adminPass?`, `ver`, `platform` | Login |
| `identity_challenge` | S→C | `nonce` (base64, 32 B) | Desafio Ed25519 |
| `identity_proof` | C→S | `sig` (base64) | Assinatura do nonce |
| `welcome` | S→C | ver abaixo | Estado completo após login |
| `error` | S→C | `code`, `msg` | Erro; quando fatal, a conexão é encerrada em seguida |

`welcome`:

```json
{
  "t": "welcome",
  "selfId": 5,
  "proto": 5,
  "server": {
    "name": "Servidor Halla", "motd": "…", "ver": "1.1.34",
    "platform": "Linux", "maxClients": 32, "banner": "base64…",
    "screenshare": true, "screenshare_w": 800,
    "screenshare_h": 450, "screenshare_fps": 20
  },
  "users":    [ /* objetos user, incluindo "screensharing" */ ],
  "channels": [ /* objetos chan */ ],
  "groups":   [ { "id":1, "name":"guest", "perms":{…} } ],
  "myPerms":  { "…": true },
  "voice":    { "udp": 9987, "token": "001122…eeff", "format": "hex128" },
  "iceServers": [{ "urls": "stun:…" }, { "urls": "turn:…", "username": "…", "credential": "…" }],
  "channelKeys": { "1": "base64(32 bytes)…" }
}
```

`myPerms` reúne as permissões efetivas de todos os cargos do UID. Para uma
identidade com privilégio individual total, inclui `"*": true`.

### Objeto `user`

```json
{"id":5,"name":"Ana","uid":"base64…","ver":"3.6.2","platform":"Windows",
 "desc":"","group":"normal","sigla":"[ADM]","siglaSuffix":"[Fundador]",
 "icon":"base64…","order":1,"orderEnabled":true,
 "gid":3,"position":10,"groupPosition":10,
 "mic":false,"spk":false,"away":false,"rec":false,"cc":false,
 "talking":false,"whispering":false,"screensharing":false,"av":"sha1…"}
```

`sigla` contém as siglas efetivas que aparecem antes do nome e
`siglaSuffix`, as que aparecem depois. `order` é a menor ordem entre os cargos
atribuídos cuja `orderEnabled` esteja ativa; se nenhum cargo participar,
`orderEnabled` é `false`.

### Objeto `group`

```json
{"id":100,"name":"Moderador","perms":{"kick":true},"sigla":"[Mod]",
 "siglaAfter":false,"order":20,"orderEnabled":true,"icon":"🛡️","position":50}
```

`siglaAfter=true` coloca a sigla desse cargo depois do nome. `orderEnabled=false`
mantém o número salvo, mas exclui o cargo do cálculo da ordem efetiva do usuário.
A `position` hierárquica continua independente e não é desativada por essa opção.

### Objeto `chan`

```json
{"id":1,"parent":0,"order":0,"name":"Canal padrão","topic":"","desc":"",
 "pw":false,"def":true,"noSymbol":false,"tempParent":false,"type":2,"moderated":false,
 "codec":4,"quality":6,"bitrate":96,"max":-1,
 "linked":[2],"users":[5,7],"ops":["uid…"],
 "groupPerms":{ }, "groupPositionReqs":{ }}
```

`type`: 0 temporário, 1 semi-permanente, 2 permanente.
`tempParent=true` designa este canal não temporário como o único destino global:
novos canais temporários passam a ser criados automaticamente como seus subcanais.
Alterar essa propriedade exige `chanEdit`. Na criação de um canal `type=0`, o
servidor substitui o `parent` enviado pelo cliente e valida as permissões no
destino configurado.
`codec`: 4 = Opus Voice, 5 = Opus Music (+ legados Speex/CELT por compatibilidade).

### Cliente → Servidor

| Mensagem | Campos | Descrição |
|---|---|---|
| `ping` | `ts` | Latência (resposta `pong` com mesmo `ts`) |
| `chat` | `scope` (`server`/`channel`/`private`), `to?`, `text` | Mensagem de chat |
| `move` | `channel`, `pass?` | Trocar de canal |
| `move_other` | `id`, `channel` | Mover outro cliente (perm `move`) |
| `voice_hello` | — | Solicita token/UDP (`voice_token`) |
| `talking` | `on` | Indicador "está falando" (isento de rate limit) |
| `status` | `mic?`,`spk?`,`away?`,`rec?`,`cc?` | Estados do próprio usuário |
| `nick` | `name` | Alterar apelido (máx. 30) |
| `desc` | `text` | Alterar descrição |
| `poke` | `to`, `msg` | Cutucar cliente |
| `volume` | `to`, `db` (−40..12) | Informativo (volume é aplicado localmente) |
| `chan_create` | `name`,`parent`,`topic?`,`desc?`,`pass?`,`type`,`codec`,`quality`,`max`,`moderated?`,`tempParent?` | Criar canal |
| `chan_edit` | `id` + campos de `chan_create`, `op_add?`,`op_del?` | Editar canal / operadores |
| `chan_move` | `id`,`parent`,`order` | Reordenar/mover canal |
| `chan_link` | `ids` (2+), `link` | Vincular/desvincular áudio (rotaciona chaves) |
| `chan_delete` | `id` | Excluir canal |
| `kick` | `id`, `reason?`, `from` (`channel`/`server`) | Expulsar |
| `ban` | `id`, `reason?`, `minutes` (0 = permanente) | Banir por UID e IP |
| `privkey` | `key` | Usar chave de privilégio (`CHAVE@grupo`) |
| `banlist` | — | Lista de banimentos (perm `banList`) |
| `unban` | `uid` | Remover banimento (perm `ban`) |
| `group_list` | — | Lista grupos e permissões |
| `group_set` | `id?`,`name?`,`perms?`,`sigla?`,`siglaAfter?`,`order?`,`orderEnabled?`,`icon?`,`position?` | Criar/editar grupo (perm `groupEdit`) |
| `group_delete` | `id` | Excluir grupo custom (id ≥ 100) |
| `client_set_group` | `id?` ou `uid?`, `gid`, `op?` (`add`/`remove`; ausente = toggle legado) | Adicionar ou remover cargo persistente por UID |
| `server_edit` | `name?`,`motd?`,`banner?` (base64; vazio remove) | Editar servidor (perm `serverEdit`) |
| `avatar_set` | `data` (base64 ≤ 128 KiB; vazio remove) | Definir avatar |
| `avatar_get` | `uid` | Pedir avatar de um cliente |
| `icon_set` | `name`, `data` | Definir ícone de grupo |
| `icon_get` | `name` | Pedir ícone |
| `offline_send` | `uid`, `text` (≤ 500) | Mensagem offline |
| `complaint_add` | `id`, `text` | Registrar reclamação |
| `complaint_list` | — | Listar reclamações (perm `banList`) |
| `complaint_clear` | `uid?` | Limpar reclamações |
| `whisper` | `ids` (array; vazio desativa) | Direcionar voz a usuários específicos |
| `plugin_data` (v5) | `plugin`, `target` (0 canal/1 usuários/2 servidor), `ids?`, `topic`, `data` (base64) | Encaminhar até 8 KiB entre instâncias do mesmo complemento |
| `ft_upload` | `channel`,`name`,`data` (base64 ≤ 1 MiB) | Enviar arquivo (máx. 50/canal, 10 MiB total) |
| `ft_list` | `channel` | Listar arquivos do canal |
| `ft_download` | `channel`,`name` | Baixar arquivo |
| `ft_delete` | `channel`,`name` | Excluir arquivo (dono/op/`chanEdit`) |
| `commander` | `id`, `on` | Conceder/retirar comandante |
| `screenshare_start` / `screenshare_stop` | — | Screen share legado (JPEG/UDP) |
| `webrtc_stream_start` / `webrtc_stream_stop` | — | Iniciar/parar transmissão WebRTC |
| `webrtc_watch_request` | `to` | Pedir para assistir (alvo deve estar transmitindo) |
| `webrtc_watch_stop` | `to` | Parar de assistir |
| `webrtc_offer` / `webrtc_answer` | `to`, `sdp` | SDP roteado pelo servidor |
| `webrtc_ice` | `to`, `candidate`… | Candidato ICE roteado |
| `quit` | — | Desconexão educada |

### Servidor → Cliente

| Mensagem | Campos | Descrição |
|---|---|---|
| `pong` | `ts` | Resposta de latência |
| `voice_token` | `udp`, `token` | Token/porta para voz |
| `channel_key` | `channel`, `key` (base64, 32 B) | Chave de voz do canal |
| `chat` | `scope`, `from`, `fromName?`, `text` | Chat retransmitido |
| `user_joined` | `user:{…}` | Cliente entrou |
| `user_left` | `id`, `reason` (`quit`/`kicked`/`banned`/`dropped`) | Cliente saiu |
| `user_moved` | `id`, `channel`, `by?` | Trocou de canal |
| `user_state` / `user_nick` / `user_desc` / `user_group` | `id` + campos | Mudanças de estado/apelido/descrição/grupo (`user_group` inclui `gid`, `sigla`, `siglaSuffix`, `order` e `orderEnabled`) |
| `user_avatar` | `id`, `av` (sha-1) | Avatar mudou |
| `avatar_data` | `uid`, `data` | Resposta a `avatar_get` |
| `icon_data` | `name`, `data` | Resposta a `icon_get` |
| `offline_msg` | `fromUid`,`fromName`,`text`,`ts` | Entregues no login (máx. 20/caixa) |
| `offline_sent` | `uid` | Mensagem offline aceita |
| `complaint_added` / `complaint_list` / `complaint_cleared` | — | Reclamações |
| `chan_update` | `chan:{…}` | Canal criado/editado |
| `chan_removed` | `id` | Canal removido |
| `poke` | `from`, `fromName`, `msg` | Você foi cutucado |
| `kicked` | `reason`, `ban`, `minutes?` | Expulso/banido (conexão encerra em seguida) |
| `banlist` | `bans:[{uid,ip,name,reason,expires?}]` | Lista de banimentos |
| `ban_removed` | `uid` | Banimento removido |
| `group_list` | `groups:[…]` | Broadcast quando grupos mudam |
| `group_set_ok` | `group:{…}` | Confirma ao editor os valores efetivamente aplicados ao cargo |
| `privilege_granted` | `individual`, `myPerms` | Confirma a chave e atualiza imediatamente as permissões efetivas |
| `server_edit` | `name`,`motd`,`banner?` | Servidor renomeado/MOTD/banner mudou |
| `whisper_ok` | `count` | Sussurro ativado para N usuários |
| `plugin_data` (v5) | `from`, `plugin`, `topic`, `data` (base64) | Payload confiável encaminhado pelo servidor |
| `ft_uploaded` / `ft_list` / `ft_data` / `ft_deleted` | — | Transferência de arquivos |
| `user_screenshare_state` | `id`, `on`, `mode?` (`"webrtc"` no modo novo) | Transmissão de tela ativa/inativa |

### Dados de complementos (v5)

`plugin_data` usa o canal TCP/TLS e não é persistido nem interpretado pelo
servidor. O ID do complemento aceita 3–64 caracteres ASCII minúsculos, números,
ponto, hífen e sublinhado; `topic` aceita até 64 bytes UTF-8 e `data`, depois da
decodificação base64, até 8 KiB.

Destinos:

- `target=0`: todos os demais usuários do canal atual;
- `target=1`: `ids` com 1–64 usuários conectados;
- `target=2`: todos os demais clientes v5 do servidor.

O servidor acrescenta `from`, não ecoa ao remetente e só entrega a sessões que
negociaram protocolo v5. O limite é de 200 mensagens por 10 segundos por
cliente, suficiente para telemetria posicional de até 20 Hz. Complementos devem
usar tópicos/estruturas versionados e manter os payloads pequenos.

### Códigos de erro

`bad_password`, `server_full`, `banned`, `name_in_use`, `no_permission`,
`bad_channel_pass`, `bad_uid`, `bad_identity`, `privkey_used`, `locked`,
`no_talk_power`, `not_found`, `inbox_full`, `screenshare_disabled`,
`webrtc_target`, `webrtc_channel`, `webrtc_not_streaming`,
`plugin_data_unsupported`, `bad_plugin_data`, `plugin_data_too_big`.

## Voz (UDP)

### Pacote cliente → servidor

| Bytes | Campo |
|---|---|
| 4 | magic `"HAL4"` |
| 16 | token CSPRNG de 128 bits (bytes do hex recebido via TLS) |
| 2 | `seq` u16 (LE) |
| 4 | `counter` u32 (LE) — parte do payload AEAD |
| N | ciphertext Opus |
| 16 | tag Poly1305 |

O servidor aprende o endpoint UDP somente depois de validar a credencial aleatória
de 128 bits recebida pelo cliente via TLS e retransmite aos membros do canal (+ canais vinculados).
Sem token válido, o pacote é descartado. Frames de 20 ms, 48 kHz mono,
Opus com bitrate configurável por canal (16–384 kbps).

### Pacote servidor → cliente

| Bytes | Campo |
|---|---|
| 4 | magic `"HALL"` |
| 4 | `fromId` u32 (LE) — usado no nonce de decifragem |
| 2 | `seq` u16 (LE) |
| 4+ N + 16 | payload AEAD (`counter` | ciphertext | tag) |

O servidor **nunca decodifica nem decifra áudio** — relay puro.

## Screen share legado (UDP, pacotes `HALF`)

Usado pela transmissão JPEG do desktop. Cada frame JPEG é fatiado em chunks
de até 1200 bytes; cada chunk é cifrado individualmente com o AEAD do canal.

| Bytes | Campo |
|---|---|
| 4 | magic `"HAF4"` no sentido C→S (`"HALF"` permanece S→C) |
| 16 | token CSPRNG de 128 bits no sentido C→S |
| 2 | `seq` u16 (LE) — identifica o frame |
| 1 | `chunkIdx` |
| 1 | `chunkCount` (máx. 255) |
| … | payload AEAD do chunk |

O destinatário remonta o frame quando reúne `chunkCount` chunks para o mesmo
`(fromId, seq)`, descartando sequências antigas. Parâmetros negociados no
`welcome` (`screenshare`, `screenshare_w`, `screenshare_h`, `screenshare_fps`).
Recomenda-se usar o modo WebRTC em clientes novos.

### Áudio de reprodução da tela Mobile

O Android transmite o vídeo por WebRTC e envia o áudio interno capturável como
Opus em um fluxo paralelo autenticado:

- cliente → servidor: `"HAG4" | token(16) | seq(u16) | AEAD Opus`;
- servidor → espectadores: `"HAGA" | senderId(u32) | seq(u16) | AEAD Opus`.

O servidor só retransmite esse áudio para clientes Desktop do mesmo canal que
enviaram `webrtc_watch_request`; viewers Android recebem a track de áudio do
próprio WebRTC, evitando reprodução duplicada. `webrtc_watch_stop`, desconexão
ou fim da live remove a assinatura. O cliente Android exclui o próprio UID da
captura, evitando que as vozes reproduzidas pelo Halla retornem na transmissão.

## Transmissão de tela WebRTC

O servidor atua **apenas como relay de sinalização** pelo canal TLS; a mídia
flui P2P com criptografia DTLS-SRTP do próprio WebRTC.

Regras de roteamento (aplicadas pelo servidor):
- alvo deve existir e não ser o próprio remetente → senão `webrtc_target`;
- remetente e alvo devem estar **no mesmo canal** → senão `webrtc_channel`;
- ambos precisam da permissão de canal `listen` → senão `no_permission`;
- `webrtc_watch_request` exige que o alvo esteja transmitindo →
  senão `webrtc_not_streaming`.

Toda mensagem roteada recebe do servidor os campos `from`, `fromName` e `to`
(o destino é o id de sessão). Estado de transmissão é persistido na sessão e
exposto em `users[].screensharing` (inclusive no `welcome`, para quem entra
ver lives já abertas) e via broadcast `user_screenshare_state` com `mode:"webrtc"`.

Fluxo típico:

```
streamer  → servidor : webrtc_stream_start            (broadcast user_screenshare_state)
viewer    → servidor : webrtc_watch_request {to}
viewer    → servidor : webrtc_offer {to, sdp}         (roteado ao streamer)
streamer  → servidor : webrtc_answer {to, sdp}        (roteado ao viewer)
ambos     → servidor : webrtc_ice {to, candidate…}    (roteado nos dois sentidos)
… mídia P2P via DTLS-SRTP …
streamer  → servidor : webrtc_stream_stop
```

## Permissões (v2 + hierarquia)

Grupos embutidos:

| id | nome | permissões padrão |
|---|---|---|
| 1 | `guest` | `poke`, `privmsg`, talkPower 10 |
| 2 | `normal` | guest + `chanCreateTemp`, talkPower 25 |
| 3 | `admin` | `*`, talkPower 75 |

Grupos customizados têm `id ≥ 100` e persistem em `halla-data.json`.

Chaves de permissão: `*`, `kick`, `ban`, `banList`, `move`,
`chanCreateTemp`/`chanCreateSemi`/`chanCreatePerm`, `chanEdit`, `chanDelete`,
`serverEdit`, `groupEdit`, `poke`, `privmsg`, `ignoreChanPass`,
`ignoreTalkPower`, `talkPower` (número) e `listen` (necessária para
receber voz/sinalização WebRTC no canal; concedida por padrão).

Regras especiais:
- Não-administrador (`*`) não expulsa/bane administrador (`*`).
- Não se remove `*` de um grupo que o possui (anti-lockout).
- Só administrador total cria, edita ou atribui grupos com `*`.
- `groupEdit` só gerencia cargos e clientes estritamente abaixo da maior
  `position` do executor. O próprio cargo, posições iguais e cargos acima são
  bloqueados na edição, exclusão e atribuição.
- Um não-administrador não pode criar ou reposicionar cargo na própria altura
  ou acima dela.
- O nome `admin` é reservado ao grupo interno 3; nomes de cargo ou apelidos
  nunca concedem permissões administrativas.
- Grupos embutidos (1–3) não podem ser excluídos.
- Extensões: `position` (posição hierárquica), `groupPerms` e
  `groupPositionReqs` por canal (allow/deny/inherit) e overrides de
  permissão por canal.

### Visibilidade de canais

A permissão de canal `view` corresponde a **Ver canal**. Sem regra explícita,
o canal permanece visível para manter compatibilidade. Um `Deny` oculta o canal
e todos os seus subcanais; o servidor não inclui esses objetos no `welcome` nem
em atualizações destinadas ao cliente. Se qualquer outro cargo do mesmo usuário
tiver `Allow`, o canal volta a ser visível — portanto um cargo acima de Normal
pode revelar um canal negado ao cargo Normal. Administradores totais ignoram o
bloqueio. Alterações de cargos e `privilegekey` ressincronizam a árvore
imediatamente.

### Poder de fala (talk power)

```
need = ntalk > 0 ? ntalk : (moderated ? 25 : 0)
pode falar = need == 0 ou talkPower(cliente) >= need ou ignoreTalkPower
```

Sem poder de fala, o servidor responde `no_talk_power` ao `talking=on` e
**descarta os pacotes de voz** do cliente até `talking=off`.

### Operadores de canal

Quem cria um canal vira operador (`channels[].ops` = UIDs). Operadores editam
o próprio canal sem `chanEdit` e expulsam dele (exceto outros operadores).
`chan_edit` aceita `op_add`/`op_del` (perm `chanEdit`).

## Limites, rate limiting e validação

- **2 MiB** de teto por mensagem TCP (mensagens maiores derrubam a conexão).
- Rate limit **por tipo de mensagem** (`server_probe`, `chat`, `move`,
  `status`, `ping`, `plugin_data`, `ft_*`…) com janelas por cliente/IP;
  `talking` é isento.
- Limites por IP de conexões simultâneas e **timeout de ociosidade** TCP;
- endpoints UDP ociosos são limpos periodicamente.
- Validação estrita de tamanho/conteúdo para nick (≤ 30), chat, descrições,
  tópicos e campos de canal.
- Backoff/limite de tentativas de login inválido.

## ServerQuery (v3.1)

Interface TCP protegida por **TLS**, desligada por padrão (`port=0`) e ligada a
`127.0.0.1` por padrão. A porta e o bind são configuráveis em `[query]`. Há
limite de 64 KiB por conexão, linhas de 8 KiB, no máximo 32 conexões e cinco
tentativas de login por IP/minuto. Comandos `chave=valor`; toda resposta termina com
`error id=0 msg=ok` (ou o código) + `\n\r`. Escapes: espaço `\s`, pipe `\p`,
barra `\/`.

```
login client_login_name=serveradmin client_login_password=***
serverinfo | clientlist | channellist
clientkick clid=<id> reasonmsg=<texto>
banclient  clid=<id> time=<min> reasonmsg=<texto>
banadd uid=<uid> time=<min> banreason=<texto>
banlist | bandel banid=<uid>
gm msg=<texto>
servergroupsetposition… | channelgroupsetpositionreq | channelgroupsetperm | channelpermlist
help | version | logout | quit
```

Códigos: `1538` login inválido, `512` não encontrado, `256` comando
desconhecido, `2568` não autenticado. Na primeira execução sem senha, o
servidor gera uma senha aleatória de 24 caracteres, mostra uma única vez e
grava somente seu hash PBKDF2-SHA256 no banco.

## Persistência

| Arquivo | Conteúdo |
|---|---|
| `halla-data.json` | canais, grupos, atribuições UID→grupo, chaves usadas, registro de identidades, `queryPass` (hash PBKDF2) |
| `halla-bans.json` | banimentos (UID e IP) |
| `halla-data.db` | banco SQLite local (espelho/consultas) |
| `[database]` no INI | opcional: MySQL (`dbName`, `dbUser`, `dbPassword`); o servidor reconecta antes de salvar |

Canais temporários somem quando ficam vazios; avatares ficam em
`data/avatars/<uid>.avt`; arquivos em `data/files/<canal>/<nome>`.

## Compatibilidade e versionamento

- `hello.proto`: 1..5 (`kProtoVersion = 5`, `kProtoMin = 1`). O v4 trocou o
  token UDP sequencial de 32 bits por credencial CSPRNG de 128 bits e adotou
  `HAL4`/`HAF4`; o v5 acrescenta `plugin_data` confiável e limitado. O servidor
  mantém recepção de clientes anteriores dentro do intervalo anunciado.
- **TLS e identidade Ed25519 são incondicionais**: clientes antigos (sem TLS
  ou sem `idPub`) recebem erro/queda de conexão e devem atualizar.
- Voz sem chave (texto puro) só é aceita transitoriamente quando o canal
  ainda não distribuiu chaves; implementações novas devem exigir AEAD.

## Guia para implementações de terceiros

1. **TLS:** qualquer stack moderna serve; implemente TOFU guardando o
   fingerprint SHA-256 do certificado por `host:porta`.
2. **Ed25519:** libsodium, OpenSSL EVP ou mbedTLS (Ed25519/EdDSA). Assine os
   **bytes crus do nonce**; envie a chave pública em DER (SubjectPublicKeyInfo).
3. **AEAD:** ChaCha20-Poly1305 IETF. Construa o nonce exatamente como
   especificado (little-endian) e nunca reutilize `(chave, nonce)`.
4. **Replay (recomendado):** mantenha o maior `counter` visto por remetente e
   descarte pacotes com `counter` antigo (janela deslizante opcional).
5. **Rotação de chaves:** trate `channel_key` como autoridade; descarte chaves
   antigas do canal ao receber nova. Ao mover-se entre canais, aguarde a chave
   do novo canal antes de transmitir.
6. **Teste de conformidade:** o repositório inclui `halla-nettest` e os testes
   de integração. Para validar o transporte v5 após compilar:
   `python3 tests/plugin_data_integration.py --server build/halla-server`.

---

## Histórico de versões

| Versão | Mudanças |
|---|---|
| v1 | Base: login, canais, chat, voz UDP Opus, grupos simples |
| v2 | Permissões granulares, banlist UID+IP, grupos por UID, talk power, chaves de privilégio de uso único |
| v3 | Avatares, mensagens offline, reclamações, operadores de canal, sussurro, transferência de arquivos |
| v3.1 | ServerQuery na porta 10011 |
| v4 | Token UDP CSPRNG de 128 bits, `HAL4`/`HAF4`, ICE/TURN distribuído pelo servidor e ServerQuery TLS |
| v5 | Transporte TLS `plugin_data` para metadados binários entre complementos, com escopos, validação, limites e rate limit |
| Segurança (obrigatória) | TLS + TOFU, identidade Ed25519 com desafio, chaves de canal de 32 B com rotação, ChaCha20-Poly1305 na voz e no screen share legado, limites/rate limit |
| WebRTC | Sinalização de transmissão de tela via servidor, mídia P2P DTLS-SRTP |
