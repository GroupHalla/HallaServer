# Halla Protocol v1 + v2

Protocolo aberto do Halla (cliente ↔ servidor). Documentado para que qualquer
pessoa possa implementar clientes/bots compatíveis.

## Visão geral

| Canal | Transporte | Porta padrão | Uso |
|---|---|---|---|
| Controle | TCP | 9987 | Autenticação, canais, chat, estados, moderação |
| Voz | UDP | 9987 | Pacotes Opus de 20 ms retransmitidos por canal |

## Controle (TCP)

Mensagens são **objetos JSON compactados, um por linha** (`\n` como delimitador),
codificados em UTF-8.

### Cliente → Servidor

| Mensagem | Campos | Descrição |
|---|---|---|
| `hello` | `proto`, `uid`, `nick`, `pass?`, `adminPass?`, `ver`, `platform` | Login. `proto` = 1 ou 2 |
| `ping` | `ts` | Medição de latência (resposta `pong` com mesmo `ts`) |
| `chat` | `scope` (`server`/`channel`/`private`), `to?`, `text` | Envia mensagem de chat |
| `move` | `channel`, `pass?` | Trocar de canal |
| `voice_hello` | — | Solicita token de voz/UDP |
| `talking` | `on` (bool) | Indicador "está falando" |
| `status` | `mic?` `spk?` `away?` `rec?` `cc?` (bool) | Atualiza estados do próprio usuário |
| `nick` | `name` | Alterar apelido |
| `desc` | `text` | Alterar descrição |
| `poke` | `to`, `msg` | Cutucar cliente |
| `volume` | `to`, `db` (−40..12) | Volume local de outro cliente (não é retransmitido pela voz; cada cliente aplica localmente ao decodificar) — informativo ao servidor |
| `chan_create` | `name`, `parent`, `topic?`, `desc?`, `pass?`, `type` (0 temporário/1 semi/2 permanente), `codec`, `quality`, `max`, `moderated?` | Criar canal |
| `chan_edit` | `id`, +campos de `chan_create` | Editar canal |
| `chan_delete` | `id` | Excluir canal |
| `kick` | `id`, `reason?`, `from` (`channel`/`server`) | Expulsar (requer permissão) |
| `ban` | `id`, `reason?`, `minutes` (0 = permanente) | Banir (requer admin) |
| `privkey` | `key` | Usar chave de privilégio (concede grupo) |
| `quit` | — | Desconexão educada |

### Servidor → Cliente

| Mensagem | Campos | Descrição |
|---|---|---|
| `welcome` | `selfId`, `server:{name,motd,ver,platform,maxClients}`, `channels:[…]`, `users:[…]`, `voice:{udp,token}` | Estado completo após login |
| `pong` | `ts` | Resposta ao ping |
| `error` | `code`, `msg` | Erros (`bad_password`, `server_full`, `banned`, `name_in_use`, `no_permission`, `bad_channel_pass`…) e depois a conexão é encerrada quando fatal |
| `chat` | `scope`, `from`, `text` | Chat retransmitido |
| `user_joined` | `user:{…}` | Novo cliente entrou |
| `user_left` | `id`, `reason` (`quit`/`kicked`/`banned`/`dropped`) | Cliente saiu |
| `user_moved` | `id`, `channel`, `by?` | Cliente trocou de canal |
| `user_state` | `id` + campos de `status`/`talking` | Estado mudou |
| `user_nick` | `id`, `name` | Apelido mudou |
| `user_desc` | `id`, `text` | Descrição mudou |
| `user_group` | `id`, `group` | Grupo mudou (ex.: chave de privilégio) |
| `chan_update` | `chan:{…}` | Canal criado ou editado |
| `chan_removed` | `id` | Canal removido |
| `poke` | `from`, `msg` | Você foi cutucado |
| `kicked` | `reason`, `ban` (bool), `minutes?` | Você foi expulso/banido (conexão encerrada a seguir) |

### Objeto `user`

```json
{"id":5,"name":"Ana","uid":"base64…","ver":"3.6.2","platform":"Windows",
 "desc":"","group":"normal","mic":false,"spk":false,"away":false,
 "rec":false,"cc":false,"talking":false}
```

### Objeto `chan`

```json
{"id":1,"parent":0,"name":"Canal padrão","topic":"","desc":"","pw":false,
 "def":true,"type":2,"moderated":false,"codec":4,"quality":6,"max":-1,
 "users":[5,7]}
```

## Voz (UDP)

### Pacote cliente → servidor

| Bytes | Campo |
|---|---|
| 4 | magic `"HALL"` |
| 4 | token (little-endian, recebido no `welcome`) |
| 2 | sequência u16 |
| N | frame Opus (20 ms, 48 kHz, mono) |

O servidor aprende o endereço UDP do cliente pelo primeiro pacote recebido
(amigável a NAT) e retransmite os frames para os membros do mesmo canal.

### Pacote servidor → cliente

| Bytes | Campo |
|---|---|
| 4 | magic `"HALL"` |
| 4 | id do falante |
| 2 | sequência u16 |
| N | frame Opus |

O servidor nunca decodifica Opus — é um relay puro (baixíssima latência e CPU).

## Permissões (grupos)

| Grupo | Cria canal permanente/semi | Temporário | Poke | Kick canal | Kick servidor | Ban |
|---|---|---|---|---|---|---|
| `guest` | – | – | ✔ | – | – | – |
| `normal` | – | ✔ | ✔ | – | – | – |
| `admin` | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |

Grupos são atribuídos via `adminPass` no `hello` ou mensagem `privkey` válida
(chaves configuradas no `halla-server.ini`).

---

# Halla Protocol v2 (Cenário 3)

A versão 2 adiciona **permissões granulares por grupo**, **grupos atribuídos por
identidade (UID)**, **lista de banimentos**, **chaves de privilégio com grupo
alvo e uso único** e **poder de fala (talk power)**.

O servidor aceita clientes v1 e v2 (`kProtoMin = 1`, `kProtoVersion = 2`).
Recursos novos só existem para quem fala v2.

## Grupos e permissões

Cada cliente pertence a **um grupo de servidor**. Grupos embutidos:

| id | nome | permissões padrão |
|---|---|---|
| 1 | `guest` | `poke`, `privmsg`, talkPower 10 |
| 2 | `normal` | guest + `chanCreateTemp`, talkPower 25 |
| 3 | `admin` | `*` (tudo), talkPower 75 |

Grupos customizados têm id >= 100 e são persistidos no `halla-data.json`.

### Chaves de permissão

| Chave | Efeito |
|---|---|
| `*` | Todas as permissões (super-admin) |
| `kick` | Expulsar clientes do canal/servidor |
| `ban` | Banir e desbanir |
| `banList` | Ver a lista de banimentos |
| `move` | Mover outros clientes de canal (`move_other`) |
| `chanCreateTemp` / `chanCreateSemi` / `chanCreatePerm` | Criar canais por tipo |
| `chanEdit` / `chanDelete` | Editar/excluir canais |
| `serverEdit` | Editar nome/MOTD do servidor |
| `groupEdit` | Criar/editar/excluir grupos e atribuir grupos a clientes |
| `poke` | Cutucar |
| `privmsg` | Mensagem privada |
| `ignoreChanPass` | Entrar em canais com senha sem digitá-la |
| `ignoreTalkPower` | Falar em canais moderados sem talk power |
| `talkPower` | (número) poder de fala do grupo |

Regras especiais do servidor:
- Não-administrador (`*`) **não** pode expulsar/banir um administrador (`*`).
- Não é possível remover `*` de um grupo que o possui (anti-lockout).
- Só quem tem `*` cria/atribui grupos com `*`.
- Grupos embutidos (1–3) não podem ser excluídos.

## Mensagens novas (v2)

### Cliente → Servidor

| Mensagem | Campos | Permissão | Descrição |
|---|---|---|---|
| `banlist` | — | `banList` | Pede a lista de banimentos |
| `unban` | `uid` | `ban` | Remove banimento por UID |
| `move_other` | `id`, `channel` | `move` | Move outro cliente de canal |
| `group_list` | — | nenhuma | Lista grupos e permissões |
| `group_set` | `id?`, `name?`, `perms?` | `groupEdit` | Cria (sem `id`) ou edita grupo |
| `group_delete` | `id` | `groupEdit` | Exclui grupo custom (id>=100) |
| `client_set_group` | `id?` ou `uid?`, `gid` | `groupEdit` | Atribui grupo (persistente por UID) |
| `server_edit` | `name?`, `motd?` | `serverEdit` | Renomeia servidor / muda MOTD |

`privkey` agora aceita chaves com grupo alvo (no INI: `CHAVE@grupo`) e, por
padrão, **cada chave só pode ser usada uma vez** (`privilegeKeyReuse = false`
no INI desativa). A chave registrada fica associada ao UID para sempre.

### Servidor → Cliente

| Mensagem | Campos | Descrição |
|---|---|---|
| `welcome` | + `groups:[{id,name,perms}]`, `myPerms:{…}`, `proto` | v2 inclui grupos e suas permissões |
| `banlist` | `bans:[{uid,ip,name,reason,expires?}]` | Resposta ao pedido |
| `ban_removed` | `uid` | Banimento removido |
| `user_group` | `id`, `group`, `gid` | Agora inclui o id numérico do grupo |
| `group_list` | `groups:[…]` | Broadcast quando grupos mudam |
| `server_edit` | `name`, `motd` | Nome/MOTD mudaram em tempo real |
| `error` | `code` = `privkey_used`, `locked`, `no_talk_power`, `not_found`, `bad_uid` | Novos códigos |

## Poder de fala (talk power)

Canais têm o campo `ntalk` (0..100). Regra do servidor:

```
need = ntalk > 0 ? ntalk : (moderated ? 25 : 0)
pode falar = need == 0  ou  talkPower(cliente) >= need  ou  ignoreTalkPower
```

Se o cliente não pode falar, o servidor **responde `no_talk_power`** ao
`talking=on` e **descarta seus pacotes de voz** (ninguém mais ouve).

## Identidade (UID)

O `uid` do `hello` é **obrigatório** (erro `bad_uid`). O servidor mantém um
registro persistente (`halla-data.json` → `clients`) com nome, primeira e
última conexão, usado para:
- Bans por UID (e por IP, adicionado na v2);
- Atribuições de grupo (`assignments`: uid → gid), aplicadas a cada login;
- Chaves de privilégio conferem grupo permanentemente ao UID.
