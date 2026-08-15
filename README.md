# Halla Server 1.1.41

Servidor Qt para Halla Desktop 1.0.50+ e Halla Mobile 1.0.41+.

## Transportes

- Controle JSON: TCP/TLS 9987
- Voz Opus AEAD: UDP 9987
- Signaling WebRTC: pelo controle TLS
- ServerQuery: TLS, desligado por padrão

## Execução

```bash
./halla-server --config halla-server.ini
```

Na primeira execução, se `certFile`/`keyFile` não forem configurados, o
servidor gera certificado autoassinado. Clientes usam pinagem TOFU.

Leia [`SECURITY.md`](SECURITY.md) antes de expor o servidor à internet e
[`PROTOCOL.md`](PROTOCOL.md) para a especificação v4. Nunca configure
`adminPassword=troque-esta-senha`; esse placeholder faz o startup abortar.

## Pterodactyl

Importe [`pterodactyl/egg-halla-server.json`](pterodactyl/egg-halla-server.json).
Se o comando de startup antigo ainda contiver `xargs curl`, reimporte o egg ou
substitua o comando pelo campo `startup` do JSON atual. A versão antiga também
capturava o URL do arquivo `.sha256` e podia enviar conteúdo binário ao console.

## TURN

Configure `[webrtc]` no INI ou as variáveis `HALLA_TURN_URL`,
`HALLA_TURN_USERNAME` e `HALLA_TURN_PASSWORD`. A lista ICE é entregue somente
a clientes autenticados e anexada às mensagens de signaling.
