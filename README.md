# Halla Server 1.1.49

Servidor Qt para Halla Desktop 1.0.50+ e Halla Mobile 1.0.41+. O Desktop
1.0.64 adiciona o transporte de complementos v5; clientes anteriores continuam
compatíveis dentro do intervalo v1–v5.

## Transportes

- Controle JSON: TCP/TLS 9987
- Voz Opus AEAD: UDP 9987
- Signaling WebRTC: pelo controle TLS; vídeo e áudio da tela trafegam via WebRTC
- Dados de complementos v5: TLS, isolamento por canal e permissões `pluginData`/`pluginDataGlobal`
- Reordenação de canais sincronizada uma única vez por operação, sem amplificação N×C
- ServerQuery: TLS, desligado por padrão

## Execução

```bash
./halla-server --config halla-server.ini
```

Na primeira execução, se `certFile`/`keyFile` não forem configurados, o
servidor gera certificado autoassinado. Clientes usam pinagem TOFU.

`[server].name` aceita até 80 caracteres. Uma alteração manual no INI é
detectada por snapshot e tem prioridade sobre o nome antigo persistido no
SQLite/MySQL. Alterações feitas pela administração dentro do Halla continuam
persistindo enquanto o valor do INI não for modificado novamente.

Leia [`SECURITY.md`](SECURITY.md) antes de expor o servidor à internet e
[`PROTOCOL.md`](PROTOCOL.md) para a especificação v5. Nunca configure
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
