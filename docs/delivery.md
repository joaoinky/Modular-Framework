# Resumo da entrega

- Dois projetos: `nvg-audit` no diretorio principal e `nvg-key-material` em
  `packages/nvg-key-material`, com pyprojects independentes e dependencia local.
- Detector real do scanner extraido sem mudanca de logica; wordlist MIT,
  proveniencia e vetores publicos preservados. Orcamentos e I/O foram separados
  dos motores. O scanner nao foi migrado ou editado.
- Chassi com Protocol de modulo, descoberta deterministica, tres estados,
  isolamento por processo, timeout, JSON versionado e CLI com codigos 0/1/2/3.
- `key_exposure`: envelope NIP-49 estrutural e modo/UID exatos, somente opt-in.
  Varredura de historicos/logs continua no scanner.
- `network`: cinco casos e fixtures reconstruidas; veth/peer, dummy, IPv4/IPv6,
  contadores e controles de trafego, mais modelo de airgap com radios simulados.
- Diferencas do detector preservadas: intervalo nsec, hifen Shamir, tratamento
  de parametros bunker vazios/duplicados, BIP39 invalido, deadline vazio e
  symlinks ancestrais. Propostas e migracao futura em
  [EXTRACTION.md](../packages/nvg-key-material/EXTRACTION.md).
- Decisoes novas: ncryptsec isolado do detector existente; metadata ctime/UID/modo
  observada durante leitura; permissao exatamente 0600; runtime sem dependencias
  externas alem do pacote comum; simulacao e adaptador nativo separados.
- Validacao: 44 testes aprovados, dois testes reais de namespace nao executados;
  wheels instalados offline e JSON validado. Ainda faltam compilacao/trafego nft,
  controles negativos reais, confronto com scripts/regras originais e validacao
  na instalacao nOS. [Registro completo](validation.md).
