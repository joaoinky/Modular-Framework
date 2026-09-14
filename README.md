# NVG Audit

Framework Python independente para casos de regressao de seguranca do nOS.
O pacote `nvg_audit` recebe esse nome para distinguir testes de auditoria do
scanner passivo `nvg_scanner`. O pacote comum `nvg_key_material` identifica
material de chave sem depender de nenhum dos dois motores.

Esta entrega implementa o chassi, os plugins `network` e `key_exposure` e dois
projetos instalaveis. **As regras de rede sao reconstrucoes da documentacao,
nao arquivos originais do nOS.** Um resultado positivo da simulacao nao aprova
uma instalacao real. A validacao com namespaces nesta maquina esta indisponivel;
veja [registro de validacao](docs/validation.md).

## Instalar e executar

Linux, Python 3.10+ e biblioteca padrao em runtime. No diretorio deste projeto:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m nvg_audit --list-plugins
.venv/bin/python -m nvg_audit --target-config config/local.json --plugin network
.venv/bin/python -m nvg_audit --target-config config/local.json --all --format json --output relatorio.json
```

`requirements-dev.txt` instala primeiro o projeto comum local e depois este
framework. `pyproject.toml` declara a dependencia versionada
`nvg-key-material==0.1.0`; nenhum pacote precisa ser publicado no PyPI.
Pip pode obter setuptools para o build. Com as ferramentas de build ja disponiveis,
`--no-build-isolation --no-index` permite uma instalacao local offline.
Os dois projetos podem ser movidos para checkouts separados: instale primeiro
`pip install -e /caminho/nvg-key-material`, depois `pip install -e /caminho/nvg-audit`.

Sem instalar nem acessar a Internet:

```sh
export PYTHONPATH="$PWD/src:$PWD/packages/nvg-key-material/src"
python3 -m nvg_audit --list-plugins
python3 -m nvg_audit --all
```

Sem `--target-config`, usa defaults de simulacao, timeout de cinco segundos e
leitura de chaves desabilitada. `--all` e a selecao padrao. `--plugin` pode ser
repetido. O unico formato nesta versao e JSON. Arquivos de saida novos usam
0600 e nao sobrescrevem arquivos ou symlinks existentes. Stdout depende da
umask e do destino escolhido pelo shell.

| Exit | Significado |
| --- | --- |
| 0 | Todos os casos emitidos ficaram `verified` |
| 1 | Existe `mismatch`, mesmo com outros casos `unknown` |
| 2 | Erro de argumentos, configuracao, selecao ou escrita |
| 3 | Existe `unknown`, sem `mismatch` |
| 130 | Execucao interrompida |

JSON valido e exit 3 constituem execucao inconclusiva, nao erro interno nem
aprovacao. Identidade desabilitada em `--all` produz dois casos `unknown`.
Para validar somente a simulacao de rede, selecione `--plugin network`.

## Configurar o alvo

[config/local.json](config/local.json) e um exemplo executavel. Campos
desconhecidos, duplicados, timeouts invalidos e modos remotos sao recusados.
Caminhos da chave e da biblioteca devem ser absolutos; `~`, HOME e SUDO_UID nao
selecionam automaticamente uma conta. `network.rules_dir` relativo e resolvido
em relacao ao arquivo de configuracao, nao ao cwd.

| Campo | Contrato |
| --- | --- |
| `target.description` | Descricao explicita da simulacao/alvo; rotulos sensiveis sao omitidos |
| `execution.timeout_seconds` | Cinco segundos por caso por padrao; positivo e no maximo 300 |
| `execution.case_timeouts` | Overrides por `case_id`; o exemplo reserva 15 ou 30 segundos para rede |
| `network.mode` | Somente `simulation`; sem execucao SSH ou modo live |
| `network.rules_dir` | `null` usa fixtures publicas incorporadas; diretorio alternativo deve fornecer os tres `.nft` |
| `network.library` | Caminho configuravel de `neo-rede.sh` |
| `network.reference` | Caminho configuravel de `network-policies.json` |
| `key_exposure.enabled` | Opt-in de leitura da chave esperada, desabilitado por padrao |
| `key_exposure.key_path` | Arquivo explicitamente selecionado pelo operador |
| `key_exposure.expected_uid` | UID numerico esperado, obrigatorio ao habilitar |
| `key_exposure.limits` | Limites do [pacote comum](packages/nvg-key-material/README.md) |
| `extensions` | Configuracao reservada a novos plugins, validada por eles |

A documentacao de identidade define
`~/.local/share/neovanguard/chave.ncryptsec` e modo 0600. Para uma conta
provisionada, configure o caminho absoluto e UID reais e habilite a leitura.
Nao inclua chaves, senhas, mnemonicos ou URIs de credencial na configuracao.

`library` e `reference` **nao sao executados nem consumidos pela simulacao**.
O adaptador separado `native.verify(config, mode)` esta preparado para futura
integracao manual, somente leitura. Antes de `source`, exige arquivo regular,
ancestrais diretorios root, sem symlinks ou escrita de grupo/outros para ambos.
Valida JSON, schema, timestamp, estado solicitado e exit code de `network_verify`.
Nesta versao a API nativa aceita apenas base, tor, killswitch-tor e airgap;
os casos VPN usam exclusivamente os endpoints fixos das fixtures de simulacao.
Ele nao chama apply/cache nem comprova que um caminho de referencia customizado
e utilizado internamente pela biblioteca: esse contrato exige validacao no nOS.
Nenhum caso padrao depende dele. A checagem nao autentica root comprometido nem
elimina corridas causadas por quem ja controla os diretorios confiaveis.

A assinatura `verify(config, mode) -> Outcome` pode ser preservada para esses
quatro modos; isso nao e uma garantia de integracao validada com o nOS real.
O contrato atual devolve estado, motivo e evidencia minima (modo solicitado e
timestamp), nao os detalhes de interfaces, radios ou endpoints. A chamada tem
limite de 5 segundos e 256 KiB de stdout; falhas viram `unknown`.
Lacunas conhecidas para a proxima rodada: VPN exige interface e endpoints
esperados (via extensao de configuracao ou argumentos opcionais); `reference`
hoje e apenas checado quanto a confianca, nao passado a `network_verify`.
Seu encaminhamento depende do mecanismo aceito pela biblioteca real. Casos
que precisem de sondas de trafego ou evidencia detalhada nao serao resolvidos
apenas conectando esta funcao: sera preciso ampliar a evidencia/adaptacao.
Nenhuma mudanca de assinatura e necessaria nesta rodada; o contrato externo,
os efeitos de `source` e a ausencia de alteracoes no host ainda devem ser
validados antes de integrar casos nativos.

## Contrato e arquitetura

Cada modulo confiavel `plugins/*_plugin.py` implementa o `Protocol` `Plugin`
de [models.py](src/nvg_audit/models.py), exportando `cases(config)`.
O protocolo estrutural permite usar modulos e mocks, sem exigir heranca ou
registro central. Descoberta e ordenacao sao deterministicas. Configuracao nao
indica um arquivo Python arbitrario para importar.

Cada `Case` tem ID estavel e funcao que recebe a configuracao e retorna
`Outcome(state, reason, evidence)`. O motor adiciona `case_id`, `plugin` e
`duration_ms` medido por relogio monotonico. A identidade e o par
`(plugin, case_id)`. IDs devem ser minusculos, alfanumericos/underscore;
o prefixo `engine_` e reservado. Duplicados, enumeracao interrompida, plugins
vazios e resultados invalidos acrescentam `unknown`; resultados anteriores
continuam no relatorio.

| Estado | Interpretacao |
| --- | --- |
| `verified` | A evidencia coletada satisfaz este caso e seu escopo declarado |
| `mismatch` | Existe divergencia observada |
| `unknown` | Evidencia insuficiente, erro, consulta inacessivel ou prazo esgotado |

O schema [report.schema.json](src/nvg_audit/report.schema.json) usa
`schema_version: 1`, timestamp UTC, versao do framework, alvo, plugins, resultados
e tres contagens separadas. Nao ha score ou taxa de aprovacao que possa esconder
`unknown`. Exemplo real de degradacao: [examples/unavailable.json](examples/unavailable.json).

Cada caso roda em um processo com grupo proprio. O supervisor limita o resultado
a 256 KiB e encerra o grupo no prazo, incluindo workers de rede e peers. Comandos
usam PATH fechado, stderr descartado e captura limitada. Plugins continuam
sendo codigo Python confiavel, nao uma sandbox: importacao/enumeracao ocorrem no
motor, e um plugin que deliberadamente cria outra sessao foge dessa disciplina.
Chamadas presas em estado ininterruptivel do kernel nao oferecem garantia de
limpeza imediata. A implementacao com `fork` destina-se a CLI Linux monothread.

Evidencias do plugin de chaves so possuem tipo, localizacao, contagens e metadados
POSIX. Conteudo, fragmentos, fingerprints e hashes de segredo nao sao registrados.
Falhas usam mensagens fixas. O motor filtra rotulos e strings reconheciveis como
material sensivel, mas isso e uma defesa adicional: plugins novos devem construir
evidencias permitidas, nunca transmitir buffers de segredo para o relatorio.
Python nao garante apagamento de memoria, swap ou dumps externos.

## Casos implementados

`key_exposure` inspeciona apenas o arquivo de identidade explicitamente autorizado:

| case_id | Evidencia |
| --- | --- |
| `key_nip49_envelope` | Formato Bech32 completo NIP-49 v2, checksum, 91 bytes, campos estruturais; plaintext reconhecido pelo pacote comum e `mismatch` |
| `key_owner_mode_0600` | Arquivo regular, UID configurado e modo POSIX exatamente 0600 |

Com opt-in ativo, `key_path` declara um arquivo provisionado obrigatorio:
ausencia confirmada por `lstat` (`ENOENT`, inclusive ancestral ausente) e
`mismatch` nos dois casos. Falha de acesso/consulta nao comprova ausencia e
permanece `unknown`. Symlink final, inclusive quebrado, e `unknown`.
Se o arquivo desaparece depois do `lstat`, durante a leitura, o resultado do
envelope e `unknown`: a observacao ficou incompleta. Nao ha garantia atomica.
Leitura parcial, timeout e candidato nao confirmado tambem sao `unknown`.
Sem opt-in, ambos sao `unknown` e nem sequer consultam o caminho.
Envelope vazio/malformado e `mismatch`; versao desconhecida no mesmo envelope e
`unknown`. Um envelope estruturalmente valido nao comprova autenticacao AEAD,
senha correta/forte, autenticidade ou recuperabilidade. Nao ha decriptacao,
assinatura ou escrita na chave. Permissoes nao incluem ACLs nem auditoria dos
ancestrais. Arquivos sao observados separadamente, nao em uma transacao atomica.

Historicos, logs e varredura estatica generica permanecem responsabilidade do
scanner. A verificacao de permissao aqui usa **modo exato**; o scanner usa uma
mascara maxima e pode aceitar 0400. A diferenca e deliberada para o contrato
persistido 0600 pedido nesta entrega.

`network` usa dois namespaces anonimos, um par veth para o peer de eco e uma
interface `nvgvpn0` dummy. Nenhuma rota default e criada. Cada caso tem rede
descartavel propria. Regras so sao aplicadas depois de confirmar namespaces
distintos dos do processo invocador; nao ha namespace nomeado nem alteracao no
firewall, interfaces, servicos ou radios do host.

| case_id | Sondas implementadas |
| --- | --- |
| `nvg06_established_sessions_direct` | TCP/UDP IPv4/IPv6 anteriores ao firewall, nos dois modos Tor; conntrack medido antes; controle do proprietario autorizado |
| `nvg07_dns_leak_lan_resolver` | DNS TCP/UDP novo redirecionado a 9040/9053, LAN e publico IPv4/IPv6; DNS anterior bloqueado; LAN IPv4 nao-DNS preservada |
| `nvg08_airgap_false_success` | `ip -j link show` real, dummy e veth UP/DOWN; radios simulados; marcador simulado so apos confirmacao e sem erro operacional |
| `nvg10_vpn_dns_leak` | DNS LAN TCP/UDP IPv4/IPv6, novo e anterior, bloqueado; LAN nao-DNS preservada |
| `nvg11_vpn_udp_unrestricted` | UDP 51820/1194 novo/anterior fora dos endpoints e porta errada bloqueados; pares IPv4/IPv6 permitidos |

Sondas negativas exigem contador nftables de descarte aumentando, controles
positivos antes/depois e peer saudavel. Uma janela sem resposta sem veredito
mensuravel produz `unknown`. Repostas que contradizem a expectativa produzem
`mismatch`. Timeouts de comandos/infraestrutura sempre produzem `unknown`.

## Testar e reproduzir regressoes

```sh
export PYTHONPATH="$PWD/src:$PWD/packages/nvg-key-material/src"
python3 -m unittest discover -s packages/nvg-key-material/tests -v
python3 -m unittest discover -s tests -v
```

Testes unitarios usam `unittest`, mocks, vetores publicos e arquivos temporarios.
Incluem leitura real, FIFO/symlink, checksums, tres estados, timeout, contratos
nativos contraditorios e erros de comandos. Nenhuma chave pessoal e usada.

`packages/nvg-key-material/tests/test_scanner_equivalence.py` compara o
detector original em subprocesso isolado com o extraido, campo a campo,
usando os mesmos vetores publicos e casos adicionais invalidos/candidatos.
Por padrao procura `../Hardening-scanner`; sem esse checkout, somente a
comparacao direta e pulada, e o hash dos vetores originais continua testado.
Para exigir a comparacao (checkout ausente passa a ser falha):

```sh
NVG_SCANNER_CHECKOUT=/caminho/Hardening-scanner python3 -m unittest discover -s packages/nvg-key-material/tests -v
```

Para **exigir** integracao real, numa maquina Linux com `nft` (nftables), `ip`
(iproute2), `unshare` (util-linux), IPv6, veth/dummy e permissao para namespaces:

```sh
NVG_RUN_NETNS=1 python3 -m unittest tests.test_netns_integration -v
```

Sem essa variavel, os dois testes de integracao sao explicitamente pulados.
Com ela, ferramenta/permissao ausente **falha a suite**. Os testes exigem os
cinco casos corrigidos `verified` e quatro controles negativos `mismatch`.
Nao elevamos privilegios automaticamente. Dependencias do sistema nao sao
instaladas pelo framework.

Para criar manualmente a regressao NVG-07 em uma copia separada:

```sh
python3 examples/make_regressions.py nvg07 examples/broken-nvg07
python3 -m nvg_audit --target-config examples/nvg07-regression.json --plugin network
```

O gerador tambem aceita `nvg06`, `nvg10` e `nvg11`; recusa diretorio existente.
Os arquivos originais incorporados sao preservados. As copias quebradas sao
fixtures publicas para namespaces, nunca politica a instalar no host.

## Adicionar um plugin

Crie `src/nvg_audit/plugins/example_plugin.py`:

```python
from nvg_audit.models import Case, Outcome


def inspect_target(config):
    return Outcome("unknown", "Backend not configured", {})


def cases(config):
    yield Case("example_target_state", inspect_target)
```

Adicione testes com casos conclusivos, inconclusivos e timeout. Parametros novos
ficam em `extensions.example` e sao validados pelo plugin. Os futuros `daemon_test`
e `recon` podem seguir exatamente esse contrato; nao estao implementados.
Plugins com descendentes devem manter o grupo do caso e fechar recursos ao sair.

## Limitacoes e suposicoes

A fonte de verdade do alvo e a copia em [NVG-Doc](NVG-Doc/README.md), em especial
[verificacao](NVG-Doc/verificacao-estado-rede.md),
[historico Tor/VPN](NVG-Doc/testes-firewall-tor.md),
[marcadores](NVG-Doc/correcoes-marcadores-rede.md),
[identidade](NVG-Doc/identidade.md) e
[escopo de seguranca](NVG-Doc/security-review-scope.md).
O scanner real foi lido em `../Hardening-scanner`, sem migracao ou edicao.

Os fontes de `test-nft-network.py`, `test-network-modes.py`,
`check-network-policies.py`, `neo-rede.sh` e os `.nft` originais **nao foram
fornecidos**. Foram lidas suas descricoes e os contratos; nao foi possivel ler
esses scripts. Em particular:

- Os fixtures implementam apenas os cenarios solicitados; input permissivo,
  LAN reduzida e ICMPv6 permitido facilitam a topologia isolada. Nao sao politica
  de hardening, copia do ruleset distribuido ou prova de equivalencia completa.
- O UID Tor 43 vem da documentacao; controle positivo substitui 43 por 0
  somente na copia em memoria. Nao se valida o usuario real do daemon.
- DNSPort/TransPort sao listeners de eco locais. Nao existe Tor, DNS real,
  anonimato, VPN, handshake WireGuard, roaming ou teste de DNS pelo tunel dummy.
- LAN nao-DNS permanece uma excecao documentada, inclusive UDP em portas de VPN.
  NVG-11 testa restricao de endpoints **fora dessa excecao**; nao afirma bloquear
  todo datagrama 51820/1194 destinado a LAN. DHCP esta nas regras, mas nao tem
  sonda dedicada nesta versao.
- NVG-08 usa `ip` real e o modelo local do contrato de marcadores. A consulta
  `rfkill --json --output ID,TYPE,SOFT,HARD` e representada por fixtures
  `rfkilldevices` com valores `blocked`/`unblocked`. Nenhum radio real e consultado
  ou alterado. Formatos efetivos e comandos originais precisam de validacao.
- NVG-05 e coberto apenas por testes do parser de verificacao e do modelo de
  invalidacao; nao ha caso de ponta a ponta do painel `neo-status`.
- NVG-09 nao e regressao de rede: trata da recuperacao Shamir com partes de
  divisoes diferentes, conforme a [quinta rodada](NVG-Doc/auditoria-erros/2026-09-09/correcoes-05.md).
  Sua ausencia no README anterior foi uma omissao documental. Nao ha caso
  NVG-09 nesta entrega: reconhecer candidatos `nvgs1`/`nvgs2` nao valida a
  recuperacao. Pendencia: testar as funcoes reais de `neo-shamir` com vetores
  sinteticos quando disponiveis, incluindo misturas, ID/CRC adulterados e
  comportamento legado. Reimplementar Shamir a partir da documentacao nao
  testaria o codigo original e foge ao escopo do detector sem reconstrucao.
- NIP-49 e validado estruturalmente segundo a
  [especificacao oficial](https://github.com/nostr-protocol/nips/blob/master/49.md).
  O pacote nao implementa criptografia. As sondas usam a
  [semantica nftables](https://netfilter.org/projects/nftables/manpage.html),
  mas a compilacao dos fixtures ainda precisa ser exercitada com nft/kernel real.

Para rodar ao lado de um checkout real do nOS, mantenha este projeto separado,
descreva o checkout/commit em `target.description` e execute os comandos acima.
Isso continua sendo simulacao. Antes de confiar no framework como auditor da
distribuicao, confronte as fixtures com os arquivos reais, execute a suite de
controle negativo no kernel, valide caminhos/formatos da biblioteca instalada
e compare com os scripts originais. Usar um checkout como descricao nao faz
o framework testar seu codigo. Nao ha SSH, CI do nOS, build de ISO ou instalacao
de componentes no OS nesta entrega.

Detalhes da extracao, diferencas preservadas e migracao futura do scanner:
[EXTRACTION.md](packages/nvg-key-material/EXTRACTION.md).
