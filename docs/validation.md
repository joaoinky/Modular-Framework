# Registro de validacao - 2026-09-13

Ambiente observado: Linux, Python 3.13, UID 1000, terminal em ambiente restrito.
Nao e uma instalacao nOS identificada ou uma ISO em teste.

## Executado

| Verificacao | Resultado |
| --- | --- |
| Pacote comum: `unittest discover -s packages/nvg-key-material/tests -v` | 13 testes aprovados |
| Framework: `unittest discover -s tests -v` | 31 aprovados, 2 testes de integracao explicitamente pulados |
| Total de testes executados | 44 aprovados |
| CLI `--list-plugins` | `key_exposure` e `network` descobertos |
| CLI `--all`, configuracao local | JSON produzido; 0 verified, 0 mismatch, 7 unknown; exit 3 |
| Schema do relatorio | JSON Schema Draft 2020-12 e exemplo validados com jsonschema/FormatChecker |
| Build dos dois wheels | setuptools/pip com `--no-deps --no-build-isolation`, sucesso |
| Instalacao dos wheels | Venv local, `--no-index --find-links dist`, dependencia resolvida localmente |
| Importacao com `python -I` | Pacotes instalados, dois plugins, tres regras nft, schema e 2048 palavras presentes |
| Extracao | Detector identico ao scanner salvo namespace de resources; wordlist/licenca/proveniencia/vetores copiados |

`jsonschema` foi usado somente como ferramenta de validacao no venv. Nao e
dependencia de runtime do projeto. Testes de leitura usaram arquivos temporarios,
FIFO, symlinks e apenas vetores publicos. Mocks validaram estados, falhas,
marcadores e classificacao de sondas; nao representam trafego real.

O exemplo [unavailable.json](../examples/unavailable.json) foi gerado pela CLI,
sem editar resultados. Chaves nao foram lidas: opt-in desabilitado.
`ip` e `nft` nao foram encontrados. A sonda independente
`unshare --user --map-root-user --net true` retornou
`Operation not permitted` antes de executar o comando interno.

## Nao comprovado neste ambiente

Nenhum cenario de trafego do framework foi executado em namespace real aqui.
Nao houve compilacao das fixtures pelo nft nem demonstracao real da transicao
`verified -> mismatch` ao reintroduzir um bug. Os dois testes que exigem essas
evidencias estao implementados em `tests/test_netns_integration.py` e pulados
explicitamente na suite comum. O criterio de aceitacao de trafego permanece
pendente ate uma execucao bem-sucedida em ambiente com essas capacidades.

Para reproduzir e exigir essa validacao:

```sh
export PYTHONPATH="$PWD/src:$PWD/packages/nvg-key-material/src"
NVG_RUN_NETNS=1 python3 -m unittest tests.test_netns_integration -v
```

Nessa modalidade `unknown` falha o teste; nao vira skip ou aprovacao.
O primeiro teste exige cinco resultados `verified`. O segundo exige
`mismatch` nos quatro controles negativos NVG-06/07/10/11.
NVG-08 testa o modelo local de marcadores e radios simulados, com interfaces
reais somente quando o namespace estiver disponivel.

Mesmo depois da suite passar, ainda sera necessario confrontar as fixtures e
o adaptador com o codigo nOS real e validar o sistema instalado. Nao se testou
boot, hardware, Tor, VPN real, autenticacao de ciphertext ou SSH. Nenhum CI do
nOS foi integrado e nenhuma ISO foi construida.
