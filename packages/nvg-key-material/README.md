# NVG Key Material

Projeto Python independente `nvg-key-material`, modulo `nvg_key_material`.
O nome descreve material sensivel sem acoplar a biblioteca a scanner, plugins
ou ao sistema nOS. Nenhum motor de auditoria e importado; runtime usa somente
a biblioteca padrao, Python 3.10+.

## Instalar e testar

Dentro deste diretorio:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install .
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Ou instale com `pip install -e /caminho/nvg-key-material` no ambiente dos
consumidores. Sem instalacao, `PYTHONPATH=src` permite importar a biblioteca.
Nao ha CLI de varredura: a selecao e a politica pertencem ao consumidor.

## API

`patterns.py` foi extraido do scanner real sem mudar a logica; apenas o nome
do pacote que fornece a wordlist foi atualizado. Veja [proveniencia e
divergencias](EXTRACTION.md) antes de migrar outro consumidor.

| API | Retorno/escopo |
| --- | --- |
| `detect(text, wordlist(), deadline)` | `(counts, candidates, timed_out)`, sem valores detectados |
| `valid_nsec`, `valid_wif`, `valid_mnemonic` | Validadores matematicos locais de formatos suportados |
| `safe_location(label)` | Rotulo original ou omissao integral se parecer sensivel |
| `files.Limits`, `files.Budget` | Orcamento cumulativo de arquivos, bytes e tempo |
| `files.read_regular(path, limit)` | Leitura limitada de arquivo regular, sem seguir symlink final; buffer com repr oculto |
| `files.select_files` | Caminho absoluto ou glob somente no nome final, sem recursao |
| `files.inspect_files(paths, limits)` | Iterador de metadados: localizacao, contagens, candidatos e completude |
| `encrypted.ncryptsec_format(token)` | `valid`, `invalid` ou `unsupported`; apenas envelope NIP-49 v2 |

A biblioteca nao emite resultados de auditoria `pass/fail`. O framework adapta
os dados a `verified/mismatch/unknown`: consulta incompleta nunca deve aprovar;
um candidato Shamir nao comprova exposicao da seed. Ausencia de deteccao em
arquivo parcialmente lido nao constitui evidencia de ausencia. Validade
matematica de um formato nao comprova uso, saldo ou propriedade.

O modulo puro de padroes nao le arquivos e aceita texto em memoria. A camada
de I/O separada e opcional, sem dependencia de motor. `Read.data` e um buffer
transitorio para adaptadores; nunca serialize esse objeto ou seu conteudo.
`inspect_files` e a API que retorna exclusivamente metadados.

## Limites e confidencialidade

| Limite | Padrao | Teto de configuracao |
| --- | ---: | ---: |
| Bytes por arquivo | 262144 | 1048576 |
| Bytes analisados por execucao | 1048576 | 8388608 |
| Arquivos tentados | 8 | 64 |
| Segundos | 5 | 30 |
| Entradas por selecao de diretorio | 128 | 1024 |

Uma sondagem adicional de ate um byte por arquivo detecta truncamento. Arquivos
regulares sao abertos com O_NOFOLLOW/O_NONBLOCK e confirmados com fstat.
FIFO, dispositivo e symlink final nao sao lidos. Ancestrais ainda podem ser
symlinks, exatamente como no scanner: configure caminhos confiaveis.
Nao ha recursao, clipboard, busca automatica de usuarios ou acesso a rede.
Leituras alteradas, inacessiveis, parciais e orcamento esgotado sao incompletas.
O prazo e cooperativo neste pacote; o framework acrescenta isolamento por
processo. O pacote sozinho nao interrompe syscalls presas no kernel.

Saidas de deteccao nao incluem segredo, trecho, linha, fingerprint nem hash de
segredo. Rotulos potencialmente sensiveis sao omitidos por inteiro. Tipos e
contagens nao identificam qual chave apareceu. Python nao garante apagamento
de memoria nem controle de swap/dumps feitos externamente.

Nsec usa Bech32 e intervalo secp256k1; WIF usa Base58Check mainnet/testnet.
BIP39 suporta 12/15/18/21/24 palavras inglesas contiguas com checksum.
`bunker://` com chave publica hexadecimal e secret reconhecido e credencial;
partes `nvgs1-`/`nvgs2-` sao apenas candidatas, sem CRC ou reconstrucao.
O scanner ignora ncryptsec como plaintext. A nova API de envelope e separada
para nao mudar esse comportamento.

A wordlist publica e incorporada, tem SHA-256 verificado em runtime, procedencia
e licenca MIT nos arquivos [data](src/nvg_key_material/data/PROVENANCE.txt).
Seu hash e de dados publicos, nao de uma chave encontrada. Os vetores publicos
NIP-19/BIP39/WIF do scanner foram copiados integralmente; o teste NIP-49 usa
o vetor de [49.md](https://github.com/nostr-protocol/nips/blob/master/49.md).
O pacote nao baixa dados durante execucao.

## Limitacoes e extensao

Sem acesso a arvore real do nOS, nao se confirma o formato integral de Shamir,
o codigo que persiste a identidade ou sua criptografia. NIP-49 so recebe
checagem estrutural; nao se autentica ciphertext nem se testa senha. Outros
idiomas BIP39, fragmentos e codificacoes nao documentadas ficam fora do escopo.

Este projeto nao tem plugins. Novos formatos entram em funcoes independentes,
com testes publicos e retorno sem conteudo. Plugins de auditoria sao adicionados
ao framework consumidor conforme o README dele. Mudancas em regras extraidas
devem ser versionadas e revisadas com ambos os consumidores. A migracao do
scanner e futura, descrita em [EXTRACTION.md](EXTRACTION.md), e nao foi realizada.
