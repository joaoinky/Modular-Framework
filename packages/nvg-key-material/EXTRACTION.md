# Extracao e decisoes de compatibilidade

Referencia local lida: `../Hardening-scanner`, versao 0.3.0,
HEAD `5d1d98a335a51559a7b2f08cbb65d7f32edc7408`.
A extracao foi feita a partir dos arquivos presentes em 2026-09-13, nao de uma
implementacao inventada a partir do README. Nenhum arquivo do scanner foi editado.

| Fonte no scanner | SHA-256 publico observado |
| --- | --- |
| `src/nvg_scanner/key_patterns.py` | `f3e88d803d75b1b241bba99dba1bdaa529cb5b4985646d3786105228b043013e` |
| `src/nvg_scanner/checks/key_exposure_checks.py` | `8b448259900d7bf08565f04b894ac9337d07854c0ee615d75be0179aad4b4bc6` |
| `src/nvg_scanner/collectors.py` | `926a6222da63c3b1227ae42139ae642446e87b264a576efe407e8b8b6d481e3e` |
| `tests/public_key_vectors.json` | `c6819a85c5d1cbaad27be8ffce6988c032dd24e86a2e375ab20ee94f523883fc` |

`patterns.py` e identico ao arquivo de origem apos substituir exclusivamente
`resources.files("nvg_scanner")` por `resources.files("nvg_key_material")`.
Wordlist, PROVENANCE.txt, LICENSE.txt e os vetores foram copiados integralmente.
Esses hashes identificam codigo/dados publicos, nunca material coletado.

## Teste de equivalencia comportamental

Adicionado no follow-up: `tests/test_scanner_equivalence.py`, classe
`ScannerEquivalenceTests`, teste `test_original_and_extracted_field_equivalence`.
Executa o original do checkout local em subprocesso Python isolado, sem alterar
o scanner nem torna-lo dependencia de runtime. Confere igualdade dos vetores
JSON e da wordlist, depois compara todos os campos de `detect` (contagens,
candidatos e timeout), validadores e `safe_location`. Inclui vetores publicos,
combinacoes, corrupcoes, candidatos Shamir/bunker, caixa e prazo vencido.
Nao prova equivalencia para toda entrada possivel nem cobre o coletor original.

O checkout padrao e `../Hardening-scanner` em relacao ao framework. Configure
`NVG_SCANNER_CHECKOUT` para exigir outro checkout: caminho explicito indisponivel
falha, enquanto ausencia do checkout padrao gera skip explicito. O teste
`test_public_vectors_match_extraction_baseline` sempre confere o hash registrado
acima, mesmo sem scanner. Antes deste follow-up havia testes dos vetores no
pacote extraido e comparacao textual da extracao, mas nao teste diferencial.

Do check e do coletor foram separados os orcamentos e a leitura protegida em
`files.py`. Nao foram copiados `Result`, scoring, Context, configuracao nOS ou
o motor. A biblioteca oferece dados; cada consumidor decide a politica.
`encrypted.py` e uma adicao nova e isolada para checar estrutura NIP-49;
nao altera `detect` nem implementa criptografia.

## Diferencas encontradas e preservadas

| Regra | Observacao no codigo real | Proposta para mantenedores |
| --- | --- | --- |
| nsec | README resume checksum/comprimento; codigo tambem exige `0 < chave < ORDER` | Preservar a validacao e tornar a documentacao mais precisa |
| Shamir | README menciona prefixos `nvgs1`/`nvgs2`; regex exige hifen e caracteres ASCII alfanumericos/hifen | Preservar ate conferir o formato real; nao inventar CRC nem alargar silenciosamente |
| bunker | `parse_qs` ignora valores vazios; URI com `secret=&secret=x` pode ser reconhecida como um secret nao vazio | Manter compatibilidade agora; decidir se parametros duplicados devem ser sempre candidatos |
| BIP39 invalido | Frase sem checksum nao gera candidato BIP39, so ausencia de deteccao | Preservar; discutir outra classe de candidato sem transformar falsos positivos em chaves confirmadas |
| Prazo | `detect` com texto vazio pode terminar sem marcar timeout mesmo com deadline vencida; regexes/tokenizacao tem trechos sem preempcao | Preservar o detector; consumidores verificam o prazo tambem apos a chamada |
| Symlinks | Leitor recusa componente final, mas nao ancestrais; README detalhado confirma isso | Preservar e documentar; eventual walker por descritor sem links deve ser uma mudanca versionada |

Nenhuma dessas regras foi corrigida silenciosamente. Esta entrega nao depende
de uma decisao futura para funcionar, mas nao presume aprovacao das propostas.

## Diferencas novas e deliberadas

O leitor extraido tambem compara ctime, modo e UID antes/depois da leitura;
o scanner comparava tamanho e mtime. Isso aumenta a deteccao de mudancas de
metadados e pode reduzir a cobertura; nao cria aprovacoes adicionais.
`select_files` valida glob ancestral mesmo quando o nome final nao tem glob;
no scanner parte dessa validacao vivia na configuracao. No pacote, ela fica
na fronteira de I/O para consumidores sem aquele validador.

Limites e tetos foram mantidos. A camada pura nao define estados de auditoria;
o framework conserva `verified/mismatch/unknown`, enquanto o scanner futuro
pode continuar com seu mapeamento documentado de pass/fail/warning.

O plugin nao repete a varredura de historicos/logs: limita-se ao arquivo de
identidade autorizado, confirmando o envelope e modo exatamente 0600. Isso
difere da mascara maxima de permissao do scanner, que aceita 0400. Estrutura
NIP-49 valida nao autentica a chave cifrada.

## Migracao futura do scanner, fora desta entrega

1. Instalar uma versao fixa de `nvg-key-material` no ambiente do scanner,
   inicialmente por caminho local/arquivo wheel, sem importar `nvg_audit`.
2. Trocar imports de `key_patterns` pelos exports do pacote; manter um modulo
   de compatibilidade fino se consumidores externos usarem o caminho antigo.
3. Fazer o coletor delegar leitura/selecao ao pacote e compartilhar Budget
   onde apropriado; revisar a nova deteccao de mudancas de metadados.
4. Rodar a suite completa do scanner, os mesmos vetores publicos e comparacoes
   de contagens/candidatos/rotulos. Preservar opt-in, warnings, scoring e diff.
5. Remover a copia local da wordlist/detector apenas apos paridade comprovada;
   documentar a dependencia offline e combinar o versionamento entre projetos.
6. Decidir as divergencias acima com os mantenedores em mudanca separada.

Nao existe dependencia circular nem necessidade de publicar no PyPI.
A licenca MIT copiada refere-se a wordlist BIP39; nao presume relicenciamento
do codigo original do scanner, cuja referencia nao forneceu licenca geral.
