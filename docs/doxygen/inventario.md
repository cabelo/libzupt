// libzupt - Inventário de cobertura da documentação
// Este arquivo é processado pelo Doxygen como página Markdown.

@page page-inventario Inventário da documentação

@tableofcontents

# Como ler este inventário

Três números são medidos por arquivo, e medem coisas diferentes:

- **Blocos** — comentários Doxygen escritos no arquivo. Contados pelo início do
  comentário (`//!`, `///`, `/**` ou `/*!`), uma vez por bloco, independentemente
  de quantas linhas ele ocupou.
- **Itens** — entradas que o Doxygen colocou na lista de itens da API a partir
  do arquivo: o próprio arquivo, as estruturas, uniões, enumerações e classes
  declaradas nele, e as funções, variáveis, macros, typedefs, enumeradores e
  membros declarados nele. Cada item conta uma vez, pelo seu identificador.
- **Doc** — dos itens anteriores, quantos têm texto: descrição breve ou
  descrição detalhada não vazia no XML gerado pelo Doxygen.

Em todos os arquivos da tabela **Doc é igual a Itens**. Não existe item na
lista de itens da API sem texto, o que é conferido pelas opções do `Doxyfile`
`WARN_IF_UNDOCUMENTED = YES`, `WARN_IF_DOC_ERROR = YES` e `WARN_NO_PARAMDOC = YES`:
a geração não produz nenhum aviso.

O número de blocos pode ser diferente do de itens por dois motivos: um único
comentário pode descrever vários membros (os campos de uma estrutura ou os
enumeradores de uma enumeração escritos com o sufixo `/**< ... */`), e um
comentário pode descrever algo que o parser do Doxygen 1.8.14 não representa
como item de lista. Os dois casos concretos estão explicados em
@ref inv-limites.

# Cobertura por arquivo

| Arquivo | Blocos | Itens | Doc |
|---|---|---|---|
| `include/zupt.h` | 167 | 195 | 195 |
| `include/zupt.hpp` | 135 | 79 | 79 |
| `include/zupt_cxx.h` | 13 | 13 | 13 |
| `include/zupt_mlkem.h` | 17 | 17 | 17 |
| `include/zupt_keccak.h` | 14 | 19 | 19 |
| `include/zupt_x25519.h` | 3 | 3 | 3 |
| `include/zupt_cpuid.h` | 4 | 9 | 9 |
| `include/libzupt_version.h` | 2 | 2 | 2 |
| `include/zupt_acsl.h` | 1 | 1 | 1 |
| `include/zupt_jasmin.h` | 4 | 1 | 1 |
| `src/zupt_mlkem.c` | 48 | 46 | 46 |
| `src/zupt_crypto.c` | 25 | 30 | 30 |
| `src/zupt_cxx.c` | 12 | 19 | 19 |
| `src/zupt_x25519.c` | 21 | 18 | 18 |
| `src/zupt_sha256.c` | 12 | 16 | 16 |
| `src/zupt_keccak.c` | 10 | 22 | 22 |
| `src/zupt_xxh.c` | 13 | 13 | 13 |
| `src/zupt_aes256.c` | 8 | 9 | 9 |
| `src/zupt_mlock.c` | 7 | 3 | 3 |
| `src/zupt_crypto.cpp` | 1 | 1 | 1 |
| `examples_nodejs/src/zupt_napi.cpp` | 44 | 43 | 43 |
| `examples_python/zupt_pybind.cpp` | 47 | 2 | 2 |
| `examples_java/zupt_jni.cpp` | 29 | 28 | 28 |
| `examples_nodejs/src/zupt_crypto_c_bridge.c` | 1 | 1 | 1 |
| `examples_nodejs/src/zupt_crypto_cpp_bridge.cpp` | 1 | 1 | 1 |
| **Total (código)** | **639** | **591** | **591** |

Os 12 arquivos Markdown de `docs/doxygen/` (esta página e as outras 11) não
entram na tabela: cada um é uma página, não código.

@anchor inv-modulos
# Cobertura por módulo

Somando a tabela anterior por grupo, os totais fecham com os 639 blocos e os 591
itens:

| Módulo | Blocos | Itens |
|---|---|---|
| Cabeçalhos C (`include/*.h`) | 225 | 260 |
| Cabeçalho C++ (`include/zupt.hpp`) | 135 | 79 |
| Implementação (`src/`) | 157 | 177 |
| Vinculações (`examples_java`, `examples_python`, `examples_nodejs`) | 122 | 75 |
| **Total** | **639** | **591** |

O peso está onde se espera: os cabeçalhos concentram mais da metade dos itens,
porque a interface pública é declarada neles. Os 75 itens das vinculações se
concentram no JNI (28) e no N-API (43); os 2 do pybind são o artefato do padrão
lambda descrito abaixo.

@anchor inv-sem-definicao
# Símbolos declarados sem definição

A cobertura acima mede *documentação*, não *implementação*. Comparando o que
`include/` declara com o que `build/libzupt_static.a` contém
(`nm --defined-only`), **52 dos 113 nomes** aparecem nos cabeçalhos e em nenhum
objeto. Estão documentados — têm `@brief`, parâmetros e notas — e não têm corpo.

A distribuição:

| Grupo | Qtd. | Onde estão |
|---|---|---|
| Primitivas Jasmin e CPU | 6 | `include/zupt_jasmin.h`, `include/zupt_cpuid.h` |
| Arquivos, codecs e desduplicação | 46 | `include/zupt.h` |

A lista completa está em @ref page-limitacoes, que também explica por que o
vínculo não quebra hoje (os usuários desses nomes só existem sob macros de
condição de especificação desligadas, ou não existem).

Isso não afeta a verificação de cobertura: o Doxygen cobra documentação de tudo
que *declara*, e esses 52 símbolos estão documentados como os demais. Mas significa
que a frase "toda a API está documentada" não deve ser lida como "toda a API
existe".

@anchor inv-limites
# Onde os números divergem e por quê

- `include/zupt.hpp` tem 135 blocos para 79 itens: os métodos das classes são
  declarados e documentados aqui, e apenas implementados em
  `src/zupt_crypto.cpp`. As definições daquele arquivo não geram itens novos
  porque a documentação já está anexada às declarações. Por isso
  `src/zupt_crypto.cpp` aparece com um único item: o próprio arquivo.
- `src/zupt_keccak.c` (10 blocos, 22 itens) e `src/zupt_cxx.c` (12, 19):
  comentários de seção descrevem grupos de funções internas, e campos de
  estruturas privadas são documentados no ponto de definição.
- `examples_python/zupt_pybind.cpp` tem 47 blocos para 2 itens: a maior parte
  da documentação está sobre expressões lambda registradas em
  `m.def(...)`. O Doxygen 1.8.14 não cria item de lista para lambda, então o
  texto aparece na página do arquivo e nos parâmetros descritos em lista
  nominal, mas não em páginas próprias. Os dois itens são o arquivo e a função
  do módulo.
- `include/zupt_jasmin.h` tem 4 blocos para 1 item: três dos comentários
  descrevem protótipos que só existem sob a macro de condição de especificação,
  que não está definida na geração normal, então não viram itens.
- `include/zupt.h` tem 167 blocos para 195 itens porque os campos de várias
  estruturas públicas são documentados no bloco da estrutura.
