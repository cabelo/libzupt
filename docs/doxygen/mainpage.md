@mainpage page-mainpage libzupt — visão geral

<b>libzupt</b> é uma biblioteca C11 com interface C++17 que combina
criptografia autenticada híbrida (ML-KEM-768 + X25519) com um contêiner de
compressão em blocos. A documentação aqui gerada foi escrita lendo o código
de `src/` e `include/`; onde o código diverge dos comentários originais, do
`README.md` ou de `docs/FORMAT.md`, o texto descreve o comportamento do
código e registra a divergência. Ver @ref page-limitacoes.

\section main-pq Documentação desta revisão

- Configuração: `Doxyfile` na raiz do repositório. Comando: `doxygen Doxyfile`.
- Saída HTML: `build/apidocs/html/` (gerada, não versionada).
- Idioma da documentação: português; nomes de símbolos, tipos e arquivos
  permanecem em inglês.
- Apenas comentários foram adicionados aos fontes. Nenhuma linha de código,
  assinatura, valor de macro ou bloco ACSL foi alterado.

\section main-arquivos O que existe na árvore

| Caminho | Conteúdo |
|---|---|
| `include/` | 10 cabeçalhos públicos e internos |
| `src/` | 10 arquivos de implementação (9 `.c` e 1 `.cpp`) |
| `tests/` | testes unitários C/C++, vetores de teste, harness Python |
| `examples*` | pontes para Python, Node.js, Java, .NET, Go, PHP, Rust e exemplos C++ |
| `docs/FORMAT.md` | formato de envelope da API (ZUP2), distinto do contêiner de compressão |

A maior parte da superfície declarada em `include/zupt.h` não tem definição
em `src/`. Isso não é um erro de documentação: a árvore distribui a interface
completa, mas várias funções (compactação LZ, extração, desduplicação,
utilitários de arquivo, backup em disco) estão ausentes. A lista exata está
em @ref page-inventario. Onde isso afeta o uso, o símbolo documentado traz a
nota correspondente.

\section main-duas-familias Duas famílias de API convivendo

A biblioteca tem duas superfícies independentes que compartilham o mesmo
prefixo `zupt_`:

- <b>Contêiner de compressão</b> (`include/zupt.h`): tipos
  @ref zupt_archive_header_t, @ref zupt_footer_t, @ref zupt_index_entry_t,
  @ref zupt_options_t, @ref zupt_error_t, macros `ZUPT_BLOCK_*` e funções de
  arquivo como @ref zupt_compress_files. É o formato de arquivo descrito em
  @ref page-formato.
- <b>Envelope criptográfico da API</b> (`include/zupt.hpp`,
  `include/zupt_cxx.h`): as classes @ref zupt::KeyGenerator,
  @ref zupt::Encryptor e @ref zupt::Decryptor, com @ref zupt::SecureBuffer
  para o material em memória e @ref zupt::ZuptError para os erros.
  Este é o formato `ZUP2` especificado em `docs/FORMAT.md`.

As duas famílias usam primitivas comuns (AES-256-CTR, HMAC-SHA256, SHA-3)
mas <b>não</b> são intercambiáveis: magic, cabeçalhos, derivação de chave e
enquadramento são diferentes. Ver @ref page-arquitetura.

\section main-advertencias Advertências resumidas

As páginas de @ref page-limitacoes e @ref page-seguranca detalham cada item;
as cinco mais relevantes para quem vai usar a biblioteca:

- `include/zupt_keccak.h` não tem guard `extern "C"`. Incluí-lo de um
  arquivo C++ produz símbolos com name mangling e falha de link contra a
  `libzupt` compilada em C.
- @ref ZUPT_FLAG_CKSUM_XXH64 é `(0u << 5)`, isto é, `0`. Testar ou posicionar
  esse bit em `global_flags` não tem efeito algum.
- `zupt_decrypt_buffer` devolve `NULL` para causas distintas (falha de
  autenticação, dados corrompidos, falta de memória), sem canal para
  distingui-las.
- `keccak_finalize()` aplicado duas vezes ao mesmo contexto produz digest
  errado, silenciosamente.
- A versão da biblioteca aparece como `1.0.15`, `2.1.5` e `2.0.0` em três
  lugares diferentes. Ver @ref page-compilacao.

\section main-indice Páginas desta documentação

- @ref page-arquitetura — camadas, dependências entre módulos, dispatch de CPU.
- @ref page-api-guia — como usar as duas famílias de API, com os contratos reais.
- @ref page-formato — layout em disco do contêiner e do envelope.
- @ref page-memoria — quem aloca, quem libera, o que é limpo.
- @ref page-erros — @ref zupt_error_t e as formas alternativas de sinalizar erro.
- @ref page-concorrencia — o que o código garante e o que não garante.
- @ref page-seguranca — primitivas, proteção de segredos, achados.
- @ref page-compilacao — CMake, opções, versões, testes.
- @ref page-exemplos — os exemplos da árvore e o que cada um exerce.
- @ref page-limitacoes — divergências e defeitos registrados, não corrigidos.
- @ref page-inventario — tabela de símbolos documentados por arquivo.
