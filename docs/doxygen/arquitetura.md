/**
 * @page page-arquitetura Arquitetura e camadas
 *
 * A biblioteca é composta por camadas que só dependem das camadas abaixo.
 * Esta página descreve o que o código de `src/` faz; nomes de arquivos e
 * símbolos são os reais da árvore.
 *
 * \section arch-camadas As camadas
 *
 * \dotfile camadas.dot "Grafo de dependências entre camadas: cada aresta foi verificada no código (chamada ou diretiva de inclusão)"
 *
 * \subsection arch-l0 Primitivas (camada 0)
 *
 * - `src/zupt_sha256.c` — SHA-256 (FIPS 180-4) incremental
 *   (@ref zupt_sha256_init, @ref zupt_sha256_update, @ref zupt_sha256_final) e
 *   a versão de uma passada @ref zupt_sha256. Tabela `K[64]` gerada no próprio
 *   arquivo; contexto @ref zupt_sha256_ctx.
 * - `src/zupt_keccak.c` — esponja Keccak-f[1600] com taxa variável:
 *   `keccak_init`, `keccak_absorb`, `keccak_squeeze`, `keccak_finalize`, e os
 *   atalhos `zupt_sha3_*` / `zupt_shake*`. Contexto @ref zupt_keccak_ctx.
 * - `src/zupt_xxh.c` — XXH32 e XXH64 (somas de verificação não
 *   criptográficas).
 * - `src/zupt_aes256.c` — AES-256 em modo ECB de bloco único
 *   (@ref zupt_aes256_encrypt_block) com expansão de chave em
 *   @ref zupt_aes256_ctx. Há dois caminhos: tabelas portáveis e, sob
 *   `__GNUC__`/`__clang__` em x86 e sem `ZUPT_FORCE_PORTABLE_AES`, a
 *   instrução AES-NI via `aesni_encrypt_block()` protegida por
 *   `__builtin_cpu_supports("aes")`. Existe apenas cifragem: a estrutura não
 *   guarda agenda de descriptação, porque o modo usado pela biblioteca é CTR.
 *
 * \subsection arch-l1 KEM e troca de chave (camada 1)
 *
 * - `src/zupt_mlkem.c` — ML-KEM-768: NTT de grau 256 sobre `q = 3329`,
 *   amostragem por expansão determinística, encapsulação/desencapsulação e as
 *   rotinas de verificação @ref zupt_mlkem768_public_key_check,
 *   @ref zupt_mlkem768_secret_key_check, @ref zupt_mlkem768_selftest. Também
 *   implementa o caminho legado de decapsulação
 *   (@ref zupt_legacy_mlkem768_decaps), com funções de derivação de segredo
 *   diferentes do caminho atual.
 * - `src/zupt_x25519.c` — X25519 (RFC 7748) em aritmética de 5 limbos de 51
 *   bits, com @ref zupt_x25519 e @ref zupt_x25519_base. Os comentários
 *   originais do arquivo afirmam 4 limbos de 64 bits (donna64); o código
 *   implementa 5×51. Ver @ref page-limitacoes.
 *
 * \subsection arch-l2 Cola criptográfica (camada 2)
 *
 * - `src/zupt_crypto.c` — HMAC-SHA256, PBKDF2-HMAC-SHA256 (RFC 8018),
 *   @ref zupt_aes256_ctr, @ref zupt_derive_keys, @ref zupt_encrypt_buffer,
 *   @ref zupt_decrypt_buffer e @ref zupt_random_bytes. Também define o formato
 *   de chave híbrida serializada (`ZKEY`) e as frentes de inicialização
 *   @ref zupt_hybrid_keygen, @ref zupt_hybrid_encrypt_init e
 *   @ref zupt_hybrid_decrypt_init, além das variantes em memória. O dispatch
 *   acelerado por `zupt_cpu` vive em um ramo sob `ZUPT_USE_JASMIN`
 *   (`src/zupt_crypto.c:427-433`). A função @ref zupt_secure_wipe, usada por
 *   este arquivo, não está aqui: é `static inline` em `include/zupt.h`.
 * - `src/zupt_mlock.c` — @ref zupt_mlock_keys / @ref zupt_munlock_keys,
 *   fixação de páginas de segredo em memória (`mlock`) com ramo Windows.
 *
 * \subsection arch-l3 Fronteiras (camada 3)
 *
 * - `src/zupt_cxx.c` — frente C da API de envelope e de arquivos: as rotinas
 *   declaradas em `include/zupt_cxx.h` (@ref zupt_hybrid_keygen_c,
 *   @ref zupt_free e as operações de leitura/escrita de arquivo), os macros de
 *   cabeçalho e prefixo do envelope e os wrappers que reaproveitam as
 *   primitivas de `zupt_crypto.c`.
 * - `src/zupt_crypto.cpp` — a mesma frente em C++ no namespace `zupt`
 *   (@ref zupt::KeyGenerator, @ref zupt::Encryptor,
 *   @ref zupt::Decryptor, @ref zupt::SecureBuffer, @ref zupt::randomBytes,
 *   @ref zupt::sha256, @ref zupt::sha3_512), com exceções no lugar de
 *   códigos de erro (@ref zupt::ZuptError).
 *
 * \section arch-dependências Dependências reais entre módulos
 *
 * As arestas abaixo vêm das diretivas de inclusão de cada arquivo:
 *
 * - `zupt_mlkem.c` inclui `zupt_mlkem.h`, `zupt_keccak.h` (SHA3/SHAKE),
 *   `zupt.h`, `zupt_acsl.h` e `zupt_jasmin.h` — usa @ref zupt_random_bytes
 *   (definido em `zupt_crypto.c`) e @ref zupt_secure_wipe (inline em
 *   `include/zupt.h`). Ou seja, a camada 1 depende da camada 2 para
 *   aleatoriedade.
 * - `zupt_x25519.c` inclui `zupt_x25519.h`, `zupt_jasmin.h` e `zupt_cpuid.h`;
 *   nenhum símbolo declarado por `zupt_cpuid.h` é usado no código do arquivo.
 * - `zupt_aes256.c` inclui `zupt.h` e `zupt_acsl.h` e usa
 *   @ref zupt_secure_wipe, a função inline do cabeçalho.
 * - `zupt_crypto.c` inclui `zupt.h`, `zupt_acsl.h`, `zupt_cxx.h`,
 *   `zupt_jasmin.h` e `zupt_cpuid.h` no topo; `zupt_mlkem.h`, `zupt_x25519.h` e
 *   `zupt_keccak.h` aparecem mais adiante no mesmo arquivo, sem proteção
 *   condicional, no ponto em que começa a seção de chaves híbridas
 *   (`src/zupt_crypto.c:810-812`).
 *
 * \section arch-acsl ACSL, Jasmin e o que a build não faz
 *
 * Vários pontos do código carregam blocos ACSL (`/*@ ... */`) para
 * verificação em FRAMA-C, e existem cabeçalhos de anotação
 * (`include/zupt_acsl.h`, `include/zupt_jasmin.h`). Nenhum target do
 * `CMakeLists.txt` executa FRAMA-C, KB-MODELS ou o compilador Jasmin, e a
 * árvore não contém arquivos `.jasmin` nem assembly `.s`/`.S`. As anotações
 * são, portanto, documentação formal não verificada por esta build. Onde um
 * contrato ACSL descreve algo diferente do que a função faz, a documentação
 * registra o escopo realmente executado.
 *
 * \section arch-cpu Dispatch de processador
 *
 * Há dois mecanismos independentes de dispatch:
 *
 * - `zupt_aes256_encrypt_block()` consulta `__builtin_cpu_supports("aes")` no
 *   ponto de uso, sem estado global.
 * - Em `src/zupt_crypto.c`, o ramo sob `-DZUPT_USE_JASMIN` decide pelo par
 *   `zupt_cpu.has_aesni && zupt_cpu.has_avx`. `zupt_cpu` é declarado em
 *   `include/zupt_cpuid.h` e `zupt_detect_cpu()` também: <b>nenhum dos dois
 *   tem definição em `src/`</b>. Uma ligação que não forneça esses símbolos
 *   não resolve; se o programa os definir como zero, o ramo acelerado nunca é
 *   escolhido. A documentação de cada ponto de uso é explícita sobre isso.
 *
 * \section arch-onde-olhar Por onde começar a ler
 *
 * - Para o contêiner de compressão: @ref zupt_archive_header_t,
 *   @ref zupt_footer_t, @ref zupt_index_entry_t e @ref page-formato.
 * - Para o envelope criptográfico: @ref zupt::Encryptor e `docs/FORMAT.md`.
 * - Para primitivas: @ref zupt_sha256, @ref zupt_sha3_256,
 *   @ref zupt_aes256_ctr, @ref zupt_x25519, @ref zupt_mlkem768_encaps.
 *
 * \section arch-fluxo Fluxo da cifra híbrida
 *
 * O desenho abaixo resume a sequência de chamadas do envelope v2, com os
 * tamanhos que o código realmente escreve. As duas frentes (`zupt_cxx.c` e a
 * camada C++) chegam ao mesmo resultado: `zupt_cxx.c` chama o keyring e o
 * HMAC à mão, enquanto `include/zupt.hpp` usa `Encryptor`/`Decryptor`.
 *
 * \dotfile fluxo.dot "Sequência de chamadas da cifra e da decifra híbrida (tamanhos verificados em src/zupt_crypto.c e src/zupt_cxx.c)"
 */
