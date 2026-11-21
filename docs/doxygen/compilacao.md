/**
 * @page page-compilacao Compilação, configuração e testes
 *
 * @brief Como o projeto é montado pelo CMake, quais opções existem e o que os
 *         testes cobrem.
 *
 * @details
 *
 * # CMake
 *
 * `CMakeLists.txt` exige CMake 3.15 ou superior e declara o projeto em C e C++.
 * A versão vem de uma regex sobre `include/libzupt_version.h`, exatamente a
 * linha que define `LIBZUPT_VERSION_STRING`:
 *
 * @code
 * file(STRINGS "include/libzupt_version.h" LIBZUPT_VERSION_LINE
 *     REGEX "^#define LIBZUPT_VERSION_STRING")
 * string(REGEX MATCH "[0-9]+\\.[0-9]+\\.[0-9]+" LIBZUPT_VERSION "${LIBZUPT_VERSION_LINE}")
 * project(libzupt VERSION ${LIBZUPT_VERSION} LANGUAGES C CXX)
 * @endcode
 *
 * Hoje isso resulta em `1.0.15`. Na biblioteca compartilhada, `VERSION` recebe
 * esse valor inteiro e `SOVERSION` recebe apenas `PROJECT_VERSION_MAJOR`, ou
 * seja `1`; na árvore compilada isto aparece como `libzupt.so` →
 * `libzupt.so.1` → `libzupt.so.1.0.15`. Ver \ref page-limitacoes sobre as
 * demais versões no repositório.
 *
 * ## Alvos
 *
 * | Alvo | Tipo | Conteúdo |
 * | --- | --- | --- |
 * | `zupt_shared` | `SHARED` | Os nove `src/*.c` listados em `LIBZUPT_C_SOURCES` (`CMakeLists.txt:36-46`) mais todos os `src/*.cpp` apanhados por `file(GLOB)` (`CMakeLists.txt:48-49`) |
 * | `zupt_static` | `STATIC` | Mesmas fontes |
 * | `zupt` | `ALIAS` | Apelido de `zupt_shared` |
 *
 * `zupt_shared` compila com a definição privada `ZUPT_EXPORTS`
 * (`CMakeLists.txt:65`), que controla a macro de exportação de símbolos, e
 * exige C++17 (`cxx_std_17`, `CMakeLists.txt:66`). `zupt_static` marca
 * `ZUPT_STATIC` como `PUBLIC` (`CMakeLists.txt:102`).
 *
 * ## Opções
 *
 * | Opção | Padrão | Efeito |
 * | --- | --- | --- |
 * | `LIBZUPT_BUILD_TESTS` | `ON` | Chama `enable_testing()` e adiciona `tests/`, onde os casos são registrados no CTest (`CMakeLists.txt:190-194`) |
 * | `LIBZUPT_BUILD_EXAMPLES` | `ON` | Adiciona `examples/`, com os quatro executáveis e o teste de migração (`CMakeLists.txt:196-198`) |
 * | `LIBZUPT_BUILD_PYTHON` | `OFF` | Adiciona `examples_python/`, que exige pybind11 encontrado pelo CMake (`CMakeLists.txt:200-202`) |
 * | `LIBZUPT_SANITIZERS` | `OFF` | Liga AddressSanitizer e UndefinedBehaviorSanitizer (`CMakeLists.txt:11`) |
 * | `LIBZUPT_BUILD_FUZZERS` | `OFF` | Compila o harness `zupt_fuzz_decrypt`; exige Clang **e** `LIBZUPT_SANITIZERS=ON`, senão o CMake encerra com `FATAL_ERROR` (`CMakeLists.txt:20-25`, `204-212`) |
 *
 * Não existe opção para as bindings Java: `examples_java/` não é referenciada
 * por nenhum `add_subdirectory` e não entra no build do CMake.
 *
 * A instalação publica as duas bibliotecas (`CMakeLists.txt:126-131`), os
 * arquivos de configuração do CMake (`:133-136`, `:172-176`), o `libzupt.pc`
 * gerado de `libzupt.pc.in` (`:146-155`) e exatamente três cabeçalhos —
 * `zupt.hpp`, `zupt_cxx.h` e `libzupt_version.h` (`:138-143`) — ver
 * \ref page-limitacoes.
 *
 * # build.sh
 *
 * `build.sh` é o atalho: cria `build/`, configura em `Release` com
 * `LIBZUPT_BUILD_TESTS=ON` e `CMAKE_INSTALL_PREFIX=/usr/local`, roda `make -j`
 * e depois `make test`. O arquivo não tem bit de execução no repositório, então
 * deve ser chamado como `bash build.sh`.
 *
 * # Definições de pré-processador que mudam o resultado
 *
 * | Macro | Onde | Efeito |
 * | --- | --- | --- |
 * | `ZUPT_STATIC` | `include/zupt_cxx.h:84` | Sob Windows/Cygwin, torna `ZUPT_API` vazia (vinculação estática); o CMake a define `PUBLIC` na meta estática (`CMakeLists.txt:102`) |
 * | `ZUPT_EXPORTS` | CMake, privada em `zupt_shared` | Sob Windows/Cygwin, seleciona `dllexport` ao compilar a DLL |
 * | `ZUPT_TESTING` | `src/zupt_mlkem.c:1143` | Expõe os pontos de entrada KAT consumidos só pelos testes |
 * | `ZUPT_USE_JASMIN` | `include/zupt_jasmin.h`, `src/zupt_crypto.c` | Ativa o dispatch Jasmin/AES-NI e AVX; sem ela o caminho portático é o usado |
 * | `ZUPT_FORCE_PORTABLE_AES` | `src/zupt_aes256.c` | Desliga a checagem `__builtin_cpu_supports("aes")` e força o AES por tabela |
 *
 * Nenhum alvo do CMake executa FRAMA-C nem o compilador Jasmin, e esta árvore
 * não contém nenhum arquivo `.acsl` ou `.jasmin`: as especificações existem
 * apenas como comentários ACSL dentro dos fontes, e as declarações Jasmin só em
 * `include/zupt_jasmin.h` — ver \ref page-limitacoes.
 *
 * # Testes
 *
 * `tests/CMakeLists.txt` gera um executável `zupt_test_<nome>` por fonte de
 * teste (função `add_zupt_test`, `tests/CMakeLists.txt:4-20`), que vincula
 * `zupt_shared` e força `-UNDEBUG` para que os `assert` continuem ativos em
 * `Release`. Os casos Python são chamados via `${Python3_EXECUTABLE}` contra a
 * biblioteca já construída. Com as opções padrão, a suíte tem catorze casos,
 * todos executáveis nesta máquina (gcc/g++ 12.3.0, cmake 3.28.3,
 * python 3.11.10). Treze vêm de `tests/CMakeLists.txt`;
 * `zupt_test_migration_cli` é o único registrado em outro lugar —
 * `examples/CMakeLists.txt:25-29`:
 *
 * - `zupt_test_keygen`
 * - `zupt_test_encrypt`
 * - `zupt_test_decrypt`
 * - `zupt_test_roundtrip`
 * - `zupt_test_file_ops`
 * - `zupt_test_authentication`
 * - `zupt_test_secure_buffer`
 * - `zupt_test_fuzz_smoke`
 * - `zupt_test_key_storage` (só sob `UNIX`, `tests/CMakeLists.txt:31-33`)
 * - `zupt_test_acvp` (Python, rótulo `python`)
 * - `zupt_test_aes_portable` (C, compilado com `ZUPT_FORCE_PORTABLE_AES`)
 * - `zupt_test_primitives` (Python, rótulo `python`)
 * - `zupt_test_legacy` (Python, rótulo `python`)
 * - `zupt_test_migration_cli` (Python, rótulo `python`)
 *
 * O teste ACVP consome uma biblioteca auxiliar `zupt_kat`
 * (`tests/CMakeLists.txt:36-42`), montada só para ele a partir de
 * `src/zupt_mlkem.c`, `src/zupt_keccak.c` e `tests/mlkem_support.c` com
 * `-DZUPT_TESTING`. Com `LIBZUPT_BUILD_PYTHON=ON` e
 * `LIBZUPT_BUILD_TESTS=ON` aparece ainda `zupt_test_python_binding`
 * (`examples_python/CMakeLists.txt:9-13`), que não roda nesta configuração
 * porque pybind11 não está instalado.
 *
 * `tests/CMakeLists.txt:59-63` também gera `build/run_tests.sh` a partir de
 * `run_tests.sh.in`.
 *
 * O resultado obtido com as alterações de documentação foi
 * `100% tests passed, 0 tests failed out of 14`.
 *
 * @see \ref page-exemplos para as bindings fora do build principal.
 */
