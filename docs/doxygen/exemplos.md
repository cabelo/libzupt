/**
 * @page page-exemplos Exemplos prontos e como construí-los
 *
 * A árvore traz quatro conjuntos de exemplos, cada um com um mecanismo de
 * construção diferente. Apenas os C++ participam do CMake principal; os de
 * Python dependem de uma opção desligada por padrão, e os de Java e Node.js
 * têm projetos próprios, fora do `CMakeLists.txt` da biblioteca.
 *
 * # C++ — `examples/`
 *
 * Quatro executáveis, declarados em `examples/CMakeLists.txt`:
 *
 * - `zupt_example_basic` (`example_basic.cpp`) — gera par de chaves com
 *   `zupt::KeyGenerator::generateKeyPair()`, cifra e decifra um trecho em
 *   memória com `zupt::Encryptor` / `zupt::Decryptor` e imprime
 *   `zupt::getVersion()`.
 * - `zupt_example_file` (`example_file.cpp`) — cifra e decifra um arquivo,
 *   carregando o par de chaves do disco com `loadKeyPair()`; trata as
 *   falhas com `catch (const zupt::ZuptError& e)`.
 * - `zupt_example_binary` (`example_binary.cpp`) — ida e volta de dados
 *   binários gerados localmente.
 * - `zupt_migrate` (`migrate_v1.cpp`) — converte material do formato
 *   antigo, usando `zupt::SecureBuffer` e `zupt::secureWipe` sobre a chave
 *   lida.
 *
 * Todos linkam `zupt_shared` nas plataformas UNIX e `zupt_static` em
 * Windows (`examples/CMakeLists.txt:3-7`) e são instalados no diretório
 * binário (`examples/CMakeLists.txt:32-33`). O bloco inteiro só é
 * adicionado ao build se `LIBZUPT_BUILD_EXAMPLES` estiver ligado, o que é o
 * padrão (`CMakeLists.txt:184`, `:196-198`).
 *
 * Existe um teste CTest para o migrador: `zupt_test_migration_cli` executa
 * `scripts/check-migration-cli.py` passando `zupt_example_file` e
 * `zupt_migrate`, e carrega a etiqueta `python`
 * (`examples/CMakeLists.txt:23-29`). Ele só aparece quando
 * `LIBZUPT_BUILD_TESTS` está ligado.
 *
 * @see @ref page-compilacao para os comandos de configuração.
 *
 * # Python — `examples_python/`
 *
 * Os cinco scripts (`example_basic.py`, `example_file.py`,
 * `example_keygen.py`, `example_random.py`, `example_secure_buffer.py`)
 * importam um único módulo, `import zupt`, que é a extensão pybind11
 * construída pelo alvo `zupt_python_bindings` com `OUTPUT_NAME zupt`
 * (`examples_python/CMakeLists.txt:6-7`). O registro acontece na macro
 * `PYBIND11_MODULE(zupt, m)` (`examples_python/zupt_pybind.cpp:78`), e o
 * alvo linka `zupt_shared`.
 *
 * Nada disso acontece por padrão: `LIBZUPT_BUILD_PYTHON` é `OFF`
 * (`CMakeLists.txt:185`) e o subdiretório só entra em `:200-202`. Quando
 * ligado, o `find_package(pybind11 CONFIG REQUIRED)` de
 * `examples_python/CMakeLists.txt:5` faz a configuração falhar se a
 * biblioteca pybind11 não estiver instalada.
 *
 * Ligado o option, aparece o teste CTest `zupt_test_python_binding`, que
 * roda `tests/python_binding.py` apontando para o diretório da extensão
 * (`examples_python/CMakeLists.txt:9-13`).
 *
 * # Node.js — `examples_nodejs/`
 *
 * O pacote `libzupt-examples` (versão `2.1.5` em `package.json`) tem
 * `gypfile: true` e scripts `install`/`build` que rodam
 * `node-gyp rebuild`. O alvo `zupt`, do tipo `loadable_module`
 * (`binding.gyp:4-5`), compila `src/zupt_napi.cpp`, os dois arquivos de
 * ponte e oito arquivos de `../src/` listados um a um
 * (`binding.gyp:6-19`): o addon não linka `libzupt`, ele recompila as
 * primitivas.
 *
 * Os dois arquivos de ponte, além disso, incluem um arquivo de código fonte
 * de texto: `examples_nodejs/src/zupt_crypto_c_bridge.c:41` traz
 * `../../src/zupt_crypto.c`, e
 * `examples_nodejs/src/zupt_crypto_cpp_bridge.cpp:51` traz
 * `../../src/zupt_crypto.cpp`. As duas traduções existem nos dois lugares —
 * na biblioteca e no addon —, cada uma com o seu conjunto de flags.
 *
 * `index.js` tenta carregar `build/Release/zupt.node`. Se o carregamento
 * falha, exporta uma implementação JavaScript de reserva que não faz
 * criptografia: `KeyGenerator::generateKeyPair`, `Encryptor::encryptMemory`
 * e `Decryptor::decryptMemory` lançam erro informando o motivo da falha, e
 * `getVersion()` devolve a string literal `'2.1.5'`. O teste do pacote,
 * `npm test`, roda `example_basic.js`.
 *
 * # Java — `examples_java/`
 *
 * O pacote `com.libzupt` tem as classes `SecureBuffer`, `KeyPair`,
 * `KeyGenerator`, `Encryptor`, `Decryptor`, `NativeLib` e `ZuptError`, mais
 * cinco executáveis de exemplo (`ExampleBasic`, `ExampleKeygen`,
 * `ExampleFile`, `ExampleRandom`, `ExampleSecureBuffer`).
 *
 * A ponte nativa é `zupt_jni.cpp`, compilada pelo alvo `zupt_jni`
 * (`examples_java/CMakeLists.txt:40`), que recebe `libzupt` de um
 * `find_package(libzupt 1.0.15 CONFIG)` ou, em alternativa, embute a árvore
 * local via `add_subdirectory` com as quatro opções de build desligadas
 * (`examples_java/CMakeLists.txt:8-33`). As classes nativas são registradas
 * em `JNI_OnLoad`: cinco para `KeyGenerator`, duas para `Encryptor`, duas
 * para `Decryptor` e três para `NativeLib`
 * (`examples_java/zupt_jni.cpp:523-541`). As chamadas nativas capturam
 * `const std::exception&` e traduzem a exceção C++ em erro JNI.
 *
 * Dois desajustes merecem nota. O alvo define `OUTPUT_NAME Jzupt` com
 * `PREFIX "lib"` (`examples_java/CMakeLists.txt:43`), produzindo
 * `libJzupt.so`, mas o `build.sh` do próprio diretório tenta copiar
 * `zupt.so` (`examples_java/build.sh:64`) com o erro suprimido; e ele testa
 * a existência de `libzupt.a`, nome que o `CMakeLists.txt` da biblioteca não
 * gera — o alvo estático se chama `zupt_static`.
 *
 * @see @ref page-limitacoes, seção das limitações por vínculo.
 */
