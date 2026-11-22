/*
 * Bridge file for node-gyp.
 *
 * Both C and C++ crypto units use distinct bridge basenames, avoiding
 * node-gyp/make collisions between zupt_crypto.c and zupt_crypto.cpp.
 */

/**
 * @cond PORT
 * @file  examples_nodejs/src/zupt_crypto_cpp_bridge.cpp
 * @brief Ponte de compilação: faz do TU `src/zupt_crypto.cpp` um objeto com
 * nome de arquivo diferente, para o node-gyp.
 * @details Este arquivo não contém código nem símbolos próprios: a única
 * instrução é a diretiva de inclusão de `../../src/zupt_crypto.cpp`.
 * Por isso,
 * este TU passa a ser a definição de tudo o que
 * `include/zupt.hpp` declara em `namespace zupt`: os métodos de
 * `KeyGenerator`, `Encryptor` e `Decryptor`, além das funções
 * utilitárias `randomBytes`, `sha256` (duas assinaturas), `sha3_512`,
 * `secureWipe`, `getVersion` e `getLibraryName`.
 *
 * <b>Por que a ponte existe</b>: `make` derivaria `zupt_crypto.o` tanto
 * de `zupt_crypto.c` quanto de `zupt_crypto.cpp`. No mesmo diretório de
 * saída haveria um único arquivo objeto disputado pelas duas regras, e
 * a reconstrução pelo arquivo mais novo trocaria o conteúdo do objeto.
 * Nomes-base distintos (`zupt_crypto_cpp_bridge` aqui,
 * `zupt_crypto_c_bridge` no par C) separam os dois objetos.
 *
 * <b>Linkagem</b>: sendo `.cpp`, este TU é compilado pelo compilador C++
 * com `cflags_cc` do `binding.gyp` (`-std=c++17`, `-fPIC`,
 * `-fexceptions`, e as flags `-fno-exceptions` explícitamente
 * removidas por `cflags_cc!`). As entidades ficam em `namespace zupt` e
 * têm linkagem C++ mangled, o que não colide com os símbolos C
 * produzidos por `src/zupt_crypto_c_bridge.c`. As chamadas do lado C++
 * para o núcleo C passam pelo bloco `extern "C"` do próprio
 * `src/zupt_crypto.cpp`, que envolve os cabeçalhos `zupt.h`,
 * `zupt_mlkem.h`, `zupt_x25519.h` e `zupt_keccak.h`.
 *
 * <b>Exceções</b>: as rotinas C++ deste TU reportam falha lançando
 * `zupt::ZuptError` ou exceções da STL; por isso a habilitação de
 * exceções em tempo de compilação é parte do contrato do build, e não
 * do código.
 *
 * <b>Includes</b>: as diretivas de inclusão entre aspas feitas pelo
 * arquivo incluído são resolvidas pelos `include_dirs` do `binding.gyp`
 * (`../include` e `../src`), e não pelo diretório deste arquivo.
 *
 * <b>Documentação</b>: as entidades definidas por este TU estão
 * documentadas em `src/zupt_crypto.cpp`. Esta ponte não repete texto.
 * @endcond
 * @cond INGLES
 * @file  examples_nodejs/src/zupt_crypto_cpp_bridge.cpp
 * @brief Compilation bridge: turns the TU `src/zupt_crypto.cpp` into an object with
 * a different file name, for node-gyp.
 * @details This file contains no code and no symbols of its own: the only
 * instruction is the inclusion directive of `../../src/zupt_crypto.cpp`.
 * For this reason,
 * this TU becomes the definition of everything that
 * `include/zupt.hpp` declares in `namespace zupt`: the methods of
 * `KeyGenerator`, `Encryptor` and `Decryptor`, plus the utility
 * functions `randomBytes`, `sha256` (two signatures), `sha3_512`,
 * `secureWipe`, `getVersion` and `getLibraryName`.
 *
 * <b>Why the bridge exists</b>: `make` would derive `zupt_crypto.o` both
 * from `zupt_crypto.c` and from `zupt_crypto.cpp`. In the same output
 * directory there would be a single object file contested by the two rules, and
 * rebuilding by the newer file would replace the object's content.
 * Distinct base names (`zupt_crypto_cpp_bridge` here,
 * `zupt_crypto_c_bridge` in the C counterpart) separate the two objects.
 *
 * <b>Linkage</b>: being `.cpp`, this TU is compiled by the C++ compiler
 * with `cflags_cc` from `binding.gyp` (`-std=c++17`, `-fPIC`,
 * `-fexceptions`, and the `-fno-exceptions` flags explicitly
 * removed by `cflags_cc!`). The entities live in `namespace zupt` and
 * have mangled C++ linkage, which does not collide with the C symbols
 * produced by `src/zupt_crypto_c_bridge.c`. Calls from the C++ side
 * to the C core go through the `extern "C"` block of
 * `src/zupt_crypto.cpp` itself, which wraps the headers `zupt.h`,
 * `zupt_mlkem.h`, `zupt_x25519.h` and `zupt_keccak.h`.
 *
 * <b>Exceptions</b>: the C++ routines of this TU report failure by throwing
 * `zupt::ZuptError` or STL exceptions; therefore the enabling of
 * exceptions at compile time is part of the build contract, and not
 * of the code.
 *
 * <b>Includes</b>: the quoted inclusion directives made by the
 * included file are resolved by the `include_dirs` of `binding.gyp`
 * (`../include` and `../src`), and not by this file's directory.
 *
 * <b>Documentation</b>: the entities defined by this TU are
 * documented in `src/zupt_crypto.cpp`. This bridge does not repeat text.
 * @endcond */

#include "../../src/zupt_crypto.cpp"
