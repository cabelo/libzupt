/**
 * @cond PORT
 * @file  examples_nodejs/src/zupt_crypto_c_bridge.c
 * @brief Ponte de compilação: faz do TU `src/zupt_crypto.c` um objeto com nome
 * de arquivo diferente, para o node-gyp.
 * @details Este arquivo não contém código nem símbolos próprios: a única
 * instrução é a diretiva de inclusão de
 * `../../src/zupt_crypto.c`, o que faz
 * este TU ser o local de definição de todas as funções C do núcleo
 * criptográfico (CSPRNG, `zupt_secure_wipe`, AES-256, SHA-256,
 * SHA3-512/Keccak, ML-KEM-768, X25519, XXH e as funções híbridas de
 * mais alto nível).
 *
 * <b>Por que a ponte existe</b>: o `binding.gyp` deste exemplo lista
 * `src/zupt_crypto_c_bridge.c` e `src/zupt_crypto_cpp_bridge.cpp`
 * (que por sua vez inclui `../../src/zupt_crypto.cpp`) no lugar de
 * listar os arquivos do núcleo diretamente. Em `make`, o objeto
 * derivado de `zupt_crypto.c` e o derivado de `zupt_crypto.cpp`
 * compartilhariam o mesmo nome-base (`zupt_crypto.o`) no mesmo
 * diretório de saída, e a regra implícita de reconstrução passaria a
 * regenerar esse objeto a partir do `.cpp` mais novo. Nomes-base
 * distintos (`zupt_crypto_c_bridge` e `zupt_crypto_cpp_bridge`)
 * eliminam o choque.
 *
 * <b>Linkagem</b>: por ter extensão `.c`, este TU é compilado pelo
 * compilador C: os símbolos definidos aqui têm linkagem C. O TU
 * equivalente do lado C++ define suas entidades dentro de `namespace
 * zupt`, portanto não há definição duplicada de símbolo na linkagem do
 * addon `zupt.node`.
 *
 * <b>Recompilação em cascata</b>: qualquer mudança em
 * `src/zupt_crypto.c` força a recompilação deste TU inteiro (todas as
 * funções do núcleo), e não apenas do objeto do arquivo original.
 *
 * <b>Documentação</b>: as funções definidas por este TU estão
 * documentadas em `src/zupt_crypto.c` (arquivo incluído aqui). Este
 * arquivo de ponte não repete nem redefine nada, de propósito.
 * @endcond
 * @cond INGLES
 * @file  examples_nodejs/src/zupt_crypto_c_bridge.c
 * @brief Compilation bridge: turns the TU `src/zupt_crypto.c` into an object with a
 * different file name, for node-gyp.
 * @details This file contains no code and no symbols of its own: the only
 * instruction is the inclusion directive of
 * `../../src/zupt_crypto.c`, which makes
 * this TU the definition site of all the C functions of the cryptographic
 * core (CSPRNG, `zupt_secure_wipe`, AES-256, SHA-256,
 * SHA3-512/Keccak, ML-KEM-768, X25519, XXH and the
 * higher-level hybrid functions).
 *
 * <b>Why the bridge exists</b>: this example's `binding.gyp` lists
 * `src/zupt_crypto_c_bridge.c` and `src/zupt_crypto_cpp_bridge.cpp`
 * (which in turn includes `../../src/zupt_crypto.cpp`) instead of
 * listing the core files directly. Under `make`, the object
 * derived from `zupt_crypto.c` and the one derived from `zupt_crypto.cpp`
 * would share the same base name (`zupt_crypto.o`) in the same
 * output directory, and the implicit rebuild rule would start
 * regenerating that object from the newer `.cpp`. Distinct
 * base names (`zupt_crypto_c_bridge` and `zupt_crypto_cpp_bridge`)
 * eliminate the clash.
 *
 * <b>Linkage</b>: because it has a `.c` extension, this TU is compiled by
 * the C compiler: the symbols defined here have C linkage. The equivalent
 * TU on the C++ side defines its entities inside `namespace
 * zupt`, so there is no duplicated symbol definition in the linkage of the
 * `zupt.node` addon.
 *
 * <b>Cascading recompilation</b>: any change in
 * `src/zupt_crypto.c` forces recompilation of this entire TU (all the
 * core functions), and not only of the original file's object.
 *
 * <b>Documentation</b>: the functions defined by this TU are
 * documented in `src/zupt_crypto.c` (the file included here). This
 * bridge file deliberately repeats and redefines nothing.
 * @endcond */

/* Keep the C and C++ crypto translation units on distinct object basenames.
 * Otherwise make/node-gyp may rebuild zupt_crypto.o from the newer .cpp file. */
#include "../../src/zupt_crypto.c"
