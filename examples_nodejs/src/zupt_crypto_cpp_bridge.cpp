/*
 * Bridge file for node-gyp.
 *
 * Both C and C++ crypto units use distinct bridge basenames, avoiding
 * node-gyp/make collisions between zupt_crypto.c and zupt_crypto.cpp.
 */

/**
 * @file  examples_nodejs/src/zupt_crypto_cpp_bridge.cpp
 * @brief Ponte de compilação: faz do TU `src/zupt_crypto.cpp` um objeto com
 *        nome de arquivo diferente, para o node-gyp.
 * @details Este arquivo não contém código nem símbolos próprios: a única
 *          instrução é a diretiva de inclusão de `../../src/zupt_crypto.cpp`.
 *          Por isso,
 *          este TU passa a ser a definição de tudo o que
 *          `include/zupt.hpp` declara em `namespace zupt`: os métodos de
 *          `KeyGenerator`, `Encryptor` e `Decryptor`, além das funções
 *          utilitárias `randomBytes`, `sha256` (duas assinaturas), `sha3_512`,
 *          `secureWipe`, `getVersion` e `getLibraryName`.
 *
 *          <b>Por que a ponte existe</b>: `make` derivaria `zupt_crypto.o` tanto
 *          de `zupt_crypto.c` quanto de `zupt_crypto.cpp`. No mesmo diretório de
 *          saída haveria um único arquivo objeto disputado pelas duas regras, e
 *          a reconstrução pelo arquivo mais novo trocaria o conteúdo do objeto.
 *          Nomes-base distintos (`zupt_crypto_cpp_bridge` aqui,
 *          `zupt_crypto_c_bridge` no par C) separam os dois objetos.
 *
 *          <b>Linkagem</b>: sendo `.cpp`, este TU é compilado pelo compilador C++
 *          com `cflags_cc` do `binding.gyp` (`-std=c++17`, `-fPIC`,
 *          `-fexceptions`, e as flags `-fno-exceptions` explícitamente
 *          removidas por `cflags_cc!`). As entidades ficam em `namespace zupt` e
 *          têm linkagem C++ mangled, o que não colide com os símbolos C
 *          produzidos por `src/zupt_crypto_c_bridge.c`. As chamadas do lado C++
 *          para o núcleo C passam pelo bloco `extern "C"` do próprio
 *          `src/zupt_crypto.cpp`, que envolve os cabeçalhos `zupt.h`,
 *          `zupt_mlkem.h`, `zupt_x25519.h` e `zupt_keccak.h`.
 *
 *          <b>Exceções</b>: as rotinas C++ deste TU reportam falha lançando
 *          `zupt::ZuptError` ou exceções da STL; por isso a habilitação de
 *          exceções em tempo de compilação é parte do contrato do build, e não
 *          do código.
 *
 *          <b>Includes</b>: as diretivas de inclusão entre aspas feitas pelo
 *          arquivo incluído são resolvidas pelos `include_dirs` do `binding.gyp`
 *          (`../include` e `../src`), e não pelo diretório deste arquivo.
 *
 *          <b>Documentação</b>: as entidades definidas por este TU estão
 *          documentadas em `src/zupt_crypto.cpp`. Esta ponte não repete texto.
 */

#include "../../src/zupt_crypto.cpp"
