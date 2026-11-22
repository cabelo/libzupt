/*
 * libzupt - Node.js N-API Binding
 * Hybrid Post-Quantum Encryption (ML-KEM-768 + X25519)
 *
 * SPDX-License-Identifier: MIT
 */

/**
 * @cond PORT
 * @file  examples_nodejs/src/zupt_napi.cpp
 * @brief Binding Node.js (N-API / node-addon-api) da camada C++ da libzupt.
 * @details Este TU expõe, como addon `zupt.node`, quatro classes JavaScript
 * (`SecureBuffer`, `KeyGenerator`, `Encryptor`, `Decryptor`) e duas
 * funções de módulo (`randomBytes`, `getVersion`). Cada classe é
 * implementada por uma classe wrapper C++ derivada de
 * `Napi::ObjectWrap`, que guarda a instância C++ correspondente num
 * `std::unique_ptr` membro.
 *
 * <b>Fronteira de tipos</b>: toda troca de bytes entre JavaScript e C++
 * usa `Napi::Uint8Array` (o que cobre `Buffer` e `Uint8Array`) na
 * entrada e `Napi::Buffer<uint8_t>` na saída via a função de cópia da
 * biblioteca N-API, que aloca o buffer na engine.
 * então o objeto JavaScript devolvido é independente dos vetores C++
 * locais; esses vetores morrem ao fim da chamada. Nenhum ponteiro da
 * pilha C++ é exposto ao JavaScript.
 *
 * <b>Erros</b>: o addon é compilado com `NAPI_CPP_EXCEPTIONS`
 * (`defines` do `binding.gyp`) e `-fexceptions`. As funções C++ de
 * `include/zupt.hpp` lançam `zupt::ZuptError` (derivada de
 * `std::runtime_error`); elas não são capturadas neste arquivo, exceto
 * onde há checagem explícita. O que o addon faz é lançar
 * `Napi::Error` ou `Napi::TypeError` para os poucos erros de uso da
 * fronteira que ele mesmo detecta (objeto destruído, argumento de tipo
 * errado). Uma exceção C++ que escape de `zupt::` atravessa a chamada
 * N-API e é convertida pela biblioteca node-addon-api em exceção
 * JavaScript.
 *
 * <b>Conversão numérica</b>: `napi_value` numérica vira `uint32_t`
 * (`Uint32Value`), que vira `size_t` na alocação C++. `Napi::Number`
 * aceita qualquer número JavaScript, incluindo negativos e não
 * inteiros, sem verificação de faixa neste arquivo (ver arquivo de
 * achados).
 *
 * <b>Uso concorrente</b>: as funções N-API executam na thread do event
 * loop do addon (nenhuma delas usa thread-safe function nem worker),
 * mas este arquivo não declara nem impede uso simultâneo de um mesmo
 * objeto wrapper por múltiplos contextos.
 *
 * <b>Fallback JavaScript</b>: `examples_nodejs/index.js` tenta carregar
 * este addon; se o load falhar, exporta uma implementação JS
 * alternativa que "não faz criptografia real". Este TU não tem
 * participação nesse comportamento.
 * @endcond
 * @cond INGLES
 * @file  examples_nodejs/src/zupt_napi.cpp
 * @brief Node.js binding (N-API / node-addon-api) of the C++ layer of libzupt.
 * @details This TU exposes, as the `zupt.node` addon, four JavaScript classes
 * (`SecureBuffer`, `KeyGenerator`, `Encryptor`, `Decryptor`) and two
 * module functions (`randomBytes`, `getVersion`). Each class is
 * implemented by a C++ wrapper class derived from
 * `Napi::ObjectWrap`, which holds the corresponding C++ instance in a
 * member `std::unique_ptr`.
 *
 * <b>Type boundary</b>: every byte exchange between JavaScript and C++
 * uses `Napi::Uint8Array` (which covers `Buffer` and `Uint8Array`) on
 * input and `Napi::Buffer<uint8_t>` on output, via the copy function of the
 * N-API library, which allocates the buffer in the engine.
 * so the JavaScript object returned is independent of the local C++
 * vectors; those vectors die at the end of the call. No pointer from the C++
 * stack is exposed to JavaScript.
 *
 * <b>Errors</b>: the addon is compiled with `NAPI_CPP_EXCEPTIONS`
 * (`defines` of `binding.gyp`) and `-fexceptions`. The C++ functions of
 * `include/zupt.hpp` throw `zupt::ZuptError` (derived from
 * `std::runtime_error`); they are not caught in this file, except
 * where there is an explicit check. What the addon does is throw
 * `Napi::Error` or `Napi::TypeError` for the few boundary use
 * errors that it detects itself (destroyed object, argument of the wrong
 * type). A C++ exception that escapes from `zupt::` crosses the N-API
 * call and is converted by the node-addon-api library into a JavaScript
 * exception.
 *
 * <b>Numeric conversion</b>: a numeric `napi_value` becomes `uint32_t`
 * (`Uint32Value`), which becomes `size_t` in the C++ allocation. `Napi::Number`
 * accepts any JavaScript number, including negative and
 * non-integer ones, with no range check in this file (see the findings
 * file).
 *
 * <b>Concurrent use</b>: the N-API functions run on the addon's event
 * loop thread (none of them uses a thread-safe function nor a worker),
 * but this file neither declares nor prevents simultaneous use of the same
 * wrapper object by multiple contexts.
 *
 * <b>JavaScript fallback</b>: `examples_nodejs/index.js` tries to load
 * this addon; if the load fails, it exports an alternative JS
 * implementation that "does not do real cryptography". This TU has
 * no part in that behavior.
 * @endcond */

/* Define NAPI_VERSION before including napi.h to ensure proper API selection */
#ifndef NAPI_VERSION
/**
 * @cond PORT
 * @def NAPI_VERSION
 * @brief Versão da API N-API exigida por este binding.
 * @details O valor 9 é a versão que este binding escolhe para a seleção de
 * símbolos de `napi.h`. A diretiva condicional permite que o build
 * defina uma versão diferente antes da inclusão, o que acontece quando
 * o ambiente de compilação já a definiu. O comentário acima do bloco
 * comentário acima do guarda de inclusão registra a razão do macro: `napi.h` escolhe o subconjunto
 * de símbolos de acordo com a versão definida no momento da inclusão.
 * Nenhum código deste arquivo depende de uma interface específica da
 * versão 9 que não exista em versões anteriores; a escolha é do
 * binding, não exigência observável daqui.
 * @endcond
 * @cond INGLES
 * @def NAPI_VERSION
 * @brief N-API API version required by this binding.
 * @details The value 9 is the version this binding chooses for the symbol
 * selection of `napi.h`. The conditional directive allows the build
 * to define a different version before inclusion, which happens when
 * the compilation environment has already defined it. The comment above the block
 * comment above the inclusion guard records the reason for the macro: `napi.h` picks the subset
 * of symbols according to the version defined at the moment of inclusion.
 * No code in this file depends on a version 9 specific interface
 * that does not exist in earlier versions; the choice is the
 * binding's, not an observable requirement from here.
 * @endcond */
#define NAPI_VERSION 9
#endif

#include <napi.h>
#include "../include/zupt.hpp"

/* Helper to convert napi_value to std::vector<uint8_t> */
/**
 * @cond PORT
 * @brief Converte um valor JavaScript em cópia de `std::vector<uint8_t>`.
 * @details Não há verificação do tipo do valor: o `As<Napi::Uint8Array>()` é
 * aplicado às cegas, o que só é seguro quando o chamador já confirmou
 * que o argumento é `Buffer` ou `Uint8Array`. Não há checagem de
 * `napi_is_arraybuffer`: um `ArrayBuffer` (sem view) produz resultado
 * indefinido pela própria biblioteca.
 * <b>Cópia</b>: o intervalo `[arr.Data(), arr.Data() +
 * arr.ByteLength())` é copiado para o vetor devolvido, portanto o
 * resultado é independente do buffer JavaScript de origem (muda no JS
 * não afeta o vetor, e vice-versa). Em caso de falha de alocação, o
 * construtor do vetor lança `std::bad_alloc`, que atravessa a chamada
 * N-API.
 * @note Nenhum dos chamadores deste arquivo usa esta função: os métodos que
 * precisam de dados de entrada fazem o `As<Napi::Uint8Array>()` e o
 * `memcpy` diretamente (ver arquivo de achados).
 * @param[in] value Valor JavaScript esperado como `Buffer` ou `Uint8Array`.
 * @return Vetor com os `ByteLength()` bytes do array de entrada.
 * @endcond
 * @cond INGLES
 * @brief Converts a JavaScript value into a copy of `std::vector<uint8_t>`.
 * @details There is no check of the type of the value: the `As<Napi::Uint8Array>()` is
 * applied blindly, which is only safe when the caller has already confirmed
 * that the argument is a `Buffer` or a `Uint8Array`. There is no check of
 * `napi_is_arraybuffer`: an `ArrayBuffer` (without a view) produces
 * undefined behavior in the library itself.
 * <b>Copy</b>: the range `[arr.Data(), arr.Data() +
 * arr.ByteLength())` is copied into the vector returned, so the
 * result is independent of the source JavaScript buffer (a change in the JS
 * does not affect the vector, and vice versa). In case of allocation failure, the
 * vector constructor throws `std::bad_alloc`, which crosses the N-API
 * call.
 * @note None of the callers in this file uses this function: the methods that
 * need input data do the `As<Napi::Uint8Array>()` and the
 * `memcpy` directly (see the findings file).
 * @param[in] value JavaScript value expected as a `Buffer` or `Uint8Array`.
 * @return Vector with the `ByteLength()` bytes of the input array.
 * @endcond */
static std::vector<uint8_t> GetBufferAsVector(const Napi::Value& value) {
    Napi::Uint8Array arr = value.As<Napi::Uint8Array>();
    return std::vector<uint8_t>(arr.Data(), arr.Data() + arr.ByteLength());
}

/* Helper to create a Buffer from vector */
/**
 * @cond PORT
 * @brief Cria um `Buffer` JavaScript copiando o conteúdo de um vetor C++.
 * @details a função de cópia de `Napi::Buffer` aloca o buffer no heap controlado
 * pela engine e copia `vec.size()` bytes de `vec.data()`. O buffer
 * resultante é independente do vetor: o vetor pode ser apagado ou
 * destruído sem afetar o objeto JavaScript.
 * <b>Buffer vazio</b>: com `vec.size() == 0` o resultado é um `Buffer`
 * de comprimento zero (a engine aceita `nullptr` quando o tamanho é
 * zero, o que é o caso para vetores vazios).
 * @param[in] env  Ambiente N-API da chamada em curso.
 * @param[in] vec  Conteúdo a copiar para o buffer JavaScript.
 * @return Objeto `Buffer` com os bytes de `vec`.
 * @endcond
 * @cond INGLES
 * @brief Creates a JavaScript `Buffer` by copying the content of a C++ vector.
 * @details The copy function of `Napi::Buffer` allocates the buffer on the heap controlled
 * by the engine and copies `vec.size()` bytes from `vec.data()`. The
 * resulting buffer is independent of the vector: the vector can be cleared or
 * destroyed without affecting the JavaScript object.
 * <b>Empty buffer</b>: with `vec.size() == 0` the result is a `Buffer`
 * of zero length (the engine accepts `nullptr` when the size is
 * zero, which is the case for empty vectors).
 * @param[in] env  N-API environment of the ongoing call.
 * @param[in] vec  Content to copy into the JavaScript buffer.
 * @return `Buffer` object with the bytes of `vec`.
 * @endcond */
static Napi::Value CreateBufferFromVector(Napi::Env env, const std::vector<uint8_t>& vec) {
    return Napi::Buffer<uint8_t>::Copy(env, vec.data(), vec.size());
}

/* ═══════════════════════════════════════════════════════════════════
 * SECURE BUFFER WRAPPER
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * @cond PORT
 * @class SecureBufferWrapper
 * @brief Wrapper N-API de `zupt::SecureBuffer`.
 * @details Em JavaScript o objeto é chamado `SecureBuffer` (nome registrado em
 * \ref SecureBufferWrapper::Init). O conteúdo do buffer fica
 * exclusivamente no objeto C++ apontado por `buffer_`; JavaScript vê
 * apenas métodos e acessores.
 * <b>Estado "destruído"</b>: o método `destroy` libera o `unique_ptr`, e o
 * objeto JavaScript continua vivo, porém vazio. A partir desse ponto:
 * `copy()` e `toBuffer()` lançam `Napi::Error`; `zeroize()`, `size` e
 * `dataLength` toleram o estado e devolvem `undefined`/`0`. Não há
 * transição de volta ao estado ativo.
 * <b>Conversão de memória</b>: nenhuma operação deste wrapper devolve
 * ponteiro interno ao JavaScript. `toBuffer()` copia o conteúdo via
 * `toVector()` intermediário e depois por `Napi::Buffer::Copy`, ou
 * seja, o texto em claro chega a existir em três lugares durante a
 * chamada (buffer C++, `std::vector` local, `Buffer` JS). Os dois
 * primeiros morrem com a chamada; o `Buffer` JS não é auto-apagável.
 * \note `zupt::SecureBuffer` não bloqueia memória (não chama `mlock`),
 * então o nome "SecureBuffer" não implica proteção contra swap.
 * \see include/zupt.hpp (classe `zupt::SecureBuffer`)
 * @endcond
 * @cond INGLES
 * @class SecureBufferWrapper
 * @brief N-API wrapper of `zupt::SecureBuffer`.
 * @details In JavaScript the object is called `SecureBuffer` (the name registered in
 * \ref SecureBufferWrapper::Init). The content of the buffer stays
 * exclusively in the C++ object pointed to by `buffer_`; JavaScript sees
 * only methods and accessors.
 * <b>"Destroyed" state</b>: the `destroy` method releases the `unique_ptr`, and the
 * JavaScript object stays alive, but empty. From that point on:
 * `copy()` and `toBuffer()` throw `Napi::Error`; `zeroize()`, `size` and
 * `dataLength` tolerate the state and return `undefined`/`0`. There is no
 * transition back to the active state.
 * <b>Memory conversion</b>: no operation of this wrapper returns an
 * internal pointer to JavaScript. `toBuffer()` copies the content via an
 * intermediate `toVector()` and then through `Napi::Buffer::Copy`,
 * that is, the plaintext comes to exist in three places during the
 * call (C++ buffer, local `std::vector`, JS `Buffer`). The first
 * two die with the call; the JS `Buffer` is not self-wiping.
 * \note `zupt::SecureBuffer` does not lock memory (it does not call `mlock`),
 * so the name "SecureBuffer" does not imply protection against swap.
 * \see include/zupt.hpp (class `zupt::SecureBuffer`)
 * @endcond */
class SecureBufferWrapper : public Napi::ObjectWrap<SecureBufferWrapper> {
public:
    /**
     * @cond PORT
     * @brief Registra a classe `SecureBuffer` e seus métodos no objeto de
     * exports do módulo.
     * @details `DefineClass` cria o construtor JavaScript e associa os métodos
     * de instância `copy`, `zeroize`, `toBuffer`, `destroy` e os
     * acessores `size` e `dataLength` (somente getter — o setter é
     * `nullptr`, então escrever em `size` gera erro do lado JS).
     * Ao final, `exports.SecureBuffer` aponta para o construtor.
     * @param[in]     env     Ambiente da chamada de inicialização.
     * @param[in,out] exports Objeto de exports do módulo; recebe a propriedade
     * `SecureBuffer`.
     * @return O mesmo `exports` recebido, já com a classe registrada.
     * @endcond
     * @cond INGLES
     * @brief Registers the `SecureBuffer` class and its methods in the module's
     * exports object.
     * @details `DefineClass` creates the JavaScript constructor and associates the
     * instance methods `copy`, `zeroize`, `toBuffer`, `destroy` and the
     * accessors `size` and `dataLength` (getter only — the setter is
     * `nullptr`, so writing to `size` raises an error on the JS side).
     * At the end, `exports.SecureBuffer` points to the constructor.
     * @param[in]     env     Environment of the initialization call.
     * @param[in,out] exports Module exports object; receives the property
     * `SecureBuffer`.
     * @return The same `exports` received, already with the class registered.
     * @endcond */
    static Napi::Object Init(Napi::Env env, Napi::Object exports);

    /**
     * @cond PORT
     * @brief Constrói o wrapper a partir do argumento de `new SecureBuffer(n)`.
     * @details Converte o primeiro argumento para `uint32_t` e constrói o
     * `zupt::SecureBuffer` correspondente. Não há checagem do tipo nem
     * da presença do argumento: `new SecureBuffer()` produz
     * `Uint32Value()` sobre `undefined`, e `undefined` não é número —
     * o comportamento depende da conversão da biblioteca (lança
     * `Error` de conversão). Números negativos e não inteiros são
     * truncados para `uint32_t`.
     * Falha de alocação no `make_unique` lança `std::bad_alloc`, que
     * não é convertida explicitamente aqui.
     * @param[in] info Metadados da chamada de construtor. `info[0]` é o tamanho
     * em bytes pedido.
     * @pre `info.Length() >= 1` e `info[0]` é um número (não verificado).
     * @endcond
     * @cond INGLES
     * @brief Builds the wrapper from the argument of `new SecureBuffer(n)`.
     * @details Converts the first argument to `uint32_t` and builds the
     * corresponding `zupt::SecureBuffer`. There is no check of the type nor
     * of the presence of the argument: `new SecureBuffer()` produces
     * `Uint32Value()` over `undefined`, and `undefined` is not a number —
     * the behavior depends on the library's conversion (it throws
     * a conversion `Error`). Negative and non-integer numbers are
     * truncated to `uint32_t`.
     * Allocation failure in `make_unique` throws `std::bad_alloc`, which
     * is not explicitly converted here.
     * @param[in] info Metadata of the constructor call. `info[0]` is the requested
     * size in bytes.
     * @pre `info.Length() >= 1` and `info[0]` is a number (not verified).
     * @endcond */
    SecureBufferWrapper(const Napi::CallbackInfo& info);

    /**
     * @cond PORT
     * @brief Destrutor padrão.
     * @details O zerado do conteúdo é feito pelo destructor de
     * `zupt::SecureBuffer` quando `buffer_` é destruído. Se `destroy()`
     * já tiver sido chamado, não há o que apagar.
     * @endcond
     * @cond INGLES
     * @brief Default destructor.
     * @details The zeroing of the content is done by the destructor of
     * `zupt::SecureBuffer` when `buffer_` is destroyed. If `destroy()`
     * has already been called, there is nothing to erase.
     * @endcond */
    ~SecureBufferWrapper();

private:
    /**
     * @cond PORT
     * @brief `copy(buf)`: copia os bytes de `buf` para o buffer interno.
     * @details Valida, nesta ordem: (1) se o objeto não foi destruído; (2) se
     * `info[0]` existe e é um `TypedArray`. Depois calcula
     * `copyLen = min(inputLen, bufferLen)` e faz um `memcpy` de
     * `copyLen` bytes do buffer JavaScript para `buffer_->data()`.
     * <b>Truncação silenciosa</b>: entrada maior que o buffer interno
     * tem o excedente descartado sem aviso; entrada menor deixa o
     * restante do buffer com o conteúdo anterior (a alocação inicial
     * não zera o buffer).
     * \note `data()` pode ser `nullptr` se o objeto tiver sido movido;
     * aqui isso não ocorre, pois o wrapper nunca é movido.
     * @param[in] info Metadados da chamada. `info[0]` é o `Buffer` ou
     * `Uint8Array` de origem.
     * @return Número com a quantidade de bytes efetivamente copiados
     * (`copyLen`), o que permite ao chamador detectar truncamento.
     * @exception Napi::Error quando o objeto foi destruído.
     * @exception Napi::TypeError quando `info[0]` está ausente ou não é
     * `TypedArray`.
     * @endcond
     * @cond INGLES
     * @brief `copy(buf)`: copies the bytes of `buf` into the internal buffer.
     * @details Validates, in this order: (1) whether the object has not been destroyed; (2) whether
     * `info[0]` exists and is a `TypedArray`. Then it computes
     * `copyLen = min(inputLen, bufferLen)` and does a `memcpy` of
     * `copyLen` bytes from the JavaScript buffer into `buffer_->data()`.
     * <b>Silent truncation</b>: input larger than the internal buffer
     * has its excess discarded without warning; smaller input leaves the
     * remainder of the buffer with the previous content (the initial allocation
     * does not zero the buffer).
     * \note `data()` can be `nullptr` if the object has been moved;
     * here that does not occur, because the wrapper is never moved.
     * @param[in] info Metadata of the call. `info[0]` is the source `Buffer` or
     * `Uint8Array`.
     * @return Number with the amount of bytes actually copied
     * (`copyLen`), which lets the caller detect truncation.
     * @exception Napi::Error when the object has been destroyed.
     * @exception Napi::TypeError when `info[0]` is missing or is not a
     * `TypedArray`.
     * @endcond */
    Napi::Value Copy(const Napi::CallbackInfo& info);

    /**
     * @cond PORT
     * @brief `zeroize()`: zera o conteúdo do buffer interno.
     * @details Delega a `zupt::SecureBuffer::zeroize()`, que usa `secureWipe`
     * (escrita via `volatile`, sem otimização). Se o objeto foi
     * destruído (`buffer_ == nullptr`), a chamada é um no-op e não
     * lança.
     * @param[in] info Metadados da chamada. Nenhum argumento é lido.
     * @return `undefined`.
     * @endcond
     * @cond INGLES
     * @brief `zeroize()`: zeroes the content of the internal buffer.
     * @details Delegates to `zupt::SecureBuffer::zeroize()`, which uses `secureWipe`
     * (write via `volatile`, without optimization). If the object has been
     * destroyed (`buffer_ == nullptr`), the call is a no-op and does not
     * throw.
     * @param[in] info Metadata of the call. No argument is read.
     * @return `undefined`.
     * @endcond */
    Napi::Value Zeroize(const Napi::CallbackInfo& info);

    /**
     * @cond PORT
     * @brief `toBuffer()`: devolve uma cópia do conteúdo como `Buffer`.
     * @details Passa por `toVector()` (cópia 1) e `Napi::Buffer::Copy`
     * (cópia 2). O `Buffer` devolvido não é apagado quando morre,
     * então o texto em claro pode persistir em memória mesmo depois de
     * `zeroize()` ou `destroy()` do objeto de origem.
     * @param[in] info Metadados da chamada. Nenhum argumento é lido.
     * @return `Buffer` com os `size()` bytes do buffer interno.
     * @exception Napi::Error quando o objeto foi destruído.
     * @endcond
     * @cond INGLES
     * @brief `toBuffer()`: returns a copy of the content as a `Buffer`.
     * @details Goes through `toVector()` (copy 1) and `Napi::Buffer::Copy`
     * (copy 2). The `Buffer` returned is not wiped when it dies,
     * so the plaintext can persist in memory even after
     * `zeroize()` or `destroy()` of the source object.
     * @param[in] info Metadata of the call. No argument is read.
     * @return `Buffer` with the `size()` bytes of the internal buffer.
     * @exception Napi::Error when the object has been destroyed.
     * @endcond */
    Napi::Value ToBuffer(const Napi::CallbackInfo& info);

    /**
     * @cond PORT
     * @brief `destroy()`: libera o buffer interno imediatamente.
     * @details `buffer_.reset()` destrói o `zupt::SecureBuffer`, que zera o
     * conteúdo antes de liberar a memória. O objeto JavaScript
     * permanece existindo, mas entra no estado "destruído" descrito na
     * classe. Chamada repetida é inofensiva (`reset()` sobre pointer
     * já nulo é no-op).
     * @param[in] info Metadados da chamada. Nenhum argumento é lido.
     * @return `undefined`.
     * @endcond
     * @cond INGLES
     * @brief `destroy()`: releases the internal buffer immediately.
     * @details `buffer_.reset()` destroys the `zupt::SecureBuffer`, which zeroes the
     * content before releasing the memory. The JavaScript object
     * keeps existing, but enters the "destroyed" state described in the
     * class. A repeated call is harmless (`reset()` over an
     * already null pointer is a no-op).
     * @param[in] info Metadata of the call. No argument is read.
     * @return `undefined`.
     * @endcond */
    Napi::Value Destroy(const Napi::CallbackInfo& info);

    /**
     * @cond PORT
     * @brief Getter do acessor `size`.
     * @details Devolve `buffer_->size()`. Quando o objeto foi destruído, devolve
     * `0` em vez de lançar.
     * @param[in] info Metadados da chamada. Nenhum argumento é lido.
     * @return Número com o tamanho em bytes do buffer, ou `0`.
     * @endcond
     * @cond INGLES
     * @brief Getter of the `size` accessor.
     * @details Returns `buffer_->size()`. When the object has been destroyed, it returns
     * `0` instead of throwing.
     * @param[in] info Metadata of the call. No argument is read.
     * @return Number with the size of the buffer in bytes, or `0`.
     * @endcond */
    Napi::Value GetSize(const Napi::CallbackInfo& info);

    /**
     * @cond PORT
     * @brief Getter do acessor `dataLength`.
     * @details O corpo é idêntico ao de \ref GetSize: devolve
     * `buffer_->size()`, ou `0` se o objeto foi destruído. Não há, no
     * lado C++, o conceito de "bytes usados" distinto da capacidade —
     * `zupt::SecureBuffer` tem tamanho fixo. Os dois acessores, portanto
     * sempre devolvem o mesmo número.
     * \warning Redundância: `size` e `dataLength` são indistinguíveis
     * pelo comportamento (ver arquivo de achados).
     * @param[in] info Metadados da chamada. Nenhum argumento é lido.
     * @return Número com o tamanho em bytes do buffer, ou `0`.
     * @see GetSize
     * @endcond
     * @cond INGLES
     * @brief Getter of the `dataLength` accessor.
     * @details The body is identical to that of \ref GetSize — it returns
     * `buffer_->size()`, or `0` if the object has been destroyed. On the C++ side
     * there is no concept of "bytes used" distinct from the capacity —
     * `zupt::SecureBuffer` has a fixed size. The two accessors, therefore,
     * always return the same number.
     * \warning Redundancy: `size` and `dataLength` are indistinguishable
     * by behavior (see the findings file).
     * @param[in] info Metadata of the call. No argument is read.
     * @return Number with the size of the buffer in bytes, or `0`.
     * @see GetSize
     * @endcond */
    Napi::Value GetDataLength(const Napi::CallbackInfo& info);

    /**
     * @cond PORT
     * Buffer C++ subjacente; `nullptr` após `destroy()`.
     * @endcond
     * @cond INGLES
     * Underlying C++ buffer; `nullptr` after `destroy()`.
     * @endcond */
    std::unique_ptr<zupt::SecureBuffer> buffer_;
};

Napi::Object SecureBufferWrapper::Init(Napi::Env env, Napi::Object exports) {
    Napi::Function ctor = Napi::ObjectWrap<SecureBufferWrapper>::DefineClass(env, "SecureBuffer", {
        Napi::ObjectWrap<SecureBufferWrapper>::InstanceMethod("copy", &SecureBufferWrapper::Copy),
        Napi::ObjectWrap<SecureBufferWrapper>::InstanceMethod("zeroize", &SecureBufferWrapper::Zeroize),
        Napi::ObjectWrap<SecureBufferWrapper>::InstanceMethod("toBuffer", &SecureBufferWrapper::ToBuffer),
        Napi::ObjectWrap<SecureBufferWrapper>::InstanceMethod("destroy", &SecureBufferWrapper::Destroy),
        Napi::ObjectWrap<SecureBufferWrapper>::InstanceAccessor("size",
            &SecureBufferWrapper::GetSize,
            nullptr),
        Napi::ObjectWrap<SecureBufferWrapper>::InstanceAccessor("dataLength",
            &SecureBufferWrapper::GetDataLength,
            nullptr)
    });

    exports.Set("SecureBuffer", ctor);
    return exports;
}

SecureBufferWrapper::SecureBufferWrapper(const Napi::CallbackInfo& info) : Napi::ObjectWrap<SecureBufferWrapper>(info) {
    uint32_t size = info[0].As<Napi::Number>().Uint32Value();
    buffer_ = std::make_unique<zupt::SecureBuffer>(size);
}

SecureBufferWrapper::~SecureBufferWrapper() = default;

Napi::Value SecureBufferWrapper::Copy(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (!buffer_) {
        throw Napi::Error::New(env, "SecureBuffer has been destroyed");
    }

    if (info.Length() < 1 || !info[0].IsTypedArray()) {
        throw Napi::TypeError::New(env, "copy() expects a Buffer or Uint8Array");
    }

    Napi::Uint8Array input = info[0].As<Napi::Uint8Array>();
    size_t inputLen = input.ByteLength();
    size_t bufferLen = buffer_->size();
    size_t copyLen = inputLen < bufferLen ? inputLen : bufferLen;

    if (copyLen > 0) {
        memcpy(buffer_->data(), input.Data(), copyLen);
    }

    return Napi::Number::New(env, copyLen);
}

Napi::Value SecureBufferWrapper::Zeroize(const Napi::CallbackInfo& info) {
    if (buffer_) {
        buffer_->zeroize();
    }
    return info.Env().Undefined();
}

Napi::Value SecureBufferWrapper::ToBuffer(const Napi::CallbackInfo& info) {
    if (!buffer_) {
        throw Napi::Error::New(info.Env(), "SecureBuffer has been destroyed");
    }
    std::vector<uint8_t> data = buffer_->toVector();
    return Napi::Buffer<uint8_t>::Copy(info.Env(), data.data(), data.size());
}

Napi::Value SecureBufferWrapper::Destroy(const Napi::CallbackInfo& info) {
    buffer_.reset();
    return info.Env().Undefined();
}

Napi::Value SecureBufferWrapper::GetSize(const Napi::CallbackInfo& info) {
    if (buffer_) {
        return Napi::Number::New(info.Env(), buffer_->size());
    }
    return Napi::Number::New(info.Env(), 0);
}

Napi::Value SecureBufferWrapper::GetDataLength(const Napi::CallbackInfo& info) {
    if (buffer_) {
        return Napi::Number::New(info.Env(), buffer_->size());
    }
    return Napi::Number::New(info.Env(), 0);
}

/* ═══════════════════════════════════════════════════════════════════
 * KEY GENERATOR WRAPPER
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * @cond PORT
 * @class KeyGeneratorWrapper
 * @brief Envolve `zupt::KeyGenerator` e expõe a classe JS `KeyGenerator`.
 * @details Deriva de `Napi::ObjectWrap`, o que garante a semântica de
 * `new KeyGenerator()` em JavaScript. Todas as chamadas são síncronas:
 * exceptions C++ lançadas por libzupt se propagam (a build usa
 * `NAPI_CPP_EXCEPTIONS`) e o N-API as converte em exceção JavaScript.
 * Nenhum método usa `Napi::HandleScope`/`EscapableHandleScope` — o
 * wrapper conta com o scope automático do N-API.
 * \warning As chaves privadas ficam vivas em JavaScript como objetos
 * `Buffer`, que são gerenciados pelo coletor de lixo do V8 e nunca
 * são zerados por este código. Ao terminar de usar uma keypair,
 * chame `zeroize()` no `SecureBuffer` correspondente, quando existir.
 * @endcond
 * @cond INGLES
 * @class KeyGeneratorWrapper
 * @brief Wraps `zupt::KeyGenerator` and exposes the JS class `KeyGenerator`.
 * @details It derives from `Napi::ObjectWrap`, which guarantees the semantics of
 * `new KeyGenerator()` in JavaScript. All calls are synchronous:
 * C++ exceptions thrown by libzupt propagate (the build uses
 * `NAPI_CPP_EXCEPTIONS`) and the N-API converts them into a JavaScript exception.
 * No method uses `Napi::HandleScope`/`EscapableHandleScope` — the
 * wrapper relies on the automatic scope of the N-API.
 * \warning The private keys stay alive in JavaScript as
 * `Buffer` objects, which are managed by the V8 garbage collector and are never
 * zeroed by this code. When finished using a keypair,
 * call `zeroize()` on the corresponding `SecureBuffer`, when it exists.
 * @endcond */
class KeyGeneratorWrapper : public Napi::ObjectWrap<KeyGeneratorWrapper> {
public:
    /**
     * @cond PORT
     * @brief Registra a classe `KeyGenerator` nas exportações do módulo.
     * @details Usa `DefineClass` e anexa o construtor como propriedade
     * `KeyGenerator` de \p exports.
     * @param[in]     env     Ambiente N-API.
     * @param[in,out] exports Objeto de exportações enriquecido.
     * @return O próprio objeto \p exports.
     * @see SecureBufferWrapper::Init
     * @endcond
     * @cond INGLES
     * @brief Registers the `KeyGenerator` class in the module exports.
     * @details Uses `DefineClass` and attaches the constructor as the
     * `KeyGenerator` property of \p exports.
     * @param[in]     env     N-API environment.
     * @param[in,out] exports Enriched exports object.
     * @return The \p exports object itself.
     * @see SecureBufferWrapper::Init
     * @endcond */
    static Napi::Object Init(Napi::Env env, Napi::Object exports);

    /**
     * @cond PORT
     * @brief Construtor chamado por `new KeyGenerator()`.
     * @details Cria o objeto C++ subjacente; nenhum argumento de JavaScript é
     * lido. O construtor base `Napi::ObjectWrap` associa a instância JS
     * à instância C++, e o N-API cuida do destrutor quando o objeto é
     * coletado.
     * @param[in] info Metadados da chamada de construção.
     * @endcond
     * @cond INGLES
     * @brief Constructor called by `new KeyGenerator()`.
     * @details Creates the underlying C++ object; no JavaScript argument is
     * read. The base constructor `Napi::ObjectWrap` associates the JS instance
     * with the C++ instance, and the N-API takes care of the destructor when the object is
     * collected.
     * @param[in] info Metadata of the construction call.
     * @endcond */
    KeyGeneratorWrapper(const Napi::CallbackInfo& info);

    /**
     * @cond PORT
     * @brief Destrutor padrão.
     * @details `keyGen_` é liberado pelo `std::unique_ptr`; não há limpeza
     * explícita de material chave adicional.
     * @endcond
     * @cond INGLES
     * @brief Default destructor.
     * @details `keyGen_` is released by the `std::unique_ptr`; there is no explicit
     * cleanup of additional key material.
     * @endcond */
    ~KeyGeneratorWrapper();

private:
    /**
     * @cond PORT
     * @brief Implementa `generateKeyPair()`.
     * @details Delega para `zupt::KeyGenerator::generateKeyPair()` e devolve um
     * objeto JS `{ publicKey: Buffer, secretKey: Buffer }`. Depois de
     * copiar os vetores para os Buffers, zera os dados originais com
     * `zupt::secureWipe`.
     * \warning `secureWipe` é aplicado ao membro `zupt::KeyPair` local;
     * os Buffers entregues ao JavaScript permanecem com o material em
     * claro e nunca são zerados.
     * @param[in] info Metadados da chamada. Nenhum argumento é lido.
     * @return Objeto JS com as propriedades `publicKey` e `secretKey`.
     * @endcond
     * @cond INGLES
     * @brief Implements `generateKeyPair()`.
     * @details Delegates to `zupt::KeyGenerator::generateKeyPair()` and returns a JS
     * object `{ publicKey: Buffer, secretKey: Buffer }`. After
     * copying the vectors into the Buffers, it zeroes the original data with
     * `zupt::secureWipe`.
     * \warning `secureWipe` is applied to the local `zupt::KeyPair` member;
     * the Buffers delivered to JavaScript keep the material in
     * plaintext and are never zeroed.
     * @param[in] info Metadata of the call. No argument is read.
     * @return JS object with the `publicKey` and `secretKey` properties.
     * @endcond */
    Napi::Value GenerateKeyPair(const Napi::CallbackInfo& info);

    /**
     * @cond PORT
     * @brief Implementa `saveKeyPair(keypair, filename)`.
     * @details Lê `keypair.publicKey` e `keypair.secretKey` (esperando TypedArray)
     * para vetores locais, monta um `zupt::KeyPair` e o persiste via
     * `zupt::KeyGenerator::saveKeyPair`. Zera os vetores ao final.
     * \warning Nenhum verificador é aplicado: `info[0]`/`info[1]` são
     * assumidos objeto/string, e cada propriedade é assumida TypedArray.
     * Valores de outro tipo disparam `napi_fatal_error` no runtime.
     * \warning O caminho do arquivo vem diretamente do chamador, sem
     * validação.
     * @param[in] info Argumentos: `[0]` objeto keypair, `[1]` string do caminho.
     * @return `undefined`.
     * @endcond
     * @cond INGLES
     * @brief Implements `saveKeyPair(keypair, filename)`.
     * @details Reads `keypair.publicKey` and `keypair.secretKey` (expecting TypedArrays)
     * into local vectors, builds a `zupt::KeyPair` and persists it via
     * `zupt::KeyGenerator::saveKeyPair`. Zeroes the vectors at the end.
     * \warning No checker is applied: `info[0]`/`info[1]` are
     * assumed to be object/string, and each property is assumed to be a TypedArray.
     * Values of another type trigger `napi_fatal_error` in the runtime.
     * \warning The file path comes directly from the caller, without
     * validation.
     * @param[in] info Arguments: `[0]` keypair object, `[1]` path string.
     * @return `undefined`.
     * @endcond */
    Napi::Value SaveKeyPair(const Napi::CallbackInfo& info);

    /**
     * @cond PORT
     * @brief Implementa `loadKeyPair(filename)`.
     * @details Lê a keypair do arquivo indicado e a devolve como objeto JS com
     * as chaves em Buffers (`Buffer::Copy`, ou seja, cópias).
     * \warning inconsistência: ao contrário de `GenerateKeyPair`, o
     * `zupt::KeyPair` local não é passado por `zupt::secureWipe`, de
     * modo que a chave privada em claro fica no heap do processo até a
     * destruição do objeto local.
     * @param[in] info Argumentos: `[0]` string do caminho.
     * @return Objeto JS `{ publicKey, secretKey }`.
     * @endcond
     * @cond INGLES
     * @brief Implements `loadKeyPair(filename)`.
     * @details Reads the keypair from the indicated file and returns it as a JS object with
     * the keys in Buffers (`Buffer::Copy`, that is, copies).
     * \warning inconsistency: unlike `GenerateKeyPair`, the
     * local `zupt::KeyPair` is not passed through `zupt::secureWipe`, so
     * the private key in plaintext stays on the process heap until the
     * destruction of the local object.
     * @param[in] info Arguments: `[0]` path string.
     * @return JS object `{ publicKey, secretKey }`.
     * @endcond */
    Napi::Value LoadKeyPair(const Napi::CallbackInfo& info);

    /**
     * @cond PORT
     * @brief Implementa `exportPublicKey(privFile, pubFile)`.
     * @details Lê a keypair salva em \c privfile e escreve a chave pública em
     * `pubfile`, delegando a
     * `zupt::KeyGenerator::exportPublicKey(privfile, pubfile)`.
     * \warning Os dois caminhos vêm diretamente do chamador, sem
     * validação, e sobrescrevem o destino sem aviso.
     * @param[in] info Argumentos: `[0]` string do arquivo privado, `[1]` string
     * do arquivo público de saída.
     * @return `undefined`.
     * @endcond
     * @cond INGLES
     * @brief Implements `exportPublicKey(privFile, pubFile)`.
     * @details Reads the keypair saved in \c privfile and writes the public key to
     * `pubfile`, delegating to
     * `zupt::KeyGenerator::exportPublicKey(privfile, pubfile)`.
     * \warning The two paths come directly from the caller, without
     * validation, and overwrite the destination without warning.
     * @param[in] info Arguments: `[0]` private file string, `[1]` output
     * public file string.
     * @return `undefined`.
     * @endcond */
    Napi::Value ExportPublicKey(const Napi::CallbackInfo& info);

    /**
     * @cond PORT
     * @brief Implementa `loadPublicKey(filename)`.
     * @details Lê a chave pública do arquivo indicado e a devolve como `Buffer`
     * JS. O wrapper C++ não guarda a chave pública carregada: o retorno
     * serve para o chamador construí-lo um `Encryptor`.
     * @param[in] info Argumentos: `[0]` string do caminho.
     * @return `Buffer` com a chave pública lida.
     * @endcond
     * @cond INGLES
     * @brief Implements `loadPublicKey(filename)`.
     * @details Reads the public key from the indicated file and returns it as a JS `Buffer`. The C++ wrapper
     * does not keep the loaded public key: the return value lets the caller build
     * an `Encryptor`.
     * @param[in] info Arguments: `[0]` path string.
     * @return `Buffer` with the public key read.
     * @endcond */
    Napi::Value LoadPublicKey(const Napi::CallbackInfo& info);

    /**
     * @cond PORT
     * Gerador C++ subjacente.
     * @endcond
     * @cond INGLES
     * Underlying C++ generator.
     * @endcond */
    std::unique_ptr<zupt::KeyGenerator> keyGen_;
};

Napi::Object KeyGeneratorWrapper::Init(Napi::Env env, Napi::Object exports) {
    Napi::Function ctor = Napi::ObjectWrap<KeyGeneratorWrapper>::DefineClass(env, "KeyGenerator", {
        Napi::ObjectWrap<KeyGeneratorWrapper>::InstanceMethod("generateKeyPair", &KeyGeneratorWrapper::GenerateKeyPair),
        Napi::ObjectWrap<KeyGeneratorWrapper>::InstanceMethod("saveKeyPair", &KeyGeneratorWrapper::SaveKeyPair),
        Napi::ObjectWrap<KeyGeneratorWrapper>::InstanceMethod("loadKeyPair", &KeyGeneratorWrapper::LoadKeyPair),
        Napi::ObjectWrap<KeyGeneratorWrapper>::InstanceMethod("exportPublicKey", &KeyGeneratorWrapper::ExportPublicKey),
        Napi::ObjectWrap<KeyGeneratorWrapper>::InstanceMethod("loadPublicKey", &KeyGeneratorWrapper::LoadPublicKey)
    });

    exports.Set("KeyGenerator", ctor);
    return exports;
}

KeyGeneratorWrapper::KeyGeneratorWrapper(const Napi::CallbackInfo& info) : Napi::ObjectWrap<KeyGeneratorWrapper>(info) {
    keyGen_ = std::make_unique<zupt::KeyGenerator>();
}

KeyGeneratorWrapper::~KeyGeneratorWrapper() = default;

Napi::Value KeyGeneratorWrapper::GenerateKeyPair(const Napi::CallbackInfo& info) {
    if (!keyGen_) {
        throw Napi::Error::New(info.Env(), "KeyGenerator has been destroyed");
    }

    zupt::KeyPair kp = keyGen_->generateKeyPair();

    Napi::Object result = Napi::Object::New(info.Env());
    result.Set("publicKey", Napi::Buffer<uint8_t>::Copy(info.Env(), kp.public_key.data(), kp.public_key.size()));
    result.Set("secretKey", Napi::Buffer<uint8_t>::Copy(info.Env(), kp.secret_key.data(), kp.secret_key.size()));

    zupt::secureWipe(kp.public_key.data(), kp.public_key.size());
    zupt::secureWipe(kp.secret_key.data(), kp.secret_key.size());

    return result;
}

Napi::Value KeyGeneratorWrapper::SaveKeyPair(const Napi::CallbackInfo& info) {
    if (!keyGen_) {
        throw Napi::Error::New(info.Env(), "KeyGenerator has been destroyed");
    }

    Napi::Object keypair = info[0].As<Napi::Object>();
    std::string filename = info[1].As<Napi::String>();

    Napi::Uint8Array pubArray = keypair.Get("publicKey").As<Napi::Uint8Array>();
    Napi::Uint8Array privArray = keypair.Get("secretKey").As<Napi::Uint8Array>();

    std::vector<uint8_t> publicKey(pubArray.ByteLength());
    std::vector<uint8_t> secretKey(privArray.ByteLength());

    memcpy(publicKey.data(), pubArray.Data(), publicKey.size());
    memcpy(secretKey.data(), privArray.Data(), secretKey.size());

    zupt::KeyPair kp(publicKey, secretKey);
    keyGen_->saveKeyPair(kp, filename);

    zupt::secureWipe(publicKey.data(), publicKey.size());
    zupt::secureWipe(secretKey.data(), secretKey.size());

    return info.Env().Undefined();
}

Napi::Value KeyGeneratorWrapper::LoadKeyPair(const Napi::CallbackInfo& info) {
    if (!keyGen_) {
        throw Napi::Error::New(info.Env(), "KeyGenerator has been destroyed");
    }

    std::string filename = info[0].As<Napi::String>();
    zupt::KeyPair kp = keyGen_->loadKeyPair(filename);

    Napi::Object result = Napi::Object::New(info.Env());
    result.Set("publicKey", Napi::Buffer<uint8_t>::Copy(info.Env(), kp.public_key.data(), kp.public_key.size()));
    result.Set("secretKey", Napi::Buffer<uint8_t>::Copy(info.Env(), kp.secret_key.data(), kp.secret_key.size()));

    return result;
}

Napi::Value KeyGeneratorWrapper::ExportPublicKey(const Napi::CallbackInfo& info) {
    if (!keyGen_) {
        throw Napi::Error::New(info.Env(), "KeyGenerator has been destroyed");
    }

    std::string privfile = info[0].As<Napi::String>();
    std::string pubfile = info[1].As<Napi::String>();
    keyGen_->exportPublicKey(privfile, pubfile);
    return info.Env().Undefined();
}

Napi::Value KeyGeneratorWrapper::LoadPublicKey(const Napi::CallbackInfo& info) {
    if (!keyGen_) {
        throw Napi::Error::New(info.Env(), "KeyGenerator has been destroyed");
    }

    std::string filename = info[0].As<Napi::String>();
    std::vector<uint8_t> publicKey = keyGen_->loadPublicKey(filename);

    return Napi::Buffer<uint8_t>::Copy(info.Env(), publicKey.data(), publicKey.size());
}

/* ═══════════════════════════════════════════════════════════════════
 * ENCRYPTOR WRAPPER
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * @cond PORT
 * @class EncryptorWrapper
 * @brief Envolve `zupt::Encryptor` e expõe a classe JS `Encryptor`.
 * @details Recebe a chave pública do destinatário no construtor e oferece
 * criptografia de memória e de arquivo, sempre no thread principal do
 * Node.js (nenhuma operação usa N-API work queue). Exceções C++ de
 * libzupt se propagam como exceções JavaScript.
 * \warning O construtor copia a chave pública para um `std::vector`
 * local e não o zera depois de entregar o objeto ao `zupt::Encryptor`,
 * deixando uma cópia adicional do material chave em claro no heap.
 * @endcond
 * @cond INGLES
 * @class EncryptorWrapper
 * @brief Wraps `zupt::Encryptor` and exposes the JS class `Encryptor`.
 * @details It receives the recipient's public key in the constructor and offers
 * memory and file encryption, always on the main thread of
 * Node.js (no operation uses the N-API work queue). C++ exceptions of
 * libzupt propagate as JavaScript exceptions.
 * \warning The constructor copies the public key into a local `std::vector`
 * and does not zero it after handing the object to `zupt::Encryptor`,
 * leaving an additional copy of the key material in plaintext on the heap.
 * @endcond */
class EncryptorWrapper : public Napi::ObjectWrap<EncryptorWrapper> {
public:
    /**
     * @cond PORT
     * @brief Registra a classe `Encryptor` nas exportações do módulo.
     * @details Anexa `encryptMemory` e `encryptFile` como métodos de instância e
     * `getEncryptionHeaderSize` como método estático da classe JS.
     * @param[in]     env     Ambiente N-API.
     * @param[in,out] exports Objeto de exportações enriquecido.
     * @return O próprio objeto \p exports.
     * @endcond
     * @cond INGLES
     * @brief Registers the `Encryptor` class in the module exports.
     * @details Attaches `encryptMemory` and `encryptFile` as instance methods and
     * `getEncryptionHeaderSize` as a static method of the JS class.
     * @param[in]     env     N-API environment.
     * @param[in,out] exports Enriched exports object.
     * @return The \p exports object itself.
     * @endcond */
    static Napi::Object Init(Napi::Env env, Napi::Object exports);

    /**
     * @cond PORT
     * @brief Construtor chamado por `new Encryptor(publicKey)`.
     * @details Copia os bytes da chave pública do TypedArray para um
     * `std::vector` e constrói o objeto C++ com ele.
     * \warning Nenhum tipo de argumento é verificado: `info[0]` é
     * assumido TypedArray. `ByteLength()` pode ser maior que o
     * esperado; não há validação de formato de chave.
     * @param[in] info Argumentos: `[0]` `Buffer`/`Uint8Array` com a chave pública.
     * @endcond
     * @cond INGLES
     * @brief Constructor called by `new Encryptor(publicKey)`.
     * @details Copies the public key bytes from the TypedArray into a
     * `std::vector` and builds the C++ object with it.
     * \warning No argument type is verified: `info[0]` is
     * assumed to be a TypedArray. `ByteLength()` can be larger than
     * expected; there is no validation of the key format.
     * @param[in] info Arguments: `[0]` `Buffer`/`Uint8Array` with the public key.
     * @endcond */
    EncryptorWrapper(const Napi::CallbackInfo& info);

    /**
     * @cond PORT
     * @brief Destrutor padrão.
     * @details Libera `encryptor_` por meio do `std::unique_ptr`; não há
     * limpeza adicional de material chave.
     * @endcond
     * @cond INGLES
     * @brief Default destructor.
     * @details Releases `encryptor_` through the `std::unique_ptr`; there is no
     * additional cleanup of key material.
     * @endcond */
    ~EncryptorWrapper();

private:
    /**
     * @cond PORT
     * @brief Implementa `encryptMemory(data)`.
     * @details Copia o input para um `std::vector`, chama
     * `zupt::Encryptor::encryptMemory` e devolve o par estruturado como
     * objeto JS `{ ciphertext, encHeader }`, cada parte em um novo
     * `Buffer` (`Buffer::Copy`).
     * @param[in] info Argumentos: `[0]` `Buffer`/`Uint8Array` com o texto claro.
     * @return Objeto JS `{ ciphertext, encHeader }`.
     * @endcond
     * @cond INGLES
     * @brief Implements `encryptMemory(data)`.
     * @details Copies the input into a `std::vector`, calls
     * `zupt::Encryptor::encryptMemory` and returns the structured pair as a
     * JS object `{ ciphertext, encHeader }`, each part in a new
     * `Buffer` (`Buffer::Copy`).
     * @param[in] info Arguments: `[0]` `Buffer`/`Uint8Array` with the plaintext.
     * @return JS object `{ ciphertext, encHeader }`.
     * @endcond */
    Napi::Value EncryptMemory(const Napi::CallbackInfo& info);

    /**
     * @cond PORT
     * @brief Implementa `encryptFile(filename)`.
     * @details Criptografa o conteúdo do arquivo indicado, sem sobrescrevê-lo:
     * devolve o resultado em memória como `{ ciphertext, encHeader }`.
     * \warning `filename` vem do chamador, sem validação. Erros de
     * leitura do arquivo se manifestam como exceção JavaScript.
     * @param[in] info Argumentos: `[0]` string do caminho.
     * @return Objeto JS `{ ciphertext, encHeader }`.
     * @endcond
     * @cond INGLES
     * @brief Implements `encryptFile(filename)`.
     * @details Encrypts the content of the indicated file, without overwriting it:
     * it returns the result in memory as `{ ciphertext, encHeader }`.
     * \warning `filename` comes from the caller, without validation. File
     * read errors manifest as a JavaScript exception.
     * @param[in] info Arguments: `[0]` path string.
     * @return JS object `{ ciphertext, encHeader }`.
     * @endcond */
    Napi::Value EncryptFile(const Napi::CallbackInfo& info);

    /**
     * @cond PORT
     * @brief Implementa `Encryptor.getEncryptionHeaderSize()` estático.
     * @details Devolve a constante informada por
     * `zupt::Encryptor::getEncryptionHeaderSize()`.
     * @param[in] info Metadados da chamada. Nenhum argumento é lido.
     * @return Número com o tamanho do cabeçalho de criptografia, em bytes.
     * @endcond
     * @cond INGLES
     * @brief Implements the static `Encryptor.getEncryptionHeaderSize()`.
     * @details Returns the constant reported by
     * `zupt::Encryptor::getEncryptionHeaderSize()`.
     * @param[in] info Metadata of the call. No argument is read.
     * @return Number with the encryption header size, in bytes.
     * @endcond */
    static Napi::Value GetEncryptionHeaderSize(const Napi::CallbackInfo& info);

    /**
     * @cond PORT
     * Criptógrafo C++ subjacente.
     * @endcond
     * @cond INGLES
     * Underlying C++ encryptor.
     * @endcond */
    std::unique_ptr<zupt::Encryptor> encryptor_;
};

Napi::Object EncryptorWrapper::Init(Napi::Env env, Napi::Object exports) {
    Napi::Function ctor = Napi::ObjectWrap<EncryptorWrapper>::DefineClass(env, "Encryptor", {
        Napi::ObjectWrap<EncryptorWrapper>::InstanceMethod("encryptMemory", &EncryptorWrapper::EncryptMemory),
        Napi::ObjectWrap<EncryptorWrapper>::InstanceMethod("encryptFile", &EncryptorWrapper::EncryptFile),
        Napi::ObjectWrap<EncryptorWrapper>::StaticMethod("getEncryptionHeaderSize", &EncryptorWrapper::GetEncryptionHeaderSize)
    });

    exports.Set("Encryptor", ctor);
    return exports;
}

EncryptorWrapper::EncryptorWrapper(const Napi::CallbackInfo& info) : Napi::ObjectWrap<EncryptorWrapper>(info) {
    Napi::Uint8Array pubArray = info[0].As<Napi::Uint8Array>();
    std::vector<uint8_t> publicKey(pubArray.ByteLength());
    memcpy(publicKey.data(), pubArray.Data(), publicKey.size());
    encryptor_ = std::make_unique<zupt::Encryptor>(publicKey);
}

EncryptorWrapper::~EncryptorWrapper() = default;

Napi::Value EncryptorWrapper::EncryptMemory(const Napi::CallbackInfo& info) {
    if (!encryptor_) {
        throw Napi::Error::New(info.Env(), "Encryptor has been destroyed");
    }

    Napi::Uint8Array dataArray = info[0].As<Napi::Uint8Array>();
    std::vector<uint8_t> data(dataArray.ByteLength());
    memcpy(data.data(), dataArray.Data(), data.size());

    auto [ciphertext, encHeader] = encryptor_->encryptMemory(data);

    Napi::Object result = Napi::Object::New(info.Env());
    result.Set("ciphertext", Napi::Buffer<uint8_t>::Copy(info.Env(), ciphertext.data(), ciphertext.size()));
    result.Set("encHeader", Napi::Buffer<uint8_t>::Copy(info.Env(), encHeader.data(), encHeader.size()));

    return result;
}

Napi::Value EncryptorWrapper::EncryptFile(const Napi::CallbackInfo& info) {
    if (!encryptor_) {
        throw Napi::Error::New(info.Env(), "Encryptor has been destroyed");
    }

    std::string filename = info[0].As<Napi::String>();
    auto [ciphertext, encHeader] = encryptor_->encryptFile(filename);

    Napi::Object result = Napi::Object::New(info.Env());
    result.Set("ciphertext", Napi::Buffer<uint8_t>::Copy(info.Env(), ciphertext.data(), ciphertext.size()));
    result.Set("encHeader", Napi::Buffer<uint8_t>::Copy(info.Env(), encHeader.data(), encHeader.size()));

    return result;
}

Napi::Value EncryptorWrapper::GetEncryptionHeaderSize(const Napi::CallbackInfo& info) {
    return Napi::Number::New(info.Env(), zupt::Encryptor::getEncryptionHeaderSize());
}

/* ═══════════════════════════════════════════════════════════════════
 * DECRYPTOR WRAPPER
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * @cond PORT
 * @class DecryptorWrapper
 * @brief Envolve `zupt::Decryptor` e expõe a classe JS `Decryptor`.
 * @details Recebe a chave privada no construtor e oferece descriptografia de
 * memória e de arquivo, sempre de forma síncrona na thread do Event
 * Loop. Exceções C++ de libzupt se propagam como exceções JavaScript,
 * que o N-API converte no momento do retorno da chamada.
 * \warning a chave privada é copiada para um `std::vector` local no
 * construtor e não é zerada, de modo que permanecem cópias dela em
 * claro no heap do processo.
 * @endcond
 * @cond INGLES
 * @class DecryptorWrapper
 * @brief Wraps `zupt::Decryptor` and exposes the JS class `Decryptor`.
 * @details It receives the private key in the constructor and offers memory and file
 * decryption, always synchronously on the Event Loop thread. C++
 * exceptions of libzupt propagate as JavaScript exceptions,
 * which the N-API converts at the moment the call returns.
 * \warning the private key is copied into a local `std::vector` in the
 * constructor and is not zeroed, so copies of it in
 * plaintext remain on the process heap.
 * @endcond */
class DecryptorWrapper : public Napi::ObjectWrap<DecryptorWrapper> {
public:
    /**
     * @cond PORT
     * @brief Registra a classe `Decryptor` nas exportações do módulo.
     * @param[in]     env     Ambiente N-API.
     * @param[in,out] exports Objeto de exportações enriquecido.
     * @return O próprio objeto \p exports.
     * @endcond
     * @cond INGLES
     * @brief Registers the `Decryptor` class in the module exports.
     * @param[in]     env     N-API environment.
     * @param[in,out] exports Enriched exports object.
     * @return The \p exports object itself.
     * @endcond */
    static Napi::Object Init(Napi::Env env, Napi::Object exports);

    /**
     * @cond PORT
     * @brief Construtor chamado por `new Decryptor(privateKey)`.
     * @details Copia os bytes da chave privada do TypedArray para um
     * `std::vector` e constrói o objeto C++ com ele.
     * \warning Nenhum verificador de tipo é aplicado a `info[0]`.
     * @param[in] info Argumentos: `[0]` `Buffer`/`Uint8Array` com a chave privada.
     * @endcond
     * @cond INGLES
     * @brief Constructor called by `new Decryptor(privateKey)`.
     * @details Copies the private key bytes from the TypedArray into a
     * `std::vector` and builds the C++ object with it.
     * \warning No type checker is applied to `info[0]`.
     * @param[in] info Arguments: `[0]` `Buffer`/`Uint8Array` with the private key.
     * @endcond */
    DecryptorWrapper(const Napi::CallbackInfo& info);

    /**
     * @cond PORT
     * @brief Destrutor padrão.
     * @details Libera `decryptor_` por meio do `std::unique_ptr`; não há
     * limpeza adicional de material chave.
     * @endcond
     * @cond INGLES
     * @brief Default destructor.
     * @details Releases `decryptor_` through the `std::unique_ptr`; there is no
     * additional cleanup of key material.
     * @endcond */
    ~DecryptorWrapper();

private:
    /**
     * @cond PORT
     * @brief Implementa `decryptMemory(ciphertext, encHeader)`.
     * @details Copia os dois Buffers para vetores locais, chama
     * `zupt::Decryptor::decryptMemory` e devolve o texto claro como um
     * novo `Buffer` JS.
     * \warning o texto claro passa por três cópias (`std::vector` de
     * entrada, `std::vector` retornado por libzupt e o `Buffer` do V8),
     * e nenhuma delas é zerada.
     * @param[in] info Argumentos: `[0]` texto cifrado, `[1]` cabeçalho de
     * criptografia devolvido pela cifra.
     * @return `Buffer` com o texto claro.
     * @endcond
     * @cond INGLES
     * @brief Implements `decryptMemory(ciphertext, encHeader)`.
     * @details Copies the two Buffers into local vectors, calls
     * `zupt::Decryptor::decryptMemory` and returns the plaintext as a new
     * JS `Buffer`.
     * \warning the plaintext goes through three copies (the input `std::vector`,
     * the `std::vector` returned by libzupt and the V8 `Buffer`),
     * and none of them is zeroed.
     * @param[in] info Arguments: `[0]` encrypted text, `[1]` encryption
     * header returned by the cipher.
     * @return `Buffer` with the plaintext.
     * @endcond */
    Napi::Value DecryptMemory(const Napi::CallbackInfo& info);

    /**
     * @cond PORT
     * @brief Implementa `decryptFile(filename, encHeader)`.
     * @details Lê e descriptografa o arquivo indicado usando o cabeçalho
     * fornecido; o resultado é devolvido em memória, sem escrita em
     * disco.
     * \warning `filename` vem do chamador, sem validação.
     * @param[in] info Argumentos: `[0]` string do caminho, `[1]` cabeçalho de
     * criptografia.
     * @return `Buffer` com o texto claro.
     * @endcond
     * @cond INGLES
     * @brief Implements `decryptFile(filename, encHeader)`.
     * @details Reads and decrypts the indicated file using the header
     * provided; the result is returned in memory, with no write to
     * disk.
     * \warning `filename` comes from the caller, without validation.
     * @param[in] info Arguments: `[0]` path string, `[1]` encryption
     * header.
     * @return `Buffer` with the plaintext.
     * @endcond */
    Napi::Value DecryptFile(const Napi::CallbackInfo& info);

    /**
     * @cond PORT
     * Descriptógrafo C++ subjacente.
     * @endcond
     * @cond INGLES
     * Underlying C++ decryptor.
     * @endcond */
    std::unique_ptr<zupt::Decryptor> decryptor_;
};

Napi::Object DecryptorWrapper::Init(Napi::Env env, Napi::Object exports) {
    Napi::Function ctor = Napi::ObjectWrap<DecryptorWrapper>::DefineClass(env, "Decryptor", {
        Napi::ObjectWrap<DecryptorWrapper>::InstanceMethod("decryptMemory", &DecryptorWrapper::DecryptMemory),
        Napi::ObjectWrap<DecryptorWrapper>::InstanceMethod("decryptFile", &DecryptorWrapper::DecryptFile)
    });

    exports.Set("Decryptor", ctor);
    return exports;
}

DecryptorWrapper::DecryptorWrapper(const Napi::CallbackInfo& info) : Napi::ObjectWrap<DecryptorWrapper>(info) {
    Napi::Uint8Array privArray = info[0].As<Napi::Uint8Array>();
    std::vector<uint8_t> privateKey(privArray.ByteLength());
    memcpy(privateKey.data(), privArray.Data(), privateKey.size());
    decryptor_ = std::make_unique<zupt::Decryptor>(privateKey);
}

DecryptorWrapper::~DecryptorWrapper() = default;

Napi::Value DecryptorWrapper::DecryptMemory(const Napi::CallbackInfo& info) {
    if (!decryptor_) {
        throw Napi::Error::New(info.Env(), "Decryptor has been destroyed");
    }

    Napi::Uint8Array ciphertextArray = info[0].As<Napi::Uint8Array>();
    Napi::Uint8Array encHeaderArray = info[1].As<Napi::Uint8Array>();

    std::vector<uint8_t> ciphertext(ciphertextArray.ByteLength());
    std::vector<uint8_t> encHeader(encHeaderArray.ByteLength());

    memcpy(ciphertext.data(), ciphertextArray.Data(), ciphertext.size());
    memcpy(encHeader.data(), encHeaderArray.Data(), encHeader.size());

    std::vector<uint8_t> plaintext = decryptor_->decryptMemory(ciphertext, encHeader);

    return Napi::Buffer<uint8_t>::Copy(info.Env(), plaintext.data(), plaintext.size());
}

Napi::Value DecryptorWrapper::DecryptFile(const Napi::CallbackInfo& info) {
    if (!decryptor_) {
        throw Napi::Error::New(info.Env(), "Decryptor has been destroyed");
    }

    std::string filename = info[0].As<Napi::String>();
    Napi::Uint8Array encHeaderArray = info[1].As<Napi::Uint8Array>();

    std::vector<uint8_t> encHeader(encHeaderArray.ByteLength());
    memcpy(encHeader.data(), encHeaderArray.Data(), encHeader.size());

    std::vector<uint8_t> plaintext = decryptor_->decryptFile(filename, encHeader);

    return Napi::Buffer<uint8_t>::Copy(info.Env(), plaintext.data(), plaintext.size());
}

/* ═══════════════════════════════════════════════════════════════════
 * MODULE INITIALIZATION
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * @cond PORT
 * @brief Implementa `randomBytes(size)` exportada pelo módulo.
 * @details Converte o primeiro argumento para `uint32_t`, obtém os aleatórios de
 * `zupt::randomBytes` e os devolve como um novo `Buffer` JS (cópia).
 * Não há tratamento de erro próprio: se a biblioteca não conseguir
 * gerar os aleatórios, a exceção C++ se propaga para o JavaScript.
 * \warning `Uint32Value()` aceita qualquer número: valores negativos,
 * fracionários e acima de `2^32-1` são truncados silenciosamente, e
 * valores não numéricos (`NaN`/`undefined`) produzem `0` — nunca um
 * erro de tipo.
 * @param[in] info Argumentos: `[0]` quantidade de bytes desejada.
 * @return `Buffer` com os bytes aleatórios.
 * @endcond
 * @cond INGLES
 * @brief Implements the module-exported `randomBytes(size)`.
 * @details Converts the first argument to `uint32_t`, gets the random bytes from
 * `zupt::randomBytes` and returns them as a new JS `Buffer` (copy).
 * There is no error handling of its own: if the library cannot
 * generate the random bytes, the C++ exception propagates to JavaScript.
 * \warning `Uint32Value()` accepts any number: negative values,
 * fractional ones and values above `2^32-1` are truncated silently, and
 * non-numeric values (`NaN`/`undefined`) produce `0` — never a
 * type error.
 * @param[in] info Arguments: `[0]` desired number of bytes.
 * @return `Buffer` with the random bytes.
 * @endcond */
Napi::Value RandomBytes(const Napi::CallbackInfo& info) {
    uint32_t size = info[0].As<Napi::Number>().Uint32Value();
    std::vector<uint8_t> bytes = zupt::randomBytes(size);
    return Napi::Buffer<uint8_t>::Copy(info.Env(), bytes.data(), bytes.size());
}

/**
 * @cond PORT
 * @brief Implementa `getVersion()` exportada pelo módulo.
 * @details Devolve a versão da biblioteca como string JS, obtida de
 * `zupt::getVersion()`.
 * \warning Não há verificação de nulos: `zupt::getVersion()` devolve
 * `const char*` e `Napi::String::New` percorre a string, de modo que
 * um retorno nulo derrubaria o processo.
 * @param[in] info Metadados da chamada. Nenhum argumento é lido.
 * @return String com a versão da biblioteca.
 * @endcond
 * @cond INGLES
 * @brief Implements the module-exported `getVersion()`.
 * @details Returns the library version as a JS string, obtained from
 * `zupt::getVersion()`.
 * \warning There is no null check: `zupt::getVersion()` returns
 * `const char*` and `Napi::String::New` walks the string, so
 * a null return would bring the process down.
 * @param[in] info Metadata of the call. No argument is read.
 * @return String with the library version.
 * @endcond */
Napi::Value GetVersion(const Napi::CallbackInfo& info) {
    return Napi::String::New(info.Env(), zupt::getVersion());
}

/**
 * @cond PORT
 * @brief Função de registro do módulo: chama cada wrapper e anexa as livres.
 * @details Executa, nesta ordem, `SecureBufferWrapper::Init`,
 * `KeyGeneratorWrapper::Init`, `EncryptorWrapper::Init` e
 * `DecryptorWrapper::Init` (os retornos são descartados porque cada um
 * já escreve em \p exports) e depois cria as funções JS
 * `randomBytes` e `getVersion` com `Napi::Function::New`.
 * \note As quatro chamadas não verificam o retorno: qualquer falha de
 * registro se manifesta por exceção N-API, que o runtime trata como
 * falha de carregamento do addon.
 * @param[in]     env     Ambiente N-API do carregamento.
 * @param[in,out] exports Objeto de exportações do módulo.
 * @return O próprio objeto \p exports.
 * @see NODE_API_MODULE
 * @endcond
 * @cond INGLES
 * @brief Module registration function: calls each wrapper and attaches the free functions.
 * @details Runs, in this order, `SecureBufferWrapper::Init`,
 * `KeyGeneratorWrapper::Init`, `EncryptorWrapper::Init` and
 * `DecryptorWrapper::Init` (the return values are discarded because each one
 * already writes into \p exports) and then creates the JS functions
 * `randomBytes` and `getVersion` with `Napi::Function::New`.
 * \note The four calls do not check the return value: any registration failure
 * manifests through a N-API exception, which the runtime treats as a
 * failure to load the addon.
 * @param[in]     env     N-API environment of the load.
 * @param[in,out] exports Module exports object.
 * @return The \p exports object itself.
 * @see NODE_API_MODULE
 * @endcond */
Napi::Object Init(Napi::Env env, Napi::Object exports) {
    SecureBufferWrapper::Init(env, exports);
    KeyGeneratorWrapper::Init(env, exports);
    EncryptorWrapper::Init(env, exports);
    DecryptorWrapper::Init(env, exports);

    exports.Set("randomBytes", Napi::Function::New(env, RandomBytes));
    exports.Set("getVersion", Napi::Function::New(env, GetVersion));

    return exports;
}

/**
 * @cond PORT
 * @brief Ponto de entrada do addon, registrado pela macro `NODE_API_MODULE`.
 * @details A macro expande para a estrutura de registro exigida pelo Node-API,
 * associando o nome do módulo `zupt_napi` à função \ref Init. O nome do
 * primeiro argumento coincide com `target_name` do `binding.gyp`, que é
 * o nome do arquivo carregado por `require`.
 * @note É apenas uma invocação de macro; não contém código deste arquivo.
 * @endcond
 * @cond INGLES
 * @brief Addon entry point, registered by the `NODE_API_MODULE` macro.
 * @details The macro expands into the registration structure required by the Node-API,
 * associating the module name `zupt_napi` with the \ref Init function. The name of the
 * first argument matches the `target_name` of `binding.gyp`, which is
 * the name of the file loaded by `require`.
 * @note It is only a macro invocation; it contains no code of this file.
 * @endcond */
NODE_API_MODULE(zupt_napi, Init)
