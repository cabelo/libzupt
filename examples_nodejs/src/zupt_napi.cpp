/*
 * libzupt - Node.js N-API Binding
 * Hybrid Post-Quantum Encryption (ML-KEM-768 + X25519)
 *
 * SPDX-License-Identifier: MIT
 */

/**
 * @file  examples_nodejs/src/zupt_napi.cpp
 * @brief Binding Node.js (N-API / node-addon-api) da camada C++ da libzupt.
 * @details Este TU expõe, como addon `zupt.node`, quatro classes JavaScript
 *          (`SecureBuffer`, `KeyGenerator`, `Encryptor`, `Decryptor`) e duas
 *          funções de módulo (`randomBytes`, `getVersion`). Cada classe é
 *          implementada por uma classe wrapper C++ derivada de
 *          `Napi::ObjectWrap`, que guarda a instância C++ correspondente num
 *          `std::unique_ptr` membro.
 *
 *          <b>Fronteira de tipos</b>: toda troca de bytes entre JavaScript e C++
 *          usa `Napi::Uint8Array` (o que cobre `Buffer` e `Uint8Array`) na
 *          entrada e `Napi::Buffer<uint8_t>` na saída via a função de cópia da
 *          biblioteca N-API, que aloca o buffer na engine.
 *          então o objeto JavaScript devolvido é independente dos vetores C++
 *          locais; esses vetores morrem ao fim da chamada. Nenhum ponteiro da
 *          pilha C++ é exposto ao JavaScript.
 *
 *          <b>Erros</b>: o addon é compilado com `NAPI_CPP_EXCEPTIONS`
 *          (`defines` do `binding.gyp`) e `-fexceptions`. As funções C++ de
 *          `include/zupt.hpp` lançam `zupt::ZuptError` (derivada de
 *          `std::runtime_error`); elas não são capturadas neste arquivo, exceto
 *          onde há checagem explícita. O que o addon faz é lançar
 *          `Napi::Error` ou `Napi::TypeError` para os poucos erros de uso da
 *          fronteira que ele mesmo detecta (objeto destruído, argumento de tipo
 *          errado). Uma exceção C++ que escape de `zupt::` atravessa a chamada
 *          N-API e é convertida pela biblioteca node-addon-api em exceção
 *          JavaScript.
 *
 *          <b>Conversão numérica</b>: `napi_value` numérica vira `uint32_t`
 *          (`Uint32Value`), que vira `size_t` na alocação C++. `Napi::Number`
 *          aceita qualquer número JavaScript, incluindo negativos e não
 *          inteiros, sem verificação de faixa neste arquivo (ver arquivo de
 *          achados).
 *
 *          <b>Uso concorrente</b>: as funções N-API executam na thread do event
 *          loop do addon (nenhuma delas usa thread-safe function nem worker),
 *          mas este arquivo não declara nem impede uso simultâneo de um mesmo
 *          objeto wrapper por múltiplos contextos.
 *
 *          <b>Fallback JavaScript</b>: `examples_nodejs/index.js` tenta carregar
 *          este addon; se o load falhar, exporta uma implementação JS
 *          alternativa que "não faz criptografia real". Este TU não tem
 *          participação nesse comportamento.
 */

/* Define NAPI_VERSION before including napi.h to ensure proper API selection */
#ifndef NAPI_VERSION
/**
 * @def NAPI_VERSION
 * @brief Versão da API N-API exigida por este binding.
 * @details O valor 9 é a versão que este binding escolhe para a seleção de
 *          símbolos de `napi.h`. A diretiva condicional permite que o build
 *          defina uma versão diferente antes da inclusão, o que acontece quando
 *          o ambiente de compilação já a definiu. O comentário acima do bloco
 *          comentário acima do guarda de inclusão registra a razão do macro: `napi.h` escolhe o subconjunto
 *          de símbolos de acordo com a versão definida no momento da inclusão.
 *          Nenhum código deste arquivo depende de uma interface específica da
 *          versão 9 que não exista em versões anteriores; a escolha é do
 *          binding, não exigência observável daqui.
 */
#define NAPI_VERSION 9
#endif

#include <napi.h>
#include "../include/zupt.hpp"

/* Helper to convert napi_value to std::vector<uint8_t> */
/**
 * @brief Converte um valor JavaScript em cópia de `std::vector<uint8_t>`.
 * @details Não há verificação do tipo do valor: o `As<Napi::Uint8Array>()` é
 *          aplicado às cegas, o que só é seguro quando o chamador já confirmou
 *          que o argumento é `Buffer` ou `Uint8Array`. Não há checagem de
 *          `napi_is_arraybuffer`: um `ArrayBuffer` (sem view) produz resultado
 *          indefinido pela própria biblioteca.
 *          <b>Cópia</b>: o intervalo `[arr.Data(), arr.Data() +
 *          arr.ByteLength())` é copiado para o vetor devolvido, portanto o
 *          resultado é independente do buffer JavaScript de origem (muda no JS
 *          não afeta o vetor, e vice-versa). Em caso de falha de alocação, o
 *          construtor do vetor lança `std::bad_alloc`, que atravessa a chamada
 *          N-API.
 * @note Nenhum dos chamadores deste arquivo usa esta função: os métodos que
 *       precisam de dados de entrada fazem o `As<Napi::Uint8Array>()` e o
 *       `memcpy` diretamente (ver arquivo de achados).
 * @param[in] value Valor JavaScript esperado como `Buffer` ou `Uint8Array`.
 * @return Vetor com os `ByteLength()` bytes do array de entrada.
 */
static std::vector<uint8_t> GetBufferAsVector(const Napi::Value& value) {
    Napi::Uint8Array arr = value.As<Napi::Uint8Array>();
    return std::vector<uint8_t>(arr.Data(), arr.Data() + arr.ByteLength());
}

/* Helper to create a Buffer from vector */
/**
 * @brief Cria um `Buffer` JavaScript copiando o conteúdo de um vetor C++.
 * @details a função de cópia de `Napi::Buffer` aloca o buffer no heap controlado
 *          pela engine e copia `vec.size()` bytes de `vec.data()`. O buffer
 *          resultante é independente do vetor: o vetor pode ser apagado ou
 *          destruído sem afetar o objeto JavaScript.
 *          <b>Buffer vazio</b>: com `vec.size() == 0` o resultado é um `Buffer`
 *          de comprimento zero (a engine aceita `nullptr` quando o tamanho é
 *          zero, o que é o caso para vetores vazios).
 * @param[in] env  Ambiente N-API da chamada em curso.
 * @param[in] vec  Conteúdo a copiar para o buffer JavaScript.
 * @return Objeto `Buffer` com os bytes de `vec`.
 */
static Napi::Value CreateBufferFromVector(Napi::Env env, const std::vector<uint8_t>& vec) {
    return Napi::Buffer<uint8_t>::Copy(env, vec.data(), vec.size());
}

/* ═══════════════════════════════════════════════════════════════════
 * SECURE BUFFER WRAPPER
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * @class SecureBufferWrapper
 * @brief Wrapper N-API de `zupt::SecureBuffer`.
 * @details Em JavaScript o objeto é chamado `SecureBuffer` (nome registrado em
 *          \ref SecureBufferWrapper::Init). O conteúdo do buffer fica
 *          exclusivamente no objeto C++ apontado por `buffer_`; JavaScript vê
 *          apenas métodos e acessores.
 *          <b>Estado "destruído"</b>: o método `destroy` libera o `unique_ptr`, e o
 *          objeto JavaScript continua vivo, porém vazio. A partir desse ponto:
 *          `copy()` e `toBuffer()` lançam `Napi::Error`; `zeroize()`, `size` e
 *          `dataLength` toleram o estado e devolvem `undefined`/`0`. Não há
 *          transição de volta ao estado ativo.
 *          <b>Conversão de memória</b>: nenhuma operação deste wrapper devolve
 *          ponteiro interno ao JavaScript. `toBuffer()` copia o conteúdo via
 *          `toVector()` intermediário e depois por `Napi::Buffer::Copy`, ou
 *          seja, o texto em claro chega a existir em três lugares durante a
 *          chamada (buffer C++, `std::vector` local, `Buffer` JS). Os dois
 *          primeiros morrem com a chamada; o `Buffer` JS não é auto-apagável.
 *          \note `zupt::SecureBuffer` não bloqueia memória (não chama `mlock`),
 *                então o nome "SecureBuffer" não implica proteção contra swap.
 *          \see include/zupt.hpp (classe `zupt::SecureBuffer`)
 */
class SecureBufferWrapper : public Napi::ObjectWrap<SecureBufferWrapper> {
public:
    /**
     * @brief Registra a classe `SecureBuffer` e seus métodos no objeto de
     *        exports do módulo.
     * @details `DefineClass` cria o construtor JavaScript e associa os métodos
     *          de instância `copy`, `zeroize`, `toBuffer`, `destroy` e os
     *          acessores `size` e `dataLength` (somente getter — o setter é
     *          `nullptr`, então escrever em `size` gera erro do lado JS).
     *          Ao final, `exports.SecureBuffer` aponta para o construtor.
     * @param[in]     env     Ambiente da chamada de inicialização.
     * @param[in,out] exports Objeto de exports do módulo; recebe a propriedade
     *                        `SecureBuffer`.
     * @return O mesmo `exports` recebido, já com a classe registrada.
     */
    static Napi::Object Init(Napi::Env env, Napi::Object exports);

    /**
     * @brief Constrói o wrapper a partir do argumento de `new SecureBuffer(n)`.
     * @details Converte o primeiro argumento para `uint32_t` e constrói o
     *          `zupt::SecureBuffer` correspondente. Não há checagem do tipo nem
     *          da presença do argumento: `new SecureBuffer()` produz
     *          `Uint32Value()` sobre `undefined`, e `undefined` não é número —
     *          o comportamento depende da conversão da biblioteca (lança
     *          `Error` de conversão). Números negativos e não inteiros são
     *          truncados para `uint32_t`.
     *          Falha de alocação no `make_unique` lança `std::bad_alloc`, que
     *          não é convertida explicitamente aqui.
     * @param[in] info Metadados da chamada de construtor. `info[0]` é o tamanho
     *                 em bytes pedido.
     * @pre `info.Length() >= 1` e `info[0]` é um número (não verificado).
     */
    SecureBufferWrapper(const Napi::CallbackInfo& info);

    /**
     * @brief Destrutor padrão.
     * @details O zerado do conteúdo é feito pelo destructor de
     *          `zupt::SecureBuffer` quando `buffer_` é destruído. Se `destroy()`
     *          já tiver sido chamado, não há o que apagar.
     */
    ~SecureBufferWrapper();

private:
    /**
     * @brief `copy(buf)`: copia os bytes de `buf` para o buffer interno.
     * @details Valida, nesta ordem: (1) se o objeto não foi destruído; (2) se
     *          `info[0]` existe e é um `TypedArray`. Depois calcula
     *          `copyLen = min(inputLen, bufferLen)` e faz um `memcpy` de
     *          `copyLen` bytes do buffer JavaScript para `buffer_->data()`.
     *          <b>Truncação silenciosa</b>: entrada maior que o buffer interno
     *          tem o excedente descartado sem aviso; entrada menor deixa o
     *          restante do buffer com o conteúdo anterior (a alocação inicial
     *          não zera o buffer).
     *          \note `data()` pode ser `nullptr` se o objeto tiver sido movido;
     *          aqui isso não ocorre, pois o wrapper nunca é movido.
     * @param[in] info Metadados da chamada. `info[0]` é o `Buffer` ou
     *                 `Uint8Array` de origem.
     * @return Número com a quantidade de bytes efetivamente copiados
     *         (`copyLen`), o que permite ao chamador detectar truncamento.
     * @exception Napi::Error quando o objeto foi destruído.
     * @exception Napi::TypeError quando `info[0]` está ausente ou não é
     *            `TypedArray`.
     */
    Napi::Value Copy(const Napi::CallbackInfo& info);

    /**
     * @brief `zeroize()`: zera o conteúdo do buffer interno.
     * @details Delega a `zupt::SecureBuffer::zeroize()`, que usa `secureWipe`
     *          (escrita via `volatile`, sem otimização). Se o objeto foi
     *          destruído (`buffer_ == nullptr`), a chamada é um no-op e não
     *          lança.
     * @param[in] info Metadados da chamada. Nenhum argumento é lido.
     * @return `undefined`.
     */
    Napi::Value Zeroize(const Napi::CallbackInfo& info);

    /**
     * @brief `toBuffer()`: devolve uma cópia do conteúdo como `Buffer`.
     * @details Passa por `toVector()` (cópia 1) e `Napi::Buffer::Copy`
     *          (cópia 2). O `Buffer` devolvido não é apagado quando morre,
     *          então o texto em claro pode persistir em memória mesmo depois de
     *          `zeroize()` ou `destroy()` do objeto de origem.
     * @param[in] info Metadados da chamada. Nenhum argumento é lido.
     * @return `Buffer` com os `size()` bytes do buffer interno.
     * @exception Napi::Error quando o objeto foi destruído.
     */
    Napi::Value ToBuffer(const Napi::CallbackInfo& info);

    /**
     * @brief `destroy()`: libera o buffer interno imediatamente.
     * @details `buffer_.reset()` destrói o `zupt::SecureBuffer`, que zera o
     *          conteúdo antes de liberar a memória. O objeto JavaScript
     *          permanece existindo, mas entra no estado "destruído" descrito na
     *          classe. Chamada repetida é inofensiva (`reset()` sobre pointer
     *          já nulo é no-op).
     * @param[in] info Metadados da chamada. Nenhum argumento é lido.
     * @return `undefined`.
     */
    Napi::Value Destroy(const Napi::CallbackInfo& info);

    /**
     * @brief Getter do acessor `size`.
     * @details Devolve `buffer_->size()`. Quando o objeto foi destruído, devolve
     *          `0` em vez de lançar.
     * @param[in] info Metadados da chamada. Nenhum argumento é lido.
     * @return Número com o tamanho em bytes do buffer, ou `0`.
     */
    Napi::Value GetSize(const Napi::CallbackInfo& info);

    /**
     * @brief Getter do acessor `dataLength`.
     * @details O corpo é idêntico ao de \ref GetSize: devolve
     *          `buffer_->size()`, ou `0` se o objeto foi destruído. Não há, no
     *          lado C++, o conceito de "bytes usados" distinto da capacidade —
     *          `zupt::SecureBuffer` tem tamanho fixo. Os dois acessores, portanto
     *          sempre devolvem o mesmo número.
     *          \warning Redundância: `size` e `dataLength` são indistinguíveis
     *          pelo comportamento (ver arquivo de achados).
     * @param[in] info Metadados da chamada. Nenhum argumento é lido.
     * @return Número com o tamanho em bytes do buffer, ou `0`.
     * @see GetSize
     */
    Napi::Value GetDataLength(const Napi::CallbackInfo& info);

    /** Buffer C++ subjacente; `nullptr` após `destroy()`. */
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
 * @class KeyGeneratorWrapper
 * @brief Envolve `zupt::KeyGenerator` e expõe a classe JS `KeyGenerator`.
 * @details Deriva de `Napi::ObjectWrap`, o que garante a semântica de
 *          `new KeyGenerator()` em JavaScript. Todas as chamadas são síncronas:
 *          exceptions C++ lançadas por libzupt se propagam (a build usa
 *          `NAPI_CPP_EXCEPTIONS`) e o N-API as converte em exceção JavaScript.
 *          Nenhum método usa `Napi::HandleScope`/`EscapableHandleScope` — o
 *          wrapper conta com o scope automático do N-API.
 *          \warning As chaves privadas ficam vivas em JavaScript como objetos
 *          `Buffer`, que são gerenciados pelo coletor de lixo do V8 e nunca
 *          são zerados por este código. Ao terminar de usar uma keypair,
 *          chame `zeroize()` no `SecureBuffer` correspondente, quando existir.
 */
class KeyGeneratorWrapper : public Napi::ObjectWrap<KeyGeneratorWrapper> {
public:
    /**
     * @brief Registra a classe `KeyGenerator` nas exportações do módulo.
     * @details Usa `DefineClass` e anexa o construtor como propriedade
     *          `KeyGenerator` de \p exports.
     * @param[in]     env     Ambiente N-API.
     * @param[in,out] exports Objeto de exportações enriquecido.
     * @return O próprio objeto \p exports.
     * @see SecureBufferWrapper::Init
     */
    static Napi::Object Init(Napi::Env env, Napi::Object exports);

    /**
     * @brief Construtor chamado por `new KeyGenerator()`.
     * @details Cria o objeto C++ subjacente; nenhum argumento de JavaScript é
     *          lido. O construtor base `Napi::ObjectWrap` associa a instância JS
     *          à instância C++, e o N-API cuida do destrutor quando o objeto é
     *          coletado.
     * @param[in] info Metadados da chamada de construção.
     */
    KeyGeneratorWrapper(const Napi::CallbackInfo& info);

    /**
     * @brief Destrutor padrão.
     * @details `keyGen_` é liberado pelo `std::unique_ptr`; não há limpeza
     *          explícita de material chave adicional.
     */
    ~KeyGeneratorWrapper();

private:
    /**
     * @brief Implementa `generateKeyPair()`.
     * @details Delega para `zupt::KeyGenerator::generateKeyPair()` e devolve um
     *          objeto JS `{ publicKey: Buffer, secretKey: Buffer }`. Depois de
     *          copiar os vetores para os Buffers, zera os dados originais com
     *          `zupt::secureWipe`.
     *          \warning `secureWipe` é aplicado ao membro `zupt::KeyPair` local;
     *          os Buffers entregues ao JavaScript permanecem com o material em
     *          claro e nunca são zerados.
     * @param[in] info Metadados da chamada. Nenhum argumento é lido.
     * @return Objeto JS com as propriedades `publicKey` e `secretKey`.
     */
    Napi::Value GenerateKeyPair(const Napi::CallbackInfo& info);

    /**
     * @brief Implementa `saveKeyPair(keypair, filename)`.
     * @details Lê `keypair.publicKey` e `keypair.secretKey` (esperando TypedArray)
     *          para vetores locais, monta um `zupt::KeyPair` e o persiste via
     *          `zupt::KeyGenerator::saveKeyPair`. Zera os vetores ao final.
     *          \warning Nenhum verificador é aplicado: `info[0]`/`info[1]` são
     *          assumidos objeto/string, e cada propriedade é assumida TypedArray.
     *          Valores de outro tipo disparam `napi_fatal_error` no runtime.
     *          \warning O caminho do arquivo vem diretamente do chamador, sem
     *          validação.
     * @param[in] info Argumentos: `[0]` objeto keypair, `[1]` string do caminho.
     * @return `undefined`.
     */
    Napi::Value SaveKeyPair(const Napi::CallbackInfo& info);

    /**
     * @brief Implementa `loadKeyPair(filename)`.
     * @details Lê a keypair do arquivo indicado e a devolve como objeto JS com
     *          as chaves em Buffers (`Buffer::Copy`, ou seja, cópias).
     *          \warning inconsistência: ao contrário de `GenerateKeyPair`, o
     *          `zupt::KeyPair` local não é passado por `zupt::secureWipe`, de
     *          modo que a chave privada em claro fica no heap do processo até a
     *          destruição do objeto local.
     * @param[in] info Argumentos: `[0]` string do caminho.
     * @return Objeto JS `{ publicKey, secretKey }`.
     */
    Napi::Value LoadKeyPair(const Napi::CallbackInfo& info);

    /**
     * @brief Implementa `exportPublicKey(privFile, pubFile)`.
     * @details Lê a keypair salva em \c privfile e escreve a chave pública em
     *          `pubfile`, delegando a
     *          `zupt::KeyGenerator::exportPublicKey(privfile, pubfile)`.
     *          \warning Os dois caminhos vêm diretamente do chamador, sem
     *          validação, e sobrescrevem o destino sem aviso.
     * @param[in] info Argumentos: `[0]` string do arquivo privado, `[1]` string
     *                 do arquivo público de saída.
     * @return `undefined`.
     */
    Napi::Value ExportPublicKey(const Napi::CallbackInfo& info);

    /**
     * @brief Implementa `loadPublicKey(filename)`.
     * @details Lê a chave pública do arquivo indicado e a devolve como `Buffer`
     *          JS. O wrapper C++ não guarda a chave pública carregada: o retorno
     *          serve para o chamador construí-lo um `Encryptor`.
     * @param[in] info Argumentos: `[0]` string do caminho.
     * @return `Buffer` com a chave pública lida.
     */
    Napi::Value LoadPublicKey(const Napi::CallbackInfo& info);

    /** Gerador C++ subjacente. */
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
 * @class EncryptorWrapper
 * @brief Envolve `zupt::Encryptor` e expõe a classe JS `Encryptor`.
 * @details Recebe a chave pública do destinatário no construtor e oferece
 *          criptografia de memória e de arquivo, sempre no thread principal do
 *          Node.js (nenhuma operação usa N-API work queue). Exceções C++ de
 *          libzupt se propagam como exceções JavaScript.
 *          \warning O construtor copia a chave pública para um `std::vector`
 *          local e não o zera depois de entregar o objeto ao `zupt::Encryptor`,
 *          deixando uma cópia adicional do material chave em claro no heap.
 */
class EncryptorWrapper : public Napi::ObjectWrap<EncryptorWrapper> {
public:
    /**
     * @brief Registra a classe `Encryptor` nas exportações do módulo.
     * @details Anexa `encryptMemory` e `encryptFile` como métodos de instância e
     *          `getEncryptionHeaderSize` como método estático da classe JS.
     * @param[in]     env     Ambiente N-API.
     * @param[in,out] exports Objeto de exportações enriquecido.
     * @return O próprio objeto \p exports.
     */
    static Napi::Object Init(Napi::Env env, Napi::Object exports);

    /**
     * @brief Construtor chamado por `new Encryptor(publicKey)`.
     * @details Copia os bytes da chave pública do TypedArray para um
     *          `std::vector` e constrói o objeto C++ com ele.
     *          \warning Nenhum tipo de argumento é verificado: `info[0]` é
     *          assumido TypedArray. `ByteLength()` pode ser maior que o
     *          esperado; não há validação de formato de chave.
     * @param[in] info Argumentos: `[0]` `Buffer`/`Uint8Array` com a chave pública.
     */
    EncryptorWrapper(const Napi::CallbackInfo& info);

    /**
     * @brief Destrutor padrão.
     * @details Libera `encryptor_` por meio do `std::unique_ptr`; não há
     *          limpeza adicional de material chave.
     */
    ~EncryptorWrapper();

private:
    /**
     * @brief Implementa `encryptMemory(data)`.
     * @details Copia o input para um `std::vector`, chama
     *          `zupt::Encryptor::encryptMemory` e devolve o par estruturado como
     *          objeto JS `{ ciphertext, encHeader }`, cada parte em um novo
     *          `Buffer` (`Buffer::Copy`).
     * @param[in] info Argumentos: `[0]` `Buffer`/`Uint8Array` com o texto claro.
     * @return Objeto JS `{ ciphertext, encHeader }`.
     */
    Napi::Value EncryptMemory(const Napi::CallbackInfo& info);

    /**
     * @brief Implementa `encryptFile(filename)`.
     * @details Criptografa o conteúdo do arquivo indicado, sem sobrescrevê-lo:
     *          devolve o resultado em memória como `{ ciphertext, encHeader }`.
     *          \warning `filename` vem do chamador, sem validação. Erros de
     *          leitura do arquivo se manifestam como exceção JavaScript.
     * @param[in] info Argumentos: `[0]` string do caminho.
     * @return Objeto JS `{ ciphertext, encHeader }`.
     */
    Napi::Value EncryptFile(const Napi::CallbackInfo& info);

    /**
     * @brief Implementa `Encryptor.getEncryptionHeaderSize()` estático.
     * @details Devolve a constante informada por
     *          `zupt::Encryptor::getEncryptionHeaderSize()`.
     * @param[in] info Metadados da chamada. Nenhum argumento é lido.
     * @return Número com o tamanho do cabeçalho de criptografia, em bytes.
     */
    static Napi::Value GetEncryptionHeaderSize(const Napi::CallbackInfo& info);

    /** Criptógrafo C++ subjacente. */
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
 * @class DecryptorWrapper
 * @brief Envolve `zupt::Decryptor` e expõe a classe JS `Decryptor`.
 * @details Recebe a chave privada no construtor e oferece descriptografia de
 *          memória e de arquivo, sempre de forma síncrona na thread do Event
 *          Loop. Exceções C++ de libzupt se propagam como exceções JavaScript,
 *          que o N-API converte no momento do retorno da chamada.
 *          \warning a chave privada é copiada para um `std::vector` local no
 *          construtor e não é zerada, de modo que permanecem cópias dela em
 *          claro no heap do processo.
 */
class DecryptorWrapper : public Napi::ObjectWrap<DecryptorWrapper> {
public:
    /**
     * @brief Registra a classe `Decryptor` nas exportações do módulo.
     * @param[in]     env     Ambiente N-API.
     * @param[in,out] exports Objeto de exportações enriquecido.
     * @return O próprio objeto \p exports.
     */
    static Napi::Object Init(Napi::Env env, Napi::Object exports);

    /**
     * @brief Construtor chamado por `new Decryptor(privateKey)`.
     * @details Copia os bytes da chave privada do TypedArray para um
     *          `std::vector` e constrói o objeto C++ com ele.
     *          \warning Nenhum verificador de tipo é aplicado a `info[0]`.
     * @param[in] info Argumentos: `[0]` `Buffer`/`Uint8Array` com a chave privada.
     */
    DecryptorWrapper(const Napi::CallbackInfo& info);

    /**
     * @brief Destrutor padrão.
     * @details Libera `decryptor_` por meio do `std::unique_ptr`; não há
     *          limpeza adicional de material chave.
     */
    ~DecryptorWrapper();

private:
    /**
     * @brief Implementa `decryptMemory(ciphertext, encHeader)`.
     * @details Copia os dois Buffers para vetores locais, chama
     *          `zupt::Decryptor::decryptMemory` e devolve o texto claro como um
     *          novo `Buffer` JS.
     *          \warning o texto claro passa por três cópias (`std::vector` de
     *          entrada, `std::vector` retornado por libzupt e o `Buffer` do V8),
     *          e nenhuma delas é zerada.
     * @param[in] info Argumentos: `[0]` texto cifrado, `[1]` cabeçalho de
     *                 criptografia devolvido pela cifra.
     * @return `Buffer` com o texto claro.
     */
    Napi::Value DecryptMemory(const Napi::CallbackInfo& info);

    /**
     * @brief Implementa `decryptFile(filename, encHeader)`.
     * @details Lê e descriptografa o arquivo indicado usando o cabeçalho
     *          fornecido; o resultado é devolvido em memória, sem escrita em
     *          disco.
     *          \warning `filename` vem do chamador, sem validação.
     * @param[in] info Argumentos: `[0]` string do caminho, `[1]` cabeçalho de
     *                 criptografia.
     * @return `Buffer` com o texto claro.
     */
    Napi::Value DecryptFile(const Napi::CallbackInfo& info);

    /** Descriptógrafo C++ subjacente. */
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
 * @brief Implementa `randomBytes(size)` exportada pelo módulo.
 * @details Converte o primeiro argumento para `uint32_t`, obtém os aleatórios de
 *          `zupt::randomBytes` e os devolve como um novo `Buffer` JS (cópia).
 *          Não há tratamento de erro próprio: se a biblioteca não conseguir
 *          gerar os aleatórios, a exceção C++ se propaga para o JavaScript.
 *          \warning `Uint32Value()` aceita qualquer número: valores negativos,
 *          fracionários e acima de `2^32-1` são truncados silenciosamente, e
 *          valores não numéricos (`NaN`/`undefined`) produzem `0` — nunca um
 *          erro de tipo.
 * @param[in] info Argumentos: `[0]` quantidade de bytes desejada.
 * @return `Buffer` com os bytes aleatórios.
 */
Napi::Value RandomBytes(const Napi::CallbackInfo& info) {
    uint32_t size = info[0].As<Napi::Number>().Uint32Value();
    std::vector<uint8_t> bytes = zupt::randomBytes(size);
    return Napi::Buffer<uint8_t>::Copy(info.Env(), bytes.data(), bytes.size());
}

/**
 * @brief Implementa `getVersion()` exportada pelo módulo.
 * @details Devolve a versão da biblioteca como string JS, obtida de
 *          `zupt::getVersion()`.
 *          \warning Não há verificação de nulos: `zupt::getVersion()` devolve
 *          `const char*` e `Napi::String::New` percorre a string, de modo que
 *          um retorno nulo derrubaria o processo.
 * @param[in] info Metadados da chamada. Nenhum argumento é lido.
 * @return String com a versão da biblioteca.
 */
Napi::Value GetVersion(const Napi::CallbackInfo& info) {
    return Napi::String::New(info.Env(), zupt::getVersion());
}

/**
 * @brief Função de registro do módulo: chama cada wrapper e anexa as livres.
 * @details Executa, nesta ordem, `SecureBufferWrapper::Init`,
 *          `KeyGeneratorWrapper::Init`, `EncryptorWrapper::Init` e
 *          `DecryptorWrapper::Init` (os retornos são descartados porque cada um
 *          já escreve em \p exports) e depois cria as funções JS
 *          `randomBytes` e `getVersion` com `Napi::Function::New`.
 *          \note As quatro chamadas não verificam o retorno: qualquer falha de
 *          registro se manifesta por exceção N-API, que o runtime trata como
 *          falha de carregamento do addon.
 * @param[in]     env     Ambiente N-API do carregamento.
 * @param[in,out] exports Objeto de exportações do módulo.
 * @return O próprio objeto \p exports.
 * @see NODE_API_MODULE
 */
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
 * @brief Ponto de entrada do addon, registrado pela macro `NODE_API_MODULE`.
 * @details A macro expande para a estrutura de registro exigida pelo Node-API,
 *          associando o nome do módulo `zupt_napi` à função \ref Init. O nome do
 *          primeiro argumento coincide com `target_name` do `binding.gyp`, que é
 *          o nome do arquivo carregado por `require`.
 * @note É apenas uma invocação de macro; não contém código deste arquivo.
 */
NODE_API_MODULE(zupt_napi, Init)
