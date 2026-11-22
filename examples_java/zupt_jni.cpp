/*
 * libzupt - Java Native Interface (JNI) bindings
 * SPDX-License-Identifier: MIT
 */

#include <jni.h>
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>

#include "zupt.hpp"

/**
 * @cond PORT
 * \file zupt_jni.cpp
 * \brief Implementação dos métodos nativos consumidos pelas classes de
 * `com.libzupt` (JNI).
 *
 * \details Este arquivo não declara tipos nem constantes próprios: cada função
 * aqui traduz chamadas Java para a API C++ documentada em
 * `zupt.hpp`. As classes Java correspondentes ficam em
 * `examples_java/src/com/libzupt/` e carregam esta biblioteca por
 * `System.loadLibrary("Jzupt")` — o `CMakeLists.txt` do exemplo gera
 * `libJzupt.so` a partir deste arquivo (`add_library(zupt_jni SHARED
 * zupt_jni.cpp)` + `OUTPUT_NAME Jzupt` + `PREFIX "lib"`).
 *
 * \b Ligação: o vínculo entre Java e C++ é feito de forma explícita
 * em \ref JNI_OnLoad, que chama `RegisterNatives()` para as quatro
 * classes que possuem métodos nativos (`KeyGenerator`, `Encryptor`,
 * `Decryptor` e `NativeLib`). Por isso as assinaturas dos métodos
 * nativos não precisam seguir a convenção de nomes do JNI, embora
 * sigam por consistência. As tabelas de vínculo são as quatro
 * `static JNINativeMethod[]` deste arquivo.
 *
 * \b Erros: todas as funções nativas executam seu corpo dentro de um
 * `try` / `catch (const std::exception& e)` e convertem a exceção C++
 * em exceção Java via \ref throwJavaException. Nenhuma função nativa
 * propaga exceção C++ para a JVM (o que seria comportamento
 * indefinido). Além disso, os métodos retornam `nullptr` em caso de
 * erro, e o lado Java lança `ZuptError` quando a matriz retornada é
 * nula.
 *
 * \b Memória: a conversão de dados binários usa cópias completas —
 * `GetByteArrayRegion`/`SetByteArrayRegion` (cópia, sem pinning de
 * elementos). Nenhum dos buffers temporários em `std::vector` é
 * limpo com `zupt::secureWipe()` antes da saída da função nativa, o
 * que inclui material sensível como chaves privadas e texto claro.
 *
 * \warning `JNI_OnUnload` não é implementado, portanto as referências globais
 * criadas aqui nunca são liberadas. Como a biblioteca só é
 * descarregada quando a JVM se encerra, o vazamento é benigno, mas as
 * referências ficam apontando para classes de um `ClassLoader` que o
 * código de aplicação poderia querer descartar.
 *
 * \note Este arquivo usa apenas o padrão C++11, compatível com o padrão C++
 * configurado pelo `CMAKE_CXX_STANDARD` do `CMakeLists.txt` do exemplo.
 * @endcond
 * @cond INGLES
 * \file zupt_jni.cpp
 * \brief Implementation of the native methods consumed by the
 * `com.libzupt` classes (JNI).
 *
 * \details This file declares no types or constants of its own: each function
 * here translates Java calls to the C++ API documented in
 * `zupt.hpp`. The corresponding Java classes live in
 * `examples_java/src/com/libzupt/` and load this library via
 * `System.loadLibrary("Jzupt")` — the example's `CMakeLists.txt` generates
 * `libJzupt.so` from this file (`add_library(zupt_jni SHARED
 * zupt_jni.cpp)` + `OUTPUT_NAME Jzupt` + `PREFIX "lib"`).
 *
 * \b Binding: the link between Java and C++ is made explicitly
 * in \ref JNI_OnLoad, which calls `RegisterNatives()` for the four
 * classes that have native methods (`KeyGenerator`, `Encryptor`,
 * `Decryptor` and `NativeLib`). Therefore the signatures of the
 * native methods do not need to follow the JNI naming convention,
 * although they do so for consistency. The binding tables are the four
 * `static JNINativeMethod[]` arrays of this file.
 *
 * \b Errors: every native function executes its body inside a
 * `try` / `catch (const std::exception& e)` and converts the C++ exception
 * into a Java exception via \ref throwJavaException. No native function
 * propagates a C++ exception to the JVM (which would be undefined
 * behavior). In addition, the methods return `nullptr` on error, and the Java
 * side throws `ZuptError` when the returned array is
 * null.
 *
 * \b Memory: the conversion of binary data uses full copies —
 * `GetByteArrayRegion`/`SetByteArrayRegion` (copy, with no element
 * pinning). None of the temporary buffers in `std::vector` is
 * wiped with `zupt::secureWipe()` before the native function returns, which
 * includes sensitive material such as private keys and plaintext.
 *
 * \warning `JNI_OnUnload` is not implemented, so the global references
 * created here are never released. Since the library is only
 * unloaded when the JVM exits, the leak is benign, but the
 * references keep pointing to classes of a `ClassLoader` that
 * application code might want to discard.
 *
 * \note This file uses only the C++11 standard, compatible with the C++
 * standard configured by the `CMAKE_CXX_STANDARD` of the example's
 * `CMakeLists.txt`.
 * @endcond */

// Exception class for ZuptError
/**
 * @cond PORT
 * \var zuptErrorClass
 * \brief Referência global à classe `com.libzupt.ZuptError`, usada por
 * \ref throwJavaException.
 *
 * \details É criada de forma sob demanda (lazy) na primeira chamada que
 * precisa lançar exceção, via `FindClass` + `NewGlobalRef`. O valor
 * `nullptr` significa "ainda não resolvida". Não há proteção contra
 * acesso concorrente: se duas threads native chamarem
 * \ref throwJavaException ao mesmo tempo antes do primeiro cache,
 * ambas executam o bloco de inicialização (ver \ref zuptErrorClass e
 * \ref throwJavaException).
 * @endcond
 * @cond INGLES
 * \var zuptErrorClass
 * \brief Global reference to the `com.libzupt.ZuptError` class, used by
 * \ref throwJavaException.
 *
 * \details It is created lazily on the first call that
 * needs to throw an exception, via `FindClass` + `NewGlobalRef`. The
 * value `nullptr` means "not yet resolved". There is no protection against
 * concurrent access: if two native threads call
 * \ref throwJavaException at the same time before the first cache,
 * both execute the initialization block (see \ref zuptErrorClass and
 * \ref throwJavaException).
 * @endcond */
static jclass zuptErrorClass = nullptr;

// Helper function to throw Java exception from C++ exception
/**
 * @cond PORT
 * \brief Lança na JVM uma exceção equivalente a uma exceção C++ capturada.
 * \details Estratégia em três níveis, na ordem:
 * - Se \ref zuptErrorClass ainda é nula, resolve
 * `com/libzupt/ZuptError` com `FindClass` e a converte em
 * referência global (`NewGlobalRef`), liberando a referência
 * local. Se `FindClass` falhar, nenhum estado é salvo e a
 * tentativa se repete a cada chamada.
 * - Havendo referência válida, lança `ZuptError` com a mensagem
 * `e.what()` (`ThrowNew`).
 * - Caso contrário recorre a `java/lang/RuntimeException`; e se
 * este também não for encontrado, lança `java/lang/Error` com a
 * mensagem de `e.what()` (ou `"Unknown error"` quando nula).
 *
 * Todas as funções nativas deste arquivo chamam esta função a
 * partir de `catch (const std::exception& e)`, de modo que exceções
 * como `zupt::ZuptError` e `std::bad_alloc` cheguem ao código Java
 * como `ZuptError`.
 *
 * \param[in] env Ponteiro do contexto JNI (`JNIEnv`) da thread chamadora.
 * \param[in] e   Exceção C++ capturada cuja mensagem descreve o erro.
 *
 * \warning `NewGlobalRef` é chamado sem verificar o resultado. Se ele
 * retornar `nullptr` (por falta de memória), \ref zuptErrorClass fica
 * nula e cada nova tentativa de lançar exceção volta a rodar o bloco
 * de cache.
 *
 * \warning Quando `FindClass("com/libzupt/ZuptError")` falha, o JNI deixa uma
 * exceção `NoClassDefFoundError` pendente na `env`. Essa exceção
 * pendente permanece ativa mesmo depois do caminho alternativo que
 * lança `RuntimeException`, e a ordem de lançamento fica invertida em
 * relação ao esperado: a exceção "principal" passa a ser a pendente.
 *
 * \warning A chamada final usa `env->FindClass("java/lang/Error")`
 * diretamente como argumento de `ThrowNew`, sem testar o retorno. Se
 * `java/lang/Error` não puder ser resolvida, `ThrowNew` recebe um
 * `jclass` nulo, o que é comportamento indefinido.
 *
 * \note A função tem vinculação externa (não é `static`), embora seja usada
 * apenas dentro deste arquivo. Ela é visível a outras unidades de
 * tradução e poderia colidir com um símbolo homônimo.
 * @endcond
 * @cond INGLES
 * \brief Throws into the JVM an exception equivalent to a captured C++ exception.
 * \details Three-level strategy, in order:
 * - If \ref zuptErrorClass is still null, resolves
 * `com/libzupt/ZuptError` with `FindClass` and converts it into a
 * global reference (`NewGlobalRef`), releasing the local
 * reference. If `FindClass` fails, no state is saved and the
 * attempt is repeated on every call.
 * - Given a valid reference, throws `ZuptError` with the message
 * `e.what()` (`ThrowNew`).
 * - Otherwise falls back to `java/lang/RuntimeException`; and if
 * that one is also not found, throws `java/lang/Error` with the
 * message from `e.what()` (or `"Unknown error"` when null).
 *
 * All native functions of this file call this function
 * from `catch (const std::exception& e)`, so exceptions
 * such as `zupt::ZuptError` and `std::bad_alloc` reach the Java code
 * as `ZuptError`.
 *
 * \param[in] env JNI context pointer (`JNIEnv`) of the calling thread.
 * \param[in] e   Captured C++ exception whose message describes the error.
 *
 * \warning `NewGlobalRef` is called without checking the result. If it
 * returns `nullptr` (due to lack of memory), \ref zuptErrorClass stays
 * null and each new attempt to throw an exception runs the caching
 * block again.
 *
 * \warning When `FindClass("com/libzupt/ZuptError")` fails, JNI leaves a
 * `NoClassDefFoundError` exception pending in `env`. That pending
 * exception remains active even after the fallback path that
 * throws `RuntimeException`, and the throwing order ends up inverted
 * relative to what is expected: the "main" exception becomes the pending one.
 *
 * \warning The final call uses `env->FindClass("java/lang/Error")`
 * directly as an argument to `ThrowNew`, without testing the return. If
 * `java/lang/Error` cannot be resolved, `ThrowNew` receives a
 * null `jclass`, which is undefined behavior.
 *
 * \note The function has external linkage (it is not `static`), although it is used
 * only within this file. It is visible to other translation
 * units and could collide with a symbol of the same name.
 * @endcond */
void throwJavaException(JNIEnv* env, const std::exception& e) {
    // Cache zuptErrorClass if not already done
    if (!zuptErrorClass) {
        // Try to find the class - if this fails, use RuntimeException
        jclass exClass = env->FindClass("com/libzupt/ZuptError");
        if (exClass) {
            zuptErrorClass = (jclass)env->NewGlobalRef(exClass);
            env->DeleteLocalRef(exClass);
        }
    }

    if (zuptErrorClass) {
        env->ThrowNew(zuptErrorClass, e.what());
    } else {
        // Fallback to RuntimeException if ZuptError not found
        jclass runtimeExClass = env->FindClass("java/lang/RuntimeException");
        if (runtimeExClass) {
            env->ThrowNew(runtimeExClass, e.what());
            env->DeleteLocalRef(runtimeExClass);
        } else {
            // Ultimate fallback - can't throw proper exception
            const char* msg = e.what();
            if (!msg) msg = "Unknown error";
            env->ThrowNew(env->FindClass("java/lang/Error"), msg);
        }
    }
}

/**
 * @cond PORT
 * \brief Copia uma matriz de bytes Java para um `std::vector<uint8_t>`.
 * \details Obtém o comprimento com `GetArrayLength`, dimensiona o vetor na
 * mesma quantidade e copia o conteúdo inteiro de uma vez com
 * `GetByteArrayRegion` (região 0 ao fim). Não usa
 * `GetByteArrayElements`, portanto não há pinning nem risco de
 * liberar um ponteiro sem cópia de volta. O vetor é retornado por
 * valor (move elision / move semantics).
 *
 * É usada tanto para dados comuns (texto claro, texto cifrado,
 * cabeçalho) quanto para material sensível (chaves públicas e
 * privadas lidas dos campos dos objetos `Encryptor`, `Decryptor` e
 * `KeyPair`).
 *
 * \param[in] env Ponteiro do contexto JNI (`JNIEnv`) da thread chamadora.
 * \param[in] arr Matriz `byte[]` de origem.
 *
 * \return Vetor com exatamente os bytes de `arr`.
 *
 * \warning Nenhum dos dois argumentos é verificado. Se `arr` for `nullptr`
 * (campo `null` no objeto Java, por exemplo), `GetArrayLength` recebe
 * um objeto nulo, o que é comportamento indefinido.
 *
 * \warning `GetByteArrayRegion` pode deixar uma exceção
 * `ArrayIndexOutOfBoundsException` pendente, mas o retorno não é
 * verificado; o vetor é retornado mesmo assim.
 *
 * \note A função tem vinculação externa (não é `static`), embora seja usada
 * apenas dentro deste arquivo.
 * @endcond
 * @cond INGLES
 * \brief Copies a Java byte array into a `std::vector<uint8_t>`.
 * \details Gets the length with `GetArrayLength`, sizes the vector to the
 * same amount and copies the whole content at once with
 * `GetByteArrayRegion` (region 0 to the end). It does not use
 * `GetByteArrayElements`, so there is no pinning and no risk of
 * releasing a pointer without a copy back. The vector is returned by
 * value (move elision / move semantics).
 *
 * It is used both for regular data (plaintext, ciphertext,
 * header) and for sensitive material (public and private
 * keys read from the fields of the `Encryptor`, `Decryptor` and
 * `KeyPair` objects).
 *
 * \param[in] env JNI context pointer (`JNIEnv`) of the calling thread.
 * \param[in] arr Source `byte[]` array.
 *
 * \return Vector with exactly the bytes of `arr`.
 *
 * \warning Neither argument is checked. If `arr` is `nullptr`
 * (for example a `null` field in the Java object), `GetArrayLength` receives
 * a null object, which is undefined behavior.
 *
 * \warning `GetByteArrayRegion` can leave an
 * `ArrayIndexOutOfBoundsException` exception pending, but the return value is not
 * checked; the vector is returned anyway.
 *
 * \note The function has external linkage (it is not `static`), although it is used
 * only within this file.
 * @endcond */
// Convert jbyteArray to std::vector<uint8_t>
std::vector<uint8_t> jbyteArrayToVector(JNIEnv* env, jbyteArray arr) {
    jsize len = env->GetArrayLength(arr);
    std::vector<uint8_t> vec(len);
    env->GetByteArrayRegion(arr, 0, len, reinterpret_cast<jbyte*>(vec.data()));
    return vec;
}

/**
 * @cond PORT
 * \brief Copia um `std::vector<uint8_t>` para uma nova matriz de bytes Java.
 * \details Cria a matriz de destino com `NewByteArray` no tamanho do vetor e
 * preenche a região inteira com `SetByteArrayRegion`. O `const_cast`
 * mais o `reinterpret_cast` existem apenas para satisfazer a
 * assinatura de `SetByteArrayRegion`, que recebe `jbyte*` não `const`
 * mesmo para cópia de saída (a matriz Java é o destino, o vetor de
 * origem não é modificado).
 *
 * A matriz devolvida é uma referência local: passa a ser de
 * responsabilidade da função nativa que a chamou, e o coletor de
 * lixo do lado Java descarta a matriz quando ela se torna inacessível.
 *
 * \param[in] env Ponteiro do contexto JNI (`JNIEnv`) da thread chamadora.
 * \param[in] vec Vetor de origem com os bytes a transferir.
 *
 * \return Matriz `byte[]` recém-criada com o conteúdo de `vec`, ou `nullptr`
 * se `NewByteArray` falhar.
 *
 * \warning O retorno de `NewByteArray` não é verificado. Ele retorna `nullptr`
 * quando não há memória disponível (inclusive quando o tamanho
 * solicitado excede o limite da pilha nativa). Nesse caso
 * `SetByteArrayRegion` recebe um objeto nulo, o que é comportamento
 * indefinido.
 *
 * \note `vec.size()` é `size_t` sem sinal e é convertido para `jsize`
 * (inteiro de 32 bits). Vetores acima de `INT32_MAX` bytes geram
 * truncamento silencioso do comprimento.
 *
 * \note A função tem vinculação externa (não é `static`), embora seja usada
 * apenas dentro deste arquivo.
 * @endcond
 * @cond INGLES
 * \brief Copies a `std::vector<uint8_t>` into a new Java byte array.
 * \details Creates the destination array with `NewByteArray` at the size of the vector and
 * fills the whole region with `SetByteArrayRegion`. The `const_cast`
 * plus the `reinterpret_cast` exist only to satisfy the
 * signature of `SetByteArrayRegion`, which takes a non-`const` `jbyte*`
 * even for an output copy (the Java array is the destination, the source
 * vector is not modified).
 *
 * The array returned is a local reference: it becomes the
 * responsibility of the native function that called it, and the garbage
 * collector on the Java side discards the array once it becomes unreachable.
 *
 * \param[in] env JNI context pointer (`JNIEnv`) of the calling thread.
 * \param[in] vec Source vector with the bytes to transfer.
 *
 * \return Newly created `byte[]` array with the content of `vec`, or `nullptr`
 * if `NewByteArray` fails.
 *
 * \warning The return value of `NewByteArray` is not checked. It returns `nullptr`
 * when there is no memory available (including when the requested size
 * exceeds the native stack limit). In that case
 * `SetByteArrayRegion` receives a null object, which is undefined
 * behavior.
 *
 * \note `vec.size()` is an unsigned `size_t` and is converted to `jsize`
 * (32-bit integer). Vectors above `INT32_MAX` bytes cause
 * silent truncation of the length.
 *
 * \note The function has external linkage (it is not `static`), although it is used
 * only within this file.
 * @endcond */
// Convert std::vector<uint8_t> to jbyteArray
jbyteArray vectorToJByteArray(JNIEnv* env, const std::vector<uint8_t>& vec) {
    jsize len = vec.size();
    jbyteArray arr = env->NewByteArray(len);
    env->SetByteArrayRegion(arr, 0, len, const_cast<jbyte*>(reinterpret_cast<const jbyte*>(vec.data())));
    return arr;
}

// KeyPair class
/**
 * @cond PORT
 * \var keyPairClass
 * \brief Referência global à classe `com.libzupt.KeyPair`.
 *
 * \details É resolvida de forma sob demanda pela primeira função que
 * precisa dela: \ref createKeyPair ou
 * \ref Java_com_libzupt_KeyGenerator_saveKeyPair. Serve também como
 * sinalizador de "campos já resolvidos", pois
 * \ref publicKeyField e \ref secretKeyField são consultados no
 * mesmo bloco de inicialização. Não há proteção contra
 * concorrência.
 * @endcond
 * @cond INGLES
 * \var keyPairClass
 * \brief Global reference to the `com.libzupt.KeyPair` class.
 *
 * \details It is resolved lazily by the first function that
 * needs it: \ref createKeyPair or
 * \ref Java_com_libzupt_KeyGenerator_saveKeyPair. It also serves as
 * the "fields already resolved" flag, since
 * \ref publicKeyField and \ref secretKeyField are queried in the
 * same initialization block. There is no protection against
 * concurrency.
 * @endcond */
static jclass keyPairClass = nullptr;

/**
 * @cond PORT
 * \var publicKeyField
 * \brief Identificador do campo `publicKey` (tipo `[B`) de
 * `com.libzupt.KeyPair`.
 *
 * \details Resolvido junto com \ref keyPairClass. É usado para ler o campo
 * ao salvar (`GetObjectField`) e para gravá-lo ao construir o objeto
 * de retorno (`SetObjectField`). Vale `nullptr` se a resolução de
 * campos falhou ou ainda não aconteceu.
 *
 * \warning `com.libzupt.Encryptor` e `com.libzupt.Decryptor` também têm um
 * campo de nome `publicKey`/`secretKey`, mas cada um é resolvido com
 * `GetFieldID` sobre a classe do próprio objeto, dentro das funções
 * nativas correspondentes; este identificador vale apenas para
 * `KeyPair`.
 * @endcond
 * @cond INGLES
 * \var publicKeyField
 * \brief Identifier of the `publicKey` field (type `[B`) of
 * `com.libzupt.KeyPair`.
 *
 * \details Resolved together with \ref keyPairClass. It is used to read the field
 * when saving (`GetObjectField`) and to write it when building the
 * return object (`SetObjectField`). It is `nullptr` if field
 * resolution failed or has not happened yet.
 *
 * \warning `com.libzupt.Encryptor` and `com.libzupt.Decryptor` also have a
 * field named `publicKey`/`secretKey`, but each one is resolved with
 * `GetFieldID` over the class of the object itself, inside the
 * corresponding native functions; this identifier is valid only for
 * `KeyPair`.
 * @endcond */
static jfieldID publicKeyField = nullptr;

/**
 * @cond PORT
 * \var secretKeyField
 * \brief Identificador do campo `secretKey` (tipo `[B`) de
 * `com.libzupt.KeyPair`.
 *
 * \details Resolvido junto com \ref keyPairClass e usado nas mesmas duas
 * operações de \ref publicKeyField. Por guardar chave privada, os
 * caminhos que o usam merecem a mesma atenção quanto à limpeza dos
 * buffers temporários descrita no cabeçalho deste arquivo.
 * @endcond
 * @cond INGLES
 * \var secretKeyField
 * \brief Identifier of the `secretKey` field (type `[B`) of
 * `com.libzupt.KeyPair`.
 *
 * \details Resolved together with \ref keyPairClass and used in the same two
 * operations as \ref publicKeyField. Because it holds a private key, the
 * paths that use it deserve the same attention regarding the wiping of
 * the temporary buffers described in the header of this file.
 * @endcond */
static jfieldID secretKeyField = nullptr;

/**
 * @cond PORT
 * \brief Constrói um objeto `com.libzupt.KeyPair` a partir de um
 * `zupt::KeyPair` da biblioteca.
 * \details Na primeira chamada resolve `com/libzupt/KeyPair` e os
 * identificadores de campo (\ref keyPairClass, \ref publicKeyField,
 * \ref secretKeyField). Depois cria a instância com
 * `NewObject(keyPairClass, GetMethodID(keyPairClass, "<init>",
 * "()V"))` e copia os dois vetores para campos da instância via
 * \ref vectorToJByteArray + `SetObjectField`.
 *
 * O construtor Java de `KeyPair()` apenas inicializa os dois campos
 * como matrizes de tamanho zero; os valores reais chegam pelos dois
 * `SetObjectField`.
 *
 * \param[in] env Ponteiro do contexto JNI (`JNIEnv`) da thread chamadora.
 * \param[in] kp  Par de chaves da biblioteca a transferir para Java.
 *
 * \return Referência local ao objeto `KeyPair` preenchido.
 *
 * \warning `NewObject` é chamado com o resultado de `GetMethodID` para
 * `<init>` como segundo argumento, sem testar nenhum dos dois. Se a
 * classe não pôde ser resolvida (`keyPairClass == nullptr`) ou o
 * construtor não existir, o comportamento é indefinido.
 *
 * \warning `GetMethodID(keyPairClass, "<init>", "()V")` é executado a cada
 * chamada, embora o resultado pudesse ser cacheado junto com os
 * campos, como os outros identificadores estáticos deste arquivo.
 *
 * \warning As duas matrizes criadas por \ref vectorToJByteArray são
 * referências locais que nunca são liberadas com
 * `DeleteLocalRef`. Elas sobrevivem até o retorno da função nativa
 * que chamou este helper (limite de referências locais da JVM).
 *
 * \note Os vetores de `kp` (que contêm chave privada) não são limpos com
 * `zupt::secureWipe()` após a cópia, e o `zupt::KeyPair` local da função
 * chamadora também não.
 * @endcond
 * @cond INGLES
 * \brief Builds a `com.libzupt.KeyPair` object from a
 * `zupt::KeyPair` of the library.
 * \details On the first call it resolves `com/libzupt/KeyPair` and the
 * field identifiers (\ref keyPairClass, \ref publicKeyField,
 * \ref secretKeyField). Then it creates the instance with
 * `NewObject(keyPairClass, GetMethodID(keyPairClass, "<init>",
 * "()V"))` and copies the two vectors into instance fields via
 * \ref vectorToJByteArray + `SetObjectField`.
 *
 * The Java constructor of `KeyPair()` only initializes the two fields
 * as zero-length arrays; the actual values arrive through the two
 * `SetObjectField` calls.
 *
 * \param[in] env JNI context pointer (`JNIEnv`) of the calling thread.
 * \param[in] kp  Library key pair to transfer to Java.
 *
 * \return Local reference to the filled `KeyPair` object.
 *
 * \warning `NewObject` is called with the result of `GetMethodID` for
 * `<init>` as the second argument, without testing either. If the
 * class could not be resolved (`keyPairClass == nullptr`) or the
 * constructor does not exist, the behavior is undefined.
 *
 * \warning `GetMethodID(keyPairClass, "<init>", "()V")` is executed on every
 * call, although the result could be cached together with the
 * fields, like the other static identifiers of this file.
 *
 * \warning The two arrays created by \ref vectorToJByteArray are
 * local references that are never released with
 * `DeleteLocalRef`. They survive until the return of the native function
 * that called this helper (JVM local reference limit).
 *
 * \note The vectors of `kp` (which contain a private key) are not wiped with
 * `zupt::secureWipe()` after the copy, and neither is the caller's local
 * `zupt::KeyPair`.
 * @endcond */
jobject createKeyPair(JNIEnv* env, const zupt::KeyPair& kp) {
    if (!keyPairClass) {
        jclass cls = env->FindClass("com/libzupt/KeyPair");
        if (cls) {
            keyPairClass = (jclass)env->NewGlobalRef(cls);
            publicKeyField = env->GetFieldID(keyPairClass, "publicKey", "[B");
            secretKeyField = env->GetFieldID(keyPairClass, "secretKey", "[B");
        }
    }

    jobject result = env->NewObject(keyPairClass, env->GetMethodID(keyPairClass, "<init>", "()V"));
    env->SetObjectField(result, publicKeyField, vectorToJByteArray(env, kp.public_key));
    env->SetObjectField(result, secretKeyField, vectorToJByteArray(env, kp.secret_key));
    return result;
}

/**
 * @cond PORT
 * \brief Declarações antecipadas dos métodos nativos vinculados em
 * \ref JNI_OnLoad.
 *
 * \details As quatro tabelas de vínculo (`JNINativeMethod[]`) definidas logo
 * abaixo precisam do endereço de cada função, e esse endereço só é
 * obtido se a função estiver declarada antes da tabela — as
 * implementações vêm bem mais adiante neste arquivo. Os nomes
 * seguem a convenção padrão do JNI (`Java_com_libzupt_<Classe>_<método>`),
 * embora a vinculação por `RegisterNatives` dispense essa
 * exigência.
 *
 * \note Apenas as funções efetivamente listadas nas tabelas estão declaradas
 * aqui. `Java_com_libzupt_Encryptor_nativeEncryptMemorySecure` e
 * `Java_com_libzupt_Decryptor_decryptMemorySecure` têm implementação
 * neste arquivo, mas não aparecem nesta lista, não aparecem em
 * nenhuma das tabelas de vínculo e não têm declaração nativa
 * correspondente nos arquivos Java do pacote `com.libzupt` (ver os
 * blocos de documentação dessas duas funções).
 * @endcond
 * @cond INGLES
 * \brief Forward declarations of the native methods bound in
 * \ref JNI_OnLoad.
 *
 * \details The four binding tables (`JNINativeMethod[]`) defined just
 * below need the address of each function, and that address is only
 * obtained if the function is declared before the table — the
 * implementations come much later in this file. The names
 * follow the standard JNI convention (`Java_com_libzupt_<Class>_<method>`),
 * although binding through `RegisterNatives` waives that
 * requirement.
 *
 * \note Only the functions actually listed in the tables are declared
 * here. `Java_com_libzupt_Encryptor_nativeEncryptMemorySecure` and
 * `Java_com_libzupt_Decryptor_decryptMemorySecure` have an implementation
 * in this file, but do not appear in this list, do not appear in
 * any of the binding tables and have no corresponding native
 * declaration in the Java files of the `com.libzupt` package (see the
 * documentation blocks of those two functions).
 * @endcond */
// Forward declarations for native methods
JNIEXPORT jobject JNICALL Java_com_libzupt_KeyGenerator_generateKeyPair(JNIEnv*, jobject);
JNIEXPORT jobject JNICALL Java_com_libzupt_KeyGenerator_loadKeyPair(JNIEnv*, jobject, jstring);
JNIEXPORT jbyteArray JNICALL Java_com_libzupt_KeyGenerator_loadPublicKey(JNIEnv*, jobject, jstring);
JNIEXPORT void JNICALL Java_com_libzupt_KeyGenerator_exportPublicKey(JNIEnv*, jobject, jstring, jstring);
JNIEXPORT void JNICALL Java_com_libzupt_KeyGenerator_saveKeyPair(JNIEnv*, jobject, jobject, jstring);
JNIEXPORT jobject JNICALL Java_com_libzupt_Encryptor_nativeEncryptMemory(JNIEnv*, jobject, jbyteArray);
JNIEXPORT jobject JNICALL Java_com_libzupt_Encryptor_nativeEncryptMemorySecure(JNIEnv*, jobject, jbyteArray);
JNIEXPORT jobject JNICALL Java_com_libzupt_Encryptor_nativeEncryptFile(JNIEnv*, jobject, jstring);
JNIEXPORT jbyteArray JNICALL Java_com_libzupt_Decryptor_decryptMemoryNative(JNIEnv*, jobject, jbyteArray, jbyteArray);
JNIEXPORT jbyteArray JNICALL Java_com_libzupt_Decryptor_decryptFileNative(JNIEnv*, jobject, jstring, jbyteArray);
JNIEXPORT jbyteArray JNICALL Java_com_libzupt_NativeLib_randomBytes(JNIEnv*, jobject, jint);
JNIEXPORT jbyteArray JNICALL Java_com_libzupt_NativeLib_sha256(JNIEnv*, jobject, jbyteArray);
JNIEXPORT jbyteArray JNICALL Java_com_libzupt_NativeLib_sha3512(JNIEnv*, jobject, jbyteArray);

// Native method declarations
/**
 * @cond PORT
 * \var keyGenMethods
 * \brief Tabela de vínculo dos métodos nativos de `com.libzupt.KeyGenerator`.
 *
 * \details Cada linha associa o nome simples do método nativo, a assinatura
 * JNI em formato de descritor e o endereço da implementação. A
 * contagem de elementos (5) é passada como argumento fixo em
 * \ref JNI_OnLoad.
 *
 * \warning O número de elementos é informado manualmente
 * (`RegisterNatives(..., keyGenMethods, 5)`), e o tamanho da tabela é
 * deduzido pelo compilador. Adicionar ou remover uma linha sem
 * atualizar o literal em \ref JNI_OnLoad faz o JNI ler a tabela fora
 * dos limites.
 *
 * \note Os descritores retornam `Lcom/libzupt/KeyPair;` para
 * `generateKeyPair`/`loadKeyPair` e `[B` para `loadPublicKey`, o que
 * corresponde aos tipos de retorno das implementações.
 * @endcond
 * @cond INGLES
 * \var keyGenMethods
 * \brief Binding table for the native methods of `com.libzupt.KeyGenerator`.
 *
 * \details Each line associates the simple name of the native method, the JNI
 * signature in descriptor form and the address of the implementation. The
 * element count (5) is passed as a fixed argument in
 * \ref JNI_OnLoad.
 *
 * \warning The number of elements is provided manually
 * (`RegisterNatives(..., keyGenMethods, 5)`), and the size of the table is
 * inferred by the compiler. Adding or removing a line without
 * updating the literal in \ref JNI_OnLoad makes JNI read the table out
 * of bounds.
 *
 * \note The descriptors return `Lcom/libzupt/KeyPair;` for
 * `generateKeyPair`/`loadKeyPair` and `[B` for `loadPublicKey`, which
 * matches the return types of the implementations.
 * @endcond */
static JNINativeMethod keyGenMethods[] = {
    {"generateKeyPair", "()Lcom/libzupt/KeyPair;", (void*)Java_com_libzupt_KeyGenerator_generateKeyPair},
    {"loadKeyPair", "(Ljava/lang/String;)Lcom/libzupt/KeyPair;", (void*)Java_com_libzupt_KeyGenerator_loadKeyPair},
    {"loadPublicKey", "(Ljava/lang/String;)[B", (void*)Java_com_libzupt_KeyGenerator_loadPublicKey},
    {"exportPublicKey", "(Ljava/lang/String;Ljava/lang/String;)V", (void*)Java_com_libzupt_KeyGenerator_exportPublicKey},
    {"saveKeyPair", "(Lcom/libzupt/KeyPair;Ljava/lang/String;)V", (void*)Java_com_libzupt_KeyGenerator_saveKeyPair}
};

/**
 * @cond PORT
 * \var encryptorMethods
 * \brief Tabela de vínculo dos métodos nativos de `com.libzupt.Encryptor`.
 *
 * \details Contém dois métodos: `nativeEncryptMemory` e `nativeEncryptFile`.
 * Ambos têm descritor de retorno `[Ljava/lang/Object;`, ou seja,
 * `java.lang.Object[]`, e a implementação devolve de fato uma
 * `jobjectArray` de dois elementos, cada um uma matriz de bytes
 * (`[B`): texto cifrado na posição 0 e cabeçalho na posição 1.
 *
 * \warning `Java_com_libzupt_Encryptor_nativeEncryptMemorySecure` está
 * implementado neste arquivo, mas não está nesta tabela, não está na
 * lista de declarações antecipadas e `Encryptor.java` não declara
 * nenhum método nativo com esse nome. Do lado Java,
 * `encryptMemorySecure(SecureBuffer)` chama `nativeEncryptMemory`, de
 * modo que a implementação com nome "secure" não é alcançável.
 *
 * \warning `Encryptor.java` é a única classe do pacote `com.libzupt` com
 * métodos nativos que não tem um bloco estático com
 * `System.loadLibrary("Jzupt")` (`KeyGenerator.java`,
 * `Decryptor.java` e `NativeLib.java` têm). Se a aplicação usar
 * apenas `Encryptor`, a biblioteca nunca é carregada: a função
 * \ref JNI_OnLoad não executa, nenhum método é registrado e as
 * chamadas resultam em `UnsatisfiedLinkError`.
 *
 * \note A contagem de elementos (2) é um literal repetido em
 * \ref JNI_OnLoad.
 * @endcond
 * @cond INGLES
 * \var encryptorMethods
 * \brief Binding table for the native methods of `com.libzupt.Encryptor`.
 *
 * \details Contains two methods: `nativeEncryptMemory` and `nativeEncryptFile`.
 * Both have a `[Ljava/lang/Object;` return descriptor, that is,
 * `java.lang.Object[]`, and the implementation does return a
 * `jobjectArray` of two elements, each one a byte array
 * (`[B`): ciphertext at position 0 and header at position 1.
 *
 * \warning `Java_com_libzupt_Encryptor_nativeEncryptMemorySecure` is
 * implemented in this file, but is not in this table, is not in the
 * forward-declaration list and `Encryptor.java` declares no
 * native method with that name. On the Java side,
 * `encryptMemorySecure(SecureBuffer)` calls `nativeEncryptMemory`, so the
 * implementation with the "secure" name is unreachable.
 *
 * \warning `Encryptor.java` is the only class of the `com.libzupt` package
 * with native methods that has no static block with
 * `System.loadLibrary("Jzupt")` (`KeyGenerator.java`,
 * `Decryptor.java` and `NativeLib.java` do). If the application uses
 * only `Encryptor`, the library is never loaded: the
 * \ref JNI_OnLoad function does not run, no method is registered and the
 * calls result in `UnsatisfiedLinkError`.
 *
 * \note The element count (2) is a literal repeated in
 * \ref JNI_OnLoad.
 * @endcond */
static JNINativeMethod encryptorMethods[] = {
    {"nativeEncryptMemory", "([B)[Ljava/lang/Object;", (void*)Java_com_libzupt_Encryptor_nativeEncryptMemory},
    {"nativeEncryptFile", "(Ljava/lang/String;)[Ljava/lang/Object;", (void*)Java_com_libzupt_Encryptor_nativeEncryptFile}
};

/**
 * @cond PORT
 * \var decryptorMethods
 * \brief Tabela de vínculo dos métodos nativos de `com.libzupt.Decryptor`.
 *
 * \details Contém `decryptMemoryNative` e `decryptFileNative`, ambos com
 * retorno `byte[]` (descritor `[B`), o que corresponde a
 * `jbyteArray` nas implementações.
 *
 * \warning `Java_com_libzupt_Decryptor_decryptMemorySecure` está implementado
 * neste arquivo, mas não está nesta tabela, não está na lista de
 * declarações antecipadas e `Decryptor.java` não declara nenhum
 * método nativo com esse nome. O método Java de mesmo nome chama
 * `decryptMemoryNative` e apenas envolve o resultado com um
 * `SecureBuffer` no lado Java, de modo que a implementação nativa com
 * nome "secure" não é alcançável.
 *
 * \note A contagem de elementos (2) é um literal repetido em
 * \ref JNI_OnLoad.
 * @endcond
 * @cond INGLES
 * \var decryptorMethods
 * \brief Binding table for the native methods of `com.libzupt.Decryptor`.
 *
 * \details Contains `decryptMemoryNative` and `decryptFileNative`, both with
 * a `byte[]` return (descriptor `[B`), which corresponds to
 * `jbyteArray` in the implementations.
 *
 * \warning `Java_com_libzupt_Decryptor_decryptMemorySecure` is implemented
 * in this file, but is not in this table, is not in the list of
 * forward declarations and `Decryptor.java` declares no native
 * method with that name. The Java method of the same name calls
 * `decryptMemoryNative` and only wraps the result with a
 * `SecureBuffer` on the Java side, so the native implementation with
 * the "secure" name is unreachable.
 *
 * \note The element count (2) is a literal repeated in
 * \ref JNI_OnLoad.
 * @endcond */
static JNINativeMethod decryptorMethods[] = {
    {"decryptMemoryNative", "([B[B)[B", (void*)Java_com_libzupt_Decryptor_decryptMemoryNative},
    {"decryptFileNative", "(Ljava/lang/String;[B)[B", (void*)Java_com_libzupt_Decryptor_decryptFileNative}
};

/**
 * @cond PORT
 * \var nativeLibMethods
 * \brief Tabela de vínculo dos métodos nativos de `com.libzupt.NativeLib`.
 *
 * \details Agrupa as três funções utilitárias expostas sem estado:
 * `randomBytes` (descritor `(I)[B`), `sha256` e `sha3512` (ambos
 * `([B)[B`). No lado Java, `NativeLib` declara os três como `public
 * static native`, sem métodos de envolventes e sem validação de
 * argumentos.
 *
 * \note A contagem de elementos (3) é um literal repetido em
 * \ref JNI_OnLoad.
 *
 * \warning `NativeLib.java` tem uma abertura de comentário de documentação
 * não fechada entre o bloco estático de carga da biblioteca e o bloco
 * de documentação de `randomBytes`, o que compromete a documentação da
 * classe na ferramenta de documentação do Java.
 * @endcond
 * @cond INGLES
 * \var nativeLibMethods
 * \brief Binding table for the native methods of `com.libzupt.NativeLib`.
 *
 * \details Groups the three stateless utility functions exposed:
 * `randomBytes` (descriptor `(I)[B`), `sha256` and `sha3512` (both
 * `([B)[B`). On the Java side, `NativeLib` declares the three of them as
 * `public static native`, with no wrapper methods and with no argument
 * validation.
 *
 * \note The element count (3) is a literal repeated in
 * \ref JNI_OnLoad.
 *
 * \warning `NativeLib.java` has an unclosed documentation comment
 * opening between the static library-loading block and the
 * documentation block of `randomBytes`, which compromises the class
 * documentation in the Java documentation tool.
 * @endcond */
static JNINativeMethod nativeLibMethods[] = {
    {"randomBytes", "(I)[B", (void*)Java_com_libzupt_NativeLib_randomBytes},
    {"sha256", "([B)[B", (void*)Java_com_libzupt_NativeLib_sha256},
    {"sha3512", "([B)[B", (void*)Java_com_libzupt_NativeLib_sha3512}
};

/**
 * @cond PORT
 * \brief Função de inicialização da biblioteca nativa, chamada pela JVM no
 * carregamento de `libJzupt.so`.
 *
 * \details Executa duas tarefas:
 * - Negocia a versão do JNI com `GetEnv` pedindo
 * `JNI_VERSION_1_8`; se a JVM não suportar essa versão, devolve
 * `JNI_ERR` e o carregamento da biblioteca falha.
 * - Registra os métodos nativos de cada classe com
 * `RegisterNatives`, usando as quatro tabelas `static
 * JNINativeMethod[]` deste arquivo: \ref keyGenMethods (5),
 * \ref encryptorMethods (2), \ref decryptorMethods (2) e
 * \ref nativeLibMethods (3).
 *
 * Não resolve as referências de classe cacheadas
 * (\ref zuptErrorClass, \ref keyPairClass) — essas continuam
 * resolvidas sob demanda.
 *
 * \param[in] vm Ponteiro da `JavaVM` da aplicação.
 * <b>reserved</b> (parâmetro sem nome na assinatura) Reservado pela especificação
 * JNI; não usado (o nome está comentado no código).
 *
 * \return `JNI_VERSION_1_8` em caso de sucesso, ou `JNI_ERR` se `GetEnv`
 * falhar ou se alguma das quatro chamadas `RegisterNatives` retornar
 * valor negativo.
 *
 * \warning O registro só é tentado quando `FindClass` obteve a classe, pelo
 * curto-circuito em `if (cls && RegisterNatives(...) < 0)`. Quando
 * `FindClass` retorna `nullptr`, a classe é ignorada em silêncio e a
 * função continua, podendo devolver `JNI_VERSION_1_8`: a biblioteca
 * aparece como carregada, mas os métodos daquela classe ficam sem
 * vínculo e a falha só aparece depois, como `UnsatisfiedLinkError` na
 * primeira chamada.
 *
 * \note Quando `FindClass` falha, o JNI deixa uma exceção
 * `NoClassDefFoundError` pendente na `env`, e este código não a limpa.
 * Essa exceção pendente atravessa o retorno de `JNI_OnLoad`.
 *
 * \warning As contagens de métodos de cada tabela são literais (5, 2, 2, 3)
 * repetidos aqui, e não `sizeof` das tabelas.
 *
 * \note As quatro referências locais de classe (`keyGenClass`,
 * `encryptClass`, `decryptClass`, `nativeLibClass`) não são liberadas
 * com `DeleteLocalRef`.
 *
 * \note Este arquivo não implementa `JNI_OnUnload`, então as referências
 * globais criadas em \ref throwJavaException e \ref createKeyPair não
 * são liberadas ao descarregar a biblioteca.
 * @endcond
 * @cond INGLES
 * \brief Initialization function of the native library, called by the JVM on
 * loading of `libJzupt.so`.
 *
 * \details Performs two tasks:
 * - Negotiates the JNI version with `GetEnv` requesting
 * `JNI_VERSION_1_8`; if the JVM does not support that version, it returns
 * `JNI_ERR` and the loading of the library fails.
 * - Registers the native methods of each class with
 * `RegisterNatives`, using the four `static
 * JNINativeMethod[]` tables of this file: \ref keyGenMethods (5),
 * \ref encryptorMethods (2), \ref decryptorMethods (2) and
 * \ref nativeLibMethods (3).
 *
 * It does not resolve the cached class references
 * (\ref zuptErrorClass, \ref keyPairClass) — those remain
 * resolved lazily.
 *
 * \param[in] vm Pointer to the application's `JavaVM`.
 * <b>reserved</b> (parameter without a name in the signature) Reserved by the JNI
 * specification; not used (the name is commented out in the code).
 *
 * \return `JNI_VERSION_1_8` on success, or `JNI_ERR` if `GetEnv`
 * fails or if any of the four `RegisterNatives` calls returns a
 * negative value.
 *
 * \warning Registration is only attempted when `FindClass` obtained the class, due
 * to the short-circuit in `if (cls && RegisterNatives(...) < 0)`. When
 * `FindClass` returns `nullptr`, the class is silently skipped and the
 * function continues, possibly returning `JNI_VERSION_1_8`: the library
 * appears as loaded, but the methods of that class remain unbound and the
 * failure only shows up later, as `UnsatisfiedLinkError` on the
 * first call.
 *
 * \note When `FindClass` fails, JNI leaves a
 * `NoClassDefFoundError` exception pending in `env`, and this code does not
 * clear it. That pending exception outlives the return of `JNI_OnLoad`.
 *
 * \warning The method counts of each table are literals (5, 2, 2, 3)
 * repeated here, and not `sizeof` of the tables.
 *
 * \note The four local class references (`keyGenClass`,
 * `encryptClass`, `decryptClass`, `nativeLibClass`) are not released
 * with `DeleteLocalRef`.
 *
 * \note This file does not implement `JNI_OnUnload`, so the global
 * references created in \ref throwJavaException and \ref createKeyPair are
 * not released when the library is unloaded.
 * @endcond */
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* /* reserved */) {
    JNIEnv* env;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_8) != JNI_OK) {
        return JNI_ERR;
    }

    // Register native methods for KeyGenerator
    jclass keyGenClass = env->FindClass("com/libzupt/KeyGenerator");
    if (keyGenClass && env->RegisterNatives(keyGenClass, keyGenMethods, 5) < 0) {
        return JNI_ERR;
    }

    // Register native methods for Encryptor
    jclass encryptClass = env->FindClass("com/libzupt/Encryptor");
    if (encryptClass && env->RegisterNatives(encryptClass, encryptorMethods, 2) < 0) {
        return JNI_ERR;
    }

    // Register native methods for Decryptor
    jclass decryptClass = env->FindClass("com/libzupt/Decryptor");
    if (decryptClass && env->RegisterNatives(decryptClass, decryptorMethods, 2) < 0) {
        return JNI_ERR;
    }

    // Register native methods for NativeLib (helpers)
    jclass nativeLibClass = env->FindClass("com/libzupt/NativeLib");
    if (nativeLibClass && env->RegisterNatives(nativeLibClass, nativeLibMethods, 3) < 0) {
        return JNI_ERR;
    }

    return JNI_VERSION_1_8;
}

// KeyGenerator native methods
/**
 * @cond PORT
 * \brief Implementação nativa de `KeyGenerator.generateKeyPair()`.
 *
 * \details Constrói um `zupt::KeyGenerator` na pilha, chama
 * `generateKeyPair()` da biblioteca e converte o resultado em objeto
 * `com.libzupt.KeyPair` com \ref createKeyPair. Todo o corpo está
 * protegido por `try` / `catch (const std::exception& e)`, que
 * converte a exceção C++ em exceção Java via \ref throwJavaException.
 *
 * \param[in] env Ponteiro do contexto JNI (`JNIEnv`) da thread chamadora.
 * <b>self</b> (parâmetro sem nome na assinatura) Instância de
 * `com.libzupt.KeyGenerator` que chamou o método. Não é usada (o nome
 * está comentado na assinatura), pois a classe não guarda estado.
 * classe não guarda estado.
 *
 * \return Referência local ao objeto `KeyPair` recém-gerado, ou `nullptr` se
 * uma exceção foi lançada (caso em que a chamada Java nunca vê o
 * valor de retorno).
 *
 * \note As exceções de `zupt::KeyGenerator::generateKeyPair()` — por exemplo
 * falha do gerador de aleatoriedade — chegam como `ZuptError` no lado
 * Java, com a mensagem de `e.what()`. `std::bad_alloc` também cai nesta
 * mesma tradução.
 *
 * \note `kp` local contém a chave privada e não é limpo com
 * `zupt::secureWipe()` antes do retorno; as cópias em Java também não
 * são limpas (ver \ref createKeyPair).
 * @endcond
 * @cond INGLES
 * \brief Native implementation of `KeyGenerator.generateKeyPair()`.
 *
 * \details Builds a `zupt::KeyGenerator` on the stack, calls
 * the library's `generateKeyPair()` and converts the result into a
 * `com.libzupt.KeyPair` object with \ref createKeyPair. The whole body is
 * protected by `try` / `catch (const std::exception& e)`, which
 * converts the C++ exception into a Java exception via \ref throwJavaException.
 *
 * \param[in] env JNI context pointer (`JNIEnv`) of the calling thread.
 * <b>self</b> (parameter without a name in the signature) `com.libzupt.KeyGenerator`
 * instance that called the method. Not used (the name
 * is commented out in the signature), because the class holds no state.
 *
 * \return Local reference to the newly generated `KeyPair` object, or `nullptr` if
 * an exception was thrown (in which case the Java call never sees the
 * return value).
 *
 * \note The exceptions of `zupt::KeyGenerator::generateKeyPair()` — for example
 * a failure of the randomness generator — arrive as `ZuptError` on the Java
 * side, with the message of `e.what()`. `std::bad_alloc` also falls into this
 * same translation.
 *
 * \note The local `kp` contains the private key and is not wiped with
 * `zupt::secureWipe()` before the return; the copies in Java are not
 * wiped either (see \ref createKeyPair).
 * @endcond */
JNIEXPORT jobject JNICALL Java_com_libzupt_KeyGenerator_generateKeyPair(JNIEnv* env, jobject /* self */) {
    try {
        zupt::KeyGenerator kg;
        zupt::KeyPair kp = kg.generateKeyPair();
        return createKeyPair(env, kp);
    } catch (const std::exception& e) {
        throwJavaException(env, e);
        return nullptr;
    }
}

/**
 * @cond PORT
 * \brief Implementação nativa de `KeyGenerator.loadKeyPair(String)`.
 *
 * \details Converte o argumento `String` para UTF-8 com
 * `GetStringUTFChars`, chama `loadKeyPair()` da biblioteca e monta o
 * objeto `com.libzupt.KeyPair` de resposta com \ref createKeyPair. A
 * liberação da string é feita com `ReleaseStringUTFChars` logo após a
 * leitura, antes da construção do objeto Java.
 *
 * \param[in] env Ponteiro do contexto JNI (`JNIEnv`) da thread chamadora.
 * <b>self</b> (parâmetro sem nome na assinatura) Instância de
 * `com.libzupt.KeyGenerator` que chamou o método. Não é usada.
 * \param[in] jfilename Nome do arquivo de chave privada no formato `ZKEY`,
 * como `java.lang.String`.
 *
 * \return Referência local ao objeto `KeyPair` carregado, ou `nullptr` se uma
 * exceção foi lançada.
 *
 * \warning O retorno de `GetStringUTFChars` não é verificado. Ele pode
 * devolver `nullptr` quando a JVM não consegue alocar o buffer de
 * conversão, e nesse caso `filename` é passado nulo para
 * `loadKeyPair()`, que o trata como `std::string` a partir de um
 * ponteiro nulo (comportamento indefinido).
 *
 * \warning Se `loadKeyPair()` lançar exceção, o `ReleaseStringUTFChars` da
 * linha seguinte não é executado: o buffer UTF-8 fica sem liberação.
 * Como a thread logo retorna à JVM, o dano é limitado, mas o padrão
 * seguro seria liberar antes de relançar (RAII).
 *
 * \note `filename` é uma string UTF-8 modificada (Modified UTF-8 do JNI), não
 * necessariamente UTF-8 padrão; caminhos com caracteres não ASCII fora
 * do BMP podem não ser interpretados como o chamador espera.
 *
 * \note Ao contrário do que fazem as ligações Node.js e Python, este caminho
 * não limpa a chave privada dos buffers temporários.
 * @endcond
 * @cond INGLES
 * \brief Native implementation of `KeyGenerator.loadKeyPair(String)`.
 *
 * \details Converts the `String` argument to UTF-8 with
 * `GetStringUTFChars`, calls the library's `loadKeyPair()` and builds the
 * `com.libzupt.KeyPair` response object with \ref createKeyPair. The
 * release of the string is done with `ReleaseStringUTFChars` right after
 * the read, before the construction of the Java object.
 *
 * \param[in] env JNI context pointer (`JNIEnv`) of the calling thread.
 * <b>self</b> (parameter without a name in the signature) `com.libzupt.KeyGenerator`
 * instance that called the method. Not used.
 * \param[in] jfilename Name of the private key file in `ZKEY` format,
 * as a `java.lang.String`.
 *
 * \return Local reference to the loaded `KeyPair` object, or `nullptr` if an
 * exception was thrown.
 *
 * \warning The return value of `GetStringUTFChars` is not checked. It can
 * return `nullptr` when the JVM cannot allocate the buffer for the
 * conversion, and in that case `filename` is passed as null to
 * `loadKeyPair()`, which treats it as a `std::string` built from a
 * null pointer (undefined behavior).
 *
 * \warning If `loadKeyPair()` throws an exception, the `ReleaseStringUTFChars`
 * of the next line is not executed: the UTF-8 buffer is left unreleased.
 * Since the thread returns to the JVM shortly after, the damage is
 * limited, but the safe pattern would be to release before rethrowing
 * (RAII).
 *
 * \note `filename` is a modified UTF-8 string (JNI Modified UTF-8), not
 * necessarily standard UTF-8; paths with non-ASCII characters outside
 * the BMP may not be interpreted as the caller expects.
 *
 * \note Unlike what the Node.js and Python bindings do, this path
 * does not wipe the private key from the temporary buffers.
 * @endcond */
JNIEXPORT jobject JNICALL Java_com_libzupt_KeyGenerator_loadKeyPair(JNIEnv* env, jobject /* self */, jstring jfilename) {
    try {
        const char* filename = env->GetStringUTFChars(jfilename, nullptr);
        zupt::KeyGenerator kg;
        zupt::KeyPair kp = kg.loadKeyPair(filename);
        env->ReleaseStringUTFChars(jfilename, filename);
        return createKeyPair(env, kp);
    } catch (const std::exception& e) {
        throwJavaException(env, e);
        return nullptr;
    }
}

/**
 * @cond PORT
 * \brief Implementação nativa de `KeyGenerator.loadPublicKey(String)`.
 *
 * \details Converte o nome do arquivo para UTF-8, chama `loadPublicKey()` da
 * biblioteca e devolve o resultado como matriz `byte[]` criada por
 * \ref vectorToJByteArray. A string UTF-8 é liberada com
 * `ReleaseStringUTFChars` antes da conversão da resposta.
 *
 * O conteúdo devolvido é o arquivo inteiro no formato `ZKEY` (1224
 * bytes, com magic, versão, flags e a chave pública embutida), que é
 * exatamente o formato aceito pelo construtor de `zupt::Encryptor`.
 *
 * \param[in] env Ponteiro do contexto JNI (`JNIEnv`) da thread chamadora.
 * <b>self</b> (parâmetro sem nome na assinatura) Instância de
 * `com.libzupt.KeyGenerator` que chamou o método. Não é usada.
 * \param[in] jfilename Nome do arquivo de chave pública, como
 * `java.lang.String`.
 *
 * \return Matriz `byte[]` com o conteúdo da chave pública, ou `nullptr` se uma
 * exceção foi lançada.
 *
 * \warning `GetStringUTFChars` não é verificado quanto a `nullptr`, e o buffer
 * não é liberado se `loadPublicKey()` lançar exceção.
 *
 * \note As validações de formato (magic `ZKEY`, tamanho de 1224 bytes, versão
 * e flags) são feitas pela biblioteca e chegam ao Java como
 * `ZuptError`.
 *
 * \note `KeyGenerator.java` devolve essa matriz diretamente ao chamador, e o
 * exemplo a repassa ao construtor de `Encryptor`. Um arquivo de chave
 * pública de versão 1 é aceito nesta leitura, mas o `Encryptor` aceita
 * somente a versão 2: a falha então aparece mais tarde, na cifra.
 * @endcond
 * @cond INGLES
 * \brief Native implementation of `KeyGenerator.loadPublicKey(String)`.
 *
 * \details Converts the file name to UTF-8, calls the library's `loadPublicKey()`
 * and returns the result as a `byte[]` array created by
 * \ref vectorToJByteArray. The UTF-8 string is released with
 * `ReleaseStringUTFChars` before the conversion of the response.
 *
 * The content returned is the whole file in `ZKEY` format (1224
 * bytes, with magic, version, flags and the embedded public key), which is
 * exactly the format accepted by the constructor of `zupt::Encryptor`.
 *
 * \param[in] env JNI context pointer (`JNIEnv`) of the calling thread.
 * <b>self</b> (parameter without a name in the signature) `com.libzupt.KeyGenerator`
 * instance that called the method. Not used.
 * \param[in] jfilename Name of the public key file, as a
 * `java.lang.String`.
 *
 * \return `byte[]` array with the content of the public key, or `nullptr` if an
 * exception was thrown.
 *
 * \warning `GetStringUTFChars` is not checked for `nullptr`, and the buffer
 * is not released if `loadPublicKey()` throws an exception.
 *
 * \note The format validations (magic `ZKEY`, size of 1224 bytes, version
 * and flags) are performed by the library and reach Java as
 * `ZuptError`.
 *
 * \note `KeyGenerator.java` returns that array directly to the caller, and the
 * example passes it on to the constructor of `Encryptor`. A version 1 public key
 * file is accepted on this read, but `Encryptor` accepts
 * only version 2: the failure therefore appears later, during encryption.
 * @endcond */
JNIEXPORT jbyteArray JNICALL Java_com_libzupt_KeyGenerator_loadPublicKey(JNIEnv* env, jobject /* self */, jstring jfilename) {
    try {
        const char* filename = env->GetStringUTFChars(jfilename, nullptr);
        zupt::KeyGenerator kg;
        std::vector<uint8_t> publicKey = kg.loadPublicKey(filename);
        env->ReleaseStringUTFChars(jfilename, filename);
        return vectorToJByteArray(env, publicKey);
    } catch (const std::exception& e) {
        throwJavaException(env, e);
        return nullptr;
    }
}

/**
 * @cond PORT
 * \brief Implementação nativa de `KeyGenerator.exportPublicKey(String, String)`.
 *
 * \details Converte os dois argumentos `String` para UTF-8 e chama
 * `exportPublicKey()` da biblioteca, que lê a chave privada de
 * `privfile` e grava apenas a chave pública em `pubfile`. Depois
 * libera os dois buffers com `ReleaseStringUTFChars`. Não há valor de
 * retorno: o sucesso é indicado pela ausência de exceção.
 *
 * \param[in] env Ponteiro do contexto JNI (`JNIEnv`) da thread chamadora.
 * <b>self</b> (parâmetro sem nome na assinatura) Instância de
 * `com.libzupt.KeyGenerator` que chamou o método. Não é usada.
 * \param[in] jprivfile Caminho do arquivo de chave privada de origem.
 * \param[in] jpubfile Caminho do arquivo de chave pública de destino.
 *
 * \warning Os dois retornos de `GetStringUTFChars` não são verificados quanto
 * a `nullptr`.
 *
 * \warning Se `exportPublicKey()` lançar exceção, nenhuma das duas liberações
 * é executada; os buffers UTF-8 ficam sem liberação.
 *
 * \note O arquivo de destino é criado com as permissões padrão do processo. A
 * biblioteca não aplica aqui as restrições de permissão usadas ao gravar
 * chaves privadas, o que é aceitável porque o conteúdo é público.
 * @endcond
 * @cond INGLES
 * \brief Native implementation of `KeyGenerator.exportPublicKey(String, String)`.
 *
 * \details Converts the two `String` arguments to UTF-8 and calls
 * the library's `exportPublicKey()`, which reads the private key from
 * `privfile` and writes only the public key to `pubfile`. Then it
 * releases both buffers with `ReleaseStringUTFChars`. There is no return
 * value: success is indicated by the absence of an exception.
 *
 * \param[in] env JNI context pointer (`JNIEnv`) of the calling thread.
 * <b>self</b> (parameter without a name in the signature) `com.libzupt.KeyGenerator`
 * instance that called the method. Not used.
 * \param[in] jprivfile Path of the source private key file.
 * \param[in] jpubfile Path of the destination public key file.
 *
 * \warning The two return values of `GetStringUTFChars` are not checked for
 * `nullptr`.
 *
 * \warning If `exportPublicKey()` throws an exception, neither of the two
 * releases is executed; the UTF-8 buffers are left unreleased.
 *
 * \note The destination file is created with the default permissions of the process. The
 * library does not apply here the permission restrictions used when writing
 * private keys, which is acceptable because the content is public.
 * @endcond */
JNIEXPORT void JNICALL Java_com_libzupt_KeyGenerator_exportPublicKey(JNIEnv* env, jobject /* self */, jstring jprivfile, jstring jpubfile) {
    try {
        const char* privfile = env->GetStringUTFChars(jprivfile, nullptr);
        const char* pubfile = env->GetStringUTFChars(jpubfile, nullptr);
        zupt::KeyGenerator kg;
        kg.exportPublicKey(privfile, pubfile);
        env->ReleaseStringUTFChars(jprivfile, privfile);
        env->ReleaseStringUTFChars(jpubfile, pubfile);
    } catch (const std::exception& e) {
        throwJavaException(env, e);
    }
}

/**
 * @cond PORT
 * \brief Implementação nativa de `KeyGenerator.saveKeyPair(KeyPair, String)`.
 *
 * \details Lê os campos `publicKey` e `secretKey` do objeto
 * `com.libzupt.KeyPair` recebido (com `GetObjectField` + \ref
 * jbyteArrayToVector), monta um `zupt::KeyPair` por movimentação dos
 * dois vetores e chama `saveKeyPair()` da biblioteca, que grava a
 * chave privada em `filename` com permissões restritas.
 *
 * A resolução da classe e dos campos é feita aqui de forma sob
 * demanda, duplicando o bloco de inicialização de \ref
 * createKeyPair.
 *
 * \param[in] env Ponteiro do contexto JNI (`JNIEnv`) da thread chamadora.
 * <b>self</b> (parâmetro sem nome na assinatura) Instância de
 * `com.libzupt.KeyGenerator` que chamou o método. Não é usada.
 * \param[in] jkeypair Objeto `com.libzupt.KeyPair` com os campos a gravar.
 * \param[in] jfilename Caminho do arquivo de destino, como `java.lang.String`.
 *
 * \warning Este bloco de resolução é diferente do de \ref createKeyPair, ele
 * aplica `NewGlobalRef` diretamente sobre o resultado de `FindClass`,
 * sem testar se a classe foi encontrada. Se `FindClass` devolver
 * `nullptr`, a chamada é feita com um objeto nulo (comportamento
 * indefinido) e os dois `GetFieldID` seguintes passam a usar uma
 * classe nula.
 *
 * \warning Nenhum dos dois campos lidos é verificado. Se `jkeypair` for nulo,
 * ou se `publicKey`/`secretKey` forem `null` no objeto Java, a cópia
 * chega a `GetArrayLength` com um objeto nulo.
 *
 * \warning O retorno de `GetStringUTFChars` não é verificado, e a liberação
 * não acontece se `saveKeyPair()` lançar exceção.
 *
 * \note `zupt::KeyPair kp` é construído por padrão com vetores já dimensionados
 * (tamanho das constantes de chave da biblioteca), que são descartados
 * imediatamente pelas duas movimentações.
 *
 * \note A chave privada chega a este código em cópias Java (o campo
 * `secretKey` é uma matriz `byte[]` comum, não limpa) e em cópias
 * nativas, nenhuma delas apagada com `zupt::secureWipe()`.
 * @endcond
 * @cond INGLES
 * \brief Native implementation of `KeyGenerator.saveKeyPair(KeyPair, String)`.
 *
 * \details Reads the `publicKey` and `secretKey` fields of the received
 * `com.libzupt.KeyPair` object (with `GetObjectField` + \ref
 * jbyteArrayToVector), builds a `zupt::KeyPair` by moving the two vectors
 * and calls the library's `saveKeyPair()`, which writes the private key to
 * `filename` with restricted permissions.
 *
 * Class and field resolution is done here on demand, duplicating the
 * initialization block of \ref createKeyPair.
 *
 * \param[in] env Pointer to the JNI context (`JNIEnv`) of the calling thread.
 * <b>self</b> (unnamed parameter in the signature) The
 * `com.libzupt.KeyGenerator` instance that called the method. Not used.
 * \param[in] jkeypair `com.libzupt.KeyPair` object with the fields to write.
 * \param[in] jfilename Path of the destination file, as a `java.lang.String`.
 *
 * \warning This resolution block is different from that of \ref createKeyPair — it
 * applies `NewGlobalRef` directly to the result of `FindClass`,
 * without testing whether the class was found. If `FindClass` returns
 * `nullptr`, the call is made with a null object (undefined
 * behavior) and the two following `GetFieldID` calls end up using a null
 * class.
 *
 * \warning Neither of the two fields read is checked. If `jkeypair` is null,
 * or if `publicKey`/`secretKey` are `null` in the Java object, the copy
 * reaches `GetArrayLength` with a null object.
 *
 * \warning The return value of `GetStringUTFChars` is not checked, and the
 * release does not happen if `saveKeyPair()` throws an exception.
 *
 * \note `zupt::KeyPair kp` is default-constructed with already-sized vectors
 * (size of the library's key constants), which are discarded
 * immediately by the two moves.
 *
 * \note The private key reaches this code in Java copies (the `secretKey` field
 * is a regular `byte[]` array, not wiped) and in native copies, none of
 * them erased with `zupt::secureWipe()`.
 * @endcond */
JNIEXPORT void JNICALL Java_com_libzupt_KeyGenerator_saveKeyPair(JNIEnv* env, jobject /* self */, jobject jkeypair, jstring jfilename) {
    try {
        if (!keyPairClass) {
            keyPairClass = (jclass)env->NewGlobalRef(env->FindClass("com/libzupt/KeyPair"));
            publicKeyField = env->GetFieldID(keyPairClass, "publicKey", "[B");
            secretKeyField = env->GetFieldID(keyPairClass, "secretKey", "[B");
        }

        jbyteArray pubArray = (jbyteArray)env->GetObjectField(jkeypair, publicKeyField);
        jbyteArray privArray = (jbyteArray)env->GetObjectField(jkeypair, secretKeyField);

        std::vector<uint8_t> publicKey = jbyteArrayToVector(env, pubArray);
        std::vector<uint8_t> secretKey = jbyteArrayToVector(env, privArray);

        zupt::KeyPair kp;
        kp.public_key = std::move(publicKey);
        kp.secret_key = std::move(secretKey);

        const char* filename = env->GetStringUTFChars(jfilename, nullptr);
        zupt::KeyGenerator kg;
        kg.saveKeyPair(kp, filename);
        env->ReleaseStringUTFChars(jfilename, filename);
    } catch (const std::exception& e) {
        throwJavaException(env, e);
    }
}

// Encryptor native methods
/**
 * @cond PORT
 * \brief Implementação nativa de `Encryptor.nativeEncryptMemory(byte[])`.
 *
 * \details Converte o argumento para `std::vector`, lê a chave pública do
 * campo `publicKey` do próprio objeto `Encryptor` (com
 * `GetObjectClass` + `GetFieldID` + `GetObjectField` + \ref
 * jbyteArrayToVector), constrói um `zupt::Encryptor` a partir dessa
 * chave, chama `encryptMemory(data.data(), data.size())` e devolve o
 * par `(texto cifrado, cabeçalho)` como `jobjectArray` de dois
 * elementos, cada um uma matriz de bytes criada por \ref
 * vectorToJByteArray.
 *
 * Não existe estado nativo persistente: o objeto `Encryptor` é
 * reconstruído a cada chamada a partir da cópia Java da chave
 * pública.
 *
 * \param[in] env Ponteiro do contexto JNI (`JNIEnv`) da thread chamadora.
 * \param[in] self Instância de `com.libzupt.Encryptor`; o campo `publicKey` dela
 * fornece a chave usada. O nome aparece comentado na declaração
 * antecipada, mas está presente na definição.
 * `com.libzupt.Encryptor`; o campo `publicKey` dela fornece a chave
 * usada.
 * \param[in] jdata Texto claro a cifrar, como matriz `byte[]`.
 *
 * \return Matriz de objetos com dois elementos: texto cifrado na posição 0 e
 * cabeçalho da cifra na posição 1; ou `nullptr` se uma exceção foi
 * lançada.
 *
 * \note A variável local `publicKeyField` desta função tem o mesmo nome do
 * identificador estático de arquivo (\ref publicKeyField), que pertence
 * a `com.libzupt.KeyPair`. Aqui o nome é ocultado pelo local, o que é
 * legítimo, mas torna fácil confundir os dois. Os métodos de
 * `Decryptor` fazem o mesmo com \ref secretKeyField.
 *
 * \warning `GetFieldID`, `GetObjectField`, `NewObjectArray`,
 * `env->FindClass("[B")` e `SetObjectArrayElement` são chamados sem
 * verificação de retorno. Um campo `publicKey` nulo no objeto Java faz
 * \ref jbyteArrayToVector receber `nullptr`.
 *
 * \warning `zupt::Encryptor` valida a estrutura da chave pública no
 * construtor e lança exceção se ela não for uma chave v2 válida; a
 * mensagem chega ao Java como `ZuptError`.
 *
 * \note O vetor `data`, que contém o texto claro, não é limpo com
 * `zupt::secureWipe()` antes do retorno.
 *
 * \note As referências locais criadas (classe, campos e as duas matrizes de
 * resultado) não são liberadas com `DeleteLocalRef`.
 * @endcond
 * @cond INGLES
 * \brief Native implementation of `Encryptor.nativeEncryptMemory(byte[])`.
 *
 * \details Converts the argument to `std::vector`, reads the public key from the
 * `publicKey` field of the `Encryptor` object itself (with
 * `GetObjectClass` + `GetFieldID` + `GetObjectField` + \ref
 * jbyteArrayToVector), builds a `zupt::Encryptor` from that key, calls
 * `encryptMemory(data.data(), data.size())` and returns the pair
 * `(ciphertext, header)` as a two-element `jobjectArray`, each one a byte
 * array created by \ref vectorToJByteArray.
 *
 * There is no persistent native state: the `Encryptor` object is
 * rebuilt on each call from the Java copy of the public key.
 *
 * \param[in] env Pointer to the JNI context (`JNIEnv`) of the calling thread.
 * \param[in] self The `com.libzupt.Encryptor` instance; its `publicKey` field
 * provides the key used. The name appears commented in the forward
 * declaration, but is present in the definition.
 * `com.libzupt.Encryptor`; its `publicKey` field provides the key
 * used.
 * \param[in] jdata Plaintext to encrypt, as a `byte[]` array.
 *
 * \return Object array with two elements: ciphertext at position 0 and
 * cipher header at position 1; or `nullptr` if an exception was
 * thrown.
 *
 * \note The local variable `publicKeyField` of this function has the same name as
 * the static file identifier (\ref publicKeyField), which belongs to
 * `com.libzupt.KeyPair`. Here the name is hidden by the local one, which
 * is legitimate, but it makes it easy to confuse the two. The
 * `Decryptor` methods do the same with \ref secretKeyField.
 *
 * \warning `GetFieldID`, `GetObjectField`, `NewObjectArray`,
 * `env->FindClass("[B")` and `SetObjectArrayElement` are called without
 * return-value checks. A null `publicKey` field in the Java object makes
 * \ref jbyteArrayToVector receive `nullptr`.
 *
 * \warning `zupt::Encryptor` validates the structure of the public key in the
 * constructor and throws an exception if it is not a valid v2 key; the
 * message reaches Java as `ZuptError`.
 *
 * \note The `data` vector, which holds the plaintext, is not wiped with
 * `zupt::secureWipe()` before returning.
 *
 * \note The local references created (class, fields and the two result arrays)
 * are not released with `DeleteLocalRef`.
 * @endcond */
JNIEXPORT jobject JNICALL Java_com_libzupt_Encryptor_nativeEncryptMemory(JNIEnv* env, jobject self, jbyteArray jdata) {
    try {
        std::vector<uint8_t> data = jbyteArrayToVector(env, jdata);

        jclass encryptorClass = env->GetObjectClass(self);
        jfieldID publicKeyField = env->GetFieldID(encryptorClass, "publicKey", "[B");
        jbyteArray pubArray = (jbyteArray)env->GetObjectField(self, publicKeyField);
        std::vector<uint8_t> publicKey = jbyteArrayToVector(env, pubArray);

        zupt::Encryptor encryptor(publicKey);
        auto result = encryptor.encryptMemory(data.data(), data.size());

        jobjectArray resultArray = env->NewObjectArray(2, env->FindClass("[B"), nullptr);
        env->SetObjectArrayElement(resultArray, 0, vectorToJByteArray(env, result.first));
        env->SetObjectArrayElement(resultArray, 1, vectorToJByteArray(env, result.second));
        return resultArray;
    } catch (const std::exception& e) {
        throwJavaException(env, e);
        return nullptr;
    }
}

/**
 * @cond PORT
 * \brief Implementação nativa de `Encryptor.nativeEncryptMemorySecure(byte[])`,
 * sem correspondência no lado Java.
 *
 * \details O corpo é idêntico ao de
 * \ref Java_com_libzupt_Encryptor_nativeEncryptMemory, que lê a chave pública
 * do campo `publicKey` de `self`, constrói um `zupt::Encryptor` e
 * chama `encryptMemory(data.data(), data.size())`, devolvendo o par
 * `(texto cifrado, cabeçalho)` em uma `jobjectArray`.
 *
 * \param[in] env Ponteiro do contexto JNI (`JNIEnv`) da thread chamadora.
 * \param[in] self Instância de `com.libzupt.Encryptor`; o campo `publicKey`
 * dela fornece a chave usada.
 * \param[in] jdata Texto claro a cifrar, como matriz `byte[]`.
 *
 * \return Matriz de objetos com dois elementos (texto cifrado e cabeçalho), ou
 * `nullptr` se uma exceção foi lançada.
 *
 * \warning Nada neste caminho é mais seguro que o de
 * \ref Java_com_libzupt_Encryptor_nativeEncryptMemory. O nome sugere uso de
 * `zupt::SecureBuffer`, mas a função chama exatamente o mesmo método
 * `encryptMemory` e usa apenas `std::vector` comuns, sem limpeza.
 *
 * \warning Esta função não está registrada em \ref encryptorMethods, não está
 * na lista de declarações antecipadas e `Encryptor.java` não declara
 * um método nativo com esse nome. Ela não é alcançável pelo API Java:
 * `Encryptor.encryptMemorySecure(SecureBuffer)` chama
 * `nativeEncryptMemory` com o resultado de `buffer.toBytes()`.
 *
 * \note Além de não ser alcançável, o caminho Java que existe para "cifração
 * segura" já anula o buffer seguro: `SecureBuffer.toBytes()` devolve uma
 * cópia comum, que é a matriz entregue a esta função.
 * @endcond
 * @cond INGLES
 * \brief Native implementation of `Encryptor.nativeEncryptMemorySecure(byte[])`,
 * with no counterpart on the Java side.
 *
 * \details The body is identical to that of
 * \ref Java_com_libzupt_Encryptor_nativeEncryptMemory, which reads the public key
 * from the `publicKey` field of `self`, builds a `zupt::Encryptor` and
 * calls `encryptMemory(data.data(), data.size())`, returning the pair
 * `(ciphertext, header)` in a `jobjectArray`.
 *
 * \param[in] env Pointer to the JNI context (`JNIEnv`) of the calling thread.
 * \param[in] self The `com.libzupt.Encryptor` instance; its `publicKey` field
 * provides the key used.
 * \param[in] jdata Plaintext to encrypt, as a `byte[]` array.
 *
 * \return Object array with two elements (ciphertext and header), or
 * `nullptr` if an exception was thrown.
 *
 * \warning Nothing on this path is more secure than that of
 * \ref Java_com_libzupt_Encryptor_nativeEncryptMemory. The name suggests the use
 * of `zupt::SecureBuffer`, but the function calls exactly the same
 * `encryptMemory` method and uses only regular `std::vector`s, without
 * wiping.
 *
 * \warning This function is not registered in \ref encryptorMethods, it is not
 * in the forward declaration list, and `Encryptor.java` does not declare
 * a native method with that name. It is not reachable by the Java API:
 * `Encryptor.encryptMemorySecure(SecureBuffer)` calls
 * `nativeEncryptMemory` with the result of `buffer.toBytes()`.
 *
 * \note Besides being unreachable, the Java path that exists for "secure
 * encryption" already defeats the secure buffer: `SecureBuffer.toBytes()`
 * returns a regular copy, which is the array handed to this function.
 * @endcond */
JNIEXPORT jobject JNICALL Java_com_libzupt_Encryptor_nativeEncryptMemorySecure(JNIEnv* env, jobject self, jbyteArray jdata) {
    try {
        std::vector<uint8_t> data = jbyteArrayToVector(env, jdata);

        jclass encryptorClass = env->GetObjectClass(self);
        jfieldID publicKeyField = env->GetFieldID(encryptorClass, "publicKey", "[B");
        jbyteArray pubArray = (jbyteArray)env->GetObjectField(self, publicKeyField);
        std::vector<uint8_t> publicKey = jbyteArrayToVector(env, pubArray);

        zupt::Encryptor encryptor(publicKey);
        auto result = encryptor.encryptMemory(data.data(), data.size());

        jobjectArray resultArray = env->NewObjectArray(2, env->FindClass("[B"), nullptr);
        env->SetObjectArrayElement(resultArray, 0, vectorToJByteArray(env, result.first));
        env->SetObjectArrayElement(resultArray, 1, vectorToJByteArray(env, result.second));
        return resultArray;
    } catch (const std::exception& e) {
        throwJavaException(env, e);
        return nullptr;
    }
}

/**
 * @cond PORT
 * \brief Implementação nativa de `Encryptor.nativeEncryptFile(String)`.
 *
 * \details Converte o nome do arquivo para UTF-8, lê a chave pública do campo
 * `publicKey` de `self`, constrói um `zupt::Encryptor` e chama
 * `encryptFile(filename)`. A string UTF-8 é liberada depois da
 * cifra, e o par `(texto cifrado, cabeçalho)` é devolvido como
 * `jobjectArray` de duas matrizes de bytes.
 *
 * \param[in] env Ponteiro do contexto JNI (`JNIEnv`) da thread chamadora.
 * \param[in] self Instância de `com.libzupt.Encryptor`; o campo `publicKey`
 * dela fornece a chave usada.
 * \param[in] jfilename Caminho do arquivo em disco a cifrar, como
 * `java.lang.String`.
 *
 * \return Matriz de objetos com dois elementos: texto cifrado na posição 0 e
 * cabeçalho da cifra na posição 1; ou `nullptr` se uma exceção foi
 * lançada.
 *
 * \warning O retorno de `GetStringUTFChars` não é verificado, e a liberação não
 * acontece se a cifra lançar exceção.
 *
 * \warning Assim como nos demais métodos de `Encryptor`, as chamadas de
 * `GetFieldID`/`GetObjectField`/`NewObjectArray`/`FindClass` não têm
 * verificação de retorno.
 *
 * \note O arquivo de origem não é modificado: a cifra é feita em memória e o
 * resultado é devolvido ao chamador Java, que decide o que fazer com
 * ele.
 * @endcond
 * @cond INGLES
 * \brief Native implementation of `Encryptor.nativeEncryptFile(String)`.
 *
 * \details Converts the file name to UTF-8, reads the public key from the
 * `publicKey` field of `self`, builds a `zupt::Encryptor` and calls
 * `encryptFile(filename)`. The UTF-8 string is released after
 * encryption, and the pair `(ciphertext, header)` is returned as a
 * `jobjectArray` of two byte arrays.
 *
 * \param[in] env Pointer to the JNI context (`JNIEnv`) of the calling thread.
 * \param[in] self The `com.libzupt.Encryptor` instance; its `publicKey` field
 * provides the key used.
 * \param[in] jfilename Path of the file on disk to encrypt, as
 * `java.lang.String`.
 *
 * \return Object array with two elements: ciphertext at position 0 and
 * cipher header at position 1; or `nullptr` if an exception was
 * thrown.
 *
 * \warning The return value of `GetStringUTFChars` is not checked, and the
 * release does not happen if encryption throws an exception.
 *
 * \warning As in the other `Encryptor` methods, the
 * `GetFieldID`/`GetObjectField`/`NewObjectArray`/`FindClass` calls have no
 * return-value checks.
 *
 * \note The source file is not modified: encryption is done in memory and the
 * result is returned to the Java caller, which decides what to do with
 * it.
 * @endcond */
JNIEXPORT jobject JNICALL Java_com_libzupt_Encryptor_nativeEncryptFile(JNIEnv* env, jobject self, jstring jfilename) {
    try {
        const char* filename = env->GetStringUTFChars(jfilename, nullptr);

        jclass encryptorClass = env->GetObjectClass(self);
        jfieldID publicKeyField = env->GetFieldID(encryptorClass, "publicKey", "[B");
        jbyteArray pubArray = (jbyteArray)env->GetObjectField(self, publicKeyField);
        std::vector<uint8_t> publicKey = jbyteArrayToVector(env, pubArray);

        zupt::Encryptor encryptor(publicKey);
        auto result = encryptor.encryptFile(filename);
        env->ReleaseStringUTFChars(jfilename, filename);

        jobjectArray resultArray = env->NewObjectArray(2, env->FindClass("[B"), nullptr);
        env->SetObjectArrayElement(resultArray, 0, vectorToJByteArray(env, result.first));
        env->SetObjectArrayElement(resultArray, 1, vectorToJByteArray(env, result.second));
        return resultArray;
    } catch (const std::exception& e) {
        throwJavaException(env, e);
        return nullptr;
    }
}

// Decryptor native methods
/**
 * @cond PORT
 * \brief Implementação nativa de `Decryptor.decryptMemoryNative(byte[], byte[])`.
 *
 * \details Converte o texto cifrado e o cabeçalho para `std::vector`, lê a
 * chave privada do campo `secretKey` do próprio objeto `Decryptor`
 * (com `GetObjectClass` + `GetFieldID` + `GetObjectField` + \ref
 * jbyteArrayToVector), constrói um `zupt::Decryptor` a partir dessa
 * chave e chama `decryptMemory(ponteiro, tamanho, cabeçalho)`. O
 * texto claro resultante é devolvido como matriz `byte[]` criada por
 * \ref vectorToJByteArray.
 *
 * Não existe estado nativo persistente: o `zupt::Decryptor` é
 * reconstruído a cada chamada a partir da cópia Java da chave privada.
 *
 * \param[in] env Ponteiro do contexto JNI (`JNIEnv`) da thread chamadora.
 * \param[in] self Instância de `com.libzupt.Decryptor`; o campo `secretKey`
 * dela fornece a chave usada.
 * \param[in] jciphertext Texto cifrado produzido pela cifra híbrida.
 * \param[in] jheader Cabeçalho da cifra devolvido junto pelo `Encryptor`.
 *
 * \return Matriz `byte[]` com o texto claro, ou `nullptr` se uma exceção foi
 * lançada.
 *
 * \warning Os três retornos de leitura (`GetFieldID`, `GetObjectField` e a
 * conversão de matriz) não são verificados, e `GetFieldID`/`FindClass`
 * são reexecutados a cada chamada sem cache.
 *
 * \note A variável local `secretKeyField` desta função oculta o identificador
 * estático de arquivo \ref secretKeyField, que pertence a
 * `com.libzupt.KeyPair`.
 *
 * \note Falhas de decifração — chave incorreta, cabeçalho inválido, soma de
 * verificação divergente, tamanho fora do suportado — são sinalizadas
 * pela biblioteca com exceção e chegam ao Java como `ZuptError`, sem
 * dados parciais no retorno.
 *
 * \warning O texto claro passa por pelo menos duas cópias nativas em memória
 * não protegida (`std::vector` do resultado e a matriz Java de
 * retorno), e nenhuma delas é limpa com `zupt::secureWipe()`.
 * @endcond
 * @cond INGLES
 * \brief Native implementation of `Decryptor.decryptMemoryNative(byte[], byte[])`.
 *
 * \details Converts the ciphertext and the header to `std::vector`, reads the
 * private key from the `secretKey` field of the `Decryptor` object
 * itself (with `GetObjectClass` + `GetFieldID` + `GetObjectField` + \ref
 * jbyteArrayToVector), builds a `zupt::Decryptor` from that key and
 * calls `decryptMemory(pointer, size, header)`. The resulting
 * plaintext is returned as a `byte[]` array created by \ref
 * vectorToJByteArray.
 *
 * There is no persistent native state: the `zupt::Decryptor` is
 * rebuilt on each call from the Java copy of the private key.
 *
 * \param[in] env Pointer to the JNI context (`JNIEnv`) of the calling thread.
 * \param[in] self The `com.libzupt.Decryptor` instance; its `secretKey` field
 * provides the key used.
 * \param[in] jciphertext Ciphertext produced by the hybrid cipher.
 * \param[in] jheader Cipher header returned together by the `Encryptor`.
 *
 * \return `byte[]` array with the plaintext, or `nullptr` if an exception was
 * thrown.
 *
 * \warning The three read returns (`GetFieldID`, `GetObjectField` and the
 * array conversion) are not checked, and `GetFieldID`/`FindClass` are
 * re-executed on each call without caching.
 *
 * \note The local variable `secretKeyField` of this function hides the static
 * file identifier \ref secretKeyField, which belongs to
 * `com.libzupt.KeyPair`.
 *
 * \note Decryption failures — wrong key, invalid header, mismatched checksum,
 * unsupported size — are signalled by the library with an exception and
 * reach Java as `ZuptError`, without partial data in the return.
 *
 * \warning The plaintext passes through at least two native copies in
 * unprotected memory (`std::vector` of the result and the returned Java
 * array), and none of them is wiped with `zupt::secureWipe()`.
 * @endcond */
JNIEXPORT jbyteArray JNICALL Java_com_libzupt_Decryptor_decryptMemoryNative(JNIEnv* env, jobject self, jbyteArray jciphertext, jbyteArray jheader) {
    try {
        std::vector<uint8_t> ciphertext = jbyteArrayToVector(env, jciphertext);
        std::vector<uint8_t> header = jbyteArrayToVector(env, jheader);

        jclass decryptorClass = env->GetObjectClass(self);
        jfieldID secretKeyField = env->GetFieldID(decryptorClass, "secretKey", "[B");
        jbyteArray privArray = (jbyteArray)env->GetObjectField(self, secretKeyField);
        std::vector<uint8_t> secretKey = jbyteArrayToVector(env, privArray);

        zupt::Decryptor decryptor(secretKey);
        std::vector<uint8_t> result = decryptor.decryptMemory(ciphertext.data(), ciphertext.size(), header);

        return vectorToJByteArray(env, result);
    } catch (const std::exception& e) {
        throwJavaException(env, e);
        return nullptr;
    }
}

/**
 * @cond PORT
 * \brief Implementação nativa de `Decryptor.decryptMemorySecure(...)`, sem
 * correspondência no lado Java.
 *
 * \details Lê texto cifrado, cabeçalho e a chave privada do campo `secretKey`
 * de `self` como nas demais funções, chama
 * `decryptMemorySecure(ciphertext, header)` da biblioteca (versão que
 * recebe os dois vetores por referência) e devolve o resultado
 * convertendo o `zupt::SecureBuffer` obtido com `toVector()` para uma
 * matriz `byte[]` comum.
 *
 * \param[in] env Ponteiro do contexto JNI (`JNIEnv`) da thread chamadora.
 * \param[in] self Instância de `com.libzupt.Decryptor`; o campo `secretKey`
 * dela fornece a chave usada.
 * \param[in] jciphertext Texto cifrado produzido pela cifra híbrida.
 * \param[in] jheader Cabeçalho da cifra devolvido junto pelo `Encryptor`.
 *
 * \return Matriz `byte[]` com o texto claro, ou `nullptr` se uma exceção foi
 * lançada.
 *
 * \warning A proteção do `zupt::SecureBuffer` é perdida na fronteira: o texto
 * claro é copiado por `toVector()` e entregue ao Java como matriz
 * comum, que não é apagada. O `SecureBuffer` local é limpo ao sair do
 * escopo, mas isso não atinge a cópia que foi devolvida.
 *
 * \warning Esta função não está registrada em \ref decryptorMethods, não está
 * na lista de declarações antecipadas e `Decryptor.java` não declara
 * um método nativo com esse nome. `Decryptor.decryptMemorySecure` em
 * Java chama `decryptMemoryNative` e apenas embrulha o resultado em um
 * `SecureBuffer` do lado Java, de modo que esta implementação não é
 * alcançável.
 * @endcond
 * @cond INGLES
 * \brief Native implementation of `Decryptor.decryptMemorySecure(...)`, with no
 * counterpart on the Java side.
 *
 * \details Reads the ciphertext, the header and the private key from the
 * `secretKey` field of `self` as in the other functions, calls the
 * library's `decryptMemorySecure(ciphertext, header)` (the version that
 * receives the two vectors by reference) and returns the result by
 * converting the obtained `zupt::SecureBuffer` with `toVector()` into a
 * regular `byte[]` array.
 *
 * \param[in] env Pointer to the JNI context (`JNIEnv`) of the calling thread.
 * \param[in] self The `com.libzupt.Decryptor` instance; its `secretKey` field
 * provides the key used.
 * \param[in] jciphertext Ciphertext produced by the hybrid cipher.
 * \param[in] jheader Cipher header returned together by the `Encryptor`.
 *
 * \return `byte[]` array with the plaintext, or `nullptr` if an exception was
 * thrown.
 *
 * \warning The protection of the `zupt::SecureBuffer` is lost at the boundary:
 * the plaintext is copied by `toVector()` and handed to Java as a
 * regular array, which is not erased. The local `SecureBuffer` is wiped
 * when leaving the scope, but that does not reach the copy that was
 * returned.
 *
 * \warning This function is not registered in \ref decryptorMethods, it is not
 * in the forward declaration list, and `Decryptor.java` does not declare
 * a native method with that name. Java's `Decryptor.decryptMemorySecure`
 * calls `decryptMemoryNative` and only wraps the result in a
 * Java-side `SecureBuffer`, so this implementation is not
 * reachable.
 * @endcond */
JNIEXPORT jbyteArray JNICALL Java_com_libzupt_Decryptor_decryptMemorySecure(JNIEnv* env, jobject self, jbyteArray jciphertext, jbyteArray jheader) {
    try {
        std::vector<uint8_t> ciphertext = jbyteArrayToVector(env, jciphertext);
        std::vector<uint8_t> header = jbyteArrayToVector(env, jheader);

        jclass decryptorClass = env->GetObjectClass(self);
        jfieldID secretKeyField = env->GetFieldID(decryptorClass, "secretKey", "[B");
        jbyteArray privArray = (jbyteArray)env->GetObjectField(self, secretKeyField);
        std::vector<uint8_t> secretKey = jbyteArrayToVector(env, privArray);

        zupt::Decryptor decryptor(secretKey);
        zupt::SecureBuffer result = decryptor.decryptMemorySecure(ciphertext, header);

        return vectorToJByteArray(env, result.toVector());
    } catch (const std::exception& e) {
        throwJavaException(env, e);
        return nullptr;
    }
}

/**
 * @cond PORT
 * \brief Implementação nativa de `Decryptor.decryptFileNative(String, byte[])`.
 *
 * \details Converte o nome do arquivo e o cabeçalho, lê a chave privada do
 * campo `secretKey` de `self`, constrói um `zupt::Decryptor` e chama
 * `decryptFile(filename, header)`. A string UTF-8 é liberada depois da
 * decifração e o texto claro é devolvido como matriz `byte[]`.
 *
 * \param[in] env Ponteiro do contexto JNI (`JNIEnv`) da thread chamadora.
 * \param[in] self Instância de `com.libzupt.Decryptor`; o campo `secretKey`
 * dela fornece a chave usada.
 * \param[in] jfilename Caminho do arquivo cifrado em disco.
 * \param[in] jheader Cabeçalho da cifra devolvido pelo `Encryptor`.
 *
 * \return Matriz `byte[]` com o texto claro, ou `nullptr` se uma exceção foi
 * lançada.
 *
 * \warning O retorno de `GetStringUTFChars` não é verificado, e a liberação não
 * acontece se a decifração lançar exceção.
 *
 * \note As leituras de campo e de matriz não são verificadas; o texto claro
 * resultante também não é limpo após a cópia para Java.
 * @endcond
 * @cond INGLES
 * \brief Native implementation of `Decryptor.decryptFileNative(String, byte[])`.
 *
 * \details Converts the file name and the header, reads the private key from
 * the `secretKey` field of `self`, builds a `zupt::Decryptor` and calls
 * `decryptFile(filename, header)`. The UTF-8 string is released after
 * decryption and the plaintext is returned as a `byte[]` array.
 *
 * \param[in] env Pointer to the JNI context (`JNIEnv`) of the calling thread.
 * \param[in] self The `com.libzupt.Decryptor` instance; its `secretKey` field
 * provides the key used.
 * \param[in] jfilename Path of the encrypted file on disk.
 * \param[in] jheader Cipher header returned by the `Encryptor`.
 *
 * \return `byte[]` array with the plaintext, or `nullptr` if an exception was
 * thrown.
 *
 * \warning The return value of `GetStringUTFChars` is not checked, and the
 * release does not happen if decryption throws an exception.
 *
 * \note The field reads and array reads are not checked; the resulting
 * plaintext is also not wiped after the copy to Java.
 * @endcond */
JNIEXPORT jbyteArray JNICALL Java_com_libzupt_Decryptor_decryptFileNative(JNIEnv* env, jobject self, jstring jfilename, jbyteArray jheader) {
    try {
        const char* filename = env->GetStringUTFChars(jfilename, nullptr);
        std::vector<uint8_t> header = jbyteArrayToVector(env, jheader);

        jclass decryptorClass = env->GetObjectClass(self);
        jfieldID secretKeyField = env->GetFieldID(decryptorClass, "secretKey", "[B");
        jbyteArray privArray = (jbyteArray)env->GetObjectField(self, secretKeyField);
        std::vector<uint8_t> secretKey = jbyteArrayToVector(env, privArray);

        zupt::Decryptor decryptor(secretKey);
        std::vector<uint8_t> result = decryptor.decryptFile(filename, header);
        env->ReleaseStringUTFChars(jfilename, filename);

        return vectorToJByteArray(env, result);
    } catch (const std::exception& e) {
        throwJavaException(env, e);
        return nullptr;
    }
}

// NativeLib helper methods
/**
 * @cond PORT
 * \brief Implementação nativa de `NativeLib.randomBytes(int)`.
 *
 * \details Chama `zupt::randomBytes(size)` da biblioteca, que preenche um
 * vetor com bytes de aleatoriedade criptograficamente segura, e
 * devolve o resultado como matriz `byte[]` criada por \ref
 * vectorToJByteArray.
 *
 * \param[in] env Ponteiro do contexto JNI (`JNIEnv`) da thread chamadora.
 * <b>self</b> Classe `com.libzupt.NativeLib` (o método é `static`). Não é
 * usado (o nome está comentado na assinatura).
 * \param[in] size Quantidade de bytes a gerar.
 *
 * \return Matriz `byte[]` com os bytes aleatórios, ou `nullptr` se uma exceção
 * foi lançada.
 *
 * \warning `size` é um `jint` com sinal e é convertido implicitamente para o
 * `size_t` sem sinal de `zupt::randomBytes`. Um valor negativo vira um
 * tamanho enorme; o `std::vector` interno então lança
 * `std::length_error` ou `std::bad_alloc`, que é reportado ao Java
 * como `ZuptError` com mensagem de alocação, e não como argumento
 * inválido.
 *
 * \warning Não há limite superior verificado aqui, e `NativeLib.java` declara o
 * método como `public static native` sem qualquer envolvente de
 * validação, de modo que a aplicação pode pedir uma alocação
 * arbitrariamente grande.
 * @endcond
 * @cond INGLES
 * \brief Native implementation of `NativeLib.randomBytes(int)`.
 *
 * \details Calls the library's `zupt::randomBytes(size)`, which fills a vector
 * with cryptographically secure random bytes, and returns the result as a
 * `byte[]` array created by \ref vectorToJByteArray.
 *
 * \param[in] env Pointer to the JNI context (`JNIEnv`) of the calling thread.
 * <b>self</b> The `com.libzupt.NativeLib` class (the method is `static`). Not
 * used (the name is commented out in the signature).
 * \param[in] size Number of bytes to generate.
 *
 * \return `byte[]` array with the random bytes, or `nullptr` if an exception
 * was thrown.
 *
 * \warning `size` is a signed `jint` and is implicitly converted to the
 * unsigned `size_t` of `zupt::randomBytes`. A negative value becomes an
 * enormous size; the internal `std::vector` then throws
 * `std::length_error` or `std::bad_alloc`, which is reported to Java
 * as `ZuptError` with an allocation message, and not as an invalid
 * argument.
 *
 * \warning There is no upper bound checked here, and `NativeLib.java` declares
 * the method as `public static native` without any validation wrapper,
 * so the application can request an arbitrarily large allocation.
 * @endcond */
JNIEXPORT jbyteArray JNICALL Java_com_libzupt_NativeLib_randomBytes(JNIEnv* env, jobject /* self */, jint size) {
    try {
        std::vector<uint8_t> result = zupt::randomBytes(size);
        return vectorToJByteArray(env, result);
    } catch (const std::exception& e) {
        throwJavaException(env, e);
        return nullptr;
    }
}

/**
 * @cond PORT
 * \brief Calcula o digest SHA-256 dos bytes recebidos.
 *
 * Converte o array Java em `std::vector<uint8_t>` por \ref jbyteArrayToVector,
 * chama `zupt::sha256(const uint8_t*, size_t)` e converte o resultado de volta
 * por \ref vectorToJByteArray. O vetor de saída tem sempre 32 bytes.
 *
 * \param[in] env Ponteiro do contexto JNI (`JNIEnv`) da thread chamadora.
 * <b>self</b> Classe `com.libzupt.NativeLib` (o método é `static`). Não é
 * usado (o nome está comentado na assinatura).
 * \param[in] jdata Dados a serem hasheados.
 *
 * \return Matriz `byte[]` de 32 bytes com o digest, ou `nullptr` se uma exceção
 * foi lançada.
 *
 * \note \ref jbyteArrayToVector não verifica `jdata`; ver as observações dessa
 * função para o comportamento diante de matriz nula.
 * @endcond
 * @cond INGLES
 * \brief Computes the SHA-256 digest of the received bytes.
 *
 * Converts the Java array to `std::vector<uint8_t>` via \ref jbyteArrayToVector,
 * calls `zupt::sha256(const uint8_t*, size_t)` and converts the result back
 * via \ref vectorToJByteArray. The output vector is always 32 bytes.
 *
 * \param[in] env Pointer to the JNI context (`JNIEnv`) of the calling thread.
 * <b>self</b> The `com.libzupt.NativeLib` class (the method is `static`). Not
 * used (the name is commented out in the signature).
 * \param[in] jdata Data to be hashed.
 *
 * \return 32-byte `byte[]` array with the digest, or `nullptr` if an exception
 * was thrown.
 *
 * \note \ref jbyteArrayToVector does not check `jdata`; see the remarks of that
 * function for the behavior on a null array.
 * @endcond */
JNIEXPORT jbyteArray JNICALL Java_com_libzupt_NativeLib_sha256(JNIEnv* env, jobject /* self */, jbyteArray jdata) {
    try {
        std::vector<uint8_t> data = jbyteArrayToVector(env, jdata);
        std::vector<uint8_t> result = zupt::sha256(data.data(), data.size());
        return vectorToJByteArray(env, result);
    } catch (const std::exception& e) {
        throwJavaException(env, e);
        return nullptr;
    }
}

/**
 * @cond PORT
 * \brief Calcula o digest SHA3-512 dos bytes recebidos.
 *
 * Idêntica em estrutura a \ref Java_com_libzupt_NativeLib_sha256, mas chama
 * `zupt::sha3_512(const uint8_t*, size_t)`. O vetor de saída tem sempre 64
 * bytes.
 *
 * \param[in] env Ponteiro do contexto JNI (`JNIEnv`) da thread chamadora.
 * <b>self</b> Classe `com.libzupt.NativeLib` (o método é `static`). Não é
 * usado (o nome está comentado na assinatura).
 * \param[in] jdata Dados a serem hasheados.
 *
 * \return Matriz `byte[]` de 64 bytes com o digest, ou `nullptr` se uma
 * exceção foi lançada.
 *
 * \note O nome exposto ao Java é `sha3512`, enquanto a função C++ chamada é
 * `zupt::sha3_512` (SHA3-512, digest de 64 bytes). A tabela de métodos
 * nativos em \ref nativeLibMethods é o que associa os dois.
 * @endcond
 * @cond INGLES
 * \brief Computes the SHA3-512 digest of the received bytes.
 *
 * Identical in structure to \ref Java_com_libzupt_NativeLib_sha256, but calls
 * `zupt::sha3_512(const uint8_t*, size_t)`. The output vector is always 64
 * bytes.
 *
 * \param[in] env Pointer to the JNI context (`JNIEnv`) of the calling thread.
 * <b>self</b> The `com.libzupt.NativeLib` class (the method is `static`). Not
 * used (the name is commented out in the signature).
 * \param[in] jdata Data to be hashed.
 *
 * \return 64-byte `byte[]` array with the digest, or `nullptr` if an
 * exception was thrown.
 *
 * \note The name exposed to Java is `sha3512`, while the C++ function called is
 * `zupt::sha3_512` (SHA3-512, 64-byte digest). The native method table
 * in \ref nativeLibMethods is what associates the two.
 * @endcond */
JNIEXPORT jbyteArray JNICALL Java_com_libzupt_NativeLib_sha3512(JNIEnv* env, jobject /* self */, jbyteArray jdata) {
    try {
        std::vector<uint8_t> data = jbyteArrayToVector(env, jdata);
        std::vector<uint8_t> result = zupt::sha3_512(data.data(), data.size());
        return vectorToJByteArray(env, result);
    } catch (const std::exception& e) {
        throwJavaException(env, e);
        return nullptr;
    }
}