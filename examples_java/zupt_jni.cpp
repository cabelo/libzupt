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
 * \file zupt_jni.cpp
 * \brief Implementação dos métodos nativos consumidos pelas classes de
 *        `com.libzupt` (JNI).
 *
 * \details Este arquivo não declara tipos nem constantes próprios: cada função
 *          aqui traduz chamadas Java para a API C++ documentada em
 *          `zupt.hpp`. As classes Java correspondentes ficam em
 *          `examples_java/src/com/libzupt/` e carregam esta biblioteca por
 *          `System.loadLibrary("Jzupt")` — o `CMakeLists.txt` do exemplo gera
 *          `libJzupt.so` a partir deste arquivo (`add_library(zupt_jni SHARED
 *          zupt_jni.cpp)` + `OUTPUT_NAME Jzupt` + `PREFIX "lib"`).
 *
 *          \b Ligação: o vínculo entre Java e C++ é feito de forma explícita
 *          em \ref JNI_OnLoad, que chama `RegisterNatives()` para as quatro
 *          classes que possuem métodos nativos (`KeyGenerator`, `Encryptor`,
 *          `Decryptor` e `NativeLib`). Por isso as assinaturas dos métodos
 *          nativos não precisam seguir a convenção de nomes do JNI, embora
 *          sigam por consistência. As tabelas de vínculo são as quatro
 *          `static JNINativeMethod[]` deste arquivo.
 *
 *          \b Erros: todas as funções nativas executam seu corpo dentro de um
 *          `try` / `catch (const std::exception& e)` e convertem a exceção C++
 *          em exceção Java via \ref throwJavaException. Nenhuma função nativa
 *          propaga exceção C++ para a JVM (o que seria comportamento
 *          indefinido). Além disso, os métodos retornam `nullptr` em caso de
 *          erro, e o lado Java lança `ZuptError` quando a matriz retornada é
 *          nula.
 *
 *          \b Memória: a conversão de dados binários usa cópias completas —
 *          `GetByteArrayRegion`/`SetByteArrayRegion` (cópia, sem pinning de
 *          elementos). Nenhum dos buffers temporários em `std::vector` é
 *          limpo com `zupt::secureWipe()` antes da saída da função nativa, o
 *          que inclui material sensível como chaves privadas e texto claro.
 *
 * \warning `JNI_OnUnload` não é implementado, portanto as referências globais
 *          criadas aqui nunca são liberadas. Como a biblioteca só é
 *          descarregada quando a JVM se encerra, o vazamento é benigno, mas as
 *          referências ficam apontando para classes de um `ClassLoader` que o
 *          código de aplicação poderia querer descartar.
 *
 * \note Este arquivo usa apenas o padrão C++11, compatível com o padrão C++
 *       configurado pelo `CMAKE_CXX_STANDARD` do `CMakeLists.txt` do exemplo.
 */

// Exception class for ZuptError
/**
 * \var zuptErrorClass
 * \brief Referência global à classe `com.libzupt.ZuptError`, usada por
 *        \ref throwJavaException.
 *
 * \details É criada de forma sob demanda (lazy) na primeira chamada que
 *          precisa lançar exceção, via `FindClass` + `NewGlobalRef`. O valor
 *          `nullptr` significa "ainda não resolvida". Não há proteção contra
 *          acesso concorrente: se duas threads native chamarem
 *          \ref throwJavaException ao mesmo tempo antes do primeiro cache,
 *          ambas executam o bloco de inicialização (ver \ref zuptErrorClass e
 *          \ref throwJavaException).
 */
static jclass zuptErrorClass = nullptr;

// Helper function to throw Java exception from C++ exception
/**
 * \brief Lança na JVM uma exceção equivalente a uma exceção C++ capturada.
 * \details Estratégia em três níveis, na ordem:
 *          - Se \ref zuptErrorClass ainda é nula, resolve
 *             `com/libzupt/ZuptError` com `FindClass` e a converte em
 *             referência global (`NewGlobalRef`), liberando a referência
 *             local. Se `FindClass` falhar, nenhum estado é salvo e a
 *             tentativa se repete a cada chamada.
 *          - Havendo referência válida, lança `ZuptError` com a mensagem
 *             `e.what()` (`ThrowNew`).
 *          - Caso contrário recorre a `java/lang/RuntimeException`; e se
 *             este também não for encontrado, lança `java/lang/Error` com a
 *             mensagem de `e.what()` (ou `"Unknown error"` quando nula).
 *
 *          Todas as funções nativas deste arquivo chamam esta função a
 *          partir de `catch (const std::exception& e)`, de modo que exceções
 *          como `zupt::ZuptError` e `std::bad_alloc` cheguem ao código Java
 *          como `ZuptError`.
 *
 * \param[in] env Ponteiro do contexto JNI (`JNIEnv`) da thread chamadora.
 * \param[in] e   Exceção C++ capturada cuja mensagem descreve o erro.
 *
 * \warning `NewGlobalRef` é chamado sem verificar o resultado. Se ele
 *          retornar `nullptr` (por falta de memória), \ref zuptErrorClass fica
 *          nula e cada nova tentativa de lançar exceção volta a rodar o bloco
 *          de cache.
 *
 * \warning Quando `FindClass("com/libzupt/ZuptError")` falha, o JNI deixa uma
 *          exceção `NoClassDefFoundError` pendente na `env`. Essa exceção
 *          pendente permanece ativa mesmo depois do caminho alternativo que
 *          lança `RuntimeException`, e a ordem de lançamento fica invertida em
 *          relação ao esperado: a exceção "principal" passa a ser a pendente.
 *
 * \warning A chamada final usa `env->FindClass("java/lang/Error")`
 *          diretamente como argumento de `ThrowNew`, sem testar o retorno. Se
 *          `java/lang/Error` não puder ser resolvida, `ThrowNew` recebe um
 *          `jclass` nulo, o que é comportamento indefinido.
 *
 * \note A função tem vinculação externa (não é `static`), embora seja usada
 *       apenas dentro deste arquivo. Ela é visível a outras unidades de
 *       tradução e poderia colidir com um símbolo homônimo.
 */
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
 * \brief Copia uma matriz de bytes Java para um `std::vector<uint8_t>`.
 * \details Obtém o comprimento com `GetArrayLength`, dimensiona o vetor na
 *          mesma quantidade e copia o conteúdo inteiro de uma vez com
 *          `GetByteArrayRegion` (região 0 ao fim). Não usa
 *          `GetByteArrayElements`, portanto não há pinning nem risco de
 *          liberar um ponteiro sem cópia de volta. O vetor é retornado por
 *          valor (move elision / move semantics).
 *
 *          É usada tanto para dados comuns (texto claro, texto cifrado,
 *          cabeçalho) quanto para material sensível (chaves públicas e
 *          privadas lidas dos campos dos objetos `Encryptor`, `Decryptor` e
 *          `KeyPair`).
 *
 * \param[in] env Ponteiro do contexto JNI (`JNIEnv`) da thread chamadora.
 * \param[in] arr Matriz `byte[]` de origem.
 *
 * \return Vetor com exatamente os bytes de `arr`.
 *
 * \warning Nenhum dos dois argumentos é verificado. Se `arr` for `nullptr`
 *          (campo `null` no objeto Java, por exemplo), `GetArrayLength` recebe
 *          um objeto nulo, o que é comportamento indefinido.
 *
 * \warning `GetByteArrayRegion` pode deixar uma exceção
 *          `ArrayIndexOutOfBoundsException` pendente, mas o retorno não é
 *          verificado; o vetor é retornado mesmo assim.
 *
 * \note A função tem vinculação externa (não é `static`), embora seja usada
 *       apenas dentro deste arquivo.
 */
// Convert jbyteArray to std::vector<uint8_t>
std::vector<uint8_t> jbyteArrayToVector(JNIEnv* env, jbyteArray arr) {
    jsize len = env->GetArrayLength(arr);
    std::vector<uint8_t> vec(len);
    env->GetByteArrayRegion(arr, 0, len, reinterpret_cast<jbyte*>(vec.data()));
    return vec;
}

/**
 * \brief Copia um `std::vector<uint8_t>` para uma nova matriz de bytes Java.
 * \details Cria a matriz de destino com `NewByteArray` no tamanho do vetor e
 *          preenche a região inteira com `SetByteArrayRegion`. O `const_cast`
 *          mais o `reinterpret_cast` existem apenas para satisfazer a
 *          assinatura de `SetByteArrayRegion`, que recebe `jbyte*` não `const`
 *          mesmo para cópia de saída (a matriz Java é o destino, o vetor de
 *          origem não é modificado).
 *
 *          A matriz devolvida é uma referência local: passa a ser de
 *          responsabilidade da função nativa que a chamou, e o coletor de
 *          lixo do lado Java descarta a matriz quando ela se torna inacessível.
 *
 * \param[in] env Ponteiro do contexto JNI (`JNIEnv`) da thread chamadora.
 * \param[in] vec Vetor de origem com os bytes a transferir.
 *
 * \return Matriz `byte[]` recém-criada com o conteúdo de `vec`, ou `nullptr`
 *         se `NewByteArray` falhar.
 *
 * \warning O retorno de `NewByteArray` não é verificado. Ele retorna `nullptr`
 *          quando não há memória disponível (inclusive quando o tamanho
 *          solicitado excede o limite da pilha nativa). Nesse caso
 *          `SetByteArrayRegion` recebe um objeto nulo, o que é comportamento
 *          indefinido.
 *
 * \note `vec.size()` é `size_t` sem sinal e é convertido para `jsize`
 *       (inteiro de 32 bits). Vetores acima de `INT32_MAX` bytes geram
 *       truncamento silencioso do comprimento.
 *
 * \note A função tem vinculação externa (não é `static`), embora seja usada
 *       apenas dentro deste arquivo.
 */
// Convert std::vector<uint8_t> to jbyteArray
jbyteArray vectorToJByteArray(JNIEnv* env, const std::vector<uint8_t>& vec) {
    jsize len = vec.size();
    jbyteArray arr = env->NewByteArray(len);
    env->SetByteArrayRegion(arr, 0, len, const_cast<jbyte*>(reinterpret_cast<const jbyte*>(vec.data())));
    return arr;
}

// KeyPair class
/**
 * \var keyPairClass
 * \brief Referência global à classe `com.libzupt.KeyPair`.
 *
 * \details É resolvida de forma sob demanda pela primeira função que
 *          precisa dela: \ref createKeyPair ou
 *          \ref Java_com_libzupt_KeyGenerator_saveKeyPair. Serve também como
 *          sinalizador de "campos já resolvidos", pois
 *          \ref publicKeyField e \ref secretKeyField são consultados no
 *          mesmo bloco de inicialização. Não há proteção contra
 *          concorrência.
 */
static jclass keyPairClass = nullptr;

/**
 * \var publicKeyField
 * \brief Identificador do campo `publicKey` (tipo `[B`) de
 *        `com.libzupt.KeyPair`.
 *
 * \details Resolvido junto com \ref keyPairClass. É usado para ler o campo
 *          ao salvar (`GetObjectField`) e para gravá-lo ao construir o objeto
 *          de retorno (`SetObjectField`). Vale `nullptr` se a resolução de
 *          campos falhou ou ainda não aconteceu.
 *
 * \warning `com.libzupt.Encryptor` e `com.libzupt.Decryptor` também têm um
 *          campo de nome `publicKey`/`secretKey`, mas cada um é resolvido com
 *          `GetFieldID` sobre a classe do próprio objeto, dentro das funções
 *          nativas correspondentes; este identificador vale apenas para
 *          `KeyPair`.
 */
static jfieldID publicKeyField = nullptr;

/**
 * \var secretKeyField
 * \brief Identificador do campo `secretKey` (tipo `[B`) de
 *        `com.libzupt.KeyPair`.
 *
 * \details Resolvido junto com \ref keyPairClass e usado nas mesmas duas
 *          operações de \ref publicKeyField. Por guardar chave privada, os
 *          caminhos que o usam merecem a mesma atenção quanto à limpeza dos
 *          buffers temporários descrita no cabeçalho deste arquivo.
 */
static jfieldID secretKeyField = nullptr;

/**
 * \brief Constrói um objeto `com.libzupt.KeyPair` a partir de um
 *        `zupt::KeyPair` da biblioteca.
 * \details Na primeira chamada resolve `com/libzupt/KeyPair` e os
 *          identificadores de campo (\ref keyPairClass, \ref publicKeyField,
 *          \ref secretKeyField). Depois cria a instância com
 *          `NewObject(keyPairClass, GetMethodID(keyPairClass, "<init>",
 *          "()V"))` e copia os dois vetores para campos da instância via
 *          \ref vectorToJByteArray + `SetObjectField`.
 *
 *          O construtor Java de `KeyPair()` apenas inicializa os dois campos
 *          como matrizes de tamanho zero; os valores reais chegam pelos dois
 *          `SetObjectField`.
 *
 * \param[in] env Ponteiro do contexto JNI (`JNIEnv`) da thread chamadora.
 * \param[in] kp  Par de chaves da biblioteca a transferir para Java.
 *
 * \return Referência local ao objeto `KeyPair` preenchido.
 *
 * \warning `NewObject` é chamado com o resultado de `GetMethodID` para
 *          `<init>` como segundo argumento, sem testar nenhum dos dois. Se a
 *          classe não pôde ser resolvida (`keyPairClass == nullptr`) ou o
 *          construtor não existir, o comportamento é indefinido.
 *
 * \warning `GetMethodID(keyPairClass, "<init>", "()V")` é executado a cada
 *          chamada, embora o resultado pudesse ser cacheado junto com os
 *          campos, como os outros identificadores estáticos deste arquivo.
 *
 * \warning As duas matrizes criadas por \ref vectorToJByteArray são
 *          referências locais que nunca são liberadas com
 *          `DeleteLocalRef`. Elas sobrevivem até o retorno da função nativa
 *          que chamou este helper (limite de referências locais da JVM).
 *
 * \note Os vetores de `kp` (que contêm chave privada) não são limpos com
 *       `zupt::secureWipe()` após a cópia, e o `zupt::KeyPair` local da função
 *       chamadora também não.
 */
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
 * \brief Declarações antecipadas dos métodos nativos vinculados em
 *        \ref JNI_OnLoad.
 *
 * \details As quatro tabelas de vínculo (`JNINativeMethod[]`) definidas logo
 *          abaixo precisam do endereço de cada função, e esse endereço só é
 *          obtido se a função estiver declarada antes da tabela — as
 *          implementações vêm bem mais adiante neste arquivo. Os nomes
 *          seguem a convenção padrão do JNI (`Java_com_libzupt_<Classe>_<método>`),
 *          embora a vinculação por `RegisterNatives` dispense essa
 *          exigência.
 *
 * \note Apenas as funções efetivamente listadas nas tabelas estão declaradas
 *          aqui. `Java_com_libzupt_Encryptor_nativeEncryptMemorySecure` e
 *          `Java_com_libzupt_Decryptor_decryptMemorySecure` têm implementação
 *          neste arquivo, mas não aparecem nesta lista, não aparecem em
 *          nenhuma das tabelas de vínculo e não têm declaração nativa
 *          correspondente nos arquivos Java do pacote `com.libzupt` (ver os
 *          blocos de documentação dessas duas funções).
 */
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
 * \var keyGenMethods
 * \brief Tabela de vínculo dos métodos nativos de `com.libzupt.KeyGenerator`.
 *
 * \details Cada linha associa o nome simples do método nativo, a assinatura
 *          JNI em formato de descritor e o endereço da implementação. A
 *          contagem de elementos (5) é passada como argumento fixo em
 *          \ref JNI_OnLoad.
 *
 * \warning O número de elementos é informado manualmente
 *          (`RegisterNatives(..., keyGenMethods, 5)`), e o tamanho da tabela é
 *          deduzido pelo compilador. Adicionar ou remover uma linha sem
 *          atualizar o literal em \ref JNI_OnLoad faz o JNI ler a tabela fora
 *          dos limites.
 *
 * \note Os descritores retornam `Lcom/libzupt/KeyPair;` para
 *          `generateKeyPair`/`loadKeyPair` e `[B` para `loadPublicKey`, o que
 *          corresponde aos tipos de retorno das implementações.
 */
static JNINativeMethod keyGenMethods[] = {
    {"generateKeyPair", "()Lcom/libzupt/KeyPair;", (void*)Java_com_libzupt_KeyGenerator_generateKeyPair},
    {"loadKeyPair", "(Ljava/lang/String;)Lcom/libzupt/KeyPair;", (void*)Java_com_libzupt_KeyGenerator_loadKeyPair},
    {"loadPublicKey", "(Ljava/lang/String;)[B", (void*)Java_com_libzupt_KeyGenerator_loadPublicKey},
    {"exportPublicKey", "(Ljava/lang/String;Ljava/lang/String;)V", (void*)Java_com_libzupt_KeyGenerator_exportPublicKey},
    {"saveKeyPair", "(Lcom/libzupt/KeyPair;Ljava/lang/String;)V", (void*)Java_com_libzupt_KeyGenerator_saveKeyPair}
};

/**
 * \var encryptorMethods
 * \brief Tabela de vínculo dos métodos nativos de `com.libzupt.Encryptor`.
 *
 * \details Contém dois métodos: `nativeEncryptMemory` e `nativeEncryptFile`.
 *          Ambos têm descritor de retorno `[Ljava/lang/Object;`, ou seja,
 *          `java.lang.Object[]`, e a implementação devolve de fato uma
 *          `jobjectArray` de dois elementos, cada um uma matriz de bytes
 *          (`[B`): texto cifrado na posição 0 e cabeçalho na posição 1.
 *
 * \warning `Java_com_libzupt_Encryptor_nativeEncryptMemorySecure` está
 *          implementado neste arquivo, mas não está nesta tabela, não está na
 *          lista de declarações antecipadas e `Encryptor.java` não declara
 *          nenhum método nativo com esse nome. Do lado Java,
 *          `encryptMemorySecure(SecureBuffer)` chama `nativeEncryptMemory`, de
 *          modo que a implementação com nome "secure" não é alcançável.
 *
 * \warning `Encryptor.java` é a única classe do pacote `com.libzupt` com
 *          métodos nativos que não tem um bloco estático com
 *          `System.loadLibrary("Jzupt")` (`KeyGenerator.java`,
 *          `Decryptor.java` e `NativeLib.java` têm). Se a aplicação usar
 *          apenas `Encryptor`, a biblioteca nunca é carregada: a função
 *          \ref JNI_OnLoad não executa, nenhum método é registrado e as
 *          chamadas resultam em `UnsatisfiedLinkError`.
 *
 * \note A contagem de elementos (2) é um literal repetido em
 *       \ref JNI_OnLoad.
 */
static JNINativeMethod encryptorMethods[] = {
    {"nativeEncryptMemory", "([B)[Ljava/lang/Object;", (void*)Java_com_libzupt_Encryptor_nativeEncryptMemory},
    {"nativeEncryptFile", "(Ljava/lang/String;)[Ljava/lang/Object;", (void*)Java_com_libzupt_Encryptor_nativeEncryptFile}
};

/**
 * \var decryptorMethods
 * \brief Tabela de vínculo dos métodos nativos de `com.libzupt.Decryptor`.
 *
 * \details Contém `decryptMemoryNative` e `decryptFileNative`, ambos com
 *          retorno `byte[]` (descritor `[B`), o que corresponde a
 *          `jbyteArray` nas implementações.
 *
 * \warning `Java_com_libzupt_Decryptor_decryptMemorySecure` está implementado
 *          neste arquivo, mas não está nesta tabela, não está na lista de
 *          declarações antecipadas e `Decryptor.java` não declara nenhum
 *          método nativo com esse nome. O método Java de mesmo nome chama
 *          `decryptMemoryNative` e apenas envolve o resultado com um
 *          `SecureBuffer` no lado Java, de modo que a implementação nativa com
 *          nome "secure" não é alcançável.
 *
 * \note A contagem de elementos (2) é um literal repetido em
 *       \ref JNI_OnLoad.
 */
static JNINativeMethod decryptorMethods[] = {
    {"decryptMemoryNative", "([B[B)[B", (void*)Java_com_libzupt_Decryptor_decryptMemoryNative},
    {"decryptFileNative", "(Ljava/lang/String;[B)[B", (void*)Java_com_libzupt_Decryptor_decryptFileNative}
};

/**
 * \var nativeLibMethods
 * \brief Tabela de vínculo dos métodos nativos de `com.libzupt.NativeLib`.
 *
 * \details Agrupa as três funções utilitárias expostas sem estado:
 *          `randomBytes` (descritor `(I)[B`), `sha256` e `sha3512` (ambos
 *          `([B)[B`). No lado Java, `NativeLib` declara os três como `public
 *          static native`, sem métodos de envolventes e sem validação de
 *          argumentos.
 *
 * \note A contagem de elementos (3) é um literal repetido em
 *       \ref JNI_OnLoad.
 *
 * \warning `NativeLib.java` tem uma abertura de comentário de documentação
 *          não fechada entre o bloco estático de carga da biblioteca e o bloco
 *          de documentação de `randomBytes`, o que compromete a documentação da
 *          classe na ferramenta de documentação do Java.
 */
static JNINativeMethod nativeLibMethods[] = {
    {"randomBytes", "(I)[B", (void*)Java_com_libzupt_NativeLib_randomBytes},
    {"sha256", "([B)[B", (void*)Java_com_libzupt_NativeLib_sha256},
    {"sha3512", "([B)[B", (void*)Java_com_libzupt_NativeLib_sha3512}
};

/**
 * \brief Função de inicialização da biblioteca nativa, chamada pela JVM no
 *        carregamento de `libJzupt.so`.
 *
 * \details Executa duas tarefas:
 *          - Negocia a versão do JNI com `GetEnv` pedindo
 *            `JNI_VERSION_1_8`; se a JVM não suportar essa versão, devolve
 *            `JNI_ERR` e o carregamento da biblioteca falha.
 *          - Registra os métodos nativos de cada classe com
 *            `RegisterNatives`, usando as quatro tabelas `static
 *            JNINativeMethod[]` deste arquivo: \ref keyGenMethods (5),
 *            \ref encryptorMethods (2), \ref decryptorMethods (2) e
 *            \ref nativeLibMethods (3).
 *
 *          Não resolve as referências de classe cacheadas
 *          (\ref zuptErrorClass, \ref keyPairClass) — essas continuam
 *          resolvidas sob demanda.
 *
 * \param[in] vm Ponteiro da `JavaVM` da aplicação.
 * <b>reserved</b> (parâmetro sem nome na assinatura) Reservado pela especificação
 *            JNI; não usado (o nome está comentado no código).
 *
 * \return `JNI_VERSION_1_8` em caso de sucesso, ou `JNI_ERR` se `GetEnv`
 *         falhar ou se alguma das quatro chamadas `RegisterNatives` retornar
 *         valor negativo.
 *
 * \warning O registro só é tentado quando `FindClass` obteve a classe, pelo
 *          curto-circuito em `if (cls && RegisterNatives(...) < 0)`. Quando
 *          `FindClass` retorna `nullptr`, a classe é ignorada em silêncio e a
 *          função continua, podendo devolver `JNI_VERSION_1_8`: a biblioteca
 *          aparece como carregada, mas os métodos daquela classe ficam sem
 *          vínculo e a falha só aparece depois, como `UnsatisfiedLinkError` na
 *          primeira chamada.
 *
 * \note Quando `FindClass` falha, o JNI deixa uma exceção
 *       `NoClassDefFoundError` pendente na `env`, e este código não a limpa.
 *       Essa exceção pendente atravessa o retorno de `JNI_OnLoad`.
 *
 * \warning As contagens de métodos de cada tabela são literais (5, 2, 2, 3)
 *          repetidos aqui, e não `sizeof` das tabelas.
 *
 * \note As quatro referências locais de classe (`keyGenClass`,
 *       `encryptClass`, `decryptClass`, `nativeLibClass`) não são liberadas
 *       com `DeleteLocalRef`.
 *
 * \note Este arquivo não implementa `JNI_OnUnload`, então as referências
 *       globais criadas em \ref throwJavaException e \ref createKeyPair não
 *       são liberadas ao descarregar a biblioteca.
 */
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
 * \brief Implementação nativa de `KeyGenerator.generateKeyPair()`.
 *
 * \details Constrói um `zupt::KeyGenerator` na pilha, chama
 *          `generateKeyPair()` da biblioteca e converte o resultado em objeto
 *          `com.libzupt.KeyPair` com \ref createKeyPair. Todo o corpo está
 *          protegido por `try` / `catch (const std::exception& e)`, que
 *          converte a exceção C++ em exceção Java via \ref throwJavaException.
 *
 * \param[in] env Ponteiro do contexto JNI (`JNIEnv`) da thread chamadora.
 * <b>self</b> (parâmetro sem nome na assinatura) Instância de
 *            `com.libzupt.KeyGenerator` que chamou o método. Não é usada (o nome
 *            está comentado na assinatura), pois a classe não guarda estado.
 *            classe não guarda estado.
 *
 * \return Referência local ao objeto `KeyPair` recém-gerado, ou `nullptr` se
 *         uma exceção foi lançada (caso em que a chamada Java nunca vê o
 *         valor de retorno).
 *
 * \note As exceções de `zupt::KeyGenerator::generateKeyPair()` — por exemplo
 *       falha do gerador de aleatoriedade — chegam como `ZuptError` no lado
 *       Java, com a mensagem de `e.what()`. `std::bad_alloc` também cai nesta
 *       mesma tradução.
 *
 * \note `kp` local contém a chave privada e não é limpo com
 *       `zupt::secureWipe()` antes do retorno; as cópias em Java também não
 *       são limpas (ver \ref createKeyPair).
 */
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
 * \brief Implementação nativa de `KeyGenerator.loadKeyPair(String)`.
 *
 * \details Converte o argumento `String` para UTF-8 com
 *          `GetStringUTFChars`, chama `loadKeyPair()` da biblioteca e monta o
 *          objeto `com.libzupt.KeyPair` de resposta com \ref createKeyPair. A
 *          liberação da string é feita com `ReleaseStringUTFChars` logo após a
 *          leitura, antes da construção do objeto Java.
 *
 * \param[in] env Ponteiro do contexto JNI (`JNIEnv`) da thread chamadora.
 * <b>self</b> (parâmetro sem nome na assinatura) Instância de
 *            `com.libzupt.KeyGenerator` que chamou o método. Não é usada.
 * \param[in] jfilename Nome do arquivo de chave privada no formato `ZKEY`,
 *            como `java.lang.String`.
 *
 * \return Referência local ao objeto `KeyPair` carregado, ou `nullptr` se uma
 *         exceção foi lançada.
 *
 * \warning O retorno de `GetStringUTFChars` não é verificado. Ele pode
 *          devolver `nullptr` quando a JVM não consegue alocar o buffer de
 *          conversão, e nesse caso `filename` é passado nulo para
 *          `loadKeyPair()`, que o trata como `std::string` a partir de um
 *          ponteiro nulo (comportamento indefinido).
 *
 * \warning Se `loadKeyPair()` lançar exceção, o `ReleaseStringUTFChars` da
 *          linha seguinte não é executado: o buffer UTF-8 fica sem liberação.
 *          Como a thread logo retorna à JVM, o dano é limitado, mas o padrão
 *          seguro seria liberar antes de relançar (RAII).
 *
 * \note `filename` é uma string UTF-8 modificada (Modified UTF-8 do JNI), não
 *       necessariamente UTF-8 padrão; caminhos com caracteres não ASCII fora
 *       do BMP podem não ser interpretados como o chamador espera.
 *
 * \note Ao contrário do que fazem as ligações Node.js e Python, este caminho
 *       não limpa a chave privada dos buffers temporários.
 */
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
 * \brief Implementação nativa de `KeyGenerator.loadPublicKey(String)`.
 *
 * \details Converte o nome do arquivo para UTF-8, chama `loadPublicKey()` da
 *          biblioteca e devolve o resultado como matriz `byte[]` criada por
 *          \ref vectorToJByteArray. A string UTF-8 é liberada com
 *          `ReleaseStringUTFChars` antes da conversão da resposta.
 *
 *          O conteúdo devolvido é o arquivo inteiro no formato `ZKEY` (1224
 *          bytes, com magic, versão, flags e a chave pública embutida), que é
 *          exatamente o formato aceito pelo construtor de `zupt::Encryptor`.
 *
 * \param[in] env Ponteiro do contexto JNI (`JNIEnv`) da thread chamadora.
 * <b>self</b> (parâmetro sem nome na assinatura) Instância de
 *            `com.libzupt.KeyGenerator` que chamou o método. Não é usada.
 * \param[in] jfilename Nome do arquivo de chave pública, como
 *            `java.lang.String`.
 *
 * \return Matriz `byte[]` com o conteúdo da chave pública, ou `nullptr` se uma
 *         exceção foi lançada.
 *
 * \warning `GetStringUTFChars` não é verificado quanto a `nullptr`, e o buffer
 *          não é liberado se `loadPublicKey()` lançar exceção.
 *
 * \note As validações de formato (magic `ZKEY`, tamanho de 1224 bytes, versão
 *       e flags) são feitas pela biblioteca e chegam ao Java como
 *       `ZuptError`.
 *
 * \note `KeyGenerator.java` devolve essa matriz diretamente ao chamador, e o
 *       exemplo a repassa ao construtor de `Encryptor`. Um arquivo de chave
 *       pública de versão 1 é aceito nesta leitura, mas o `Encryptor` aceita
 *       somente a versão 2: a falha então aparece mais tarde, na cifra.
 */
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
 * \brief Implementação nativa de `KeyGenerator.exportPublicKey(String, String)`.
 *
 * \details Converte os dois argumentos `String` para UTF-8 e chama
 *          `exportPublicKey()` da biblioteca, que lê a chave privada de
 *          `privfile` e grava apenas a chave pública em `pubfile`. Depois
 *          libera os dois buffers com `ReleaseStringUTFChars`. Não há valor de
 *          retorno: o sucesso é indicado pela ausência de exceção.
 *
 * \param[in] env Ponteiro do contexto JNI (`JNIEnv`) da thread chamadora.
 * <b>self</b> (parâmetro sem nome na assinatura) Instância de
 *            `com.libzupt.KeyGenerator` que chamou o método. Não é usada.
 * \param[in] jprivfile Caminho do arquivo de chave privada de origem.
 * \param[in] jpubfile Caminho do arquivo de chave pública de destino.
 *
 * \warning Os dois retornos de `GetStringUTFChars` não são verificados quanto
 *          a `nullptr`.
 *
 * \warning Se `exportPublicKey()` lançar exceção, nenhuma das duas liberações
 *          é executada; os buffers UTF-8 ficam sem liberação.
 *
 * \note O arquivo de destino é criado com as permissões padrão do processo. A
 *       biblioteca não aplica aqui as restrições de permissão usadas ao gravar
 *       chaves privadas, o que é aceitável porque o conteúdo é público.
 */
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
 * \brief Implementação nativa de `KeyGenerator.saveKeyPair(KeyPair, String)`.
 *
 * \details Lê os campos `publicKey` e `secretKey` do objeto
 *          `com.libzupt.KeyPair` recebido (com `GetObjectField` + \ref
 *          jbyteArrayToVector), monta um `zupt::KeyPair` por movimentação dos
 *          dois vetores e chama `saveKeyPair()` da biblioteca, que grava a
 *          chave privada em `filename` com permissões restritas.
 *
 *          A resolução da classe e dos campos é feita aqui de forma sob
 *          demanda, duplicando o bloco de inicialização de \ref
 *          createKeyPair.
 *
 * \param[in] env Ponteiro do contexto JNI (`JNIEnv`) da thread chamadora.
 * <b>self</b> (parâmetro sem nome na assinatura) Instância de
 *            `com.libzupt.KeyGenerator` que chamou o método. Não é usada.
 * \param[in] jkeypair Objeto `com.libzupt.KeyPair` com os campos a gravar.
 * \param[in] jfilename Caminho do arquivo de destino, como `java.lang.String`.
 *
 * \warning Este bloco de resolução é diferente do de \ref createKeyPair, ele
 *          aplica `NewGlobalRef` diretamente sobre o resultado de `FindClass`,
 *          sem testar se a classe foi encontrada. Se `FindClass` devolver
 *          `nullptr`, a chamada é feita com um objeto nulo (comportamento
 *          indefinido) e os dois `GetFieldID` seguintes passam a usar uma
 *          classe nula.
 *
 * \warning Nenhum dos dois campos lidos é verificado. Se `jkeypair` for nulo,
 *          ou se `publicKey`/`secretKey` forem `null` no objeto Java, a cópia
 *          chega a `GetArrayLength` com um objeto nulo.
 *
 * \warning O retorno de `GetStringUTFChars` não é verificado, e a liberação
 *          não acontece se `saveKeyPair()` lançar exceção.
 *
 * \note `zupt::KeyPair kp` é construído por padrão com vetores já dimensionados
 *       (tamanho das constantes de chave da biblioteca), que são descartados
 *       imediatamente pelas duas movimentações.
 *
 * \note A chave privada chega a este código em cópias Java (o campo
 *       `secretKey` é uma matriz `byte[]` comum, não limpa) e em cópias
 *       nativas, nenhuma delas apagada com `zupt::secureWipe()`.
 */
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
 * \brief Implementação nativa de `Encryptor.nativeEncryptMemory(byte[])`.
 *
 * \details Converte o argumento para `std::vector`, lê a chave pública do
 *          campo `publicKey` do próprio objeto `Encryptor` (com
 *          `GetObjectClass` + `GetFieldID` + `GetObjectField` + \ref
 *          jbyteArrayToVector), constrói um `zupt::Encryptor` a partir dessa
 *          chave, chama `encryptMemory(data.data(), data.size())` e devolve o
 *          par `(texto cifrado, cabeçalho)` como `jobjectArray` de dois
 *          elementos, cada um uma matriz de bytes criada por \ref
 *          vectorToJByteArray.
 *
 *          Não existe estado nativo persistente: o objeto `Encryptor` é
 *          reconstruído a cada chamada a partir da cópia Java da chave
 *          pública.
 *
 * \param[in] env Ponteiro do contexto JNI (`JNIEnv`) da thread chamadora.
 * \param[in] self Instância de `com.libzupt.Encryptor`; o campo `publicKey` dela
 *            fornece a chave usada. O nome aparece comentado na declaração
 *            antecipada, mas está presente na definição.
 *            `com.libzupt.Encryptor`; o campo `publicKey` dela fornece a chave
 *            usada.
 * \param[in] jdata Texto claro a cifrar, como matriz `byte[]`.
 *
 * \return Matriz de objetos com dois elementos: texto cifrado na posição 0 e
 *         cabeçalho da cifra na posição 1; ou `nullptr` se uma exceção foi
 *         lançada.
 *
 * \note A variável local `publicKeyField` desta função tem o mesmo nome do
 *       identificador estático de arquivo (\ref publicKeyField), que pertence
 *       a `com.libzupt.KeyPair`. Aqui o nome é ocultado pelo local, o que é
 *       legítimo, mas torna fácil confundir os dois. Os métodos de
 *       `Decryptor` fazem o mesmo com \ref secretKeyField.
 *
 * \warning `GetFieldID`, `GetObjectField`, `NewObjectArray`,
 *          `env->FindClass("[B")` e `SetObjectArrayElement` são chamados sem
 *          verificação de retorno. Um campo `publicKey` nulo no objeto Java faz
 *          \ref jbyteArrayToVector receber `nullptr`.
 *
 * \warning `zupt::Encryptor` valida a estrutura da chave pública no
 *          construtor e lança exceção se ela não for uma chave v2 válida; a
 *          mensagem chega ao Java como `ZuptError`.
 *
 * \note O vetor `data`, que contém o texto claro, não é limpo com
 *       `zupt::secureWipe()` antes do retorno.
 *
 * \note As referências locais criadas (classe, campos e as duas matrizes de
 *       resultado) não são liberadas com `DeleteLocalRef`.
 */
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
 * \brief Implementação nativa de `Encryptor.nativeEncryptMemorySecure(byte[])`,
 *        sem correspondência no lado Java.
 *
 * \details O corpo é idêntico ao de
 *          \ref Java_com_libzupt_Encryptor_nativeEncryptMemory, que lê a chave pública
 *          do campo `publicKey` de `self`, constrói um `zupt::Encryptor` e
 *          chama `encryptMemory(data.data(), data.size())`, devolvendo o par
 *          `(texto cifrado, cabeçalho)` em uma `jobjectArray`.
 *
 * \param[in] env Ponteiro do contexto JNI (`JNIEnv`) da thread chamadora.
 * \param[in] self Instância de `com.libzupt.Encryptor`; o campo `publicKey`
 *            dela fornece a chave usada.
 * \param[in] jdata Texto claro a cifrar, como matriz `byte[]`.
 *
 * \return Matriz de objetos com dois elementos (texto cifrado e cabeçalho), ou
 *         `nullptr` se uma exceção foi lançada.
 *
 * \warning Nada neste caminho é mais seguro que o de
 *          \ref Java_com_libzupt_Encryptor_nativeEncryptMemory. O nome sugere uso de
 *          `zupt::SecureBuffer`, mas a função chama exatamente o mesmo método
 *          `encryptMemory` e usa apenas `std::vector` comuns, sem limpeza.
 *
 * \warning Esta função não está registrada em \ref encryptorMethods, não está
 *          na lista de declarações antecipadas e `Encryptor.java` não declara
 *          um método nativo com esse nome. Ela não é alcançável pelo API Java:
 *          `Encryptor.encryptMemorySecure(SecureBuffer)` chama
 *          `nativeEncryptMemory` com o resultado de `buffer.toBytes()`.
 *
 * \note Além de não ser alcançável, o caminho Java que existe para "cifração
 *       segura" já anula o buffer seguro: `SecureBuffer.toBytes()` devolve uma
 *       cópia comum, que é a matriz entregue a esta função.
 */
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
 * \brief Implementação nativa de `Encryptor.nativeEncryptFile(String)`.
 *
 * \details Converte o nome do arquivo para UTF-8, lê a chave pública do campo
 *          `publicKey` de `self`, constrói um `zupt::Encryptor` e chama
 *          `encryptFile(filename)`. A string UTF-8 é liberada depois da
 *          cifra, e o par `(texto cifrado, cabeçalho)` é devolvido como
 *          `jobjectArray` de duas matrizes de bytes.
 *
 * \param[in] env Ponteiro do contexto JNI (`JNIEnv`) da thread chamadora.
 * \param[in] self Instância de `com.libzupt.Encryptor`; o campo `publicKey`
 *            dela fornece a chave usada.
 * \param[in] jfilename Caminho do arquivo em disco a cifrar, como
 *            `java.lang.String`.
 *
 * \return Matriz de objetos com dois elementos: texto cifrado na posição 0 e
 *         cabeçalho da cifra na posição 1; ou `nullptr` se uma exceção foi
 *         lançada.
 *
 * \warning O retorno de `GetStringUTFChars` não é verificado, e a liberação não
 *          acontece se a cifra lançar exceção.
 *
 * \warning Assim como nos demais métodos de `Encryptor`, as chamadas de
 *          `GetFieldID`/`GetObjectField`/`NewObjectArray`/`FindClass` não têm
 *          verificação de retorno.
 *
 * \note O arquivo de origem não é modificado: a cifra é feita em memória e o
 *       resultado é devolvido ao chamador Java, que decide o que fazer com
 *       ele.
 */
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
 * \brief Implementação nativa de `Decryptor.decryptMemoryNative(byte[], byte[])`.
 *
 * \details Converte o texto cifrado e o cabeçalho para `std::vector`, lê a
 *          chave privada do campo `secretKey` do próprio objeto `Decryptor`
 *          (com `GetObjectClass` + `GetFieldID` + `GetObjectField` + \ref
 *          jbyteArrayToVector), constrói um `zupt::Decryptor` a partir dessa
 *          chave e chama `decryptMemory(ponteiro, tamanho, cabeçalho)`. O
 *          texto claro resultante é devolvido como matriz `byte[]` criada por
 *          \ref vectorToJByteArray.
 *
 *          Não existe estado nativo persistente: o `zupt::Decryptor` é
 *          reconstruído a cada chamada a partir da cópia Java da chave privada.
 *
 * \param[in] env Ponteiro do contexto JNI (`JNIEnv`) da thread chamadora.
 * \param[in] self Instância de `com.libzupt.Decryptor`; o campo `secretKey`
 *            dela fornece a chave usada.
 * \param[in] jciphertext Texto cifrado produzido pela cifra híbrida.
 * \param[in] jheader Cabeçalho da cifra devolvido junto pelo `Encryptor`.
 *
 * \return Matriz `byte[]` com o texto claro, ou `nullptr` se uma exceção foi
 *         lançada.
 *
 * \warning Os três retornos de leitura (`GetFieldID`, `GetObjectField` e a
 *          conversão de matriz) não são verificados, e `GetFieldID`/`FindClass`
 *          são reexecutados a cada chamada sem cache.
 *
 * \note A variável local `secretKeyField` desta função oculta o identificador
 *       estático de arquivo \ref secretKeyField, que pertence a
 *       `com.libzupt.KeyPair`.
 *
 * \note Falhas de decifração — chave incorreta, cabeçalho inválido, soma de
 *       verificação divergente, tamanho fora do suportado — são sinalizadas
 *       pela biblioteca com exceção e chegam ao Java como `ZuptError`, sem
 *       dados parciais no retorno.
 *
 * \warning O texto claro passa por pelo menos duas cópias nativas em memória
 *          não protegida (`std::vector` do resultado e a matriz Java de
 *          retorno), e nenhuma delas é limpa com `zupt::secureWipe()`.
 */
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
 * \brief Implementação nativa de `Decryptor.decryptMemorySecure(...)`, sem
 *        correspondência no lado Java.
 *
 * \details Lê texto cifrado, cabeçalho e a chave privada do campo `secretKey`
 *          de `self` como nas demais funções, chama
 *          `decryptMemorySecure(ciphertext, header)` da biblioteca (versão que
 *          recebe os dois vetores por referência) e devolve o resultado
 *          convertendo o `zupt::SecureBuffer` obtido com `toVector()` para uma
 *          matriz `byte[]` comum.
 *
 * \param[in] env Ponteiro do contexto JNI (`JNIEnv`) da thread chamadora.
 * \param[in] self Instância de `com.libzupt.Decryptor`; o campo `secretKey`
 *            dela fornece a chave usada.
 * \param[in] jciphertext Texto cifrado produzido pela cifra híbrida.
 * \param[in] jheader Cabeçalho da cifra devolvido junto pelo `Encryptor`.
 *
 * \return Matriz `byte[]` com o texto claro, ou `nullptr` se uma exceção foi
 *         lançada.
 *
 * \warning A proteção do `zupt::SecureBuffer` é perdida na fronteira: o texto
 *          claro é copiado por `toVector()` e entregue ao Java como matriz
 *          comum, que não é apagada. O `SecureBuffer` local é limpo ao sair do
 *          escopo, mas isso não atinge a cópia que foi devolvida.
 *
 * \warning Esta função não está registrada em \ref decryptorMethods, não está
 *          na lista de declarações antecipadas e `Decryptor.java` não declara
 *          um método nativo com esse nome. `Decryptor.decryptMemorySecure` em
 *          Java chama `decryptMemoryNative` e apenas embrulha o resultado em um
 *          `SecureBuffer` do lado Java, de modo que esta implementação não é
 *          alcançável.
 */
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
 * \brief Implementação nativa de `Decryptor.decryptFileNative(String, byte[])`.
 *
 * \details Converte o nome do arquivo e o cabeçalho, lê a chave privada do
 *          campo `secretKey` de `self`, constrói um `zupt::Decryptor` e chama
 *          `decryptFile(filename, header)`. A string UTF-8 é liberada depois da
 *          decifração e o texto claro é devolvido como matriz `byte[]`.
 *
 * \param[in] env Ponteiro do contexto JNI (`JNIEnv`) da thread chamadora.
 * \param[in] self Instância de `com.libzupt.Decryptor`; o campo `secretKey`
 *            dela fornece a chave usada.
 * \param[in] jfilename Caminho do arquivo cifrado em disco.
 * \param[in] jheader Cabeçalho da cifra devolvido pelo `Encryptor`.
 *
 * \return Matriz `byte[]` com o texto claro, ou `nullptr` se uma exceção foi
 *         lançada.
 *
 * \warning O retorno de `GetStringUTFChars` não é verificado, e a liberação não
 *          acontece se a decifração lançar exceção.
 *
 * \note As leituras de campo e de matriz não são verificadas; o texto claro
 *       resultante também não é limpo após a cópia para Java.
 */
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
 * \brief Implementação nativa de `NativeLib.randomBytes(int)`.
 *
 * \details Chama `zupt::randomBytes(size)` da biblioteca, que preenche um
 *          vetor com bytes de aleatoriedade criptograficamente segura, e
 *          devolve o resultado como matriz `byte[]` criada por \ref
 *          vectorToJByteArray.
 *
 * \param[in] env Ponteiro do contexto JNI (`JNIEnv`) da thread chamadora.
 * <b>self</b> Classe `com.libzupt.NativeLib` (o método é `static`). Não é
 *            usado (o nome está comentado na assinatura).
 * \param[in] size Quantidade de bytes a gerar.
 *
 * \return Matriz `byte[]` com os bytes aleatórios, ou `nullptr` se uma exceção
 *         foi lançada.
 *
 * \warning `size` é um `jint` com sinal e é convertido implicitamente para o
 *          `size_t` sem sinal de `zupt::randomBytes`. Um valor negativo vira um
 *          tamanho enorme; o `std::vector` interno então lança
 *          `std::length_error` ou `std::bad_alloc`, que é reportado ao Java
 *          como `ZuptError` com mensagem de alocação, e não como argumento
 *          inválido.
 *
 * \warning Não há limite superior verificado aqui, e `NativeLib.java` declara o
 *          método como `public static native` sem qualquer envolvente de
 *          validação, de modo que a aplicação pode pedir uma alocação
 *          arbitrariamente grande.
 */
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
 * \brief Calcula o digest SHA-256 dos bytes recebidos.
 *
 * Converte o array Java em `std::vector<uint8_t>` por \ref jbyteArrayToVector,
 * chama `zupt::sha256(const uint8_t*, size_t)` e converte o resultado de volta
 * por \ref vectorToJByteArray. O vetor de saída tem sempre 32 bytes.
 *
 * \param[in] env Ponteiro do contexto JNI (`JNIEnv`) da thread chamadora.
 * <b>self</b> Classe `com.libzupt.NativeLib` (o método é `static`). Não é
 *            usado (o nome está comentado na assinatura).
 * \param[in] jdata Dados a serem hasheados.
 *
 * \return Matriz `byte[]` de 32 bytes com o digest, ou `nullptr` se uma exceção
 *         foi lançada.
 *
 * \note \ref jbyteArrayToVector não verifica `jdata`; ver as observações dessa
 *       função para o comportamento diante de matriz nula.
 */
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
 * \brief Calcula o digest SHA3-512 dos bytes recebidos.
 *
 * Idêntica em estrutura a \ref Java_com_libzupt_NativeLib_sha256, mas chama
 * `zupt::sha3_512(const uint8_t*, size_t)`. O vetor de saída tem sempre 64
 * bytes.
 *
 * \param[in] env Ponteiro do contexto JNI (`JNIEnv`) da thread chamadora.
 * <b>self</b> Classe `com.libzupt.NativeLib` (o método é `static`). Não é
 *            usado (o nome está comentado na assinatura).
 * \param[in] jdata Dados a serem hasheados.
 *
 * \return Matriz `byte[]` de 64 bytes com o digest, ou `nullptr` se uma
 *         exceção foi lançada.
 *
 * \note O nome exposto ao Java é `sha3512`, enquanto a função C++ chamada é
 *       `zupt::sha3_512` (SHA3-512, digest de 64 bytes). A tabela de métodos
 *       nativos em \ref nativeLibMethods é o que associa os dois.
 */
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