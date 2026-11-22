/*
 * libzupt - Dynamic library for hybrid post-quantum encryption
 * ML-KEM-768 + X25519 for file and memory encryption/decryption
 *
 * Copyright (c) 2026 Cristian Cezar Moisés
 * SPDX-License-Identifier: MIT
 *
 * C++ Wrapper for Zupt hybrid encryption library
 */

/*!
 * @cond PORT
 * @file  zupt.hpp
 * @brief Interface C++17 da libzupt: invólucros de objeto sobre a ABI C.
 * @details Este cabeçalho apresenta a mesma biblioteca de `include/zupt.h` e
 * `include/zupt_cxx.h` como classes e tipos C++. Nada aqui reimplementa
 * criptografia: cada método apenas valida os argumentos, chama as funções C de
 * `zupt_cxx.h` (implementadas em `src/zupt_cxx.c`) e converte os resultados e
 * códigos de erro. As implementações dos métodos ficam em `src/zupt_crypto.cpp`.
 *
 * O que cada parte entrega:
 * - `ErrorCode` e `ZuptError`: os códigos de erro C viram exceções lançadas,
 * com a mensagem textual do erro; nada retorna código de erro por valor.
 * - `SecureBuffer`: memória alocada com as funções de páginas seguras da
 * biblioteca (via `zupt_secure_alloc`/`zupt_secure_free`), zerada no
 * destrutor — o equivalente RAII de `zupt_secure_alloc` + `zupt_secure_wipe`
 * + `zupt_secure_free` em C.
 * - `KeyGenerator`, `Encryptor` e `Decryptor`: ciclo de vida completo
 * (geração, cifra, decifragem) com a chave guardada no objeto.
 * - Funções soltas (`generateKeyPair`, `randomBytes`, `sha256`,
 * `secureWipe`, `lockMemory`, `unlockMemory`, `isMemoryLocked` e os
 * carregadores/salvadores de chave): atalhos diretos para as funções C
 * correspondentes, sem objeto envolvido.
 *
 * Convenções desta camada, que valem para todos os métodos:
 * - Erros são exceções (`ZuptError` para falhas da biblioteca,
 * `std::bad_alloc` para falta de memória). Nenhum método retorna "nulo" para
 * indicar erro, exceto onde o comentário do próprio método diz o contrário.
 * - Toda chave, texto cifrado e cabeçalho de cifra que entram em uma destas
 * classes são copiados para dentro do objeto. O chamador continua dono dos
 * buffers originais.
 * - `Encryptor` guarda o cabeçalho da última cifra e o zera no destrutor;
 * `Decryptor` guarda a chave privada e a zera no destrutor. Nenhum dos dois
 * apaga o texto cifrado que o chamador forneceu.
 *
 * @note `Encryptor::initEncryptionHeader` e `Decryptor::deriveKeys` são
 * declaradas aqui e não definidas em `src/`. Qualquer chamada resulta em
 * erro de vinculação. Ver os comentários dos membros.
 * @endcond
 * @cond INGLES
 * @file  zupt.hpp
 * @brief C++17 interface of libzupt: object wrappers over the C ABI.
 * @details This header presents the same library as `include/zupt.h` and
 * `include/zupt_cxx.h` as C++ classes and types. Nothing here reimplements
 * cryptography: each method only validates the arguments, calls the C functions of
 * `zupt_cxx.h` (implemented in `src/zupt_cxx.c`) and converts the results and
 * error codes. The method implementations live in `src/zupt_crypto.cpp`.
 *
 * What each part delivers:
 * - `ErrorCode` and `ZuptError`: the C error codes become thrown exceptions,
 * with the textual error message; nothing returns an error code by value.
 * - `SecureBuffer`: memory allocated with the library's secure page functions
 * (via `zupt_secure_alloc`/`zupt_secure_free`), zeroed in the
 * destructor — the RAII equivalent of `zupt_secure_alloc` + `zupt_secure_wipe`
 * + `zupt_secure_free` in C.
 * - `KeyGenerator`, `Encryptor` and `Decryptor`: full life cycle
 * (generation, encryption, decryption) with the key held in the object.
 * - Free functions (`generateKeyPair`, `randomBytes`, `sha256`,
 * `secureWipe`, `lockMemory`, `unlockMemory`, `isMemoryLocked` and the
 * key loaders/savers): direct shortcuts to the corresponding C functions,
 * with no object involved.
 *
 * Conventions of this layer, which apply to all methods:
 * - Errors are exceptions (`ZuptError` for library failures,
 * `std::bad_alloc` for out of memory). No method returns "null" to
 * indicate an error, except where the comment of the method itself says
 * otherwise.
 * - Every key, ciphertext and encryption header that enters one of these
 * classes is copied into the object. The caller remains the owner of the
 * original buffers.
 * - `Encryptor` keeps the header of the last encryption and zeroes it in the
 * destructor; `Decryptor` keeps the private key and zeroes it in the
 * destructor. Neither one erases the ciphertext the caller provided.
 *
 * @note `Encryptor::initEncryptionHeader` and `Decryptor::deriveKeys` are
 * declared here and not defined in `src/`. Any call results in a link
 * error. See the comments of the members.
 * @endcond */

#ifndef ZUPT_HPP
#define ZUPT_HPP

#include "zupt_cxx.h"
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>
#include <utility>
#include <string.h>
/**
 * @cond PORT
 * @namespace zupt
 * @brief Espaço de nomes da API C++ da libzupt.
 * @endcond
 * @cond INGLES
 * @namespace zupt
 * @brief Namespace of the libzupt C++ API.
 * @endcond */
namespace zupt {

/* ═══════════════════════════════════════════════════════════════════
 * ERROR CODES
 * ═══════════════════════════════════════════════════════════════════ */

//! @cond PORT
//! @brief Códigos de erro reportados pela camada C++ via \ref zupt::ZuptError "ZuptError".
//! @endcond
//! @cond INGLES
//! @brief Error codes reported by the C++ layer via \ref zupt::ZuptError "ZuptError".
//! @endcond
/*!
 * @cond PORT
 * \details São valores negativos (exceto OK = 0), no mesmo espírito dos
 * códigos da API C. \note Nem todos os valores são lançados pela
 * camada C++: funções internas do wrapper C devolvem `int` e o lado
 * C++ converte qualquer valor diferente de zero em
 * ErrorCode::ERR_INVALID, sem mapear o código original.
 * @endcond
 * @cond INGLES
 * \details These are negative values (except OK = 0), in the same spirit as
 * the codes of the C API. \note Not all values are thrown by the
 * C++ layer: internal functions of the C wrapper return `int` and the
 * C++ side converts any value different from zero into
 * ErrorCode::ERR_INVALID, without mapping the original code.
 * @endcond */
enum class ErrorCode : int {
    //! @cond PORT
    //! @brief Operação concluída com sucesso (nenhuma falha).
    //! @endcond
    //! @cond INGLES
    //! @brief Operation completed successfully (no failure).
    //! @endcond
    OK = 0,
    //! @cond PORT
    //! @brief Falha de entrada/saída: abrir, ler, escrever ou determinar o tamanho de um arquivo.
    //! @endcond
    //! @cond INGLES
    //! @brief Input/output failure: opening, reading, writing, or determining the size of a file.
    //! @endcond
    ERR_IO = -1,
    //! @cond PORT
    //! @brief Dados cifrados/serializados corrompidos (estrutura interna inconsistente).
    //! @endcond
    //! @cond INGLES
    //! @brief Corrupted encrypted/serialized data (inconsistent internal structure).
    //! @endcond
    ERR_CORRUPT = -2,
    //! @cond PORT
    //! @brief Magic/assinatura de formato ausente ou diferente do esperado.
    //! @endcond
    //! @cond INGLES
    //! @brief Format magic/signature missing or different from the expected one.
    //! @endcond
    ERR_BAD_MAGIC = -3,
    //! @cond PORT
    //! @brief Versão de formato não suportada (chave, cabeçalho de cifra ou envelope).
    //! @endcond
    //! @cond INGLES
    //! @brief Unsupported format version (key, cipher header, or envelope).
    //! @endcond
    ERR_BAD_VERSION = -4,
    //! @cond PORT
    //! @brief Soma de verificação do envelope não confere.
    //! @endcond
    //! @cond INGLES
    //! @brief Envelope checksum does not match.
    //! @endcond
    ERR_BAD_CHECKSUM = -5,
    //! @cond PORT
    //! @brief Falha de alocação de memória.
    //! @endcond
    //! @cond INGLES
    //! @brief Memory allocation failure.
    //! @endcond
    ERR_NOMEM = -6,
    //! @cond PORT
    //! @brief Tamanho pedido excede o máximo suportado pelo formato ou pelo tipo de contagem usado.
    //! @endcond
    //! @cond INGLES
    //! @brief Requested size exceeds the maximum supported by the format or by the count type used.
    //! @endcond
    ERR_OVERFLOW = -7,
    //! @cond PORT
    //! @brief Argumento, buffer, tamanho ou resultado de chamada interna inválido (inclusive falhas genéricas do lado C).
    //! @endcond
    //! @cond INGLES
    //! @brief Invalid argument, buffer, size, or internal call result (including generic failures on the C side).
    //! @endcond
    ERR_INVALID = -8,
    //! @cond PORT
    //! @brief Item procurado não existe (por exemplo chave em anel de chaves).
    //! @endcond
    //! @cond INGLES
    //! @brief Requested item does not exist (for example a key in a keyring).
    //! @endcond
    ERR_NOT_FOUND = -9,
    //! @cond PORT
    //! @brief Operação, versão ou parâmetro não suportado por esta build.
    //! @endcond
    //! @cond INGLES
    //! @brief Operation, version, or parameter not supported by this build.
    //! @endcond
    ERR_UNSUPPORTED = -10,
    //! @cond PORT
    //! @brief Falha de autenticação: o MAC/GCM do envelope não validou (dados adulterados, chave errada ou cabeçalho inconsistente).
    //! @endcond
    //! @cond INGLES
    //! @brief Authentication failure: the MAC/GCM of the envelope did not validate (tampered data, wrong key, or inconsistent header).
    //! @endcond
    ERR_AUTH_FAIL = -11,
};

/* ═══════════════════════════════════════════════════════════════════
 * EXCEPTION CLASS
 * ═══════════════════════════════════════════════════════════════════ */

//! @cond PORT
//! @brief Exceção lançada por toda a camada C++ da biblioteca.
//! @endcond
//! @cond INGLES
//! @brief Exception thrown by the whole C++ layer of the library.
//! @endcond
/*!
 * @cond PORT
 * \details Todas as funções C++ deste cabeçalho reportam falhas lançando
 * ZuptError (ou uma exceção padrão da STL que a camada reencapsula).
 * \note A camada C++ não usa códigos de retorno: as funções que o
 * wrapper C chama internamente retornam `int`, e qualquer valor
 * diferente de zero faz `checkError()` lançar
 * ErrorCode::ERR_INVALID. O código de erro específico de cada função
 * (por exemplo ERR_AUTH_FAIL) não é propagado para o lado C++ — ver
 * arquivo de achados.
 * \exception std::bad_alloc alocação dos buffers internos falha.
 * @endcond
 * @cond INGLES
 * \details All C++ functions of this header report failures by throwing
 * ZuptError (or a standard STL exception that the layer wraps again).
 * \note The C++ layer does not use return codes: the functions that the
 * C wrapper calls internally return `int`, and any value
 * different from zero makes `checkError()` throw
 * ErrorCode::ERR_INVALID. The specific error code of each function
 * (for example ERR_AUTH_FAIL) is not propagated to the C++ side — see
 * findings file.
 * \exception std::bad_alloc allocation of the internal buffers fails.
 * @endcond */
class ZuptError : public std::runtime_error {
public:
    //! @cond PORT
    //! @brief Constrói a exceção.
    //! @endcond
    //! @cond INGLES
    //! @brief Constructs the exception.
    //! @endcond
    /*!
     * @cond PORT
     * \param code Código de erro que descreve a falha.
     * \param msg  Mensagem descritiva (opcional); pode ser vazia.
     * \exception std::bad_alloc alocação da string da exceção falha.
     * @endcond
     * @cond INGLES
     * \param code Error code that describes the failure.
     * \param msg  Descriptive message (optional); it may be empty.
     * \exception std::bad_alloc allocation of the exception string fails.
     * @endcond */
    explicit ZuptError(ErrorCode code, const std::string& msg = "")
        : std::runtime_error(msg), code_(code) {}

    //! @cond PORT
    //! @brief Retorna o código numérico da exceção.
    //! @endcond
    //! @cond INGLES
    //! @brief Returns the numeric code of the exception.
    //! @endcond
    /*!
     * @cond PORT
     * \return O mesmo enumerador informado no construtor.
     * @endcond
     * @cond INGLES
     * \return The same enumerator reported in the constructor.
     * @endcond */
    ErrorCode code() const noexcept { return code_; }

private:
    /**
     * @cond PORT
     * @brief Código de erro associado à exceção.
     * @endcond
     * @cond INGLES
     * @brief Error code associated with the exception.
     * @endcond */
    ErrorCode code_;
};

/* ═══════════════════════════════════════════════════════════════════
 * CONSTANTS
 * ═══════════════════════════════════════════════════════════════════ */

//! @cond PORT
//! @brief Tamanho da chave pública ML-KEM-768 (FIPS 203), em bytes.
//! @endcond
//! @cond INGLES
//! @brief Size of the ML-KEM-768 (FIPS 203) public key, in bytes.
//! @endcond
constexpr size_t MLKEM_PUBLICKEYBYTES = 1184;

//! @cond PORT
//! @brief Tamanho da chave secreta ML-KEM-768 (FIPS 203), em bytes.
//! @endcond
//! @cond INGLES
//! @brief Size of the ML-KEM-768 (FIPS 203) secret key, in bytes.
//! @endcond
constexpr size_t MLKEM_SECRETKEYBYTES = 2400;

//! @cond PORT
//! @brief Tamanho do texto cifrado (ciphertext) ML-KEM-768 (FIPS 203), em bytes.
//! @endcond
//! @cond INGLES
//! @brief Size of the ML-KEM-768 (FIPS 203) ciphertext, in bytes.
//! @endcond
constexpr size_t MLKEM_CIPHERTEXTBYTES = 1088;

//! @cond PORT
//! @brief Tamanho do segredo compartilhado (shared secret) ML-KEM-768, em bytes.
//! @endcond
//! @cond INGLES
//! @brief Size of the ML-KEM-768 shared secret, in bytes.
//! @endcond
/*!
 * @cond PORT
 * \details Alimenta a KDF que produz a chave AES-256 da sessão.
 * @endcond
 * @cond INGLES
 * \details Feeds the KDF that produces the AES-256 session key.
 * @endcond */
constexpr size_t MLKEM_SSBYTES = 32;

//! @cond PORT
//! @brief Tamanho da chave (privada ou pública) X25519, em bytes.
//! @endcond
//! @cond INGLES
//! @brief Size of the X25519 key (private or public), in bytes.
//! @endcond
constexpr size_t X25519_KEYBYTES = 32;

//! @cond PORT
//! @brief Tamanhos dos arquivos de chave híbrida, em bytes.
//! @endcond
//! @cond INGLES
//! @brief Sizes of the hybrid key files, in bytes.
//! @endcond

//! @cond PORT
//! @brief Chave pública híbrida serializada: 8 (cabeçalho ZKEY) + 1184 (ML-KEM-768 pk) + 32 (X25519 pk).
//! @endcond
//! @cond INGLES
//! @brief Serialized hybrid public key: 8 (ZKEY header) + 1184 (ML-KEM-768 pk) + 32 (X25519 pk).
//! @endcond
constexpr size_t HYBRID_PUB_KEY_SIZE = 1224;  // 8 (header) + 1184 (ml_kem_pk) + 32 (x25519_pk)

//! @cond PORT
//! @brief Chave privada híbrida serializada: 8 (cabeçalho ZKEY) + 1184 (ml_kem_pk) + 32 (x25519 pk) + 2400 (ml_kem_sk) + 32 (x25519 sk).
//! @endcond
//! @cond INGLES
//! @brief Serialized hybrid private key: 8 (ZKEY header) + 1184 (ml_kem_pk) + 32 (x25519 pk) + 2400 (ml_kem_sk) + 32 (x25519 sk).
//! @endcond
constexpr size_t HYBRID_PRIV_KEY_SIZE = 3656; // 8 (header) + 1184 + 32 + 2400 + 32

//! @cond PORT
//! @brief Cabeçalho de cifra no modo híbrido: 1 (enc_type) + 1088 (ml_ct) + 32 (eph_pk) + 16 (nonce).
//! @endcond
//! @cond INGLES
//! @brief Cipher header in hybrid mode: 1 (enc_type) + 1088 (ml_ct) + 32 (eph_pk) + 16 (nonce).
//! @endcond
/*!
 * @cond PORT
 * \details É exatamente o tamanho retornado por `getEncryptionHeaderSize()`
 * e o valor aceito pelo lado C (`enc_hdr_len == 1137`).
 * @endcond
 * @cond INGLES
 * \details It is exactly the size returned by `getEncryptionHeaderSize()`
 * and the value accepted by the C side (`enc_hdr_len == 1137`).
 * @endcond */
constexpr size_t HYBRID_ENC_HEADER_SIZE = 1137; // 1 (enc_type) + 1088 (ml_ct) + 32 (eph_pk) + 16 (nonce)

//! @cond PORT
//! @brief Tamanho da chave AES-256 usada pelo wrapper C++ (32 bytes).
//! @endcond
//! @cond INGLES
//! @brief Size of the AES-256 key used by the C++ wrapper (32 bytes).
//! @endcond
constexpr size_t AES_KEY_SIZE = 32;

//! @cond PORT
//! @brief Tamanho do nonce AES-GCM (16 bytes).
//! @endcond
//! @cond INGLES
//! @brief Size of the AES-GCM nonce (16 bytes).
//! @endcond
constexpr size_t AES_NONCE_SIZE = 16;

//! @cond PORT
//! @brief Tamanho do MAC de verificação de autenticação (32 bytes).
//! @endcond
//! @cond INGLES
//! @brief Size of the authentication verification MAC (32 bytes).
//! @endcond
constexpr size_t HMAC_SIZE = 32;

/* ═══════════════════════════════════════════════════════════════════
 * KEY PAIR - Hybrid Post-Quantum Key Pair
 * ═══════════════════════════════════════════════════════════════════ */

//! @cond PORT
//! @brief Par de chaves híbridas pós-quânticas (ML-KEM-768 + X25519).
//! @endcond
//! @cond INGLES
//! @brief Post-quantum hybrid key pair (ML-KEM-768 + X25519).
//! @endcond
/*!
 * @cond PORT
 * \details Invariantes de tamanho observadas pelo código:
 * - `public_key`: 1224 bytes quando gerado/carregado por
 * `generateKeyPair()`/`loadKeyPair()`; quando a chave privada é
 * carregada a partir de um arquivo v1 (`legacy_version == 1`),
 * `public_key` recebe 1184 bytes (somente a chave pública ML-KEM,
 * sem o cabeçalho ZKEY de 8 bytes).
 * - `secret_key`: sempre 3656 bytes.
 * \note `secret_key` contém material sensível. Enquanto o objeto
 * viver, o segredo permanece em memória; este tipo não é movido para
 * um buffer auto-apagável.
 * @endcond
 * @cond INGLES
 * \details Size invariants observed by the code:
 * - `public_key`: 1224 bytes when generated/loaded by
 * `generateKeyPair()`/`loadKeyPair()`; when the private key is
 * loaded from a v1 file (`legacy_version == 1`),
 * `public_key` receives 1184 bytes (only the ML-KEM public key,
 * without the 8-byte ZKEY header).
 * - `secret_key`: always 3656 bytes.
 * \note `secret_key` contains sensitive material. While the object
 * lives, the secret remains in memory; this type is not moved to a
 * self-wiping buffer.
 * @endcond */
struct KeyPair {
    /**
     * @cond PORT
     * @brief Chave pública híbrida serializada (ver \ref KeyPair).
     * @endcond
     * @cond INGLES
     * @brief Serialized hybrid public key (see \ref KeyPair).
     * @endcond */
    std::vector<uint8_t> public_key;
    /**
     * @cond PORT
     * @brief Chave privada híbrida serializada (material sensível).
     * @endcond
     * @cond INGLES
     * @brief Serialized hybrid private key (sensitive material).
     * @endcond */
    std::vector<uint8_t> secret_key;

    //! @cond PORT
    //! @brief Constrói um par de chaves com os tamanhos padrão de chave híbrida.
    //! @endcond
    //! @cond INGLES
    //! @brief Constructs a key pair with the default hybrid key sizes.
    //! @endcond
    /*!
     * @cond PORT
     * \details Aloca `public_key` com HYBRID_PUB_KEY_SIZE (1224) e
     * `secret_key` com HYBRID_PRIV_KEY_SIZE (3656). Nenhum dos dois
     * vetores é preenchido: o chamador deve passar o objeto para
     * `generateKeyPairInternal()` (via `generateKeyPair()`) ou
     * `loadKeyPair()` antes de usar os valores.
     * @endcond
     * @cond INGLES
     * \details Allocates `public_key` with HYBRID_PUB_KEY_SIZE (1224) and
     * `secret_key` with HYBRID_PRIV_KEY_SIZE (3656). Neither one of the
     * two vectors is filled: the caller must pass the object to
     * `generateKeyPairInternal()` (via `generateKeyPair()`) or
     * `loadKeyPair()` before using the values.
     * @endcond */
    KeyPair() : public_key(HYBRID_PUB_KEY_SIZE), secret_key(HYBRID_PRIV_KEY_SIZE) {}

    //! @cond PORT
    //! @brief Constrói um par de chaves a partir de vetores existentes (move).
    //! @endcond
    //! @cond INGLES
    //! @brief Constructs a key pair from existing vectors (move).
    //! @endcond
    /*!
     * @cond PORT
     * \param pub  Chave pública serializada.
     * \param priv Chave privada serializada.
     * \details Não há verificação de tamanho: o objeto aceita vetores de
     * qualquer extensão, inclusive vazios.
     * @endcond
     * @cond INGLES
     * \param pub  Serialized public key.
     * \param priv Serialized private key.
     * \details There is no size check: the object accepts vectors of
     * any length, including empty ones.
     * @endcond */
    KeyPair(std::vector<uint8_t> pub, std::vector<uint8_t> priv)
        : public_key(std::move(pub)), secret_key(std::move(priv)) {}
};

/* ═══════════════════════════════════════════════════════════════════
 * SECURE BUFFER - Zeroized on destruction
 * ═══════════════════════════════════════════════════════════════════ */

//! @cond PORT
//! @brief Apaga `size` bytes de `ptr` de forma que o compilador não possa otimizar a escrita.
//! @endcond
//! @cond INGLES
//! @brief Wipes `size` bytes of `ptr` in a way the compiler cannot optimize the write away.
//! @endcond
/*!
 * @cond PORT
 * \param ptr Início do buffer a apagar. O ponteiro deve ser um buffer
 * contíguo de propriedade do chamador; a função não aloca nem
 * libera memória. Não há verificação de `nullptr`: passar
 * `nullptr` com `size > 0` é comportamento indefinido.
 * \param size Quantidade de bytes a apagar. `size == 0` é um no-op.
 * \details Implementação: `volatile` write + `asm volatile` de barreira de
 * otimização em `src/zupt_crypto.cpp`.
 * \note A função é declarada duas vezes neste cabeçalho (antes e depois das
 * classes); a duplicação é legal em C++, mas é redundância — ver
 * arquivo de achados.
 * @endcond
 * @cond INGLES
 * \param ptr Start of the buffer to wipe. The pointer must be a contiguous
 * buffer owned by the caller; the function neither allocates nor
 * frees memory. There is no `nullptr` check: passing
 * `nullptr` with `size > 0` is undefined behavior.
 * \param size Number of bytes to wipe. `size == 0` is a no-op.
 * \details Implementation: `volatile` write + `asm volatile` optimization barrier
 * in `src/zupt_crypto.cpp`.
 * \note The function is declared twice in this header (before and after the
 * classes); the duplication is legal in C++, but it is redundancy — see
 * findings file.
 * @endcond */
ZUPT_API void secureWipe(void* ptr, size_t size);

//! @cond PORT
//! @brief Buffer de tamanho fixo que zera o conteúdo ao ser destruído.
//! @endcond
//! @cond INGLES
//! @brief Fixed-size buffer that zeroes its content when destroyed.
//! @endcond
/*!
 * @cond PORT
 * \details Regras de cópia/movimento conforme o código:
 * - cópia construtiva e de atribuição: proibidas (`= delete`);
 * - movimento (construtor e atribuição): permitidos e `noexcept`. No
 * movimento por atribuição, o conteúdo destino é zerado
 * (`zeroize()`) antes de o buffer ser tomado de `other`; `other`
 * fica com `size() == 0` e `data() == nullptr`.
 * - destrutor: chama `zeroize()` se houver buffer.
 * \note `data()` devolve um ponteiro interno: ele é válido até o
 * objeto ser destruído ou movido, e o conteúdo pode ser sensível.
 * @endcond
 * @cond INGLES
 * \details Copy/move rules as in the code:
 * - copy constructor and copy assignment: forbidden (`= delete`);
 * - move (constructor and assignment): allowed and `noexcept`. In the
 * move assignment, the destination content is zeroed
 * (`zeroize()`) before the buffer is taken from `other`; `other`
 * is left with `size() == 0` and `data() == nullptr`.
 * - destructor: calls `zeroize()` if there is a buffer.
 * \note `data()` returns an internal pointer: it is valid until the
 * object is destroyed or moved, and the content may be sensitive.
 * @endcond */
class SecureBuffer {
public:
    //! @cond PORT
    //! @brief Aloca um buffer de `size` bytes (conteúdo inicial não definido).
    //! @endcond
    //! @cond INGLES
    //! @brief Allocates a buffer of `size` bytes (initial content is not defined).
    //! @endcond
    /*!
     * @cond PORT
     * \param size Quantidade de bytes a alocar.
     * \exception std::bad_alloc alocação falha.
     * @endcond
     * @cond INGLES
     * \param size Number of bytes to allocate.
     * \exception std::bad_alloc allocation fails.
     * @endcond */
    explicit SecureBuffer(size_t size)
        : data_(std::make_unique<uint8_t[]>(size)), size_(size) {}

    //! @cond PORT
    //! @brief Aloca um buffer de `size` bytes e copia o conteúdo de `data` para ele.
    //! @endcond
    //! @cond INGLES
    //! @brief Allocates a buffer of `size` bytes and copies the content of `data` into it.
    //! @endcond
    /*!
     * @cond PORT
     * \param data Fonte (pode ser `nullptr`, caso em que nada é copiado e o
     * buffer fica não inicializado).
     * \param size Tamanho a alocar e, se `data` não é nulo, a copiar.
     * \details Não há verificação do tamanho real de `data`; o chamador deve
     * garantir que `size` não ultrapassa o buffer fonte.
     * \exception std::bad_alloc alocação falha.
     * @endcond
     * @cond INGLES
     * \param data Source (it may be `nullptr`, in which case nothing is copied and
     * the buffer is left uninitialized).
     * \param size Size to allocate and, if `data` is not null, to copy.
     * \details There is no check of the actual size of `data`; the caller must
     * ensure that `size` does not exceed the source buffer.
     * \exception std::bad_alloc allocation fails.
     * @endcond */
    SecureBuffer(const uint8_t* data, size_t size)
        : data_(std::make_unique<uint8_t[]>(size)), size_(size) {
        if (data) {
            memcpy(data_.get(), data, size);
        }
    }

    //! @cond PORT
    //! @brief Cria um buffer com o mesmo conteúdo de `data`.
    //! @endcond
    //! @cond INGLES
    //! @brief Creates a buffer with the same content as `data`.
    //! @endcond
    /*!
     * @cond PORT
     * \param data Vetor fonte; o buffer fica com `data.size()` bytes.
     * \exception std::bad_alloc alocação falha.
     * @endcond
     * @cond INGLES
     * \param data Source vector; the buffer is left with `data.size()` bytes.
     * \exception std::bad_alloc allocation fails.
     * @endcond */
    SecureBuffer(const std::vector<uint8_t>& data)
        : data_(std::make_unique<uint8_t[]>(data.size())), size_(data.size()) {
        if (!data.empty()) {
            memcpy(data_.get(), data.data(), data.size());
        }
    }

    //! @cond PORT
    //! @brief Destrutor: zera o conteúdo antes de liberar o buffer.
    //! @endcond
    //! @cond INGLES
    //! @brief Destructor: zeroes the content before releasing the buffer.
    //! @endcond
    ~SecureBuffer() {
        if (data_) {
            zeroize();
        }
    }

    // Prevent copying
    /**
     * @cond PORT
     * @brief Cópias são proibidas para evitar duplicar material sensível.
     * @endcond
     * @cond INGLES
     * @brief Copies are forbidden to avoid duplicating sensitive material.
     * @endcond */
    SecureBuffer(const SecureBuffer&) = delete;
    //! @cond PORT
    //! @brief Atribuição por cópia é proibida.
    //! @endcond
    //! @cond INGLES
    //! @brief Copy assignment is forbidden.
    //! @endcond
    /*!
     * @cond PORT
     * \return Não há: a função está marcada como `= delete`.
     * @endcond
     * @cond INGLES
     * \return There is none: the function is marked as `= delete`.
     * @endcond */
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    // Allow moving
    //! @cond PORT
    //! @brief Construtor de movimento (noexcept): toma o buffer de `other`.
    //! @endcond
    //! @cond INGLES
    //! @brief Move constructor (noexcept): takes the buffer of `other`.
    //! @endcond
    /*!
     * @cond PORT
     * \param other Objeto de origem; ao final, `other.size() == 0` e
     * `other.data() == nullptr`. Nenhum zerado é aplicado à
     * origem (o conteúdo migra junto com o buffer).
     * @endcond
     * @cond INGLES
     * \param other Source object; at the end, `other.size() == 0` and
     * `other.data() == nullptr`. No zeroing is applied to the
     * source (the content migrates together with the buffer).
     * @endcond */
    SecureBuffer(SecureBuffer&& other) noexcept
        : data_(std::move(other.data_)), size_(std::exchange(other.size_, 0)) {}

    //! @cond PORT
    //! @brief Atribuição por movimento (noexcept): zera o destino e toma o buffer de `other`.
    //! @endcond
    //! @cond INGLES
    //! @brief Move assignment (noexcept): zeroes the destination and takes the buffer of `other`.
    //! @endcond
    /*!
     * @cond PORT
     * \param other Objeto de origem; ao final fica com tamanho zero.
     * \return Referencia a `*this`.
     * \details Se `this == &other`, nada é feito (nem o zerado).
     * @endcond
     * @cond INGLES
     * \param other Source object; at the end it is left with zero size.
     * \return Reference to `*this`.
     * \details If `this == &other`, nothing is done (not even the zeroing).
     * @endcond */
    SecureBuffer& operator=(SecureBuffer&& other) noexcept {
        if (this != &other) {
            zeroize();
            data_ = std::move(other.data_);
            size_ = std::exchange(other.size_, 0);
        }
        return *this;
    }

    /**
     * @cond PORT
     * Ponteiro mutável para o início do buffer.
     * @return `data_.get()`, que pode ser `nullptr` (buffer nulo ou objeto
     * movido). Válido enquanto o objeto viver.
     * @endcond
     * @cond INGLES
     * Mutable pointer to the start of the buffer.
     * @return `data_.get()`, which may be `nullptr` (null buffer or moved
     * object). Valid while the object lives.
     * @endcond */
    uint8_t* data() noexcept { return data_.get(); }

    /**
     * @cond PORT
     * Ponteiro somente leitura para o início do buffer.
     * @return `data_.get()`, que pode ser `nullptr` (buffer nulo ou objeto
     * movido). Válido enquanto o objeto viver.
     * @endcond
     * @cond INGLES
     * Read-only pointer to the start of the buffer.
     * @return `data_.get()`, which may be `nullptr` (null buffer or moved
     * object). Valid while the object lives.
     * @endcond */
    const uint8_t* data() const noexcept { return data_.get(); }

    /**
     * @cond PORT
     * Número de bytes do buffer.
     * @return Tamanho em bytes; `0` depois de o objeto ser movido.
     * @endcond
     * @cond INGLES
     * Number of bytes of the buffer.
     * @return Size in bytes; `0` after the object has been moved.
     * @endcond */
    size_t size() const noexcept { return size_; }

    //! @cond PORT
    //! @brief Zera todos os bytes do buffer via \ref secureWipe.
    //! @endcond
    //! @cond INGLES
    //! @brief Zeroes all bytes of the buffer via \ref secureWipe.
    //! @endcond
    /*!
     * @cond PORT
     * \details Não faz nada quando o buffer é nulo ou `size() == 0`.
     * @endcond
     * @cond INGLES
     * \details Does nothing when the buffer is null or `size() == 0`.
     * @endcond */
    void zeroize() noexcept {
        if (data_ && size_ > 0) {
            secureWipe(data_.get(), size_);
        }
    }

    //! @cond PORT
    //! @brief Copia o conteúdo para um `std::vector<uint8_t>`.
    //! @endcond
    //! @cond INGLES
    //! @brief Copies the content into a `std::vector<uint8_t>`.
    //! @endcond
    /*!
     * @cond PORT
     * \return Vetor com `size()` bytes do buffer; vazio quando `size() == 0`.
     * \exception std::bad_alloc alocação do vetor falha.
     * @endcond
     * @cond INGLES
     * \return Vector with `size()` bytes of the buffer; empty when `size() == 0`.
     * \exception std::bad_alloc allocation of the vector fails.
     * @endcond */
    std::vector<uint8_t> toVector() const {
        if (size_ == 0) return {};
        return std::vector<uint8_t>(data_.get(), data_.get() + size_);
    }

    //! @cond PORT
    //! @brief Copia o conteúdo para um `std::string` (sem interpretar o texto).
    //! @endcond
    //! @cond INGLES
    //! @brief Copies the content into a `std::string` (without interpreting the text).
    //! @endcond
    /*!
     * @cond PORT
     * \return String de `size()` bytes; vazia quando `size() == 0`.
     * \exception std::bad_alloc alocação da string falha.
     * @endcond
     * @cond INGLES
     * \return String of `size()` bytes; empty when `size() == 0`.
     * \exception std::bad_alloc allocation of the string fails.
     * @endcond */
    std::string toString() const {
        if (size_ == 0) return {};
        return std::string(reinterpret_cast<const char*>(data_.get()), size_);
    }

private:
    /**
     * @cond PORT
     * @brief Buffer de tamanho fixo (propriedade exclusiva do objeto).
     * @endcond
     * @cond INGLES
     * @brief Fixed-size buffer (exclusive property of the object).
     * @endcond */
    std::unique_ptr<uint8_t[]> data_;
    /**
     * @cond PORT
     * @brief Tamanho do buffer em bytes; 0 após movimento.
     * @endcond
     * @cond INGLES
     * @brief Size of the buffer in bytes; 0 after a move.
     * @endcond */
    size_t size_;
};

/* ═══════════════════════════════════════════════════════════════════
 * KEY GENERATOR - Generates hybrid post-quantum key pairs
 * ═══════════════════════════════════════════════════════════════════ */

//! @cond PORT
//! @brief Gerador e gerenciador de pares de chaves híbridas (ML-KEM-768 + X25519).
//! @endcond
//! @cond INGLES
//! @brief Generator and manager of hybrid key pairs (ML-KEM-768 + X25519).
//! @endcond
/*!
 * @cond PORT
 * \details Classe sem estado: não guarda material de chave entre chamadas.
 * Pode ser copida/movida livremente (regras padrão geradas pelo
 * compilador). Todo o estado observável está nos arquivos e nos
 * valores de retorno.
 * @endcond
 * @cond INGLES
 * \details Stateless class: it does not keep key material between calls.
 * It can be copied/moved freely (default rules generated by the
 * compiler). All observable state is in the files and in the
 * return values.
 * @endcond */
class KeyGenerator {
public:
    /**
     * @cond PORT
     * @brief Construtor padrão (não inicializa nada).
     * @endcond
     * @cond INGLES
     * @brief Default constructor (initializes nothing).
     * @endcond */
    KeyGenerator() = default;

    //! @cond PORT
    //! @brief Destrutor padrão (não há recursos a liberar).
    //! @endcond
    //! @cond INGLES
    //! @brief Default destructor (there are no resources to release).
    //! @endcond
    ~KeyGenerator() = default;

    // Generate a new hybrid key pair (ML-KEM-768 + X25519)
    //! @cond PORT
    //! @brief Gera um novo par de chaves híbridas.
    //! @endcond
    //! @cond INGLES
    //! @brief Generates a new hybrid key pair.
    //! @endcond
    /*!
     * @cond PORT
     * \return KeyPair com `public_key` de 1224 bytes (formato ZKEY público)
     * e `secret_key` de 3656 bytes (formato ZKEY privado).
     * \details Percorre o caminho completo em memória, sem tocar o disco:
     * aloca os buffers, chama `generateKeyPairInternal()` e empacota
     * o resultado.
     * \exception ZuptError(ErrorCode::ERR_INVALID) o lado C sinalizou falha
     * (retornou diferente de zero); a mensagem indica qual etapa
     * falhou.
     * \exception std::bad_alloc alocação dos buffers internos falha.
     * \note O segredo retornado é um `std::vector` comum — não é apagado
     * automaticamente quando o objeto morre.
     * @endcond
     * @cond INGLES
     * \return KeyPair with a 1224-byte `public_key` (public ZKEY format)
     * and a 3656-byte `secret_key` (private ZKEY format).
     * \details Walks the full path in memory, without touching the disk:
     * it allocates the buffers, calls `generateKeyPairInternal()` and packages
     * the result.
     * \exception ZuptError(ErrorCode::ERR_INVALID) the C side signaled a failure
     * (it returned a value different from zero); the message indicates which
     * step failed.
     * \exception std::bad_alloc allocation of the internal buffers fails.
     * \note The returned secret is a regular `std::vector` — it is not wiped
     * automatically when the object dies.
     * @endcond */
    KeyPair generateKeyPair();

    // Load a key pair from a file
    //! @cond PORT
    //! @brief Carrega um par de chaves privada+pública de um arquivo ZKEY privado.
    //! @endcond
    //! @cond INGLES
    //! @brief Loads a private+public key pair from a private ZKEY file.
    //! @endcond
    /*!
     * @cond PORT
     * \param filename Caminho do arquivo de chave privada.
     * \return KeyPair com `secret_key` igual ao arquivo inteiro (3656 bytes)
     * e `public_key` com os 1224 primeiros bytes do arquivo, tendo o
     * byte 5 (flag "tem chave privada") limpo.
     * \exception ZuptError(ErrorCode::ERR_IO) arquivo inexistente, tamanho
     * indeterminável ou falha de leitura.
     * \exception ZuptError(ErrorCode::ERR_INVALID) magic `ZKEY` ausente,
     * flag de privado ausente, ou tamanho diferente de 3656.
     * \exception ZuptError(ErrorCode::ERR_BAD_VERSION) byte de versão
     * diferente de 1 e de 2, ou bytes reservados (6 e 7)
     * diferentes de zero.
     * \details A chave pública nunca é recomputada a partir da privada: ela é
     * extraída dos bytes do arquivo. Não há checagem de que a chave
     * pública gravada corresponde à chave privada.
     * @endcond
     * @cond INGLES
     * \param filename Path of the private key file.
     * \return KeyPair with `secret_key` equal to the whole file (3656 bytes)
     * and `public_key` with the first 1224 bytes of the file, having
     * byte 5 ("has private key" flag) cleared.
     * \exception ZuptError(ErrorCode::ERR_IO) nonexistent file, undeterminable
     * size or read failure.
     * \exception ZuptError(ErrorCode::ERR_INVALID) `ZKEY` magic missing,
     * private flag missing, or size different from 3656.
     * \exception ZuptError(ErrorCode::ERR_BAD_VERSION) version byte
     * different from 1 and from 2, or reserved bytes (6 and 7)
     * different from zero.
     * \details The public key is never recomputed from the private one: it is
     * extracted from the bytes of the file. There is no check that the public
     * key stored corresponds to the private key.
     * @endcond */
    KeyPair loadKeyPair(const std::string& filename);

    // Load a public key only from a file
    //! @cond PORT
    //! @brief Carrega apenas a chave pública de um arquivo ZKEY público.
    //! @endcond
    //! @cond INGLES
    //! @brief Loads only the public key from a public ZKEY file.
    //! @endcond
    /*!
     * @cond PORT
     * \param filename Caminho do arquivo de chave pública.
     * \return Vetor com o conteúdo inteiro do arquivo (1224 bytes, já no
     * formato aceito por `Encryptor` e por \ref zupt_hybrid_encrypt).
     * \exception ZuptError(ErrorCode::ERR_IO) falha ao abrir/ler o arquivo.
     * \exception ZuptError(ErrorCode::ERR_INVALID) magic `ZKEY` ausente ou
     * tamanho diferente de 1224.
     * \exception ZuptError(ErrorCode::ERR_BAD_VERSION) byte de versão
     * diferente de 1 e de 2, flag de privado (byte 5) diferente
     * de zero, ou bytes reservados (6 e 7) diferentes de zero.
     * \note Esta função aceita arquivos v1, mas o `Encryptor` aceita
     * somente v2: uma chave pública v1 carregada aqui falha ao ser
     * usada para cifrar (ver arquivo de achados).
     * @endcond
     * @cond INGLES
     * \param filename Path of the public key file.
     * \return Vector with the whole content of the file (1224 bytes, already in
     * the format accepted by `Encryptor` and by \ref zupt_hybrid_encrypt).
     * \exception ZuptError(ErrorCode::ERR_IO) failure to open/read the file.
     * \exception ZuptError(ErrorCode::ERR_INVALID) `ZKEY` magic missing or
     * size different from 1224.
     * \exception ZuptError(ErrorCode::ERR_BAD_VERSION) version byte
     * different from 1 and from 2, private flag (byte 5) different
     * from zero, or reserved bytes (6 and 7) different from zero.
     * \note This function accepts v1 files, but the `Encryptor` accepts
     * only v2: a v1 public key loaded here fails when used to encrypt
     * (see findings file).
     * @endcond */
    std::vector<uint8_t> loadPublicKey(const std::string& filename);

    // Export only the public key to a file
    //! @cond PORT
    //! @brief Extrai a chave pública de um arquivo de chave privada e a grava em outro arquivo.
    //! @endcond
    //! @cond INGLES
    //! @brief Extracts the public key from a private key file and writes it to another file.
    //! @endcond
    /*!
     * @cond PORT
     * \param privfile Arquivo de chave privada ZKEY de origem (processado por
     * `loadKeyPair()` (membro privado), portanto sujeito às
     * mesmas validações).
     * \param pubfile  Arquivo de chave pública ZKEY de destino.
     * \exception ZuptError(ErrorCode::ERR_IO) falha ao criar/gravar o destino.
     * \exception ZuptError(ErrorCode::ERR_IO), ERR_INVALID ou
     * ERR_BAD_VERSION propagados de \ref loadKeyPair.
     * \details O arquivo de destino contém exatamente os 1224 bytes da chave
     * pública com a flag de privado limpa. Não são aplicadas as
     * proteções de permissão usadas por \ref zupt_write_private_key
     * (o arquivo é criado com as permissões padrão do processo). O
     * arquivo de origem não é alterado.
     * @endcond
     * @cond INGLES
     * \param privfile Source ZKEY private key file (processed by
     * `loadKeyPair()` (private member), therefore subject to
     * the same validations).
     * \param pubfile  Destination ZKEY public key file.
     * \exception ZuptError(ErrorCode::ERR_IO) failure to create/write the
     * destination.
     * \exception ZuptError(ErrorCode::ERR_IO), ERR_INVALID or
     * ERR_BAD_VERSION propagated from \ref loadKeyPair.
     * \details The destination file contains exactly the 1224 bytes of the public
     * key with the private flag cleared. The permission protections used by
     * \ref zupt_write_private_key are not applied (the file is created with
     * the default permissions of the process). The source file is not
     * altered.
     * @endcond */
    void exportPublicKey(const std::string& privfile, const std::string& pubfile);

    // Save a key pair to a file
    //! @cond PORT
    //! @brief Grava a chave privada de um par de chaves em arquivo com permissões restritas.
    //! @endcond
    //! @cond INGLES
    //! @brief Writes the private key of a key pair to a file with restricted permissions.
    //! @endcond
    /*!
     * @cond PORT
     * \param kp       Par de chaves cuja `secret_key` será gravada.
     * \param filename Caminho do arquivo de destino.
     * \exception ZuptError(ErrorCode::ERR_IO) \ref zupt_write_private_key
     * retornou erro (arquivo, permissão ou validação de formato).
     * \details Delega a \ref zupt_write_private_key, que aplica a escrita
     * restrita descrita nela. `public_key` de `kp` é ignorado.
     * @endcond
     * @cond INGLES
     * \param kp       Key pair whose `secret_key` will be written.
     * \param filename Path of the destination file.
     * \exception ZuptError(ErrorCode::ERR_IO) \ref zupt_write_private_key
     * returned an error (file, permission or format validation).
     * \details Delegates to \ref zupt_write_private_key, which applies the
     * restricted write described in it. The `public_key` of `kp` is ignored.
     * @endcond */
    void saveKeyPair(const KeyPair& kp, const std::string& filename);

private:
    //! @cond PORT
    //! @brief Etapa interna de geração (ML-KEM-768 + X25519), usada por \ref generateKeyPair.
    //! @endcond
    //! @cond INGLES
    //! @brief Internal generation step (ML-KEM-768 + X25519), used by \ref generateKeyPair.
    //! @endcond
    /*!
     * @cond PORT
     * \param ml_pk Buffer destino da chave pública ML-KEM (1184 bytes).
     * \param ml_sk Buffer destino da chave privada ML-KEM (2400 bytes).
     * \param x_pk  Buffer destino da chave pública X25519 (32 bytes).
     * \param x_sk  Buffer destino da chave privada X25519 (32 bytes).
     * \details Os quatro buffers são de responsabilidade do chamador.
     * @endcond
     * @cond INGLES
     * \param ml_pk Destination buffer of the ML-KEM public key (1184 bytes).
     * \param ml_sk Destination buffer of the ML-KEM private key (2400 bytes).
     * \param x_pk  Destination buffer of the X25519 public key (32 bytes).
     * \param x_sk  Destination buffer of the X25519 private key (32 bytes).
     * \details The four buffers are the responsibility of the caller.
     * @endcond */
    void generateKeyPairInternal(uint8_t* ml_pk, uint8_t* ml_sk,
                                  uint8_t* x_pk, uint8_t* x_sk);
};

/* ═══════════════════════════════════════════════════════════════════
 * ENCRYPTOR - Hybrid post-quantum encryption
 * ═══════════════════════════════════════════════════════════════════ */

//! @cond PORT
//! @brief Cifrador híbrido pós-quântico (ML-KEM-768 + X25519).
//! @endcond
//! @cond INGLES
//! @brief Post-quantum hybrid encryptor (ML-KEM-768 + X25519).
//! @endcond
/*!
 * @cond PORT
 * \details Invariante mantida pelo construtor: a chave guardada tem
 * exatamente HYBRID_PUB_KEY_SIZE (1224) bytes, magic `ZKEY`, byte 4
 * igual a ZUPT_KEY_FORMAT_VERSION (2), byte 5 igual a 0 (chave
 * pública), bytes 6 e 7 iguais a 0, e a chave pública ML-KEM passa em
 * `zupt_mlkem768_public_key_check`. Uma chave que não atende a isso
 * é rejeitada com ErrorCode::ERR_BAD_VERSION, inclusive chaves
 * públicas v1.
 * \note `Encryptor` é copiável/movível pelas regras padrão do
 * compilador (não declara cópia ou movimento). A cópia é segura por
 * conteúdo (apenas chave pública), mas o cabeçalho interno da última
 * cifra é duplicado.
 * \note Não há proteção contra uso concorrente: a chamada de
 * cifragem grava o cabeçalho da última operação em estado interno.
 * @endcond
 * @cond INGLES
 * \details Invariant maintained by the constructor: the stored key has
 * exactly HYBRID_PUB_KEY_SIZE (1224) bytes, `ZKEY` magic, byte 4
 * equal to ZUPT_KEY_FORMAT_VERSION (2), byte 5 equal to 0 (public
 * key), bytes 6 and 7 equal to 0, and the ML-KEM public key passes
 * `zupt_mlkem768_public_key_check`. A key that does not meet this
 * is rejected with ErrorCode::ERR_BAD_VERSION, including v1 public
 * keys.
 * \note `Encryptor` is copyable/movable by the default rules of the
 * compiler (it does not declare copy or move). The copy is safe by
 * content (public key only), but the internal header of the last
 * encryption is duplicated.
 * \note There is no protection against concurrent use: the encryption call
 * writes the header of the last operation into internal state.
 * @endcond */
class Encryptor {
public:
    //! @cond PORT
    //! @brief Constrói o cifrador a partir de uma chave pública híbrida.
    //! @endcond
    //! @cond INGLES
    //! @brief Constructs the encryptor from a hybrid public key.
    //! @endcond
    /*!
     * @cond PORT
     * \param publicKey Chave pública no formato ZKEY público (1224 bytes),
     * como produzida por `generateKeyPair()` ou
     * `loadPublicKey()` (membro privado).
     * \exception ZuptError(ErrorCode::ERR_BAD_VERSION) chave rejeitada:
     * tamanho diferente de 1224, magic ausente, versão diferente
     * de ZUPT_KEY_FORMAT_VERSION, flag de chave privada
     * diferente de zero, bytes reservados diferentes de zero ou
     * chave pública ML-KEM inválida.
     * \exception std::bad_alloc cópia da chave falha.
     * \details A chave é copiada para o objeto; o chamador pode liberar
     * o vetor original.
     * @endcond
     * @cond INGLES
     * \param publicKey Public key in the public ZKEY format (1224 bytes),
     * as produced by `generateKeyPair()` or
     * `loadPublicKey()` (private member).
     * \exception ZuptError(ErrorCode::ERR_BAD_VERSION) key rejected:
     * size different from 1224, magic missing, version different
     * from ZUPT_KEY_FORMAT_VERSION, private key flag
     * different from zero, reserved bytes different from zero or
     * invalid ML-KEM public key.
     * \exception std::bad_alloc copy of the key fails.
     * \details The key is copied into the object; the caller may free
     * the original vector.
     * @endcond */
    explicit Encryptor(const std::vector<uint8_t>& publicKey);

    //! @cond PORT
    //! @brief Destrutor: apaga o cabeçalho da última cifra guardado no objeto.
    //! @endcond
    //! @cond INGLES
    //! @brief Destructor: wipes the cipher header of the last encryption stored in the object.
    //! @endcond
    /*!
     * @cond PORT
     * \details O cabeçalho contém o ciphertext ML-KEM da chave de sessão,
     * por isso é zerado. O buffer de chave pública não é apagado
     * (não é material sensível).
     * @endcond
     * @cond INGLES
     * \details The header contains the ML-KEM ciphertext of the session key,
     * which is why it is zeroed. The public key buffer is not erased
     * (it is not sensitive material).
     * @endcond */
    ~Encryptor();

    // Encrypt a file - returns ciphertext and encryption header
    //! @cond PORT
    //! @brief Cifra o conteúdo inteiro de um arquivo.
    //! @endcond
    //! @cond INGLES
    //! @brief Encrypts the whole content of a file.
    //! @endcond
    /*!
     * @cond PORT
     * \param filename Arquivo em claro a ler.
     * \return Par `{ciphertext, enc_header}`: o texto cifrado (mesmo
     * tamanho do arquivo, pois o modo é de fluxo com MAC) e o
     * cabeçalho de cifra de HYBRID_ENC_HEADER_SIZE (1137) bytes.
     * \exception ZuptError(ErrorCode::ERR_IO) arquivo inexistente, tamanho
     * indeterminável ou falha de leitura.
     * \exception ZuptError(ErrorCode::ERR_INVALID) falha de cifragem ou
     * tamanho de cabeçalho inesperado retornado pelo lado C.
     * \exception std::bad_alloc o arquivo inteiro é lido para memória.
     * \details O arquivo de origem não é modificado: a função só lê. Cabe ao
     * chamador decidir se e quando apaga o arquivo em claro e se
     * grava `{ciphertext, enc_header}` no disco.
     * @endcond
     * @cond INGLES
     * \param filename Plaintext file to read.
     * \return Pair `{ciphertext, enc_header}`: the ciphertext (same
     * size as the file, because the mode is streaming with MAC) and the
     * encryption header of HYBRID_ENC_HEADER_SIZE (1137) bytes.
     * \exception ZuptError(ErrorCode::ERR_IO) nonexistent file, undeterminable
     * size or read failure.
     * \exception ZuptError(ErrorCode::ERR_INVALID) encryption failure or
     * unexpected header size returned by the C side.
     * \exception std::bad_alloc the whole file is read into memory.
     * \details The source file is not modified: the function only reads. It is up
     * to the caller to decide whether and when to erase the plaintext file and
     * whether to write `{ciphertext, enc_header}` to disk.
     * @endcond */
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> encryptFile(const std::string& filename);

    // Encrypt data in memory - returns ciphertext and encryption header
    //! @cond PORT
    //! @brief Cifra `size` bytes a partir de `data`.
    //! @endcond
    //! @cond INGLES
    //! @brief Encrypts `size` bytes starting from `data`.
    //! @endcond
    /*!
     * @cond PORT
     * \param data Buffer em claro (pode ser nulo apenas quando `size == 0`).
     * \param size Quantidade de bytes a cifrar.
     * \return Par `{ciphertext, enc_header}` com o texto cifrado e o
     * cabeçalho de cifra de 1137 bytes gerado para esta operação.
     * \exception ZuptError(ErrorCode::ERR_INVALID) `data` nulo com `size > 0`,
     * falha de cifragem ou tamanho de cabeçalho inesperado.
     * \exception std::bad_alloc alocação dos vetores de saída.
     * \details Cada chamada gera material efêmero novo, portanto o cabeçalho
     * retornado é específico deste texto cifrado. O cabeçalho desta
     * chamada também fica copiado no estado interno do objeto.
     * @endcond
     * @cond INGLES
     * \param data Plaintext buffer (it may be null only when `size == 0`).
     * \param size Number of bytes to encrypt.
     * \return Pair `{ciphertext, enc_header}` with the ciphertext and the
     * 1137-byte encryption header generated for this operation.
     * \exception ZuptError(ErrorCode::ERR_INVALID) null `data` with `size > 0`,
     * encryption failure or unexpected header size.
     * \exception std::bad_alloc allocation of the output vectors.
     * \details Each call generates new ephemeral material, therefore the returned
     * header is specific to this ciphertext. The header of this call
     * is also copied into the internal state of the object.
     * @endcond */
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> encryptMemory(const uint8_t* data, size_t size);

    // Encrypt data in memory (vector version)
    //! @cond PORT
    //! @brief Cifra o conteúdo de um vetor (equivale a `encryptMemory(data.data(), data.size())`).
    //! @endcond
    //! @cond INGLES
    //! @brief Encrypts the content of a vector (equivalent to `encryptMemory(data.data(), data.size())`).
    //! @endcond
    /*!
     * @cond PORT
     * \param data Vetor em claro (pode ser vazio: o resultado é um texto
     * cifrado de 0 bytes mais o cabeçalho).
     * \return Par `{ciphertext, enc_header}`.
     * \exception Ver \ref encryptMemory(const uint8_t*, size_t).
     * @endcond
     * @cond INGLES
     * \param data Plaintext vector (it may be empty: the result is a ciphertext of
     * 0 bytes plus the header).
     * \return Pair `{ciphertext, enc_header}`.
     * \exception See \ref encryptMemory(const uint8_t*, size_t).
     * @endcond */
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> encryptMemory(const std::vector<uint8_t>& data);

    // Encrypt data in memory (SecureBuffer version)
    //! @cond PORT
    //! @brief Cifra o conteúdo de um \ref SecureBuffer (o buffer de origem não é apagado).
    //! @endcond
    //! @cond INGLES
    //! @brief Encrypts the content of a \ref SecureBuffer (the source buffer is not wiped).
    //! @endcond
    /*!
     * @cond PORT
     * \param buffer Buffer em claro (pode ser vazio).
     * \return Par `{ciphertext, enc_header}`.
     * \exception Ver \ref encryptMemory(const uint8_t*, size_t).
     * @endcond
     * @cond INGLES
     * \param buffer Plaintext buffer (it may be empty).
     * \return Pair `{ciphertext, enc_header}`.
     * \exception See \ref encryptMemory(const uint8_t*, size_t).
     * @endcond */
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> encryptMemory(const SecureBuffer& buffer);

    // Get the encryption header size
    //! @cond PORT
    //! @brief Tamanho do cabeçalho de cifra gerado por este cifrador.
    //! @endcond
    //! @cond INGLES
    //! @brief Size of the cipher header generated by this encryptor.
    //! @endcond
    /*!
     * @cond PORT
     * \return HYBRID_ENC_HEADER_SIZE (1137 bytes), sempre.
     * @endcond
     * @cond INGLES
     * \return HYBRID_ENC_HEADER_SIZE (1137 bytes), always.
     * @endcond */
    static constexpr size_t getEncryptionHeaderSize() noexcept {
        return HYBRID_ENC_HEADER_SIZE;
    }

private:
    /*!
     * @cond PORT
     * Chave pública validada, em formato ZKEY público (1224 bytes).
     * Copiada do argumento do construtor e conferida ali mesmo: tamanho,
     * magic, versão, flags e a chave pública ML-KEM embutida. Não é apagada
     * no destrutor por não ser material sensível.
     * @endcond
     * @cond INGLES
     * Validated public key, in the public ZKEY format (1224 bytes).
     * Copied from the argument of the constructor and checked there: size,
     * magic, version, flags and the embedded ML-KEM public key. It is not erased
     * in the destructor because it is not sensitive material.
     * @endcond */
    std::vector<uint8_t> publicKey_;
    /*!
     * @cond PORT
     * Cópia do cabeçalho de cifra da última operação de cifra feita pelo
     * objeto. Contém o ciphertext ML-KEM da chave de sessão, portanto é
     * zerado com \ref secureWipe no destrutor (ver `~Encryptor`).
     * @endcond
     * @cond INGLES
     * Copy of the encryption header of the last encryption operation made by
     * the object. It contains the ML-KEM ciphertext of the session key, therefore
     * it is zeroed with \ref secureWipe in the destructor (see `~Encryptor`).
     * @endcond */
    std::vector<uint8_t> encryptionHeader_;

    /*!
     * @cond PORT
     * Reservada por código legado: declarada aqui, mas sem definição em
     * `src/`. Nenhuma função deste cabeçalho a chama, então chamar dá erro
     * de vinculação, não comportamento silencioso.
     * @endcond
     * @cond INGLES
     * Reserved by legacy code: declared here, but without a definition in
     * `src/`. No function of this header calls it, so calling it gives a link
     * error, not silent behavior.
     * @endcond */
    void initEncryptionHeader();
};

/* ═══════════════════════════════════════════════════════════════════
 * DECRYPTOR - Hybrid post-quantum decryption
 * ═══════════════════════════════════════════════════════════════════ */

//! @cond PORT
//! @brief Decifrador híbrido pós-quântico (ML-KEM-768 + X25519).
//! @endcond
//! @cond INGLES
//! @brief Post-quantum hybrid decryptor (ML-KEM-768 + X25519).
//! @endcond
/*!
 * @cond PORT
 * \details Invariante mantida pelo construtor: a chave guardada tem
 * exatamente HYBRID_PRIV_KEY_SIZE (3656) bytes. Diferentemente de
 * \ref Encryptor, o construtor NÃO valida magic, versão, flag de
 * privado nem o conteúdo das chaves: um buffer de 3656 bytes com
 * qualquer conteúdo é aceito e a falha aparece somente na decifragem
 * (ErrorCode::ERR_AUTH_FAIL).
 * \note `Decryptor` é copiável/movível pelas regras padrão do
 * compilador (não declara cópia nem movimento). Copiá-lo duplica a
 * chave privada em memória, e cada cópia é zerada no próprio destrutor.
 * \note Não há proteção contra uso concorrente.
 * @endcond
 * @cond INGLES
 * \details Invariant maintained by the constructor: the stored key has
 * exactly HYBRID_PRIV_KEY_SIZE (3656) bytes. Differently from
 * \ref Encryptor, the constructor does NOT validate magic, version, private
 * flag nor the content of the keys: a 3656-byte buffer with
 * any content is accepted and the failure appears only in the decryption
 * (ErrorCode::ERR_AUTH_FAIL).
 * \note `Decryptor` is copyable/movable by the default rules of the
 * compiler (it does not declare copy nor move). Copying it duplicates the
 * private key in memory, and each copy is zeroed in its own destructor.
 * \note There is no protection against concurrent use.
 * @endcond */
class Decryptor {
public:
    //! @cond PORT
    //! @brief Constrói o decifrador a partir de uma chave privada híbrida.
    //! @endcond
    //! @cond INGLES
    //! @brief Constructs the decryptor from a hybrid private key.
    //! @endcond
    /*!
     * @cond PORT
     * \param privateKey Chave privada no formato ZKEY privado (3656 bytes),
     * como produzida por `generateKeyPair()` ou
     * `loadKeyPair()` (membro privado).
     * \exception ZuptError(ErrorCode::ERR_INVALID) tamanho diferente de
     * HYBRID_PRIV_KEY_SIZE.
     * \exception std::bad_alloc cópia da chave falha.
     * \details A chave é copiada para o objeto; o chamador ainda é dono do
     * vetor original e é responsável por apagá-lo.
     * @endcond
     * @cond INGLES
     * \param privateKey Private key in the private ZKEY format (3656 bytes),
     * as produced by `generateKeyPair()` or
     * `loadKeyPair()` (private member).
     * \exception ZuptError(ErrorCode::ERR_INVALID) size different from
     * HYBRID_PRIV_KEY_SIZE.
     * \exception std::bad_alloc copy of the key fails.
     * \details The key is copied into the object; the caller is still the owner of
     * the original vector and is responsible for erasing it.
     * @endcond */
    explicit Decryptor(const std::vector<uint8_t>& privateKey);

    //! @cond PORT
    //! @brief Destrutor: apaga a chave privada guardada no objeto.
    //! @endcond
    //! @cond INGLES
    //! @brief Destructor: wipes the private key stored in the object.
    //! @endcond
    /*!
     * @cond PORT
     * \details Aplica \ref secureWipe sobre todo o buffer da chave privada.
     * @endcond
     * @cond INGLES
     * \details Applies \ref secureWipe over the whole private key buffer.
     * @endcond */
    ~Decryptor();

    // Decrypt a file using the provided encryption header
    //! @cond PORT
    //! @brief Decifra o conteúdo inteiro de um arquivo cifrado.
    //! @endcond
    //! @cond INGLES
    //! @brief Decrypts the whole content of an encrypted file.
    //! @endcond
    /*!
     * @cond PORT
     * \param filename  Arquivo contendo o texto cifrado (somente o corpo; o
     * cabeçalho de cifra não é lido daqui).
     * \param encHeader Cabeçalho de cifra de 1137 bytes obtido na cifragem.
     * \return Texto em claro com o tamanho real decifrado.
     * \exception ZuptError(ErrorCode::ERR_IO) arquivo inexistente, tamanho
     * indeterminável ou falha de leitura.
     * \exception ZuptError(ErrorCode::ERR_INVALID) cabeçalho com tamanho
     * diferente de 1137.
     * \exception ZuptError(ErrorCode::ERR_AUTH_FAIL) decifragem falhou
     * (chave errada, dados adulterados ou cabeçalho inconsistente).
     * \exception std::bad_alloc o arquivo inteiro é lido para memória.
     * \details O arquivo cifrado de origem não é modificado.
     * @endcond
     * @cond INGLES
     * \param filename  File containing the ciphertext (only the body; the
     * encryption header is not read from here).
     * \param encHeader 1137-byte encryption header obtained in the encryption.
     * \return Plaintext with the actual decrypted size.
     * \exception ZuptError(ErrorCode::ERR_IO) nonexistent file, undeterminable
     * size or read failure.
     * \exception ZuptError(ErrorCode::ERR_INVALID) header with size
     * different from 1137.
     * \exception ZuptError(ErrorCode::ERR_AUTH_FAIL) decryption failed
     * (wrong key, tampered data or inconsistent header).
     * \exception std::bad_alloc the whole file is read into memory.
     * \details The source encrypted file is not modified.
     * @endcond */
    std::vector<uint8_t> decryptFile(const std::string& filename, const std::vector<uint8_t>& encHeader);

    // Decrypt data in memory using the provided encryption header
    //! @cond PORT
    //! @brief Decifra `ciphertextSize` bytes a partir de `ciphertext`.
    //! @endcond
    //! @cond INGLES
    //! @brief Decrypts `ciphertextSize` bytes starting from `ciphertext`.
    //! @endcond
    /*!
     * @cond PORT
     * \param ciphertext     Buffer do texto cifrado (pode ser nulo apenas
     * quando `ciphertextSize == 0`).
     * \param ciphertextSize Quantidade de bytes cifrados.
     * \param encHeader      Cabeçalho de cifra de 1137 bytes.
     * \return Texto em claro com exatamente o comprimento decifrado.
     * \exception ZuptError(ErrorCode::ERR_INVALID) `ciphertext` nulo com
     * tamanho maior que zero, ou cabeçalho com tamanho diferente
     * de 1137.
     * \exception ZuptError(ErrorCode::ERR_AUTH_FAIL) a decifragem foi
     * rejeitada pelo lado C. \note este é o único código devolvido
     * para qualquer causa de falha (chave inválida, autenticação,
     * formato interno do cabeçalho etc.), pois o wrapper C++ não
     * distingue os erros da chamada interna.
     * \exception std::bad_alloc alocação do texto em claro. \note se a cópia
     * para o `std::vector` de retorno lançar, o buffer devolvido
     * pelo lado C não é zerado nem liberado (vazamento de texto em
     * claro).
     * \details O buffer devolvido pelo lado C é copiado, zerado
     * (\ref secureWipe) e liberado (\ref zupt_free) antes do return.
     * O keyring derivado vive só no lado C e é apagado por
     * `zupt_munlock_keys()`, que executa `zupt_secure_wipe()` antes
     * de liberar o bloqueio de memória — inclusive na decifragem
     * rejeitada.
     * @endcond
     * @cond INGLES
     * \param ciphertext     Buffer of the ciphertext (it may be null only
     * when `ciphertextSize == 0`).
     * \param ciphertextSize Number of encrypted bytes.
     * \param encHeader      1137-byte encryption header.
     * \return Plaintext with exactly the decrypted length.
     * \exception ZuptError(ErrorCode::ERR_INVALID) null `ciphertext` with
     * size greater than zero, or header with size different
     * from 1137.
     * \exception ZuptError(ErrorCode::ERR_AUTH_FAIL) the decryption was
     * rejected by the C side. \note this is the only code returned
     * for any cause of failure (invalid key, authentication,
     * internal format of the header etc.), because the C++ wrapper
     * does not distinguish the errors of the internal call.
     * \exception std::bad_alloc allocation of the plaintext. \note if the copy
     * into the return `std::vector` throws, the buffer returned
     * by the C side is neither zeroed nor freed (plaintext leak).
     * \details The buffer returned by the C side is copied, zeroed
     * (\ref secureWipe) and freed (\ref zupt_free) before the return.
     * The derived keyring lives only on the C side and is erased by
     * `zupt_munlock_keys()`, which runs `zupt_secure_wipe()` before
     * releasing the memory lock — including on rejected decryption.
     * @endcond */
    std::vector<uint8_t> decryptMemory(const uint8_t* ciphertext, size_t ciphertextSize,
                                       const std::vector<uint8_t>& encHeader);

    // Decrypt data in memory (vector version)
    //! @cond PORT
    //! @brief Decifra um vetor de texto cifrado (equivale à versão por ponteiro).
    //! @endcond
    //! @cond INGLES
    //! @brief Decrypts a vector of ciphertext (equivalent to the pointer version).
    //! @endcond
    /*!
     * @cond PORT
     * \param ciphertext Texto cifrado.
     * \param encHeader  Cabeçalho de cifra de 1137 bytes.
     * \return Texto em claro.
     * \exception Ver \ref decryptMemory(const uint8_t*, size_t, const std::vector<uint8_t>&).
     * @endcond
     * @cond INGLES
     * \param ciphertext Ciphertext.
     * \param encHeader  1137-byte encryption header.
     * \return Plaintext.
     * \exception See \ref decryptMemory(const uint8_t*, size_t, const std::vector<uint8_t>&).
     * @endcond */
    std::vector<uint8_t> decryptMemory(const std::vector<uint8_t>& ciphertext,
                                       const std::vector<uint8_t>& encHeader);

    // Decrypt data in memory (SecureBuffer version)
    //! @cond PORT
    //! @brief Decifra um \ref SecureBuffer, devolvendo um `std::vector` (não auto-apagável).
    //! @endcond
    //! @cond INGLES
    //! @brief Decrypts a \ref SecureBuffer, returning a `std::vector` (not self-wiping).
    //! @endcond
    /*!
     * @cond PORT
     * \param ciphertext Texto cifrado em buffer seguro.
     * \param encHeader  Cabeçalho de cifra de 1137 bytes.
     * \return Texto em claro comum (fica em memória até o chamador liberar).
     * \exception Ver \ref decryptMemory(const uint8_t*, size_t, const std::vector<uint8_t>&).
     * \details Use \ref decryptMemorySecure quando precisar que o texto em
     * claro também resida em buffer auto-apagável.
     * @endcond
     * @cond INGLES
     * \param ciphertext Ciphertext in a secure buffer.
     * \param encHeader  1137-byte encryption header.
     * \return Regular plaintext (it stays in memory until the caller frees it).
     * \exception See \ref decryptMemory(const uint8_t*, size_t, const std::vector<uint8_t>&).
     * \details Use \ref decryptMemorySecure when the plaintext must also reside
     * in a self-wiping buffer.
     * @endcond */
    std::vector<uint8_t> decryptMemory(const SecureBuffer& ciphertext,
                                       const std::vector<uint8_t>& encHeader);

    // Decrypt data in memory (SecureBuffer version with SecureBuffer output)
    //! @cond PORT
    //! @brief Decifra um \ref SecureBuffer devolvendo o texto em claro em um \ref SecureBuffer.
    //! @endcond
    //! @cond INGLES
    //! @brief Decrypts a \ref SecureBuffer, returning the plaintext in a \ref SecureBuffer.
    //! @endcond
    /*!
     * @cond PORT
     * \param ciphertext Texto cifrado em buffer seguro (não é apagado por esta
     * função).
     * \param encHeader  Cabeçalho de cifra de 1137 bytes.
     * \return Buffer seguro com o texto em claro; é zerado quando morre.
     * \exception Ver \ref decryptMemory(const uint8_t*, size_t, const std::vector<uint8_t>&).
     * \exception std::bad_alloc alocações intermediárias (vetor temporário e
     * buffer seguro) falham.
     * \details O texto em claro passa por um vetor temporário que é zerado
     * antes do return, evitando cópia sensível residual.
     * @endcond
     * @cond INGLES
     * \param ciphertext Ciphertext in a secure buffer (it is not erased by this
     * function).
     * \param encHeader  1137-byte encryption header.
     * \return Secure buffer with the plaintext; it is zeroed when it dies.
     * \exception See \ref decryptMemory(const uint8_t*, size_t, const std::vector<uint8_t>&).
     * \exception std::bad_alloc intermediate allocations (temporary vector and
     * secure buffer) fail.
     * \details The plaintext goes through a temporary vector that is zeroed
     * before the return, avoiding a residual sensitive copy.
     * @endcond */
    SecureBuffer decryptMemorySecure(const SecureBuffer& ciphertext,
                                     const std::vector<uint8_t>& encHeader);

    // Decrypt data in memory (vector version with SecureBuffer output)
    //! @cond PORT
    //! @brief Decifra um vetor de texto cifrado devolvendo um \ref SecureBuffer.
    //! @endcond
    //! @cond INGLES
    //! @brief Decrypts a vector of ciphertext, returning a \ref SecureBuffer.
    //! @endcond
    /*!
     * @cond PORT
     * \param ciphertext Texto cifrado.
     * \param encHeader  Cabeçalho de cifra de 1137 bytes.
     * \return Buffer seguro com o texto em claro.
     * \exception Ver \ref decryptMemorySecure(const SecureBuffer&, const std::vector<uint8_t>&).
     * \details O texto cifrado é copiado para um buffer seguro temporário,
     * que por sua vez é usado na decifragem.
     * @endcond
     * @cond INGLES
     * \param ciphertext Ciphertext.
     * \param encHeader  1137-byte encryption header.
     * \return Secure buffer with the plaintext.
     * \exception See \ref decryptMemorySecure(const SecureBuffer&, const std::vector<uint8_t>&).
     * \details The ciphertext is copied into a temporary secure buffer,
     * which in turn is used in the decryption.
     * @endcond */
    SecureBuffer decryptMemorySecure(const std::vector<uint8_t>& ciphertext,
                                     const std::vector<uint8_t>& encHeader);

private:
    /*!
     * @cond PORT
     * Chave privada híbrida (HYBRID_PRIV_KEY_SIZE, 3656 bytes).
     * Copiada do argumento do construtor, que confere apenas o tamanho — não
     * magic, nem versão, nem o conteúdo das chaves embarcadas. É o material
     * usado por `zupt_hybrid_decrypt` em todas as operações desta classe e é
     * zerada com \ref secureWipe no destrutor.
     * @endcond
     * @cond INGLES
     * Hybrid private key (HYBRID_PRIV_KEY_SIZE, 3656 bytes).
     * Copied from the argument of the constructor, which checks only the size — not
     * magic, nor version, nor the content of the embedded keys. It is the material
     * used by `zupt_hybrid_decrypt` in all operations of this class and it is
     * zeroed with \ref secureWipe in the destructor.
     * @endcond */
    std::vector<uint8_t> privateKey_;

    /*!
     * @cond PORT
     * Reservada por código legado: declarada aqui, mas sem definição em
     * `src/`. Nenhuma função deste cabeçalho a chama, então chamar dá erro
     * de vinculação, não comportamento silencioso.
     * @endcond
     * @cond INGLES
     * Reserved by legacy code: declared here, but without a definition in
     * `src/`. No function of this header calls it, so calling it gives a link
     * error, not silent behavior.
     * @endcond */
    void deriveKeys(const std::vector<uint8_t>& encHeader);
    /*!
     * @cond PORT
     * Reservada por código legado: declarada aqui e nunca lida nem escrita
     * pelas funções deste wrapper (a decifragem recebe o cabeçalho como
     * argumento de cada chamada).
     * @endcond
     * @cond INGLES
     * Reserved by legacy code: declared here and never read nor written
     * by the functions of this wrapper (the decryption receives the header as
     * an argument of each call).
     * @endcond */
    std::vector<uint8_t> encryptionHeader_;
};

/* ═══════════════════════════════════════════════════════════════════
 * HELPER FUNCTIONS
 * ═══════════════════════════════════════════════════════════════════ */

// Generate cryptographically secure random bytes
//! @cond PORT
//! @brief Gera `size` bytes aleatórios de origem criptograficamente segura.
//! @endcond
//! @cond INGLES
//! @brief Generates `size` random bytes from a cryptographically secure source.
//! @endcond
/*!
 * @cond PORT
 * \param size Quantidade de bytes a gerar.
 * \return Vetor com `size` bytes aleatórios (vazio quando `size == 0`).
 * \note Se o CSPRNG interno falhar, a chamada do lado C encerra o processo
 * (não lança exceção): não há como tratar essa falha pelo lado C++.
 * @endcond
 * @cond INGLES
 * \param size Number of bytes to generate.
 * \return Vector with `size` random bytes (empty when `size == 0`).
 * \note If the internal CSPRNG fails, the C-side call terminates the process
 * (it does not throw an exception): there is no way to handle that failure
 * from the C++ side.
 * @endcond */
std::vector<uint8_t> randomBytes(size_t size);

// Compute SHA-256 hash
//! @cond PORT
//! @brief Calcula o SHA-256 de `size` bytes a partir de `data`.
//! @endcond
//! @cond INGLES
//! @brief Computes the SHA-256 of `size` bytes starting from `data`.
//! @endcond
/*!
 * @cond PORT
 * \param data Buffer de entrada (pode ser nulo quando `size == 0`).
 * \param size Quantidade de bytes a hashar.
 * \return Vetor com os 32 bytes do resumo SHA-256.
 * \exception std::bad_alloc alocação do vetor de saída falha.
 * @endcond
 * @cond INGLES
 * \param data Input buffer (it may be null when `size == 0`).
 * \param size Number of bytes to hash.
 * \return Vector with the 32 bytes of the SHA-256 digest.
 * \exception std::bad_alloc allocation of the output vector fails.
 * @endcond */
std::vector<uint8_t> sha256(const uint8_t* data, size_t size);

// Compute SHA-256 hash (string version)
//! @cond PORT
//! @brief Calcula o SHA-256 dos bytes de uma string (sem incluir o terminador NUL).
//! @endcond
//! @cond INGLES
//! @brief Computes the SHA-256 of the bytes of a string (without including the NUL terminator).
//! @endcond
/*!
 * @cond PORT
 * \param data String de entrada.
 * \return Vetor com os 32 bytes do resumo SHA-256.
 * \exception std::bad_alloc alocação do vetor de saída falha.
 * @endcond
 * @cond INGLES
 * \param data Input string.
 * \return Vector with the 32 bytes of the SHA-256 digest.
 * \exception std::bad_alloc allocation of the output vector fails.
 * @endcond */
std::vector<uint8_t> sha256(const std::string& data);

// Compute SHA3-512 hash (for key derivation)
//! @cond PORT
//! @brief Calcula o SHA3-512 de `size` bytes a partir de `data`.
//! @endcond
//! @cond INGLES
//! @brief Computes the SHA3-512 of `size` bytes starting from `data`.
//! @endcond
/*!
 * @cond PORT
 * \param data Buffer de entrada (pode ser nulo quando `size == 0`).
 * \param size Quantidade de bytes a hashar.
 * \return Vetor com os 64 bytes do resumo SHA3-512.
 * \exception std::bad_alloc alocação do vetor de saída falha.
 * @endcond
 * @cond INGLES
 * \param data Input buffer (it may be null when `size == 0`).
 * \param size Number of bytes to hash.
 * \return Vector with the 64 bytes of the SHA3-512 digest.
 * \exception std::bad_alloc allocation of the output vector fails.
 * @endcond */
std::vector<uint8_t> sha3_512(const uint8_t* data, size_t size);

// Securely wipe memory
ZUPT_API void secureWipe(void* ptr, size_t size);

/* ═══════════════════════════════════════════════════════════════════
 * VERSION INFORMATION
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * @cond PORT
 * Devolve a versão da biblioteca como string.
 * @return Cadeia de caracteres terminada em NUL com a versão (ex.: `"2.0.0"`),
 * estática: não liberar.
 * @endcond
 * @cond INGLES
 * Returns the library version as a string.
 * @return NUL-terminated character string with the version (e.g. `"2.0.0"`),
 * static: do not free.
 * @endcond */
const char* getVersion();

/**
 * @cond PORT
 * Devolve o nome da biblioteca.
 * @return Cadeia de caracteres terminada em NUL (`"libzupt"`), estática:
 * não liberar.
 * @endcond
 * @cond INGLES
 * Returns the library name.
 * @return NUL-terminated character string (`"libzupt"`), static:
 * do not free.
 * @endcond */
const char* getLibraryName();

/* ═══════════════════════════════════════════════════════════════════
 * IMPLEMENTATION DETAILS - Inline function definitions
 * ═══════════════════════════════════════════════════════════════════ */

// Error handling helper
//! @cond PORT
//! @brief Auxílio inline de tratamento de erros: converte código de retorno do lado C em exceção.
//! @endcond
//! @cond INGLES
//! @brief Inline error-handling helper: converts a C-side return code into an exception.
//! @endcond
/*!
 * @cond PORT
 * \param ret Valor retornado pela função C chamada.
 * \param msg Prefixo da mensagem de exceção (identifica a etapa).
 * \exception ZuptError(ErrorCode::ERR_INVALID) quando `ret != 0`. A mensagem
 * concatenada termina com `" (error code: N)"`, onde N é o valor
 * devolvido pelo lado C — o significado de N depende da função
 * chamada e não é mapeado para um enumerador ErrorCode.
 * @endcond
 * @cond INGLES
 * \param ret Value returned by the C function called.
 * \param msg Prefix of the exception message (identifies the step).
 * \exception ZuptError(ErrorCode::ERR_INVALID) when `ret != 0`. The
 * concatenated message ends with `" (error code: N)"`, where N is the value
 * returned by the C side — the meaning of N depends on the function
 * called and is not mapped to an ErrorCode enumerator.
 * @endcond */
inline void checkError(int ret, const std::string& msg) {
    if (ret != 0) {
        throw ZuptError(ErrorCode::ERR_INVALID, msg + " (error code: " + std::to_string(ret) + ")");
    }
}

} // namespace zupt

#endif // ZUPT_HPP
