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
 *   com a mensagem textual do erro; nada retorna código de erro por valor.
 * - `SecureBuffer`: memória alocada com as funções de páginas seguras da
 *   biblioteca (via `zupt_secure_alloc`/`zupt_secure_free`), zerada no
 *   destrutor — o equivalente RAII de `zupt_secure_alloc` + `zupt_secure_wipe`
 *   + `zupt_secure_free` em C.
 * - `KeyGenerator`, `Encryptor` e `Decryptor`: ciclo de vida completo
 *   (geração, cifra, decifragem) com a chave guardada no objeto.
 * - Funções soltas (`generateKeyPair`, `randomBytes`, `sha256`,
 *   `secureWipe`, `lockMemory`, `unlockMemory`, `isMemoryLocked` e os
 *   carregadores/salvadores de chave): atalhos diretos para as funções C
 *   correspondentes, sem objeto envolvido.
 *
 * Convenções desta camada, que valem para todos os métodos:
 * - Erros são exceções (`ZuptError` para falhas da biblioteca,
 *   `std::bad_alloc` para falta de memória). Nenhum método retorna "nulo" para
 *   indicar erro, exceto onde o comentário do próprio método diz o contrário.
 * - Toda chave, texto cifrado e cabeçalho de cifra que entram em uma destas
 *   classes são copiados para dentro do objeto. O chamador continua dono dos
 *   buffers originais.
 * - `Encryptor` guarda o cabeçalho da última cifra e o zera no destrutor;
 *   `Decryptor` guarda a chave privada e a zera no destrutor. Nenhum dos dois
 *   apaga o texto cifrado que o chamador forneceu.
 *
 * @note `Encryptor::initEncryptionHeader` e `Decryptor::deriveKeys` são
 *       declaradas aqui e não definidas em `src/`. Qualquer chamada resulta em
 *       erro de vinculação. Ver os comentários dos membros.
 */

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
 * @namespace zupt
 * @brief Espaço de nomes da API C++ da libzupt.
 */
namespace zupt {

/* ═══════════════════════════════════════════════════════════════════
 * ERROR CODES
 * ═══════════════════════════════════════════════════════════════════ */

//! Códigos de erro reportados pela camada C++ via \ref zupt::ZuptError "ZuptError".
/*! \details São valores negativos (exceto OK = 0), no mesmo espírito dos
 *          códigos da API C. \note Nem todos os valores são lançados pela
 *          camada C++: funções internas do wrapper C devolvem `int` e o lado
 *          C++ converte qualquer valor diferente de zero em
 *          ErrorCode::ERR_INVALID, sem mapear o código original. */
enum class ErrorCode : int {
    //! Operação concluída com sucesso (nenhuma falha).
    OK = 0,
    //! Falha de entrada/saída: abrir, ler, escrever ou determinar o tamanho de um arquivo.
    ERR_IO = -1,
    //! Dados cifrados/serializados corrompidos (estrutura interna inconsistente).
    ERR_CORRUPT = -2,
    //! Magic/assinatura de formato ausente ou diferente do esperado.
    ERR_BAD_MAGIC = -3,
    //! Versão de formato não suportada (chave, cabeçalho de cifra ou envelope).
    ERR_BAD_VERSION = -4,
    //! Soma de verificação do envelope não confere.
    ERR_BAD_CHECKSUM = -5,
    //! Falha de alocação de memória.
    ERR_NOMEM = -6,
    //! Tamanho pedido excede o máximo suportado pelo formato ou pelo tipo de contagem usado.
    ERR_OVERFLOW = -7,
    //! Argumento, buffer, tamanho ou resultado de chamada interna inválido (inclusive falhas genéricas do lado C).
    ERR_INVALID = -8,
    //! Item procurado não existe (por exemplo chave em anel de chaves).
    ERR_NOT_FOUND = -9,
    //! Operação, versão ou parâmetro não suportado por esta build.
    ERR_UNSUPPORTED = -10,
    //! Falha de autenticação: o MAC/GCM do envelope não validou (dados adulterados, chave errada ou cabeçalho inconsistente).
    ERR_AUTH_FAIL = -11,
};

/* ═══════════════════════════════════════════════════════════════════
 * EXCEPTION CLASS
 * ═══════════════════════════════════════════════════════════════════ */

//! Exceção lançada por toda a camada C++ da biblioteca.
/*! \details Todas as funções C++ deste cabeçalho reportam falhas lançando
 *          ZuptError (ou uma exceção padrão da STL que a camada reencapsula).
 *          \note A camada C++ não usa códigos de retorno: as funções que o
 *          wrapper C chama internamente retornam `int`, e qualquer valor
 *          diferente de zero faz `checkError()` lançar
 *          ErrorCode::ERR_INVALID. O código de erro específico de cada função
 *          (por exemplo ERR_AUTH_FAIL) não é propagado para o lado C++ — ver
 *          arquivo de achados.
 *          \exception std::bad_alloc alocação dos buffers internos falha. */
class ZuptError : public std::runtime_error {
public:
    //! Constrói a exceção.
    /*! \param code Código de erro que descreve a falha.
     *   \param msg  Mensagem descritiva (opcional); pode ser vazia.
     *   \exception std::bad_alloc alocação da string da exceção falha. */
    explicit ZuptError(ErrorCode code, const std::string& msg = "")
        : std::runtime_error(msg), code_(code) {}

    //! Retorna o código numérico da exceção.
    /*! \return O mesmo enumerador informado no construtor. */
    ErrorCode code() const noexcept { return code_; }

private:
    ErrorCode code_; //!< Código de erro associado à exceção.
};

/* ═══════════════════════════════════════════════════════════════════
 * CONSTANTS
 * ═══════════════════════════════════════════════════════════════════ */

//! Tamanho da chave pública ML-KEM-768 (FIPS 203), em bytes.
constexpr size_t MLKEM_PUBLICKEYBYTES = 1184;

//! Tamanho da chave secreta ML-KEM-768 (FIPS 203), em bytes.
constexpr size_t MLKEM_SECRETKEYBYTES = 2400;

//! Tamanho do texto cifrado (ciphertext) ML-KEM-768 (FIPS 203), em bytes.
constexpr size_t MLKEM_CIPHERTEXTBYTES = 1088;

//! Tamanho do segredo compartilhado (shared secret) ML-KEM-768, em bytes.
/*! \details Alimenta a KDF que produz a chave AES-256 da sessão. */
constexpr size_t MLKEM_SSBYTES = 32;

//! Tamanho da chave (privada ou pública) X25519, em bytes.
constexpr size_t X25519_KEYBYTES = 32;

//! Tamanhos dos arquivos de chave híbrida, em bytes.

//! Chave pública híbrida serializada: 8 (cabeçalho ZKEY) + 1184 (ML-KEM-768 pk) + 32 (X25519 pk).
constexpr size_t HYBRID_PUB_KEY_SIZE = 1224;  // 8 (header) + 1184 (ml_kem_pk) + 32 (x25519_pk)

//! Chave privada híbrida serializada: 8 (cabeçalho ZKEY) + 1184 (ml_kem_pk) + 32 (x25519 pk) + 2400 (ml_kem_sk) + 32 (x25519 sk).
constexpr size_t HYBRID_PRIV_KEY_SIZE = 3656; // 8 (header) + 1184 + 32 + 2400 + 32

//! Cabeçalho de cifra no modo híbrido: 1 (enc_type) + 1088 (ml_ct) + 32 (eph_pk) + 16 (nonce).
/*! \details É exatamente o tamanho retornado por `getEncryptionHeaderSize()`
 *          e o valor aceito pelo lado C (`enc_hdr_len == 1137`). */
constexpr size_t HYBRID_ENC_HEADER_SIZE = 1137; // 1 (enc_type) + 1088 (ml_ct) + 32 (eph_pk) + 16 (nonce)

//! Tamanho da chave AES-256 usada pelo wrapper C++ (32 bytes).
constexpr size_t AES_KEY_SIZE = 32;

//! Tamanho do nonce AES-GCM (16 bytes).
constexpr size_t AES_NONCE_SIZE = 16;

//! Tamanho do MAC de verificação de autenticação (32 bytes).
constexpr size_t HMAC_SIZE = 32;

/* ═══════════════════════════════════════════════════════════════════
 * KEY PAIR - Hybrid Post-Quantum Key Pair
 * ═══════════════════════════════════════════════════════════════════ */

//! Par de chaves híbridas pós-quânticas (ML-KEM-768 + X25519).
/*! \details Invariantes de tamanho observadas pelo código:
 *          - `public_key`: 1224 bytes quando gerado/carregado por
 *            `generateKeyPair()`/`loadKeyPair()`; quando a chave privada é
 *            carregada a partir de um arquivo v1 (`legacy_version == 1`),
 *            `public_key` recebe 1184 bytes (somente a chave pública ML-KEM,
 *            sem o cabeçalho ZKEY de 8 bytes).
 *          - `secret_key`: sempre 3656 bytes.
 *          \note `secret_key` contém material sensível. Enquanto o objeto
 *          viver, o segredo permanece em memória; este tipo não é movido para
 *          um buffer auto-apagável. */
struct KeyPair {
    std::vector<uint8_t> public_key; //!< Chave pública híbrida serializada (ver \ref KeyPair).
    std::vector<uint8_t> secret_key; //!< Chave privada híbrida serializada (material sensível).

    //! Constrói um par de chaves com os tamanhos padrão de chave híbrida.
    /*! \details Aloca `public_key` com HYBRID_PUB_KEY_SIZE (1224) e
     *          `secret_key` com HYBRID_PRIV_KEY_SIZE (3656). Nenhum dos dois
     *          vetores é preenchido: o chamador deve passar o objeto para
     *          `generateKeyPairInternal()` (via `generateKeyPair()`) ou
     *          `loadKeyPair()` antes de usar os valores. */
    KeyPair() : public_key(HYBRID_PUB_KEY_SIZE), secret_key(HYBRID_PRIV_KEY_SIZE) {}

    //! Constrói um par de chaves a partir de vetores existentes (move).
    /*! \param pub  Chave pública serializada.
     *   \param priv Chave privada serializada.
     *   \details Não há verificação de tamanho: o objeto aceita vetores de
     *           qualquer extensão, inclusive vazios. */
    KeyPair(std::vector<uint8_t> pub, std::vector<uint8_t> priv)
        : public_key(std::move(pub)), secret_key(std::move(priv)) {}
};

/* ═══════════════════════════════════════════════════════════════════
 * SECURE BUFFER - Zeroized on destruction
 * ═══════════════════════════════════════════════════════════════════ */

//! Apaga `size` bytes de `ptr` de forma que o compilador não possa otimizar a escrita.
/*! \param ptr Início do buffer a apagar. O ponteiro deve ser um buffer
 *              contíguo de propriedade do chamador; a função não aloca nem
 *              libera memória. Não há verificação de `nullptr`: passar
 *              `nullptr` com `size > 0` é comportamento indefinido.
 *  \param size Quantidade de bytes a apagar. `size == 0` é um no-op.
 *  \details Implementação: `volatile` write + `asm volatile` de barreira de
 *           otimização em `src/zupt_crypto.cpp`.
 *  \note A função é declarada duas vezes neste cabeçalho (antes e depois das
 *        classes); a duplicação é legal em C++, mas é redundância — ver
 *        arquivo de achados. */
ZUPT_API void secureWipe(void* ptr, size_t size);

//! Buffer de tamanho fixo que zera o conteúdo ao ser destruído.
/*! \details Regras de cópia/movimento conforme o código:
 *          - cópia construtiva e de atribuição: proibidas (`= delete`);
 *          - movimento (construtor e atribuição): permitidos e `noexcept`. No
 *            movimento por atribuição, o conteúdo destino é zerado
 *            (`zeroize()`) antes de o buffer ser tomado de `other`; `other`
 *            fica com `size() == 0` e `data() == nullptr`.
 *          - destrutor: chama `zeroize()` se houver buffer.
 *          \note `data()` devolve um ponteiro interno: ele é válido até o
 *          objeto ser destruído ou movido, e o conteúdo pode ser sensível. */
class SecureBuffer {
public:
    //! Aloca um buffer de `size` bytes (conteúdo inicial não definido).
    /*! \param size Quantidade de bytes a alocar.
     *   \exception std::bad_alloc alocação falha. */
    explicit SecureBuffer(size_t size)
        : data_(std::make_unique<uint8_t[]>(size)), size_(size) {}

    //! Aloca um buffer de `size` bytes e copia o conteúdo de `data` para ele.
    /*! \param data Fonte (pode ser `nullptr`, caso em que nada é copiado e o
     *               buffer fica não inicializado).
     *   \param size Tamanho a alocar e, se `data` não é nulo, a copiar.
     *   \details Não há verificação do tamanho real de `data`; o chamador deve
     *           garantir que `size` não ultrapassa o buffer fonte.
     *   \exception std::bad_alloc alocação falha. */
    SecureBuffer(const uint8_t* data, size_t size)
        : data_(std::make_unique<uint8_t[]>(size)), size_(size) {
        if (data) {
            memcpy(data_.get(), data, size);
        }
    }

    //! Cria um buffer com o mesmo conteúdo de `data`.
    /*! \param data Vetor fonte; o buffer fica com `data.size()` bytes.
     *   \exception std::bad_alloc alocação falha. */
    SecureBuffer(const std::vector<uint8_t>& data)
        : data_(std::make_unique<uint8_t[]>(data.size())), size_(data.size()) {
        if (!data.empty()) {
            memcpy(data_.get(), data.data(), data.size());
        }
    }

    //! Destrutor: zera o conteúdo antes de liberar o buffer.
    ~SecureBuffer() {
        if (data_) {
            zeroize();
        }
    }

    // Prevent copying
    SecureBuffer(const SecureBuffer&) = delete; //!< Cópias são proibidas para evitar duplicar material sensível.
    //! Atribuição por cópia é proibida.
    /*! \return Não há: a função está marcada como `= delete`. */
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    // Allow moving
    //! Construtor de movimento (noexcept): toma o buffer de `other`.
    /*! \param other Objeto de origem; ao final, `other.size() == 0` e
     *                `other.data() == nullptr`. Nenhum zerado é aplicado à
     *                origem (o conteúdo migra junto com o buffer). */
    SecureBuffer(SecureBuffer&& other) noexcept
        : data_(std::move(other.data_)), size_(std::exchange(other.size_, 0)) {}

    //! Atribuição por movimento (noexcept): zera o destino e toma o buffer de `other`.
    /*! \param other Objeto de origem; ao final fica com tamanho zero.
     *   \return Referencia a `*this`.
     *   \details Se `this == &other`, nada é feito (nem o zerado). */
    SecureBuffer& operator=(SecureBuffer&& other) noexcept {
        if (this != &other) {
            zeroize();
            data_ = std::move(other.data_);
            size_ = std::exchange(other.size_, 0);
        }
        return *this;
    }

    /**
     * Ponteiro mutável para o início do buffer.
     * @return `data_.get()`, que pode ser `nullptr` (buffer nulo ou objeto
     *         movido). Válido enquanto o objeto viver.
     */
    uint8_t* data() noexcept { return data_.get(); }

    /**
     * Ponteiro somente leitura para o início do buffer.
     * @return `data_.get()`, que pode ser `nullptr` (buffer nulo ou objeto
     *         movido). Válido enquanto o objeto viver.
     */
    const uint8_t* data() const noexcept { return data_.get(); }

    /**
     * Número de bytes do buffer.
     * @return Tamanho em bytes; `0` depois de o objeto ser movido.
     */
    size_t size() const noexcept { return size_; }

    //! Zera todos os bytes do buffer via \ref secureWipe.
    /*! \details Não faz nada quando o buffer é nulo ou `size() == 0`. */
    void zeroize() noexcept {
        if (data_ && size_ > 0) {
            secureWipe(data_.get(), size_);
        }
    }

    //! Copia o conteúdo para um `std::vector<uint8_t>`.
    /*! \return Vetor com `size()` bytes do buffer; vazio quando `size() == 0`.
     *   \exception std::bad_alloc alocação do vetor falha. */
    std::vector<uint8_t> toVector() const {
        if (size_ == 0) return {};
        return std::vector<uint8_t>(data_.get(), data_.get() + size_);
    }

    //! Copia o conteúdo para um `std::string` (sem interpretar o texto).
    /*! \return String de `size()` bytes; vazia quando `size() == 0`.
     *   \exception std::bad_alloc alocação da string falha. */
    std::string toString() const {
        if (size_ == 0) return {};
        return std::string(reinterpret_cast<const char*>(data_.get()), size_);
    }

private:
    std::unique_ptr<uint8_t[]> data_; //!< Buffer de tamanho fixo (propriedade exclusiva do objeto).
    size_t size_;                     //!< Tamanho do buffer em bytes; 0 após movimento.
};

/* ═══════════════════════════════════════════════════════════════════
 * KEY GENERATOR - Generates hybrid post-quantum key pairs
 * ═══════════════════════════════════════════════════════════════════ */

//! Gerador e gerenciador de pares de chaves híbridas (ML-KEM-768 + X25519).
/*! \details Classe sem estado: não guarda material de chave entre chamadas.
 *          Pode ser copida/movida livremente (regras padrão geradas pelo
 *          compilador). Todo o estado observável está nos arquivos e nos
 *          valores de retorno. */
class KeyGenerator {
public:
    KeyGenerator() = default; //!< Construtor padrão (não inicializa nada).

    //! Destrutor padrão (não há recursos a liberar).
    ~KeyGenerator() = default;

    // Generate a new hybrid key pair (ML-KEM-768 + X25519)
    //! Gera um novo par de chaves híbridas.
    /*! \return KeyPair com `public_key` de 1224 bytes (formato ZKEY público)
     *          e `secret_key` de 3656 bytes (formato ZKEY privado).
     *   \details Percorre o caminho completo em memória, sem tocar o disco:
     *           aloca os buffers, chama `generateKeyPairInternal()` e empacota
     *           o resultado.
     *   \exception ZuptError(ErrorCode::ERR_INVALID) o lado C sinalizou falha
     *              (retornou diferente de zero); a mensagem indica qual etapa
     *              falhou.
     *   \exception std::bad_alloc alocação dos buffers internos falha.
     *   \note O segredo retornado é um `std::vector` comum — não é apagado
     *           automaticamente quando o objeto morre. */
    KeyPair generateKeyPair();

    // Load a key pair from a file
    //! Carrega um par de chaves privada+pública de um arquivo ZKEY privado.
    /*! \param filename Caminho do arquivo de chave privada.
     *   \return KeyPair com `secret_key` igual ao arquivo inteiro (3656 bytes)
     *           e `public_key` com os 1224 primeiros bytes do arquivo, tendo o
     *           byte 5 (flag "tem chave privada") limpo.
     *   \exception ZuptError(ErrorCode::ERR_IO) arquivo inexistente, tamanho
     *              indeterminável ou falha de leitura.
     *   \exception ZuptError(ErrorCode::ERR_INVALID) magic `ZKEY` ausente,
     *              flag de privado ausente, ou tamanho diferente de 3656.
     *   \exception ZuptError(ErrorCode::ERR_BAD_VERSION) byte de versão
     *              diferente de 1 e de 2, ou bytes reservados (6 e 7)
     *              diferentes de zero.
     *   \details A chave pública nunca é recomputada a partir da privada: ela é
     *           extraída dos bytes do arquivo. Não há checagem de que a chave
     *           pública gravada corresponde à chave privada. */
    KeyPair loadKeyPair(const std::string& filename);

    // Load a public key only from a file
    //! Carrega apenas a chave pública de um arquivo ZKEY público.
    /*! \param filename Caminho do arquivo de chave pública.
     *   \return Vetor com o conteúdo inteiro do arquivo (1224 bytes, já no
     *           formato aceito por `Encryptor` e por \ref zupt_hybrid_encrypt).
     *   \exception ZuptError(ErrorCode::ERR_IO) falha ao abrir/ler o arquivo.
     *   \exception ZuptError(ErrorCode::ERR_INVALID) magic `ZKEY` ausente ou
     *              tamanho diferente de 1224.
     *   \exception ZuptError(ErrorCode::ERR_BAD_VERSION) byte de versão
     *              diferente de 1 e de 2, flag de privado (byte 5) diferente
     *              de zero, ou bytes reservados (6 e 7) diferentes de zero.
     *   \note Esta função aceita arquivos v1, mas o `Encryptor` aceita
     *           somente v2: uma chave pública v1 carregada aqui falha ao ser
     *           usada para cifrar (ver arquivo de achados). */
    std::vector<uint8_t> loadPublicKey(const std::string& filename);

    // Export only the public key to a file
    //! Extrai a chave pública de um arquivo de chave privada e a grava em outro arquivo.
    /*! \param privfile Arquivo de chave privada ZKEY de origem (processado por
     *                  `loadKeyPair()` (membro privado), portanto sujeito às
     *                  mesmas validações).
     *   \param pubfile  Arquivo de chave pública ZKEY de destino.
     *   \exception ZuptError(ErrorCode::ERR_IO) falha ao criar/gravar o destino.
     *   \exception ZuptError(ErrorCode::ERR_IO), ERR_INVALID ou
     *              ERR_BAD_VERSION propagados de \ref loadKeyPair.
     *   \details O arquivo de destino contém exatamente os 1224 bytes da chave
     *           pública com a flag de privado limpa. Não são aplicadas as
     *           proteções de permissão usadas por \ref zupt_write_private_key
     *           (o arquivo é criado com as permissões padrão do processo). O
     *           arquivo de origem não é alterado. */
    void exportPublicKey(const std::string& privfile, const std::string& pubfile);

    // Save a key pair to a file
    //! Grava a chave privada de um par de chaves em arquivo com permissões restritas.
    /*! \param kp       Par de chaves cuja `secret_key` será gravada.
     *   \param filename Caminho do arquivo de destino.
     *   \exception ZuptError(ErrorCode::ERR_IO) \ref zupt_write_private_key
     *              retornou erro (arquivo, permissão ou validação de formato).
     *   \details Delega a \ref zupt_write_private_key, que aplica a escrita
     *           restrita descrita nela. `public_key` de `kp` é ignorado. */
    void saveKeyPair(const KeyPair& kp, const std::string& filename);

private:
    //! Etapa interna de geração (ML-KEM-768 + X25519), usada por \ref generateKeyPair.
    /*! \param ml_pk Buffer destino da chave pública ML-KEM (1184 bytes).
     *   \param ml_sk Buffer destino da chave privada ML-KEM (2400 bytes).
     *   \param x_pk  Buffer destino da chave pública X25519 (32 bytes).
     *   \param x_sk  Buffer destino da chave privada X25519 (32 bytes).
     *   \details Os quatro buffers são de responsabilidade do chamador. */
    void generateKeyPairInternal(uint8_t* ml_pk, uint8_t* ml_sk,
                                  uint8_t* x_pk, uint8_t* x_sk);
};

/* ═══════════════════════════════════════════════════════════════════
 * ENCRYPTOR - Hybrid post-quantum encryption
 * ═══════════════════════════════════════════════════════════════════ */

//! Cifrador híbrido pós-quântico (ML-KEM-768 + X25519).
/*! \details Invariante mantida pelo construtor: a chave guardada tem
 *          exatamente HYBRID_PUB_KEY_SIZE (1224) bytes, magic `ZKEY`, byte 4
 *          igual a ZUPT_KEY_FORMAT_VERSION (2), byte 5 igual a 0 (chave
 *          pública), bytes 6 e 7 iguais a 0, e a chave pública ML-KEM passa em
 *          `zupt_mlkem768_public_key_check`. Uma chave que não atende a isso
 *          é rejeitada com ErrorCode::ERR_BAD_VERSION, inclusive chaves
 *          públicas v1.
 *          \note `Encryptor` é copiável/movível pelas regras padrão do
 *          compilador (não declara cópia ou movimento). A cópia é segura por
 *          conteúdo (apenas chave pública), mas o cabeçalho interno da última
 *          cifra é duplicado.
 *          \note Não há proteção contra uso concorrente: a chamada de
 *          cifragem grava o cabeçalho da última operação em estado interno. */
class Encryptor {
public:
    //! Constrói o cifrador a partir de uma chave pública híbrida.
    /*! \param publicKey Chave pública no formato ZKEY público (1224 bytes),
     *                    como produzida por `generateKeyPair()` ou
     *                    `loadPublicKey()` (membro privado).
     *   \exception ZuptError(ErrorCode::ERR_BAD_VERSION) chave rejeitada:
     *              tamanho diferente de 1224, magic ausente, versão diferente
     *              de ZUPT_KEY_FORMAT_VERSION, flag de chave privada
     *              diferente de zero, bytes reservados diferentes de zero ou
     *              chave pública ML-KEM inválida.
     *   \exception std::bad_alloc cópia da chave falha.
     *   \details A chave é copiada para o objeto; o chamador pode liberar
     *            o vetor original. */
    explicit Encryptor(const std::vector<uint8_t>& publicKey);

    //! Destrutor: apaga o cabeçalho da última cifra guardado no objeto.
    /*! \details O cabeçalho contém o ciphertext ML-KEM da chave de sessão,
     *           por isso é zerado. O buffer de chave pública não é apagado
     *           (não é material sensível). */
    ~Encryptor();

    // Encrypt a file - returns ciphertext and encryption header
    //! Cifra o conteúdo inteiro de um arquivo.
    /*! \param filename Arquivo em claro a ler.
     *   \return Par `{ciphertext, enc_header}`: o texto cifrado (mesmo
     *           tamanho do arquivo, pois o modo é de fluxo com MAC) e o
     *           cabeçalho de cifra de HYBRID_ENC_HEADER_SIZE (1137) bytes.
     *   \exception ZuptError(ErrorCode::ERR_IO) arquivo inexistente, tamanho
     *              indeterminável ou falha de leitura.
     *   \exception ZuptError(ErrorCode::ERR_INVALID) falha de cifragem ou
     *              tamanho de cabeçalho inesperado retornado pelo lado C.
     *   \exception std::bad_alloc o arquivo inteiro é lido para memória.
     *   \details O arquivo de origem não é modificado: a função só lê. Cabe ao
     *           chamador decidir se e quando apaga o arquivo em claro e se
     *           grava `{ciphertext, enc_header}` no disco. */
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> encryptFile(const std::string& filename);

    // Encrypt data in memory - returns ciphertext and encryption header
    //! Cifra `size` bytes a partir de `data`.
    /*! \param data Buffer em claro (pode ser nulo apenas quando `size == 0`).
     *   \param size Quantidade de bytes a cifrar.
     *   \return Par `{ciphertext, enc_header}` com o texto cifrado e o
     *           cabeçalho de cifra de 1137 bytes gerado para esta operação.
     *   \exception ZuptError(ErrorCode::ERR_INVALID) `data` nulo com `size > 0`,
     *              falha de cifragem ou tamanho de cabeçalho inesperado.
     *   \exception std::bad_alloc alocação dos vetores de saída.
     *   \details Cada chamada gera material efêmero novo, portanto o cabeçalho
     *           retornado é específico deste texto cifrado. O cabeçalho desta
     *           chamada também fica copiado no estado interno do objeto. */
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> encryptMemory(const uint8_t* data, size_t size);

    // Encrypt data in memory (vector version)
    //! Cifra o conteúdo de um vetor (equivale a `encryptMemory(data.data(), data.size())`).
    /*! \param data Vetor em claro (pode ser vazio: o resultado é um texto
     *                cifrado de 0 bytes mais o cabeçalho).
     *   \return Par `{ciphertext, enc_header}`.
     *   \exception Ver \ref encryptMemory(const uint8_t*, size_t). */
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> encryptMemory(const std::vector<uint8_t>& data);

    // Encrypt data in memory (SecureBuffer version)
    //! Cifra o conteúdo de um \ref SecureBuffer (o buffer de origem não é apagado).
    /*! \param buffer Buffer em claro (pode ser vazio).
     *   \return Par `{ciphertext, enc_header}`.
     *   \exception Ver \ref encryptMemory(const uint8_t*, size_t). */
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> encryptMemory(const SecureBuffer& buffer);

    // Get the encryption header size
    //! Tamanho do cabeçalho de cifra gerado por este cifrador.
    /*! \return HYBRID_ENC_HEADER_SIZE (1137 bytes), sempre. */
    static constexpr size_t getEncryptionHeaderSize() noexcept {
        return HYBRID_ENC_HEADER_SIZE;
    }

private:
    /*! Chave pública validada, em formato ZKEY público (1224 bytes).
     *  Copiada do argumento do construtor e conferida ali mesmo: tamanho,
     *  magic, versão, flags e a chave pública ML-KEM embutida. Não é apagada
     *  no destrutor por não ser material sensível. */
    std::vector<uint8_t> publicKey_;
    /*! Cópia do cabeçalho de cifra da última operação de cifra feita pelo
     *  objeto. Contém o ciphertext ML-KEM da chave de sessão, portanto é
     *  zerado com \ref secureWipe no destrutor (ver `~Encryptor`). */
    std::vector<uint8_t> encryptionHeader_;

    /*! Reservada por código legado: declarada aqui, mas sem definição em
     *  `src/`. Nenhuma função deste cabeçalho a chama, então chamar dá erro
     *  de vinculação, não comportamento silencioso. */
    void initEncryptionHeader();
};

/* ═══════════════════════════════════════════════════════════════════
 * DECRYPTOR - Hybrid post-quantum decryption
 * ═══════════════════════════════════════════════════════════════════ */

//! Decifrador híbrido pós-quântico (ML-KEM-768 + X25519).
/*! \details Invariante mantida pelo construtor: a chave guardada tem
 *          exatamente HYBRID_PRIV_KEY_SIZE (3656) bytes. Diferentemente de
 *          \ref Encryptor, o construtor NÃO valida magic, versão, flag de
 *          privado nem o conteúdo das chaves: um buffer de 3656 bytes com
 *          qualquer conteúdo é aceito e a falha aparece somente na decifragem
 *          (ErrorCode::ERR_AUTH_FAIL).
 *          \note `Decryptor` é copiável/movível pelas regras padrão do
 *          compilador (não declara cópia nem movimento). Copiá-lo duplica a
 *          chave privada em memória, e cada cópia é zerada no próprio destrutor.
 *          \note Não há proteção contra uso concorrente. */
class Decryptor {
public:
    //! Constrói o decifrador a partir de uma chave privada híbrida.
    /*! \param privateKey Chave privada no formato ZKEY privado (3656 bytes),
     *                     como produzida por `generateKeyPair()` ou
     *                     `loadKeyPair()` (membro privado).
     *   \exception ZuptError(ErrorCode::ERR_INVALID) tamanho diferente de
     *              HYBRID_PRIV_KEY_SIZE.
     *   \exception std::bad_alloc cópia da chave falha.
     *   \details A chave é copiada para o objeto; o chamador ainda é dono do
     *            vetor original e é responsável por apagá-lo. */
    explicit Decryptor(const std::vector<uint8_t>& privateKey);

    //! Destrutor: apaga a chave privada guardada no objeto.
    /*! \details Aplica \ref secureWipe sobre todo o buffer da chave privada. */
    ~Decryptor();

    // Decrypt a file using the provided encryption header
    //! Decifra o conteúdo inteiro de um arquivo cifrado.
    /*! \param filename  Arquivo contendo o texto cifrado (somente o corpo; o
     *                    cabeçalho de cifra não é lido daqui).
     *   \param encHeader Cabeçalho de cifra de 1137 bytes obtido na cifragem.
     *   \return Texto em claro com o tamanho real decifrado.
     *   \exception ZuptError(ErrorCode::ERR_IO) arquivo inexistente, tamanho
     *              indeterminável ou falha de leitura.
     *   \exception ZuptError(ErrorCode::ERR_INVALID) cabeçalho com tamanho
     *              diferente de 1137.
     *   \exception ZuptError(ErrorCode::ERR_AUTH_FAIL) decifragem falhou
     *              (chave errada, dados adulterados ou cabeçalho inconsistente).
     *   \exception std::bad_alloc o arquivo inteiro é lido para memória.
     *   \details O arquivo cifrado de origem não é modificado. */
    std::vector<uint8_t> decryptFile(const std::string& filename, const std::vector<uint8_t>& encHeader);

    // Decrypt data in memory using the provided encryption header
    //! Decifra `ciphertextSize` bytes a partir de `ciphertext`.
    /*! \param ciphertext     Buffer do texto cifrado (pode ser nulo apenas
     *                         quando `ciphertextSize == 0`).
     *   \param ciphertextSize Quantidade de bytes cifrados.
     *   \param encHeader      Cabeçalho de cifra de 1137 bytes.
     *   \return Texto em claro com exatamente o comprimento decifrado.
     *   \exception ZuptError(ErrorCode::ERR_INVALID) `ciphertext` nulo com
     *              tamanho maior que zero, ou cabeçalho com tamanho diferente
     *              de 1137.
     *   \exception ZuptError(ErrorCode::ERR_AUTH_FAIL) a decifragem foi
     *              rejeitada pelo lado C. \note este é o único código devolvido
     *              para qualquer causa de falha (chave inválida, autenticação,
     *              formato interno do cabeçalho etc.), pois o wrapper C++ não
     *              distingue os erros da chamada interna.
     *   \exception std::bad_alloc alocação do texto em claro. \note se a cópia
     *              para o `std::vector` de retorno lançar, o buffer devolvido
     *              pelo lado C não é zerado nem liberado (vazamento de texto em
     *              claro).
     *   \details O buffer devolvido pelo lado C é copiado, zerado
     *            (\ref secureWipe) e liberado (\ref zupt_free) antes do return.
     *            O keyring derivado vive só no lado C e é apagado por
     *            `zupt_munlock_keys()`, que executa `zupt_secure_wipe()` antes
     *            de liberar o bloqueio de memória — inclusive na decifragem
     *            rejeitada. */
    std::vector<uint8_t> decryptMemory(const uint8_t* ciphertext, size_t ciphertextSize,
                                       const std::vector<uint8_t>& encHeader);

    // Decrypt data in memory (vector version)
    //! Decifra um vetor de texto cifrado (equivale à versão por ponteiro).
    /*! \param ciphertext Texto cifrado.
     *   \param encHeader  Cabeçalho de cifra de 1137 bytes.
     *   \return Texto em claro.
     *   \exception Ver \ref decryptMemory(const uint8_t*, size_t, const std::vector<uint8_t>&). */
    std::vector<uint8_t> decryptMemory(const std::vector<uint8_t>& ciphertext,
                                       const std::vector<uint8_t>& encHeader);

    // Decrypt data in memory (SecureBuffer version)
    //! Decifra um \ref SecureBuffer, devolvendo um `std::vector` (não auto-apagável).
    /*! \param ciphertext Texto cifrado em buffer seguro.
     *   \param encHeader  Cabeçalho de cifra de 1137 bytes.
     *   \return Texto em claro comum (fica em memória até o chamador liberar).
     *   \exception Ver \ref decryptMemory(const uint8_t*, size_t, const std::vector<uint8_t>&).
     *   \details Use \ref decryptMemorySecure quando precisar que o texto em
     *            claro também resida em buffer auto-apagável. */
    std::vector<uint8_t> decryptMemory(const SecureBuffer& ciphertext,
                                       const std::vector<uint8_t>& encHeader);

    // Decrypt data in memory (SecureBuffer version with SecureBuffer output)
    //! Decifra um \ref SecureBuffer devolvendo o texto em claro em um \ref SecureBuffer.
    /*! \param ciphertext Texto cifrado em buffer seguro (não é apagado por esta
     *                     função).
     *   \param encHeader  Cabeçalho de cifra de 1137 bytes.
     *   \return Buffer seguro com o texto em claro; é zerado quando morre.
     *   \exception Ver \ref decryptMemory(const uint8_t*, size_t, const std::vector<uint8_t>&).
     *   \exception std::bad_alloc alocações intermediárias (vetor temporário e
     *              buffer seguro) falham.
     *   \details O texto em claro passa por um vetor temporário que é zerado
     *            antes do return, evitando cópia sensível residual. */
    SecureBuffer decryptMemorySecure(const SecureBuffer& ciphertext,
                                     const std::vector<uint8_t>& encHeader);

    // Decrypt data in memory (vector version with SecureBuffer output)
    //! Decifra um vetor de texto cifrado devolvendo um \ref SecureBuffer.
    /*! \param ciphertext Texto cifrado.
     *   \param encHeader  Cabeçalho de cifra de 1137 bytes.
     *   \return Buffer seguro com o texto em claro.
     *   \exception Ver \ref decryptMemorySecure(const SecureBuffer&, const std::vector<uint8_t>&).
     *   \details O texto cifrado é copiado para um buffer seguro temporário,
     *            que por sua vez é usado na decifragem. */
    SecureBuffer decryptMemorySecure(const std::vector<uint8_t>& ciphertext,
                                     const std::vector<uint8_t>& encHeader);

private:
    /*! Chave privada híbrida (HYBRID_PRIV_KEY_SIZE, 3656 bytes).
     *  Copiada do argumento do construtor, que confere apenas o tamanho — não
     *  magic, nem versão, nem o conteúdo das chaves embarcadas. É o material
     *  usado por `zupt_hybrid_decrypt` em todas as operações desta classe e é
     *  zerada com \ref secureWipe no destrutor. */
    std::vector<uint8_t> privateKey_;

    /*! Reservada por código legado: declarada aqui, mas sem definição em
     *  `src/`. Nenhuma função deste cabeçalho a chama, então chamar dá erro
     *  de vinculação, não comportamento silencioso. */
    void deriveKeys(const std::vector<uint8_t>& encHeader);
    /*! Reservada por código legado: declarada aqui e nunca lida nem escrita
     *  pelas funções deste wrapper (a decifragem recebe o cabeçalho como
     *  argumento de cada chamada). */
    std::vector<uint8_t> encryptionHeader_;
};

/* ═══════════════════════════════════════════════════════════════════
 * HELPER FUNCTIONS
 * ═══════════════════════════════════════════════════════════════════ */

// Generate cryptographically secure random bytes
//! Gera `size` bytes aleatórios de origem criptograficamente segura.
/*! \param size Quantidade de bytes a gerar.
 *   \return Vetor com `size` bytes aleatórios (vazio quando `size == 0`).
 *   \note Se o CSPRNG interno falhar, a chamada do lado C encerra o processo
 *           (não lança exceção): não há como tratar essa falha pelo lado C++. */
std::vector<uint8_t> randomBytes(size_t size);

// Compute SHA-256 hash
//! Calcula o SHA-256 de `size` bytes a partir de `data`.
/*! \param data Buffer de entrada (pode ser nulo quando `size == 0`).
 *   \param size Quantidade de bytes a hashar.
 *   \return Vetor com os 32 bytes do resumo SHA-256.
 *   \exception std::bad_alloc alocação do vetor de saída falha. */
std::vector<uint8_t> sha256(const uint8_t* data, size_t size);

// Compute SHA-256 hash (string version)
//! Calcula o SHA-256 dos bytes de uma string (sem incluir o terminador NUL).
/*! \param data String de entrada.
 *   \return Vetor com os 32 bytes do resumo SHA-256.
 *   \exception std::bad_alloc alocação do vetor de saída falha. */
std::vector<uint8_t> sha256(const std::string& data);

// Compute SHA3-512 hash (for key derivation)
//! Calcula o SHA3-512 de `size` bytes a partir de `data`.
/*! \param data Buffer de entrada (pode ser nulo quando `size == 0`).
 *   \param size Quantidade de bytes a hashar.
 *   \return Vetor com os 64 bytes do resumo SHA3-512.
 *   \exception std::bad_alloc alocação do vetor de saída falha. */
std::vector<uint8_t> sha3_512(const uint8_t* data, size_t size);

// Securely wipe memory
ZUPT_API void secureWipe(void* ptr, size_t size);

/* ═══════════════════════════════════════════════════════════════════
 * VERSION INFORMATION
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * Devolve a versão da biblioteca como string.
 * @return Cadeia de caracteres terminada em NUL com a versão (ex.: `"2.0.0"`),
 *         estática: não liberar.
 */
const char* getVersion();

/**
 * Devolve o nome da biblioteca.
 * @return Cadeia de caracteres terminada em NUL (`"libzupt"`), estática:
 *         não liberar.
 */
const char* getLibraryName();

/* ═══════════════════════════════════════════════════════════════════
 * IMPLEMENTATION DETAILS - Inline function definitions
 * ═══════════════════════════════════════════════════════════════════ */

// Error handling helper
//! Auxílio inline de tratamento de erros: converte código de retorno do lado C em exceção.
/*! \param ret Valor retornado pela função C chamada.
 *   \param msg Prefixo da mensagem de exceção (identifica a etapa).
 *   \exception ZuptError(ErrorCode::ERR_INVALID) quando `ret != 0`. A mensagem
 *              concatenada termina com `" (error code: N)"`, onde N é o valor
 *              devolvido pelo lado C — o significado de N depende da função
 *              chamada e não é mapeado para um enumerador ErrorCode. */
inline void checkError(int ret, const std::string& msg) {
    if (ret != 0) {
        throw ZuptError(ErrorCode::ERR_INVALID, msg + " (error code: " + std::to_string(ret) + ")");
    }
}

} // namespace zupt

#endif // ZUPT_HPP
