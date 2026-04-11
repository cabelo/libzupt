/*
 * libzupt - Dynamic library for hybrid post-quantum encryption
 * ML-KEM-768 + X25519 for file and memory encryption/decryption
 *
 * Copyright (c) 2026 Cristian Cezar Moisés
 * SPDX-License-Identifier: MIT
 *
 * C++ Wrapper for Zupt hybrid encryption library
 */

#ifndef ZUPT_HPP
#define ZUPT_HPP

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>
#include <string.h>
namespace zupt {

/* ═══════════════════════════════════════════════════════════════════
 * ERROR CODES
 * ═══════════════════════════════════════════════════════════════════ */

enum class ErrorCode : int {
    OK = 0,
    ERR_IO = -1,
    ERR_CORRUPT = -2,
    ERR_BAD_MAGIC = -3,
    ERR_BAD_VERSION = -4,
    ERR_BAD_CHECKSUM = -5,
    ERR_NOMEM = -6,
    ERR_OVERFLOW = -7,
    ERR_INVALID = -8,
    ERR_NOT_FOUND = -9,
    ERR_UNSUPPORTED = -10,
    ERR_AUTH_FAIL = -11,
};

/* ═══════════════════════════════════════════════════════════════════
 * EXCEPTION CLASS
 * ═══════════════════════════════════════════════════════════════════ */

class ZuptError : public std::runtime_error {
public:
    explicit ZuptError(ErrorCode code, const std::string& msg = "")
        : std::runtime_error(msg), code_(code) {}

    ErrorCode code() const noexcept { return code_; }

private:
    ErrorCode code_;
};

/* ═══════════════════════════════════════════════════════════════════
 * CONSTANTS
 * ═══════════════════════════════════════════════════════════════════ */

constexpr size_t MLKEM_PUBLICKEYBYTES = 1184;
constexpr size_t MLKEM_SECRETKEYBYTES = 2400;
constexpr size_t MLKEM_CIPHERTEXTBYTES = 1088;
constexpr size_t MLKEM_SSBYTES = 32;

constexpr size_t X25519_KEYBYTES = 32;

/* Hybrid key file sizes */
constexpr size_t HYBRID_PUB_KEY_SIZE = 1224;  // 8 (header) + 1184 (ml_kem_pk) + 32 (x25519_pk)
constexpr size_t HYBRID_PRIV_KEY_SIZE = 3656; // 8 (header) + 1184 + 32 + 2400 + 32

/* Encryption header size for hybrid mode */
constexpr size_t HYBRID_ENC_HEADER_SIZE = 1137; // 1 (enc_type) + 1088 (ml_ct) + 32 (eph_pk) + 16 (nonce)

/* AES-256 constants */
constexpr size_t AES_KEY_SIZE = 32;
constexpr size_t AES_NONCE_SIZE = 16;
constexpr size_t HMAC_SIZE = 32;

/* ═══════════════════════════════════════════════════════════════════
 * KEY PAIR - Hybrid Post-Quantum Key Pair
 * ═══════════════════════════════════════════════════════════════════ */

struct KeyPair {
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> secret_key;

    KeyPair() : public_key(HYBRID_PUB_KEY_SIZE), secret_key(HYBRID_PRIV_KEY_SIZE) {}
    KeyPair(std::vector<uint8_t> pub, std::vector<uint8_t> priv)
        : public_key(std::move(pub)), secret_key(std::move(priv)) {}
};

/* ═══════════════════════════════════════════════════════════════════
 * SECURE BUFFER - Zeroized on destruction
 * ═══════════════════════════════════════════════════════════════════ */

class SecureBuffer {
public:
    explicit SecureBuffer(size_t size)
        : data_(std::make_unique<uint8_t[]>(size)), size_(size) {}

    SecureBuffer(const uint8_t* data, size_t size)
        : data_(std::make_unique<uint8_t[]>(size)), size_(size) {
        if (data) {
            memcpy(data_.get(), data, size);
        }
    }

    SecureBuffer(const std::vector<uint8_t>& data)
        : data_(std::make_unique<uint8_t[]>(data.size())), size_(data.size()) {
        if (!data.empty()) {
            memcpy(data_.get(), data.data(), data.size());
        }
    }

    ~SecureBuffer() {
        if (data_) {
            zeroize();
        }
    }

    // Prevent copying
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    // Allow moving
    SecureBuffer(SecureBuffer&&) = default;
    SecureBuffer& operator=(SecureBuffer&&) = default;

    uint8_t* data() noexcept { return data_.get(); }
    const uint8_t* data() const noexcept { return data_.get(); }
    size_t size() const noexcept { return size_; }

    void zeroize() noexcept {
        if (data_ && size_ > 0) {
            memset(data_.get(), 0, size_);
        }
    }

    std::vector<uint8_t> toVector() const {
        return std::vector<uint8_t>(data_.get(), data_.get() + size_);
    }

    std::string toString() const {
        return std::string(reinterpret_cast<const char*>(data_.get()), size_);
    }

private:
    std::unique_ptr<uint8_t[]> data_;
    size_t size_;
};

/* ═══════════════════════════════════════════════════════════════════
 * KEY GENERATOR - Generates hybrid post-quantum key pairs
 * ═══════════════════════════════════════════════════════════════════ */

class KeyGenerator {
public:
    KeyGenerator() = default;
    ~KeyGenerator() = default;

    // Generate a new hybrid key pair (ML-KEM-768 + X25519)
    KeyPair generateKeyPair();

    // Load a key pair from a file
    KeyPair loadKeyPair(const std::string& filename);

    // Load a public key only from a file
    std::vector<uint8_t> loadPublicKey(const std::string& filename);

    // Export only the public key to a file
    void exportPublicKey(const std::string& privfile, const std::string& pubfile);

    // Save a key pair to a file
    void saveKeyPair(const KeyPair& kp, const std::string& filename);

private:
    void generateKeyPairInternal(uint8_t* ml_pk, uint8_t* ml_sk,
                                  uint8_t* x_pk, uint8_t* x_sk);
};

/* ═══════════════════════════════════════════════════════════════════
 * ENCRYPTOR - Hybrid post-quantum encryption
 * ═══════════════════════════════════════════════════════════════════ */

class Encryptor {
public:
    explicit Encryptor(const std::vector<uint8_t>& publicKey);
    ~Encryptor();

    // Encrypt a file - returns ciphertext and encryption header
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> encryptFile(const std::string& filename);

    // Encrypt data in memory - returns ciphertext and encryption header
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> encryptMemory(const uint8_t* data, size_t size);

    // Encrypt data in memory (vector version)
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> encryptMemory(const std::vector<uint8_t>& data);

    // Encrypt data in memory (SecureBuffer version)
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> encryptMemory(const SecureBuffer& buffer);

    // Get the encryption header size
    static constexpr size_t getEncryptionHeaderSize() noexcept {
        return HYBRID_ENC_HEADER_SIZE;
    }

private:
    std::vector<uint8_t> publicKey_;
    std::vector<uint8_t> encryptionHeader_;

    void initEncryptionHeader();
};

/* ═══════════════════════════════════════════════════════════════════
 * DECRYPTOR - Hybrid post-quantum decryption
 * ═══════════════════════════════════════════════════════════════════ */

class Decryptor {
public:
    explicit Decryptor(const std::vector<uint8_t>& privateKey);
    ~Decryptor();

    // Decrypt a file using the provided encryption header
    std::vector<uint8_t> decryptFile(const std::string& filename, const std::vector<uint8_t>& encHeader);

    // Decrypt data in memory using the provided encryption header
    std::vector<uint8_t> decryptMemory(const uint8_t* ciphertext, size_t ciphertextSize,
                                       const std::vector<uint8_t>& encHeader);

    // Decrypt data in memory (vector version)
    std::vector<uint8_t> decryptMemory(const std::vector<uint8_t>& ciphertext,
                                       const std::vector<uint8_t>& encHeader);

    // Decrypt data in memory (SecureBuffer version)
    std::vector<uint8_t> decryptMemory(const SecureBuffer& ciphertext,
                                       const std::vector<uint8_t>& encHeader);

    // Decrypt data in memory (SecureBuffer version with SecureBuffer output)
    SecureBuffer decryptMemorySecure(const SecureBuffer& ciphertext,
                                     const std::vector<uint8_t>& encHeader);

    // Decrypt data in memory (vector version with SecureBuffer output)
    SecureBuffer decryptMemorySecure(const std::vector<uint8_t>& ciphertext,
                                     const std::vector<uint8_t>& encHeader);

private:
    std::vector<uint8_t> privateKey_;

    void deriveKeys(const std::vector<uint8_t>& encHeader);
    std::vector<uint8_t> encryptionHeader_;
};

/* ═══════════════════════════════════════════════════════════════════
 * HELPER FUNCTIONS
 * ═══════════════════════════════════════════════════════════════════ */

// Generate cryptographically secure random bytes
std::vector<uint8_t> randomBytes(size_t size);

// Compute SHA-256 hash
std::vector<uint8_t> sha256(const uint8_t* data, size_t size);

// Compute SHA-256 hash (string version)
std::vector<uint8_t> sha256(const std::string& data);

// Compute SHA3-512 hash (for key derivation)
std::vector<uint8_t> sha3_512(const uint8_t* data, size_t size);

// Securely wipe memory
void secureWipe(void* ptr, size_t size);

/* ═══════════════════════════════════════════════════════════════════
 * VERSION INFORMATION
 * ═══════════════════════════════════════════════════════════════════ */

const char* getVersion();
const char* getLibraryName();

/* ═══════════════════════════════════════════════════════════════════
 * IMPLEMENTATION DETAILS - Inline function definitions
 * ═══════════════════════════════════════════════════════════════════ */

// Error handling helper
inline void checkError(int ret, const std::string& msg) {
    if (ret != 0) {
        throw ZuptError(ErrorCode::ERR_INVALID, msg + " (error code: " + std::to_string(ret) + ")");
    }
}

} // namespace zupt

#endif // ZUPT_HPP
