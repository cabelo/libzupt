/*
 * libzupt - C++ wrapper for hybrid post-quantum encryption
 * Implementation of encryption/decryption and key management
 *
 * SPDX-License-Identifier: MIT
 */

#include "zupt.hpp"
#include "zupt_cxx.h"
#include "libzupt_version.h"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <stdexcept>

#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

// Include C implementation headers
extern "C" {
#include "zupt.h"
#include "zupt_mlkem.h"
#include "zupt_x25519.h"
#include "zupt_keccak.h"
}

namespace zupt {

/* ═══════════════════════════════════════════════════════════════════
 * KEY GENERATOR IMPLEMENTATION
 * ═══════════════════════════════════════════════════════════════════ */

KeyPair KeyGenerator::generateKeyPair() {
    uint8_t ml_pk[MLKEM_PUBLICKEYBYTES];
    uint8_t ml_sk[MLKEM_SECRETKEYBYTES];
    uint8_t x_pk[X25519_KEYBYTES];
    uint8_t x_sk[X25519_KEYBYTES];

    generateKeyPairInternal(ml_pk, ml_sk, x_pk, x_sk);

    // Build key pair in zupt format
    KeyPair kp;
    uint8_t* pub = kp.public_key.data();
    uint8_t* priv = kp.secret_key.data();

    // Public key header
    memcpy(pub, "ZKEY", 4);
    pub[4] = ZUPT_KEY_FORMAT_VERSION; // version
    pub[5] = 0x00; // no private key
    pub[6] = pub[7] = 0; // reserved
    memcpy(pub + 8, ml_pk, MLKEM_PUBLICKEYBYTES);
    memcpy(pub + 8 + MLKEM_PUBLICKEYBYTES, x_pk, X25519_KEYBYTES);

    // Private key header
    memcpy(priv, "ZKEY", 4);
    priv[4] = ZUPT_KEY_FORMAT_VERSION; // version
    priv[5] = 0x01; // has private key
    priv[6] = priv[7] = 0; // reserved
    memcpy(priv + 8, ml_pk, MLKEM_PUBLICKEYBYTES);
    memcpy(priv + 8 + MLKEM_PUBLICKEYBYTES, x_pk, X25519_KEYBYTES);
    memcpy(priv + 8 + MLKEM_PUBLICKEYBYTES + X25519_KEYBYTES, ml_sk, MLKEM_SECRETKEYBYTES);
    memcpy(priv + 8 + MLKEM_PUBLICKEYBYTES + X25519_KEYBYTES + MLKEM_SECRETKEYBYTES, x_sk, X25519_KEYBYTES);

    // Wipe temporary keys
    secureWipe(ml_sk, MLKEM_SECRETKEYBYTES);
    secureWipe(x_sk, X25519_KEYBYTES);

    return kp;
}

void KeyGenerator::generateKeyPairInternal(uint8_t* ml_pk, uint8_t* ml_sk,
                                           uint8_t* x_pk, uint8_t* x_sk) {
    // Generate ML-KEM-768 keypair
    if (zupt_mlkem768_keygen(ml_pk, ml_sk) != 0) {
        throw ZuptError(ErrorCode::ERR_INVALID, "ML-KEM-768 key generation failed");
    }

    // Generate X25519 keypair
    zupt_random_bytes(x_sk, X25519_KEYBYTES);
    zupt_x25519_base(x_pk, x_sk);
}

KeyPair KeyGenerator::loadKeyPair(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file) {
        throw ZuptError(ErrorCode::ERR_IO, "Cannot open key file: " + filename);
    }

    std::streamsize size = file.tellg();
    if (size < 0) throw ZuptError(ErrorCode::ERR_IO, "Cannot determine file size");
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> data(size);
    if (!file.read(reinterpret_cast<char*>(data.data()), size)) {
        throw ZuptError(ErrorCode::ERR_IO, "Cannot read key file: " + filename);
    }

    // Validate header
    if (size_t(size) < 8 || memcmp(data.data(), "ZKEY", 4) != 0) {
        throw ZuptError(ErrorCode::ERR_INVALID, "Invalid key file format");
    }

    if ((data[4] != 1 && data[4] != ZUPT_KEY_FORMAT_VERSION) || data[6] || data[7])
        throw ZuptError(ErrorCode::ERR_BAD_VERSION, "Unsupported key version");
    bool hasPrivate = data[5] == 0x01;
    if (!hasPrivate) {
        throw ZuptError(ErrorCode::ERR_INVALID, "Key file does not contain private key");
    }

    if (size != HYBRID_PRIV_KEY_SIZE) {
        throw ZuptError(ErrorCode::ERR_INVALID,
            "Invalid key file size: expected " + std::to_string(HYBRID_PRIV_KEY_SIZE) +
            ", got " + std::to_string(size));
    }

    KeyPair kp;
    // Copy the full private key data to secret_key
    std::copy(data.begin(), data.end(), kp.secret_key.begin());
    // Extract public key from the private key (first HYBRID_PUB_KEY_SIZE bytes)
    std::copy(data.begin(), data.begin() + HYBRID_PUB_KEY_SIZE, kp.public_key.begin());
    // Fix the public key header: clear the "has_private" flag (byte 5)
    kp.public_key[5] &= ~0x01;
    return kp;
}

std::vector<uint8_t> KeyGenerator::loadPublicKey(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file) {
        throw ZuptError(ErrorCode::ERR_IO, "Cannot open public key file: " + filename);
    }

    std::streamsize size = file.tellg();
    if (size < 0) throw ZuptError(ErrorCode::ERR_IO, "Cannot determine file size");
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> data(size);
    if (!file.read(reinterpret_cast<char*>(data.data()), size)) {
        throw ZuptError(ErrorCode::ERR_IO, "Cannot read public key file: " + filename);
    }

    // Validate header
    if (size_t(size) < 8 || memcmp(data.data(), "ZKEY", 4) != 0) {
        throw ZuptError(ErrorCode::ERR_INVALID, "Invalid public key file format");
    }

    if (size != HYBRID_PUB_KEY_SIZE) {
        throw ZuptError(ErrorCode::ERR_INVALID,
            "Invalid public key file size: expected " + std::to_string(HYBRID_PUB_KEY_SIZE) +
            ", got " + std::to_string(size));
    }

    if ((data[4] != 1 && data[4] != ZUPT_KEY_FORMAT_VERSION) ||
        data[5] != 0 || data[6] || data[7])
        throw ZuptError(ErrorCode::ERR_BAD_VERSION, "Unsupported public key format");
    return data;
}

void KeyGenerator::exportPublicKey(const std::string& privfile, const std::string& pubfile) {
    const auto keys = loadKeyPair(privfile);
    std::ofstream output(pubfile, std::ios::binary);
    if (!output || !output.write(reinterpret_cast<const char*>(keys.public_key.data()),
                                  keys.public_key.size()))
        throw ZuptError(ErrorCode::ERR_IO, "Cannot write public key file: " + pubfile);
}


void KeyGenerator::saveKeyPair(const KeyPair& kp, const std::string& filename) {
    if (zupt_write_private_key(filename.c_str(), kp.secret_key.data(), kp.secret_key.size()) != 0)
        throw ZuptError(ErrorCode::ERR_IO, "Cannot securely write private key: " + filename);

}

/* ═══════════════════════════════════════════════════════════════════
 * ENCRYPTOR IMPLEMENTATION
 * ═══════════════════════════════════════════════════════════════════ */

Encryptor::Encryptor(const std::vector<uint8_t>& publicKey)
    : publicKey_(publicKey) {
    if (publicKey_.size() != HYBRID_PUB_KEY_SIZE ||
        std::memcmp(publicKey_.data(), "ZKEY", 4) != 0 ||
        publicKey_[4] != ZUPT_KEY_FORMAT_VERSION || publicKey_[5] != 0 ||
        publicKey_[6] || publicKey_[7] ||
        zupt_mlkem768_public_key_check(publicKey_.data() + 8) != 0)
        throw ZuptError(ErrorCode::ERR_BAD_VERSION,
            "Encryption requires a valid v2 public key; generate new keys for migration");

}

Encryptor::~Encryptor() {
    // Encryption header may contain sensitive data, wipe it
    if (!encryptionHeader_.empty()) {
        secureWipe(encryptionHeader_.data(), encryptionHeader_.size());
    }
}

std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
Encryptor::encryptMemory(const uint8_t* data, size_t size) {
    if (!data && size > 0) {
        throw ZuptError(ErrorCode::ERR_INVALID, "Null data pointer");
    }

    size_t enc_header_len = 0;
    size_t ciphertext_len = 0;

    // Get a fresh encryption header for this encryption
    std::vector<uint8_t> enc_header(HYBRID_ENC_HEADER_SIZE);

    uint8_t* ciphertext = zupt_hybrid_encrypt(
        publicKey_.data(), publicKey_.size(),
        data, size,
        enc_header.data(), &enc_header_len,
        &ciphertext_len);

    if (!ciphertext) {
        throw ZuptError(ErrorCode::ERR_INVALID, "Encryption failed");
    }

    if (enc_header_len != HYBRID_ENC_HEADER_SIZE) {
        if (ciphertext) free(ciphertext);
        throw ZuptError(ErrorCode::ERR_INVALID,
            "Unexpected encryption header size: " + std::to_string(enc_header_len));
    }

    std::vector<uint8_t> result_ciphertext;
    if (ciphertext) {
        result_ciphertext.assign(ciphertext, ciphertext + ciphertext_len);
        free(ciphertext);
    }

    encryptionHeader_ = enc_header;
    return {result_ciphertext, enc_header};
}

std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
Encryptor::encryptMemory(const std::vector<uint8_t>& data) {
    return encryptMemory(data.data(), data.size());
}

std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
Encryptor::encryptMemory(const SecureBuffer& buffer) {
    return encryptMemory(buffer.data(), buffer.size());
}

std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
Encryptor::encryptFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file) {
        throw ZuptError(ErrorCode::ERR_IO, "Cannot open file: " + filename);
    }

    std::streamsize size = file.tellg();
    if (size < 0) throw ZuptError(ErrorCode::ERR_IO, "Cannot determine file size");
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> data(size);
    if (!file.read(reinterpret_cast<char*>(data.data()), size)) {
        throw ZuptError(ErrorCode::ERR_IO, "Cannot read file: " + filename);
    }

    return encryptMemory(data.data(), data.size());
}

/* ═══════════════════════════════════════════════════════════════════
 * DECRYPTOR IMPLEMENTATION
 * ═══════════════════════════════════════════════════════════════════ */

Decryptor::Decryptor(const std::vector<uint8_t>& privateKey)
    : privateKey_(privateKey) {
    if (privateKey_.size() != HYBRID_PRIV_KEY_SIZE) {
        throw ZuptError(ErrorCode::ERR_INVALID,
            "Invalid private key size: expected " + std::to_string(HYBRID_PRIV_KEY_SIZE) +
            ", got " + std::to_string(privateKey_.size()));
    }
}

Decryptor::~Decryptor() {
    // Wipe private key
    secureWipe(privateKey_.data(), privateKey_.size());
}

std::vector<uint8_t>
Decryptor::decryptMemory(const uint8_t* ciphertext, size_t ciphertextSize,
                         const std::vector<uint8_t>& encHeader) {
    if (!ciphertext && ciphertextSize > 0) {
        throw ZuptError(ErrorCode::ERR_INVALID, "Null ciphertext pointer");
    }

    if (encHeader.size() != HYBRID_ENC_HEADER_SIZE) {
        throw ZuptError(ErrorCode::ERR_INVALID,
            "Invalid encryption header size: expected " + std::to_string(HYBRID_ENC_HEADER_SIZE) +
            ", got " + std::to_string(encHeader.size()));
    }

    size_t plaintext_len = 0;

    uint8_t* plaintext = zupt_hybrid_decrypt(
        privateKey_.data(), privateKey_.size(),
        ciphertext, ciphertextSize,
        encHeader.data(), encHeader.size(),
        &plaintext_len);

    if (!plaintext) {
        throw ZuptError(ErrorCode::ERR_AUTH_FAIL, "Decryption failed (authentication error)");
    }

    std::vector<uint8_t> result(plaintext, plaintext + plaintext_len);
    secureWipe(plaintext, plaintext_len);
    zupt_free(plaintext);

    return result;
}

std::vector<uint8_t>
Decryptor::decryptMemory(const std::vector<uint8_t>& ciphertext,
                         const std::vector<uint8_t>& encHeader) {
    return decryptMemory(ciphertext.data(), ciphertext.size(), encHeader);
}

std::vector<uint8_t>
Decryptor::decryptMemory(const SecureBuffer& ciphertext,
                         const std::vector<uint8_t>& encHeader) {
    return decryptMemory(ciphertext.data(), ciphertext.size(), encHeader);
}

SecureBuffer
Decryptor::decryptMemorySecure(const std::vector<uint8_t>& ciphertext,
                               const std::vector<uint8_t>& encHeader) {
    return decryptMemorySecure(SecureBuffer(ciphertext.data(), ciphertext.size()), encHeader);
}

SecureBuffer
Decryptor::decryptMemorySecure(const SecureBuffer& ciphertext,
                               const std::vector<uint8_t>& encHeader) {
    std::vector<uint8_t> result = decryptMemory(ciphertext.data(), ciphertext.size(), encHeader);
    SecureBuffer secure(result.data(), result.size());
    secureWipe(result.data(), result.size());
    return secure;
}

std::vector<uint8_t>
Decryptor::decryptFile(const std::string& filename, const std::vector<uint8_t>& encHeader) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file) {
        throw ZuptError(ErrorCode::ERR_IO, "Cannot open file: " + filename);
    }

    std::streamsize size = file.tellg();
    if (size < 0) throw ZuptError(ErrorCode::ERR_IO, "Cannot determine file size");
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> ciphertext(size);
    if (!file.read(reinterpret_cast<char*>(ciphertext.data()), size)) {
        throw ZuptError(ErrorCode::ERR_IO, "Cannot read file: " + filename);
    }

    return decryptMemory(ciphertext.data(), ciphertext.size(), encHeader);
}

/* ═══════════════════════════════════════════════════════════════════
 * HELPER FUNCTIONS
 * ═══════════════════════════════════════════════════════════════════ */

std::vector<uint8_t> randomBytes(size_t size) {
    std::vector<uint8_t> result(size);
    zupt_random_bytes(result.data(), size);
    return result;
}

std::vector<uint8_t> sha256(const uint8_t* data, size_t size) {
    std::vector<uint8_t> result(32);
    zupt_sha256(data, size, result.data());
    return result;
}

std::vector<uint8_t> sha256(const std::string& data) {
    return sha256(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

std::vector<uint8_t> sha3_512(const uint8_t* data, size_t size) {
    std::vector<uint8_t> result(64);
    zupt_sha3_512(data, size, result.data());
    return result;
}

void secureWipe(void* ptr, size_t size) {
    if (ptr && size > 0) {
        zupt_secure_wipe(ptr, size);
    }
}

const char* getVersion() {
    return LIBZUPT_VERSION_STRING;
}

const char* getLibraryName() {
    return "libzupt";
}

} // namespace zupt
