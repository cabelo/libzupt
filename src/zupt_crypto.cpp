/*
 * libzupt - C++ wrapper for hybrid post-quantum encryption
 * Implementation of encryption/decryption and key management
 *
 * SPDX-License-Identifier: MIT
 */

#include "zupt.hpp"
#include "zupt_cxx.h"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <stdexcept>

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
    pub[4] = 0x01; // version
    pub[5] = 0x00; // no private key
    pub[6] = pub[7] = 0; // reserved
    memcpy(pub + 8, ml_pk, MLKEM_PUBLICKEYBYTES);
    memcpy(pub + 8 + MLKEM_PUBLICKEYBYTES, x_pk, X25519_KEYBYTES);

    // Private key header
    memcpy(priv, "ZKEY", 4);
    priv[4] = 0x01; // version
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
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> data(size);
    if (!file.read(reinterpret_cast<char*>(data.data()), size)) {
        throw ZuptError(ErrorCode::ERR_IO, "Cannot read key file: " + filename);
    }

    // Validate header
    if (size_t(size) < 8 || memcmp(data.data(), "ZKEY", 4) != 0) {
        throw ZuptError(ErrorCode::ERR_INVALID, "Invalid key file format");
    }

    bool hasPrivate = (data[5] & 0x01) != 0;
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

    return data;
}

void KeyGenerator::exportPublicKey(const std::string& privfile, const std::string& pubfile) {
    std::ifstream priv(privfile, std::ios::binary);
    if (!priv) {
        throw ZuptError(ErrorCode::ERR_IO, "Cannot open private key file: " + privfile);
    }

    uint8_t hdr[8];
    if (!priv.read(reinterpret_cast<char*>(hdr), 8)) {
        throw ZuptError(ErrorCode::ERR_IO, "Cannot read private key header");
    }

    if (memcmp(hdr, "ZKEY", 4) != 0 || !(hdr[5] & 0x01)) {
        throw ZuptError(ErrorCode::ERR_INVALID, "Invalid private key file");
    }

    uint8_t pk_data[MLKEM_PUBLICKEYBYTES + X25519_KEYBYTES];
    if (!priv.read(reinterpret_cast<char*>(pk_data), sizeof(pk_data))) {
        throw ZuptError(ErrorCode::ERR_IO, "Cannot read public key data");
    }
    priv.close();

    std::ofstream pub(pubfile, std::ios::binary);
    if (!pub) {
        throw ZuptError(ErrorCode::ERR_IO, "Cannot create public key file: " + pubfile);
    }

    uint8_t out[HYBRID_PUB_KEY_SIZE];
    memcpy(out, "ZKEY", 4);
    out[4] = 0x01; // version
    out[5] = 0x00; // no private key
    out[6] = out[7] = 0;
    memcpy(out + 8, pk_data, sizeof(pk_data));

    if (!pub.write(reinterpret_cast<const char*>(out), sizeof(out))) {
        throw ZuptError(ErrorCode::ERR_IO, "Cannot write public key file");
    }
}

void KeyGenerator::saveKeyPair(const KeyPair& kp, const std::string& filename) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        throw ZuptError(ErrorCode::ERR_IO, "Cannot create key file: " + filename);
    }

    if (!file.write(reinterpret_cast<const char*>(kp.secret_key.data()),
                    kp.secret_key.size())) {
        throw ZuptError(ErrorCode::ERR_IO, "Cannot write key file");
    }
}

/* ═══════════════════════════════════════════════════════════════════
 * ENCRYPTOR IMPLEMENTATION
 * ═══════════════════════════════════════════════════════════════════ */

Encryptor::Encryptor(const std::vector<uint8_t>& publicKey)
    : publicKey_(publicKey) {
    // Pre-allocate space for encryption header
    encryptionHeader_.resize(HYBRID_ENC_HEADER_SIZE);

    // Pre-generate encryption header by doing a dummy encryption
    // Use a single byte buffer instead of nullptr since zupt_hybrid_encrypt requires valid input
    size_t enc_header_len = 0;
    size_t ciphertext_len = 0;

    uint8_t dummy_byte = 0;
    uint8_t* ciphertext = zupt_hybrid_encrypt(
        publicKey_.data(), publicKey_.size(),
        &dummy_byte, 1,  // minimal valid plaintext for header generation
        encryptionHeader_.data(), &enc_header_len,
        &ciphertext_len);

    if (ciphertext) {
        free(ciphertext);
    }

    // Ciphertext should be minimal (just encryption overhead for 1 byte)
    if (ciphertext_len > 1024) {  // Reasonable upper bound for 1 byte
        throw ZuptError(ErrorCode::ERR_INVALID,
            "Unexpected ciphertext size from dummy encryption");
    }

    if (enc_header_len != HYBRID_ENC_HEADER_SIZE) {
        throw ZuptError(ErrorCode::ERR_INVALID,
            "Unexpected encryption header size: " + std::to_string(enc_header_len));
    }
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

    if (!ciphertext && size > 0) {
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

    // Empty ciphertext means empty plaintext
    if (ciphertextSize == 0) {
        return std::vector<uint8_t>();
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
    free(plaintext);

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
    return SecureBuffer(result.data(), result.size());
}

std::vector<uint8_t>
Decryptor::decryptFile(const std::string& filename, const std::vector<uint8_t>& encHeader) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file) {
        throw ZuptError(ErrorCode::ERR_IO, "Cannot open file: " + filename);
    }

    std::streamsize size = file.tellg();
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
    return ZUPT_VERSION_STRING;
}

const char* getLibraryName() {
    return "libzupt";
}

} // namespace zupt