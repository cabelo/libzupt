/*
 * libzupt - C++ wrapper for hybrid post-quantum encryption
 * C API for C++ implementation
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef ZUPT_CXX_H
#define ZUPT_CXX_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ═══════════════════════════════════════════════════════════════════
 * HYBRID KEY DERIVATION C API
 * ═══════════════════════════════════════════════════════════════════ */

/* Maximum key derivation input size */
#define ZUPT_KDF_INPUT_MAX (32 + 1088 + 32 + 15)

/* Derive archive keys from hybrid shared secret and transcript
 * Returns 64 bytes: enc_key[32] + mac_key[32]
 * Returns 0 on success, -1 on error
 */
int zupt_hybrid_derive_keys(const uint8_t* ml_ss, const uint8_t* ml_ct,
                            const uint8_t* eph_pk, const uint8_t* ml_pk,
                            uint8_t* archive_key);

/* Derive archive keys from private key and encryption header
 * Returns 0 on success, -1 on error
 */
int zupt_hybrid_decrypt_derive_keys(const uint8_t* priv_key, size_t priv_key_len,
                                    const uint8_t* enc_header, size_t enc_header_len,
                                    uint8_t* archive_key);

/* ═══════════════════════════════════════════════════════════════════
 * KEY GENERATION C API
 * ═══════════════════════════════════════════════════════════════════ */

/* Generate a hybrid key pair
 * pub_key: output public key buffer (must be at least HYBRID_PUB_KEY_SIZE bytes)
 * priv_key: output private key buffer (must be at least HYBRID_PRIV_KEY_SIZE bytes)
 * Returns 0 on success, -1 on error
 */
int zupt_hybrid_keygen_c(uint8_t* pub_key, uint8_t* priv_key);

/* Export public key from private key
 * priv_key: input private key buffer
 * pub_key: output public key buffer
 * Returns 0 on success, -1 on error
 */
int zupt_hybrid_export_pubkey_c(const uint8_t* priv_key, uint8_t* pub_key);

/* ═══════════════════════════════════════════════════════════════════
 * FILE I/O C API
 * ═══════════════════════════════════════════════════════════════════ */

/* Read entire file into buffer
 * Returns allocated buffer (caller must free), or NULL on error
 * size: output parameter for file size
 */
uint8_t* zupt_read_file(const char* path, size_t* size);

/* Write buffer to file
 * Returns 0 on success, -1 on error
 */
int zupt_write_file(const char* path, const uint8_t* data, size_t size);

/* ═══════════════════════════════════════════════════════════════════
 * ENCRYPTION/DECRYPTION C API
 * ═══════════════════════════════════════════════════════════════════ */

/* Encrypt buffer with hybrid encryption
 * pub_key: public key buffer
 * pub_key_len: public key size
 * plaintext: input data
 * plaintext_len: input size
 * enc_header: output encryption header (must be at least HYBRID_ENC_HEADER_SIZE bytes)
 * enc_header_len: output header size
 * Returns allocated ciphertext (caller must free), or NULL on error
 * ciphertext_len: output ciphertext size
 */
uint8_t* zupt_hybrid_encrypt(const uint8_t* pub_key, size_t pub_key_len,
                             const uint8_t* plaintext, size_t plaintext_len,
                             uint8_t* enc_header, size_t* enc_header_len,
                             size_t* ciphertext_len);

/* Decrypt buffer with hybrid encryption
 * priv_key: private key buffer
 * priv_key_len: private key size
 * ciphertext: input ciphertext
 * ciphertext_len: input ciphertext size
 * enc_header: encryption header from encryption
 * enc_header_len: header size
 * Returns allocated plaintext (caller must free), or NULL on error
 * plaintext_len: output plaintext size
 */
uint8_t* zupt_hybrid_decrypt(const uint8_t* priv_key, size_t priv_key_len,
                             const uint8_t* ciphertext, size_t ciphertext_len,
                             const uint8_t* enc_header, size_t enc_header_len,
                             size_t* plaintext_len);

#ifdef __cplusplus
}
#endif

#endif /* ZUPT_CXX_H */