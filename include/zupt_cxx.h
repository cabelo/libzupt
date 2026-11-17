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

/* Application framing versions, distinct from the ML-KEM parameter set. */
#define ZUPT_KEY_FORMAT_VERSION 2
#define ZUPT_ENVELOPE_FORMAT 3

#if defined(_WIN32) || defined(__CYGWIN__)
  #ifdef ZUPT_STATIC
    #define ZUPT_API
  #elif defined(ZUPT_EXPORTS)
    #define ZUPT_API __declspec(dllexport)
  #else
    #define ZUPT_API __declspec(dllimport)
  #endif
#else
  #if defined(__GNUC__) && __GNUC__ >= 4
    #define ZUPT_API __attribute__((visibility("default")))
  #else
    #define ZUPT_API
  #endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Release allocations returned by the C API in the same runtime that made
 * them. Required across Windows CRT/FFI boundaries. */
ZUPT_API void zupt_free(void* ptr);

/* KEY GENERATION C API */

/* Generate a hybrid key pair
 * pub_key: output public key buffer
 * priv_key: output private key buffer
 * Returns 0 on success, -1 on error
 */
ZUPT_API int zupt_hybrid_keygen_c(uint8_t* pub_key, uint8_t* priv_key);

/* Export public key from private key
 * priv_key: input private key buffer
 * pub_key: output public key buffer
 * Returns 0 on success, -1 on error
 */
ZUPT_API int zupt_hybrid_export_pubkey_c(const uint8_t* priv_key, uint8_t* pub_key);

/* FILE I/O C API */

/* Read entire file into buffer
 * Returns allocated buffer (caller must free), or NULL on error
 * size: output parameter for file size
 */
ZUPT_API uint8_t* zupt_read_file(const char* path, size_t* size);

/* Write buffer to file
 * Returns 0 on success, -1 on error
 */
ZUPT_API int zupt_write_file(const char* path, const uint8_t* data, size_t size);

/* API-format private keys only. POSIX: checked owner, regular single-link file,
 * O_NOFOLLOW, mode 0600 before writing. Windows: caller controls directory ACLs. */
ZUPT_API int zupt_write_private_key(const char* path, const uint8_t* data, size_t size);

/* ENCRYPTION/DECRYPTION C API */

/* Encrypt buffer with hybrid encryption
 * pub_key: public key buffer
 * pub_key_len: public key size
 * plaintext: input data
 * plaintext_len: input size
 * enc_header: output encryption header
 * enc_header_len: output header size
 * Returns allocated ciphertext (caller must free), or NULL on error
 * ciphertext_len: output ciphertext size
 */
ZUPT_API uint8_t* zupt_hybrid_encrypt(const uint8_t* pub_key, size_t pub_key_len,
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
ZUPT_API uint8_t* zupt_hybrid_decrypt(const uint8_t* priv_key, size_t priv_key_len,
                                      const uint8_t* ciphertext, size_t ciphertext_len,
                                      const uint8_t* enc_header, size_t enc_header_len,
                                      size_t* plaintext_len);

/* Explicit v1 recovery only. expected_sha256 must come from a trusted source:
 * the legacy format cannot authenticate removal of complete final blocks.
 * New keys/envelopes are never interpreted as legacy. Returns NULL on error. */
ZUPT_API uint8_t* zupt_hybrid_decrypt_legacy(
    const uint8_t* priv_key, size_t priv_key_len,
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t* enc_header, size_t enc_header_len,
    const uint8_t expected_sha256[32], size_t* plaintext_len);

#ifdef __cplusplus
}
#endif

#endif /* ZUPT_CXX_H */
