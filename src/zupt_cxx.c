/*
 * libzupt - C wrapper for hybrid post-quantum encryption
 * C implementation for C++ library
 *
 * SPDX-License-Identifier: MIT
 */

#include "zupt_cxx.h"
#include "zupt.h"
#include "zupt_mlkem.h"
#include "zupt_x25519.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ═══════════════════════════════════════════════════════════════════
 * KEY GENERATION
 * ═══════════════════════════════════════════════════════════════════ */

int zupt_hybrid_keygen_c(uint8_t* pub_key, uint8_t* priv_key) {
    if (!pub_key || !priv_key) return -1;

    uint8_t ml_pk[MLKEM_PUBLICKEYBYTES];
    uint8_t ml_sk[MLKEM_SECRETKEYBYTES];
    uint8_t x_sk[32], x_pk[32];

    /* Generate ML-KEM-768 keypair */
    if (zupt_mlkem768_keygen(ml_pk, ml_sk) != 0) {
        return -1;
    }

    /* Generate X25519 keypair */
    zupt_random_bytes(x_sk, 32);
    zupt_x25519_base(x_pk, x_sk);

    /* Build public key: ZKEY header + ml_pk + x_pk */
    memcpy(pub_key, "ZKEY", 4);
    pub_key[4] = 0x01; /* version */
    pub_key[5] = 0x00; /* no private key */
    pub_key[6] = pub_key[7] = 0;
    memcpy(pub_key + 8, ml_pk, 1184);
    memcpy(pub_key + 8 + 1184, x_pk, 32);

    /* Build private key: ZKEY header + ml_pk + x_pk + ml_sk + x_sk */
    memcpy(priv_key, "ZKEY", 4);
    priv_key[4] = 0x01; /* version */
    priv_key[5] = 0x01; /* has private key */
    priv_key[6] = priv_key[7] = 0;
    memcpy(priv_key + 8, ml_pk, 1184);
    memcpy(priv_key + 8 + 1184, x_pk, 32);
    memcpy(priv_key + 8 + 1184 + 32, ml_sk, 2400);
    memcpy(priv_key + 8 + 1184 + 32 + 2400, x_sk, 32);

    /* Wipe temporary keys */
    zupt_secure_wipe(ml_sk, sizeof(ml_sk));
    zupt_secure_wipe(x_sk, 32);

    return 0;
}

int zupt_hybrid_export_pubkey_c(const uint8_t* priv_key, uint8_t* pub_key) {
    if (!priv_key || !pub_key) return -1;

    /* Validate private key header */
    if (memcmp(priv_key, "ZKEY", 4) != 0) return -1;
    if (!(priv_key[5] & 0x01)) return -1;

    /* Extract public key data */
    const uint8_t* ml_pk = priv_key + 8;
    const uint8_t* x_pk = ml_pk + 1184;

    /* Build public key */
    memcpy(pub_key, "ZKEY", 4);
    pub_key[4] = 0x01; /* version */
    pub_key[5] = 0x00; /* no private key */
    pub_key[6] = pub_key[7] = 0;
    memcpy(pub_key + 8, ml_pk, 1184);
    memcpy(pub_key + 8 + 1184, x_pk, 32);

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * FILE I/O
 * ═══════════════════════════════════════════════════════════════════ */

uint8_t* zupt_read_file(const char* path, size_t* size) {
    if (!path || !size) return NULL;

    FILE* f = fopen(path, "rb");
    if (!f) return NULL;

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }

    long file_size = ftell(f);
    if (file_size < 0) {
        fclose(f);
        return NULL;
    }
    *size = (size_t)file_size;

    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return NULL;
    }

    uint8_t* buf = (uint8_t*)malloc(*size);
    if (!buf) {
        fclose(f);
        return NULL;
    }

    size_t read_size = fread(buf, 1, *size, f);
    fclose(f);

    if (read_size != *size) {
        free(buf);
        return NULL;
    }

    return buf;
}

int zupt_write_file(const char* path, const uint8_t* data, size_t size) {
    if (!path || (!data && size > 0)) return -1;

    FILE* f = fopen(path, "wb");
    if (!f) return -1;

    size_t written = fwrite(data, 1, size, f);
    fclose(f);

    return (written == size) ? 0 : -1;
}

/* ═══════════════════════════════════════════════════════════════════
 * HYBRID ENCRYPTION/DECRYPTION
 * ═══════════════════════════════════════════════════════════════════ */

/* Block size for chunked encryption */
#define ZUPT_ENCRYPT_BLOCK_SIZE (4 * 1024 * 1024)

/* Size of payload length prefix in each block (4 bytes, little-endian) */
#define ZUPT_PAYLOAD_LEN_SIZE 4

uint8_t* zupt_hybrid_encrypt(const uint8_t* pub_key, size_t pub_key_len,
                             const uint8_t* plaintext, size_t plaintext_len,
                             uint8_t* enc_header, size_t* enc_header_len,
                             size_t* ciphertext_len) {
    if (!pub_key || !enc_header || !enc_header_len || !ciphertext_len) {
        return NULL;
    }

    /* Allow NULL plaintext only if size is 0 */
    if (!plaintext && plaintext_len > 0) {
        return NULL;
    }

    /* Initialize hybrid encryption directly from the in-memory public key.
     * No key material is ever written to disk. */
    zupt_keyring_t kr = {};
    int ret = zupt_hybrid_encrypt_init_mem(&kr, pub_key, pub_key_len,
                                           enc_header, enc_header_len);
    if (ret != 0) {
        return NULL;
    }

    if (*enc_header_len != 1 + 1088 + 32 + 16) {
        zupt_secure_wipe(&kr, sizeof(kr));
        return NULL;
    }

    /* Encrypt in blocks */
    size_t total_size = 0;
    uint8_t* ciphertext = NULL;

    size_t pos = 0;
    do {
        size_t remaining = plaintext_len - pos;
        size_t block_len = remaining < ZUPT_ENCRYPT_BLOCK_SIZE ? remaining : ZUPT_ENCRYPT_BLOCK_SIZE;
        size_t out_len = 0;

        /* Empty messages still need a nonce and MAC. Avoid arithmetic on NULL. */
        uint8_t* encrypted = zupt_encrypt_buffer(&kr, plaintext ? plaintext + pos : NULL, block_len,
                                                  pos / ZUPT_ENCRYPT_BLOCK_SIZE, &out_len);
        if (!encrypted) {
            zupt_secure_wipe(&kr, sizeof(kr));
            free(ciphertext);
            return NULL;
        }

        /* Expected ciphertext from zupt_encrypt_buffer: nonce(16) + payload + hmac(32) */
        size_t encrypted_size = 16 + block_len + 32;
        if (out_len != encrypted_size) {
            zupt_secure_wipe(&kr, sizeof(kr));
            free(encrypted);
            free(ciphertext);
            return NULL;
        }

        /* Calculate total size with payload length prefix */
        size_t block_size = ZUPT_PAYLOAD_LEN_SIZE + encrypted_size;

        if (block_size > SIZE_MAX - total_size) {
            zupt_secure_wipe(&kr, sizeof(kr));
            free(encrypted);
            free(ciphertext);
            return NULL;
        }
        uint8_t* new_buf = (uint8_t*)realloc(ciphertext, total_size + block_size);
        if (!new_buf) {
            zupt_secure_wipe(&kr, sizeof(kr));
            free(encrypted);
            free(ciphertext);
            return NULL;
        }
        ciphertext = new_buf;

        /* Write payload length (little-endian) */
        uint8_t len_buf[4];
        len_buf[0] = block_len & 0xFF;
        len_buf[1] = (block_len >> 8) & 0xFF;
        len_buf[2] = (block_len >> 16) & 0xFF;
        len_buf[3] = (block_len >> 24) & 0xFF;

        /* Copy payload length, then encrypted data */
        memcpy(ciphertext + total_size, len_buf, ZUPT_PAYLOAD_LEN_SIZE);
        memcpy(ciphertext + total_size + ZUPT_PAYLOAD_LEN_SIZE, encrypted, encrypted_size);
        total_size += block_size;
        free(encrypted);
        pos += block_len;
    } while (pos < plaintext_len);

    zupt_secure_wipe(&kr, sizeof(kr));
    *ciphertext_len = total_size;
    return ciphertext;
}

uint8_t* zupt_hybrid_decrypt(const uint8_t* priv_key, size_t priv_key_len,
                             const uint8_t* ciphertext, size_t ciphertext_len,
                             const uint8_t* enc_header, size_t enc_header_len,
                             size_t* plaintext_len) {
    if (!priv_key || !ciphertext || !enc_header || !plaintext_len) {
        return NULL;
    }

    /* Initialize hybrid decryption directly from the in-memory private key.
     * The secret key is never staged on disk (which would defeat the
     * in-RAM mlock protection and leave key material in /tmp). */
    zupt_keyring_t kr = {};
    int ret = zupt_hybrid_decrypt_init_mem(&kr, priv_key, priv_key_len,
                                           enc_header, enc_header_len);
    if (ret != 0) {
        return NULL;
    }

    /* Decrypt in blocks */
    size_t total_size = 0;
    uint8_t* plaintext = NULL;
    size_t pos = 0;
    uint64_t block_num = 0;

    while (pos < ciphertext_len) {
        /* Check for valid block header (payload_len + nonce + hmac) */
        if (ciphertext_len - pos < ZUPT_PAYLOAD_LEN_SIZE + 16 + 32) {
            zupt_secure_wipe(&kr, sizeof(kr));
            free(plaintext);
            return NULL;
        }

        /* Read payload length from ciphertext (little-endian).
         * Cast to uint32_t before shifting: a bare uint8_t promotes to int,
         * so `byte << 24` is undefined/sign-extends when the top bit is set,
         * which would yield a bogus (huge) block_len. */
        size_t block_len = (size_t)ciphertext[pos] |
                          ((size_t)ciphertext[pos + 1] << 8) |
                          ((size_t)ciphertext[pos + 2] << 16) |
                          ((size_t)ciphertext[pos + 3] << 24);

        /* A zero payload is valid only as one authenticated empty message. */
        if (block_len > ZUPT_ENCRYPT_BLOCK_SIZE ||
            (block_len == 0 && (pos != 0 || ciphertext_len != 52))) {
            zupt_secure_wipe(&kr, sizeof(kr));
            free(plaintext);
            return NULL;
        }

        /* Verify block fits in remaining ciphertext */
        size_t block_size = ZUPT_PAYLOAD_LEN_SIZE + 16 + block_len + 32;
        if (block_size > ciphertext_len - pos) {
            zupt_secure_wipe(&kr, sizeof(kr));
            free(plaintext);
            return NULL;
        }

        size_t out_len = 0;
        uint8_t* decrypted = zupt_decrypt_buffer(&kr, ciphertext + pos + ZUPT_PAYLOAD_LEN_SIZE,
                                                  16 + block_len + 32,
                                                  block_num, &out_len);
        if (!decrypted) {
            zupt_secure_wipe(&kr, sizeof(kr));
            free(plaintext);
            return NULL;
        }

        size_t new_size = total_size + out_len;
        uint8_t* new_buf = (uint8_t*)realloc(plaintext, new_size ? new_size : 1);
        if (!new_buf) {
            zupt_secure_wipe(&kr, sizeof(kr));
            free(decrypted);
            free(plaintext);
            return NULL;
        }
        plaintext = new_buf;

        memcpy(plaintext + total_size, decrypted, out_len);
        total_size += out_len;
        free(decrypted);

        /* Move to next block */
        pos += block_size;
        block_num++;
    }

    zupt_secure_wipe(&kr, sizeof(kr));
    *plaintext_len = total_size;
    return plaintext;
}
