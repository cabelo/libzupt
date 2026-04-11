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
#include "zupt_keccak.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef _WIN32
#include <process.h>
#include <io.h>
#define getpid _getpid
#define unlink _unlink
#endif


/* ═══════════════════════════════════════════════════════════════════
 * HYBRID KEY DERIVATION
 * ═══════════════════════════════════════════════════════════════════ */

int zupt_hybrid_derive_keys(const uint8_t* ml_ss, const uint8_t* ml_ct,
                            const uint8_t* eph_pk, const uint8_t* ml_pk,
                            uint8_t* archive_key) {
    if (!ml_ss || !ml_ct || !eph_pk || !archive_key) return -1;

    /* Compute hybrid shared secret: XOR ML-KEM and X25519 shared secrets */
    uint8_t hybrid_ikm[32];
    for (int i = 0; i < 32; i++) {
        hybrid_ikm[i] = ml_ss[i];
    }

    /* Key derivation:
     * archive_key = SHA3-512(hybrid_ikm || ml_ct || eph_pk || "ZUPT-HYBRID-v1")
     * Output: enc_key[32] + mac_key[32]
     */
    uint8_t kdf_input[ZUPT_KDF_INPUT_MAX];
    size_t pos = 0;

    memcpy(kdf_input + pos, hybrid_ikm, 32);
    pos += 32;

    memcpy(kdf_input + pos, ml_ct, 1088);
    pos += 1088;

    memcpy(kdf_input + pos, eph_pk, 32);
    pos += 32;

    memcpy(kdf_input + pos, "ZUPT-HYBRID-v1", 15);
    pos += 15;

    /* Compute SHA3-512 */
    zupt_sha3_512(kdf_input, pos, archive_key);

    /* Wipe sensitive data */
    zupt_secure_wipe(hybrid_ikm, sizeof(hybrid_ikm));
    zupt_secure_wipe(kdf_input, pos);

    return 0;
}

int zupt_hybrid_decrypt_derive_keys(const uint8_t* priv_key, size_t priv_key_len,
                                    const uint8_t* enc_header, size_t enc_header_len,
                                    uint8_t* archive_key) {
    /* Parse private key: ZKEY header (8) + ml_pk(1184) + x_pk(32) + ml_sk(2400) + x_sk(32) */
    if (priv_key_len < 8 + 1184 + 32 + 2400 + 32) return -1;
    if (enc_header_len < 1 + 1088 + 32 + 16) return -1;

    const uint8_t* ml_pk = priv_key + 8;
    const uint8_t* x_pk = ml_pk + 1184;
    const uint8_t* ml_sk = x_pk + 32;
    const uint8_t* x_sk = ml_sk + 2400;

    /* Parse encryption header: enc_type(1) + ml_ct(1088) + eph_pk(32) + nonce(16) */
    const uint8_t* ml_ct = enc_header + 1;
    const uint8_t* eph_pk = ml_ct + 1088;

    /* ML-KEM decapsulation */
    uint8_t ml_ss[32];
    if (zupt_mlkem768_decaps(ml_ss, ml_ct, ml_sk) != 0) {
        return -1;
    }

    /* X25519 ECDH */
    uint8_t x_ss[32];
    zupt_x25519(x_ss, x_sk, eph_pk);

    /* Hybrid shared secret */
    uint8_t hybrid_ikm[32];
    for (int i = 0; i < 32; i++) {
        hybrid_ikm[i] = ml_ss[i] ^ x_ss[i];
    }

    /* Key derivation */
    uint8_t kdf_input[ZUPT_KDF_INPUT_MAX];
    size_t pos = 0;

    memcpy(kdf_input + pos, hybrid_ikm, 32);
    pos += 32;

    memcpy(kdf_input + pos, ml_ct, 1088);
    pos += 1088;

    memcpy(kdf_input + pos, eph_pk, 32);
    pos += 32;

    memcpy(kdf_input + pos, "ZUPT-HYBRID-v1", 15);
    pos += 15;

    zupt_sha3_512(kdf_input, pos, archive_key);

    /* Wipe sensitive data */
    zupt_secure_wipe(ml_ss, sizeof(ml_ss));
    zupt_secure_wipe(x_ss, sizeof(x_ss));
    zupt_secure_wipe(hybrid_ikm, sizeof(hybrid_ikm));
    zupt_secure_wipe(kdf_input, pos);

    return 0;
}

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

    /* Create temporary public key file */
    FILE* tmp = tmpfile();
    if (!tmp) return NULL;

    if (fwrite(pub_key, 1, pub_key_len, tmp) != pub_key_len) {
        fclose(tmp);
        return NULL;
    }
    rewind(tmp);

    /* Read public key file path via temp file descriptor */
    char tmp_path[64];
    snprintf(tmp_path, sizeof(tmp_path), "/tmp/zupt_pub_XXXXXX");

    /* Actually, let's use a different approach - write to a temp file by name */
    snprintf(tmp_path, sizeof(tmp_path), "/tmp/zupt_pub_%d", getpid());
    FILE* f = fopen(tmp_path, "wb");
    if (!f) {
        fclose(tmp);
        return NULL;
    }
    fwrite(pub_key, 1, pub_key_len, f);
    fclose(f);
    fclose(tmp);

    /* Initialize hybrid encryption */
    zupt_keyring_t kr = {};
    int ret = zupt_hybrid_encrypt_init(&kr, tmp_path, enc_header, enc_header_len);
    unlink(tmp_path);

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

    for (size_t pos = 0; pos < plaintext_len; pos += ZUPT_ENCRYPT_BLOCK_SIZE) {
        size_t block_len = (pos + ZUPT_ENCRYPT_BLOCK_SIZE <= plaintext_len) ? ZUPT_ENCRYPT_BLOCK_SIZE : plaintext_len - pos;
        size_t out_len = 0;

        uint8_t* encrypted = zupt_encrypt_buffer(&kr, plaintext + pos, block_len,
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
    }

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

    /* Create temporary private key file */
    char tmp_path[64];
    snprintf(tmp_path, sizeof(tmp_path), "/tmp/zupt_priv_%d", getpid());
    FILE* f = fopen(tmp_path, "wb");
    if (!f) return NULL;

    if (fwrite(priv_key, 1, priv_key_len, f) != priv_key_len) {
        fclose(f);
        unlink(tmp_path);
        return NULL;
    }
    fclose(f);

    /* Initialize hybrid decryption */
    zupt_keyring_t kr = {};
    int ret = zupt_hybrid_decrypt_init(&kr, tmp_path, enc_header, enc_header_len);
    unlink(tmp_path);

    if (ret != 0) {
        return NULL;
    }

    /* Decrypt in blocks */
    size_t total_size = 0;
    uint8_t* plaintext = NULL;
    size_t pos = 0;
    int block_num = 0;

    while (pos < ciphertext_len) {
        /* Check for valid block header (payload_len + nonce + hmac) */
        if (pos + ZUPT_PAYLOAD_LEN_SIZE + 16 + 32 > ciphertext_len) {
            zupt_secure_wipe(&kr, sizeof(kr));
            free(plaintext);
            return NULL;
        }

        /* Read payload length from ciphertext (little-endian) */
        size_t block_len = ciphertext[pos] |
                          (ciphertext[pos + 1] << 8) |
                          (ciphertext[pos + 2] << 16) |
                          (ciphertext[pos + 3] << 24);

        if (block_len == 0) break;

        /* Verify block fits in remaining ciphertext */
        size_t block_size = ZUPT_PAYLOAD_LEN_SIZE + 16 + block_len + 32;
        if (pos + block_size > ciphertext_len) {
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

        uint8_t* new_buf = (uint8_t*)realloc(plaintext, total_size + out_len);
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
