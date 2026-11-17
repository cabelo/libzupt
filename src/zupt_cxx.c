/*
 * libzupt - C wrapper for hybrid post-quantum encryption
 * C implementation for C++ library
 *
 * SPDX-License-Identifier: MIT
 */

#define _POSIX_C_SOURCE 200809L
#include "zupt_cxx.h"
#include "zupt.h"
#include "zupt_mlkem.h"
#include "zupt_x25519.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

void zupt_free(void* ptr) { free(ptr); }

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
    pub_key[4] = ZUPT_KEY_FORMAT_VERSION; /* version */
    pub_key[5] = 0x00; /* no private key */
    pub_key[6] = pub_key[7] = 0;
    memcpy(pub_key + 8, ml_pk, 1184);
    memcpy(pub_key + 8 + 1184, x_pk, 32);

    /* Build private key: ZKEY header + ml_pk + x_pk + ml_sk + x_sk */
    memcpy(priv_key, "ZKEY", 4);
    priv_key[4] = ZUPT_KEY_FORMAT_VERSION; /* version */
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
    if ((priv_key[4] != 1 && priv_key[4] != ZUPT_KEY_FORMAT_VERSION) ||
        priv_key[5] != 1 || priv_key[6] || priv_key[7]) return -1;

    /* Extract public key data */
    const uint8_t* ml_pk = priv_key + 8;
    const uint8_t* x_pk = ml_pk + 1184;

    /* Build public key */
    memcpy(pub_key, "ZKEY", 4);
    pub_key[4] = priv_key[4]; /* preserve the source format */
    pub_key[5] = 0x00;
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

    uint8_t* buf = (uint8_t*)malloc(*size ? *size : 1);
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
    int closed = fclose(f);
    return (written == size && closed == 0) ? 0 : -1;
}

int zupt_write_private_key(const char* path, const uint8_t* data, size_t size) {
    if (!path || !data || size != 3656 || memcmp(data, "ZKEY", 4) != 0 ||
        (data[4] != 1 && data[4] != ZUPT_KEY_FORMAT_VERSION) ||
        data[5] != 1 || data[6] || data[7]) return -1;
#ifndef _WIN32
    int fd = open(path, O_WRONLY | O_CREAT | O_NOFOLLOW | O_NONBLOCK, 0600);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_nlink != 1 ||
        st.st_uid != geteuid() || fchmod(fd, 0600) != 0 || ftruncate(fd, 0) != 0) {
        close(fd);
        return -1;
    }
    FILE* file = fdopen(fd, "wb");
    if (!file) { close(fd); return -1; }
    size_t written = fwrite(data, 1, size, file);
    int closed = fclose(file);
    return written == size && closed == 0 ? 0 : -1;
#else
    return zupt_write_file(path, data, size);
#endif
}

/* ═══════════════════════════════════════════════════════════════════
 * HYBRID ENCRYPTION/DECRYPTION
 * ═══════════════════════════════════════════════════════════════════ */

/* v2 envelope: "ZUP2" || u64le(plaintext bytes) || block records || HMAC.
 * The final MAC binds the entire encryption header and complete record stream.
 * Authenticate this MAC before parsing lengths or returning any plaintext. */
#define ZUPT_ENCRYPT_BLOCK_SIZE (4 * 1024 * 1024)
#define ENVELOPE_PREFIX 12
#define ENVELOPE_TAG 32

extern int zupt_hybrid_decrypt_init_legacy_mem(zupt_keyring_t *,
    const uint8_t *, size_t, const uint8_t *, size_t);

static void discard_plain(uint8_t *p, size_t len) {
    if (p) { zupt_secure_wipe(p, len); free(p); }
}

static void envelope_tag(const zupt_keyring_t *kr, const uint8_t header[1137],
                         const uint8_t *records, size_t len, uint8_t tag[32]) {
    static const uint8_t domain[] = "libzupt/envelope/v2";
    static const uint8_t key_domain[] = "libzupt/envelope/key/v2";
    uint8_t pad[64], inner[32], outer_key[32];
    zupt_hmac_sha256(kr->mac_key, 32, key_domain, sizeof(key_domain) - 1, outer_key);
    zupt_sha256_ctx ctx;
    memset(pad, 0x36, sizeof(pad));
    for (size_t i = 0; i < 32; ++i) pad[i] ^= outer_key[i];
    zupt_sha256_init(&ctx);
    zupt_sha256_update(&ctx, pad, sizeof(pad));
    zupt_sha256_update(&ctx, domain, sizeof(domain) - 1);
    zupt_sha256_update(&ctx, header, 1137);
    zupt_sha256_update(&ctx, records, len);
    zupt_sha256_final(&ctx, inner);
    memset(pad, 0x5c, sizeof(pad));
    for (size_t i = 0; i < 32; ++i) pad[i] ^= outer_key[i];
    zupt_sha256_init(&ctx);
    zupt_sha256_update(&ctx, pad, sizeof(pad));
    zupt_sha256_update(&ctx, inner, sizeof(inner));
    zupt_sha256_final(&ctx, tag);
    zupt_secure_wipe(pad, sizeof(pad));
    zupt_secure_wipe(inner, sizeof(inner));
    zupt_secure_wipe(outer_key, sizeof(outer_key));
    zupt_secure_wipe(&ctx, sizeof(ctx));
}

static int same_tag(const uint8_t a[32], const uint8_t b[32]) {
    uint32_t diff = 0;
    for (size_t i = 0; i < 32; ++i) diff |= a[i] ^ b[i];
    return diff == 0;
}

uint8_t* zupt_hybrid_encrypt(const uint8_t* pub_key, size_t pub_key_len,
    const uint8_t* plaintext, size_t plaintext_len,
    uint8_t* enc_header, size_t* enc_header_len, size_t* ciphertext_len) {
    if (ciphertext_len) *ciphertext_len = 0;
    if (enc_header_len) *enc_header_len = 0;
    if (!pub_key || !enc_header || !enc_header_len || !ciphertext_len ||
        (!plaintext && plaintext_len)) return NULL;
    size_t blocks = plaintext_len ? 1 + (plaintext_len - 1) / ZUPT_ENCRYPT_BLOCK_SIZE : 1;
    if (plaintext_len > SIZE_MAX - ENVELOPE_PREFIX - ENVELOPE_TAG ||
        blocks > (SIZE_MAX - ENVELOPE_PREFIX - ENVELOPE_TAG - plaintext_len) / 52)
        return NULL;
    size_t total = ENVELOPE_PREFIX + plaintext_len + blocks * 52 + ENVELOPE_TAG;
    uint8_t *out = (uint8_t *)malloc(total);
    if (!out) return NULL;
    zupt_keyring_t kr = {0};
    if (zupt_hybrid_encrypt_init_mem(&kr, pub_key, pub_key_len,
                                    enc_header, enc_header_len) != 0) {
        zupt_munlock_keys(&kr, sizeof(kr));
        free(out);
        return NULL;
    }
    memcpy(out, "ZUP2", 4);
    zupt_le64_put(out + 4, (uint64_t)plaintext_len);
    size_t source = 0, dest = ENVELOPE_PREFIX;
    for (size_t block = 0; block < blocks; ++block) {
        size_t n = plaintext_len - source;
        if (n > ZUPT_ENCRYPT_BLOCK_SIZE) n = ZUPT_ENCRYPT_BLOCK_SIZE;
        size_t encrypted_len = 0;
        uint8_t *encrypted = zupt_encrypt_buffer(&kr,
            plaintext ? plaintext + source : NULL, n, block, &encrypted_len);
        if (!encrypted || encrypted_len != n + 48) {
            free(encrypted);
            zupt_munlock_keys(&kr, sizeof(kr));
            free(out);
            *enc_header_len = 0;
            return NULL;
        }
        for (unsigned i = 0; i < 4; ++i) out[dest + i] = (uint8_t)(n >> (8 * i));
        memcpy(out + dest + 4, encrypted, encrypted_len);
        free(encrypted);
        source += n;
        dest += n + 52;
    }
    envelope_tag(&kr, enc_header, out, dest, out + dest);
    zupt_munlock_keys(&kr, sizeof(kr));
    *ciphertext_len = total;
    return out;
}

static uint8_t *decrypt_records(zupt_keyring_t *kr, const uint8_t *ciphertext,
    size_t ciphertext_len, size_t expected_len, size_t *plaintext_len) {
    if (ciphertext_len < 52 || expected_len > ciphertext_len) return NULL;
    uint8_t *plaintext = (uint8_t *)malloc(expected_len ? expected_len : 1);
    if (!plaintext) return NULL;
    size_t pos = 0, total = 0;
    uint64_t block = 0;
    while (pos < ciphertext_len) {
        if (ciphertext_len - pos < 52) goto fail;
        uint32_t n = (uint32_t)ciphertext[pos] |
            ((uint32_t)ciphertext[pos + 1] << 8) |
            ((uint32_t)ciphertext[pos + 2] << 16) |
            ((uint32_t)ciphertext[pos + 3] << 24);
        if (n > ZUPT_ENCRYPT_BLOCK_SIZE || n > expected_len - total ||
            (n == 0 && (pos != 0 || ciphertext_len != 52)) ||
            (size_t)n + 52 > ciphertext_len - pos) goto fail;
        size_t decoded_len = 0;
        uint8_t *decoded = zupt_decrypt_buffer(kr, ciphertext + pos + 4,
                                               (size_t)n + 48, block, &decoded_len);
        if (!decoded || decoded_len != n) {
            discard_plain(decoded, decoded_len);
            goto fail;
        }
        if (n) memcpy(plaintext + total, decoded, n);
        discard_plain(decoded, decoded_len);
        total += n;
        pos += (size_t)n + 52;
        ++block;
    }
    if (total != expected_len) goto fail;
    *plaintext_len = total;
    return plaintext;
fail:
    discard_plain(plaintext, expected_len);
    return NULL;
}

uint8_t* zupt_hybrid_decrypt(const uint8_t* priv_key, size_t priv_key_len,
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t* enc_header, size_t enc_header_len, size_t* plaintext_len) {
    if (plaintext_len) *plaintext_len = 0;
    if (!priv_key || !ciphertext || !enc_header || !plaintext_len ||
        enc_header_len != 1137 || enc_header[0] != ZUPT_ENVELOPE_FORMAT ||
        ciphertext_len < ENVELOPE_PREFIX + 52 + ENVELOPE_TAG ||
        memcmp(ciphertext, "ZUP2", 4) != 0) return NULL;
    zupt_keyring_t kr = {0};
    if (zupt_hybrid_decrypt_init_mem(&kr, priv_key, priv_key_len,
                                    enc_header, enc_header_len) != 0) {
        zupt_munlock_keys(&kr, sizeof(kr));
        return NULL;
    }
    uint8_t tag[32];
    envelope_tag(&kr, enc_header, ciphertext, ciphertext_len - ENVELOPE_TAG, tag);
    int authenticated = same_tag(tag, ciphertext + ciphertext_len - ENVELOPE_TAG);
    zupt_secure_wipe(tag, sizeof(tag));
    uint8_t *plaintext = NULL;
    if (authenticated) {
        uint64_t expected = zupt_le64_get(ciphertext + 4);
        size_t record_len = ciphertext_len - ENVELOPE_PREFIX - ENVELOPE_TAG;
        if (expected <= SIZE_MAX && expected <= record_len)
            plaintext = decrypt_records(&kr, ciphertext + ENVELOPE_PREFIX,
                record_len, (size_t)expected, plaintext_len);
    }
    zupt_munlock_keys(&kr, sizeof(kr));
    return plaintext;
}

uint8_t* zupt_hybrid_decrypt_legacy(const uint8_t* priv_key, size_t priv_key_len,
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t* enc_header, size_t enc_header_len,
    const uint8_t expected_sha256[32], size_t* plaintext_len) {
    if (plaintext_len) *plaintext_len = 0;
    if (!priv_key || !ciphertext || !enc_header || !expected_sha256 || !plaintext_len ||
        enc_header_len != 1137 || enc_header[0] != 2 || ciphertext_len < 52) return NULL;
    /* Count legacy payload bytes with bounds checks, without allocating. */
    size_t pos = 0, expected = 0;
    while (pos < ciphertext_len) {
        if (ciphertext_len - pos < 52) return NULL;
        uint32_t n = (uint32_t)ciphertext[pos] |
            ((uint32_t)ciphertext[pos + 1] << 8) |
            ((uint32_t)ciphertext[pos + 2] << 16) |
            ((uint32_t)ciphertext[pos + 3] << 24);
        if (n > ZUPT_ENCRYPT_BLOCK_SIZE || (size_t)n + 52 > ciphertext_len - pos ||
            n > SIZE_MAX - expected) return NULL;
        expected += n;
        pos += (size_t)n + 52;
    }
    zupt_keyring_t kr = {0};
    if (zupt_hybrid_decrypt_init_legacy_mem(&kr, priv_key, priv_key_len,
                                           enc_header, enc_header_len) != 0) {
        zupt_munlock_keys(&kr, sizeof(kr));
        return NULL;
    }
    size_t restored_len = 0;
    uint8_t *plaintext = decrypt_records(&kr, ciphertext, ciphertext_len,
                                        expected, &restored_len);
    zupt_munlock_keys(&kr, sizeof(kr));
    if (!plaintext) return NULL;
    uint8_t digest[32];
    zupt_sha256(plaintext, restored_len, digest);
    int valid = same_tag(digest, expected_sha256);
    zupt_secure_wipe(digest, sizeof(digest));
    if (!valid) { discard_plain(plaintext, restored_len); return NULL; }
    *plaintext_len = restored_len;
    return plaintext;
}
