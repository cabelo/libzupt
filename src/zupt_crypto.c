/*
 * Zupt — Backup-oriented compression with AES-256 encryption
 * Copyright (c) 2026 Cristian Cezar Moisés
 * SPDX-License-Identifier: MIT
 *
 * Cryptographic operations:
 * - HMAC-SHA256, PBKDF2, AES-256-CTR, Encrypt-then-MAC (v0.2+)
 * - Hybrid PQ KEM: ML-KEM-768 + X25519 (v0.7.0)
 *
 * FRAMA-C: ACSL-annotated (v2.0.0)
 */
#define _GNU_SOURCE
#include "zupt.h"
#include "zupt_acsl.h"
#include "zupt_jasmin.h"
#include "zupt_cpuid.h"  /* JASMIN-VERIFIED: AES-NI dispatch */
#include <stdlib.h>
#include <string.h>
#include <time.h>
#if defined(__linux__)
  #include <sys/syscall.h>
  #include <unistd.h>
#endif

/* ═══════════════════════════════════════════════════════════════════
 * RANDOM BYTES (OS-native CSPRNG — NO FALLBACK)
 *
 * If the OS CSPRNG is unavailable, this aborts. Using rand() would
 * make salt/nonce predictable and destroy all security guarantees.
 * ═══════════════════════════════════════════════════════════════════ */

void zupt_random_bytes(uint8_t *buf, size_t len) {
#ifdef _WIN32
    /* Windows: RtlGenRandom (SystemFunction036) */
    HMODULE lib = LoadLibraryA("advapi32.dll");
    if (lib) {
        typedef BOOLEAN(WINAPI *RtlGenRandomFunc)(PVOID, ULONG);
        RtlGenRandomFunc fn = (RtlGenRandomFunc)(void(*)(void))GetProcAddress(lib, "SystemFunction036");
        if (fn && fn(buf, (ULONG)len)) { FreeLibrary(lib); return; }
        FreeLibrary(lib);
    }
    fprintf(stderr, "FATAL: Windows CSPRNG (RtlGenRandom) unavailable.\n");
    exit(1);
#else
    /* Linux/macOS/BSD: try getrandom(2) first, then /dev/urandom */
  #if defined(__linux__)
    #if defined(SYS_getrandom)
    ssize_t r = syscall(SYS_getrandom, buf, len, 0);
    if (r == (ssize_t)len) return;
    #endif
  #endif
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        size_t r = fread(buf, 1, len, f);
        fclose(f);
        if (r == len) return;
    }
    fprintf(stderr, "FATAL: /dev/urandom unavailable. Cannot generate secure random bytes.\n");
    exit(1);
#endif
}

/* ═══════════════════════════════════════════════════════════════════
 * HMAC-SHA256 (RFC 2104)
 * ═══════════════════════════════════════════════════════════════════ */

/* FRAMA-C: HMAC-SHA256 (RFC 2104) */
/*@ requires klen <= 256;
  @ requires \valid_read(key + (0..klen-1));
  @ requires \valid_read(data + (0..dlen-1));
  @ requires \valid(mac + (0..31));
  @ requires \separated(key + (0..klen-1), mac + (0..31));
  @ requires \separated(data + (0..dlen-1), mac + (0..31));
  @ assigns mac[0..31];
  @ ensures \initialized(mac + (0..31));
*/
void zupt_hmac_sha256(const uint8_t *key, size_t klen,
                      const uint8_t *data, size_t dlen,
                      uint8_t mac[32]) {
    uint8_t k_pad[64];
    uint8_t k_hash[32];

    /* If key > 64 bytes, hash it first */
    if (klen > 64) {
        zupt_sha256(key, klen, k_hash);
        key = k_hash; klen = 32;
    }

    /* ipad = key XOR 0x36 */
    memset(k_pad, 0x36, 64);
    for (size_t i = 0; i < klen; i++) k_pad[i] ^= key[i];

    /* inner = SHA256(ipad || data) */
    zupt_sha256_ctx ctx;
    zupt_sha256_init(&ctx);
    zupt_sha256_update(&ctx, k_pad, 64);
    zupt_sha256_update(&ctx, data, dlen);
    uint8_t inner[32];
    zupt_sha256_final(&ctx, inner);

    /* opad = key XOR 0x5c */
    memset(k_pad, 0x5c, 64);
    for (size_t i = 0; i < klen; i++) k_pad[i] ^= key[i];

    /* mac = SHA256(opad || inner) */
    zupt_sha256_init(&ctx);
    zupt_sha256_update(&ctx, k_pad, 64);
    zupt_sha256_update(&ctx, inner, 32);
    zupt_sha256_final(&ctx, mac);

    /* Wipe sensitive data */
    zupt_secure_wipe(k_pad, 64);
    zupt_secure_wipe(inner, 32);
    zupt_secure_wipe(k_hash, 32);
}

/* ═══════════════════════════════════════════════════════════════════
 * PBKDF2-HMAC-SHA256 (RFC 8018)
 * ═══════════════════════════════════════════════════════════════════ */

/* FRAMA-C: PBKDF2-HMAC-SHA256 (RFC 8018) */
/*@ requires pwlen <= 256;
  @ requires slen <= 252;
  @ requires olen > 0 && olen <= 64;
  @ requires iterations >= 1;
  @ requires \valid_read(pw + (0..pwlen-1));
  @ requires \valid_read(salt + (0..slen-1));
  @ requires \valid(output + (0..olen-1));
  @ assigns output[0..olen-1];
  @ ensures \initialized(output + (0..olen-1));
*/
void zupt_pbkdf2_sha256(const uint8_t *pw, size_t pwlen,
                        const uint8_t *salt, size_t slen,
                        uint32_t iterations,
                        uint8_t *output, size_t olen) {
    /* Clamp salt length to fit in the stack buffer.
     * ZUPT always passes ZUPT_SALT_SIZE (32) so this is a safety net. */
    size_t effective_slen = slen;
    if (effective_slen > 252) effective_slen = 252;

    uint32_t block_num = 1;
    size_t pos = 0;

    while (pos < olen) {
        /* U_1 = HMAC(pw, salt || INT_32_BE(block_num)) */
        uint8_t salt_block[256];
        memcpy(salt_block, salt, effective_slen);
        salt_block[effective_slen+0] = (uint8_t)(block_num >> 24);
        salt_block[effective_slen+1] = (uint8_t)(block_num >> 16);
        salt_block[effective_slen+2] = (uint8_t)(block_num >> 8);
        salt_block[effective_slen+3] = (uint8_t)(block_num);

        uint8_t u[32], t[32];
        zupt_hmac_sha256(pw, pwlen, salt_block, effective_slen + 4, u);
        memcpy(t, u, 32);

        /* U_2 .. U_c: XOR chain */
        for (uint32_t i = 1; i < iterations; i++) {
            zupt_hmac_sha256(pw, pwlen, u, 32, u);
            for (int j = 0; j < 32; j++) t[j] ^= u[j];
        }

        /* Copy to output */
        size_t chunk = olen - pos;
        if (chunk > 32) chunk = 32;
        memcpy(output + pos, t, chunk);
        pos += chunk;
        block_num++;

        /* Wipe per-block intermediates */
        zupt_secure_wipe(u, 32);
        zupt_secure_wipe(t, 32);
        zupt_secure_wipe(salt_block, sizeof(salt_block));
    }
}

/* ═══════════════════════════════════════════════════════════════════
 * AES-256-CTR MODE
 * ═══════════════════════════════════════════════════════════════════ */

/* FRAMA-C: AES-256-CTR stream cipher */
/*@ requires \valid_read(key + (0..31));
  @ requires \valid_read(nonce + (0..15));
  @ requires \valid_read(in + (0..len-1));
  @ requires \valid(out + (0..len-1));
  @ requires \separated(in + (0..len-1), out + (0..len-1));
  @ assigns out[0..len-1];
  @ ensures \initialized(out + (0..len-1));
*/
void zupt_aes256_ctr(const uint8_t key[32], const uint8_t nonce[16],
                     const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t counter[16], keystream[16];
    memcpy(counter, nonce, 16);

#ifdef ZUPT_USE_JASMIN
    /* JASMIN-VERIFIED: AES-NI path — constant-time, no T-table leakage.
     * The Jasmin-generated assembly uses VEX-encoded instructions (vaesenc,
     * vmovdqu, vpxor, etc.) which require BOTH AES-NI AND AVX support.
     * Checking only has_aesni would SIGILL on CPUs with AES-NI but no AVX,
     * or where the OS hasn't enabled XSAVE for YMM state. */
    if (zupt_cpu.has_aesni && zupt_cpu.has_avx) {
        size_t full_blocks = len / 16;
        size_t tail_bytes = len % 16;

        if (full_blocks >= 4) {
            /* 4-block pipeline: processes 4 blocks per iteration */
            size_t pipe_blocks = (full_blocks / 4) * 4;
            zupt_aes256_ctr4(out, in, key, counter, pipe_blocks);
            size_t pipe_bytes = pipe_blocks * 16;
            in += pipe_bytes;
            out += pipe_bytes;
            full_blocks -= pipe_blocks;
        }

        /* Remaining 0-3 full blocks: single-block path */
        size_t pos = 0;
        for (size_t b = 0; b < full_blocks; b++) {
            zupt_aes256_blk(out + pos, in + pos, key, counter);
            pos += 16;
            /* Increment counter (big-endian, last 8 bytes) */
            for (int i = 15; i >= 8; i--) {
                if (++counter[i] != 0) break;
            }
        }
        in += pos;
        out += pos;

        /* Tail: partial last block */
        if (tail_bytes > 0) {
            uint8_t tmp_in[16], tmp_out[16];
            memset(tmp_in, 0, 16);
            memcpy(tmp_in, in, tail_bytes);
            zupt_aes256_blk(tmp_out, tmp_in, key, counter);
            memcpy(out, tmp_out, tail_bytes);
            zupt_secure_wipe(tmp_in, 16);
            zupt_secure_wipe(tmp_out, 16);
        }

        zupt_secure_wipe(counter, 16);
        zupt_secure_wipe(keystream, 16);
        return;
    }
#endif

    /* C table-based fallback */
    zupt_aes256_ctx ctx;
    zupt_aes256_init(&ctx, key);

    size_t pos = 0;
    while (pos < len) {
        zupt_aes256_encrypt_block(&ctx, counter, keystream);

        size_t chunk = len - pos;
        if (chunk > 16) chunk = 16;
        for (size_t i = 0; i < chunk; i++)
            out[pos + i] = in[pos + i] ^ keystream[i];
        pos += chunk;

        /* Increment counter (big-endian, last 8 bytes) */
        for (int i = 15; i >= 8; i--) {
            if (++counter[i] != 0) break;
        }
    }

    zupt_secure_wipe(&ctx, sizeof(ctx));
    zupt_secure_wipe(keystream, 16);
}

/* ═══════════════════════════════════════════════════════════════════
 * KEY DERIVATION
 * ═══════════════════════════════════════════════════════════════════ */

/* FRAMA-C: Key derivation from password + salt */
/*@ requires \valid(kr);
  @ requires \valid_read(salt + (0..31));
  @ requires \valid_read(nonce + (0..15));
  @ requires strlen(pw) <= 255;
  @ requires iterations >= 1;
  @ assigns kr->enc_key[0..31], kr->mac_key[0..31], kr->salt[0..31],
  @         kr->base_nonce[0..15], kr->iterations, kr->active;
  @ ensures kr->active == 1;
*/
void zupt_derive_keys(zupt_keyring_t *kr, const char *pw,
                      const uint8_t salt[32], const uint8_t nonce[16],
                      uint32_t iterations) {
    /* Init canaries if not already set */
    kr->canary_head = ZUPT_CANARY;
    kr->canary_tail = ZUPT_CANARY;

    memcpy(kr->salt, salt, ZUPT_SALT_SIZE);
    memcpy(kr->base_nonce, nonce, ZUPT_NONCE_SIZE);
    kr->iterations = iterations;
    kr->active = 1;

    /* Derive 64 bytes: 32 enc_key + 32 mac_key */
    uint8_t material[64];
    zupt_pbkdf2_sha256((const uint8_t *)pw, strlen(pw),
                       salt, ZUPT_SALT_SIZE,
                       iterations, material, 64);
    memcpy(kr->enc_key, material, 32);
    memcpy(kr->mac_key, material + 32, 32);

    zupt_secure_wipe(material, 64);

    /* Lock key material in RAM — prevent swap to disk */
    zupt_mlock_keys(kr->enc_key, ZUPT_AES_KEY_SIZE);
    zupt_mlock_keys(kr->mac_key, ZUPT_HMAC_SIZE);
}

/* ═══════════════════════════════════════════════════════════════════
 * ENCRYPT-THEN-MAC
 *
 * Output format: [16-byte per-block nonce] [ciphertext] [32-byte HMAC]
 * The HMAC covers the nonce and ciphertext.
 * Per-block nonce = base_nonce XOR (block_seq as LE 8 bytes in low half)
 * ═══════════════════════════════════════════════════════════════════ */

/* FRAMA-C: Encrypt-then-MAC: produces [nonce][ciphertext][HMAC] */
/*@ requires \valid_read(&kr->enc_key[0..31]);
  @ requires \valid_read(&kr->mac_key[0..31]);
  @ requires \valid_read(&kr->base_nonce[0..15]);
  @ requires kr->active == 1;
  @ requires \valid_read(plain + (0..plen-1));
  @ requires \valid(olen);
  @ assigns *olen;
  @ ensures *olen == 16 + plen + 32;
*/
uint8_t *zupt_encrypt_buffer(const zupt_keyring_t *kr,
                              const uint8_t *plain, size_t plen,
                              uint64_t block_seq, size_t *olen) {
    *olen = ZUPT_NONCE_SIZE + plen + ZUPT_HMAC_SIZE;
    uint8_t *pkg = (uint8_t *)malloc(*olen);
    if (!pkg) return NULL;

    /* Derive per-block nonce */
    uint8_t nonce[16];
    memcpy(nonce, kr->base_nonce, 16);
    for (int i = 0; i < 8; i++)
        nonce[i] ^= (uint8_t)(block_seq >> (i * 8));

    /* Store nonce */
    memcpy(pkg, nonce, 16);

    /* Encrypt */
    zupt_aes256_ctr(kr->enc_key, nonce, plain, pkg + 16, plen);

    /* MAC over nonce + ciphertext */
    zupt_hmac_sha256(kr->mac_key, ZUPT_HMAC_SIZE,
                     pkg, 16 + plen,
                     pkg + 16 + plen);

    return pkg;
}

/* FRAMA-C: Decrypt with MAC verification (Encrypt-then-MAC) */
/*@ requires \valid_read(&kr->enc_key[0..31]);
  @ requires \valid_read(&kr->mac_key[0..31]);
  @ requires kr->active == 1;
  @ requires pkglen >= 48;
  @ requires \valid_read(pkg + (0..pkglen-1));
  @ requires \valid(olen);
  @ assigns *olen;
  @ behavior auth_ok:
  @   ensures \result != \null ==> *olen == pkglen - 48;
  @ behavior auth_fail:
  @   ensures \result == \null ==> *olen == pkglen - 48;
*/
uint8_t *zupt_decrypt_buffer(const zupt_keyring_t *kr,
                              const uint8_t *pkg, size_t pkglen,
                              uint64_t block_seq, size_t *olen) {
    (void)block_seq;
    if (pkglen < ZUPT_NONCE_SIZE + ZUPT_HMAC_SIZE) return NULL;

    size_t clen = pkglen - ZUPT_NONCE_SIZE - ZUPT_HMAC_SIZE;
    *olen = clen;

    /* Verify HMAC — constant-time comparison via XOR accumulation */
    uint8_t expected_mac[32];
    zupt_hmac_sha256(kr->mac_key, ZUPT_HMAC_SIZE,
                     pkg, ZUPT_NONCE_SIZE + clen,
                     expected_mac);

    const uint8_t *stored_mac = pkg + ZUPT_NONCE_SIZE + clen;
#ifdef ZUPT_USE_JASMIN
    /* JASMIN-VERIFIED: CT MAC comparison — 4×u64 XOR accumulation.
     * Proven constant-time by Jasmin type system. */
    uint64_t diff = zupt_mac_verify_ct(expected_mac, stored_mac);
#else
    /* CT-REQUIRED: XOR accumulation fallback */
    uint64_t diff = 0;
    for (int i = 0; i < 32; i++)
        diff |= (uint64_t)(expected_mac[i] ^ stored_mac[i]);
#endif

    zupt_secure_wipe(expected_mac, 32);

    /* CT-REQUIRED: Always decrypt even on MAC failure to prevent timing oracle.
     * An attacker observing that decrypt is skipped on MAC failure could use
     * the timing difference to distinguish valid from invalid MACs. */
    uint8_t *plain = (uint8_t *)malloc(clen);
    if (!plain) return NULL;

    const uint8_t *nonce = pkg;
    zupt_aes256_ctr(kr->enc_key, nonce, pkg + 16, plain, clen);

    if (diff != 0) {
        /* Authentication failed — wipe and discard decrypted data */
        zupt_secure_wipe(plain, clen);
        free(plain);
        return NULL;
    }

    return plain;
}

/* ═══════════════════════════════════════════════════════════════════
 * HYBRID POST-QUANTUM KEM: ML-KEM-768 + X25519 (v0.7.0)
 *
 * Security model: Secure if EITHER ML-KEM-768 OR X25519 is secure.
 * Same approach as Signal (PQXDH), iMessage (PQ3), OpenSSH 9.0+.
 *
 * Key file format (.zupt-key):
 *   [4B]  magic "ZKEY"
 *   [1B]  version 0x01
 *   [1B]  flags: bit0=has_private
 *   [2B]  reserved
 *   [1184B] ml_kem_pk
 *   [32B]   x25519_pk
 *   [2400B] ml_kem_sk  (only if has_private)
 *   [32B]   x25519_sk  (only if has_private)
 *   [8B]  xxh64 checksum of all above
 * ═══════════════════════════════════════════════════════════════════ */

#include "zupt_mlkem.h"
#include "zupt_x25519.h"
#include "zupt_keccak.h"

#define ZKEY_MAGIC "ZKEY"
#define ZKEY_VERSION 0x01
#define ZKEY_FLAG_PRIVATE 0x01
#define ZKEY_PUB_SIZE  (8 + 1184 + 32)        /* header + ml_kem_pk + x25519_pk */
#define ZKEY_PRIV_SIZE (8 + 1184 + 32 + 2400 + 32) /* + ml_kem_sk + x25519_sk */

int zupt_hybrid_keygen(const char *keyfile) {
    uint8_t ml_pk[MLKEM_PUBLICKEYBYTES], ml_sk[MLKEM_SECRETKEYBYTES];
    uint8_t x_sk[32], x_pk[32];

    /* Generate ML-KEM-768 keypair */
    if (zupt_mlkem768_keygen(ml_pk, ml_sk) != 0) return -1;

    /* Generate X25519 keypair */
    zupt_random_bytes(x_sk, 32);
    zupt_x25519_base(x_pk, x_sk);

    /* Write private key file */
    FILE *f = fopen(keyfile, "wb");
    if (!f) return -1;

    size_t total = ZKEY_PRIV_SIZE;
    uint8_t *buf = (uint8_t *)calloc(total + 8, 1); /* +8 for checksum */
    if (!buf) { fclose(f); return -1; }

    memcpy(buf, ZKEY_MAGIC, 4);
    buf[4] = ZKEY_VERSION;
    buf[5] = ZKEY_FLAG_PRIVATE;
    buf[6] = buf[7] = 0; /* reserved */
    memcpy(buf + 8, ml_pk, 1184);
    memcpy(buf + 8 + 1184, x_pk, 32);
    memcpy(buf + 8 + 1184 + 32, ml_sk, 2400);
    memcpy(buf + 8 + 1184 + 32 + 2400, x_sk, 32);

    /* Checksum */
    uint64_t ck = zupt_xxh64(buf, total, 0);
    zupt_le64_put(buf + total, ck);

    size_t written = fwrite(buf, 1, total + 8, f);
    fclose(f);

    zupt_secure_wipe(ml_sk, sizeof(ml_sk));
    zupt_secure_wipe(x_sk, 32);
    zupt_secure_wipe(buf, total + 8);
    free(buf);

    return (written == total + 8) ? 0 : -1;
}

int zupt_hybrid_export_pubkey(const char *privfile, const char *pubfile) {
    FILE *f = fopen(privfile, "rb");
    if (!f) return -1;

    uint8_t hdr[8];
    if (fread(hdr, 1, 8, f) != 8 || memcmp(hdr, ZKEY_MAGIC, 4) != 0 ||
        !(hdr[5] & ZKEY_FLAG_PRIVATE)) {
        fclose(f); return -1;
    }

    uint8_t pk_data[1184 + 32];
    if (fread(pk_data, 1, 1216, f) != 1216) { fclose(f); return -1; }
    fclose(f);

    /* Write public key file */
    FILE *out = fopen(pubfile, "wb");
    if (!out) return -1;

    size_t total = ZKEY_PUB_SIZE;
    uint8_t buf[ZKEY_PUB_SIZE + 8];
    memcpy(buf, ZKEY_MAGIC, 4);
    buf[4] = ZKEY_VERSION;
    buf[5] = 0; /* no private key */
    buf[6] = buf[7] = 0;
    memcpy(buf + 8, pk_data, 1216);

    uint64_t ck = zupt_xxh64(buf, total, 0);
    zupt_le64_put(buf + total, ck);

    size_t written = fwrite(buf, 1, total + 8, out);
    fclose(out);
    return (written == total + 8) ? 0 : -1;
}

/* Read public key from a .zupt-key file (works for both pub and priv files) */
static int read_pubkey(const char *path, uint8_t ml_pk[1184], uint8_t x_pk[32]) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    uint8_t hdr[8];
    if (fread(hdr, 1, 8, f) != 8 || memcmp(hdr, ZKEY_MAGIC, 4) != 0) {
        fclose(f); return -1;
    }
    if (fread(ml_pk, 1, 1184, f) != 1184) { fclose(f); return -1; }
    if (fread(x_pk, 1, 32, f) != 32) { fclose(f); return -1; }
    fclose(f);
    return 0;
}

/* Read private key from a .zupt-key file */
static int read_privkey(const char *path, uint8_t ml_pk[1184], uint8_t x_pk[32],
                        uint8_t ml_sk[2400], uint8_t x_sk[32]) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    uint8_t hdr[8];
    if (fread(hdr, 1, 8, f) != 8 || memcmp(hdr, ZKEY_MAGIC, 4) != 0 ||
        !(hdr[5] & ZKEY_FLAG_PRIVATE)) {
        fclose(f); return -1;
    }
    if (fread(ml_pk, 1, 1184, f) != 1184) { fclose(f); return -1; }
    if (fread(x_pk, 1, 32, f) != 32) { fclose(f); return -1; }
    if (fread(ml_sk, 1, 2400, f) != 2400) { fclose(f); return -1; }
    if (fread(x_sk, 1, 32, f) != 32) { fclose(f); return -1; }
    fclose(f);
    return 0;
}

/*
 * HYBRID ENCRYPT INIT: Encapsulate with ML-KEM + X25519, derive archive keys.
 *
 * enc_hdr output (1121 bytes):
 *   [1B]    enc_type = 0x02 (PQ-Hybrid)
 *   [1088B] ml_kem_ciphertext
 *   [32B]   ephemeral_x25519_pubkey
 *
 * Key derivation:
 *   hybrid_ikm = ml_kem_ss XOR x25519_ss
 *   archive_key[64] = SHA-256(hybrid_ikm ‖ ml_kem_ct ‖ ephemeral_pk ‖ "ZUPT-HYBRID-v1")
 *   enc_key = archive_key[0:32], mac_key = archive_key[32:64]
 */
/* FRAMA-C: Hybrid PQ encrypt init — ML-KEM-768 + X25519 KEM */
/*@ requires \valid(kr);
  @ requires \valid_read(pubkeyfile);
  @ requires \valid(enc_hdr + (0..1199));
  @ requires \valid(enc_hdr_len);
  @ assigns kr->enc_key[0..31], kr->mac_key[0..31], kr->base_nonce[0..15],
  @         kr->iterations, kr->active;
  @ assigns enc_hdr[0..1199], *enc_hdr_len;
  @ ensures \result == 0 ==> kr->active == 1;
  @ ensures \result == 0 ==> *enc_hdr_len == 1137;
*/
int zupt_hybrid_encrypt_init(zupt_keyring_t *kr, const char *pubkeyfile,
                              uint8_t *enc_hdr, size_t *enc_hdr_len) {
    uint8_t ml_pk[1184], x_pk[32];
    if (read_pubkey(pubkeyfile, ml_pk, x_pk) != 0) return -1;

    /* ML-KEM-768 encapsulation */
    uint8_t ml_ct[1088], ml_ss[32];
    if (zupt_mlkem768_encaps(ml_ct, ml_ss, ml_pk) != 0) return -1;

    /* X25519 ECDH */
    uint8_t eph_sk[32], eph_pk[32], x_ss[32];
    zupt_random_bytes(eph_sk, 32);
    zupt_x25519_base(eph_pk, eph_sk);
    zupt_x25519(x_ss, eph_sk, x_pk);

    /* Hybrid shared secret: XOR then hash with transcript */
    uint8_t hybrid_ikm[32];
    for (int i = 0; i < 32; i++) hybrid_ikm[i] = ml_ss[i] ^ x_ss[i];

    /* archive_key = SHA-256(hybrid_ikm ‖ ml_ct ‖ eph_pk ‖ "ZUPT-HYBRID-v1") */
    /* We need 64 bytes, so use SHA3-512 instead of SHA-256 */
    uint8_t kdf_input[32 + 1088 + 32 + 15];
    memcpy(kdf_input, hybrid_ikm, 32);
    memcpy(kdf_input + 32, ml_ct, 1088);
    memcpy(kdf_input + 32 + 1088, eph_pk, 32);
    memcpy(kdf_input + 32 + 1088 + 32, "ZUPT-HYBRID-v1", 15);

    uint8_t archive_key[64];
    zupt_sha3_512(kdf_input, sizeof(kdf_input), archive_key);

    /* Set up keyring */
    kr->canary_head = ZUPT_CANARY;
    memcpy(kr->enc_key, archive_key, 32);
    memcpy(kr->mac_key, archive_key + 32, 32);
    zupt_random_bytes(kr->base_nonce, ZUPT_NONCE_SIZE);
    kr->iterations = 0;
    kr->active = 1;
    kr->canary_tail = ZUPT_CANARY;

    /* Lock key material in RAM */
    zupt_mlock_keys(kr->enc_key, ZUPT_AES_KEY_SIZE);
    zupt_mlock_keys(kr->mac_key, ZUPT_HMAC_SIZE);

    /* Build encryption header: enc_type(1) + ml_ct(1088) + eph_pk(32) + base_nonce(16) */
    enc_hdr[0] = ZUPT_ENC_PQ_HYBRID;
    memcpy(enc_hdr + 1, ml_ct, 1088);
    memcpy(enc_hdr + 1 + 1088, eph_pk, 32);
    memcpy(enc_hdr + 1 + 1088 + 32, kr->base_nonce, 16);
    *enc_hdr_len = 1 + 1088 + 32 + 16;  /* 1137 bytes */

    /* Wipe all intermediates */
    zupt_secure_wipe(ml_ss, 32);
    zupt_secure_wipe(x_ss, 32);
    zupt_secure_wipe(eph_sk, 32);
    zupt_secure_wipe(hybrid_ikm, 32);
    zupt_secure_wipe(kdf_input, sizeof(kdf_input));
    zupt_secure_wipe(archive_key, 64);

    return 0;
}

/*
 * HYBRID DECRYPT INIT: Decapsulate with ML-KEM + X25519, derive archive keys.
 */
/* FRAMA-C: Hybrid PQ decrypt init — ML-KEM-768 + X25519 decaps */
/*@ requires \valid(kr);
  @ requires \valid_read(privkeyfile);
  @ requires enc_hdr_len >= 1137;
  @ requires \valid_read(enc_hdr + (0..enc_hdr_len-1));
  @ assigns kr->enc_key[0..31], kr->mac_key[0..31], kr->base_nonce[0..15],
  @         kr->iterations, kr->active;
  @ ensures \result == 0 ==> kr->active == 1;
*/
int zupt_hybrid_decrypt_init(zupt_keyring_t *kr, const char *privkeyfile,
                              const uint8_t *enc_hdr, size_t enc_hdr_len) {
    if (enc_hdr_len < 1 + 1088 + 32 + 16) return -1;  /* enc_type + ct + eph_pk + nonce */
    if (enc_hdr[0] != ZUPT_ENC_PQ_HYBRID) return -1;

    const uint8_t *ml_ct  = enc_hdr + 1;
    const uint8_t *eph_pk = enc_hdr + 1 + 1088;
    const uint8_t *nonce  = enc_hdr + 1 + 1088 + 32;

    uint8_t ml_pk[1184], x_pk[32], ml_sk[2400], x_sk[32];
    if (read_privkey(privkeyfile, ml_pk, x_pk, ml_sk, x_sk) != 0) return -1;

    /* ML-KEM-768 decapsulation */
    uint8_t ml_ss[32];
    zupt_mlkem768_decaps(ml_ss, ml_ct, ml_sk);

    /* X25519 ECDH with ephemeral pubkey */
    uint8_t x_ss[32];
    zupt_x25519(x_ss, x_sk, eph_pk);

    /* Same key derivation as encrypt */
    uint8_t hybrid_ikm[32];
    for (int i = 0; i < 32; i++) hybrid_ikm[i] = ml_ss[i] ^ x_ss[i];

    uint8_t kdf_input[32 + 1088 + 32 + 15];
    memcpy(kdf_input, hybrid_ikm, 32);
    memcpy(kdf_input + 32, ml_ct, 1088);
    memcpy(kdf_input + 32 + 1088, eph_pk, 32);
    memcpy(kdf_input + 32 + 1088 + 32, "ZUPT-HYBRID-v1", 15);

    uint8_t archive_key[64];
    zupt_sha3_512(kdf_input, sizeof(kdf_input), archive_key);

    kr->canary_head = ZUPT_CANARY;
    memcpy(kr->enc_key, archive_key, 32);
    memcpy(kr->mac_key, archive_key + 32, 32);
    memcpy(kr->base_nonce, nonce, ZUPT_NONCE_SIZE); /* Read from enc_hdr, NOT random */
    kr->iterations = 0;
    kr->active = 1;
    kr->canary_tail = ZUPT_CANARY;

    /* Lock key material in RAM */
    zupt_mlock_keys(kr->enc_key, ZUPT_AES_KEY_SIZE);
    zupt_mlock_keys(kr->mac_key, ZUPT_HMAC_SIZE);

    zupt_secure_wipe(ml_sk, sizeof(ml_sk));
    zupt_secure_wipe(x_sk, 32);
    zupt_secure_wipe(ml_ss, 32);
    zupt_secure_wipe(x_ss, 32);
    zupt_secure_wipe(hybrid_ikm, 32);
    zupt_secure_wipe(kdf_input, sizeof(kdf_input));
    zupt_secure_wipe(archive_key, 64);

    return 0;
}
