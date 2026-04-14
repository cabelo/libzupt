/*
 * Zupt — Backup-oriented compression with AES-256 encryption
 * Copyright (c) 2026 Cristian Cezar Moisés
 * SPDX-License-Identifier: MIT
 *
 * Keccak-f[1600] permutation with SHA3-256, SHA3-512, SHAKE-128, SHAKE-256.
 * Implements FIPS 202 (SHA-3 Standard).
 * Required by ML-KEM-768 (FIPS 203) for hashing and sampling.
 *
 * FRAMA-C: ACSL-annotated (v2.0.0)
 */
#include "zupt_keccak.h"
#include "zupt_acsl.h"
#include <string.h>

/* ═══════════════════════════════════════════════════════════════════
 * KECCAK-f[1600] ROUND CONSTANTS
 * ═══════════════════════════════════════════════════════════════════ */

static const uint64_t KECCAK_RC[24] = {
    UINT64_C(0x0000000000000001), UINT64_C(0x0000000000008082),
    UINT64_C(0x800000000000808A), UINT64_C(0x8000000080008000),
    UINT64_C(0x000000000000808B), UINT64_C(0x0000000080000001),
    UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008009),
    UINT64_C(0x000000000000008A), UINT64_C(0x0000000000000088),
    UINT64_C(0x0000000080008009), UINT64_C(0x000000008000000A),
    UINT64_C(0x000000008000808B), UINT64_C(0x800000000000008B),
    UINT64_C(0x8000000000008089), UINT64_C(0x8000000000008003),
    UINT64_C(0x8000000000008002), UINT64_C(0x8000000000000080),
    UINT64_C(0x000000000000800A), UINT64_C(0x800000008000000A),
    UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008080),
    UINT64_C(0x0000000080000001), UINT64_C(0x8000000080008008)
};

/* Rotation offsets per FIPS 202 */
static const int KECCAK_ROT[25] = {
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14
};

/* Pi permutation indices */
static const int KECCAK_PI[25] = {
     0, 10, 20,  5, 15,
    16,  1, 11, 21,  6,
     7, 17,  2, 12, 22,
    23,  8, 18,  3, 13,
    14, 24,  9, 19,  4
};

#define ROL64(x, n) ((n) ? (((x) << (n)) | ((x) >> (64 - (n)))) : (x))

/* ═══════════════════════════════════════════════════════════════════
 * KECCAK-f[1600] PERMUTATION (24 rounds)
 * ═══════════════════════════════════════════════════════════════════ */

static void keccakf(uint64_t st[25]) {
    for (int round = 0; round < 24; round++) {
        uint64_t bc[5], t;

        /* θ (theta) */
        for (int i = 0; i < 5; i++)
            bc[i] = st[i] ^ st[i+5] ^ st[i+10] ^ st[i+15] ^ st[i+20];
        for (int i = 0; i < 5; i++) {
            t = bc[(i+4)%5] ^ ROL64(bc[(i+1)%5], 1);
            for (int j = 0; j < 25; j += 5) st[j+i] ^= t;
        }

        /* ρ (rho) + π (pi) */
        uint64_t tmp[25];
        for (int i = 0; i < 25; i++)
            tmp[KECCAK_PI[i]] = ROL64(st[i], KECCAK_ROT[i]);

        /* χ (chi) */
        for (int j = 0; j < 25; j += 5)
            for (int i = 0; i < 5; i++)
                st[j+i] = tmp[j+i] ^ ((~tmp[j+(i+1)%5]) & tmp[j+(i+2)%5]);

        /* ι (iota) */
        st[0] ^= KECCAK_RC[round];
    }
}

/* ═══════════════════════════════════════════════════════════════════
 * SPONGE CONSTRUCTION
 * ═══════════════════════════════════════════════════════════════════ */

static void keccak_init(zupt_keccak_ctx *ctx, size_t rate, uint8_t dsuf) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->rate = rate;
    ctx->dsuf = dsuf;
}

static void keccak_absorb(zupt_keccak_ctx *ctx, const uint8_t *data, size_t len) {
    size_t i = 0;
    while (i < len) {
        size_t avail = ctx->rate - ctx->pt;
        size_t chunk = (len - i) < avail ? (len - i) : avail;
        for (size_t j = 0; j < chunk; j++)
            ctx->buf[ctx->pt + j] = data[i + j];
        ctx->pt += chunk;
        i += chunk;
        if (ctx->pt == ctx->rate) {
            /* XOR buffer into state (little-endian lanes) */
            for (size_t k = 0; k < ctx->rate / 8; k++) {
                uint64_t lane = 0;
                for (int b = 7; b >= 0; b--)
                    lane = (lane << 8) | ctx->buf[k*8 + b];
                ctx->st[k] ^= lane;
            }
            keccakf(ctx->st);
            ctx->pt = 0;
        }
    }
}

static void keccak_finalize(zupt_keccak_ctx *ctx) {
    /* Pad: domain suffix + 10*1 padding */
    ctx->buf[ctx->pt] = ctx->dsuf;
    memset(ctx->buf + ctx->pt + 1, 0, ctx->rate - ctx->pt - 1);
    ctx->buf[ctx->rate - 1] |= 0x80;
    /* XOR final block into state */
    for (size_t k = 0; k < ctx->rate / 8; k++) {
        uint64_t lane = 0;
        for (int b = 7; b >= 0; b--)
            lane = (lane << 8) | ctx->buf[k*8 + b];
        ctx->st[k] ^= lane;
    }
    keccakf(ctx->st);
    ctx->pt = 0;
}

static void keccak_squeeze(zupt_keccak_ctx *ctx, uint8_t *out, size_t len) {
    size_t i = 0;
    while (i < len) {
        if (ctx->pt == ctx->rate) {
            keccakf(ctx->st);
            ctx->pt = 0;
        }
        /* Extract bytes from state (little-endian) */
        size_t avail = ctx->rate - ctx->pt;
        size_t chunk = (len - i) < avail ? (len - i) : avail;
        for (size_t j = 0; j < chunk; j++) {
            size_t byte_idx = ctx->pt + j;
            out[i + j] = (uint8_t)(ctx->st[byte_idx / 8] >> (8 * (byte_idx % 8)));
        }
        ctx->pt += chunk;
        i += chunk;
    }
}

/* ═══════════════════════════════════════════════════════════════════
 * SHA3-256: rate=136 bytes (1088 bits), capacity=512 bits
 * ═══════════════════════════════════════════════════════════════════ */

/* FRAMA-C: SHA3-256 one-shot hash */
/*@ requires \valid_read(data + (0..len-1));
  @ requires \valid(out + (0..31));
  @ requires \separated(data + (0..len-1), out + (0..31));
  @ assigns out[0..31];
  @ ensures \initialized(out + (0..31));
*/
void zupt_sha3_256(const uint8_t *data, size_t len, uint8_t out[32]) {
    zupt_keccak_ctx ctx;
    keccak_init(&ctx, 136, 0x06); /* SHA3 domain suffix */
    keccak_absorb(&ctx, data, len);
    keccak_finalize(&ctx);
    keccak_squeeze(&ctx, out, 32);
}

/* ═══════════════════════════════════════════════════════════════════
 * SHA3-512: rate=72 bytes (576 bits), capacity=1024 bits
 * ═══════════════════════════════════════════════════════════════════ */

/* FRAMA-C: SHA3-512 one-shot hash */
/*@ requires \valid_read(data + (0..len-1));
  @ requires \valid(out + (0..63));
  @ requires \separated(data + (0..len-1), out + (0..63));
  @ assigns out[0..63];
  @ ensures \initialized(out + (0..63));
*/
void zupt_sha3_512(const uint8_t *data, size_t len, uint8_t out[64]) {
    zupt_keccak_ctx ctx;
    keccak_init(&ctx, 72, 0x06);
    keccak_absorb(&ctx, data, len);
    keccak_finalize(&ctx);
    keccak_squeeze(&ctx, out, 64);
}

/* ═══════════════════════════════════════════════════════════════════
 * SHAKE-128: rate=168 bytes (1344 bits)
 * ═══════════════════════════════════════════════════════════════════ */

/* FRAMA-C: SHAKE-128 extendable output function */
/*@ requires \valid_read(data + (0..dlen-1));
  @ requires \valid(out + (0..olen-1));
  @ requires \separated(data + (0..dlen-1), out + (0..olen-1));
  @ assigns out[0..olen-1];
  @ ensures \initialized(out + (0..olen-1));
*/
void zupt_shake128(const uint8_t *data, size_t dlen, uint8_t *out, size_t olen) {
    zupt_keccak_ctx ctx;
    keccak_init(&ctx, 168, 0x1F); /* SHAKE domain suffix */
    keccak_absorb(&ctx, data, dlen);
    keccak_finalize(&ctx);
    keccak_squeeze(&ctx, out, olen);
}

void zupt_shake128_init(zupt_keccak_ctx *ctx)    { keccak_init(ctx, 168, 0x1F); }
void zupt_shake128_absorb(zupt_keccak_ctx *ctx, const uint8_t *data, size_t len) {
    keccak_absorb(ctx, data, len);
}
void zupt_shake128_finalize(zupt_keccak_ctx *ctx) { keccak_finalize(ctx); }
void zupt_shake128_squeeze(zupt_keccak_ctx *ctx, uint8_t *out, size_t len) {
    keccak_squeeze(ctx, out, len);
}

/* ═══════════════════════════════════════════════════════════════════
 * SHAKE-256: rate=136 bytes (1088 bits)
 * ═══════════════════════════════════════════════════════════════════ */

/* FRAMA-C: SHAKE-256 extendable output function */
/*@ requires \valid_read(data + (0..dlen-1));
  @ requires \valid(out + (0..olen-1));
  @ requires \separated(data + (0..dlen-1), out + (0..olen-1));
  @ assigns out[0..olen-1];
  @ ensures \initialized(out + (0..olen-1));
*/
void zupt_shake256(const uint8_t *data, size_t dlen, uint8_t *out, size_t olen) {
    zupt_keccak_ctx ctx;
    keccak_init(&ctx, 136, 0x1F);
    keccak_absorb(&ctx, data, dlen);
    keccak_finalize(&ctx);
    keccak_squeeze(&ctx, out, olen);
}

void zupt_shake256_init(zupt_keccak_ctx *ctx)    { keccak_init(ctx, 136, 0x1F); }
void zupt_shake256_absorb(zupt_keccak_ctx *ctx, const uint8_t *data, size_t len) {
    keccak_absorb(ctx, data, len);
}
void zupt_shake256_finalize(zupt_keccak_ctx *ctx) { keccak_finalize(ctx); }
void zupt_shake256_squeeze(zupt_keccak_ctx *ctx, uint8_t *out, size_t len) {
    keccak_squeeze(ctx, out, len);
}
