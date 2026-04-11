/*
 * Zupt — Backup-oriented compression with AES-256 encryption
 * Copyright (c) 2026 Cristian Cezar Moisés
 * SPDX-License-Identifier: MIT
 *
 * Keccak-f[1600] sponge: SHA3-256, SHA3-512, SHAKE-128, SHAKE-256
 * Required by ML-KEM-768 (FIPS 203).
 * Pure C11, zero dependencies, no dynamic allocation.
 */
#ifndef ZUPT_KECCAK_H
#define ZUPT_KECCAK_H

#include <stdint.h>
#include <stddef.h>

/* Sponge state: 25 × 64-bit lanes = 200 bytes */
typedef struct {
    uint64_t st[25];
    uint8_t  buf[200]; /* absorption buffer */
    size_t   rate;     /* rate in bytes */
    size_t   pt;       /* position in buf */
    uint8_t  dsuf;     /* domain suffix: 0x06 for SHA3, 0x1F for SHAKE */
} zupt_keccak_ctx;

/* SHA3-256: 32-byte output */
void zupt_sha3_256(const uint8_t *data, size_t len, uint8_t out[32]);

/* SHA3-512: 64-byte output */
void zupt_sha3_512(const uint8_t *data, size_t len, uint8_t out[64]);

/* SHAKE-128: extendable output */
void zupt_shake128(const uint8_t *data, size_t dlen, uint8_t *out, size_t olen);

/* SHAKE-256: extendable output */
void zupt_shake256(const uint8_t *data, size_t dlen, uint8_t *out, size_t olen);

/* Incremental SHAKE-128 for ML-KEM sampling */
void zupt_shake128_init(zupt_keccak_ctx *ctx);
void zupt_shake128_absorb(zupt_keccak_ctx *ctx, const uint8_t *data, size_t len);
void zupt_shake128_finalize(zupt_keccak_ctx *ctx);
void zupt_shake128_squeeze(zupt_keccak_ctx *ctx, uint8_t *out, size_t len);

/* Incremental SHAKE-256 */
void zupt_shake256_init(zupt_keccak_ctx *ctx);
void zupt_shake256_absorb(zupt_keccak_ctx *ctx, const uint8_t *data, size_t len);
void zupt_shake256_finalize(zupt_keccak_ctx *ctx);
void zupt_shake256_squeeze(zupt_keccak_ctx *ctx, uint8_t *out, size_t len);

#endif
