/*
 * Zupt — Backup-oriented compression with AES-256 encryption
 * Copyright (c) 2026 Cristian Cezar Moisés
 * SPDX-License-Identifier: MIT
 *
 * ML-KEM-768 (FIPS 203, formerly CRYSTALS-Kyber).
 * Pure C11, zero dependencies. Uses zupt_keccak.h for SHA3/SHAKE.
 *
 * SECURITY NOTE: This implementation targets correctness against FIPS 203
 * and constant-time operation. It MUST undergo independent cryptographic
 * review before use in high-assurance production environments.
 *
 * CT-REQUIRED markers indicate operations that must be constant-time.
 * All polynomial operations avoid secret-dependent branches.
 * Implicit rejection in decaps uses constant-time conditional select.
 */
#define _GNU_SOURCE
#include "zupt_mlkem.h"
#include "zupt_keccak.h"
#include "zupt.h" /* for zupt_random_bytes, zupt_secure_wipe */
#include "zupt_jasmin.h"
#include <string.h>

/* ═══════════════════════════════════════════════════════════════════
 * MODULAR ARITHMETIC
 * q = 3329, using Barrett reduction for constant-time mod.
 * ═══════════════════════════════════════════════════════════════════ */

#define Q 3329
#define QINV (-3327) /* q^(-1) mod 2^16 (signed) = 62209 unsigned */

/* CT-REQUIRED: Barrett reduction. No branches. */
static int16_t barrett_reduce(int16_t a) {
    /* v = round(2^26 / q) = 20159 */
    int16_t t = (int16_t)(((int32_t)20159 * a + (1 << 25)) >> 26);
    t = (int16_t)(a - t * Q);
    return t;
}

/* CT-REQUIRED: Montgomery reduction. */
static int16_t montgomery_reduce(int32_t a) {
    int16_t t = (int16_t)((int16_t)a * (int16_t)QINV);
    t = (int16_t)((a - (int32_t)t * Q) >> 16);
    return t;
}

/* CT-REQUIRED: Constant-time conditional move (no branch on b) */
#ifndef ZUPT_USE_JASMIN
static void cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b) {
    uint8_t mask = -(uint8_t)(b & 1);
    for (size_t i = 0; i < len; i++)
        r[i] ^= mask & (r[i] ^ x[i]);
}
#endif

/* ═══════════════════════════════════════════════════════════════════
 * NTT — Number Theoretic Transform
 *
 * ζ = 17 is a primitive 256th root of unity mod 3329.
 * Zetas in Montgomery domain, bit-reversed order per FIPS 203.
 * ═══════════════════════════════════════════════════════════════════ */

/* Precomputed zetas[i] = 17^(BitRev7(i)) * R mod q, where R = 2^16 mod q
 * These are in signed representation [-q/2, q/2] */
static const int16_t zetas[128] = {
  -1044,  -758,  -359, -1517,  1493,  1422,   287,   202,
   3158,   622,  1577,   182,   962,  2127,  1855,  1468,
    573,  2004,   264,   383,  2500,  1458,  1727,  3199,
   2648,  1017,   732,   608,  1787,   411,  3124,  1758,
   1223,   652,  2777,  1015,  2036,  1491,  3047,  1785,
    516,  3321,  3009,  2663,  1711,  2167,   126,  1469,
   2476,  3239,  3058,   830,   107,  1908,  3082,  2378,
   2931,   961,  1821,  2604,   448,  2264,   677,  2054,
   2226,   430,   555,   843,  2078,   871,  1550,   105,
    422,   587,   177,  3094,  3038,  2869,  1574,  1653,
   3083,   778,  1159,  3182,  2552,  1483,  2727,  1119,
   1739,   644,  2457,   349,   418,   329,  3173,  3254,
    817,  1097,   603,   610,  1322,  2044,  1864,   384,
   2114,  3193,  1218,  1994,  2455,   220,  2142,  1670,
   2144,  1799,  2051,   794,  1819,  2475,  2459,   478,
   3221,  3021,   996,   991,   958,  1869,  1522,  1628
};

/* CT-REQUIRED: NTT — no secret-dependent array indices */
static void ntt(int16_t r[256]) {
    int k = 1;
    for (int len = 128; len >= 2; len >>= 1) {
        for (int start = 0; start < 256; start += 2*len) {
            int16_t zeta = zetas[k++];
            for (int j = start; j < start + len; j++) {
                int16_t t = montgomery_reduce((int32_t)zeta * r[j + len]);
                r[j + len] = r[j] - t;
                r[j] = r[j] + t;
            }
        }
    }
}

/* Inverse NTT per reference pqcrystals/kyber — uses SAME zetas table, k counts down.
 * Final scaling by f = 1441 (mont^{-1} * n^{-1} mod q). */
static void inv_ntt(int16_t r[256]) {
    int k = 127;
    for (int len = 2; len <= 128; len <<= 1) {
        for (int start = 0; start < 256; start += 2*len) {
            int16_t zeta = zetas[k--];
            for (int j = start; j < start + len; j++) {
                int16_t t = r[j];
                r[j] = barrett_reduce(t + r[j + len]);
                r[j + len] = montgomery_reduce((int32_t)zeta * (r[j + len] - t));
            }
        }
    }
    /* Multiply by f = 1441 = mont^{-1} * 128^{-1} mod q */
    for (int i = 0; i < 256; i++)
        r[i] = montgomery_reduce((int32_t)1441 * r[i]);
}

/* ═══════════════════════════════════════════════════════════════════
 * POLYNOMIAL OPERATIONS
 * ═══════════════════════════════════════════════════════════════════ */

typedef int16_t poly[256];
typedef poly polyvec[MLKEM_K];

/* Pointwise multiply in NTT domain (basemul per FIPS 203 §4.4)
 * CT-REQUIRED: No secret-dependent branches.
 * Reference: pqcrystals/kyber basemul — each fqmul is a separate montgomery_reduce.
 * r[0] = fqmul(fqmul(a1,b1), zeta) + fqmul(a0,b0)
 * r[1] = fqmul(a0,b1) + fqmul(a1,b0)
 * Second pair uses -zeta. */
static void basemul_pair(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta) {
    r[0] = montgomery_reduce((int32_t)montgomery_reduce((int32_t)a[1] * b[1]) * zeta);
    r[0] = (int16_t)(r[0] + montgomery_reduce((int32_t)a[0] * b[0]));
    r[1] = montgomery_reduce((int32_t)a[0] * b[1]);
    r[1] = (int16_t)(r[1] + montgomery_reduce((int32_t)a[1] * b[0]));
}

static void poly_basemul(poly r, const poly a, const poly b) {
    for (int i = 0; i < 64; i++) {
        basemul_pair(&r[4*i],   &a[4*i],   &b[4*i],    zetas[64 + i]);
        basemul_pair(&r[4*i+2], &a[4*i+2], &b[4*i+2], (int16_t)(-zetas[64 + i]));
    }
}

static void poly_add(poly r, const poly a, const poly b) {
    for (int i = 0; i < 256; i++) r[i] = a[i] + b[i];
}
static void poly_sub(poly r, const poly a, const poly b) {
    for (int i = 0; i < 256; i++) r[i] = a[i] - b[i];
}
static void poly_reduce(poly r) {
    for (int i = 0; i < 256; i++) r[i] = barrett_reduce(r[i]);
}

/* Convert polynomial to Montgomery domain: multiply each coeff by R = 2^16 mod Q.
 * Reference: pqcrystals/kyber poly_tomont(). Required after basemul accumulation
 * to compensate for the R^{-1} factor introduced by Montgomery multiplication.
 * f = 2^32 mod Q = 1353, then mont(coeff * f) = coeff * 2^32 / 2^16 = coeff * R */
#define TOMONT_CONST 1353  /* 2^32 mod 3329 — verified: 4294967296 mod 3329 = 1353 */
static void poly_tomont(poly r) {
    for (int i = 0; i < 256; i++)
        r[i] = montgomery_reduce((int32_t)r[i] * TOMONT_CONST);
}

/* Polyvec inner product in NTT domain */
static void polyvec_ntt(polyvec pv) {
    for (int i = 0; i < MLKEM_K; i++) ntt(pv[i]);
}
static void polyvec_invntt(polyvec pv) {
    for (int i = 0; i < MLKEM_K; i++) inv_ntt(pv[i]);
}

/* C11 §6.7.3: arrays-of-arrays cannot undergo multi-level const conversion.
 * Reference pqcrystals/kyber uses non-const polyvec parameters for the same reason.
 * These functions do not modify the input arrays. */
static void polyvec_pointwise_acc(poly r, polyvec a, polyvec b) {
    poly t;
    poly_basemul(r, a[0], b[0]);
    for (int i = 1; i < MLKEM_K; i++) {
        poly_basemul(t, a[i], b[i]);
        poly_add(r, r, t);
    }
    poly_reduce(r);
}

/* ═══════════════════════════════════════════════════════════════════
 * SAMPLING
 * ═══════════════════════════════════════════════════════════════════ */

/* CBD(η=2): sample polynomial from centered binomial distribution */
static void cbd2(poly r, const uint8_t buf[128]) {
    for (int i = 0; i < 256/8; i++) {
        uint32_t t = (uint32_t)buf[4*i] | ((uint32_t)buf[4*i+1] << 8) |
                     ((uint32_t)buf[4*i+2] << 16) | ((uint32_t)buf[4*i+3] << 24);
        uint32_t d = (t & 0x55555555) + ((t >> 1) & 0x55555555);
        for (int j = 0; j < 8; j++) {
            int16_t a = (int16_t)((d >> (4*j)) & 3);
            int16_t b = (int16_t)((d >> (4*j+2)) & 3);
            r[8*i+j] = a - b;
        }
    }
}

/* Sample polynomial uniformly from SHAKE-128 stream (rejection sampling) */
static void poly_uniform(poly r, const uint8_t seed[32], uint8_t i, uint8_t j) {
    uint8_t extseed[34];
    memcpy(extseed, seed, 32);
    extseed[32] = i;
    extseed[33] = j;

    zupt_keccak_ctx ctx;
    zupt_shake128_init(&ctx);
    zupt_shake128_absorb(&ctx, extseed, 34);
    zupt_shake128_finalize(&ctx);

    int ctr = 0;
    while (ctr < 256) {
        uint8_t buf[3];
        zupt_shake128_squeeze(&ctx, buf, 3);
        uint16_t d1 = ((uint16_t)buf[0] | ((uint16_t)(buf[1] & 0x0F) << 8));
        uint16_t d2 = ((uint16_t)(buf[1] >> 4) | ((uint16_t)buf[2] << 4));
        if (d1 < Q) r[ctr++] = (int16_t)d1;
        if (ctr < 256 && d2 < Q) r[ctr++] = (int16_t)d2;
    }
}

/* Sample noise polynomial via PRF (SHAKE-256) + CBD */
static void poly_noise(poly r, const uint8_t seed[32], uint8_t nonce) {
    uint8_t extseed[33];
    memcpy(extseed, seed, 32);
    extseed[32] = nonce;
    uint8_t buf[128]; /* η*N/4 = 2*256/4 = 128 */
    zupt_shake256(extseed, 33, buf, 128);
    cbd2(r, buf);
}

/* ═══════════════════════════════════════════════════════════════════
 * ENCODE / DECODE
 * ═══════════════════════════════════════════════════════════════════ */

/* Encode polynomial with d bits per coefficient */
static void poly_tobytes(uint8_t *r, const poly a) {
    /* 12 bits per coefficient, 256 coeffs = 384 bytes */
    for (int i = 0; i < 256/2; i++) {
        uint16_t t0 = (uint16_t)((a[2*i] % Q + Q) % Q);
        uint16_t t1 = (uint16_t)((a[2*i+1] % Q + Q) % Q);
        r[3*i]   = (uint8_t)(t0);
        r[3*i+1] = (uint8_t)((t0 >> 8) | (t1 << 4));
        r[3*i+2] = (uint8_t)(t1 >> 4);
    }
}

static void poly_frombytes(poly r, const uint8_t *a) {
    for (int i = 0; i < 256/2; i++) {
        r[2*i]   = (int16_t)(((uint16_t)a[3*i] | ((uint16_t)(a[3*i+1] & 0x0F) << 8)));
        r[2*i+1] = (int16_t)(((uint16_t)(a[3*i+1] >> 4) | ((uint16_t)a[3*i+2] << 4)));
    }
}

/* Compress: round(2^d / q * x) mod 2^d */
static void poly_compress(uint8_t *r, const poly a, int d) {
    if (d == 10) {
        /* 10 bits per coeff, 256 coeffs = 320 bytes */
        for (int i = 0; i < 256/4; i++) {
            uint16_t t[4];
            for (int j = 0; j < 4; j++) {
                int16_t x = a[4*i+j];
                x = (int16_t)((x % Q + Q) % Q);
                t[j] = (uint16_t)(((uint32_t)x * (1 << d) + Q/2) / Q);
                t[j] &= (1 << d) - 1;
            }
            r[5*i]   = (uint8_t)(t[0]);
            r[5*i+1] = (uint8_t)((t[0] >> 8) | (t[1] << 2));
            r[5*i+2] = (uint8_t)((t[1] >> 6) | (t[2] << 4));
            r[5*i+3] = (uint8_t)((t[2] >> 4) | (t[3] << 6));
            r[5*i+4] = (uint8_t)(t[3] >> 2);
        }
    } else if (d == 4) {
        /* 4 bits per coeff = 128 bytes */
        for (int i = 0; i < 256/2; i++) {
            uint8_t t0, t1;
            int16_t x0 = (int16_t)((a[2*i] % Q + Q) % Q);
            int16_t x1 = (int16_t)((a[2*i+1] % Q + Q) % Q);
            t0 = (uint8_t)(((uint32_t)x0 * 16 + Q/2) / Q) & 0xF;
            t1 = (uint8_t)(((uint32_t)x1 * 16 + Q/2) / Q) & 0xF;
            r[i] = t0 | (t1 << 4);
        }
    }
}

static void poly_decompress(poly r, const uint8_t *a, int d) {
    if (d == 10) {
        for (int i = 0; i < 256/4; i++) {
            uint16_t t[4];
            t[0] = ((uint16_t)a[5*i] | ((uint16_t)(a[5*i+1] & 3) << 8));
            t[1] = ((uint16_t)(a[5*i+1] >> 2) | ((uint16_t)(a[5*i+2] & 0xF) << 6));
            t[2] = ((uint16_t)(a[5*i+2] >> 4) | ((uint16_t)(a[5*i+3] & 0x3F) << 4));
            t[3] = ((uint16_t)(a[5*i+3] >> 6) | ((uint16_t)a[5*i+4] << 2));
            for (int j = 0; j < 4; j++)
                r[4*i+j] = (int16_t)(((uint32_t)(t[j] & 0x3FF) * Q + 512) >> 10);
        }
    } else if (d == 4) {
        for (int i = 0; i < 256/2; i++) {
            r[2*i]   = (int16_t)(((uint32_t)(a[i] & 0xF) * Q + 8) >> 4);
            r[2*i+1] = (int16_t)(((uint32_t)(a[i] >> 4) * Q + 8) >> 4);
        }
    }
}

/* Polyvec encode/decode (12 bits per coeff) */
static void polyvec_tobytes(uint8_t *r, polyvec a) {
    for (int i = 0; i < MLKEM_K; i++) poly_tobytes(r + i*384, a[i]);
}
static void polyvec_frombytes(polyvec r, const uint8_t *a) {
    for (int i = 0; i < MLKEM_K; i++) poly_frombytes(r[i], a + i*384);
}
static void polyvec_compress(uint8_t *r, polyvec a) {
    for (int i = 0; i < MLKEM_K; i++) poly_compress(r + i*320, a[i], MLKEM_DU);
}
static void polyvec_decompress(polyvec r, const uint8_t *a) {
    for (int i = 0; i < MLKEM_K; i++) poly_decompress(r[i], a + i*320, MLKEM_DU);
}

/* ═══════════════════════════════════════════════════════════════════
 * K-PKE: IND-CPA-secure public key encryption (FIPS 203 §7.2-7.3)
 * ═══════════════════════════════════════════════════════════════════ */

/* Generate K-PKE keypair. d = random 32-byte seed. */
static void kpke_keygen(uint8_t pk[1184], uint8_t sk_pke[1152], const uint8_t d[32]) {
    uint8_t buf[64];
    /* G(d ‖ k) */
    uint8_t dk[33];
    memcpy(dk, d, 32);
    dk[32] = MLKEM_K;
    zupt_sha3_512(dk, 33, buf);
    uint8_t *rho = buf;      /* 32 bytes: public seed */
    uint8_t *sigma = buf+32; /* 32 bytes: noise seed */

    /* Generate matrix A (in NTT domain) from rho */
    polyvec Ahat[MLKEM_K];
    for (int i = 0; i < MLKEM_K; i++)
        for (int j = 0; j < MLKEM_K; j++)
            poly_uniform(Ahat[i][j], rho, (uint8_t)i, (uint8_t)j);

    /* Sample secret vector s */
    polyvec s;
    uint8_t nonce = 0;
    for (int i = 0; i < MLKEM_K; i++)
        poly_noise(s[i], sigma, nonce++);

    /* Sample error vector e */
    polyvec e;
    for (int i = 0; i < MLKEM_K; i++)
        poly_noise(e[i], sigma, nonce++);

    /* NTT(s), NTT(e) */
    polyvec_ntt(s);
    polyvec_ntt(e);

    /* t_hat = A_hat ∘ s_hat + e_hat
     * ZUPT-COMPAT: poly_tomont after basemul compensates for R^{-1} factor
     * from Montgomery multiplication, matching reference pqcrystals/kyber. */
    polyvec t_hat;
    for (int i = 0; i < MLKEM_K; i++) {
        polyvec_pointwise_acc(t_hat[i], Ahat[i], s);
        poly_tomont(t_hat[i]);
        poly_add(t_hat[i], t_hat[i], e[i]);
        poly_reduce(t_hat[i]);
    }

    /* pk = encode(t_hat) ‖ rho */
    polyvec_tobytes(pk, t_hat);
    memcpy(pk + MLKEM_K*384, rho, 32);

    /* sk_pke = encode(s_hat) */
    polyvec_tobytes(sk_pke, s);

    zupt_secure_wipe(buf, sizeof(buf));
    zupt_secure_wipe(s, sizeof(s));
    zupt_secure_wipe(e, sizeof(e));
}

/* K-PKE encrypt: encrypt message m (32 bytes) under pk with randomness r (32 bytes) */
static void kpke_encrypt(uint8_t ct[1088], const uint8_t pk[1184],
                          const uint8_t m[32], const uint8_t r[32]) {
    /* Decode pk */
    polyvec t_hat;
    polyvec_frombytes(t_hat, pk);
    uint8_t rho[32];
    memcpy(rho, pk + MLKEM_K*384, 32);

    /* Regenerate A^T from rho (transposed) */
    polyvec AT[MLKEM_K];
    for (int i = 0; i < MLKEM_K; i++)
        for (int j = 0; j < MLKEM_K; j++)
            poly_uniform(AT[i][j], rho, (uint8_t)j, (uint8_t)i);

    /* Sample r_vec, e1, e2 */
    polyvec r_vec;
    uint8_t nonce = 0;
    for (int i = 0; i < MLKEM_K; i++)
        poly_noise(r_vec[i], r, nonce++);

    polyvec e1;
    for (int i = 0; i < MLKEM_K; i++)
        poly_noise(e1[i], r, nonce++);

    poly e2;
    poly_noise(e2, r, nonce);

    polyvec_ntt(r_vec);

    /* u = NTT^-1(A^T ∘ r_hat) + e1 */
    polyvec u;
    for (int i = 0; i < MLKEM_K; i++) {
        polyvec_pointwise_acc(u[i], AT[i], r_vec);
    }
    polyvec_invntt(u);
    for (int i = 0; i < MLKEM_K; i++) poly_add(u[i], u[i], e1[i]);

    /* v = NTT^-1(t_hat^T ∘ r_hat) + e2 + Decompress(m, 1) */
    poly v;
    polyvec_pointwise_acc(v, t_hat, r_vec);
    inv_ntt(v);
    poly_add(v, v, e2);

    /* Decompress message: each bit → Q/2 or 0 */
    poly mp;
    for (int i = 0; i < 256; i++) {
        mp[i] = (int16_t)(-(int16_t)((m[i/8] >> (i%8)) & 1) & ((Q+1)/2));
    }
    poly_add(v, v, mp);

    /* Compress and encode */
    for (int i = 0; i < MLKEM_K; i++) poly_reduce(u[i]);
    poly_reduce(v);
    polyvec_compress(ct, u);
    poly_compress(ct + MLKEM_K*320, v, MLKEM_DV);

    zupt_secure_wipe(r_vec, sizeof(r_vec));
    zupt_secure_wipe(e1, sizeof(e1));
    zupt_secure_wipe(&e2, sizeof(e2));
}

/* K-PKE decrypt */
static void kpke_decrypt(uint8_t m[32], const uint8_t ct[1088],
                          const uint8_t sk_pke[1152]) {
    polyvec u;
    polyvec_decompress(u, ct);

    poly v;
    poly_decompress(v, ct + MLKEM_K*320, MLKEM_DV);

    polyvec s_hat;
    polyvec_frombytes(s_hat, sk_pke);

    polyvec_ntt(u);
    poly w;
    polyvec_pointwise_acc(w, s_hat, u);
    inv_ntt(w);
    poly_sub(w, v, w);
    poly_reduce(w);

    /* Compress to 1 bit per coefficient → message */
    memset(m, 0, 32);
    for (int i = 0; i < 256; i++) {
        int16_t x = (int16_t)((w[i] % Q + Q) % Q);
        /* Round: closest to 0 or Q/2? */
        uint16_t t = (uint16_t)(((uint32_t)x * 2 + Q/2) / Q) & 1;
        m[i/8] |= (uint8_t)(t << (i%8));
    }

    zupt_secure_wipe(s_hat, sizeof(s_hat));
}

/* ═══════════════════════════════════════════════════════════════════
 * ML-KEM-768 CCAKEM (FIPS 203 §7.1, §7.4)
 * Fujisaki-Okamoto transform for CCA security.
 * ═══════════════════════════════════════════════════════════════════ */

int zupt_mlkem768_keygen(uint8_t pk[1184], uint8_t sk[2400]) {
    /* d ← random 32 bytes */
    uint8_t d[32];
    zupt_random_bytes(d, 32);

    /* z ← random 32 bytes (for implicit rejection) */
    uint8_t z[32];
    zupt_random_bytes(z, 32);

    /* Generate K-PKE keypair */
    uint8_t sk_pke[1152];
    kpke_keygen(pk, sk_pke, d);

    /* sk = sk_pke ‖ pk ‖ H(pk) ‖ z */
    memcpy(sk, sk_pke, 1152);
    memcpy(sk + 1152, pk, 1184);
    zupt_sha3_256(pk, 1184, sk + 1152 + 1184); /* H(pk) */
    memcpy(sk + 1152 + 1184 + 32, z, 32);

    zupt_secure_wipe(d, 32);
    zupt_secure_wipe(z, 32);
    zupt_secure_wipe(sk_pke, sizeof(sk_pke));
    return 0;
}

int zupt_mlkem768_encaps(uint8_t ct[1088], uint8_t ss[32],
                          const uint8_t pk[1184]) {
    /* m ← random 32 bytes */
    uint8_t m[32];
    zupt_random_bytes(m, 32);

    /* (K, r) = G(m ‖ H(pk)) */
    uint8_t h_pk[32];
    zupt_sha3_256(pk, 1184, h_pk);

    uint8_t kr_input[64];
    memcpy(kr_input, m, 32);
    memcpy(kr_input + 32, h_pk, 32);
    uint8_t kr[64];
    zupt_sha3_512(kr_input, 64, kr);

    /* Encrypt m under pk with randomness r */
    kpke_encrypt(ct, pk, m, kr + 32);

    /* K = KDF(kr[0:32] ‖ H(ct)) */
    uint8_t h_ct[32];
    zupt_sha3_256(ct, 1088, h_ct);
    uint8_t kdf_in[64];
    memcpy(kdf_in, kr, 32);
    memcpy(kdf_in + 32, h_ct, 32);
    zupt_shake256(kdf_in, 64, ss, 32);

    zupt_secure_wipe(m, 32);
    zupt_secure_wipe(kr, 64);
    zupt_secure_wipe(kr_input, 64);
    zupt_secure_wipe(kdf_in, 64);
    return 0;
}

/* CT-REQUIRED: Implicit rejection — if ciphertext is invalid, produce
 * pseudorandom ss from z (no distinguishable failure). Both paths execute
 * fully; final selection uses constant-time conditional move. */
int zupt_mlkem768_decaps(uint8_t ss[32], const uint8_t ct[1088],
                          const uint8_t sk[2400]) {
    /* Parse sk = sk_pke ‖ pk ‖ h ‖ z */
    const uint8_t *sk_pke = sk;
    const uint8_t *pk     = sk + 1152;
    const uint8_t *h      = sk + 1152 + 1184;
    const uint8_t *z      = sk + 1152 + 1184 + 32;

    /* Decrypt to get m' */
    uint8_t m_prime[32];
    kpke_decrypt(m_prime, ct, sk_pke);

    /* (K', r') = G(m' ‖ h) */
    uint8_t kr_input[64];
    memcpy(kr_input, m_prime, 32);
    memcpy(kr_input + 32, h, 32);
    uint8_t kr[64];
    zupt_sha3_512(kr_input, 64, kr);

    /* Re-encrypt: ct' = Encrypt(pk, m', r') */
    uint8_t ct_prime[1088];
    kpke_encrypt(ct_prime, pk, m_prime, kr + 32);

    /* CT-REQUIRED: Compare ct and ct' in constant time */
    uint8_t diff = 0;
    for (int i = 0; i < 1088; i++)
        diff |= ct[i] ^ ct_prime[i];

    /* Compute success key: K = KDF(kr[0:32] ‖ H(ct)) */
    uint8_t h_ct[32];
    zupt_sha3_256(ct, 1088, h_ct);

    uint8_t kdf_success[64];
    memcpy(kdf_success, kr, 32);
    memcpy(kdf_success + 32, h_ct, 32);
    uint8_t ss_success[32];
    zupt_shake256(kdf_success, 64, ss_success, 32);

    /* Compute rejection key: K_bar = KDF(z ‖ H(ct)) */
    uint8_t kdf_reject[64];
    memcpy(kdf_reject, z, 32);
    memcpy(kdf_reject + 32, h_ct, 32);
    uint8_t ss_reject[32];
    zupt_shake256(kdf_reject, 64, ss_reject, 32);

    /* CT-REQUIRED: Select success or reject key without branching.
     * If diff == 0 (ct matches): use ss_success.
     * If diff != 0 (ct differs): use ss_reject (implicit rejection).
     *
     * Convert diff (0 or nonzero) to fail (0 or 1) using constant-time
     * bit trick: fail = ((-(uint64_t)diff) >> 63) & 1 */
    uint8_t fail = (uint8_t)(((-(int64_t)(uint64_t)diff) >> 63) & 1);
#ifdef ZUPT_USE_JASMIN
    /* JASMIN-VERIFIED: CT select — proven by Jasmin type system.
     * fail=0 → ss_success, fail=1 → ss_reject */
    zupt_ct_select_32(ss, ss_success, ss_reject, (uint64_t)fail);
#else
    memcpy(ss, ss_reject, 32);
    cmov(ss, ss_success, 32, (uint8_t)(1 - fail));
#endif

    zupt_secure_wipe(m_prime, 32);
    zupt_secure_wipe(kr, 64);
    zupt_secure_wipe(kr_input, 64);
    zupt_secure_wipe(ct_prime, sizeof(ct_prime));
    zupt_secure_wipe(kdf_success, 64);
    zupt_secure_wipe(kdf_reject, 64);
    zupt_secure_wipe(ss_success, 32);
    zupt_secure_wipe(ss_reject, 32);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * SELF-TEST — verify internal operations
 * ═══════════════════════════════════════════════════════════════════ */

int zupt_mlkem768_selftest(void) {
    int ok = 1;

    /* Test 1: NTT roundtrip — ntt then inv_ntt should recover original */
    {
        poly a, b;
        for (int i = 0; i < 256; i++) a[i] = (int16_t)(i * 17 % Q);
        memcpy(b, a, sizeof(a));
        ntt(b);
        inv_ntt(b);
        int ntt_ok = 1;
        for (int i = 0; i < 256; i++) {
            int16_t diff = (int16_t)((b[i] % Q + Q) % Q) - (int16_t)((a[i] % Q + Q) % Q);
            if ((diff % Q + Q) % Q != 0) { ntt_ok = 0; break; }
        }
        if (!ntt_ok) { fprintf(stderr, "  MLKEM selftest: NTT roundtrip FAILED\n"); ok = 0; }
    }

    /* Test 2: K-PKE encrypt/decrypt roundtrip */
    {
        uint8_t d[32], pk[1184], sk_pke[1152];
        zupt_random_bytes(d, 32);
        kpke_keygen(pk, sk_pke, d);

        uint8_t m[32], r[32], ct[1088], m2[32];
        zupt_random_bytes(m, 32);
        zupt_random_bytes(r, 32);
        kpke_encrypt(ct, pk, m, r);
        kpke_decrypt(m2, ct, sk_pke);

        if (memcmp(m, m2, 32) != 0) {
            fprintf(stderr, "  MLKEM selftest: K-PKE roundtrip FAILED\n");
            fprintf(stderr, "    m[0:4]:  %02x%02x%02x%02x\n", m[0],m[1],m[2],m[3]);
            fprintf(stderr, "    m2[0:4]: %02x%02x%02x%02x\n", m2[0],m2[1],m2[2],m2[3]);
            ok = 0;
        }
    }

    /* Test 3: Full KEM encaps/decaps */
    {
        uint8_t pk[1184], sk[2400], ct[1088], ss1[32], ss2[32];
        zupt_mlkem768_keygen(pk, sk);
        zupt_mlkem768_encaps(ct, ss1, pk);
        zupt_mlkem768_decaps(ss2, ct, sk);
        if (memcmp(ss1, ss2, 32) != 0) {
            fprintf(stderr, "  MLKEM selftest: KEM roundtrip FAILED\n");
            ok = 0;
        }
    }

    return ok ? 0 : -1;
}
