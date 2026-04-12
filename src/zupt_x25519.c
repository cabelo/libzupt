/*
 * Zupt — Backup-oriented compression with AES-256 encryption
 * Copyright (c) 2026 Cristian Cezar Moisés
 * SPDX-License-Identifier: MIT
 *
 * X25519 Diffie-Hellman (RFC 7748) over Curve25519.
 * Field: GF(2^255-19), represented as 5 × 51-bit limbs.
 * Montgomery ladder: constant-time by construction (no secret-dependent branches).
 *
 * CT-REQUIRED: Every operation in this file must be constant-time.
 * No branches on secret data. No secret-dependent memory access.
 */
#include "zupt_x25519.h"
#include <string.h>

/* ═══════════════════════════════════════════════════════════════════
 * FIELD ARITHMETIC: GF(2^255 - 19), 5 × 51-bit limbs
 * ═══════════════════════════════════════════════════════════════════ */

typedef uint64_t fe[5]; /* Field element: 5 limbs, each < 2^52 */

/* Load 32 bytes little-endian into field element */
static void fe_frombytes(fe h, const uint8_t s[32]) {
    uint64_t lo = 0;
    for (int i = 0; i < 8; i++) lo |= (uint64_t)s[i] << (8*i);
    h[0] = lo & ((UINT64_C(1) << 51) - 1);

    lo = 0;
    for (int i = 6; i < 14; i++) lo |= (uint64_t)s[i] << (8*(i-6));
    h[1] = (lo >> 3) & ((UINT64_C(1) << 51) - 1);

    lo = 0;
    for (int i = 12; i < 20; i++) lo |= (uint64_t)s[i] << (8*(i-12));
    h[2] = (lo >> 6) & ((UINT64_C(1) << 51) - 1);

    lo = 0;
    for (int i = 19; i < 27; i++) lo |= (uint64_t)s[i] << (8*(i-19));
    h[3] = (lo >> 1) & ((UINT64_C(1) << 51) - 1);

    lo = 0;
    for (int i = 25; i < 32; i++) lo |= (uint64_t)s[i] << (8*(i-25));
    h[4] = (lo >> 4) & ((UINT64_C(1) << 51) - 1);
}

/* Reduce and store field element to 32 bytes little-endian.
 * Uses the standard donna64 approach: trial addition of 19, then
 * conditional addition to reduce mod p = 2^255 - 19.
 * CT-REQUIRED: no branches on field element values. */
static void fe_tobytes(uint8_t s[32], const fe h) {
    uint64_t t[5];
    const uint64_t mask51 = (UINT64_C(1) << 51) - 1;
    for (int i = 0; i < 5; i++) t[i] = h[i];

    /* Two rounds of carry propagation to ensure limbs in [0, 2^51) */
    uint64_t c;
    for (int round = 0; round < 2; round++) {
        for (int i = 0; i < 5; i++) {
            c = t[i] >> 51;
            t[i] &= mask51;
            if (i < 4) t[i+1] += c;
            else t[0] += c * 19;
        }
    }
    /* One more carry from t[0] to t[1] after the wraparound */
    c = t[0] >> 51; t[0] &= mask51; t[1] += c;

    /* Reduce mod p = 2^255 - 19 using trial addition.
     * If t >= p, then t + 19 >= 2^255, and the carry propagates out of t[4].
     * q = 0 if t < p, q = 1 if t >= p. */
    uint64_t q = (t[0] + 19) >> 51;
    q = (t[1] + q) >> 51;
    q = (t[2] + q) >> 51;
    q = (t[3] + q) >> 51;
    q = (t[4] + q) >> 51;  /* q ∈ {0, 1} */

    t[0] += q * 19;
    c = t[0] >> 51; t[0] &= mask51; t[1] += c;
    c = t[1] >> 51; t[1] &= mask51; t[2] += c;
    c = t[2] >> 51; t[2] &= mask51; t[3] += c;
    c = t[3] >> 51; t[3] &= mask51; t[4] += c;
    t[4] &= mask51;  /* Discard overflow past 2^255 */

    /* Pack 5 × 51-bit limbs into 32 bytes (little-endian, 255 bits) */
    uint64_t combined = t[0] | (t[1] << 51);
    for (int i = 0; i < 8; i++) s[i] = (uint8_t)(combined >> (8*i));
    combined = (t[1] >> 13) | (t[2] << 38);
    for (int i = 0; i < 8; i++) s[8+i] = (uint8_t)(combined >> (8*i));
    combined = (t[2] >> 26) | (t[3] << 25);
    for (int i = 0; i < 8; i++) s[16+i] = (uint8_t)(combined >> (8*i));
    combined = (t[3] >> 39) | (t[4] << 12);
    for (int i = 0; i < 8; i++) s[24+i] = (uint8_t)(combined >> (8*i));
}

/* CT-REQUIRED: conditional swap — no branches on secret bit */
static void fe_cswap(fe a, fe b, uint64_t flag) {
    uint64_t mask = -(uint64_t)(flag & 1);
    for (int i = 0; i < 5; i++) {
        uint64_t t = mask & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
    }
}

static void fe_copy(fe h, const fe f)    { for (int i=0;i<5;i++) h[i]=f[i]; }
static void fe_set0(fe h)               { for (int i=0;i<5;i++) h[i]=0; }
static void fe_set1(fe h)               { h[0]=1; for(int i=1;i<5;i++) h[i]=0; }

static void fe_add(fe h, const fe f, const fe g) {
    for (int i = 0; i < 5; i++) h[i] = f[i] + g[i];
}

static void fe_sub(fe h, const fe f, const fe g) {
    /* Add 2*p to avoid underflow, then subtract */
    static const uint64_t two_p[5] = {
        2*((UINT64_C(1)<<51)-19), 2*((UINT64_C(1)<<51)-1),
        2*((UINT64_C(1)<<51)-1),  2*((UINT64_C(1)<<51)-1),
        2*((UINT64_C(1)<<51)-1)
    };
    for (int i = 0; i < 5; i++) h[i] = f[i] + two_p[i] - g[i];
}

/* 128-bit type for multiplication — use unsigned __int128 where available */
#if defined(__SIZEOF_INT128__)
  /* __int128 is a GCC/Clang extension — not ISO C11 but universally available
   * on 64-bit targets. The struct fallback below covers MSVC and strict-ISO builds. */
  #if defined(__GNUC__) || defined(__clang__)
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wpedantic"
  #endif
  typedef unsigned __int128 uint128_t;
  #if defined(__GNUC__) || defined(__clang__)
    #pragma GCC diagnostic pop
  #endif
  #define MUL64(a,b) ((uint128_t)(a) * (uint128_t)(b))
#else
/* Fallback: split multiplication */
typedef struct { uint64_t lo, hi; } uint128_t;
static inline uint128_t MUL64(uint64_t a, uint64_t b) {
    uint128_t r;
    uint64_t a0=a&0xFFFFFFFF, a1=a>>32, b0=b&0xFFFFFFFF, b1=b>>32;
    uint64_t m0=a0*b0, m1=a0*b1, m2=a1*b0, m3=a1*b1;
    uint64_t mid = m1 + (m0>>32); mid += m2;
    if (mid < m2) m3 += UINT64_C(1)<<32;
    r.lo = (mid << 32) | (m0 & 0xFFFFFFFF);
    r.hi = m3 + (mid >> 32);
    return r;
}
#endif

static void fe_mul(fe h, const fe f, const fe g) {
    /* Schoolbook multiplication with reduction by 19 */
    uint128_t t[5] = {0,0,0,0,0};
    for (int i = 0; i < 5; i++)
        for (int j = 0; j < 5; j++) {
            uint64_t gi = (i+j >= 5) ? g[j] * 19 : g[j];
            int idx = (i+j) % 5;
#if defined(__SIZEOF_INT128__)
            t[idx] += MUL64(f[i], gi);
#else
            uint128_t p = MUL64(f[i], gi);
            t[idx].lo += p.lo;
            if (t[idx].lo < p.lo) t[idx].hi++;
            t[idx].hi += p.hi;
#endif
        }

    /* Carry chain */
    for (int i = 0; i < 5; i++) {
#if defined(__SIZEOF_INT128__)
        uint64_t lo = (uint64_t)t[i];
        h[i] = lo & ((UINT64_C(1) << 51) - 1);
        uint64_t carry = (uint64_t)(t[i] >> 51);
#else
        h[i] = t[i].lo & ((UINT64_C(1) << 51) - 1);
        uint64_t carry = (t[i].lo >> 51) | (t[i].hi << 13);
#endif
        if (i < 4) {
#if defined(__SIZEOF_INT128__)
            t[i+1] += carry;
#else
            t[i+1].lo += carry;
            if (t[i+1].lo < carry) t[i+1].hi++;
#endif
        } else {
            h[0] += carry * 19;
        }
    }
    uint64_t c = h[0] >> 51; h[0] &= (UINT64_C(1) << 51) - 1; h[1] += c;
}

static void fe_sq(fe h, const fe f) { fe_mul(h, f, f); }

/* Compute f^(2^n) by repeated squaring */
static void fe_sq_n(fe h, const fe f, int n) {
    fe_sq(h, f);
    for (int i = 1; i < n; i++) fe_sq(h, h);
}

/* Inversion: f^(p-2) via addition chain for 2^255-21 */
static void fe_inv(fe h, const fe f) {
    fe t0, t1, t2, t3;

    fe_sq(t0, f);           /* t0 = f^2 */
    fe_sq_n(t1, t0, 2);    /* t1 = f^8 */
    fe_mul(t1, f, t1);     /* t1 = f^9 */
    fe_mul(t0, t0, t1);    /* t0 = f^11 */
    fe_sq(t2, t0);          /* t2 = f^22 */
    fe_mul(t1, t1, t2);    /* t1 = f^(2^5 - 1) = f^31 */
    fe_sq_n(t2, t1, 5);    /* t2 = f^(2^10 - 32) */
    fe_mul(t1, t2, t1);    /* t1 = f^(2^10 - 1) */
    fe_sq_n(t2, t1, 10);   fe_mul(t2, t2, t1);  /* f^(2^20 - 1) */
    fe_sq_n(t3, t2, 20);   fe_mul(t2, t3, t2);  /* f^(2^40 - 1) */
    fe_sq_n(t2, t2, 10);   fe_mul(t1, t2, t1);  /* f^(2^50 - 1) */
    fe_sq_n(t2, t1, 50);   fe_mul(t2, t2, t1);  /* f^(2^100 - 1) */
    fe_sq_n(t3, t2, 100);  fe_mul(t2, t3, t2);  /* f^(2^200 - 1) */
    fe_sq_n(t2, t2, 50);   fe_mul(t1, t2, t1);  /* f^(2^250 - 1) */
    fe_sq_n(t1, t1, 5);    fe_mul(h, t1, t0);   /* f^(2^255 - 21) */
}

/* ═══════════════════════════════════════════════════════════════════
 * X25519 MONTGOMERY LADDER
 * CT-REQUIRED: No secret-dependent branches. The ladder is constant-time
 * by construction: every iteration performs the same operations, with
 * cswap selecting which point to operate on.
 * ═══════════════════════════════════════════════════════════════════ */

void zupt_x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]) {
    uint8_t e[32];
    memcpy(e, scalar, 32);
    /* RFC 7748 clamping */
    e[0]  &= 248;
    e[31] &= 127;
    e[31] |= 64;

    fe x1, x2, z2, x3, z3, tmp0, tmp1;
    fe_frombytes(x1, point);
    fe_set1(x2);
    fe_set0(z2);
    fe_copy(x3, x1);
    fe_set1(z3);

    uint64_t swap = 0;
    for (int pos = 254; pos >= 0; pos--) {
        uint64_t bit = (e[pos/8] >> (pos%8)) & 1;
        swap ^= bit;
        fe_cswap(x2, x3, swap);
        fe_cswap(z2, z3, swap);
        swap = bit;

        /* Montgomery ladder step */
        fe a, b, c, d, da, cb, aa, bb, e2, dc;
        fe_add(a, x2, z2);
        fe_sub(b, x2, z2);
        fe_add(c, x3, z3);
        fe_sub(d, x3, z3);
        fe_mul(da, d, a);
        fe_mul(cb, c, b);
        fe_add(tmp0, da, cb); fe_sq(x3, tmp0);
        fe_sub(tmp1, da, cb); fe_sq(tmp1, tmp1); fe_mul(z3, x1, tmp1);
        fe_sq(aa, a);
        fe_sq(bb, b);
        fe_mul(x2, aa, bb);
        fe_sub(e2, aa, bb);
        /* a24 = 121666 = (486662+2)/4
         * z2 = E * (BB + a24 * E)
         * SECURITY NOTE: The formula using BB (not AA) is algebraically correct
         * for the Montgomery curve y^2 = x^3 + 486662*x^2 + x.
         * Verified against RFC 7748 test vectors and libsodium. */
        fe_copy(dc, e2);
        for (int i = 0; i < 5; i++) tmp0[i] = 0;
        tmp0[0] = 121666;
        fe_mul(tmp0, dc, tmp0);
        fe_add(tmp0, bb, tmp0);
        fe_mul(z2, e2, tmp0);
    }
    fe_cswap(x2, x3, swap);
    fe_cswap(z2, z3, swap);

    fe_inv(z2, z2);
    fe_mul(x2, x2, z2);
    fe_tobytes(out, x2);

    /* Wipe stack */
    (void)memset_s(e, sizeof e, 0, sizeof e);
}

void zupt_x25519_base(uint8_t out[32], const uint8_t scalar[32]) {
    /* Standard basepoint: u = 9 */
    uint8_t basepoint[32] = {0};
    basepoint[0] = 9;
    zupt_x25519(out, scalar, basepoint);
}
