/*
 * ZUPT - AES-256 Block Cipher (FIPS 197)
 * Portable C with algebraic S-box; optional runtime-dispatched AES-NI.
 * FRAMA-C: ACSL-annotated (v2.0.0)
 */
#include "zupt.h"
#include "zupt_acsl.h"
#include <string.h>

/* Algebraic AES S-box: fixed operations, no secret-indexed tables.
 * This removes the cache lookup surface of the former aes_sbox(state) fallback.
 * Constant-time behavior still requires compiler/target-specific review. */
static uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t out = 0;
    for (unsigned i = 0; i < 8; ++i) {
        out ^= (uint8_t)(a & (uint8_t)(0u - (b & 1u)));
        a = (uint8_t)((a << 1) ^ (0x1bu & (0u - (a >> 7))));
        b >>= 1;
    }
    return out;
}
static uint8_t rotl8(uint8_t x, unsigned n) {
    return (uint8_t)((x << n) | (x >> (8u - n)));
}
static uint8_t aes_sbox(uint8_t x) {
    /* x^254 in GF(2^8), including inverse(0) = 0. */
    uint8_t x2 = gf_mul(x, x);
    uint8_t x3 = gf_mul(x2, x);
    uint8_t x6 = gf_mul(x3, x3);
    uint8_t x12 = gf_mul(x6, x6);
    uint8_t x15 = gf_mul(x12, x3);
    uint8_t x30 = gf_mul(x15, x15);
    uint8_t x60 = gf_mul(x30, x30);
    uint8_t x120 = gf_mul(x60, x60);
    uint8_t x240 = gf_mul(x120, x120);
    uint8_t x252 = gf_mul(x240, x12);
    uint8_t y = gf_mul(x252, x2);
    return (uint8_t)(y ^ rotl8(y, 1) ^ rotl8(y, 2) ^
                     rotl8(y, 3) ^ rotl8(y, 4) ^ 0x63u);
}

static const uint8_t RCON[11] = {0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

/* ─── GF(2^8) multiply ─── */
static inline uint8_t xtime(uint8_t x) { return (x<<1)^(((x>>7)&1)*0x1b); }
static inline uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t r=0;
    for (int i=0;i<8;i++) { r ^= (uint8_t)(a & (uint8_t)(0u - (b & 1u))); a=xtime(a); b>>=1; }
    return r;
}

/* ─── Key Expansion (AES-256: 14 rounds, 60 round-key words) ─── */
/* FRAMA-C: AES-256 key schedule expansion */
/*@ requires \valid(c);
  @ requires \valid_read(key + (0..31));
  @ assigns c->rk[0..59];
  @ ensures \initialized(&c->rk[0..59]);
*/
void zupt_aes256_init(zupt_aes256_ctx *c, const uint8_t key[32]) {
    uint32_t *rk = c->rk;
    for (int i=0;i<8;i++)
        rk[i] = ((uint32_t)key[4*i]<<24)|((uint32_t)key[4*i+1]<<16)|
                ((uint32_t)key[4*i+2]<<8)|key[4*i+3];
    for (int i=8;i<60;i++) {
        uint32_t t = rk[i-1];
        if (i%8==0) {
            t = ((uint32_t)aes_sbox((t>>16)&0xFF)<<24)|((uint32_t)aes_sbox((t>>8)&0xFF)<<16)|
                ((uint32_t)aes_sbox(t&0xFF)<<8)|aes_sbox(t>>24);
            t ^= (uint32_t)RCON[i/8]<<24;
        } else if (i%8==4) {
            t = ((uint32_t)aes_sbox(t>>24)<<24)|((uint32_t)aes_sbox((t>>16)&0xFF)<<16)|
                ((uint32_t)aes_sbox((t>>8)&0xFF)<<8)|aes_sbox(t&0xFF);
        }
        rk[i] = rk[i-8]^t;
    }
}


#if !defined(ZUPT_FORCE_PORTABLE_AES) && (defined(__GNUC__) || defined(__clang__)) && (defined(__x86_64__) || defined(__i386__))
#include <wmmintrin.h>
__attribute__((target("aes,sse2")))
static void aesni_encrypt_block(const zupt_aes256_ctx *c,
                                 const uint8_t in[16], uint8_t out[16]) {
    uint8_t round_key[16];
    __m128i state = _mm_loadu_si128((const __m128i *)(const void *)in);
    for (unsigned round = 0; round < 15; ++round) {
        for (unsigned i = 0; i < 16; ++i)
            round_key[i] = (uint8_t)(c->rk[round * 4 + i / 4] >> (24 - 8 * (i % 4)));
        __m128i key = _mm_loadu_si128((const __m128i *)(const void *)round_key);
        if (round == 0) state = _mm_xor_si128(state, key);
        else if (round == 14) state = _mm_aesenclast_si128(state, key);
        else state = _mm_aesenc_si128(state, key);
    }
    _mm_storeu_si128((__m128i *)(void *)out, state);
    zupt_secure_wipe(round_key, sizeof(round_key));
}
#endif

/* ─── Single block encryption ─── */
/* FRAMA-C: AES-256 single-block encrypt */
/*@ requires \valid_read(&c->rk[0..59]);
  @ requires \valid_read(in + (0..15));
  @ requires \valid(out + (0..15));
  @ requires \separated(in + (0..15), out + (0..15));
  @ assigns out[0..15];
  @ ensures \initialized(out + (0..15));
*/
void zupt_aes256_encrypt_block(const zupt_aes256_ctx *c, const uint8_t in[16], uint8_t out[16]) {
#if !defined(ZUPT_FORCE_PORTABLE_AES) && (defined(__GNUC__) || defined(__clang__)) && (defined(__x86_64__) || defined(__i386__))
    if (__builtin_cpu_supports("aes")) {
        aesni_encrypt_block(c, in, out);
        return;
    }
#endif
    uint8_t s[16];
    const uint32_t *rk = c->rk;
    /* AddRoundKey(0) */
    for (int i=0;i<16;i++)
        s[i] = in[i]^(uint8_t)(rk[i/4]>>((3-i%4)*8));
    /* Rounds 1-13 */
    for (int r=1;r<=13;r++) {
        uint8_t t[16];
        /* SubBytes */
        for (int i=0;i<16;i++) t[i]=aes_sbox(s[i]);
        /* ShiftRows */
        uint8_t u[16];
        u[0]=t[0]; u[1]=t[5]; u[2]=t[10]; u[3]=t[15];
        u[4]=t[4]; u[5]=t[9]; u[6]=t[14]; u[7]=t[3];
        u[8]=t[8]; u[9]=t[13]; u[10]=t[2]; u[11]=t[7];
        u[12]=t[12]; u[13]=t[1]; u[14]=t[6]; u[15]=t[11];
        /* MixColumns */
        for (int col=0;col<4;col++) {
            uint8_t a0=u[col*4],a1=u[col*4+1],a2=u[col*4+2],a3=u[col*4+3];
            s[col*4+0]=gmul(a0,2)^gmul(a1,3)^a2^a3;
            s[col*4+1]=a0^gmul(a1,2)^gmul(a2,3)^a3;
            s[col*4+2]=a0^a1^gmul(a2,2)^gmul(a3,3);
            s[col*4+3]=gmul(a0,3)^a1^a2^gmul(a3,2);
        }
        /* AddRoundKey */
        for (int i=0;i<16;i++)
            s[i] ^= (uint8_t)(rk[r*4+i/4]>>((3-i%4)*8));
    }
    /* Round 14 (no MixColumns) */
    {
        uint8_t t[16];
        for (int i=0;i<16;i++) t[i]=aes_sbox(s[i]);
        uint8_t u[16];
        u[0]=t[0]; u[1]=t[5]; u[2]=t[10]; u[3]=t[15];
        u[4]=t[4]; u[5]=t[9]; u[6]=t[14]; u[7]=t[3];
        u[8]=t[8]; u[9]=t[13]; u[10]=t[2]; u[11]=t[7];
        u[12]=t[12]; u[13]=t[1]; u[14]=t[6]; u[15]=t[11];
        for (int i=0;i<16;i++)
            out[i] = u[i]^(uint8_t)(rk[56+i/4]>>((3-i%4)*8));
    }
}
