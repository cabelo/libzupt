/*
 * ZUPT - SHA-256 (FIPS 180-4)
 * Pure C implementation, no dependencies.
 * FRAMA-C: ACSL-annotated (v2.0.0)
 */
#include "zupt.h"
#include "zupt_acsl.h"
#include <string.h>

static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
};

#define RR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(x,y,z)  (((x)&(y))^((~(x))&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define EP0(x) (RR(x,2)^RR(x,13)^RR(x,22))
#define EP1(x) (RR(x,6)^RR(x,11)^RR(x,25))
#define SG0(x) (RR(x,7)^RR(x,18)^((x)>>3))
#define SG1(x) (RR(x,17)^RR(x,19)^((x)>>10))

static uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];
}
static void be32_put(uint8_t *p, uint32_t v) {
    p[0]=(uint8_t)(v>>24); p[1]=(uint8_t)(v>>16); p[2]=(uint8_t)(v>>8); p[3]=(uint8_t)v;
}

static void sha256_transform(zupt_sha256_ctx *c, const uint8_t blk[64]) {
    uint32_t w[64], a,b,d,e,f,g,h,t1,t2;
    int i;
    for (i=0;i<16;i++) w[i]=be32(blk+i*4);
    for (i=16;i<64;i++) w[i]=SG1(w[i-2])+w[i-7]+SG0(w[i-15])+w[i-16];
    a=c->state[0]; b=c->state[1]; uint32_t cc=c->state[2]; d=c->state[3];
    e=c->state[4]; f=c->state[5]; g=c->state[6]; h=c->state[7];
    for (i=0;i<64;i++) {
        t1=h+EP1(e)+CH(e,f,g)+K[i]+w[i];
        t2=EP0(a)+MAJ(a,b,cc);
        h=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
    }
    c->state[0]+=a; c->state[1]+=b; c->state[2]+=cc; c->state[3]+=d;
    c->state[4]+=e; c->state[5]+=f; c->state[6]+=g; c->state[7]+=h;
}

void zupt_sha256_init(zupt_sha256_ctx *c) {
    c->state[0]=0x6a09e667; c->state[1]=0xbb67ae85;
    c->state[2]=0x3c6ef372; c->state[3]=0xa54ff53a;
    c->state[4]=0x510e527f; c->state[5]=0x9b05688c;
    c->state[6]=0x1f83d9ab; c->state[7]=0x5be0cd19;
    c->count=0;
}

void zupt_sha256_update(zupt_sha256_ctx *c, const uint8_t *d, size_t n) {
    while (n > 0) {
        size_t off = (size_t)(c->count % 64);
        size_t chunk = 64 - off;
        if (chunk > n) chunk = n;
        memcpy(c->buf + off, d, chunk);
        c->count += chunk;
        d += chunk; n -= chunk;
        if (c->count % 64 == 0)
            sha256_transform(c, c->buf);
    }
}

void zupt_sha256_final(zupt_sha256_ctx *c, uint8_t h[32]) {
    uint64_t bits = c->count * 8;
    uint8_t pad = 0x80;
    zupt_sha256_update(c, &pad, 1);
    pad = 0;
    while (c->count % 64 != 56)
        zupt_sha256_update(c, &pad, 1);
    uint8_t len[8];
    for (int i=7;i>=0;i--) { len[i]=(uint8_t)(bits&0xFF); bits>>=8; }
    zupt_sha256_update(c, len, 8);
    for (int i=0;i<8;i++) be32_put(h+i*4, c->state[i]);
}

/* FRAMA-C: SHA-256 one-shot hash */
/*@ requires n <= 0xFFFFFFFFFFFFFFFF / 8;
  @ requires \valid_read(d + (0..n-1));
  @ requires \valid(h + (0..31));
  @ requires \separated(d + (0..n-1), h + (0..31));
  @ assigns h[0..31];
  @ ensures \initialized(h + (0..31));
*/
void zupt_sha256(const uint8_t *d, size_t n, uint8_t h[32]) {
    zupt_sha256_ctx c;
    zupt_sha256_init(&c);
    zupt_sha256_update(&c, d, n);
    zupt_sha256_final(&c, h);
}
