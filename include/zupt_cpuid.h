/*
 * Zupt — CPU Feature Detection
 * Copyright (c) 2026 Cristian Cezar Moisés — MIT License
 */
#ifndef ZUPT_CPUID_H
#define ZUPT_CPUID_H

#include <stdint.h>

typedef struct {
    int has_aesni;   /* CPUID.01H:ECX[25] — AES-NI instructions */
    int has_avx;     /* AVX (VEX-encoded SSE) — requires CPUID + OS XSAVE */
    int has_pclmul;  /* CPUID.01H:ECX[1]  — CLMUL (carry-less multiply) */
    int has_avx2;    /* CPUID.07H:EBX[5]  — AVX2 (256-bit SIMD) */
    int has_sse41;   /* CPUID.01H:ECX[19] — SSE4.1 */
} zupt_cpu_features_t;

/*@ assigns f->has_aesni, f->has_avx, f->has_pclmul, f->has_avx2, f->has_sse41;
  @ ensures f->has_aesni == 0 || f->has_aesni == 1;
  @ ensures f->has_avx == 0 || f->has_avx == 1;
  @ ensures f->has_pclmul == 0 || f->has_pclmul == 1;
  @ ensures f->has_avx2 == 0 || f->has_avx2 == 1;
  @ ensures f->has_sse41 == 0 || f->has_sse41 == 1;
*/
void zupt_detect_cpu(zupt_cpu_features_t *f);

/* Global instance — set once at program start */
extern zupt_cpu_features_t zupt_cpu;

#endif /* ZUPT_CPUID_H */
