/*
 * Zupt — Jasmin Verified Crypto Declarations
 * Copyright (c) 2026 Cristian Cezar Moisés — MIT License
 *
 * Extern declarations for Jasmin-compiled assembly functions.
 * These replace C fallbacks when built with -DZUPT_USE_JASMIN.
 *
 * Calling convention: System V AMD64 ABI.
 * Pointer args passed in RDI, RSI, RDX, RCX, R8, R9.
 *
 * v2.0.0: All 4 Jasmin functions wired and active.
 */
#ifndef ZUPT_JASMIN_H
#define ZUPT_JASMIN_H

#ifdef ZUPT_USE_JASMIN
#include <stdint.h>

/* JASMIN-VERIFIED: CT MAC comparison (4×u64 XOR accumulation).
 * Returns 0 if all 32 bytes match, nonzero if any differ.
 * Replaces XOR loop in zupt_decrypt_buffer(). */
extern uint64_t zupt_mac_verify_ct(const void *expected, const void *actual);

/* JASMIN-VERIFIED: CT conditional select (4×u64 masked select).
 * if cond==0: copies a→out. if cond!=0: copies b→out.
 * Replaces cmov in zupt_mlkem768_decaps(). */
extern void zupt_ct_select_32(void *out, const void *a,
                               const void *b, uint64_t cond);

/* JASMIN-VERIFIED: CT conditional swap (4×u64 masked XOR swap).
 * if cond==0: no-op. if cond==1: swaps a↔b in place.
 * Replaces fe_cswap in zupt_x25519.c.
 * NOTE: Requires 4×u64 field element layout (donna64). */
extern void zupt_fe_cswap(void *a, void *b, uint64_t cond);

/* JASMIN-VERIFIED: AES-256 single-block encrypt via AES-NI.
 * out = AES-256-ECB(key, ctr) XOR in.
 * FIX v2.0.0: Stack offset bug resolved — round keys at correct
 * 16-byte aligned offsets. Requires AES-NI (checked via CPUID).
 *
 * Args (System V ABI):
 *   out_ptr (RDI): destination for 16-byte result
 *   in_blk  (RSI): pointer to 16-byte plaintext block
 *   key     (RDX): pointer to 32-byte AES-256 key (two u128)
 *   ctr_blk (RCX): pointer to 16-byte counter block
 */
extern void zupt_aes256_blk(void *out, const void *in,
                              const void *key, const void *ctr);

/* JASMIN-VERIFIED: AES-256-CTR 4-block pipeline via AES-NI.
 * Processes nblocks×16 bytes with 4-way interleaving.
 * Counter is updated in-place (big-endian increment in bytes [8..15]).
 * Requires AES-NI. Falls back to zupt_aes256_blk for remaining 1-3 blocks.
 *
 * Args: out(RDI), in(RSI), key(RDX), ctr(RCX), nblocks(R8)
 */
extern void zupt_aes256_ctr4(void *out, const void *in,
                               const void *key, void *ctr,
                               uint64_t nblocks);

#endif /* ZUPT_USE_JASMIN */
#endif /* ZUPT_JASMIN_H */
