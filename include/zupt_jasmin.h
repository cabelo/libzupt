/*
 * Zupt — Jasmin Verified Crypto Declarations
 * Copyright (c) 2026 Cristian Cezar Moisés — MIT License
 *
 * Extern declarations for Jasmin-compiled assembly functions.
 * These replace C fallbacks when built with -DZUPT_USE_JASMIN.
 *
 * Calling convention: System V AMD64 ABI.
 * Pointer args passed in RDI, RSI, RDX, RCX, R8, R9.
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
 * Replaces fe_cswap in zupt_x25519.c. */
extern void zupt_fe_cswap(void *a, void *b, uint64_t cond);

/* NOTE: zupt_aes256_blk has an offset bug in the Jasmin-generated
 * assembly (stack u128[15] indexing uses byte offset instead of
 * element offset — rk.[1] generates [rsp+1] not [rsp+16]).
 * AES-NI path is NOT wired in until the .jazz source is fixed.
 * C table-based AES remains the active path. */

#endif /* ZUPT_USE_JASMIN */
#endif /* ZUPT_JASMIN_H */
