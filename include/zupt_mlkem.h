/*
 * Zupt — Backup-oriented compression with AES-256 encryption
 * Copyright (c) 2026 Cristian Cezar Moisés
 * SPDX-License-Identifier: MIT
 *
 * ML-KEM-768 (FIPS 203, formerly CRYSTALS-Kyber).
 * Post-quantum key encapsulation mechanism.
 *
 * Parameters (ML-KEM-768):
 *   k = 3, η₁ = 2, η₂ = 2, d_u = 10, d_v = 4
 *   Public key:  1184 bytes
 *   Secret key:  2400 bytes
 *   Ciphertext:  1088 bytes
 *   Shared secret: 32 bytes
 *
 * SECURITY NOTE: This implementation must undergo independent review
 * before deployment in high-assurance contexts. It targets correctness
 * against NIST test vectors and constant-time operation.
 */
#ifndef ZUPT_MLKEM_H
#define ZUPT_MLKEM_H

#include <stdint.h>

#define MLKEM_K     3
#define MLKEM_N     256
#define MLKEM_Q     3329
#define MLKEM_ETA1  2
#define MLKEM_ETA2  2
#define MLKEM_DU    10
#define MLKEM_DV    4

#define MLKEM_PUBLICKEYBYTES    1184
#define MLKEM_SECRETKEYBYTES    2400
#define MLKEM_CIPHERTEXTBYTES   1088
#define MLKEM_SSBYTES           32

/* KeyGen: generate public/secret keypair.
 * pk: output public key (1184 bytes)
 * sk: output secret key (2400 bytes)
 * Returns 0 on success. */
int zupt_mlkem768_keygen(uint8_t pk[MLKEM_PUBLICKEYBYTES],
                          uint8_t sk[MLKEM_SECRETKEYBYTES]);

/* Encapsulate: produce ciphertext and shared secret from public key.
 * ct: output ciphertext (1088 bytes)
 * ss: output shared secret (32 bytes)
 * pk: input public key (1184 bytes)
 * Returns 0 on success. */
int zupt_mlkem768_encaps(uint8_t ct[MLKEM_CIPHERTEXTBYTES],
                          uint8_t ss[MLKEM_SSBYTES],
                          const uint8_t pk[MLKEM_PUBLICKEYBYTES]);

/* Decapsulate: recover shared secret from ciphertext and secret key.
 * ss: output shared secret (32 bytes)
 * ct: input ciphertext (1088 bytes)
 * sk: input secret key (2400 bytes)
 * Returns 0 on success.
 * CT-REQUIRED: Implicit rejection — invalid ciphertext produces a
 * pseudorandom shared secret (no distinguishable failure). */
int zupt_mlkem768_decaps(uint8_t ss[MLKEM_SSBYTES],
                          const uint8_t ct[MLKEM_CIPHERTEXTBYTES],
                          const uint8_t sk[MLKEM_SECRETKEYBYTES]);

#endif
