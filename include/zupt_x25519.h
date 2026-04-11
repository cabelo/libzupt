/*
 * Zupt — Backup-oriented compression with AES-256 encryption
 * Copyright (c) 2026 Cristian Cezar Moisés
 * SPDX-License-Identifier: MIT
 *
 * X25519 Diffie-Hellman key agreement (RFC 7748).
 * Montgomery ladder — constant-time by construction.
 */
#ifndef ZUPT_X25519_H
#define ZUPT_X25519_H

#include <stdint.h>

/* X25519(scalar, point) → result. All inputs/outputs are 32 bytes.
 * CT-REQUIRED: Montgomery ladder is inherently constant-time. */
void zupt_x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]);

/* X25519 with the standard basepoint (9).
 * Used for keygen: public = X25519(private, basepoint). */
void zupt_x25519_base(uint8_t out[32], const uint8_t scalar[32]);

#endif
