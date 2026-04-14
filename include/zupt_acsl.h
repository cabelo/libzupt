/*
 * Zupt — ACSL Custom Predicates for Frama-C/WP
 * Copyright (c) 2026 Cristian Cezar Moisés — MIT License
 *
 * Usage: frama-c -wp -wp-rte -wp-model Typed+Cast
 *        -cpp-extra-args="-Iinclude -Isrc" src/zupt_crypto.c
 */
#ifndef ZUPT_ACSL_H
#define ZUPT_ACSL_H

#ifdef __FRAMAC__
#include <stdint.h>

/*@ predicate ValidBuffer{L}(uint8_t *p, size_t n) =
  @   \valid_read(p + (0..n-1)) &&
  @   \initialized(p + (0..n-1));
  @
  @ predicate ValidWriteBuffer{L}(uint8_t *p, size_t n) =
  @   \valid(p + (0..n-1));
  @
  @ predicate Separated2(uint8_t *a, size_t an,
  @                      uint8_t *b, size_t bn) =
  @   \separated(a + (0..an-1), b + (0..bn-1));
  @
  @ predicate KeyWiped{L}(uint8_t *k, size_t n) =
  @   \forall integer i; 0 <= i < n ==> \at(k[i],L) == 0;
  @
  @ predicate ValidKey{L}(uint8_t *k, size_t n) =
  @   ValidBuffer{L}(k, n) && n == 32;
  @
  @ predicate ConstantTimeCompare{L}(uint8_t *a, uint8_t *b,
  @   size_t n) =
  @   \forall integer i; 0 <= i < n ==>
  @   \initialized(\at(a+i,L)) && \initialized(\at(b+i,L));
  @
  @ predicate MACValid{L}(uint8_t *mac) =
  @   ValidBuffer{L}(mac, 32);
*/
#endif /* __FRAMAC__ */

#endif /* ZUPT_ACSL_H */
