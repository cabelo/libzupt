/*
 * Zupt — ACSL Custom Predicates for Frama-C/WP
 * Copyright (c) 2026 Cristian Cezar Moisés — MIT License
 *
 * Usage: frama-c -wp -wp-rte -wp-model Typed+Cast
 *        -cpp-extra-args="-Iinclude -Isrc" src/zupt_crypto.c
 */
/**
 * @cond PORT
 * @file  zupt_acsl.h
 * @brief Predicados ACSL personalizados para verificação com Frama-C/WP.
 * @details Este cabeçalho declara apenas predicados ACSL, usados como
 * vocabulário comum nas anotações dos módulos criptográficos
 * (por exemplo src/zupt_sha256.c e src/zupt_crypto.c). Nada aqui
 * afeta a compilação normal: todo o conteúdo está protegido por
 * a condição de pré-processador sobre `__FRAMAC__`, que é definido somente pelo pré-processador
 * do Frama-C; em um compilador C comum o cabeçalho expande para nada,
 * além do próprio guarda de inclusão.
 *
 * O conteúdo (preservado literalmente na documentação, pois pertence
 * ao contrato formal) define:
 * - `ValidBuffer(p, n)`: as n bytes a partir de `p` são legíveis e
 * inicializadas.
 * - `ValidWriteBuffer(p, n)`: as n bytes a partir de `p` são
 * endereços graváveis.
 * - `Separated2(a, an, b, bn)`: as duas regiões não se sobrepõem.
 * - `KeyWiped(k, n)`: todos os n bytes de `k` valem zero no local L.
 * - `ValidKey(k, n)`: `ValidBuffer(k, n)` e `n == 32`.
 * - `ConstantTimeCompare(a, b, n)`: todas as n bytes de cada buffer
 * estão inicializadas (predicado de bem-formado; não expressa, por
 * si, custo constante de tempo).
 * - `MACValid(mac)`: `ValidBuffer(mac, 32)`.
 *
 * @note Para executar a verificação, use a linha de comando indicada no
 * cabeçalho original:
 * `frama-c -wp -wp-rte -wp-model Typed+Cast -cpp-extra-args="-Iinclude -Isrc" src/zupt_crypto.c`.
 * Essa verificação não foi executada nesta revisão de documentação.
 * @see ZUPT_USE_JASMIN
 * @endcond
 * @cond INGLES
 * @file  zupt_acsl.h
 * @brief Custom ACSL predicates for verification with Frama-C/WP.
 * @details This header declares only ACSL predicates, used as
 * common vocabulary in the annotations of the cryptographic modules
 * (for example src/zupt_sha256.c and src/zupt_crypto.c). Nothing here
 * affects normal compilation: all the content is protected by
 * the preprocessor condition on `__FRAMAC__`, which is defined only by the Frama-C preprocessor; in a regular C compiler the header expands to nothing,
 * apart from the include guard itself.
 *
 * The content (preserved literally in the documentation, because it belongs
 * to the formal contract) defines:
 * - `ValidBuffer(p, n)`: the n bytes starting at `p` are readable and
 * initialized.
 * - `ValidWriteBuffer(p, n)`: the n bytes starting at `p` are
 * writable addresses.
 * - `Separated2(a, an, b, bn)`: the two regions do not overlap.
 * - `KeyWiped(k, n)`: all n bytes of `k` equal zero at location L.
 * - `ValidKey(k, n)`: `ValidBuffer(k, n)` and `n == 32`.
 * - `ConstantTimeCompare(a, b, n)`: all n bytes of each buffer
 * are initialized (well-formedness predicate; does not, by itself,
 * express constant-time cost).
 * - `MACValid(mac)`: `ValidBuffer(mac, 32)`.
 *
 * @note To run the verification, use the command line indicated in the
 * original header:
 * `frama-c -wp -wp-rte -wp-model Typed+Cast -cpp-extra-args="-Iinclude -Isrc" src/zupt_crypto.c`.
 * That verification was not executed in this documentation revision.
 * @see ZUPT_USE_JASMIN
 * @endcond */
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
