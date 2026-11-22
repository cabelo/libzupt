/*
 * Zupt — Backup-oriented compression with AES-256 encryption
 * Copyright (c) 2026 Cristian Cezar Moisés
 * SPDX-License-Identifier: MIT
 *
 * X25519 Diffie-Hellman key agreement (RFC 7748).
 * Montgomery ladder — constant-time by construction.
 */
/**
 * @cond PORT
 * @file   zupt_x25519.h
 * @brief  Interface pública da concordância de chave X25519 (RFC 7748).
 * @details Expõe a função Diffie-Hellman da curva Montgomery Curve25519, que
 * calcula a multiplicação escalar do ponto de coordenada afim `u`
 * fornecido pelo escalar de 32 bytes, retornando a coordenada u do
 * resultado em 32 bytes little-endian (a coordenada v não é
 * reconstruída nem verificada).
 *
 * A aritmética do corpo GF(2^255 - 19) usa 5 limbos de 51 bits
 * internamente. A multiplicação é o produto escolar 5×51 cujos
 * termos de índice ≥ 5 são dobrados de volta multiplicados por 19
 * (2^255 ≡ 19 mod p), seguida de propagação de carry; a inversão é
 * exponenciação binária por z^(2^255-21) = z^(p-2) (ver
 * src/zupt_x25519.c).
 *
 * Não há verificação de subgrupo, de ponto de ordem baixa, nem de
 * igualdade a zero: a função sempre escreve 32 bytes. Cabe ao
 * chamador rejeitar resultados todo-zero — o consumidor interno
 * as rotinas internas `hybrid_encrypt_core` e
 * `hybrid_decrypt_core`, de `src/zupt_crypto.c`, em
 * src/zupt_crypto.c faz essa checagem antes de derivar chaves.
 *
 * Nota: o cabeçalho de licença acima afirma "constant-time by
 * construction". Os mecanismos observáveis correspondentes estão
 * descritos na implementação; esta interface não faz garantias
 * próprias.
 * @see    src/zupt_x25519.c
 * @endcond
 * @cond INGLES
 * @file   zupt_x25519.h
 * @brief  Public interface of the X25519 key agreement (RFC 7748).
 * @details Exposes the Diffie-Hellman function of the Montgomery curve Curve25519, which
 * computes the scalar multiplication of the affine coordinate point `u`
 * provided by the 32-byte scalar, returning the u coordinate of the
 * result in 32 little-endian bytes (the v coordinate is not
 * reconstructed nor verified).
 *
 * The arithmetic of the field GF(2^255 - 19) uses 5 limbs of 51 bits
 * internally. The multiplication is the 5×51 schoolbook product whose
 * terms of index ≥ 5 are folded back multiplied by 19
 * (2^255 ≡ 19 mod p), followed by carry propagation; the inversion is
 * binary exponentiation by z^(2^255-21) = z^(p-2) (see
 * src/zupt_x25519.c).
 *
 * There is no subgroup check, no low-order point check, and no check
 * for equality to zero: the function always writes 32 bytes. It is up to
 * the caller to reject all-zero results — the internal consumer:
 * the internal routines `hybrid_encrypt_core` and
 * `hybrid_decrypt_core`, from `src/zupt_crypto.c`, in
 * src/zupt_crypto.c, perform that check before deriving keys.
 *
 * Note: the license header above states "constant-time by
 * construction". The corresponding observable mechanisms are
 * described in the implementation; this interface makes no guarantees
 * of its own.
 * @see    src/zupt_x25519.c
 * @endcond */
#ifndef ZUPT_X25519_H
#define ZUPT_X25519_H

#include <stdint.h>

/**
 * @cond PORT
 * @brief X25519(scalar, point) → result. All inputs/outputs are 32 bytes.
 * @details Copia o escalar, aplica o clamping da RFC 7748 (bit 0,1,2 de
 * byte 0 zerados; bit 255 zerado; bit 254 posto a 1), executa a
 * escada de Montgomery sobre os bits 254..0 do escalar tratado com
 * máscara, inverte a coordenada z por exponenciação
 * (z^(2^255-21)) e multiplica por x para obter a coordenada afim.
 * Nenhum valor de entrada é rejeitado: qualquer sequência de 32
 * bytes é aceita como ponto e como escalar.
 * @param[out] out    Coordenada u do resultado (32 bytes little-endian).
 * @param[in]  scalar Escalar privado (32 bytes little-endian; é clampado
 * internamente, a cópia de entrada não é alterada).
 * @param[in]  point  Coordenada u do ponto de entrada (32 bytes
 * little-endian; a máscara de bit alto do byte 31 é
 * aplicada na decodificação do corpo).
 * @note     CT-REQUIRED: Montgomery ladder is inherently constant-time. A
 * ordem de operações por iteração é fixa e a seleção do ponto é
 * feita por troca condicional (fe_cswap), sem ramificação sobre o
 * bit do escalar.
 * @warning  `out` não deve sobrepor `scalar` nem `point`, conforme os
 * requisitos ACSL `\separated` adjuntos à implementação.
 * @pre      Os três buffers têm exatamente 32 bytes válidos.
 * @see      zupt_x25519_base()
 * @endcond
 * @cond INGLES
 * @brief X25519(scalar, point) → result. All inputs/outputs are 32 bytes.
 * @details Copies the scalar, applies the RFC 7748 clamping (bits 0,1,2 of
 * byte 0 zeroed; bit 255 zeroed; bit 254 set to 1), runs the
 * Montgomery ladder over the bits 254..0 of the masked scalar, inverts the z coordinate by exponentiation
 * (z^(2^255-21)) and multiplies by x to obtain the affine coordinate.
 * No input value is rejected: any sequence of 32
 * bytes is accepted as a point and as a scalar.
 * @param[out] out    u coordinate of the result (32 bytes little-endian).
 * @param[in]  scalar Private scalar (32 bytes little-endian; it is clamped
 * internally, the input copy is not altered).
 * @param[in]  point  u coordinate of the input point (32 bytes
 * little-endian; the high-bit mask of byte 31 is
 * applied during field decoding).
 * @note     CT-REQUIRED: Montgomery ladder is inherently constant-time. The
 * order of operations per iteration is fixed and the point selection is
 * done by a conditional swap (fe_cswap), without branching on the
 * scalar bit.
 * @warning  `out` must not overlap `scalar` nor `point`, according to the
 * ACSL `\separated` requirements attached to the implementation.
 * @pre      The three buffers have exactly 32 valid bytes.
 * @see      zupt_x25519_base()
 * @endcond */
void zupt_x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]);

/**
 * @cond PORT
 * @brief X25519 com o ponto base padrão (u = 9).
 * @details Monta em pilha o vetor little-endian do ponto base (byte 0 = 9,
 * demais bytes zero) e delega a zupt_x25519(). Usado para
 * geração de chave: public = X25519(private, basepoint).
 * @param[out] out    Chave pública resultante (32 bytes).
 * @param[in]  scalar Escalar privado (32 bytes, clampado internamente).
 * @note     Equivalente a zupt_x25519(out, scalar, basepoint) com basepoint
 * = {9, 0, ...}. Não valida o escalar além do clamping.
 * @see      zupt_x25519()
 * @endcond
 * @cond INGLES
 * @brief X25519 with the default base point (u = 9).
 * @details Builds on the stack the little-endian vector of the base point (byte 0 = 9,
 * the other bytes zero) and delegates to zupt_x25519(). Used for
 * key generation: public = X25519(private, basepoint).
 * @param[out] out    Resulting public key (32 bytes).
 * @param[in]  scalar Private scalar (32 bytes, clamped internally).
 * @note     Equivalent to zupt_x25519(out, scalar, basepoint) with basepoint
 * = {9, 0, ...}. Does not validate the scalar beyond clamping.
 * @see      zupt_x25519()
 * @endcond */
void zupt_x25519_base(uint8_t out[32], const uint8_t scalar[32]);

#endif
