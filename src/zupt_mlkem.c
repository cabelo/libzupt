/*
 * Zupt — Backup-oriented compression with AES-256 encryption
 * Copyright (c) 2026 Cristian Cezar Moisés
 * SPDX-License-Identifier: MIT
 *
 * ML-KEM-768 (FIPS 203, formerly CRYSTALS-Kyber).
 * Pure C11, zero dependencies. Uses zupt_keccak.h for SHA3/SHAKE.
 *
 * SECURITY NOTE: This implementation targets correctness against FIPS 203
 * and constant-time operation. It MUST undergo independent cryptographic
 * review before use in high-assurance production environments.
 *
 * CT-REQUIRED markers indicate operations that must be constant-time.
 * Fixed-shape polynomial loops; compiler/target side-channel review is still required.
 * Implicit rejection in decaps uses constant-time conditional select.
 */
/**
 * @cond PORT
 * @file   zupt_mlkem.c
 * @brief  Implementação em C11 puro do KEM ML-KEM-768 (FIPS 203).
 * @details Este arquivo implementa, sem dependências externas além de
 * zupt_keccak.h (SHA3/SHAKE) e zupt.h (aleatoriedade e limpeza
 * segura), a construção completa de FIPS 203 na parameterização 768:
 *
 * - Aritmética modular sobre q = 3329: redução de Barrett para
 * int16_t (sem ramificações) e redução de Montgomery para
 * int32_t, com QINV = q^(-1) mod 2^16.
 * - NTT de 256 pontos sobre Z_q[x]/(x^256+1), com raiz primitiva
 * de ordem 256 zeta = 17, tabela pré-computada em domínio de
 * Montgomery e ordem bit-reversed; inversa com escala final
 * f = 1441.
 * - Operações de polinômio e de vetor de polinômios (soma, subtração,
 * produto ponto a ponto "basemul" em NTT, redução, conversão ao
 * domínio de Montgomery).
 * - Amostragem: CBD(eta=2) a partir de 128 bytes, distribuição
 * uniforme por rejeição sobre fluxo SHAKE-128 e ruído via
 * PRF SHAKE-256 + CBD.
 * - Codificação/decodificação em 12 bits por coeficiente e
 * compressão/expandir em 10 e 4 bits.
 * - Esquema K-PKE IND-CPA (seções 7.2-7.3 de FIPS 203) e a
 * transformação Fujisaki-Okamoto que produz ML-KEM-768 (seções
 * 6-7), com rejeição implícita no decapsulamento.
 * - Verificações de codificação de chave pública e de chave secreta,
 * além de um auto-teste de ida e volta.
 *
 * Estrutura de memória: um polinômio é um array de 256 int16_t
 * (typedef poly); coeficientes podem ficar fora de [0, q) durante os
 * cálculos e só são normalizados por poly_reduce() ou pelas
 * funções de codificação.
 *
 * Seleção de ramo em tempo de compilação: ZUPT_USE_JASMIN troca a
 * função de seleção condicional em C por zupt_ct_select_32()
 * fornecida pelo Jasmin; ZUPT_TESTING habilita pontos de entrada
 * determinísticos usados por scripts/check-acvp.py.
 *
 * Nota factual: as marcações "CT-REQUIRED" e as declarações de
 * tempo constante do cabeçalho acima descrevem a intenção do autor.
 * Os mecanismos observáveis neste arquivo são: ausência de
 * ramificações em barrett_reduce()/montgomery_reduce(), índices de
 * tabela e limites de laço independentes de dados secretos, e a
 * seleção final por máscara de bits. A ausência de canais laterais
 * depende também do compilador e da arquitetura-alvo.
 * @endcond
 * @cond INGLES
 * @file   zupt_mlkem.c
 * @brief  Pure C11 implementation of the ML-KEM-768 KEM (FIPS 203).
 * @details This file implements, with no external dependencies besides
 * zupt_keccak.h (SHA3/SHAKE) and zupt.h (randomness and secure
 * wiping), the complete FIPS 203 construction under the 768
 * parameterization:
 *
 * - Modular arithmetic over q = 3329: Barrett reduction for
 * int16_t (branch-free) and Montgomery reduction for
 * int32_t, with QINV = q^(-1) mod 2^16.
 * - 256-point NTT over Z_q[x]/(x^256+1), with primitive root
 * of order 256 zeta = 17, pre-computed table in the Montgomery
 * domain and bit-reversed order; inverse with final scale
 * f = 1441.
 * - Polynomial and polynomial-vector operations (addition, subtraction,
 * pointwise "basemul" product in the NTT, reduction, conversion to
 * the Montgomery domain).
 * - Sampling: CBD(eta=2) from 128 bytes, uniform distribution
 * by rejection over a SHAKE-128 stream, and noise via
 * PRF SHAKE-256 + CBD.
 * - Encoding/decoding in 12 bits per coefficient and
 * compression/decompression in 10 and 4 bits.
 * - The K-PKE IND-CPA scheme (sections 7.2-7.3 of FIPS 203) and the
 * Fujisaki-Okamoto transform that produces ML-KEM-768 (sections
 * 6-7), with implicit rejection in decapsulation.
 * - Public key and secret key encoding checks,
 * plus a round-trip self-test.
 *
 * Memory layout: a polynomial is an array of 256 int16_t
 * (typedef poly); coefficients may lie outside [0, q) during the
 * computations and are normalized only by poly_reduce() or by the
 * encoding functions.
 *
 * Compile-time branch selection: ZUPT_USE_JASMIN replaces the
 * conditional selection function in C with zupt_ct_select_32()
 * provided by Jasmin; ZUPT_TESTING enables deterministic
 * entry points used by scripts/check-acvp.py.
 *
 * Factual note: the "CT-REQUIRED" markers and the constant-time
 * declarations in the header above describe the author's intent.
 * The observable mechanisms in this file are: the absence of
 * branches in barrett_reduce()/montgomery_reduce(), table indices
 * and loop bounds independent of secret data, and the final
 * selection by bit mask. The absence of side channels also
 * depends on the compiler and the target architecture.
 * @endcond */

/**
 * @cond PORT
 * @def _GNU_SOURCE
 * @brief Macro de feature do glibc, definido antes da primeira inclusão.
 *
 * Habilita as extensões GNU declaradas pelos cabeçalhos C padrão incluídos
 * em sequência. Não é referenciado por nenhum código deste arquivo, não faz
 * parte da API da biblioteca e não aparece na documentação pública.
 * @endcond
 * @cond INGLES
 * @def _GNU_SOURCE
 * @brief glibc feature macro, defined before the first inclusion.
 *
 * Enables the GNU extensions declared by the C standard headers included
 * in sequence. It is not referenced by any code in this file, it is not
 * part of the library API and it does not appear in the public documentation.
 * @endcond */
#define _GNU_SOURCE
#include "zupt_mlkem.h"
#include "zupt_keccak.h"
#include "zupt.h" /* for zupt_random_bytes, zupt_secure_wipe */
#include "zupt_acsl.h"
#include "zupt_jasmin.h"
#include <string.h>

/* ═══════════════════════════════════════════════════════════════════
 * MODULAR ARITHMETIC
 * q = 3329, using Barrett reduction for constant-time mod.
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * @cond PORT
 * @brief Módulo do anel de polinômios: q = 3329.
 * @endcond
 * @cond INGLES
 * @brief Polynomial ring module: q = 3329.
 * @endcond */
#define Q 3329
/**
 * @cond PORT
 * @brief Inverso multiplicativo de q módulo 2^16, na forma assinada (equivale a 62209 não assinado).
 * @endcond
 * @cond INGLES
 * @brief Multiplicative inverse of q modulo 2^16, in signed form (equivalent to 62209 unsigned).
 * @endcond */
#define QINV (-3327) /* q^(-1) mod 2^16 (signed) = 62209 unsigned */

/**
 * @cond PORT
 * @brief Redução de Barrett: devolve a representado em [-q/2, q/2] (CT-REQUIRED).
 * @details Calcula v = round(a * 2^26 / q) como (20159*a + 2^25) >> 26, onde
 * 20159 = round(2^26 / q), e retorna a - v*q. Não contém nenhuma
 * comparação ou desvio condicional: o resultado é função apenas do
 * valor de `a`, o que torna o fluxo de controle independente do
 * dado.
 * @param[in] a Valor a reduzir; o domínio esperado é o intervalo de int16_t.
 * @return    Congruente a `a` módulo q, com valor absoluto menor ou igual a q/2.
 * @note      Não idempotente em todos os valores de entrada: entradas fora do
 * intervalo podem produzir resultados ainda fora de [-q/2, q/2].
 * @endcond
 * @cond INGLES
 * @brief Barrett reduction: returns a represented in [-q/2, q/2] (CT-REQUIRED).
 * @details Computes v = round(a * 2^26 / q) as (20159*a + 2^25) >> 26, where
 * 20159 = round(2^26 / q), and returns a - v*q. It contains no
 * comparison or conditional offset: the result is a function only of the
 * value of `a`, which makes the control flow independent of the
 * data.
 * @param[in] a Value to reduce; the expected domain is the int16_t range.
 * @return    Congruent to `a` modulo q, with absolute value less than or equal to q/2.
 * @note      Not idempotent for all input values: inputs outside the
 * range may produce results still outside [-q/2, q/2].
 * @endcond */
static int16_t barrett_reduce(int16_t a) {
    /* v = round(2^26 / q) = 20159 */
    int16_t t = (int16_t)(((int32_t)20159 * a + (1 << 25)) >> 26);
    t = (int16_t)(a - t * Q);
    return t;
}

/**
 * @cond PORT
 * @brief Redução de Montgomery por 2^16 (CT-REQUIRED).
 * @details Calcula t = a * QINV mod 2^16 e retorna (a - t*q) / 2^16. Como
 * t*q ≡ a (mod 2^16), a subtração é divisível por 2^16 e a divisão
 * é uma troca aritmética exata de bits; o valor retornado é
 * congruente a a * 2^(-16) módulo q. Sem ramificações.
 * @param[in] a Produto em 32 bits a ser reduzido.
 * @return    Congruente a a * 2^(-16) módulo q.
 * @pre       `a` deve estar no intervalo que garante que a - t*q caiba em
 * 32 bits (produções de MUL16 por coeficientes de int16_t).
 * @endcond
 * @cond INGLES
 * @brief Montgomery reduction by 2^16 (CT-REQUIRED).
 * @details Computes t = a * QINV mod 2^16 and returns (a - t*q) / 2^16. Since
 * t*q ≡ a (mod 2^16), the subtraction is divisible by 2^16 and the division
 * is an exact arithmetic swap of bits; the returned value is
 * congruent to a * 2^(-16) modulo q. Branch-free.
 * @param[in] a 32-bit product to be reduced.
 * @return    Congruent to a * 2^(-16) modulo q.
 * @pre       `a` must be in the range that guarantees that a - t*q fits in
 * 32 bits (MUL16 outputs multiplied by int16_t coefficients).
 * @endcond */
static int16_t montgomery_reduce(int32_t a) {
    int16_t t = (int16_t)((int16_t)a * (int16_t)QINV);
    t = (int16_t)((a - (int32_t)t * Q) >> 16);
    return t;
}

/* CT-REQUIRED: Constant-time conditional move (no branch on b) */
#ifndef ZUPT_USE_JASMIN
/**
 * @cond PORT
 * @brief Cópia condicional por máscara de bits: r := x quando b for 1 (fallback C).
 * @details Expande o bit menos significativo de `b` na máscara 0x00 ou 0xFF
 * e aplica a identidade r ^= mask & (r ^ x) em cada byte. O laço
 * percorre `len` bytes independentemente do valor de `b`, e não há
 * desvio baseado em `b`; o tempo de execução depende apenas de `len`.
 * @param[in,out] r   Buffer de destino, atualizado condicionalmente.
 * @param[in]     x   Buffer de origem, lido integralmente.
 * @param[in]     len Número de bytes afetados.
 * @param[in]     b   Seletor: usa apenas o bit menos significativo (0 mantém, 1 copia).
 * @pre         `r` e `x` têm pelo menos `len` bytes válidos.
 * @note        Compilada somente quando ZUPT_USE_JASMIN não está definido.
 * Quando Jasmin está habilitado, zupt_ct_select_32() assume o
 * papel na decapsulação.
 * @endcond
 * @cond INGLES
 * @brief Conditional copy by bit mask: r := x when b is 1 (C fallback).
 * @details Expands the least significant bit of `b` into the mask 0x00 or 0xFF
 * and applies the identity r ^= mask & (r ^ x) on each byte. The loop
 * walks `len` bytes regardless of the value of `b`, and there is no
 * offset based on `b`; the running time depends only on `len`.
 * @param[in,out] r   Destination buffer, updated conditionally.
 * @param[in]     x   Source buffer, read in full.
 * @param[in]     len Number of bytes affected.
 * @param[in]     b   Selector: uses only the least significant bit (0 keeps, 1 copies).
 * @pre         `r` and `x` have at least `len` valid bytes.
 * @note        Compiled only when ZUPT_USE_JASMIN is not defined.
 * When Jasmin is enabled, zupt_ct_select_32() takes over the
 * role in decapsulation.
 * @endcond */
static void cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b) {
    uint8_t mask = -(uint8_t)(b & 1);
    for (size_t i = 0; i < len; i++)
        r[i] ^= mask & (r[i] ^ x[i]);
}
#endif

/* ═══════════════════════════════════════════════════════════════════
 * NTT — Number Theoretic Transform
 *
 * ζ = 17 is a primitive 256th root of unity mod 3329.
 * Zetas in Montgomery domain, bit-reversed order per FIPS 203.
 * ═══════════════════════════════════════════════════════════════════ */

/* Precomputed zetas[i] = 17^(BitRev7(i)) * R mod q, where R = 2^16 mod q
 * These are in signed representation [-q/2, q/2] */
/**
 * @cond PORT
 * @brief Tabela de raízes da NTT: zetas[i] = 17^BitRev7(i) * R mod q, em forma assinada.
 * @details Contém os 128 fatores de torção pré-computados usados por ntt(),
 * inv_ntt() e poly_basemul(): a raiz primitiva de ordem 256
 * zeta = 17 (17^256 ≡ 1 mod 3329) elevada à ordem bit-reversed de 7
 * bits, multiplicada pela constante de Montgomery R = 2^16 mod q, e
 * armazenada como int16_t. Atenção: 61 das 128 entradas são ≥ q/2
 * (= 1665), isto é, resíduos positivos congruentes a negativos — a
 * tabela não está toda no intervalo [-q/2, q/2] citado pelo comentário
 * adjacente ao código. Os primeiros 64 itens são consumidos pela
 * transformada (k cresce em ntt e decresce em inv_ntt) e os últimos
 * 64, de zetas[64], pelo produto ponto a ponto de basemul. Não contém
 * dados secretos.
 * @endcond
 * @cond INGLES
 * @brief NTT root table: zetas[i] = 17^BitRev7(i) * R mod q, in signed form.
 * @details Contains the 128 pre-computed twistor factors used by ntt(),
 * inv_ntt() and poly_basemul(): the primitive root of order 256
 * zeta = 17 (17^256 ≡ 1 mod 3329) raised to the 7-bit bit-reversed
 * order, multiplied by the Montgomery constant R = 2^16 mod q, and
 * stored as int16_t. Attention: 61 of the 128 entries are ≥ q/2
 * (= 1665), that is, positive residues congruent to negatives — the
 * table is not entirely within the interval [-q/2, q/2] stated by the
 * comment adjacent to the code. The first 64 items are consumed by the
 * transform (k grows in ntt and decreases in inv_ntt) and the last
 * 64, from zetas[64], by the pointwise basemul product. It contains
 * no secret data.
 * @endcond */
static const int16_t zetas[128] = {
  -1044,  -758,  -359, -1517,  1493,  1422,   287,   202,
   3158,   622,  1577,   182,   962,  2127,  1855,  1468,
    573,  2004,   264,   383,  2500,  1458,  1727,  3199,
   2648,  1017,   732,   608,  1787,   411,  3124,  1758,
   1223,   652,  2777,  1015,  2036,  1491,  3047,  1785,
    516,  3321,  3009,  2663,  1711,  2167,   126,  1469,
   2476,  3239,  3058,   830,   107,  1908,  3082,  2378,
   2931,   961,  1821,  2604,   448,  2264,   677,  2054,
   2226,   430,   555,   843,  2078,   871,  1550,   105,
    422,   587,   177,  3094,  3038,  2869,  1574,  1653,
   3083,   778,  1159,  3182,  2552,  1483,  2727,  1119,
   1739,   644,  2457,   349,   418,   329,  3173,  3254,
    817,  1097,   603,   610,  1322,  2044,  1864,   384,
   2114,  3193,  1218,  1994,  2455,   220,  2142,  1670,
   2144,  1799,  2051,   794,  1819,  2475,  2459,   478,
   3221,  3021,   996,   991,   958,  1869,  1522,  1628
};

/* CT-REQUIRED: NTT — no secret-dependent array indices */
/**
 * @cond PORT
 * @brief Transformada Numérica Teórica direta de 256 pontos, Cooley-Tukey decimada.
 * @details Percorre os estágios de comprimento len = 128, 64, ..., 2. Em cada
 * borboleta calcula t = zeta * r[j+len] por montgomery_reduce(), e
 * substitui o par por (r[j] + t, r[j] - t). Ao final, os coeficientes
 * estão na base da NTT com um fator de Montgomery R pendente
 * (compensado por poly_tomont() ou por basemul).
 * Os índices de tabela (`zetas[k++]`) e os limites de laço dependem
 * apenas da estrutura fixa de 256 coeficientes, não do conteúdo de
 * `r`; não há comparação de dados dentro do laço.
 * @param[in,out] r Polinômio de 256 coeficientes, transformado in-place.
 * @post        Os coeficientes ficam na forma NTT desta implementação, na
 * ordem de índice usada por poly_basemul(). O fator de escala
 * conjunto com inv_ntt() é medido na documentação de inv_ntt():
 * inv_ntt(ntt(a)) ≡ 2^16 · a (mod q).
 * @see         inv_ntt(), poly_basemul()
 * @endcond
 * @cond INGLES
 * @brief Forward 256-point Number Theoretic Transform, decimated Cooley-Tukey.
 * @details Walks the stages of length len = 128, 64, ..., 2. In each
 * butterfly it computes t = zeta * r[j+len] by montgomery_reduce(), and
 * replaces the pair with (r[j] + t, r[j] - t). At the end, the coefficients
 * are in the NTT base with a pending Montgomery factor R
 * (compensated by poly_tomont() or by basemul).
 * The table indices (`zetas[k++]`) and the loop bounds depend
 * only on the fixed structure of 256 coefficients, not on the content of
 * `r`; there is no data comparison inside the loop.
 * @param[in,out] r Polynomial of 256 coefficients, transformed in-place.
 * @post        The coefficients are left in the NTT form of this implementation, in the
 * index order used by poly_basemul(). The scale factor
 * taken together with inv_ntt() is measured in the documentation of inv_ntt():
 * inv_ntt(ntt(a)) ≡ 2^16 · a (mod q).
 * @see         inv_ntt(), poly_basemul()
 * @endcond */
static void ntt(int16_t r[256]) {
    int k = 1;
    for (int len = 128; len >= 2; len >>= 1) {
        for (int start = 0; start < 256; start += 2*len) {
            int16_t zeta = zetas[k++];
            for (int j = start; j < start + len; j++) {
                int16_t t = montgomery_reduce((int32_t)zeta * r[j + len]);
                r[j + len] = r[j] - t;
                r[j] = r[j] + t;
            }
        }
    }
}

/* Inverse NTT per reference pqcrystals/kyber — uses SAME zetas table, k counts down.
 * Final scaling by f = 1441 (mont^{-1} * n^{-1} mod q). */
/**
 * @cond PORT
 * @brief NTT inversa: reconstrói o polinômio padrão a partir da forma NTT.
 * @details Executa o esquema de Gentleman-Sande de ponta a cabeça da
 * transformada direta (len = 2, 4, ..., 128), consumindo a MESMA
 * tabela zetas com k decrescendo de 127. Cada borboleta faz
 * r[j] = Barrett(r[j] + r[j+len]) e
 * r[j+len] = montgomery(zeta * (r[j+len] - t)). Termina aplicando
 * montgomery_reduce(1441 * r[i]) a todos os coeficientes, o que
 * equivale a multiplicá-los por 1441 · R^(-1) = 512 mod q.
 * O efeito combinado das duas transformadas é
 * inv_ntt(ntt(a)) ≡ R · a = 2^16 · a (mod q), medido
 * experimentalmente: o resultado fica no domínio de Montgomery
 * (semântica "invntt_tomont" da referência pqcrystals/kyber), e não
 * no domínio plano. Estrutura de laço fixa; nenhum índice depende
 * dos dados.
 * @param[in,out] r Polinômio de 256 coeficientes na forma NTT, convertido in-place.
 * @see         ntt()
 * @endcond
 * @cond INGLES
 * @brief Inverse NTT: reconstructs the standard polynomial from the NTT form.
 * @details Runs the Gentleman-Sande scheme from the end to the head of the
 * forward transform (len = 2, 4, ..., 128), consuming the SAME
 * zetas table with k decreasing from 127. Each butterfly does
 * r[j] = Barrett(r[j] + r[j+len]) and
 * r[j+len] = montgomery(zeta * (r[j+len] - t)). It ends by applying
 * montgomery_reduce(1441 * r[i]) to all coefficients, which
 * is equivalent to multiplying them by 1441 · R^(-1) = 512 mod q.
 * The combined effect of the two transforms is
 * inv_ntt(ntt(a)) ≡ R · a = 2^16 · a (mod q), measured
 * experimentally: the result stays in the Montgomery domain
 * ("invntt_tomont" semantics of the pqcrystals/kyber reference), and not
 * in the plain domain. Fixed loop structure; no index depends
 * on the data.
 * @param[in,out] r Polynomial of 256 coefficients in NTT form, converted in-place.
 * @see         ntt()
 * @endcond */
static void inv_ntt(int16_t r[256]) {
    int k = 127;
    for (int len = 2; len <= 128; len <<= 1) {
        for (int start = 0; start < 256; start += 2*len) {
            int16_t zeta = zetas[k--];
            for (int j = start; j < start + len; j++) {
                int16_t t = r[j];
                r[j] = barrett_reduce(t + r[j + len]);
                r[j + len] = montgomery_reduce((int32_t)zeta * (r[j + len] - t));
            }
        }
    }
    /* Multiply by f = 1441 = mont^{-1} * 128^{-1} mod q */
    for (int i = 0; i < 256; i++)
        r[i] = montgomery_reduce((int32_t)1441 * r[i]);
}

/* ═══════════════════════════════════════════════════════════════════
 * POLYNOMIAL OPERATIONS
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * @cond PORT
 * @typedef poly
 * @brief Polinômio de 256 coeficientes int16_t sobre Z_q, com q = 3329.
 * @details O índice do array corresponde à potência de x; o anel é
 * Z_q[x]/(x^256 + 1). Fora das fronteiras de codificação, um
 * coeficiente pode ser negativo ou exceder q; apenas poly_reduce(),
 * a codificação em bytes e a compressão normalizam o valor.
 * @see     polyvec, poly_reduce()
 * @endcond
 * @cond INGLES
 * @typedef poly
 * @brief Polynomial of 256 int16_t coefficients over Z_q, with q = 3329.
 * @details The array index corresponds to the power of x; the ring is
 * Z_q[x]/(x^256 + 1). Outside of the encoding boundaries, a
 * coefficient may be negative or exceed q; only poly_reduce(),
 * the byte encoding and the compression normalize the value.
 * @see     polyvec, poly_reduce()
 * @endcond */
typedef int16_t poly[256];
/**
 * @cond PORT
 * @typedef polyvec
 * @brief Vetor de MLKEM_K (= 3) polinômios, isto é, um array de poly.
 * @details Usado para s, e, t_hat, A_hat e u. Sendo poly um typedef de
 * array, polyvec é um array de arrays; isso impede a conversão
 * multi-nível para const em C11 (ver polyvec_pointwise_acc()).
 * @endcond
 * @cond INGLES
 * @typedef polyvec
 * @brief Vector of MLKEM_K (= 3) polynomials, that is, an array of poly.
 * @details Used for s, e, t_hat, A_hat and u. Since poly is a typedef of
 * array, polyvec is an array of arrays; this prevents the
 * multi-level conversion to const in C11 (see polyvec_pointwise_acc()).
 * @endcond */
typedef poly polyvec[MLKEM_K];

/* Pointwise multiply in NTT domain (basemul per FIPS 203 §4.4)
 * CT-REQUIRED: No secret-dependent branches.
 * Reference: pqcrystals/kyber basemul — each fqmul is a separate montgomery_reduce.
 * r[0] = fqmul(fqmul(a1,b1), zeta) + fqmul(a0,b0)
 * r[1] = fqmul(a0,b1) + fqmul(a1,b0)
 * Second pair uses -zeta. */
/**
 * @cond PORT
 * @brief Produto ponto a ponto de dois pares de coeficientes na NTT (basemul).
 * @details Bloco elementar do produto de polinômios em NTT (FIPS 203 §4.4):
 * calcula o produto no quociente Z_q[x]/(x^2 - zeta). Cada produto
 * de coeficientes é uma multiplicação de Montgomery separada, o que
 * acumula um fator R^(-1) por chamada. As seis operações são
 * executadas sempre, sem comparação sobre os dados.
 * @param[out] r     Par de coeficientes de saída (2 int16_t).
 * @param[in]  a     Par de coeficientes do primeiro fator.
 * @param[in]  b     Par de coeficientes do segundo fator.
 * @param[in]  zeta  Fator de torção do par; poly_basemul() passa -zeta no
 * segundo par.
 * @pre       Cada elemento de `a`, `b` e `zeta` cabe em int16_t.
 * @see       poly_basemul(), montgomery_reduce()
 * @endcond
 * @cond INGLES
 * @brief Pointwise product of two coefficient pairs in the NTT (basemul).
 * @details Elementary block of the polynomial product in the NTT (FIPS 203 §4.4):
 * computes the product in the quotient Z_q[x]/(x^2 - zeta). Each
 * coefficient product is a separate Montgomery multiplication, which
 * accumulates a factor R^(-1) per call. The six operations are
 * always executed, with no comparison on the data.
 * @param[out] r     Output coefficient pair (2 int16_t).
 * @param[in]  a     Coefficient pair of the first factor.
 * @param[in]  b     Coefficient pair of the second factor.
 * @param[in]  zeta  Twistor factor of the pair; poly_basemul() passes -zeta on the
 * second pair.
 * @pre       Each element of `a`, `b` and `zeta` fits in int16_t.
 * @see       poly_basemul(), montgomery_reduce()
 * @endcond */
static void basemul_pair(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta) {
    r[0] = montgomery_reduce((int32_t)montgomery_reduce((int32_t)a[1] * b[1]) * zeta);
    r[0] = (int16_t)(r[0] + montgomery_reduce((int32_t)a[0] * b[0]));
    r[1] = montgomery_reduce((int32_t)a[0] * b[1]);
    r[1] = (int16_t)(r[1] + montgomery_reduce((int32_t)a[1] * b[0]));
}

/**
 * @cond PORT
 * @brief Produto de polinômios no domínio da NTT (basemul de 256 coeficientes).
 * @details Decompõe o anel Z_q[x]/(x^256+1) em 64 sub-anelos de grau 2. Para
 * cada bloco i, aplica basemul_pair() com zeta = zetas[64+i] sobre a
 * primeira dupla e com -zetas[64+i] sobre a segunda, o que
 * corresponde às raízes ±zeta do quociente. O laço percorre sempre
 * as 64 posições; nenhum índice depende dos dados.
 * @param[out] r Resultado em NTT: r = a ∘ b (produto de Montgomery).
 * @param[in]  a Primeiro fator em NTT.
 * @param[in]  b Segundo fator em NTT.
 * @note       O resultado carrega um fator R^(-1) relativo ao produto exato;
 * poly_tomont() o compensa quando necessário.
 * @see        basemul_pair(), poly_tomont()
 * @endcond
 * @cond INGLES
 * @brief Polynomial product in the NTT domain (basemul of 256 coefficients).
 * @details Decomposes the ring Z_q[x]/(x^256+1) into 64 sub-rings of degree 2. For
 * each block i, it applies basemul_pair() with zeta = zetas[64+i] on the
 * first pair and with -zetas[64+i] on the second, which
 * corresponds to the roots ±zeta of the quotient. The loop always walks
 * the 64 positions; no index depends on the data.
 * @param[out] r Result in the NTT: r = a ∘ b (Montgomery product).
 * @param[in]  a First factor in the NTT.
 * @param[in]  b Second factor in the NTT.
 * @note       The result carries a factor R^(-1) relative to the exact product;
 * poly_tomont() compensates for it when needed.
 * @see        basemul_pair(), poly_tomont()
 * @endcond */
static void poly_basemul(poly r, const poly a, const poly b) {
    for (int i = 0; i < 64; i++) {
        basemul_pair(&r[4*i],   &a[4*i],   &b[4*i],    zetas[64 + i]);
        basemul_pair(&r[4*i+2], &a[4*i+2], &b[4*i+2], (int16_t)(-zetas[64 + i]));
    }
}

/**
 * @cond PORT
 * @brief Soma dois polinômios coeficiente a coeficiente, sem redução modilar.
 * @param[out] r Resultado (pode sobrepor a ou b).
 * @param[in]  a Parcela.
 * @param[in]  b Parcela.
 * @note       Não reduz: os resultados podem exceder o intervalo [-Q, Q] e
 * precisam de poly_reduce() antes de qualquer serialização.
 * @endcond
 * @cond INGLES
 * @brief Adds two polynomials coefficient by coefficient, without modular reduction.
 * @param[out] r Result (may overlap a or b).
 * @param[in]  a Addend.
 * @param[in]  b Addend.
 * @note       Does not reduce: the results may exceed the interval [-Q, Q] and
 * need poly_reduce() before any serialization.
 * @endcond */
static void poly_add(poly r, const poly a, const poly b) {
    for (int i = 0; i < 256; i++) r[i] = a[i] + b[i];
}

/**
 * @cond PORT
 * @brief Subtrai dois polinômios coeficiente a coeficiente, sem redução modilar.
 * @param[out] r Resultado (pode sobrepor a ou b).
 * @param[in]  a Minuendo.
 * @param[in]  b Subtraendo.
 * @note       Mesmo comportamento de poly_add(): nenhuma redução é aplicada.
 * @endcond
 * @cond INGLES
 * @brief Subtracts two polynomials coefficient by coefficient, without modular reduction.
 * @param[out] r Result (may overlap a or b).
 * @param[in]  a Minuend.
 * @param[in]  b Subtrahend.
 * @note       Same behavior as poly_add(): no reduction is applied.
 * @endcond */
static void poly_sub(poly r, const poly a, const poly b) {
    for (int i = 0; i < 256; i++) r[i] = a[i] - b[i];
}

/**
 * @cond PORT
 * @brief Reduz todos os coeficientes de um polinômio para o intervalo padrão.
 * @param[in,out] r Polinômio reduzido no lugar.
 * @see           barrett_reduce()
 * @endcond
 * @cond INGLES
 * @brief Reduces all coefficients of a polynomial to the standard interval.
 * @param[in,out] r Polynomial reduced in place.
 * @see           barrett_reduce()
 * @endcond */
static void poly_reduce(poly r) {
    for (int i = 0; i < 256; i++) r[i] = barrett_reduce(r[i]);
}

/**
 * @cond PORT
 * @brief Constante 2³² mod Q = 1353, usada para levar coeficientes ao domínio de Montgomery.
 * @endcond
 * @cond INGLES
 * @brief Constant 2³² mod Q = 1353, used to bring coefficients into the Montgomery domain.
 * @endcond */
#define TOMONT_CONST 1353  /* 2^32 mod 3329 — verified: 4294967296 mod 3329 = 1353 */

/**
 * @cond PORT
 * @brief Converte um polinômio para o domínio de Montgomery (multiplica por R = 2¹⁶).
 * @param[in,out] r Polinômio convertido no lugar.
 * @details       Aplica mont(r[i]) = r[i] · TOMONT_CONST · R⁻¹ mod Q. Como
 * TOMONT_CONST = 2³² mod Q, o resultado é r[i] · 2³² · 2⁻¹⁶ = r[i]·R.
 * A compensação é necessária porque poly_basemul() acumula produtos com
 * um fator R⁻¹ por multiplicação.
 * @see           poly_basemul(), montgomery_reduce()
 * @endcond
 * @cond INGLES
 * @brief Converts a polynomial to the Montgomery domain (multiplies by R = 2¹⁶).
 * @param[in,out] r Polynomial converted in place.
 * @details       Applies mont(r[i]) = r[i] · TOMONT_CONST · R⁻¹ mod Q. Since
 * TOMONT_CONST = 2³² mod Q, the result is r[i] · 2³² · 2⁻¹⁶ = r[i]·R.
 * The compensation is needed because poly_basemul() accumulates products with
 * a factor R⁻¹ per multiplication.
 * @see           poly_basemul(), montgomery_reduce()
 * @endcond */
static void poly_tomont(poly r) {
    for (int i = 0; i < 256; i++)
        r[i] = montgomery_reduce((int32_t)r[i] * TOMONT_CONST);
}

/**
 * @cond PORT
 * @brief Aplica a NTT direta nos k polinômios de um polyvec.
 * @param[in,out] pv Polinômios transformados no lugar.
 * @see           ntt()
 * @endcond
 * @cond INGLES
 * @brief Applies the forward NTT to the k polynomials of a polyvec.
 * @param[in,out] pv Polynomials transformed in place.
 * @see           ntt()
 * @endcond */
static void polyvec_ntt(polyvec pv) {
    for (int i = 0; i < MLKEM_K; i++) ntt(pv[i]);
}

/**
 * @cond PORT
 * @brief Aplica a NTT inversa nos k polinômios de um polyvec.
 * @param[in,out] pv Polinômios transformados no lugar.
 * @see           inv_ntt()
 * @endcond
 * @cond INGLES
 * @brief Applies the inverse NTT to the k polynomials of a polyvec.
 * @param[in,out] pv Polynomials transformed in place.
 * @see           inv_ntt()
 * @endcond */
static void polyvec_invntt(polyvec pv) {
    for (int i = 0; i < MLKEM_K; i++) inv_ntt(pv[i]);
}

/* C11 §6.7.3: arrays-of-arrays cannot undergo multi-level const conversion.
 * Reference pqcrystals/kyber uses non-const polyvec parameters for the same reason.
 * These functions do not modify the input arrays. */
/**
 * @cond PORT
 * @brief Acumula o produto interno de dois polyvecs no domínio da NTT.
 * @param[out] r Resultado: r = Σᵢ basemul(a[i], b[i]), reduzido mod Q.
 * @param[in]  a Polinômios em NTT (MLKEM_K entradas).
 * @param[in]  b Polinômios em NTT (MLKEM_K entradas).
 * @details    Executa poly_basemul() para cada par e soma os resultados com
 * poly_add(), que não reduz; por isso poly_reduce() é aplicado no
 * final para manter os coeficientes dentro de [-Q, Q].
 * @see        poly_basemul(), poly_reduce()
 * @endcond
 * @cond INGLES
 * @brief Accumulates the inner product of two polyvecs in the NTT domain.
 * @param[out] r Result: r = Σᵢ basemul(a[i], b[i]), reduced mod Q.
 * @param[in]  a Polynomials in the NTT (MLKEM_K entries).
 * @param[in]  b Polynomials in the NTT (MLKEM_K entries).
 * @details    Runs poly_basemul() for each pair and sums the results with
 * poly_add(), which does not reduce; for this reason poly_reduce() is applied
 * at the end to keep the coefficients within [-Q, Q].
 * @see        poly_basemul(), poly_reduce()
 * @endcond */
static void polyvec_pointwise_acc(poly r, polyvec a, polyvec b) {
    poly t;
    poly_basemul(r, a[0], b[0]);
    for (int i = 1; i < MLKEM_K; i++) {
        poly_basemul(t, a[i], b[i]);
        poly_add(r, r, t);
    }
    poly_reduce(r);
}

/* ═══════════════════════════════════════════════════════════════════
 * SAMPLING
 * ═══════════════════════════════════════════════════════════════════ */

/* CBD(η=2): sample polynomial from centered binomial distribution */
/**
 * @cond PORT
 * @brief Amostra um polinômio da distribuição binomial centrada CBD(η = 2).
 * @param[out] r   Polinômio amostrado; cada coeficiente fica em [-2, 2].
 * @param[in]  buf 128 bytes de bytes aleatórios (η·N/4 = 2·256/4).
 * @details    Processa 4 bits por coeficiente: lê palavras de 32 bits
 * (little-endian), soma os pares de bits adjacentes com aritmética
 * de máscara (0x55555555) e produz r[i] = a − b, onde a e b são as
 * parcelas de 2 bits consecutivas. Nenhum desvio de fluxo depende
 * dos dados: os laços percorrem sempre os 32 bytes inteiros.
 * @see        poly_noise()
 * @endcond
 * @cond INGLES
 * @brief Samples a polynomial from the centered binomial distribution CBD(η = 2).
 * @param[out] r   Sampled polynomial; each coefficient stays in [-2, 2].
 * @param[in]  buf 128 bytes of random bytes (η·N/4 = 2·256/4).
 * @details    Processes 4 bits per coefficient: reads 32-bit words
 * (little-endian), sums adjacent bit pairs with mask arithmetic
 * (0x55555555) and produces r[i] = a − b, where a and b are the
 * consecutive 2-bit addends. No control-flow offset depends
 * on the data: the loops always walk the 32 whole bytes.
 * @see        poly_noise()
 * @endcond */
static void cbd2(poly r, const uint8_t buf[128]) {
    for (int i = 0; i < 256/8; i++) {
        uint32_t t = (uint32_t)buf[4*i] | ((uint32_t)buf[4*i+1] << 8) |
                     ((uint32_t)buf[4*i+2] << 16) | ((uint32_t)buf[4*i+3] << 24);
        uint32_t d = (t & 0x55555555) + ((t >> 1) & 0x55555555);
        for (int j = 0; j < 8; j++) {
            int16_t a = (int16_t)((d >> (4*j)) & 3);
            int16_t b = (int16_t)((d >> (4*j+2)) & 3);
            r[8*i+j] = a - b;
        }
    }
}

/* Sample polynomial uniformly from SHAKE-128 stream (rejection sampling) */
/**
 * @cond PORT
 * @brief Amostra um polinômio com distribuição uniforme por rejeição.
 * @param[out] r    Polinômio resultante com coeficientes em [0, Q−1].
 * @param[in]  seed Semente de 32 bytes (eta do algoritmo ou seedB).
 * @param[in]  i    Índice da linha da matriz.
 * @param[in]  j    Índice da coluna da matriz.
 * @details    Deriva a semente estendida `seed || i || j` (34 bytes), gera o
 * fluxo com SHAKE-128 e agrupa 3 bytes em dois candidatos de 12
 * bits (d1 = bits 0–11, d2 = bits 12–23). Candidatos ≥ Q são
 * descartados (rejeição). O laço roda até obter os 256
 * coeficientes, portanto o número de iterações depende dos dados —
 * ver finding sobre o padrão de rejeição.
 * @see        zupt_shake128_squeeze()
 * @endcond
 * @cond INGLES
 * @brief Samples a polynomial with a uniform distribution by rejection.
 * @param[out] r    Resulting polynomial with coefficients in [0, Q−1].
 * @param[in]  seed 32-byte seed (the algorithm's eta or seedB).
 * @param[in]  i    Row index of the matrix.
 * @param[in]  j    Column index of the matrix.
 * @details    Derives the extended seed `seed || i || j` (34 bytes), generates the
 * stream with SHAKE-128 and groups 3 bytes into two 12-bit candidates
 * (d1 = bits 0–11, d2 = bits 12–23). Candidates ≥ Q are
 * discarded (rejection). The loop runs until the 256
 * coefficients are obtained, therefore the number of iterations depends on
 * the data — see the finding on the rejection pattern.
 * @see        zupt_shake128_squeeze()
 * @endcond */
static void poly_uniform(poly r, const uint8_t seed[32], uint8_t i, uint8_t j) {
    uint8_t extseed[34];
    memcpy(extseed, seed, 32);
    extseed[32] = i;
    extseed[33] = j;

    zupt_keccak_ctx ctx;
    zupt_shake128_init(&ctx);
    zupt_shake128_absorb(&ctx, extseed, 34);
    zupt_shake128_finalize(&ctx);

    int ctr = 0;
    while (ctr < 256) {
        uint8_t buf[3];
        zupt_shake128_squeeze(&ctx, buf, 3);
        uint16_t d1 = ((uint16_t)buf[0] | ((uint16_t)(buf[1] & 0x0F) << 8));
        uint16_t d2 = ((uint16_t)(buf[1] >> 4) | ((uint16_t)buf[2] << 4));
        if (d1 < Q) r[ctr++] = (int16_t)d1;
        if (ctr < 256 && d2 < Q) r[ctr++] = (int16_t)d2;
    }
}

/* Sample noise polynomial via PRF (SHAKE-256) + CBD */
/**
 * @cond PORT
 * @brief Amostra um polinômio de ruído (eta = 2) via PRF + CBD.
 * @param[out] r     Polinômio de ruído com coeficientes em [-2, 2].
 * @param[in]  seed  Semente secreta (d do keygen ou r da cifra).
 * @param[in]  nonce Byte de domínio que separa cada polinômio amostrado.
 * @details    Gera 128 bytes com SHAKE-256 sobre `seed || nonce` e aplica
 * CBD(η = 2). Uso: s, e no keygen; r, e₁, e₂ na cifra.
 * @see        cbd2()
 * @endcond
 * @cond INGLES
 * @brief Samples a noise polynomial (eta = 2) via PRF + CBD.
 * @param[out] r     Noise polynomial with coefficients in [-2, 2].
 * @param[in]  seed  Secret seed (d in key generation or r in encryption).
 * @param[in]  nonce Domain byte that separates each sampled polynomial.
 * @details    Generates 128 bytes with SHAKE-256 over `seed || nonce` and applies
 * CBD(η = 2). Usage: s, e in key generation; r, e₁, e₂ in encryption.
 * @see        cbd2()
 * @endcond */
static void poly_noise(poly r, const uint8_t seed[32], uint8_t nonce) {
    uint8_t extseed[33];
    memcpy(extseed, seed, 32);
    extseed[32] = nonce;
    uint8_t buf[128]; /* η*N/4 = 2*256/4 = 128 */
    zupt_shake256(extseed, 33, buf, 128);
    cbd2(r, buf);
}

/* ═══════════════════════════════════════════════════════════════════
 * ENCODE / DECODE
 * ═══════════════════════════════════════════════════════════════════ */

/* Encode polynomial with d bits per coefficient */
/**
 * @cond PORT
 * @brief Serializa um polinômio em 12 bits por coeficiente (ByteEncode₁₂).
 * @param[out] r Buffer de saída com 384 bytes (3 bytes por par de coeficientes).
 * @param[in]  a Polinômio de entrada.
 * @details    Normaliza cada coeficiente para [0, Q−1] com `((x % Q) + Q) % Q`
 * e empacota dois valores de 12 bits little-endian em 3 bytes.
 * @see        poly_frombytes()
 * @endcond
 * @cond INGLES
 * @brief Serializes a polynomial in 12 bits per coefficient (ByteEncode₁₂).
 * @param[out] r Output buffer with 384 bytes (3 bytes per pair of coefficients).
 * @param[in]  a Input polynomial.
 * @details    Normalizes each coefficient to [0, Q−1] with `((x % Q) + Q) % Q`
 * and packs two 12-bit values little-endian into 3 bytes.
 * @see        poly_frombytes()
 * @endcond */
static void poly_tobytes(uint8_t *r, const poly a) {
    /* 12 bits per coefficient, 256 coeffs = 384 bytes */
    for (int i = 0; i < 256/2; i++) {
        uint16_t t0 = (uint16_t)((a[2*i] % Q + Q) % Q);
        uint16_t t1 = (uint16_t)((a[2*i+1] % Q + Q) % Q);
        r[3*i]   = (uint8_t)(t0);
        r[3*i+1] = (uint8_t)((t0 >> 8) | (t1 << 4));
        r[3*i+2] = (uint8_t)(t1 >> 4);
    }
}

/**
 * @cond PORT
 * @brief Reconstrói um polinômio a partir de ByteEncode₁₂ (384 bytes).
 * @param[out] r Polinômio reconstruído; coeficientes em [0, 4095].
 * @param[in]  a Buffer de entrada com 384 bytes.
 * @note       Não valida nem reduz: valores acima de Q são preservados como
 * vieram do buffer, comportamento esperado do ByteDecode₁₂.
 * @see        poly_tobytes()
 * @endcond
 * @cond INGLES
 * @brief Reconstructs a polynomial from ByteEncode₁₂ (384 bytes).
 * @param[out] r Reconstructed polynomial; coefficients in [0, 4095].
 * @param[in]  a Input buffer with 384 bytes.
 * @note       Does not validate nor reduce: values above Q are kept as
 * they came from the buffer, the expected behavior of ByteDecode₁₂.
 * @see        poly_tobytes()
 * @endcond */
static void poly_frombytes(poly r, const uint8_t *a) {
    for (int i = 0; i < 256/2; i++) {
        r[2*i]   = (int16_t)(((uint16_t)a[3*i] | ((uint16_t)(a[3*i+1] & 0x0F) << 8)));
        r[2*i+1] = (int16_t)(((uint16_t)(a[3*i+1] >> 4) | ((uint16_t)a[3*i+2] << 4)));
    }
}

/* Compress: round(2^d / q * x) mod 2^d */
/**
 * @cond PORT
 * @brief Comprime um polinômio para d bits por coeficiente (Compress_q,ₔ).
 * @param[out] r Buffer de saída: 320 bytes com d = 10, 128 bytes com d = 4.
 * @param[in]  a Polinômio de entrada.
 * @param[in]  d Número de bits por coeficiente. Apenas 10 (componente u) e
 * 4 (componente v) são suportados.
 * @details    Aplica `round(2^d·x / Q) mod 2^d` com arredondamento "round half up"
 * implementado como `(x·2^d + Q/2) / Q`, após normalizar x para
 * [0, Q−1]. Se d não for 10 nem 4, a função não escreve nada no
 * buffer de saída (nenhum else cobre outros valores).
 * @see        poly_decompress()
 * @endcond
 * @cond INGLES
 * @brief Compresses a polynomial to d bits per coefficient (Compress_q,ₔ).
 * @param[out] r Output buffer: 320 bytes with d = 10, 128 bytes with d = 4.
 * @param[in]  a Input polynomial.
 * @param[in]  d Number of bits per coefficient. Only 10 (the u component) and
 * 4 (the v component) are supported.
 * @details    Applies `round(2^d·x / Q) mod 2^d` with "round half up" rounding
 * implemented as `(x·2^d + Q/2) / Q`, after normalizing x to
 * [0, Q−1]. If d is neither 10 nor 4, the function writes nothing to the
 * output buffer (no else covers other values).
 * @see        poly_decompress()
 * @endcond */
static void poly_compress(uint8_t *r, const poly a, int d) {
    if (d == 10) {
        /* 10 bits per coeff, 256 coeffs = 320 bytes */
        for (int i = 0; i < 256/4; i++) {
            uint16_t t[4];
            for (int j = 0; j < 4; j++) {
                int16_t x = a[4*i+j];
                x = (int16_t)((x % Q + Q) % Q);
                t[j] = (uint16_t)(((uint32_t)x * (1 << d) + Q/2) / Q);
                t[j] &= (1 << d) - 1;
            }
            r[5*i]   = (uint8_t)(t[0]);
            r[5*i+1] = (uint8_t)((t[0] >> 8) | (t[1] << 2));
            r[5*i+2] = (uint8_t)((t[1] >> 6) | (t[2] << 4));
            r[5*i+3] = (uint8_t)((t[2] >> 4) | (t[3] << 6));
            r[5*i+4] = (uint8_t)(t[3] >> 2);
        }
    } else if (d == 4) {
        /* 4 bits per coeff = 128 bytes */
        for (int i = 0; i < 256/2; i++) {
            uint8_t t0, t1;
            int16_t x0 = (int16_t)((a[2*i] % Q + Q) % Q);
            int16_t x1 = (int16_t)((a[2*i+1] % Q + Q) % Q);
            t0 = (uint8_t)(((uint32_t)x0 * 16 + Q/2) / Q) & 0xF;
            t1 = (uint8_t)(((uint32_t)x1 * 16 + Q/2) / Q) & 0xF;
            r[i] = t0 | (t1 << 4);
        }
    }
}

/**
 * @cond PORT
 * @brief Descomprime d bits por coeficiente de volta ao anel Z_q (Decompress_q,ₔ).
 * @param[out] r Polinômio reconstruído.
 * @param[in]  a Buffer de entrada: 320 bytes com d = 10, 128 bytes com d = 4.
 * @param[in]  d Bits por coeficiente; apenas 10 e 4 são suportados.
 * @details    Reconstrói com `(t·Q + 2^(d−1)) >> d`, o que aproxima t de `round(t·Q/2^d)`.
 * Os valores resultantes não são exatamente os originais — apenas o
 * intervalo aproximado é preservado, que é o objetivo da compressão.
 * @warning    Para d ≠ 10 e d ≠ 4 nenhum coeficiente é escrito (ausência de else).
 * @see        poly_compress()
 * @endcond
 * @cond INGLES
 * @brief Decompresses d bits per coefficient back into the ring Z_q (Decompress_q,ₔ).
 * @param[out] r Reconstructed polynomial.
 * @param[in]  a Input buffer: 320 bytes with d = 10, 128 bytes with d = 4.
 * @param[in]  d Bits per coefficient; only 10 and 4 are supported.
 * @details    Reconstructs with `(t·Q + 2^(d−1)) >> d`, which approximates t by `round(t·Q/2^d)`.
 * The resulting values are not exactly the originals — only the
 * approximate range is preserved, which is the goal of compression.
 * @warning    For d ≠ 10 and d ≠ 4 no coefficient is written (absence of else).
 * @see        poly_compress()
 * @endcond */
static void poly_decompress(poly r, const uint8_t *a, int d) {
    if (d == 10) {
        for (int i = 0; i < 256/4; i++) {
            uint16_t t[4];
            t[0] = ((uint16_t)a[5*i] | ((uint16_t)(a[5*i+1] & 3) << 8));
            t[1] = ((uint16_t)(a[5*i+1] >> 2) | ((uint16_t)(a[5*i+2] & 0xF) << 6));
            t[2] = ((uint16_t)(a[5*i+2] >> 4) | ((uint16_t)(a[5*i+3] & 0x3F) << 4));
            t[3] = ((uint16_t)(a[5*i+3] >> 6) | ((uint16_t)a[5*i+4] << 2));
            for (int j = 0; j < 4; j++)
                r[4*i+j] = (int16_t)(((uint32_t)(t[j] & 0x3FF) * Q + 512) >> 10);
        }
    } else if (d == 4) {
        for (int i = 0; i < 256/2; i++) {
            r[2*i]   = (int16_t)(((uint32_t)(a[i] & 0xF) * Q + 8) >> 4);
            r[2*i+1] = (int16_t)(((uint32_t)(a[i] >> 4) * Q + 8) >> 4);
        }
    }
}

/* Polyvec encode/decode (12 bits per coeff) */
/**
 * @cond PORT
 * @brief Serializa os k polinômios de um polyvec em 384·k bytes (12 bits por coeficiente).
 * @param[out] r Buffer de saída (MLKEM_K·384 bytes).
 * @param[in]  a Polyvec de entrada.
 * @see        poly_tobytes()
 * @endcond
 * @cond INGLES
 * @brief Serializes the k polynomials of a polyvec into 384·k bytes (12 bits per coefficient).
 * @param[out] r Output buffer (MLKEM_K·384 bytes).
 * @param[in]  a Input polyvec.
 * @see        poly_tobytes()
 * @endcond */
static void polyvec_tobytes(uint8_t *r, polyvec a) {
    for (int i = 0; i < MLKEM_K; i++) poly_tobytes(r + i*384, a[i]);
}

/**
 * @cond PORT
 * @brief Reconstrói um polyvec a partir de 384·k bytes serializados.
 * @param[out] r Polyvec reconstruído.
 * @param[in]  a Buffer de entrada (MLKEM_K·384 bytes).
 * @see        poly_frombytes()
 * @endcond
 * @cond INGLES
 * @brief Reconstructs a polyvec from 384·k serialized bytes.
 * @param[out] r Reconstructed polyvec.
 * @param[in]  a Input buffer (MLKEM_K·384 bytes).
 * @see        poly_frombytes()
 * @endcond */
static void polyvec_frombytes(polyvec r, const uint8_t *a) {
    for (int i = 0; i < MLKEM_K; i++) poly_frombytes(r[i], a + i*384);
}

/**
 * @cond PORT
 * @brief Comprime um polyvec com MLKEM_DU (10) bits por coeficiente.
 * @param[out] r Buffer de saída (MLKEM_K·320 bytes = 1280 bytes para k = 4).
 * @param[in]  a Polyvec de entrada (componente u da cifra).
 * @see        poly_compress()
 * @endcond
 * @cond INGLES
 * @brief Compresses a polyvec with MLKEM_DU (10) bits per coefficient.
 * @param[out] r Output buffer (MLKEM_K·320 bytes = 1280 bytes for k = 4).
 * @param[in]  a Input polyvec (the u component of the ciphertext).
 * @see        poly_compress()
 * @endcond */
static void polyvec_compress(uint8_t *r, polyvec a) {
    for (int i = 0; i < MLKEM_K; i++) poly_compress(r + i*320, a[i], MLKEM_DU);
}

/**
 * @cond PORT
 * @brief Descomprime um polyvec comprimido com MLKEM_DU (10) bits por coeficiente.
 * @param[out] r Polyvec reconstruído.
 * @param[in]  a Buffer de entrada (MLKEM_K·320 bytes = 1280 bytes para k = 4).
 * @see        poly_decompress()
 * @endcond
 * @cond INGLES
 * @brief Decompresses a polyvec compressed with MLKEM_DU (10) bits per coefficient.
 * @param[out] r Reconstructed polyvec.
 * @param[in]  a Input buffer (MLKEM_K·320 bytes = 1280 bytes for k = 4).
 * @see        poly_decompress()
 * @endcond */
static void polyvec_decompress(polyvec r, const uint8_t *a) {
    for (int i = 0; i < MLKEM_K; i++) poly_decompress(r[i], a + i*320, MLKEM_DU);
}

/* ═══════════════════════════════════════════════════════════════════
 * K-PKE: IND-CPA-secure public key encryption (FIPS 203 §7.2-7.3)
 * ═══════════════════════════════════════════════════════════════════ */

/* Generate K-PKE keypair. d = random 32-byte seed. */
/**
 * @cond PORT
 * @brief Gera o par de chaves do esquema K-PKE subjacente (FIPS 203 §6.10).
 * @param[out] pk      Chave pública K-PKE: 1184 bytes (k·384 de t̂ em NTT + 32 de ρ).
 * @param[out] sk_pke Chave secreta K-PKE: 1152 bytes (k·384 de ŝ serializados em NTT).
 * @param[in]  d      Semente de 32 bytes (aleatória ou derivada pelo encapsulamento).
 * @details    Deriva `G(d ‖ k)` com SHA3-512, obtendo ρ (semente da matriz) e σ
 * (semente de ruído). A matriz Â é amostrada por rejeição com
 * `Uniform(ρ, j, i)` — índices trocados de propósito, porque a cifra
 * consome Aᵀ e precisa regerar exatamente os mesmos coeficientes.
 * Depois: ŝ, ê ← CBD(η=2) com σ (nonces 0..k−1 e k..2k−1),
 * t̂ = Â∘ŝ + ê, sendo poly_tomont() aplicado após o acumulador para
 * compensar o fator R⁻¹ da multiplicação de Montgomery.
 * @post       buf, s e e são limpos com zupt_secure_wipe() antes do retorno.
 * @see        poly_uniform(), poly_noise(), polyvec_pointwise_acc(), poly_tomont()
 * @endcond
 * @cond INGLES
 * @brief Generates the key pair of the underlying K-PKE scheme (FIPS 203 §6.10).
 * @param[out] pk      K-PKE public key: 1184 bytes (k·384 of t̂ in the NTT + 32 of ρ).
 * @param[out] sk_pke K-PKE secret key: 1152 bytes (k·384 of ŝ serialized in the NTT).
 * @param[in]  d      32-byte seed (random or derived by encapsulation).
 * @details    Derives `G(d ‖ k)` with SHA3-512, obtaining ρ (the matrix seed) and σ
 * (the noise seed). The matrix Â is sampled by rejection with
 * `Uniform(ρ, j, i)` — indices deliberately swapped, because the
 * encryption consumes Aᵀ and must regenerate exactly the same coefficients.
 * Then: ŝ, ê ← CBD(η=2) with σ (nonces 0..k−1 and k..2k−1),
 * t̂ = Â∘ŝ + ê, with poly_tomont() applied after the accumulator to
 * compensate for the R⁻¹ factor of the Montgomery multiplication.
 * @post       buf, s and e are wiped with zupt_secure_wipe() before the return.
 * @see        poly_uniform(), poly_noise(), polyvec_pointwise_acc(), poly_tomont()
 * @endcond */
static void kpke_keygen(uint8_t pk[1184], uint8_t sk_pke[1152], const uint8_t d[32]) {
    uint8_t buf[64];
    /* G(d ‖ k) */
    uint8_t dk[33];
    memcpy(dk, d, 32);
    dk[32] = MLKEM_K;
    zupt_sha3_512(dk, 33, buf);
    uint8_t *rho = buf;      /* 32 bytes: public seed */
    uint8_t *sigma = buf+32; /* 32 bytes: noise seed */

    /* Generate matrix A (in NTT domain) from rho */
    polyvec Ahat[MLKEM_K];
    for (int i = 0; i < MLKEM_K; i++)
        for (int j = 0; j < MLKEM_K; j++)
            poly_uniform(Ahat[i][j], rho, (uint8_t)j, (uint8_t)i);

    /* Sample secret vector s */
    polyvec s;
    uint8_t nonce = 0;
    for (int i = 0; i < MLKEM_K; i++)
        poly_noise(s[i], sigma, nonce++);

    /* Sample error vector e */
    polyvec e;
    for (int i = 0; i < MLKEM_K; i++)
        poly_noise(e[i], sigma, nonce++);

    /* NTT(s), NTT(e) */
    polyvec_ntt(s);
    polyvec_ntt(e);

    /* t_hat = A_hat ∘ s_hat + e_hat
     * ZUPT-COMPAT: poly_tomont after basemul compensates for R^{-1} factor
     * from Montgomery multiplication, matching reference pqcrystals/kyber. */
    polyvec t_hat;
    for (int i = 0; i < MLKEM_K; i++) {
        polyvec_pointwise_acc(t_hat[i], Ahat[i], s);
        poly_tomont(t_hat[i]);
        poly_add(t_hat[i], t_hat[i], e[i]);
        poly_reduce(t_hat[i]);
    }

    /* pk = encode(t_hat) ‖ rho */
    polyvec_tobytes(pk, t_hat);
    memcpy(pk + MLKEM_K*384, rho, 32);

    /* sk_pke = encode(s_hat) */
    polyvec_tobytes(sk_pke, s);

    zupt_secure_wipe(buf, sizeof(buf));
    zupt_secure_wipe(s, sizeof(s));
    zupt_secure_wipe(e, sizeof(e));
}

/* K-PKE encrypt: encrypt message m (32 bytes) under pk with randomness r (32 bytes) */
/**
 * @cond PORT
 * @brief Cifra K-PKE (FIPS 203 §6.11): 32 bytes de mensagem sob uma chave pública.
 * @param[out] ct    Texto cifrado: 1088 bytes (k·320 de u comprimido + 32 de v).
 * @param[in]  pk    Chave pública K-PKE (1184 bytes: t̂ serializado + ρ).
 * @param[in]  m     Mensagem de 32 bytes (bits de mensagem no esquema CCA).
 * @param[in]  r     Randomness de 32 bytes usada pelo PRF (nonces 0..2k).
 * @param[in]  legacy Quando ≠ 0, gera Aᵀ com os índices trocados
 * `Uniform(ρ, j, i)` em vez do padrão desta versão.
 * @details    Regera Â a partir de ρ, amostra r̂, ê₁, ê₂ por CBD(η=2) e calcula
 * u = NTT⁻¹(Âᵀ∘r̂) + ê₁ e v = NTT⁻¹(t̂ᵀ∘r̂) + ê₂ + Decompress(m, 1),
 * com Decompress₁(mapeando cada bit para (Q+1)/2 = 1665).
 * Antes da serialização aplica poly_reduce() e comprima u com 10 bits
 * e v com 4 bits.
 * @warning    O parâmetro @p legacy muda a ordem dos índices usados para amostrar
 * a matriz, produzindo cifrastes incompatíveis com o caminho padrão.
 * Ver finding registrado para esta linha.
 * @post       r_vec, e1 e e2 são limpos com zupt_secure_wipe() antes do retorno.
 * @see        kpke_keygen(), kpke_decrypt(), polyvec_compress()
 * @endcond
 * @cond INGLES
 * @brief K-PKE encryption (FIPS 203 §6.11): 32 bytes of message under a public key.
 * @param[out] ct    Encrypted text: 1088 bytes (k·320 of compressed u + 32 of v).
 * @param[in]  pk    K-PKE public key (1184 bytes: serialized t̂ + ρ).
 * @param[in]  m     32-byte message (message bits in the CCA scheme).
 * @param[in]  r     32 bytes of randomness used by the PRF (nonces 0..2k).
 * @param[in]  legacy When ≠ 0, generates Aᵀ with the indices swapped
 * `Uniform(ρ, j, i)` instead of this version's default.
 * @details    Regenerates Â from ρ, samples r̂, ê₁, ê₂ by CBD(η=2) and computes
 * u = NTT⁻¹(Âᵀ∘r̂) + ê₁ and v = NTT⁻¹(t̂ᵀ∘r̂) + ê₂ + Decompress(m, 1),
 * with Decompress₁ mapping each bit to (Q+1)/2 = 1665).
 * Before serialization it applies poly_reduce() and compresses u with 10 bits
 * and v with 4 bits.
 * @warning    The @p legacy parameter changes the order of the indices used to sample
 * the matrix, producing ciphertexts incompatible with the default path.
 * See the finding recorded for this line.
 * @post       r_vec, e1 and e2 are wiped with zupt_secure_wipe() before the return.
 * @see        kpke_keygen(), kpke_decrypt(), polyvec_compress()
 * @endcond */
static void kpke_encrypt(uint8_t ct[1088], const uint8_t pk[1184],
                          const uint8_t m[32], const uint8_t r[32], int legacy) {
    /* Decode pk */
    polyvec t_hat;
    polyvec_frombytes(t_hat, pk);
    uint8_t rho[32];
    memcpy(rho, pk + MLKEM_K*384, 32);

    /* Regenerate A^T from rho (transposed) */
    polyvec AT[MLKEM_K];
    for (int i = 0; i < MLKEM_K; i++)
        for (int j = 0; j < MLKEM_K; j++)
            poly_uniform(AT[i][j], rho, (uint8_t)(legacy ? j : i),
                         (uint8_t)(legacy ? i : j));

    /* Sample r_vec, e1, e2 */
    polyvec r_vec;
    uint8_t nonce = 0;
    for (int i = 0; i < MLKEM_K; i++)
        poly_noise(r_vec[i], r, nonce++);

    polyvec e1;
    for (int i = 0; i < MLKEM_K; i++)
        poly_noise(e1[i], r, nonce++);

    poly e2;
    poly_noise(e2, r, nonce);

    polyvec_ntt(r_vec);

    /* u = NTT^-1(A^T ∘ r_hat) + e1 */
    polyvec u;
    for (int i = 0; i < MLKEM_K; i++) {
        polyvec_pointwise_acc(u[i], AT[i], r_vec);
    }
    polyvec_invntt(u);
    for (int i = 0; i < MLKEM_K; i++) poly_add(u[i], u[i], e1[i]);

    /* v = NTT^-1(t_hat^T ∘ r_hat) + e2 + Decompress(m, 1) */
    poly v;
    polyvec_pointwise_acc(v, t_hat, r_vec);
    inv_ntt(v);
    poly_add(v, v, e2);

    /* Decompress message: each bit → Q/2 or 0 */
    poly mp;
    for (int i = 0; i < 256; i++) {
        mp[i] = (int16_t)(-(int16_t)((m[i/8] >> (i%8)) & 1) & ((Q+1)/2));
    }
    poly_add(v, v, mp);

    /* Compress and encode */
    for (int i = 0; i < MLKEM_K; i++) poly_reduce(u[i]);
    poly_reduce(v);
    polyvec_compress(ct, u);
    poly_compress(ct + MLKEM_K*320, v, MLKEM_DV);

    zupt_secure_wipe(r_vec, sizeof(r_vec));
    zupt_secure_wipe(e1, sizeof(e1));
    zupt_secure_wipe(&e2, sizeof(e2));
}

/* K-PKE decrypt */
/**
 * @cond PORT
 * @brief Decifra K-PKE (FIPS 203 §6.12) e recupera os 32 bytes da mensagem.
 * @param[out] m     Mensagem recuperada (32 bytes, um bit por coeficiente).
 * @param[in]  ct    Texto cifrado: 1088 bytes (k·320 de u + 32 de v).
 * @param[in]  sk_pke Chave secreta K-PKE: 1152 bytes (k·384 de ŝ serializados).
 * @details    Descomprime u (10 bits) e v (4 bits), aplica NTT em u, acumula
 * ŝ∘û, volta com inv_ntt() e calcula w = v − ŝᵀ·û. Cada coeficiente é
 * convertido em bit pelo arredondamento `round(2·x/Q)` — o bit mais
 * próximo de 0 ou Q/2. Nenhum teste de integridade é feito: o valor
 * retornado é simplesmente o resultado da decifração algébrica.
 * @post       s_hat é limpo com zupt_secure_wipe() antes do retorno.
 * @see        kpke_encrypt(), polyvec_decompress()
 * @endcond
 * @cond INGLES
 * @brief Decrypts K-PKE (FIPS 203 §6.12) and recovers the 32 bytes of the message.
 * @param[out] m     Recovered message (32 bytes, one bit per coefficient).
 * @param[in]  ct    Encrypted text: 1088 bytes (k·320 of u + 32 of v).
 * @param[in]  sk_pke K-PKE secret key: 1152 bytes (k·384 of serialized ŝ).
 * @details    Decompresses u (10 bits) and v (4 bits), applies the NTT to u, accumulates
 * ŝ∘û, returns with inv_ntt() and computes w = v − ŝᵀ·û. Each coefficient is
 * converted to a bit by the rounding `round(2·x/Q)` — the bit closest
 * to 0 or to Q/2. No integrity check is performed: the value
 * returned is simply the result of the algebraic decryption.
 * @post       s_hat is wiped with zupt_secure_wipe() before the return.
 * @see        kpke_encrypt(), polyvec_decompress()
 * @endcond */
static void kpke_decrypt(uint8_t m[32], const uint8_t ct[1088],
                          const uint8_t sk_pke[1152]) {
    polyvec u;
    polyvec_decompress(u, ct);

    poly v;
    poly_decompress(v, ct + MLKEM_K*320, MLKEM_DV);

    polyvec s_hat;
    polyvec_frombytes(s_hat, sk_pke);

    polyvec_ntt(u);
    poly w;
    polyvec_pointwise_acc(w, s_hat, u);
    inv_ntt(w);
    poly_sub(w, v, w);
    poly_reduce(w);

    /* Compress to 1 bit per coefficient → message */
    memset(m, 0, 32);
    for (int i = 0; i < 256; i++) {
        int16_t x = (int16_t)((w[i] % Q + Q) % Q);
        /* Round: closest to 0 or Q/2? */
        uint16_t t = (uint16_t)(((uint32_t)x * 2 + Q/2) / Q) & 1;
        m[i/8] |= (uint8_t)(t << (i%8));
    }

    zupt_secure_wipe(s_hat, sizeof(s_hat));
}

/* ═══════════════════════════════════════════════════════════════════
 * ML-KEM-768 (FIPS 203 Sections 6-7)
 * Fujisaki-Okamoto transform for CCA security.
 * ═══════════════════════════════════════════════════════════════════ */

/* FRAMA-C: ML-KEM-768 key generation (FIPS 203) */
/*@ requires \valid(pk + (0..1183));
  @ requires \valid(sk + (0..2399));
  @ requires \separated(pk + (0..1183), sk + (0..2399));
  @ assigns pk[0..1183], sk[0..2399];
  @ ensures \result == 0 ==> \initialized(pk + (0..1183));
  @ ensures \result == 0 ==> \initialized(sk + (0..2399));
*/
/**
 * @cond PORT
 * @brief Valida a estrutura de uma chave pública ML-KEM-768.
 * @param[in] pk Buffer de 1184 bytes a validar.
 * @retval  0 Chave estruturalmente válida.
 * @retval -1 Ponteiro nulo ou pelo menos um coeficiente fora do intervalo.
 * @details Percorre os 1152 bytes do bloco t̂ em pares de 12 bits e acumula, em
 * `invalid`, o resultado de testar cada valor contra Q (3329). Só a
 * parte de t̂ é verificada: os 32 bytes finais (ρ) são uma semente
 * arbitrária e não passam por nenhum teste. A comparação é feita por
 * acumulação de bits em vez de `return` imediato, para não revelar
 * em qual posição a chave foi rejeitada.
 * @note    O bloco ACSL que aparece acima desta função no código descreve a
 * geração de chaves (`assigns pk, sk`), não esta verificação — ver
 * finding registrado para este ponto.
 * @see     zupt_mlkem768_keygen()
 * @endcond
 * @cond INGLES
 * @brief Validates the structure of an ML-KEM-768 public key.
 * @param[in] pk 1184-byte buffer to validate.
 * @retval  0 Structurally valid key.
 * @retval -1 Null pointer or at least one coefficient outside the range.
 * @details Walks the 1152 bytes of the t̂ block in pairs of 12 bits and accumulates, in
 * `invalid`, the result of testing each value against Q (3329). Only
 * the t̂ part is checked: the last 32 bytes (ρ) are an arbitrary
 * seed and undergo no test. The comparison is done by
 * bit accumulation instead of an immediate `return`, so as not to reveal
 * at which position the key was rejected.
 * @note    The ACSL block that appears above this function in the code describes the
 * key generation (`assigns pk, sk`), not this check — see
 * the finding recorded for this point.
 * @see     zupt_mlkem768_keygen()
 * @endcond */
int zupt_mlkem768_public_key_check(const uint8_t pk[1184]) {
    if (!pk) return -1;
    /* FIPS 203 Algorithm 20: ByteEncode_12(ByteDecode_12(ek)) == ek. */
    uint32_t invalid = 0;
    for (size_t i = 0; i < 1152; i += 3) {
        uint16_t a = (uint16_t)(pk[i] | ((uint16_t)(pk[i + 1] & 15) << 8));
        uint16_t b = (uint16_t)((pk[i + 1] >> 4) | ((uint16_t)pk[i + 2] << 4));
        invalid |= (uint32_t)(a >= Q) | (uint32_t)(b >= Q);
    }
    return invalid ? -1 : 0;
}

/**
 * @cond PORT
 * @brief Valida o vínculo entre a chave pública embutida e a chave secreta.
 * @param[in] sk Buffer de 2400 bytes a validar.
 * @retval  0 Vínculo confere (a chave é estruturalmente íntegra).
 * @retval -1 Ponteiro nulo ou hash divergente.
 * @details Recomputa SHA3-256 sobre o bloco de chave pública armazenado em
 * `sk[1152..2335]` (1184 bytes) e compara os 32 bytes resultantes com
 * `sk[2336..2367]`. A comparação acumula XOR (`diff`) para percorrer os
 * 32 bytes por completo. Nada é apagado em caso de falha: a função é
 * apenas uma verificação e não altera o buffer.
 * @note    Não confere os 32 bytes finais de `z` (sk[2368..2399]) — apenas o
 * vínculo H(ek) descrito acima.
 * @see     zupt_mlkem768_keygen()
 * @endcond
 * @cond INGLES
 * @brief Validates the binding between the embedded public key and the secret key.
 * @param[in] sk 2400-byte buffer to validate.
 * @retval  0 The binding matches (the key is structurally intact).
 * @retval -1 Null pointer or differing hash.
 * @details Recomputes SHA3-256 over the public key block stored in
 * `sk[1152..2335]` (1184 bytes) and compares the resulting 32 bytes with
 * `sk[2336..2367]`. The comparison accumulates XOR (`diff`) to walk the
 * 32 bytes in full. Nothing is wiped on failure: the function is
 * only a check and does not modify the buffer.
 * @note    It does not check the last 32 bytes of `z` (sk[2368..2399]) — only the
 * H(ek) binding described above.
 * @see     zupt_mlkem768_keygen()
 * @endcond */
int zupt_mlkem768_secret_key_check(const uint8_t sk[2400]) {
    if (!sk) return -1;
    uint8_t h[32], diff = 0;
    zupt_sha3_256(sk + 1152, 1184, h);
    for (size_t i = 0; i < 32; ++i) diff |= h[i] ^ sk[2336 + i];
    zupt_secure_wipe(h, sizeof(h));
    return diff ? -1 : 0;
}

/**
 * @cond PORT
 * @brief Gera o par de chaves ML-KEM-768 a partir de duas sementes explícitas.
 * @param[out] pk Chave pública: 1184 bytes (t̂ serializado + ρ).
 * @param[out] sk Chave secreta: 2400 bytes (sk_pke ‖ pk ‖ H(pk) ‖ z).
 * @param[in]  d  Semente de 32 bytes que deriva ρ e σ do K-PKE.
 * @param[in]  z  Semente de 32 bytes usada no encapsulamento (transformação FO).
 * @retval 0 Sempre (não há caminho de erro nesta função interna).
 * @details Monta exatamente a codificação de chave secreta da FIPS 203:
 * sk_pke (1152) ‖ ek (1184) ‖ H(ek) (32) ‖ z (32). O bloco H(ek) é o
 * verificado por zupt_mlkem768_secret_key_check().
 * @post    sk_pke é limpo com zupt_secure_wipe() antes do retorno.
 * @see     kpke_keygen(), zupt_mlkem768_secret_key_check()
 * @endcond
 * @cond INGLES
 * @brief Generates the ML-KEM-768 key pair from two explicit seeds.
 * @param[out] pk Public key: 1184 bytes (serialized t̂ + ρ).
 * @param[out] sk Secret key: 2400 bytes (sk_pke ‖ pk ‖ H(pk) ‖ z).
 * @param[in]  d  32-byte seed that derives ρ and σ of the K-PKE.
 * @param[in]  z  32-byte seed used in encapsulation (the FO transform).
 * @retval 0 Always (there is no error path in this internal function).
 * @details Builds exactly the FIPS 203 secret key encoding:
 * sk_pke (1152) ‖ ek (1184) ‖ H(ek) (32) ‖ z (32). The H(ek) block is the
 * one checked by zupt_mlkem768_secret_key_check().
 * @post    sk_pke is wiped with zupt_secure_wipe() before the return.
 * @see     kpke_keygen(), zupt_mlkem768_secret_key_check()
 * @endcond */
static int mlkem_keygen_internal(uint8_t pk[1184], uint8_t sk[2400],
                                 const uint8_t d[32], const uint8_t z[32]) {
    uint8_t sk_pke[1152];
    kpke_keygen(pk, sk_pke, d);
    memcpy(sk, sk_pke, 1152);
    memcpy(sk + 1152, pk, 1184);
    zupt_sha3_256(pk, 1184, sk + 2336);
    memcpy(sk + 2368, z, 32);
    zupt_secure_wipe(sk_pke, sizeof(sk_pke));
    return 0;
}

/**
 * @cond PORT
 * @brief Gera um par de chaves ML-KEM-768 com aleatoriedade do sistema.
 * @param[out] pk Chave pública: 1184 bytes.
 * @param[out] sk Chave secreta: 2400 bytes (sk_pke ‖ pk ‖ H(pk) ‖ z).
 * @retval  0 Chaves geradas com sucesso.
 * @retval -1 Pelo menos um dos ponteiros recebidos é nulo.
 * @details Obtém duas sementes de 32 bytes via zupt_random_bytes() e delega a
 * mlkem_keygen_internal().
 * @post    d e z são limpos com zupt_secure_wipe() antes de qualquer retorno
 * (inclusive na rota de erro, que ocorre antes do wipe — nesse caso
 * os buffers ainda não haviam sido preenchidos).
 * @see     mlkem_keygen_internal(), zupt_mlkem768_secret_key_check()
 * @endcond
 * @cond INGLES
 * @brief Generates an ML-KEM-768 key pair using system randomness.
 * @param[out] pk Public key: 1184 bytes.
 * @param[out] sk Secret key: 2400 bytes (sk_pke ‖ pk ‖ H(pk) ‖ z).
 * @retval  0 Keys generated successfully.
 * @retval -1 At least one of the received pointers is null.
 * @details Obtains two 32-byte seeds through zupt_random_bytes() and delegates to
 * mlkem_keygen_internal().
 * @post    d and z are wiped with zupt_secure_wipe() before any return
 * (including the error path, which occurs before the wipe — in that case
 * the buffers had not yet been filled).
 * @see     mlkem_keygen_internal(), zupt_mlkem768_secret_key_check()
 * @endcond */
int zupt_mlkem768_keygen(uint8_t pk[1184], uint8_t sk[2400]) {
    if (!pk || !sk) return -1;
    uint8_t d[32], z[32];
    zupt_random_bytes(d, sizeof(d));
    zupt_random_bytes(z, sizeof(z));
    int ret = mlkem_keygen_internal(pk, sk, d, z);
    zupt_secure_wipe(d, sizeof(d));
    zupt_secure_wipe(z, sizeof(z));
    return ret;
}

/**
 * @cond PORT
 * @brief Encapsulamento ML-KEM-768 com mensagem explícita (algoritmo interno).
 * @param[out] ct Texto cifrado: 1088 bytes.
 * @param[out] ss Segredo compartilhado: 32 bytes (ko, a primeira metade de G).
 * @param[in]  pk Chave pública: 1184 bytes.
 * @param[in]  m  Mensagem de 32 bytes que determina a aleatoriedade.
 * @retval  0 Segredo encapsulado com sucesso.
 * @retval -1 Chave pública rejeitada pela validação estrutural.
 * @details Calcula `input = m ‖ H(pk)` (H = SHA3-256) e `kr = SHA3-512(input)`.
 * A primeira metade de kr é o segredo compartilhado devolvido e a segunda
 * metade é a randomness passada a kpke_encrypt() com o caminho padrão
 * (`legacy = 0`). Não há KDF final: o segredo é kr[0..31] diretamente.
 * @post    input e kr são limpos com zupt_secure_wipe() em todos os retornos.
 * @see     kpke_encrypt(), zupt_mlkem768_encaps()
 * @endcond
 * @cond INGLES
 * @brief ML-KEM-768 encapsulation with an explicit message (internal algorithm).
 * @param[out] ct Encrypted text: 1088 bytes.
 * @param[out] ss Shared secret: 32 bytes (ko, the first half of G).
 * @param[in]  pk Public key: 1184 bytes.
 * @param[in]  m  32-byte message that determines the randomness.
 * @retval  0 Secret encapsulated successfully.
 * @retval -1 Public key rejected by the structural validation.
 * @details Computes `input = m ‖ H(pk)` (H = SHA3-256) and `kr = SHA3-512(input)`.
 * The first half of kr is the shared secret returned and the second
 * half is the randomness passed to kpke_encrypt() on the default path
 * (`legacy = 0`). There is no final KDF: the secret is kr[0..31] directly.
 * @post    input and kr are wiped with zupt_secure_wipe() on every return.
 * @see     kpke_encrypt(), zupt_mlkem768_encaps()
 * @endcond */
static int mlkem_encaps_internal(uint8_t ct[1088], uint8_t ss[32],
                                 const uint8_t pk[1184], const uint8_t m[32]) {
    if (zupt_mlkem768_public_key_check(pk) != 0) return -1;
    uint8_t input[64], kr[64];
    memcpy(input, m, 32);
    zupt_sha3_256(pk, 1184, input + 32);
    zupt_sha3_512(input, sizeof(input), kr);
    kpke_encrypt(ct, pk, m, kr + 32, 0);
    /* FIPS 203 Algorithm 17 returns K directly; no Kyber-era final KDF. */
    memcpy(ss, kr, 32);
    zupt_secure_wipe(input, sizeof(input));
    zupt_secure_wipe(kr, sizeof(kr));
    return 0;
}

/**
 * @cond PORT
 * @brief Encapsula um segredo de 32 bytes sob uma chave pública ML-KEM-768.
 * @param[out] ct Texto cifrado: 1088 bytes (k·320 de u + 32 de v).
 * @param[out] ss Segredo compartilhado: 32 bytes, sempre diferente de tudo que
 * a decifração com a chave correta não devolve.
 * @param[in]  pk Chave pública: 1184 bytes.
 * @retval  0 Segredo encapsulado com sucesso.
 * @retval -1 Algum ponteiro é nulo ou a chave pública falha na validação
 * estrutural (zupt_mlkem768_public_key_check).
 * @details Gera uma mensagem m de 32 bytes com zupt_random_bytes() e a usa como
 * entropia do encapsulamento; m é apagada antes do retorno.
 * @post    m é limpa com zupt_secure_wipe() antes do retorno.
 * @see     zupt_mlkem768_decaps(), mlkem_encaps_internal()
 * @endcond
 * @cond INGLES
 * @brief Encapsulates a 32-byte secret under an ML-KEM-768 public key.
 * @param[out] ct Encrypted text: 1088 bytes (k·320 of u + 32 of v).
 * @param[out] ss Shared secret: 32 bytes, always different from anything that
 * decryption with the correct key does not return.
 * @param[in]  pk Public key: 1184 bytes.
 * @retval  0 Secret encapsulated successfully.
 * @retval -1 Some pointer is null or the public key fails the structural
 * validation (zupt_mlkem768_public_key_check).
 * @details Generates a 32-byte message m with zupt_random_bytes() and uses it as
 * the encapsulation entropy; m is wiped before the return.
 * @post    m is wiped with zupt_secure_wipe() before the return.
 * @see     zupt_mlkem768_decaps(), mlkem_encaps_internal()
 * @endcond */
int zupt_mlkem768_encaps(uint8_t ct[1088], uint8_t ss[32],
                        const uint8_t pk[1184]) {
    if (!ct || !ss || !pk || zupt_mlkem768_public_key_check(pk) != 0) return -1;
    uint8_t m[32];
    zupt_random_bytes(m, sizeof(m));
    int ret = mlkem_encaps_internal(ct, ss, pk, m);
    zupt_secure_wipe(m, sizeof(m));
    return ret;
}

/* legacy is a public format selector, never a secret-dependent decision.
 * The legacy path exists only for explicit, authenticated-digest migration. */
/**
 * @cond PORT
 * @brief Decapsulamento ML-KEM-768 (transformação Fujisaki–Okamoto).
 * @param[out] ss Segredo compartilhado: 32 bytes.
 * @param[in]  ct Texto cifrado: 1088 bytes.
 * @param[in]  sk Chave secreta: 2400 bytes (sk_pke ‖ pk ‖ H(pk) ‖ z).
 * @param[in]  legacy Seletor de formato público (0 = FIPS 203, ≠0 = formato legado).
 * @retval  0 Sempre, inclusive na rejeição implícita — neste caso @p ss recebe o
 * segredo de rejeição e não há distinção observável de falha.
 * @retval -1 Algum ponteiro é nulo, ou (no caminho não legado) a chave secreta
 * falha em zupt_mlkem768_secret_key_check().
 * @details Decifra ct para m, recomputa `kr = SHA3-512(m ‖ H(pk))` e re-cifra m
 * com a randomness kr[32..63]. A igualdade ct == ct' é acumulada em
 * `diff` (varredura completa, sem saída antecipada) e convertida na
 * máscara `fail` por aritmética sem sinal: `(diff | −diff) >> 31` vale
 * 0xFF quando há divergência.
 * Caminho não legado: segredo bom = kr[0..31]; segredo de rejeição =
 * SHAKE-256(z ‖ ct), isto é, J(z ‖ c) da FIPS 203 (não J(z ‖ H(c))).
 * Caminho legado: bom = SHAKE-256(ko ‖ H(ct)); rejeição = SHAKE-256(z).
 * A escolha entre bom e rejeição usa máscara: zupt_ct_select_32() sob
 * ZUPT_USE_JASMIN, ou memcpy + cmov() com `1 − fail` caso contrário.
 * @note     O parâmetro @p legacy é um seletor de formato exposto na fronteira,
 * não um dado secreto; não há decisão secreta dependente de ramo.
 * @post     m, input, kr, check_ct, good, reject, reject_input, diff e fail são
 * limpos com zupt_secure_wipe() antes do retorno.
 * @see      zupt_mlkem768_decaps(), zupt_legacy_mlkem768_decaps(), cmov(), zupt_ct_select_32()
 * @endcond
 * @cond INGLES
 * @brief ML-KEM-768 decapsulation (Fujisaki–Okamoto transform).
 * @param[out] ss Shared secret: 32 bytes.
 * @param[in]  ct Encrypted text: 1088 bytes.
 * @param[in]  sk Secret key: 2400 bytes (sk_pke ‖ pk ‖ H(pk) ‖ z).
 * @param[in]  legacy Public format selector (0 = FIPS 203, ≠0 = legacy format).
 * @retval  0 Always, including under implicit rejection — in this case @p ss receives the
 * rejection secret and there is no observable distinction of failure.
 * @retval -1 Some pointer is null, or (on the non-legacy path) the secret key
 * fails zupt_mlkem768_secret_key_check().
 * @details Decrypts ct into m, recomputes `kr = SHA3-512(m ‖ H(pk))` and re-encrypts m
 * with the randomness kr[32..63]. The equality ct == ct' is accumulated in
 * `diff` (full scan, no early exit) and converted into the
 * mask `fail` by unsigned arithmetic: `(diff | −diff) >> 31` yields
 * 0xFF when there is a divergence.
 * Non-legacy path: good secret = kr[0..31]; rejection secret =
 * SHAKE-256(z ‖ ct), that is, J(z ‖ c) of FIPS 203 (not J(z ‖ H(c))).
 * Legacy path: good = SHAKE-256(ko ‖ H(ct)); rejection = SHAKE-256(z).
 * The choice between good and rejection uses a mask: zupt_ct_select_32() under
 * ZUPT_USE_JASMIN, or memcpy + cmov() with `1 − fail` otherwise.
 * @note     The @p legacy parameter is a format selector exposed at the boundary,
 * not a secret; there is no secret-dependent branch decision.
 * @post     m, input, kr, check_ct, good, reject, reject_input, diff and fail are
 * wiped with zupt_secure_wipe() before the return.
 * @see      zupt_mlkem768_decaps(), zupt_legacy_mlkem768_decaps(), cmov(), zupt_ct_select_32()
 * @endcond */
static int mlkem_decaps_internal(uint8_t ss[32], const uint8_t ct[1088],
                                 const uint8_t sk[2400], int legacy) {
    if (!ss || !ct || !sk) return -1;
    if (!legacy && zupt_mlkem768_secret_key_check(sk) != 0) return -1;
    const uint8_t *pk = sk + 1152, *h = sk + 2336, *z = sk + 2368;
    uint8_t m[32], input[64], kr[64], check_ct[1088];
    uint8_t good[32], reject[32], reject_input[32 + 1088];
    kpke_decrypt(m, ct, sk);
    memcpy(input, m, 32);
    memcpy(input + 32, h, 32);
    zupt_sha3_512(input, sizeof(input), kr);
    kpke_encrypt(check_ct, pk, m, kr + 32, legacy);
    uint8_t diff = 0;
    for (size_t i = 0; i < 1088; ++i) diff |= ct[i] ^ check_ct[i];
    if (legacy) {
        uint8_t h_ct[32];
        zupt_sha3_256(ct, 1088, h_ct);
        memcpy(input, kr, 32);
        memcpy(input + 32, h_ct, 32);
        zupt_shake256(input, sizeof(input), good, 32);
        memcpy(input, z, 32);
        zupt_shake256(input, sizeof(input), reject, 32);
        zupt_secure_wipe(h_ct, sizeof(h_ct));
    } else {
        memcpy(good, kr, 32);
        memcpy(reject_input, z, 32);
        memcpy(reject_input + 32, ct, 1088);
        /* FIPS 203 Algorithm 18: J(z || c), not J(z || H(c)). */
        zupt_shake256(reject_input, sizeof(reject_input), reject, 32);
    }
    /* Unsigned arithmetic avoids implementation-defined signed shifts. */
    uint8_t fail = (uint8_t)(((uint32_t)diff | (0u - (uint32_t)diff)) >> 31);
#ifdef ZUPT_USE_JASMIN
    zupt_ct_select_32(ss, good, reject, fail);
#else
    memcpy(ss, reject, 32);
    cmov(ss, good, 32, (uint8_t)(1u - fail));
#endif
    zupt_secure_wipe(m, sizeof(m));
    zupt_secure_wipe(input, sizeof(input));
    zupt_secure_wipe(kr, sizeof(kr));
    zupt_secure_wipe(check_ct, sizeof(check_ct));
    zupt_secure_wipe(good, sizeof(good));
    zupt_secure_wipe(reject, sizeof(reject));
    zupt_secure_wipe(reject_input, sizeof(reject_input));
    zupt_secure_wipe(&diff, sizeof(diff));
    zupt_secure_wipe(&fail, sizeof(fail));
    return 0;
}

/**
 * @cond PORT
 * @brief Decapsula um texto cifrado ML-KEM-768 no formato atual (FIPS 203).
 * @param[out] ss Segredo compartilhado: 32 bytes. Em rejeição implícita, o
 * segredo derivado de `J(z ‖ ct)` — não há código de erro.
 * @param[in]  ct Texto cifrado: 1088 bytes.
 * @param[in]  sk Chave secreta: 2400 bytes.
 * @retval  0 Processado (inclusive quando o cifraste é inválido — rejeição
 * implícita, sem distinção observável).
 * @retval -1 Ponteiro nulo ou chave secreta estruturalmente inválida.
 * @see      mlkem_decaps_internal()
 * @endcond
 * @cond INGLES
 * @brief Decapsulates an ML-KEM-768 ciphertext in the current format (FIPS 203).
 * @param[out] ss Shared secret: 32 bytes. Under implicit rejection, the
 * secret derived from `J(z ‖ ct)` — there is no error code.
 * @param[in]  ct Encrypted text: 1088 bytes.
 * @param[in]  sk Secret key: 2400 bytes.
 * @retval  0 Processed (including when the ciphertext is invalid — implicit
 * rejection, with no observable distinction).
 * @retval -1 Null pointer or structurally invalid secret key.
 * @see      mlkem_decaps_internal()
 * @endcond */
int zupt_mlkem768_decaps(uint8_t ss[32], const uint8_t ct[1088],
                        const uint8_t sk[2400]) {
    return mlkem_decaps_internal(ss, ct, sk, 0);
}

/**
 * @cond PORT
 * @brief Decapsula um texto cifrado no formato legado de ML-KEM-768.
 * @param[out] ss Segredo compartilhado: 32 bytes. No caminho legado o segredo
 * "bom" é SHAKE-256(ko ‖ H(ct)) e a rejeição é SHAKE-256(z).
 * @param[in]  ct Texto cifrado legado: 1088 bytes amostrados com a ordem de
 * índices antiga da matriz Aᵀ (ver kpke_encrypt()).
 * @param[in]  sk Chave secreta: 2400 bytes. A validação estrutural é ignorada
 * neste caminho.
 * @retval  0 Sempre que os ponteiros forem válidos.
 * @retval -1 Algum ponteiro é nulo.
 * @warning Existe apenas para migração autenticada de arquivos antigos; o
 * formato legado não é compatível com o cifraste produzido por
 * zupt_mlkem768_encaps().
 * @note    Símbolo interno: não declarado na interface pública instalada.
 * @see      mlkem_decaps_internal(), kpke_encrypt()
 * @endcond
 * @cond INGLES
 * @brief Decapsulates a ciphertext in the legacy ML-KEM-768 format.
 * @param[out] ss Shared secret: 32 bytes. On the legacy path the "good"
 * secret is SHAKE-256(ko ‖ H(ct)) and the rejection is SHAKE-256(z).
 * @param[in]  ct Legacy encrypted text: 1088 bytes sampled with the old
 * index order of the matrix Aᵀ (see kpke_encrypt()).
 * @param[in]  sk Secret key: 2400 bytes. The structural validation is ignored
 * on this path.
 * @retval  0 Whenever the pointers are valid.
 * @retval -1 Some pointer is null.
 * @warning Exists only for authenticated migration of old files; the
 * legacy format is not compatible with the ciphertext produced by
 * zupt_mlkem768_encaps().
 * @note    Internal symbol: not declared in the installed public interface.
 * @see      mlkem_decaps_internal(), kpke_encrypt()
 * @endcond */
int zupt_legacy_mlkem768_decaps(uint8_t ss[32], const uint8_t ct[1088],
                               const uint8_t sk[2400]) {
    return mlkem_decaps_internal(ss, ct, sk, 1);
}

#ifdef ZUPT_TESTING
/* Deterministic ACVP entry points are compiled only into the test executable. */
/**
 * @cond PORT
 * @brief Ponto de entrada determinístico de keygen para vetores ACVP.
 * @param[out] pk Chave pública: 1184 bytes.
 * @param[out] sk Chave secreta: 2400 bytes.
 * @param[in]  d  Semente d fornecida pelo vetor (32 bytes).
 * @param[in]  z  Semente z fornecida pelo vetor (32 bytes).
 * @retval 0 Sempre (delegação direta a mlkem_keygen_internal).
 * @note   Compilado somente com ZUPT_TESTING definido; consumido por
 * scripts/check-acvp.py.
 * @see    mlkem_keygen_internal()
 * @endcond
 * @cond INGLES
 * @brief Deterministic key generation entry point for ACVP vectors.
 * @param[out] pk Public key: 1184 bytes.
 * @param[out] sk Secret key: 2400 bytes.
 * @param[in]  d  Seed d provided by the vector (32 bytes).
 * @param[in]  z  Seed z provided by the vector (32 bytes).
 * @retval 0 Always (direct delegation to mlkem_keygen_internal).
 * @note   Compiled only with ZUPT_TESTING defined; consumed by
 * scripts/check-acvp.py.
 * @see    mlkem_keygen_internal()
 * @endcond */
int zupt_test_mlkem_keygen(uint8_t pk[1184], uint8_t sk[2400],
                          const uint8_t d[32], const uint8_t z[32]) {
    return mlkem_keygen_internal(pk, sk, d, z);
}

/**
 * @cond PORT
 * @brief Ponto de entrada determinístico de encapsulamento para vetores ACVP.
 * @param[out] ct Texto cifrado: 1088 bytes.
 * @param[out] ss Segredo compartilhado: 32 bytes.
 * @param[in]  pk Chave pública: 1184 bytes.
 * @param[in]  m  Mensagem do vetor (32 bytes), em lugar da aleatoriedade.
 * @retval  0 Encapsulado com sucesso.
 * @retval -1 Chave pública rejeitada pela validação estrutural.
 * @note   Compilado somente com ZUPT_TESTING definido.
 * @see    mlkem_encaps_internal()
 * @endcond
 * @cond INGLES
 * @brief Deterministic encapsulation entry point for ACVP vectors.
 * @param[out] ct Encrypted text: 1088 bytes.
 * @param[out] ss Shared secret: 32 bytes.
 * @param[in]  pk Public key: 1184 bytes.
 * @param[in]  m  Message from the vector (32 bytes), in place of the randomness.
 * @retval  0 Encapsulated successfully.
 * @retval -1 Public key rejected by the structural validation.
 * @note   Compiled only with ZUPT_TESTING defined.
 * @see    mlkem_encaps_internal()
 * @endcond */
int zupt_test_mlkem_encaps(uint8_t ct[1088], uint8_t ss[32],
                          const uint8_t pk[1184], const uint8_t m[32]) {
    return mlkem_encaps_internal(ct, ss, pk, m);
}
#endif

/* ═══════════════════════════════════════════════════════════════════
 * SELF-TEST — verify internal operations
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * @cond PORT
 * @brief Autoteste das operações internas de ML-KEM-768.
 * @retval  0 Todas as verificações passaram.
 * @retval -1 Pelo menos uma verificação falhou (detalhes impressos em stderr).
 * @details Executa três verificações independentes:
 * 1. Idempotência da NTT: aplica ntt() e inv_ntt() sobre um polinômio
 * determinístico (`a[i] = i·17 mod Q`) e compara `montgomery_reduce(b[i])`
 * com `a[i]`, compensando o fator de Montgomery residual do par de
 * transformadas.
 * 2. Ciclo K-PKE: kpke_keygen → kpke_encrypt → kpke_decrypt com
 * aleatoriedade do sistema, exigindo m == m′.
 * 3. Ciclo KEM completo: keygen → encaps → decaps, exigindo ss == ss′.
 * @note    Comporta-se como teste: usa saída antecipada (`break`/`return`) e
 * imprime em stderr, o que não seria aceitável em código criptográfico
 * em execução normal.
 * @see     zupt_mlkem768_encaps(), zupt_mlkem768_decaps()
 * @endcond
 * @cond INGLES
 * @brief Self-test of the internal ML-KEM-768 operations.
 * @retval  0 All checks passed.
 * @retval -1 At least one check failed (details printed to stderr).
 * @details Runs three independent checks:
 * 1. NTT idempotence: applies ntt() and inv_ntt() to a deterministic
 * polynomial (`a[i] = i·17 mod Q`) and compares `montgomery_reduce(b[i])`
 * with `a[i]`, compensating for the residual Montgomery factor of the pair of
 * transforms.
 * 2. K-PKE cycle: kpke_keygen → kpke_encrypt → kpke_decrypt with
 * system randomness, requiring m == m′.
 * 3. Full KEM cycle: keygen → encaps → decaps, requiring ss == ss′.
 * @note    Behaves as a test: it uses early exit (`break`/`return`) and
 * prints to stderr, which would not be acceptable in cryptographic code
 * running normally.
 * @see     zupt_mlkem768_encaps(), zupt_mlkem768_decaps()
 * @endcond */
int zupt_mlkem768_selftest(void) {
    int ok = 1;

    /* Test 1: NTT roundtrip — ntt then inv_ntt should recover original */
    {
        poly a, b;
        for (int i = 0; i < 256; i++) a[i] = (int16_t)(i * 17 % Q);
        memcpy(b, a, sizeof(a));
        ntt(b);
        inv_ntt(b);
        int ntt_ok = 1;
        for (int i = 0; i < 256; i++) {
            int16_t diff = (int16_t)((montgomery_reduce(b[i]) % Q + Q) % Q) - (int16_t)((a[i] % Q + Q) % Q);
            if ((diff % Q + Q) % Q != 0) { ntt_ok = 0; break; }
        }
        if (!ntt_ok) { fprintf(stderr, "  MLKEM selftest: NTT roundtrip FAILED\n"); ok = 0; }
    }

    /* Test 2: K-PKE encrypt/decrypt roundtrip */
    {
        uint8_t d[32], pk[1184], sk_pke[1152];
        zupt_random_bytes(d, 32);
        kpke_keygen(pk, sk_pke, d);

        uint8_t m[32], r[32], ct[1088], m2[32];
        zupt_random_bytes(m, 32);
        zupt_random_bytes(r, 32);
        kpke_encrypt(ct, pk, m, r, 0);
        kpke_decrypt(m2, ct, sk_pke);

        if (memcmp(m, m2, 32) != 0) {
            fprintf(stderr, "  MLKEM selftest: K-PKE roundtrip FAILED\n");
            fprintf(stderr, "    m[0:4]:  %02x%02x%02x%02x\n", m[0],m[1],m[2],m[3]);
            fprintf(stderr, "    m2[0:4]: %02x%02x%02x%02x\n", m2[0],m2[1],m2[2],m2[3]);
            ok = 0;
        }
    }

    /* Test 3: Full KEM encaps/decaps */
    {
        uint8_t pk[1184], sk[2400], ct[1088], ss1[32], ss2[32];
        zupt_mlkem768_keygen(pk, sk);
        zupt_mlkem768_encaps(ct, ss1, pk);
        zupt_mlkem768_decaps(ss2, ct, sk);
        if (memcmp(ss1, ss2, 32) != 0) {
            fprintf(stderr, "  MLKEM selftest: KEM roundtrip FAILED\n");
            ok = 0;
        }
    }

    return ok ? 0 : -1;
}
