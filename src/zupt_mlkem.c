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
 * @file   zupt_mlkem.c
 * @brief  Implementação em C11 puro do KEM ML-KEM-768 (FIPS 203).
 * @details Este arquivo implementa, sem dependências externas além de
 *          zupt_keccak.h (SHA3/SHAKE) e zupt.h (aleatoriedade e limpeza
 *          segura), a construção completa de FIPS 203 na parameterização 768:
 *
 *          - Aritmética modular sobre q = 3329: redução de Barrett para
 *            int16_t (sem ramificações) e redução de Montgomery para
 *            int32_t, com QINV = q^(-1) mod 2^16.
 *          - NTT de 256 pontos sobre Z_q[x]/(x^256+1), com raiz primitiva
 *            de ordem 256 zeta = 17, tabela pré-computada em domínio de
 *            Montgomery e ordem bit-reversed; inversa com escala final
 *            f = 1441.
 *          - Operações de polinômio e de vetor de polinômios (soma, subtração,
 *            produto ponto a ponto "basemul" em NTT, redução, conversão ao
 *            domínio de Montgomery).
 *          - Amostragem: CBD(eta=2) a partir de 128 bytes, distribuição
 *            uniforme por rejeição sobre fluxo SHAKE-128 e ruído via
 *            PRF SHAKE-256 + CBD.
 *          - Codificação/decodificação em 12 bits por coeficiente e
 *            compressão/expandir em 10 e 4 bits.
 *          - Esquema K-PKE IND-CPA (seções 7.2-7.3 de FIPS 203) e a
 *            transformação Fujisaki-Okamoto que produz ML-KEM-768 (seções
 *            6-7), com rejeição implícita no decapsulamento.
 *          - Verificações de codificação de chave pública e de chave secreta,
 *            além de um auto-teste de ida e volta.
 *
 *          Estrutura de memória: um polinômio é um array de 256 int16_t
 *          (typedef poly); coeficientes podem ficar fora de [0, q) durante os
 *            cálculos e só são normalizados por poly_reduce() ou pelas
 *            funções de codificação.
 *
 *          Seleção de ramo em tempo de compilação: ZUPT_USE_JASMIN troca a
 *          função de seleção condicional em C por zupt_ct_select_32()
 *          fornecida pelo Jasmin; ZUPT_TESTING habilita pontos de entrada
 *          determinísticos usados por scripts/check-acvp.py.
 *
 *          Nota factual: as marcações "CT-REQUIRED" e as declarações de
 *          tempo constante do cabeçalho acima descrevem a intenção do autor.
 *          Os mecanismos observáveis neste arquivo são: ausência de
 *          ramificações em barrett_reduce()/montgomery_reduce(), índices de
 *            tabela e limites de laço independentes de dados secretos, e a
 *            seleção final por máscara de bits. A ausência de canais laterais
 *            depende também do compilador e da arquitetura-alvo.
 */

/**
 * @def _GNU_SOURCE
 * @brief Macro de feature do glibc, definido antes da primeira inclusão.
 *
 * Habilita as extensões GNU declaradas pelos cabeçalhos C padrão incluídos
 * em sequência. Não é referenciado por nenhum código deste arquivo, não faz
 * parte da API da biblioteca e não aparece na documentação pública.
 */
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

/** @brief Módulo do anel de polinômios: q = 3329. */
#define Q 3329
/** @brief Inverso multiplicativo de q módulo 2^16, na forma assinada (equivale a 62209 não assinado). */
#define QINV (-3327) /* q^(-1) mod 2^16 (signed) = 62209 unsigned */

/**
 * @brief Redução de Barrett: devolve a representado em [-q/2, q/2] (CT-REQUIRED).
 * @details Calcula v = round(a * 2^26 / q) como (20159*a + 2^25) >> 26, onde
 *          20159 = round(2^26 / q), e retorna a - v*q. Não contém nenhuma
 *          comparação ou desvio condicional: o resultado é função apenas do
 *          valor de `a`, o que torna o fluxo de controle independente do
 *          dado.
 * @param[in] a Valor a reduzir; o domínio esperado é o intervalo de int16_t.
 * @return    Congruente a `a` módulo q, com valor absoluto menor ou igual a q/2.
 * @note      Não idempotente em todos os valores de entrada: entradas fora do
 *            intervalo podem produzir resultados ainda fora de [-q/2, q/2].
 */
static int16_t barrett_reduce(int16_t a) {
    /* v = round(2^26 / q) = 20159 */
    int16_t t = (int16_t)(((int32_t)20159 * a + (1 << 25)) >> 26);
    t = (int16_t)(a - t * Q);
    return t;
}

/**
 * @brief Redução de Montgomery por 2^16 (CT-REQUIRED).
 * @details Calcula t = a * QINV mod 2^16 e retorna (a - t*q) / 2^16. Como
 *          t*q ≡ a (mod 2^16), a subtração é divisível por 2^16 e a divisão
 *          é uma troca aritmética exata de bits; o valor retornado é
 *          congruente a a * 2^(-16) módulo q. Sem ramificações.
 * @param[in] a Produto em 32 bits a ser reduzido.
 * @return    Congruente a a * 2^(-16) módulo q.
 * @pre       `a` deve estar no intervalo que garante que a - t*q caiba em
 *            32 bits (produções de MUL16 por coeficientes de int16_t).
 */
static int16_t montgomery_reduce(int32_t a) {
    int16_t t = (int16_t)((int16_t)a * (int16_t)QINV);
    t = (int16_t)((a - (int32_t)t * Q) >> 16);
    return t;
}

/* CT-REQUIRED: Constant-time conditional move (no branch on b) */
#ifndef ZUPT_USE_JASMIN
/**
 * @brief Cópia condicional por máscara de bits: r := x quando b for 1 (fallback C).
 * @details Expande o bit menos significativo de `b` na máscara 0x00 ou 0xFF
 *          e aplica a identidade r ^= mask & (r ^ x) em cada byte. O laço
 *          percorre `len` bytes independentemente do valor de `b`, e não há
 *          desvio baseado em `b`; o tempo de execução depende apenas de `len`.
 * @param[in,out] r   Buffer de destino, atualizado condicionalmente.
 * @param[in]     x   Buffer de origem, lido integralmente.
 * @param[in]     len Número de bytes afetados.
 * @param[in]     b   Seletor: usa apenas o bit menos significativo (0 mantém, 1 copia).
 * @pre         `r` e `x` têm pelo menos `len` bytes válidos.
 * @note        Compilada somente quando ZUPT_USE_JASMIN não está definido.
 *              Quando Jasmin está habilitado, zupt_ct_select_32() assume o
 *              papel na decapsulação.
 */
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
 * @brief Tabela de raízes da NTT: zetas[i] = 17^BitRev7(i) * R mod q, em forma assinada.
 * @details Contém os 128 fatores de torção pré-computados usados por ntt(),
 *          inv_ntt() e poly_basemul(): a raiz primitiva de ordem 256
 *          zeta = 17 (17^256 ≡ 1 mod 3329) elevada à ordem bit-reversed de 7
 *          bits, multiplicada pela constante de Montgomery R = 2^16 mod q, e
 *          armazenada como int16_t. Atenção: 61 das 128 entradas são ≥ q/2
 *          (= 1665), isto é, resíduos positivos congruentes a negativos — a
 *          tabela não está toda no intervalo [-q/2, q/2] citado pelo comentário
 *          adjacente ao código. Os primeiros 64 itens são consumidos pela
 *          transformada (k cresce em ntt e decresce em inv_ntt) e os últimos
 *          64, de zetas[64], pelo produto ponto a ponto de basemul. Não contém
 *          dados secretos.
 */
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
 * @brief Transformada Numérica Teórica direta de 256 pontos, Cooley-Tukey decimada.
 * @details Percorre os estágios de comprimento len = 128, 64, ..., 2. Em cada
 *          borboleta calcula t = zeta * r[j+len] por montgomery_reduce(), e
 *          substitui o par por (r[j] + t, r[j] - t). Ao final, os coeficientes
 *          estão na base da NTT com um fator de Montgomery R pendente
 *          (compensado por poly_tomont() ou por basemul).
 *          Os índices de tabela (`zetas[k++]`) e os limites de laço dependem
 *          apenas da estrutura fixa de 256 coeficientes, não do conteúdo de
 *          `r`; não há comparação de dados dentro do laço.
 * @param[in,out] r Polinômio de 256 coeficientes, transformado in-place.
 * @post        Os coeficientes ficam na forma NTT desta implementação, na
 *              ordem de índice usada por poly_basemul(). O fator de escala
 *          conjunto com inv_ntt() é medido na documentação de inv_ntt():
 *          inv_ntt(ntt(a)) ≡ 2^16 · a (mod q).
 * @see         inv_ntt(), poly_basemul()
 */
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
 * @brief NTT inversa: reconstrói o polinômio padrão a partir da forma NTT.
 * @details Executa o esquema de Gentleman-Sande de ponta a cabeça da
 *          transformada direta (len = 2, 4, ..., 128), consumindo a MESMA
 *          tabela zetas com k decrescendo de 127. Cada borboleta faz
 *          r[j] = Barrett(r[j] + r[j+len]) e
 *          r[j+len] = montgomery(zeta * (r[j+len] - t)). Termina aplicando
 *          montgomery_reduce(1441 * r[i]) a todos os coeficientes, o que
 *          equivale a multiplicá-los por 1441 · R^(-1) = 512 mod q.
 *          O efeito combinado das duas transformadas é
 *          inv_ntt(ntt(a)) ≡ R · a = 2^16 · a (mod q), medido
 *          experimentalmente: o resultado fica no domínio de Montgomery
 *          (semântica "invntt_tomont" da referência pqcrystals/kyber), e não
 *          no domínio plano. Estrutura de laço fixa; nenhum índice depende
 *          dos dados.
 * @param[in,out] r Polinômio de 256 coeficientes na forma NTT, convertido in-place.
 * @see         ntt()
 */
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
 * @typedef poly
 * @brief Polinômio de 256 coeficientes int16_t sobre Z_q, com q = 3329.
 * @details O índice do array corresponde à potência de x; o anel é
 *          Z_q[x]/(x^256 + 1). Fora das fronteiras de codificação, um
 *          coeficiente pode ser negativo ou exceder q; apenas poly_reduce(),
 *          a codificação em bytes e a compressão normalizam o valor.
 * @see     polyvec, poly_reduce()
 */
typedef int16_t poly[256];
/**
 * @typedef polyvec
 * @brief Vetor de MLKEM_K (= 3) polinômios, isto é, um array de poly.
 * @details Usado para s, e, t_hat, A_hat e u. Sendo poly um typedef de
 *          array, polyvec é um array de arrays; isso impede a conversão
 *          multi-nível para const em C11 (ver polyvec_pointwise_acc()).
 */
typedef poly polyvec[MLKEM_K];

/* Pointwise multiply in NTT domain (basemul per FIPS 203 §4.4)
 * CT-REQUIRED: No secret-dependent branches.
 * Reference: pqcrystals/kyber basemul — each fqmul is a separate montgomery_reduce.
 * r[0] = fqmul(fqmul(a1,b1), zeta) + fqmul(a0,b0)
 * r[1] = fqmul(a0,b1) + fqmul(a1,b0)
 * Second pair uses -zeta. */
/**
 * @brief Produto ponto a ponto de dois pares de coeficientes na NTT (basemul).
 * @details Bloco elementar do produto de polinômios em NTT (FIPS 203 §4.4):
 *          calcula o produto no quociente Z_q[x]/(x^2 - zeta). Cada produto
 *          de coeficientes é uma multiplicação de Montgomery separada, o que
 *          acumula um fator R^(-1) por chamada. As seis operações são
 *          executadas sempre, sem comparação sobre os dados.
 * @param[out] r     Par de coeficientes de saída (2 int16_t).
 * @param[in]  a     Par de coeficientes do primeiro fator.
 * @param[in]  b     Par de coeficientes do segundo fator.
 * @param[in]  zeta  Fator de torção do par; poly_basemul() passa -zeta no
 *                    segundo par.
 * @pre       Cada elemento de `a`, `b` e `zeta` cabe em int16_t.
 * @see       poly_basemul(), montgomery_reduce()
 */
static void basemul_pair(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta) {
    r[0] = montgomery_reduce((int32_t)montgomery_reduce((int32_t)a[1] * b[1]) * zeta);
    r[0] = (int16_t)(r[0] + montgomery_reduce((int32_t)a[0] * b[0]));
    r[1] = montgomery_reduce((int32_t)a[0] * b[1]);
    r[1] = (int16_t)(r[1] + montgomery_reduce((int32_t)a[1] * b[0]));
}

/**
 * @brief Produto de polinômios no domínio da NTT (basemul de 256 coeficientes).
 * @details Decompõe o anel Z_q[x]/(x^256+1) em 64 sub-anelos de grau 2. Para
 *          cada bloco i, aplica basemul_pair() com zeta = zetas[64+i] sobre a
 *          primeira dupla e com -zetas[64+i] sobre a segunda, o que
 *          corresponde às raízes ±zeta do quociente. O laço percorre sempre
 *          as 64 posições; nenhum índice depende dos dados.
 * @param[out] r Resultado em NTT: r = a ∘ b (produto de Montgomery).
 * @param[in]  a Primeiro fator em NTT.
 * @param[in]  b Segundo fator em NTT.
 * @note       O resultado carrega um fator R^(-1) relativo ao produto exato;
 *             poly_tomont() o compensa quando necessário.
 * @see        basemul_pair(), poly_tomont()
 */
static void poly_basemul(poly r, const poly a, const poly b) {
    for (int i = 0; i < 64; i++) {
        basemul_pair(&r[4*i],   &a[4*i],   &b[4*i],    zetas[64 + i]);
        basemul_pair(&r[4*i+2], &a[4*i+2], &b[4*i+2], (int16_t)(-zetas[64 + i]));
    }
}

/**
 * @brief Soma dois polinômios coeficiente a coeficiente, sem redução modilar.
 * @param[out] r Resultado (pode sobrepor a ou b).
 * @param[in]  a Parcela.
 * @param[in]  b Parcela.
 * @note       Não reduz: os resultados podem exceder o intervalo [-Q, Q] e
 *             precisam de poly_reduce() antes de qualquer serialização.
 */
static void poly_add(poly r, const poly a, const poly b) {
    for (int i = 0; i < 256; i++) r[i] = a[i] + b[i];
}

/**
 * @brief Subtrai dois polinômios coeficiente a coeficiente, sem redução modilar.
 * @param[out] r Resultado (pode sobrepor a ou b).
 * @param[in]  a Minuendo.
 * @param[in]  b Subtraendo.
 * @note       Mesmo comportamento de poly_add(): nenhuma redução é aplicada.
 */
static void poly_sub(poly r, const poly a, const poly b) {
    for (int i = 0; i < 256; i++) r[i] = a[i] - b[i];
}

/**
 * @brief Reduz todos os coeficientes de um polinômio para o intervalo padrão.
 * @param[in,out] r Polinômio reduzido no lugar.
 * @see           barrett_reduce()
 */
static void poly_reduce(poly r) {
    for (int i = 0; i < 256; i++) r[i] = barrett_reduce(r[i]);
}

/** @brief Constante 2³² mod Q = 1353, usada para levar coeficientes ao domínio de Montgomery. */
#define TOMONT_CONST 1353  /* 2^32 mod 3329 — verified: 4294967296 mod 3329 = 1353 */

/**
 * @brief Converte um polinômio para o domínio de Montgomery (multiplica por R = 2¹⁶).
 * @param[in,out] r Polinômio convertido no lugar.
 * @details       Aplica mont(r[i]) = r[i] · TOMONT_CONST · R⁻¹ mod Q. Como
 *                TOMONT_CONST = 2³² mod Q, o resultado é r[i] · 2³² · 2⁻¹⁶ = r[i]·R.
 *                A compensação é necessária porque poly_basemul() acumula produtos com
 *                um fator R⁻¹ por multiplicação.
 * @see           poly_basemul(), montgomery_reduce()
 */
static void poly_tomont(poly r) {
    for (int i = 0; i < 256; i++)
        r[i] = montgomery_reduce((int32_t)r[i] * TOMONT_CONST);
}

/**
 * @brief Aplica a NTT direta nos k polinômios de um polyvec.
 * @param[in,out] pv Polinômios transformados no lugar.
 * @see           ntt()
 */
static void polyvec_ntt(polyvec pv) {
    for (int i = 0; i < MLKEM_K; i++) ntt(pv[i]);
}

/**
 * @brief Aplica a NTT inversa nos k polinômios de um polyvec.
 * @param[in,out] pv Polinômios transformados no lugar.
 * @see           inv_ntt()
 */
static void polyvec_invntt(polyvec pv) {
    for (int i = 0; i < MLKEM_K; i++) inv_ntt(pv[i]);
}

/* C11 §6.7.3: arrays-of-arrays cannot undergo multi-level const conversion.
 * Reference pqcrystals/kyber uses non-const polyvec parameters for the same reason.
 * These functions do not modify the input arrays. */
/**
 * @brief Acumula o produto interno de dois polyvecs no domínio da NTT.
 * @param[out] r Resultado: r = Σᵢ basemul(a[i], b[i]), reduzido mod Q.
 * @param[in]  a Polinômios em NTT (MLKEM_K entradas).
 * @param[in]  b Polinômios em NTT (MLKEM_K entradas).
 * @details    Executa poly_basemul() para cada par e soma os resultados com
 *             poly_add(), que não reduz; por isso poly_reduce() é aplicado no
 *             final para manter os coeficientes dentro de [-Q, Q].
 * @see        poly_basemul(), poly_reduce()
 */
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
 * @brief Amostra um polinômio da distribuição binomial centrada CBD(η = 2).
 * @param[out] r   Polinômio amostrado; cada coeficiente fica em [-2, 2].
 * @param[in]  buf 128 bytes de bytes aleatórios (η·N/4 = 2·256/4).
 * @details    Processa 4 bits por coeficiente: lê palavras de 32 bits
 *             (little-endian), soma os pares de bits adjacentes com aritmética
 *             de máscara (0x55555555) e produz r[i] = a − b, onde a e b são as
 *             parcelas de 2 bits consecutivas. Nenhum desvio de fluxo depende
 *             dos dados: os laços percorrem sempre os 32 bytes inteiros.
 * @see        poly_noise()
 */
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
 * @brief Amostra um polinômio com distribuição uniforme por rejeição.
 * @param[out] r    Polinômio resultante com coeficientes em [0, Q−1].
 * @param[in]  seed Semente de 32 bytes (eta do algoritmo ou seedB).
 * @param[in]  i    Índice da linha da matriz.
 * @param[in]  j    Índice da coluna da matriz.
 * @details    Deriva a semente estendida `seed || i || j` (34 bytes), gera o
 *             fluxo com SHAKE-128 e agrupa 3 bytes em dois candidatos de 12
 *             bits (d1 = bits 0–11, d2 = bits 12–23). Candidatos ≥ Q são
 *             descartados (rejeição). O laço roda até obter os 256
 *             coeficientes, portanto o número de iterações depende dos dados —
 *             ver finding sobre o padrão de rejeição.
 * @see        zupt_shake128_squeeze()
 */
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
 * @brief Amostra um polinômio de ruído (eta = 2) via PRF + CBD.
 * @param[out] r     Polinômio de ruído com coeficientes em [-2, 2].
 * @param[in]  seed  Semente secreta (d do keygen ou r da cifra).
 * @param[in]  nonce Byte de domínio que separa cada polinômio amostrado.
 * @details    Gera 128 bytes com SHAKE-256 sobre `seed || nonce` e aplica
 *             CBD(η = 2). Uso: s, e no keygen; r, e₁, e₂ na cifra.
 * @see        cbd2()
 */
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
 * @brief Serializa um polinômio em 12 bits por coeficiente (ByteEncode₁₂).
 * @param[out] r Buffer de saída com 384 bytes (3 bytes por par de coeficientes).
 * @param[in]  a Polinômio de entrada.
 * @details    Normaliza cada coeficiente para [0, Q−1] com `((x % Q) + Q) % Q`
 *             e empacota dois valores de 12 bits little-endian em 3 bytes.
 * @see        poly_frombytes()
 */
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
 * @brief Reconstrói um polinômio a partir de ByteEncode₁₂ (384 bytes).
 * @param[out] r Polinômio reconstruído; coeficientes em [0, 4095].
 * @param[in]  a Buffer de entrada com 384 bytes.
 * @note       Não valida nem reduz: valores acima de Q são preservados como
 *             vieram do buffer, comportamento esperado do ByteDecode₁₂.
 * @see        poly_tobytes()
 */
static void poly_frombytes(poly r, const uint8_t *a) {
    for (int i = 0; i < 256/2; i++) {
        r[2*i]   = (int16_t)(((uint16_t)a[3*i] | ((uint16_t)(a[3*i+1] & 0x0F) << 8)));
        r[2*i+1] = (int16_t)(((uint16_t)(a[3*i+1] >> 4) | ((uint16_t)a[3*i+2] << 4)));
    }
}

/* Compress: round(2^d / q * x) mod 2^d */
/**
 * @brief Comprime um polinômio para d bits por coeficiente (Compress_q,ₔ).
 * @param[out] r Buffer de saída: 320 bytes com d = 10, 128 bytes com d = 4.
 * @param[in]  a Polinômio de entrada.
 * @param[in]  d Número de bits por coeficiente. Apenas 10 (componente u) e
 *              4 (componente v) são suportados.
 * @details    Aplica `round(2^d·x / Q) mod 2^d` com arredondamento "round half up"
 *             implementado como `(x·2^d + Q/2) / Q`, após normalizar x para
 *             [0, Q−1]. Se d não for 10 nem 4, a função não escreve nada no
 *             buffer de saída (nenhum else cobre outros valores).
 * @see        poly_decompress()
 */
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
 * @brief Descomprime d bits por coeficiente de volta ao anel Z_q (Decompress_q,ₔ).
 * @param[out] r Polinômio reconstruído.
 * @param[in]  a Buffer de entrada: 320 bytes com d = 10, 128 bytes com d = 4.
 * @param[in]  d Bits por coeficiente; apenas 10 e 4 são suportados.
 * @details    Reconstrói com `(t·Q + 2^(d−1)) >> d`, o que aproxima t de `round(t·Q/2^d)`.
 *             Os valores resultantes não são exatamente os originais — apenas o
 *             intervalo aproximado é preservado, que é o objetivo da compressão.
 * @warning    Para d ≠ 10 e d ≠ 4 nenhum coeficiente é escrito (ausência de else).
 * @see        poly_compress()
 */
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
 * @brief Serializa os k polinômios de um polyvec em 384·k bytes (12 bits por coeficiente).
 * @param[out] r Buffer de saída (MLKEM_K·384 bytes).
 * @param[in]  a Polyvec de entrada.
 * @see        poly_tobytes()
 */
static void polyvec_tobytes(uint8_t *r, polyvec a) {
    for (int i = 0; i < MLKEM_K; i++) poly_tobytes(r + i*384, a[i]);
}

/**
 * @brief Reconstrói um polyvec a partir de 384·k bytes serializados.
 * @param[out] r Polyvec reconstruído.
 * @param[in]  a Buffer de entrada (MLKEM_K·384 bytes).
 * @see        poly_frombytes()
 */
static void polyvec_frombytes(polyvec r, const uint8_t *a) {
    for (int i = 0; i < MLKEM_K; i++) poly_frombytes(r[i], a + i*384);
}

/**
 * @brief Comprime um polyvec com MLKEM_DU (10) bits por coeficiente.
 * @param[out] r Buffer de saída (MLKEM_K·320 bytes = 1280 bytes para k = 4).
 * @param[in]  a Polyvec de entrada (componente u da cifra).
 * @see        poly_compress()
 */
static void polyvec_compress(uint8_t *r, polyvec a) {
    for (int i = 0; i < MLKEM_K; i++) poly_compress(r + i*320, a[i], MLKEM_DU);
}

/**
 * @brief Descomprime um polyvec comprimido com MLKEM_DU (10) bits por coeficiente.
 * @param[out] r Polyvec reconstruído.
 * @param[in]  a Buffer de entrada (MLKEM_K·320 bytes = 1280 bytes para k = 4).
 * @see        poly_decompress()
 */
static void polyvec_decompress(polyvec r, const uint8_t *a) {
    for (int i = 0; i < MLKEM_K; i++) poly_decompress(r[i], a + i*320, MLKEM_DU);
}

/* ═══════════════════════════════════════════════════════════════════
 * K-PKE: IND-CPA-secure public key encryption (FIPS 203 §7.2-7.3)
 * ═══════════════════════════════════════════════════════════════════ */

/* Generate K-PKE keypair. d = random 32-byte seed. */
/**
 * @brief Gera o par de chaves do esquema K-PKE subjacente (FIPS 203 §6.10).
 * @param[out] pk      Chave pública K-PKE: 1184 bytes (k·384 de t̂ em NTT + 32 de ρ).
 * @param[out] sk_pke Chave secreta K-PKE: 1152 bytes (k·384 de ŝ serializados em NTT).
 * @param[in]  d      Semente de 32 bytes (aleatória ou derivada pelo encapsulamento).
 * @details    Deriva `G(d ‖ k)` com SHA3-512, obtendo ρ (semente da matriz) e σ
 *             (semente de ruído). A matriz Â é amostrada por rejeição com
 *             `Uniform(ρ, j, i)` — índices trocados de propósito, porque a cifra
 *             consome Aᵀ e precisa regerar exatamente os mesmos coeficientes.
 *             Depois: ŝ, ê ← CBD(η=2) com σ (nonces 0..k−1 e k..2k−1),
 *             t̂ = Â∘ŝ + ê, sendo poly_tomont() aplicado após o acumulador para
 *             compensar o fator R⁻¹ da multiplicação de Montgomery.
 * @post       buf, s e e são limpos com zupt_secure_wipe() antes do retorno.
 * @see        poly_uniform(), poly_noise(), polyvec_pointwise_acc(), poly_tomont()
 */
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
 * @brief Cifra K-PKE (FIPS 203 §6.11): 32 bytes de mensagem sob uma chave pública.
 * @param[out] ct    Texto cifrado: 1088 bytes (k·320 de u comprimido + 32 de v).
 * @param[in]  pk    Chave pública K-PKE (1184 bytes: t̂ serializado + ρ).
 * @param[in]  m     Mensagem de 32 bytes (bits de mensagem no esquema CCA).
 * @param[in]  r     Randomness de 32 bytes usada pelo PRF (nonces 0..2k).
 * @param[in]  legacy Quando ≠ 0, gera Aᵀ com os índices trocados
 *                    `Uniform(ρ, j, i)` em vez do padrão desta versão.
 * @details    Regera Â a partir de ρ, amostra r̂, ê₁, ê₂ por CBD(η=2) e calcula
 *             u = NTT⁻¹(Âᵀ∘r̂) + ê₁ e v = NTT⁻¹(t̂ᵀ∘r̂) + ê₂ + Decompress(m, 1),
 *             com Decompress₁(mapeando cada bit para (Q+1)/2 = 1665).
 *             Antes da serialização aplica poly_reduce() e comprima u com 10 bits
 *             e v com 4 bits.
 * @warning    O parâmetro @p legacy muda a ordem dos índices usados para amostrar
 *             a matriz, produzindo cifrastes incompatíveis com o caminho padrão.
 *             Ver finding registrado para esta linha.
 * @post       r_vec, e1 e e2 são limpos com zupt_secure_wipe() antes do retorno.
 * @see        kpke_keygen(), kpke_decrypt(), polyvec_compress()
 */
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
 * @brief Decifra K-PKE (FIPS 203 §6.12) e recupera os 32 bytes da mensagem.
 * @param[out] m     Mensagem recuperada (32 bytes, um bit por coeficiente).
 * @param[in]  ct    Texto cifrado: 1088 bytes (k·320 de u + 32 de v).
 * @param[in]  sk_pke Chave secreta K-PKE: 1152 bytes (k·384 de ŝ serializados).
 * @details    Descomprime u (10 bits) e v (4 bits), aplica NTT em u, acumula
 *             ŝ∘û, volta com inv_ntt() e calcula w = v − ŝᵀ·û. Cada coeficiente é
 *             convertido em bit pelo arredondamento `round(2·x/Q)` — o bit mais
 *             próximo de 0 ou Q/2. Nenhum teste de integridade é feito: o valor
 *             retornado é simplesmente o resultado da decifração algébrica.
 * @post       s_hat é limpo com zupt_secure_wipe() antes do retorno.
 * @see        kpke_encrypt(), polyvec_decompress()
 */
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
 * @brief Valida a estrutura de uma chave pública ML-KEM-768.
 * @param[in] pk Buffer de 1184 bytes a validar.
 * @retval  0 Chave estruturalmente válida.
 * @retval -1 Ponteiro nulo ou pelo menos um coeficiente fora do intervalo.
 * @details Percorre os 1152 bytes do bloco t̂ em pares de 12 bits e acumula, em
 *          `invalid`, o resultado de testar cada valor contra Q (3329). Só a
 *          parte de t̂ é verificada: os 32 bytes finais (ρ) são uma semente
 *          arbitrária e não passam por nenhum teste. A comparação é feita por
 *          acumulação de bits em vez de `return` imediato, para não revelar
 *          em qual posição a chave foi rejeitada.
 * @note    O bloco ACSL que aparece acima desta função no código descreve a
 *          geração de chaves (`assigns pk, sk`), não esta verificação — ver
 *          finding registrado para este ponto.
 * @see     zupt_mlkem768_keygen()
 */
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
 * @brief Valida o vínculo entre a chave pública embutida e a chave secreta.
 * @param[in] sk Buffer de 2400 bytes a validar.
 * @retval  0 Vínculo confere (a chave é estruturalmente íntegra).
 * @retval -1 Ponteiro nulo ou hash divergente.
 * @details Recomputa SHA3-256 sobre o bloco de chave pública armazenado em
 *          `sk[1152..2335]` (1184 bytes) e compara os 32 bytes resultantes com
 *          `sk[2336..2367]`. A comparação acumula XOR (`diff`) para percorrer os
 *          32 bytes por completo. Nada é apagado em caso de falha: a função é
 *          apenas uma verificação e não altera o buffer.
 * @note    Não confere os 32 bytes finais de `z` (sk[2368..2399]) — apenas o
 *          vínculo H(ek) descrito acima.
 * @see     zupt_mlkem768_keygen()
 */
int zupt_mlkem768_secret_key_check(const uint8_t sk[2400]) {
    if (!sk) return -1;
    uint8_t h[32], diff = 0;
    zupt_sha3_256(sk + 1152, 1184, h);
    for (size_t i = 0; i < 32; ++i) diff |= h[i] ^ sk[2336 + i];
    zupt_secure_wipe(h, sizeof(h));
    return diff ? -1 : 0;
}

/**
 * @brief Gera o par de chaves ML-KEM-768 a partir de duas sementes explícitas.
 * @param[out] pk Chave pública: 1184 bytes (t̂ serializado + ρ).
 * @param[out] sk Chave secreta: 2400 bytes (sk_pke ‖ pk ‖ H(pk) ‖ z).
 * @param[in]  d  Semente de 32 bytes que deriva ρ e σ do K-PKE.
 * @param[in]  z  Semente de 32 bytes usada no encapsulamento (transformação FO).
 * @retval 0 Sempre (não há caminho de erro nesta função interna).
 * @details Monta exatamente a codificação de chave secreta da FIPS 203:
 *          sk_pke (1152) ‖ ek (1184) ‖ H(ek) (32) ‖ z (32). O bloco H(ek) é o
 *          verificado por zupt_mlkem768_secret_key_check().
 * @post    sk_pke é limpo com zupt_secure_wipe() antes do retorno.
 * @see     kpke_keygen(), zupt_mlkem768_secret_key_check()
 */
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
 * @brief Gera um par de chaves ML-KEM-768 com aleatoriedade do sistema.
 * @param[out] pk Chave pública: 1184 bytes.
 * @param[out] sk Chave secreta: 2400 bytes (sk_pke ‖ pk ‖ H(pk) ‖ z).
 * @retval  0 Chaves geradas com sucesso.
 * @retval -1 Pelo menos um dos ponteiros recebidos é nulo.
 * @details Obtém duas sementes de 32 bytes via zupt_random_bytes() e delega a
 *          mlkem_keygen_internal().
 * @post    d e z são limpos com zupt_secure_wipe() antes de qualquer retorno
 *          (inclusive na rota de erro, que ocorre antes do wipe — nesse caso
 *          os buffers ainda não haviam sido preenchidos).
 * @see     mlkem_keygen_internal(), zupt_mlkem768_secret_key_check()
 */
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
 * @brief Encapsulamento ML-KEM-768 com mensagem explícita (algoritmo interno).
 * @param[out] ct Texto cifrado: 1088 bytes.
 * @param[out] ss Segredo compartilhado: 32 bytes (ko, a primeira metade de G).
 * @param[in]  pk Chave pública: 1184 bytes.
 * @param[in]  m  Mensagem de 32 bytes que determina a aleatoriedade.
 * @retval  0 Segredo encapsulado com sucesso.
 * @retval -1 Chave pública rejeitada pela validação estrutural.
 * @details Calcula `input = m ‖ H(pk)` (H = SHA3-256) e `kr = SHA3-512(input)`.
 *          A primeira metade de kr é o segredo compartilhado devolvido e a segunda
 *          metade é a randomness passada a kpke_encrypt() com o caminho padrão
 *          (`legacy = 0`). Não há KDF final: o segredo é kr[0..31] diretamente.
 * @post    input e kr são limpos com zupt_secure_wipe() em todos os retornos.
 * @see     kpke_encrypt(), zupt_mlkem768_encaps()
 */
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
 * @brief Encapsula um segredo de 32 bytes sob uma chave pública ML-KEM-768.
 * @param[out] ct Texto cifrado: 1088 bytes (k·320 de u + 32 de v).
 * @param[out] ss Segredo compartilhado: 32 bytes, sempre diferente de tudo que
 *                a decifração com a chave correta não devolve.
 * @param[in]  pk Chave pública: 1184 bytes.
 * @retval  0 Segredo encapsulado com sucesso.
 * @retval -1 Algum ponteiro é nulo ou a chave pública falha na validação
 *           estrutural (zupt_mlkem768_public_key_check).
 * @details Gera uma mensagem m de 32 bytes com zupt_random_bytes() e a usa como
 *          entropia do encapsulamento; m é apagada antes do retorno.
 * @post    m é limpa com zupt_secure_wipe() antes do retorno.
 * @see     zupt_mlkem768_decaps(), mlkem_encaps_internal()
 */
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
 * @brief Decapsulamento ML-KEM-768 (transformação Fujisaki–Okamoto).
 * @param[out] ss Segredo compartilhado: 32 bytes.
 * @param[in]  ct Texto cifrado: 1088 bytes.
 * @param[in]  sk Chave secreta: 2400 bytes (sk_pke ‖ pk ‖ H(pk) ‖ z).
 * @param[in]  legacy Seletor de formato público (0 = FIPS 203, ≠0 = formato legado).
 * @retval  0 Sempre, inclusive na rejeição implícita — neste caso @p ss recebe o
 *           segredo de rejeição e não há distinção observável de falha.
 * @retval -1 Algum ponteiro é nulo, ou (no caminho não legado) a chave secreta
 *           falha em zupt_mlkem768_secret_key_check().
 * @details Decifra ct para m, recomputa `kr = SHA3-512(m ‖ H(pk))` e re-cifra m
 *          com a randomness kr[32..63]. A igualdade ct == ct' é acumulada em
 *          `diff` (varredura completa, sem saída antecipada) e convertida na
 *          máscara `fail` por aritmética sem sinal: `(diff | −diff) >> 31` vale
 *          0xFF quando há divergência.
 *          Caminho não legado: segredo bom = kr[0..31]; segredo de rejeição =
 *          SHAKE-256(z ‖ ct), isto é, J(z ‖ c) da FIPS 203 (não J(z ‖ H(c))).
 *          Caminho legado: bom = SHAKE-256(ko ‖ H(ct)); rejeição = SHAKE-256(z).
 *          A escolha entre bom e rejeição usa máscara: zupt_ct_select_32() sob
 *          ZUPT_USE_JASMIN, ou memcpy + cmov() com `1 − fail` caso contrário.
 * @note     O parâmetro @p legacy é um seletor de formato exposto na fronteira,
 *           não um dado secreto; não há decisão secreta dependente de ramo.
 * @post     m, input, kr, check_ct, good, reject, reject_input, diff e fail são
 *           limpos com zupt_secure_wipe() antes do retorno.
 * @see      zupt_mlkem768_decaps(), zupt_legacy_mlkem768_decaps(), cmov(), zupt_ct_select_32()
 */
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
 * @brief Decapsula um texto cifrado ML-KEM-768 no formato atual (FIPS 203).
 * @param[out] ss Segredo compartilhado: 32 bytes. Em rejeição implícita, o
 *                segredo derivado de `J(z ‖ ct)` — não há código de erro.
 * @param[in]  ct Texto cifrado: 1088 bytes.
 * @param[in]  sk Chave secreta: 2400 bytes.
 * @retval  0 Processado (inclusive quando o cifraste é inválido — rejeição
 *           implícita, sem distinção observável).
 * @retval -1 Ponteiro nulo ou chave secreta estruturalmente inválida.
 * @see      mlkem_decaps_internal()
 */
int zupt_mlkem768_decaps(uint8_t ss[32], const uint8_t ct[1088],
                        const uint8_t sk[2400]) {
    return mlkem_decaps_internal(ss, ct, sk, 0);
}

/**
 * @brief Decapsula um texto cifrado no formato legado de ML-KEM-768.
 * @param[out] ss Segredo compartilhado: 32 bytes. No caminho legado o segredo
 *                "bom" é SHAKE-256(ko ‖ H(ct)) e a rejeição é SHAKE-256(z).
 * @param[in]  ct Texto cifrado legado: 1088 bytes amostrados com a ordem de
 *                índices antiga da matriz Aᵀ (ver kpke_encrypt()).
 * @param[in]  sk Chave secreta: 2400 bytes. A validação estrutural é ignorada
 *                neste caminho.
 * @retval  0 Sempre que os ponteiros forem válidos.
 * @retval -1 Algum ponteiro é nulo.
 * @warning Existe apenas para migração autenticada de arquivos antigos; o
 *          formato legado não é compatível com o cifraste produzido por
 *          zupt_mlkem768_encaps().
 * @note    Símbolo interno: não declarado na interface pública instalada.
 * @see      mlkem_decaps_internal(), kpke_encrypt()
 */
int zupt_legacy_mlkem768_decaps(uint8_t ss[32], const uint8_t ct[1088],
                               const uint8_t sk[2400]) {
    return mlkem_decaps_internal(ss, ct, sk, 1);
}

#ifdef ZUPT_TESTING
/* Deterministic ACVP entry points are compiled only into the test executable. */
/**
 * @brief Ponto de entrada determinístico de keygen para vetores ACVP.
 * @param[out] pk Chave pública: 1184 bytes.
 * @param[out] sk Chave secreta: 2400 bytes.
 * @param[in]  d  Semente d fornecida pelo vetor (32 bytes).
 * @param[in]  z  Semente z fornecida pelo vetor (32 bytes).
 * @retval 0 Sempre (delegação direta a mlkem_keygen_internal).
 * @note   Compilado somente com ZUPT_TESTING definido; consumido por
 *         scripts/check-acvp.py.
 * @see    mlkem_keygen_internal()
 */
int zupt_test_mlkem_keygen(uint8_t pk[1184], uint8_t sk[2400],
                          const uint8_t d[32], const uint8_t z[32]) {
    return mlkem_keygen_internal(pk, sk, d, z);
}

/**
 * @brief Ponto de entrada determinístico de encapsulamento para vetores ACVP.
 * @param[out] ct Texto cifrado: 1088 bytes.
 * @param[out] ss Segredo compartilhado: 32 bytes.
 * @param[in]  pk Chave pública: 1184 bytes.
 * @param[in]  m  Mensagem do vetor (32 bytes), em lugar da aleatoriedade.
 * @retval  0 Encapsulado com sucesso.
 * @retval -1 Chave pública rejeitada pela validação estrutural.
 * @note   Compilado somente com ZUPT_TESTING definido.
 * @see    mlkem_encaps_internal()
 */
int zupt_test_mlkem_encaps(uint8_t ct[1088], uint8_t ss[32],
                          const uint8_t pk[1184], const uint8_t m[32]) {
    return mlkem_encaps_internal(ct, ss, pk, m);
}
#endif

/* ═══════════════════════════════════════════════════════════════════
 * SELF-TEST — verify internal operations
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * @brief Autoteste das operações internas de ML-KEM-768.
 * @retval  0 Todas as verificações passaram.
 * @retval -1 Pelo menos uma verificação falhou (detalhes impressos em stderr).
 * @details Executa três verificações independentes:
 *          1. Idempotência da NTT: aplica ntt() e inv_ntt() sobre um polinômio
 *             determinístico (`a[i] = i·17 mod Q`) e compara `montgomery_reduce(b[i])`
 *             com `a[i]`, compensando o fator de Montgomery residual do par de
 *             transformadas.
 *          2. Ciclo K-PKE: kpke_keygen → kpke_encrypt → kpke_decrypt com
 *             aleatoriedade do sistema, exigindo m == m′.
 *          3. Ciclo KEM completo: keygen → encaps → decaps, exigindo ss == ss′.
 * @note    Comporta-se como teste: usa saída antecipada (`break`/`return`) e
 *          imprime em stderr, o que não seria aceitável em código criptográfico
 *          em execução normal.
 * @see     zupt_mlkem768_encaps(), zupt_mlkem768_decaps()
 */
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
