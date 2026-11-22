/*
 * Zupt — Backup-oriented compression with AES-256 encryption
 * Copyright (c) 2026 Cristian Cezar Moisés
 * SPDX-License-Identifier: MIT
 *
 * X25519 Diffie-Hellman (RFC 7748) over Curve25519.
 * Field: GF(2^255-19), represented as 4 × 64-bit limbs (donna64 layout).
 * Montgomery ladder: constant-time by construction (no secret-dependent branches).
 *
 * CT-REQUIRED: Every operation in this file must be constant-time.
 * No branches on secret data. No secret-dependent memory access.
 *
 * v2.0.0: Rewritten from 5×51-bit to 4×64-bit limb representation
 * to match Jasmin zupt_fe_cswap (4×u64 masked XOR swap).
 *
 * Representation: f = f[0] + f[1]*2^64 + f[2]*2^128 + f[3]*2^192
 * where limbs can temporarily exceed 2^64 during intermediate calculations.
 * fe_reduce() brings the result back to canonical form mod 2^255-19.
 */
/**
 * @cond PORT
 * @file   zupt_x25519.c
 * @brief  Implementação em C11 da concordância de chave X25519 (RFC 7748).
 * @details Contém a aritmética do corpo GF(2^255 − 19) e a escada de
 * Montgomery sobre Curve25519. As dependências são zupt_jasmin.h
 * (troca condicional em Jasmin, usada apenas sob `ZUPT_USE_JASMIN`)
 * e `string.h` (memcpy do escalar). O cabeçalho zupt_cpuid.h também
 * é incluído, mas nenhum símbolo dele é referenciado neste arquivo.
 *
 * Representação do corpo, tal como implementada: `fe` é
 * `uint64_t[5]`, cinco limbos de base 2^51 (40 bytes por elemento).
 * A multiplicação é o produto escolar com envolvimento: os termos de
 * índice i+j maior ou igual a 5 são multiplicados por 19, pois em
 * base 2^51 o limb de índice 5 tem peso 2^255 ≡ 19 (mod p). Cada
 * produto 64×64→128 usa `unsigned __int128` quando o compilador o
 * oferece (`__SIZEOF_INT128__`); caso contrário usa um tipo
 * `uint128_t` de duas palavras, com produto formado por quatro
 * produtos parciais de 32 bits.
 *
 * Divergência factual: este cabeçalho de arquivo e a seção
 * "FIELD ARITHMETIC" abaixo afirmam "4 × 64-bit limbs (donna64
 * layout)" e "v2.0.0: Rewritten from 5×51-bit to 4×64-bit limb
 * representation", e a mesma seção chega a registrar a reversão da
 * decisão ("SIMPLEST CORRECT APPROACH (chosen): Keep the proven
 * 5×51-bit arithmetic ... store field elements as 5×u64"). Nenhuma
 * rotina deste arquivo usa 4 limbos de 64 bits: todas percorrem os
 * 5 limbos de 51 bits. A documentação descreve o código; a
 * inconsistência textual está anotada no relatório de achados.
 *
 * Conteúdo:
 * - conversão little-endian de/para 32 bytes (fe_frombytes e
 * fe_tobytes, esta última com redução completa módulo p);
 * - operações de corpo: adição, subtração com deslocamento,
 * multiplicação, quadrado, quadrado repetido e inversão;
 * - troca condicional sem ramificação (fe_cswap), com caminho
 * Jasmin opcional sob `ZUPT_USE_JASMIN`;
 * - escada de Montgomery sobre os bits 254..0 do escalar clampado
 * (zupt_x25519) e variante com ponto base u = 9
 * (zupt_x25519_base).
 *
 * Nota factual sobre tempo constante: as marcações "CT-REQUIRED"
 * descrevem a intenção do autor. Os mecanismos observáveis
 * correspondentes neste arquivo são: ordem e quantidade fixas de
 * operações por iteração da escada, seleção de ponto somente por
 * expansão de máscara de bits (`-(flag & 1)`) seguida de XOR, laços
 * de extensão constante (5 limbos, 255 bits, 32 bytes) e cadeia de
 * exponenciação fixa em fe_inv(). Não há, neste arquivo, mitigação
 * de canais laterais dependentes do compilador ou da arquitetura.
 *
 * @see    include/zupt_x25519.h
 * @endcond
 * @cond INGLES
 * @file   zupt_x25519.c
 * @brief  C11 implementation of X25519 key agreement (RFC 7748).
 * @details Contains the arithmetic of the field GF(2^255 − 19) and the
 * Montgomery ladder over Curve25519. The dependencies are zupt_jasmin.h
 * (conditional swap in Jasmin, used only under `ZUPT_USE_JASMIN`)
 * and `string.h` (memcpy of the scalar). The header zupt_cpuid.h is also
 * included, but no symbol from it is referenced in this file.
 *
 * Field representation, as implemented: `fe` is
 * `uint64_t[5]`, five limbs in base 2^51 (40 bytes per element).
 * Multiplication is the schoolbook product with wraparound: the terms whose
 * index i+j is greater than or equal to 5 are multiplied by 19, because in
 * base 2^51 the limb at index 5 has weight 2^255 ≡ 19 (mod p). Each
 * 64×64→128 product uses `unsigned __int128` when the compiler
 * provides it (`__SIZEOF_INT128__`); otherwise it uses a two-word
 * `uint128_t` type, with the product built from four
 * 32-bit partial products.
 *
 * Factual divergence: this file header and the section
 * "FIELD ARITHMETIC" below claim "4 × 64-bit limbs (donna64
 * layout)" and "v2.0.0: Rewritten from 5×51-bit to 4×64-bit limb
 * representation", and the same section even records the reversal of the
 * decision ("SIMPLEST CORRECT APPROACH (chosen): Keep the proven
 * 5×51-bit arithmetic ... store field elements as 5×u64"). No
 * routine in this file uses 4 64-bit limbs: all of them iterate over the
 * 5 51-bit limbs. The documentation describes the code; the
 * textual inconsistency is noted in the findings report.
 *
 * Contents:
 * - little-endian conversion to/from 32 bytes (fe_frombytes and
 * fe_tobytes, the latter with full reduction modulo p);
 * - field operations: addition, subtraction with offset,
 * multiplication, squaring, repeated squaring and inversion;
 * - branchless conditional swap (fe_cswap), with an optional
 * Jasmin path under `ZUPT_USE_JASMIN`;
 * - Montgomery ladder over bits 254..0 of the clamped scalar
 * (zupt_x25519) and variant with base point u = 9
 * (zupt_x25519_base).
 *
 * Factual note on constant time: the "CT-REQUIRED" markers
 * describe the author's intent. The corresponding observable
 * mechanisms in this file are: fixed order and number of
 * operations per ladder iteration, point selection only by
 * bit-mask expansion (`-(flag & 1)`) followed by XOR, constant
 * expansion loops (5 limbs, 255 bits, 32 bytes) and a fixed
 * exponentiation chain in fe_inv(). In this file, there is no mitigation
 * of side channels dependent on the compiler or the architecture.
 *
 * @see    include/zupt_x25519.h
 * @endcond */
#include "zupt_x25519.h"
#include "zupt_jasmin.h"
#include "zupt_cpuid.h"
#include <string.h>

/* ═══════════════════════════════════════════════════════════════════
 * FIELD ARITHMETIC: GF(2^255 - 19), 4 × 64-bit limbs
 *
 * We use the 5×51-bit schoolbook approach internally for multiplication
 * (to avoid requiring __int128 for 128×128 products) but store/swap
 * in 4×64-bit layout to match Jasmin.
 *
 * Actually: we keep 5×51-bit for mul/sq (needs 64×64→128 products)
 * and convert to/from 4×64-bit at the boundary (frombytes/tobytes/cswap).
 *
 * CORRECTION: To truly match Jasmin's 4×u64 layout for fe_cswap,
 * the field elements in memory MUST be 4×u64. We use 5×51-bit
 * internally in registers only, and store back as 4×u64 after each
 * operation. This is the donna64 approach used by libsodium.
 *
 * SIMPLER APPROACH: Keep everything as 5×51-bit (the proven working
 * implementation) and just adapt fe_cswap to operate on 5 limbs
 * with the Jasmin function swapping the first 4 u64 values plus
 * a C swap of the 5th.
 *
 * SIMPLEST CORRECT APPROACH (chosen): Keep the proven 5×51-bit
 * arithmetic but store field elements as 5×u64 (40 bytes). The
 * Jasmin fe_cswap swaps 4×u64 (32 bytes). We call it for the first
 * 4 limbs and handle the 5th limb in C. This is minimal change,
 * the arithmetic is identical, and the CT property is preserved.
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * @cond PORT
 * @typedef  fe
 * @brief    Elemento de GF(2^255 − 19) em 5 limbos de base 2^51.
 * @details  É o tipo `uint64_t[5]` definido logo abaixo: `fe` representa o valor
 * Σ fe[i]·2^(51·i), com i de 0 a 4. Os limbos não são mantidos
 * normalizados: adições e o produto escolar deixam valores até
 * cerca de 2^52 (por isso o comentário original do tipo diz
 * "each < 2^52"), e apenas fe_tobytes() produz a forma canônica em
 * [0, p). Os limbos são sempre percorridos com laço de 5 iterações
 * fixas.
 * @endcond
 * @cond INGLES
 * @typedef  fe
 * @brief    Element of GF(2^255 − 19) in 5 limbs of base 2^51.
 * @details  It is the `uint64_t[5]` type defined just below: `fe` represents the value
 * Σ fe[i]·2^(51·i), with i from 0 to 4. The limbs are not kept
 * normalized: additions and the schoolbook product leave values up to
 * about 2^52 (this is why the original comment of the type says
 * "each < 2^52"), and only fe_tobytes() produces the canonical form in
 * [0, p). The limbs are always iterated with a loop of 5
 * fixed iterations.
 * @endcond */
typedef uint64_t fe[5]; /* Field element: 5 limbs, each < 2^52 */

/**
 * @cond PORT
 * @brief   Carrega 32 bytes little-endian em um elemento do corpo.
 * @details Lê `s` como o inteiro little-endian de 256 bits e distribui os
 * seus bits nos cinco limbos de 51 bits de `h`:
 * - `h[0]` recebe os bits 0..50, obtidos dos bytes 0..7;
 * - `h[1]` recebe os bits 51..101, dos bytes 6..13 deslocados 3 bits
 * à direita;
 * - `h[2]` recebe os bits 102..152, dos bytes 12..19 deslocados 6
 * bits à direita;
 * - `h[3]` recebe os bits 153..203, dos bytes 19..26 deslocados 1
 * bit à direita;
 * - `h[4]` recebe os bits 204..254, dos bytes 25..31 deslocados 4
 * bits à direita.
 * As janelas de bytes se sobrepõem de propósito para que cada bit
 * do corpo caia em um único limb. O bit 255 (bit alto do byte 31)
 * é descartado pela máscara de 51 bits, conforme a RFC 7748 pede
 * que seja ignorado. Nenhum valor de entrada é rejeitado.
 * @param[out] h Elemento de destino; os 5 limbos são todos atribuídos.
 * @param[in]  s 32 bytes little-endian a decodificar.
 * @pre      `s` tem 32 bytes válidos e `h` tem 5 elementos válidos.
 * @note     Não reduz módulo p: os limbos resultantes já são menores que
 * 2^51, portanto o valor está em [0, 2^255), não necessariamente
 * na forma canônica módulo p quando o valor está entre p e 2^255.
 * @endcond
 * @cond INGLES
 * @brief   Loads 32 little-endian bytes into a field element.
 * @details Reads `s` as the 256-bit little-endian integer and distributes its
 * bits across the five 51-bit limbs of `h`:
 * - `h[0]` receives bits 0..50, taken from bytes 0..7;
 * - `h[1]` receives bits 51..101, from bytes 6..13 shifted 3 bits
 * to the right;
 * - `h[2]` receives bits 102..152, from bytes 12..19 shifted 6
 * bits to the right;
 * - `h[3]` receives bits 153..203, from bytes 19..26 shifted 1
 * bit to the right;
 * - `h[4]` receives bits 204..254, from bytes 25..31 shifted 4
 * bits to the right.
 * The byte windows overlap on purpose so that each bit of the
 * field falls in a single limb. Bit 255 (high bit of byte 31)
 * is discarded by the 51-bit mask, as RFC 7748 asks
 * it to be ignored. No input value is rejected.
 * @param[out] h Destination element; all 5 limbs are assigned.
 * @param[in]  s 32 little-endian bytes to decode.
 * @pre      `s` has 32 valid bytes and `h` has 5 valid elements.
 * @note     Does not reduce modulo p: the resulting limbs are already smaller than
 * 2^51, so the value is in [0, 2^255), not necessarily
 * in canonical form modulo p when the value is between p and 2^255.
 * @endcond */
static void fe_frombytes(fe h, const uint8_t s[32]) {
    uint64_t lo = 0;
    for (int i = 0; i < 8; i++) lo |= (uint64_t)s[i] << (8*i);
    h[0] = lo & ((UINT64_C(1) << 51) - 1);

    lo = 0;
    for (int i = 6; i < 14; i++) lo |= (uint64_t)s[i] << (8*(i-6));
    h[1] = (lo >> 3) & ((UINT64_C(1) << 51) - 1);

    lo = 0;
    for (int i = 12; i < 20; i++) lo |= (uint64_t)s[i] << (8*(i-12));
    h[2] = (lo >> 6) & ((UINT64_C(1) << 51) - 1);

    lo = 0;
    for (int i = 19; i < 27; i++) lo |= (uint64_t)s[i] << (8*(i-19));
    h[3] = (lo >> 1) & ((UINT64_C(1) << 51) - 1);

    lo = 0;
    for (int i = 25; i < 32; i++) lo |= (uint64_t)s[i] << (8*(i-25));
    h[4] = (lo >> 4) & ((UINT64_C(1) << 51) - 1);
}

/**
 * @cond PORT
 * @brief   Reduz um elemento módulo p e o grava em 32 bytes little-endian.
 * @details Executa, sobre a cópia `t` de `h`, a normalização completa:
 * - duas rodadas de propagação de carry: em cada limb o excedente
 * `t[i] >> 51` é retirado com máscara e acumulado em `t[i+1]`;
 * para o último limb o excedente é acumulado em `t[0]`
 * multiplicado por 19 (envolvência 2^255 ≡ 19);
 * - uma passada adicional de propagação começando pelo limb 0;
 * - `q` é a saída do carry ao somar 19 ao valor de 255 bits, isto é,
 * vale 1 exatamente quando `t` é maior ou igual a p = 2^255 − 19;
 * - `t[0] += q·19` seguido da propagação pelos cinco limbos, com o
 * carry final de bit 255 descartado por `t[4] &= mask51`: isso
 * equivale a subtrair p quando `q` é 1, sem qualquer ramificação
 * sobre o valor (a seleção é feita pela multiplicação por `q`).
 * Em seguida grava as janelas de bits 0..63, 64..127, 128..191 e
 * 192..255, cada uma obtida pela concatenação truncada de dois
 * limbos adjacentes (por exemplo `t[0] | (t[1] << 51)`, cujo
 * truncamento em 64 bits descarta exatamente os bits usados na
 * expressão seguinte), 8 bytes por janela.
 * @param[out] s 32 bytes little-endian do representante canônico em [0, p).
 * @param[in]  h Elemento a normalizar; não é modificado.
 * @pre      `s` tem 32 bytes válidos e os limbos de `h` comportam a
 * propagação descrita (limites das rotinas deste arquivo).
 * @note     É a única rotina do arquivo que garante saída canônica.
 * @endcond
 * @cond INGLES
 * @brief   Reduces an element modulo p and writes it as 32 little-endian bytes.
 * @details Performs the full normalization on the copy `t` of `h`:
 * - two rounds of carry propagation: in each limb the surplus
 * `t[i] >> 51` is taken out with a mask and accumulated in `t[i+1]`;
 * for the last limb the surplus is accumulated in `t[0]`
 * multiplied by 19 (wraparound 2^255 ≡ 19);
 * - an additional propagation pass starting at limb 0;
 * - `q` is the carry output of adding 19 to the 255-bit value, that is,
 * it equals 1 exactly when `t` is greater than or equal to p = 2^255 − 19;
 * - `t[0] += q·19` followed by propagation through the five limbs, with the
 * final carry at bit 255 discarded by `t[4] &= mask51`: this
 * is equivalent to subtracting p when `q` is 1, without any branching
 * on the value (the selection is made by multiplication by `q`).
 * It then writes the bit windows 0..63, 64..127, 128..191 and
 * 192..255, each one obtained by the truncated concatenation of two
 * adjacent limbs (for example `t[0] | (t[1] << 51)`, whose
 * truncation in 64 bits discards exactly the bits used in the
 * following expression), 8 bytes per window.
 * @param[out] s 32 little-endian bytes of the canonical representative in [0, p).
 * @param[in]  h Element to normalize; it is not modified.
 * @pre      `s` has 32 valid bytes and the limbs of `h` accommodate the
 * propagation described (bounds of the routines in this file).
 * @note     It is the only routine in the file that guarantees canonical output.
 * @endcond */
static void fe_tobytes(uint8_t s[32], const fe h) {
    uint64_t t[5];
    const uint64_t mask51 = (UINT64_C(1) << 51) - 1;
    for (int i = 0; i < 5; i++) t[i] = h[i];

    uint64_t c;
    for (int round = 0; round < 2; round++) {
        for (int i = 0; i < 5; i++) {
            c = t[i] >> 51;
            t[i] &= mask51;
            if (i < 4) t[i+1] += c;
            else t[0] += c * 19;
        }
    }
    c = t[0] >> 51; t[0] &= mask51; t[1] += c;

    uint64_t q = (t[0] + 19) >> 51;
    q = (t[1] + q) >> 51;
    q = (t[2] + q) >> 51;
    q = (t[3] + q) >> 51;
    q = (t[4] + q) >> 51;

    t[0] += q * 19;
    c = t[0] >> 51; t[0] &= mask51; t[1] += c;
    c = t[1] >> 51; t[1] &= mask51; t[2] += c;
    c = t[2] >> 51; t[2] &= mask51; t[3] += c;
    c = t[3] >> 51; t[3] &= mask51; t[4] += c;
    t[4] &= mask51;

    uint64_t combined = t[0] | (t[1] << 51);
    for (int i = 0; i < 8; i++) s[i] = (uint8_t)(combined >> (8*i));
    combined = (t[1] >> 13) | (t[2] << 38);
    for (int i = 0; i < 8; i++) s[8+i] = (uint8_t)(combined >> (8*i));
    combined = (t[2] >> 26) | (t[3] << 25);
    for (int i = 0; i < 8; i++) s[16+i] = (uint8_t)(combined >> (8*i));
    combined = (t[3] >> 39) | (t[4] << 12);
    for (int i = 0; i < 8; i++) s[24+i] = (uint8_t)(combined >> (8*i));
}

/* CT-REQUIRED: conditional swap — no branches on secret bit.
 * JASMIN-VERIFIED: First 4 limbs swapped by Jasmin when available;
 * 5th limb swapped in C (same constant-time XOR pattern). */
/**
 * @cond PORT
 * @brief   Troca condicional de dois elementos do corpo.
 * @details Expande `flag` na máscara `mask = −(flag & 1)`, que vale 0 quando
 * o bit menos significativo de `flag` é 0 e todas as 64 bits quando
 * é 1, e aplica a identidade `x ^= mask & (x ^ y)` em cada limb. Não
 * há ramificação sobre o valor de `flag`, nem acesso a memória
 * condicionado a ele; o número de operações é sempre o mesmo.
 * - Sob `ZUPT_USE_JASMIN`: os quatro primeiros limbos (32 bytes) são
 * trocados por `zupt_fe_cswap()`, e o quinto limb é trocado em C
 * com o mesmo padrão XOR, porque `fe` tem cinco limbos e a função
 * Jasmin opera sobre quatro `u64`.
 * - Sem `ZUPT_USE_JASMIN`: um laço de cinco iterações troca os cinco
 * limbos em C.
 * @param[in,out] a    Primeiro elemento, atualizado.
 * @param[in,out] b    Segundo elemento, atualizado.
 * @param[in]     flag Seletor: somente o bit menos significativo é usado
 * (0 mantém, 1 troca).
 * @note     `ZUPT_USE_JASMIN` é uma escolha de tempo de compilação; o texto
 * "JASMIN-VERIFIED" do comentário original refere-se aos quatro
 * limbos tratados pela rotina Jasmin.
 * @endcond
 * @cond INGLES
 * @brief   Conditional swap of two field elements.
 * @details Expands `flag` into the mask `mask = −(flag & 1)`, which is 0 when
 * the least significant bit of `flag` is 0 and all 64 bits when
 * it is 1, and applies the identity `x ^= mask & (x ^ y)` in each limb. There
 * is no branching on the value of `flag`, nor memory access
 * conditioned on it; the number of operations is always the same.
 * - Under `ZUPT_USE_JASMIN`: the first four limbs (32 bytes) are
 * swapped by `zupt_fe_cswap()`, and the fifth limb is swapped in C
 * with the same XOR pattern, because `fe` has five limbs and the
 * Jasmin function operates over four `u64`.
 * - Without `ZUPT_USE_JASMIN`: a loop of five iterations swaps the five
 * limbs in C.
 * @param[in,out] a    First element, updated.
 * @param[in,out] b    Second element, updated.
 * @param[in]     flag Selector: only the least significant bit is used
 * (0 keeps, 1 swaps).
 * @note     `ZUPT_USE_JASMIN` is a compile-time choice; the text
 * "JASMIN-VERIFIED" of the original comment refers to the four
 * limbs handled by the Jasmin routine.
 * @endcond */
static void fe_cswap(fe a, fe b, uint64_t flag) {
    uint64_t mask = -(uint64_t)(flag & 1);
#ifdef ZUPT_USE_JASMIN
    /* JASMIN-VERIFIED: CT swap of first 32 bytes (4×u64).
     * The Jasmin function operates on 4 consecutive u64 values. */
    zupt_fe_cswap(a, b, flag & 1);
    /* 5th limb: C fallback (same CT pattern) */
    {
        uint64_t t = mask & (a[4] ^ b[4]);
        a[4] ^= t;
        b[4] ^= t;
    }
#else
    for (int i = 0; i < 5; i++) {
        uint64_t t = mask & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
    }
#endif
}

/**
 * @cond PORT
 * @brief   Copia um elemento do corpo.
 * @details ATRIBUI os cinco limbos de `f` em `h`, um por um, com laço de
 * extensão constante.
 * @param[out] h Destino.
 * @param[in]  f Origem.
 * @endcond
 * @cond INGLES
 * @brief   Copies a field element.
 * @details ASSIGNS the five limbs of `f` into `h`, one by one, with a constant
 * expansion loop.
 * @param[out] h Destination.
 * @param[in]  f Source.
 * @endcond */
static void fe_copy(fe h, const fe f)    { for (int i=0;i<5;i++) h[i]=f[i]; }

/**
 * @cond PORT
 * @brief   Atribui o elemento zero.
 * @details Zera os cinco limbos de `h` com laço de extensão constante.
 * @param[out] h Elemento a zerar.
 * @endcond
 * @cond INGLES
 * @brief   Assigns the zero element.
 * @details Zeroes the five limbs of `h` with a constant expansion loop.
 * @param[out] h Element to zero.
 * @endcond */
static void fe_set0(fe h)               { for (int i=0;i<5;i++) h[i]=0; }

/**
 * @cond PORT
 * @brief   Atribui o elemento unidade.
 * @details Deixa `h[0] = 1` e zera os quatro limbos restantes.
 * @param[out] h Elemento a atribuir.
 * @endcond
 * @cond INGLES
 * @brief   Assigns the unit element.
 * @details Leaves `h[0] = 1` and zeroes the remaining four limbs.
 * @param[out] h Element to assign.
 * @endcond */
static void fe_set1(fe h)               { h[0]=1; for(int i=1;i<5;i++) h[i]=0; }

/**
 * @cond PORT
 * @brief   Soma dois elementos do corpo sem reduzir.
 * @details Calcula `h[i] = f[i] + g[i]` para os cinco limbos. Não normaliza:
 * os limbos podem ultrapassar 2^51 e o resultado continua congruente
 * módulo p apenas após a normalização de fe_tobytes().
 * @param[out] h Soma.
 * @param[in]  f Parcela.
 * @param[in]  g Parcela.
 * @endcond
 * @cond INGLES
 * @brief   Adds two field elements without reducing.
 * @details Computes `h[i] = f[i] + g[i]` for the five limbs. Does not normalize:
 * the limbs may exceed 2^51 and the result remains congruent
 * modulo p only after the normalization of fe_tobytes().
 * @param[out] h Sum.
 * @param[in]  f Addend.
 * @param[in]  g Addend.
 * @endcond */
static void fe_add(fe h, const fe f, const fe g) {
    for (int i = 0; i < 5; i++) h[i] = f[i] + g[i];
}

/**
 * @cond PORT
 * @brief   Subtrai dois elementos do corpo usando um deslocamento múltiplo de p.
 * @details Calcula `h[i] = f[i] + two_p[i] − g[i]` nos cinco limbos, sem
 * propagação de empréstimo entre limbos. `two_p` é a representação
 * em base 2^51 de 2p = 2^256 − 38: o limb 0 vale 2·(2^51 − 19) e os
 * limbos 1 a 4 valem 2·(2^51 − 1), de modo que
 * Σ two_p[i]·2^(51·i) = 2p ≡ 0 (mod p). O deslocamento existe para
 * que a aritmética sem sinal não envolva durante a subtração; o
 * resultado é congruente a `f − g` módulo p e só é normalizado por
 * fe_tobytes().
 * @param[out] h Diferença congruente.
 * @param[in]  f Minuendo.
 * @param[in]  g Subtraendo.
 * @note     Não produz necessariamente um valor em [0, p); os limites por
 * limb dependem das rotinas que geram os operandos.
 * @endcond
 * @cond INGLES
 * @brief   Subtracts two field elements using an offset that is a multiple of p.
 * @details Computes `h[i] = f[i] + two_p[i] − g[i]` on the five limbs, without
 * borrow propagation between limbs. `two_p` is the
 * representation in base 2^51 of 2p = 2^256 − 38: limb 0 is 2·(2^51 − 19) and
 * limbs 1 to 4 are 2·(2^51 − 1), so that
 * Σ two_p[i]·2^(51·i) = 2p ≡ 0 (mod p). The offset exists so that
 * the unsigned arithmetic does not wrap around during the subtraction; the
 * result is congruent to `f − g` modulo p and is only normalized by
 * fe_tobytes().
 * @param[out] h Congruent difference.
 * @param[in]  f Minuend.
 * @param[in]  g Subtrahend.
 * @note     Does not necessarily produce a value in [0, p); the bounds per
 * limb depend on the routines that generate the operands.
 * @endcond */
static void fe_sub(fe h, const fe f, const fe g) {
    /**
     * @cond PORT
     * Deslocamento por limb: representa 2p em base 2^51 (ver fe_sub()).
     * @endcond
     * @cond INGLES
     * Per-limb offset: represents 2p in base 2^51 (see fe_sub()).
     * @endcond */
    static const uint64_t two_p[5] = {
        2*((UINT64_C(1)<<51)-19), 2*((UINT64_C(1)<<51)-1),
        2*((UINT64_C(1)<<51)-1),  2*((UINT64_C(1)<<51)-1),
        2*((UINT64_C(1)<<51)-1)
    };
    for (int i = 0; i < 5; i++) h[i] = f[i] + two_p[i] - g[i];
}

/* 128-bit type for multiplication */
/* Caminho de 128 bits escolhido em tempo de compilação: quando o compilador
 * oferece o inteiro extensional de 128 bits (__SIZEOF_INT128__), o tipo e o
 * produto são nativos; as duas pragmas GCC/Clang ao redor do typedef isolam o
 * aviso "-Wpedantic" (unsigned __int128 é extensão GNU, não C11), sem
 * alterá-lo globalmente. Sem a extensão, o arquivo define o próprio par de
 * palavras e um produto manual em partes de 32 bits. */
#if defined(__SIZEOF_INT128__)
  #if defined(__GNUC__) || defined(__clang__)
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wpedantic"
  #endif
  /**
   * @cond PORT
   * @typedef  uint128_t
   * @brief    Inteiro de 128 bits sem sinal nativo do compilador.
   * @details  Usado por fe_mul() para acumular os produtos parciais do produto
   * escolar. Existe somente no ramo em que o compilador declara a
   * extensão `__SIZEOF_INT128__`; no ramo oposto do `\#if`, o mesmo
   * nome designa a struct de duas palavras de 64 bits definida mais
   * abaixo.
   * @endcond
   * @cond INGLES
   * @typedef  uint128_t
   * @brief    Compiler-native unsigned 128-bit integer.
   * @details  Used by fe_mul() to accumulate the partial products of the
   * schoolbook product. It exists only in the branch in which the compiler
   * declares the `__SIZEOF_INT128__` extension; in the opposite branch of
   * the `\#if`, the same name designates the struct of two 64-bit words
   * defined further below.
   * @endcond */
  typedef unsigned __int128 uint128_t;
  #if defined(__GNUC__) || defined(__clang__)
    #pragma GCC diagnostic pop
  #endif
  /**
   * @cond PORT
   * @def     MUL64(a,b)
   * @brief   Produto 64×64→128 de dois inteiros sem sinal.
   * @param[in] a Fator.
   * @param[in] b Fator.
   * @return  Produto de 128 bits.
   * @note    Ramificação de tempo de compilação: converte os operandos para
   * `uint128_t` e multiplica, disponível quando `__SIZEOF_INT128__`
   * está definido.
   * @endcond
   * @cond INGLES
   * @def     MUL64(a,b)
   * @brief   64×64→128 product of two unsigned integers.
   * @param[in] a Factor.
   * @param[in] b Factor.
   * @return  128-bit product.
   * @note    Compile-time branching: converts the operands to
   * `uint128_t` and multiplies, available when `__SIZEOF_INT128__`
   * is defined.
   * @endcond */
  #define MUL64(a,b) ((uint128_t)(a) * (uint128_t)(b))
#else
/**
 * @cond PORT
 * @struct   uint128_t
 * @brief    Par de palavras de 64 bits que representa um inteiro de 128 bits.
 * @details  Representação alternativa, usada quando o compilador não declara
 * `__SIZEOF_INT128__`. O valor representado é
 * `lo + hi·2^64`: o campo `lo` traz os bits 0..63 do produto e o
 * campo `hi` os bits 64..127. Ambos são lidos e escritos apenas
 * por MUL64() e fe_mul().
 *
 * Os campos não são descritos com a tag de membro `@@var` porque o
 * Doxygen 1.8.14 não a vincula a `typedef struct { ... } nome;` de
 * linha única: as formas tentativas geram avisos falsos
 * ("documented symbol ... was not declared or defined" e "member
 * with no name found"). A definição fica entre as tags de seção
 * condicional `@@cond` e `@@endcond` para que a página do tipo não
 * herde a exigência de documentar cada campo; com um Doxygen que
 * suporte esse vínculo, remover as duas tags e descrever os campos
 * com `@@var` volta a listá-los na página.
 * @endcond
 * @cond INGLES
 * @struct   uint128_t
 * @brief    Pair of 64-bit words that represents a 128-bit integer.
 * @details  Alternative representation, used when the compiler does not declare
 * `__SIZEOF_INT128__`. The value represented is
 * `lo + hi·2^64`: the `lo` field carries bits 0..63 of the product and the
 * `hi` field carries bits 64..127. Both are read and written only
 * by MUL64() and fe_mul().
 *
 * The fields are not described with the `@@var` member tag because
 * Doxygen 1.8.14 does not bind it to a single-line `typedef struct
 * { ... } name;`: the forms tried generate false warnings
 * ("documented symbol ... was not declared or defined" and "member
 * with no name found"). The definition is kept between the
 * `@@cond` and `@@endcond` conditional section tags so that the type's page does not
 * inherit the requirement to document each field; with a Doxygen that
 * supports that binding, removing the two tags and describing the fields
 * with `@@var` lists them on the page again.
 * @endcond */
/** @cond */
typedef struct { uint64_t lo, hi; } uint128_t;
/** @endcond */
/**
 * @cond PORT
 * @brief   Produto 64×64→128 calculado em quatro produtos parciais de 32 bits.
 * @details Decompõe os fatores nas metades de 32 bits (`a0`, `a1`, `b0`,
 * `b1`) e forma m0 = a0·b0, m1 = a0·b1, m2 = a1·b0, m3 = a1·b1. A
 * metade central é `mid = m1 + (m0 >> 32) + m2`: a primeira soma não
 * pode transbordar porque
 * m1 + (m0 >> 32) ≤ a0·b1 + a0·b0/2^32 = a0·(b1 + b0/2^32) é
 * estritamente menor que 2^64, enquanto a segunda pode; o teste
 * `mid < m2` detecta esse carry perdido e soma 2^32 a m3.
 * O resultado é `lo = (mid << 32) | (m0 & 0xFFFFFFFF)` e
 * `hi = m3 + (mid >> 32)`, exatamente o produto de 128 bits.
 * @param[in]  a Fator de 64 bits sem sinal.
 * @param[in]  b Fator de 64 bits sem sinal.
 * @return   Produto de 128 bits em `lo` e `hi`.
 * @note     Ramificação de tempo de compilação: esta versão existe apenas
 * quando `__SIZEOF_INT128__` não está definido.
 * @endcond
 * @cond INGLES
 * @brief   64×64→128 product computed with four 32-bit partial products.
 * @details Decomposes the factors into 32-bit halves (`a0`, `a1`, `b0`,
 * `b1`) and forms m0 = a0·b0, m1 = a0·b1, m2 = a1·b0, m3 = a1·b1. The
 * middle half is `mid = m1 + (m0 >> 32) + m2`: the first sum cannot
 * overflow because
 * m1 + (m0 >> 32) ≤ a0·b1 + a0·b0/2^32 = a0·(b1 + b0/2^32) is
 * strictly less than 2^64, while the second one can; the test
 * `mid < m2` detects that lost carry and adds 2^32 to m3.
 * The result is `lo = (mid << 32) | (m0 & 0xFFFFFFFF)` and
 * `hi = m3 + (mid >> 32)`, exactly the 128-bit product.
 * @param[in]  a Unsigned 64-bit factor.
 * @param[in]  b Unsigned 64-bit factor.
 * @return   128-bit product in `lo` and `hi`.
 * @note     Compile-time branching: this version exists only
 * when `__SIZEOF_INT128__` is not defined.
 * @endcond */
static inline uint128_t MUL64(uint64_t a, uint64_t b) {
    uint128_t r;
    uint64_t a0=a&0xFFFFFFFF, a1=a>>32, b0=b&0xFFFFFFFF, b1=b>>32;
    uint64_t m0=a0*b0, m1=a0*b1, m2=a1*b0, m3=a1*b1;
    uint64_t mid = m1 + (m0>>32); mid += m2;
    if (mid < m2) m3 += UINT64_C(1)<<32;
    r.lo = (mid << 32) | (m0 & 0xFFFFFFFF);
    r.hi = m3 + (mid >> 32);
    return r;
}
#endif

/**
 * @cond PORT
 * @brief   Multiplica dois elementos do corpo pelo produto escolar com envolvimento.
 * @details Calcula `h = f · g (mod p)` em cinco limbos de base 2^51. O laço
 * duplo forma os 25 produtos parciais `f[i]·g[j]`, que teriam peso
 * 2^(51·(i+j)). Como `(2^51)^5 = 2^255 ≡ 19 (mod p)`, todo produto com
 * `i + j ≥ 5` é reindexado em `idx = (i+j) % 5` com um fator
 * multiplicativo 19 aplicado a `g[j]` (`gi = g[j] * 19`), o que
 * substitui a redução explícita do expoente. Os produtos parciais são
 * acumulados em `t[0..4]`, de 128 bits cada.
 *
 * A propagação de carry usa o mesmo peso de envolvimento: o limbo
 * `h[i]` recebe os 51 bits baixos de `t[i]`, e o restante (`carry`) é
 * somado em `t[i+1]` para `i < 4`; para `i = 4` o carry retorna a
 * `h[0] + carry * 19`. A última linha repete o passo para o carry
 * gerado por esse retorno, de modo que `h[0]` volte a caber em 51
 * bits e `h[1]` absorva o excedente.
 *
 * Saída: todos os limbos permanecem abaixo de 2^52 e o valor
 * representado é congruente a `f · g` módulo p; não é a forma
 * canônica em [0, p), que só fe_tobytes() produz.
 * @param[out] h Elemento de destino. Pode ser o mesmo objeto que `f` ou `g`,
 * pois a escrita em `h` só começa depois de o laço duplo ter
 * acumulado todos os produtos parciais em `t`.
 * @param[in]  f Primeiro fator.
 * @param[in]  g Segundo fator.
 * @note     Ramificação de tempo de compilação: o laço interno acumula com `+`
 * nativo de 128 bits quando `__SIZEOF_INT128__` está definido; no
 * ramo oposto soma `p.lo` com teste manual de estouro e soma `p.hi`,
 * e a extração de `carry` lê os bits de `t[i].lo` e `t[i].hi` em vez
 * do inteiro de 128 bits. Os índices de laço e a ordem das operações
 * são os mesmos nos dois ramos e não dependem dos operandos.
 * @endcond
 * @cond INGLES
 * @brief   Multiplies two field elements by the schoolbook product with wraparound.
 * @details Computes `h = f · g (mod p)` in five limbs of base 2^51. The double
 * loop forms the 25 partial products `f[i]·g[j]`, which would have weight
 * 2^(51·(i+j)). Since `(2^51)^5 = 2^255 ≡ 19 (mod p)`, every product with
 * `i + j ≥ 5` is reindexed at `idx = (i+j) % 5` with a multiplicative
 * factor 19 applied to `g[j]` (`gi = g[j] * 19`), which
 * replaces the explicit reduction of the exponent. The partial products are
 * accumulated in `t[0..4]`, 128 bits each.
 *
 * The carry propagation uses the same wraparound weight: the limb
 * `h[i]` receives the low 51 bits of `t[i]`, and the remainder (`carry`) is
 * added to `t[i+1]` for `i < 4`; for `i = 4` the carry returns to
 * `h[0] + carry * 19`. The last line repeats the step for the carry
 * generated by that return, so that `h[0]` fits in 51
 * bits again and `h[1]` absorbs the surplus.
 *
 * Output: all limbs stay below 2^52 and the represented value
 * is congruent to `f · g` modulo p; it is not the
 * canonical form in [0, p), which only fe_tobytes() produces.
 * @param[out] h Destination element. It may be the same object as `f` or `g`,
 * because the write to `h` only starts after the double loop has
 * accumulated all the partial products in `t`.
 * @param[in]  f First factor.
 * @param[in]  g Second factor.
 * @note     Compile-time branching: the inner loop accumulates with native
 * 128-bit `+` when `__SIZEOF_INT128__` is defined; in the opposite branch it
 * sums `p.lo` with a manual overflow test and sums `p.hi`,
 * and the extraction of `carry` reads the bits of `t[i].lo` and `t[i].hi` instead
 * of the 128-bit integer. The loop indices and the order of the operations
 * are the same in both branches and do not depend on the operands.
 * @endcond */
static void fe_mul(fe h, const fe f, const fe g) {
    uint128_t t[5] = {0,0,0,0,0};
    for (int i = 0; i < 5; i++)
        for (int j = 0; j < 5; j++) {
            uint64_t gi = (i+j >= 5) ? g[j] * 19 : g[j];
            int idx = (i+j) % 5;
#if defined(__SIZEOF_INT128__)
            t[idx] += MUL64(f[i], gi);
#else
            uint128_t p = MUL64(f[i], gi);
            t[idx].lo += p.lo;
            if (t[idx].lo < p.lo) t[idx].hi++;
            t[idx].hi += p.hi;
#endif
        }

    for (int i = 0; i < 5; i++) {
#if defined(__SIZEOF_INT128__)
        uint64_t lo = (uint64_t)t[i];
        h[i] = lo & ((UINT64_C(1) << 51) - 1);
        uint64_t carry = (uint64_t)(t[i] >> 51);
#else
        h[i] = t[i].lo & ((UINT64_C(1) << 51) - 1);
        uint64_t carry = (t[i].lo >> 51) | (t[i].hi << 13);
#endif
        if (i < 4) {
#if defined(__SIZEOF_INT128__)
            t[i+1] += carry;
#else
            t[i+1].lo += carry;
            if (t[i+1].lo < carry) t[i+1].hi++;
#endif
        } else {
            h[0] += carry * 19;
        }
    }
    uint64_t c = h[0] >> 51; h[0] &= (UINT64_C(1) << 51) - 1; h[1] += c;
}

/**
 * @cond PORT
 * @brief   Quadrado de um elemento do corpo.
 * @details Delega a fe_mul(h, f, f): não existe rotina de quadrado separada,
 * portanto não há aproveitamento da simetria dos produtos parciais.
 * @param[out] h Elemento de destino.
 * @param[in]  f Elemento a elevar ao quadrado.
 * @endcond
 * @cond INGLES
 * @brief   Square of a field element.
 * @details Delegates to fe_mul(h, f, f): there is no separate squaring routine,
 * therefore no use is made of the symmetry of the partial products.
 * @param[out] h Destination element.
 * @param[in]  f Element to square.
 * @endcond */
static void fe_sq(fe h, const fe f) { fe_mul(h, f, f); }

/**
 * @cond PORT
 * @brief   Eleva um elemento do corpo a uma potência de dois.
 * @details Aplica `n` quadrados sucessivos: `h = f^(2^n)`. A primeira
 * quadratura é feita fora do laço, de modo que a contagem efetiva de
 * quadrados é `n` para `n ≥ 1`. Para `n = 0` o código ainda executa
 * uma quadratura e devolve `f^2` em vez de `f`; nenhum chamador
 * neste arquivo passa `n = 0` (fe_inv() usa 2, 5, 10, 20, 50 e 100).
 * @param[out] h Elemento de destino; é lido e reescrito a cada quadratura.
 * @param[in]  f Base.
 * @param[in]  n Número de quadraturas sucessivas.
 * @endcond
 * @cond INGLES
 * @brief   Raises a field element to a power of two.
 * @details Applies `n` successive squarings: `h = f^(2^n)`. The first
 * squaring is done outside the loop, so that the effective count of
 * squarings is `n` for `n ≥ 1`. For `n = 0` the code still performs
 * one squaring and returns `f^2` instead of `f`; no caller
 * in this file passes `n = 0` (fe_inv() uses 2, 5, 10, 20, 50 and 100).
 * @param[out] h Destination element; it is read and rewritten at each squaring.
 * @param[in]  f Base.
 * @param[in]  n Number of successive squarings.
 * @endcond */
static void fe_sq_n(fe h, const fe f, int n) {
    fe_sq(h, f);
    for (int i = 1; i < n; i++) fe_sq(h, h);
}

/**
 * @cond PORT
 * @brief   Inverso multiplicativo em GF(2^255 − 19) por exponenciação.
 * @details Calcula `h = f^(p-2) = f^(2^255 − 21)`, que é o inverso de `f`
 * módulo p pela pequena teorema de Fermat. A exponenciação usa a
 * cadeia binária clássica: constrói potências da forma `f^(2^k − 1)`
 * para `k = 5, 10, 20, 40, 50, 100, 250`, combinando cada uma com a
 * anterior via `fe_sq_n` seguido de `fe_mul`, e fecha com
 * `f^(2^255 − 2^5) · f^11 = f^(2^255 − 21)`.
 *
 * São 254 chamadas a fe_sq() e 11 chamadas diretas a fe_mul(), todas
 * em ordem fixa: a sequência de operações não depende do valor de
 * `f`, e não existe teste de `f = 0`. Com `f = 0` o resultado é 0,
 * sem divisão ou desvio de controle.
 * @param[out] h Elemento de destino, que pode ser o mesmo que `f` (os
 * temporários `t0..t3` absorvem a sobreposição).
 * @param[in]  f Elemento a inverter.
 * @note     Nenhum dos valores intermediários é reduzido à forma canônica: a
 * congruência módulo p é preservada pelas operações de fe_mul().
 * @endcond
 * @cond INGLES
 * @brief   Multiplicative inverse in GF(2^255 − 19) by exponentiation.
 * @details Computes `h = f^(p-2) = f^(2^255 − 21)`, which is the inverse of `f`
 * modulo p by Fermat's little theorem. The exponentiation uses the
 * classic binary chain: it builds powers of the form `f^(2^k − 1)`
 * for `k = 5, 10, 20, 40, 50, 100, 250`, combining each one with the
 * previous one via `fe_sq_n` followed by `fe_mul`, and closes with
 * `f^(2^255 − 2^5) · f^11 = f^(2^255 − 21)`.
 *
 * There are 254 calls to fe_sq() and 11 direct calls to fe_mul(), all
 * in fixed order: the sequence of operations does not depend on the value of
 * `f`, and there is no test for `f = 0`. With `f = 0` the result is 0,
 * without division or change of control flow.
 * @param[out] h Destination element, which may be the same as `f` (the
 * temporaries `t0..t3` absorb the overlap).
 * @param[in]  f Element to invert.
 * @note     None of the intermediate values is reduced to canonical form: the
 * congruence modulo p is preserved by the operations of fe_mul().
 * @endcond */
static void fe_inv(fe h, const fe f) {
    fe t0, t1, t2, t3;

    fe_sq(t0, f);
    fe_sq_n(t1, t0, 2);
    fe_mul(t1, f, t1);
    fe_mul(t0, t0, t1);
    fe_sq(t2, t0);
    fe_mul(t1, t1, t2);
    fe_sq_n(t2, t1, 5);
    fe_mul(t1, t2, t1);
    fe_sq_n(t2, t1, 10);   fe_mul(t2, t2, t1);
    fe_sq_n(t3, t2, 20);   fe_mul(t2, t3, t2);
    fe_sq_n(t2, t2, 10);   fe_mul(t1, t2, t1);
    fe_sq_n(t2, t1, 50);   fe_mul(t2, t2, t1);
    fe_sq_n(t3, t2, 100);  fe_mul(t2, t3, t2);
    fe_sq_n(t2, t2, 50);   fe_mul(t1, t2, t1);
    fe_sq_n(t1, t1, 5);    fe_mul(h, t1, t0);
}

/* ═══════════════════════════════════════════════════════════════════
 * X25519 MONTGOMERY LADDER
 * CT-REQUIRED: No secret-dependent branches. The ladder is constant-time
 * by construction: every iteration performs the same operations, with
 * cswap selecting which point to operate on.
 * ═══════════════════════════════════════════════════════════════════ */

/* Escala escalar de Montgomery sobre Curve25519 (v^2 = u^3 + 486662*u^2 + u),
 * na forma diferencial proposta por Montgomery e reproduzida na secao 5 da
 * RFC 7748. O estado sao dois pontos em coordenadas projectivas:
 * (x2:z2) = [k]P e (x3:z3) = [(k+1)]P, com P de coordenada afim u decodificada
 * de `point`. Ao final, x2 * z2^(p-2) devolve a coordenada afim u do resultado.
 *
 * Estrutura observavel desta implementacao:
 *   - O escalar usado e a copia `e` de 32 bytes, apos o clamping; a extracao
 *     (e[pos/8] >> (pos%8)) & 1 percorre os bits menos significativos
 *     primeiro, o que corresponde a leitura little-endian do escalar.
 *   - O laco roda de pos = 254 ate 0: 255 iteracoes fixas, independentemente
 *     dos bits do escalar e do valor do ponto de entrada.
 *   - `swap` guarda a diferenca entre bits consecutivos. Cada iteracao inicia
 *     com duas trocas condicionais (fe_cswap) que realinham (x2,z2) com
 *     (x3,z3) conforme o bit, e conclui atribuindo swap = bit. O par de cswap
 *     apos o laco fecha a sequencia iniciada pelo ultimo bit.
 *   - Cada iteracao executa, em ordem fixa: 5 somas/subtracoes sobre limbos,
 *     4 quadrados e 5 multiplicacoes. Como fe_sq() delega a fe_mul(), a
 *     contagem real de chamadas a fe_mul() por iteracao e 9.
 *   - Nao ha teste de ponto de ordem baixa, de pertencimento a subgrupo nem de
 *     z igual a zero. A exponenciacao inversa devolve 0 quando z2 = 0 e a
 *     saida fica toda-zero; a decisao de rejeitar essa saida e do chamador. */

/* FRAMA-C: X25519 Diffie-Hellman key agreement (RFC 7748)
 * CT-REQUIRED: Montgomery ladder — constant-time by construction */
/*@ requires \valid(out + (0..31));
  @ requires \valid_read(scalar + (0..31));
  @ requires \valid_read(point + (0..31));
  @ requires \separated(out + (0..31), scalar + (0..31));
  @ requires \separated(out + (0..31), point + (0..31));
  @ assigns out[0..31];
  @ ensures \initialized(out + (0..31));
*/
void zupt_x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]) {
    uint8_t e[32];
    memcpy(e, scalar, 32);
    /* RFC 7748 clamping */
    e[0]  &= 248;
    e[31] &= 127;
    e[31] |= 64;

    fe x1, x2, z2, x3, z3, tmp0, tmp1;
    fe_frombytes(x1, point);
    fe_set1(x2);
    fe_set0(z2);
    fe_copy(x3, x1);
    fe_set1(z3);

    uint64_t swap = 0;
    for (int pos = 254; pos >= 0; pos--) {
        uint64_t bit = (e[pos/8] >> (pos%8)) & 1;
        swap ^= bit;
        fe_cswap(x2, x3, swap);
        fe_cswap(z2, z3, swap);
        swap = bit;

        /* Montgomery ladder step */
        fe a, b, c, d, da, cb, aa, bb, e2, dc;
        fe_add(a, x2, z2);
        fe_sub(b, x2, z2);
        fe_add(c, x3, z3);
        fe_sub(d, x3, z3);
        fe_mul(da, d, a);
        fe_mul(cb, c, b);
        fe_add(tmp0, da, cb); fe_sq(x3, tmp0);
        fe_sub(tmp1, da, cb); fe_sq(tmp1, tmp1); fe_mul(z3, x1, tmp1);
        fe_sq(aa, a);
        fe_sq(bb, b);
        fe_mul(x2, aa, bb);
        fe_sub(e2, aa, bb);
        fe_copy(dc, e2);
        for (int i = 0; i < 5; i++) tmp0[i] = 0;
        tmp0[0] = 121666;
        fe_mul(tmp0, dc, tmp0);
        fe_add(tmp0, bb, tmp0);
        fe_mul(z2, e2, tmp0);
    }
    fe_cswap(x2, x3, swap);
    fe_cswap(z2, z3, swap);

    fe_inv(z2, z2);
    fe_mul(x2, x2, z2);
    fe_tobytes(out, x2);

    /* Wipe clamped scalar from stack.
     * Use volatile pointer to resist dead-store elimination (CodeQL alert #3).
     * Cannot use zupt_secure_wipe() here because this file does not include zupt.h. */
    volatile uint8_t *ve = (volatile uint8_t *)e;
    for (int i = 0; i < 32; i++) ve[i] = 0;
}

/* FRAMA-C: X25519 with standard basepoint (u=9) */
/*@ requires \valid(out + (0..31));
  @ requires \valid_read(scalar + (0..31));
  @ requires \separated(out + (0..31), scalar + (0..31));
  @ assigns out[0..31];
  @ ensures \initialized(out + (0..31));
*/
void zupt_x25519_base(uint8_t out[32], const uint8_t scalar[32]) {
    /* Standard basepoint: u = 9 */
    uint8_t basepoint[32] = {0};
    basepoint[0] = 9;
    zupt_x25519(out, scalar, basepoint);
}
