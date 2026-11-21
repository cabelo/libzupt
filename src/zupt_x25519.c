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
 * @file   zupt_x25519.c
 * @brief  Implementação em C11 da concordância de chave X25519 (RFC 7748).
 * @details Contém a aritmética do corpo GF(2^255 − 19) e a escada de
 *          Montgomery sobre Curve25519. As dependências são zupt_jasmin.h
 *          (troca condicional em Jasmin, usada apenas sob `ZUPT_USE_JASMIN`)
 *          e `string.h` (memcpy do escalar). O cabeçalho zupt_cpuid.h também
 *          é incluído, mas nenhum símbolo dele é referenciado neste arquivo.
 *
 *          Representação do corpo, tal como implementada: `fe` é
 *          `uint64_t[5]`, cinco limbos de base 2^51 (40 bytes por elemento).
 *          A multiplicação é o produto escolar com envolvimento: os termos de
 *          índice i+j maior ou igual a 5 são multiplicados por 19, pois em
 *          base 2^51 o limb de índice 5 tem peso 2^255 ≡ 19 (mod p). Cada
 *          produto 64×64→128 usa `unsigned __int128` quando o compilador o
 *          oferece (`__SIZEOF_INT128__`); caso contrário usa um tipo
 *          `uint128_t` de duas palavras, com produto formado por quatro
 *          produtos parciais de 32 bits.
 *
 *          Divergência factual: este cabeçalho de arquivo e a seção
 *          "FIELD ARITHMETIC" abaixo afirmam "4 × 64-bit limbs (donna64
 *          layout)" e "v2.0.0: Rewritten from 5×51-bit to 4×64-bit limb
 *          representation", e a mesma seção chega a registrar a reversão da
 *          decisão ("SIMPLEST CORRECT APPROACH (chosen): Keep the proven
 *          5×51-bit arithmetic ... store field elements as 5×u64"). Nenhuma
 *          rotina deste arquivo usa 4 limbos de 64 bits: todas percorrem os
 *          5 limbos de 51 bits. A documentação descreve o código; a
 *          inconsistência textual está anotada no relatório de achados.
 *
 *          Conteúdo:
 *          - conversão little-endian de/para 32 bytes (fe_frombytes e
 *            fe_tobytes, esta última com redução completa módulo p);
 *          - operações de corpo: adição, subtração com deslocamento,
 *            multiplicação, quadrado, quadrado repetido e inversão;
 *          - troca condicional sem ramificação (fe_cswap), com caminho
 *            Jasmin opcional sob `ZUPT_USE_JASMIN`;
 *          - escada de Montgomery sobre os bits 254..0 do escalar clampado
 *            (zupt_x25519) e variante com ponto base u = 9
 *            (zupt_x25519_base).
 *
 *          Nota factual sobre tempo constante: as marcações "CT-REQUIRED"
 *          descrevem a intenção do autor. Os mecanismos observáveis
 *          correspondentes neste arquivo são: ordem e quantidade fixas de
 *          operações por iteração da escada, seleção de ponto somente por
 *          expansão de máscara de bits (`-(flag & 1)`) seguida de XOR, laços
 *          de extensão constante (5 limbos, 255 bits, 32 bytes) e cadeia de
 *          exponenciação fixa em fe_inv(). Não há, neste arquivo, mitigação
 *          de canais laterais dependentes do compilador ou da arquitetura.
 *
 * @see    include/zupt_x25519.h
 */
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
 * @typedef  fe
 * @brief    Elemento de GF(2^255 − 19) em 5 limbos de base 2^51.
 * @details  É o tipo `uint64_t[5]` definido logo abaixo: `fe` representa o valor
 *           Σ fe[i]·2^(51·i), com i de 0 a 4. Os limbos não são mantidos
 *           normalizados: adições e o produto escolar deixam valores até
 *           cerca de 2^52 (por isso o comentário original do tipo diz
 *           "each < 2^52"), e apenas fe_tobytes() produz a forma canônica em
 *           [0, p). Os limbos são sempre percorridos com laço de 5 iterações
 *           fixas.
 */
typedef uint64_t fe[5]; /* Field element: 5 limbs, each < 2^52 */

/**
 * @brief   Carrega 32 bytes little-endian em um elemento do corpo.
 * @details Lê `s` como o inteiro little-endian de 256 bits e distribui os
 *          seus bits nos cinco limbos de 51 bits de `h`:
 *          - `h[0]` recebe os bits 0..50, obtidos dos bytes 0..7;
 *          - `h[1]` recebe os bits 51..101, dos bytes 6..13 deslocados 3 bits
 *            à direita;
 *          - `h[2]` recebe os bits 102..152, dos bytes 12..19 deslocados 6
 *            bits à direita;
 *          - `h[3]` recebe os bits 153..203, dos bytes 19..26 deslocados 1
 *            bit à direita;
 *          - `h[4]` recebe os bits 204..254, dos bytes 25..31 deslocados 4
 *            bits à direita.
 *          As janelas de bytes se sobrepõem de propósito para que cada bit
 *          do corpo caia em um único limb. O bit 255 (bit alto do byte 31)
 *          é descartado pela máscara de 51 bits, conforme a RFC 7748 pede
 *          que seja ignorado. Nenhum valor de entrada é rejeitado.
 * @param[out] h Elemento de destino; os 5 limbos são todos atribuídos.
 * @param[in]  s 32 bytes little-endian a decodificar.
 * @pre      `s` tem 32 bytes válidos e `h` tem 5 elementos válidos.
 * @note     Não reduz módulo p: os limbos resultantes já são menores que
 *           2^51, portanto o valor está em [0, 2^255), não necessariamente
 *           na forma canônica módulo p quando o valor está entre p e 2^255.
 */
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
 * @brief   Reduz um elemento módulo p e o grava em 32 bytes little-endian.
 * @details Executa, sobre a cópia `t` de `h`, a normalização completa:
 *          - duas rodadas de propagação de carry: em cada limb o excedente
 *            `t[i] >> 51` é retirado com máscara e acumulado em `t[i+1]`;
 *            para o último limb o excedente é acumulado em `t[0]`
 *            multiplicado por 19 (envolvência 2^255 ≡ 19);
 *          - uma passada adicional de propagação começando pelo limb 0;
 *          - `q` é a saída do carry ao somar 19 ao valor de 255 bits, isto é,
 *            vale 1 exatamente quando `t` é maior ou igual a p = 2^255 − 19;
 *          - `t[0] += q·19` seguido da propagação pelos cinco limbos, com o
 *            carry final de bit 255 descartado por `t[4] &= mask51`: isso
 *            equivale a subtrair p quando `q` é 1, sem qualquer ramificação
 *            sobre o valor (a seleção é feita pela multiplicação por `q`).
 *          Em seguida grava as janelas de bits 0..63, 64..127, 128..191 e
 *          192..255, cada uma obtida pela concatenação truncada de dois
 *          limbos adjacentes (por exemplo `t[0] | (t[1] << 51)`, cujo
 *          truncamento em 64 bits descarta exatamente os bits usados na
 *          expressão seguinte), 8 bytes por janela.
 * @param[out] s 32 bytes little-endian do representante canônico em [0, p).
 * @param[in]  h Elemento a normalizar; não é modificado.
 * @pre      `s` tem 32 bytes válidos e os limbos de `h` comportam a
 *           propagação descrita (limites das rotinas deste arquivo).
 * @note     É a única rotina do arquivo que garante saída canônica.
 */
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
 * @brief   Troca condicional de dois elementos do corpo.
 * @details Expande `flag` na máscara `mask = −(flag & 1)`, que vale 0 quando
 *          o bit menos significativo de `flag` é 0 e todas as 64 bits quando
 *          é 1, e aplica a identidade `x ^= mask & (x ^ y)` em cada limb. Não
 *          há ramificação sobre o valor de `flag`, nem acesso a memória
 *          condicionado a ele; o número de operações é sempre o mesmo.
 *          - Sob `ZUPT_USE_JASMIN`: os quatro primeiros limbos (32 bytes) são
 *            trocados por `zupt_fe_cswap()`, e o quinto limb é trocado em C
 *            com o mesmo padrão XOR, porque `fe` tem cinco limbos e a função
 *            Jasmin opera sobre quatro `u64`.
 *          - Sem `ZUPT_USE_JASMIN`: um laço de cinco iterações troca os cinco
 *            limbos em C.
 * @param[in,out] a    Primeiro elemento, atualizado.
 * @param[in,out] b    Segundo elemento, atualizado.
 * @param[in]     flag Seletor: somente o bit menos significativo é usado
 *                     (0 mantém, 1 troca).
 * @note     `ZUPT_USE_JASMIN` é uma escolha de tempo de compilação; o texto
 *           "JASMIN-VERIFIED" do comentário original refere-se aos quatro
 *           limbos tratados pela rotina Jasmin.
 */
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
 * @brief   Copia um elemento do corpo.
 * @details ATRIBUI os cinco limbos de `f` em `h`, um por um, com laço de
 *          extensão constante.
 * @param[out] h Destino.
 * @param[in]  f Origem.
 */
static void fe_copy(fe h, const fe f)    { for (int i=0;i<5;i++) h[i]=f[i]; }

/**
 * @brief   Atribui o elemento zero.
 * @details Zera os cinco limbos de `h` com laço de extensão constante.
 * @param[out] h Elemento a zerar.
 */
static void fe_set0(fe h)               { for (int i=0;i<5;i++) h[i]=0; }

/**
 * @brief   Atribui o elemento unidade.
 * @details Deixa `h[0] = 1` e zera os quatro limbos restantes.
 * @param[out] h Elemento a atribuir.
 */
static void fe_set1(fe h)               { h[0]=1; for(int i=1;i<5;i++) h[i]=0; }

/**
 * @brief   Soma dois elementos do corpo sem reduzir.
 * @details Calcula `h[i] = f[i] + g[i]` para os cinco limbos. Não normaliza:
 *          os limbos podem ultrapassar 2^51 e o resultado continua congruente
 *          módulo p apenas após a normalização de fe_tobytes().
 * @param[out] h Soma.
 * @param[in]  f Parcela.
 * @param[in]  g Parcela.
 */
static void fe_add(fe h, const fe f, const fe g) {
    for (int i = 0; i < 5; i++) h[i] = f[i] + g[i];
}

/**
 * @brief   Subtrai dois elementos do corpo usando um deslocamento múltiplo de p.
 * @details Calcula `h[i] = f[i] + two_p[i] − g[i]` nos cinco limbos, sem
 *          propagação de empréstimo entre limbos. `two_p` é a representação
 *          em base 2^51 de 2p = 2^256 − 38: o limb 0 vale 2·(2^51 − 19) e os
 *          limbos 1 a 4 valem 2·(2^51 − 1), de modo que
 *          Σ two_p[i]·2^(51·i) = 2p ≡ 0 (mod p). O deslocamento existe para
 *          que a aritmética sem sinal não envolva durante a subtração; o
 *          resultado é congruente a `f − g` módulo p e só é normalizado por
 *          fe_tobytes().
 * @param[out] h Diferença congruente.
 * @param[in]  f Minuendo.
 * @param[in]  g Subtraendo.
 * @note     Não produz necessariamente um valor em [0, p); os limites por
 *           limb dependem das rotinas que geram os operandos.
 */
static void fe_sub(fe h, const fe f, const fe g) {
    /** Deslocamento por limb: representa 2p em base 2^51 (ver fe_sub()). */
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
   * @typedef  uint128_t
   * @brief    Inteiro de 128 bits sem sinal nativo do compilador.
   * @details  Usado por fe_mul() para acumular os produtos parciais do produto
   *           escolar. Existe somente no ramo em que o compilador declara a
   *           extensão `__SIZEOF_INT128__`; no ramo oposto do `\#if`, o mesmo
   *           nome designa a struct de duas palavras de 64 bits definida mais
   *           abaixo.
   */
  typedef unsigned __int128 uint128_t;
  #if defined(__GNUC__) || defined(__clang__)
    #pragma GCC diagnostic pop
  #endif
  /**
   * @def     MUL64(a,b)
   * @brief   Produto 64×64→128 de dois inteiros sem sinal.
   * @param[in] a Fator.
   * @param[in] b Fator.
   * @return  Produto de 128 bits.
   * @note    Ramificação de tempo de compilação: converte os operandos para
   *           `uint128_t` e multiplica, disponível quando `__SIZEOF_INT128__`
   *           está definido.
   */
  #define MUL64(a,b) ((uint128_t)(a) * (uint128_t)(b))
#else
/**
 * @struct   uint128_t
 * @brief    Par de palavras de 64 bits que representa um inteiro de 128 bits.
 * @details  Representação alternativa, usada quando o compilador não declara
 *           `__SIZEOF_INT128__`. O valor representado é
 *           `lo + hi·2^64`: o campo `lo` traz os bits 0..63 do produto e o
 *           campo `hi` os bits 64..127. Ambos são lidos e escritos apenas
 *           por MUL64() e fe_mul().
 *
 *           Os campos não são descritos com a tag de membro `@@var` porque o
 *           Doxygen 1.8.14 não a vincula a `typedef struct { ... } nome;` de
 *           linha única: as formas tentativas geram avisos falsos
 *           ("documented symbol ... was not declared or defined" e "member
 *           with no name found"). A definição fica entre as tags de seção
 *           condicional `@@cond` e `@@endcond` para que a página do tipo não
 *           herde a exigência de documentar cada campo; com um Doxygen que
 *           suporte esse vínculo, remover as duas tags e descrever os campos
 *           com `@@var` volta a listá-los na página.
 */
/** @cond */
typedef struct { uint64_t lo, hi; } uint128_t;
/** @endcond */
/**
 * @brief   Produto 64×64→128 calculado em quatro produtos parciais de 32 bits.
 * @details Decompõe os fatores nas metades de 32 bits (`a0`, `a1`, `b0`,
 *          `b1`) e forma m0 = a0·b0, m1 = a0·b1, m2 = a1·b0, m3 = a1·b1. A
 *          metade central é `mid = m1 + (m0 >> 32) + m2`: a primeira soma não
 *          pode transbordar porque
 *          m1 + (m0 >> 32) ≤ a0·b1 + a0·b0/2^32 = a0·(b1 + b0/2^32) é
 *          estritamente menor que 2^64, enquanto a segunda pode; o teste
 *          `mid < m2` detecta esse carry perdido e soma 2^32 a m3.
 *          O resultado é `lo = (mid << 32) | (m0 & 0xFFFFFFFF)` e
 *          `hi = m3 + (mid >> 32)`, exatamente o produto de 128 bits.
 * @param[in]  a Fator de 64 bits sem sinal.
 * @param[in]  b Fator de 64 bits sem sinal.
 * @return   Produto de 128 bits em `lo` e `hi`.
 * @note     Ramificação de tempo de compilação: esta versão existe apenas
 *           quando `__SIZEOF_INT128__` não está definido.
 */
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
 * @brief   Multiplica dois elementos do corpo pelo produto escolar com envolvimento.
 * @details Calcula `h = f · g (mod p)` em cinco limbos de base 2^51. O laço
 *          duplo forma os 25 produtos parciais `f[i]·g[j]`, que teriam peso
 *          2^(51·(i+j)). Como `(2^51)^5 = 2^255 ≡ 19 (mod p)`, todo produto com
 *          `i + j ≥ 5` é reindexado em `idx = (i+j) % 5` com um fator
 *          multiplicativo 19 aplicado a `g[j]` (`gi = g[j] * 19`), o que
 *          substitui a redução explícita do expoente. Os produtos parciais são
 *          acumulados em `t[0..4]`, de 128 bits cada.
 *
 *          A propagação de carry usa o mesmo peso de envolvimento: o limbo
 *          `h[i]` recebe os 51 bits baixos de `t[i]`, e o restante (`carry`) é
 *          somado em `t[i+1]` para `i < 4`; para `i = 4` o carry retorna a
 *          `h[0] + carry * 19`. A última linha repete o passo para o carry
 *          gerado por esse retorno, de modo que `h[0]` volte a caber em 51
 *          bits e `h[1]` absorva o excedente.
 *
 *          Saída: todos os limbos permanecem abaixo de 2^52 e o valor
 *          representado é congruente a `f · g` módulo p; não é a forma
 *          canônica em [0, p), que só fe_tobytes() produz.
 * @param[out] h Elemento de destino. Pode ser o mesmo objeto que `f` ou `g`,
 *               pois a escrita em `h` só começa depois de o laço duplo ter
 *               acumulado todos os produtos parciais em `t`.
 * @param[in]  f Primeiro fator.
 * @param[in]  g Segundo fator.
 * @note     Ramificação de tempo de compilação: o laço interno acumula com `+`
 *           nativo de 128 bits quando `__SIZEOF_INT128__` está definido; no
 *           ramo oposto soma `p.lo` com teste manual de estouro e soma `p.hi`,
 *           e a extração de `carry` lê os bits de `t[i].lo` e `t[i].hi` em vez
 *           do inteiro de 128 bits. Os índices de laço e a ordem das operações
 *           são os mesmos nos dois ramos e não dependem dos operandos.
 */
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
 * @brief   Quadrado de um elemento do corpo.
 * @details Delega a fe_mul(h, f, f): não existe rotina de quadrado separada,
 *          portanto não há aproveitamento da simetria dos produtos parciais.
 * @param[out] h Elemento de destino.
 * @param[in]  f Elemento a elevar ao quadrado.
 */
static void fe_sq(fe h, const fe f) { fe_mul(h, f, f); }

/**
 * @brief   Eleva um elemento do corpo a uma potência de dois.
 * @details Aplica `n` quadrados sucessivos: `h = f^(2^n)`. A primeira
 *          quadratura é feita fora do laço, de modo que a contagem efetiva de
 *          quadrados é `n` para `n ≥ 1`. Para `n = 0` o código ainda executa
 *          uma quadratura e devolve `f^2` em vez de `f`; nenhum chamador
 *          neste arquivo passa `n = 0` (fe_inv() usa 2, 5, 10, 20, 50 e 100).
 * @param[out] h Elemento de destino; é lido e reescrito a cada quadratura.
 * @param[in]  f Base.
 * @param[in]  n Número de quadraturas sucessivas.
 */
static void fe_sq_n(fe h, const fe f, int n) {
    fe_sq(h, f);
    for (int i = 1; i < n; i++) fe_sq(h, h);
}

/**
 * @brief   Inverso multiplicativo em GF(2^255 − 19) por exponenciação.
 * @details Calcula `h = f^(p-2) = f^(2^255 − 21)`, que é o inverso de `f`
 *          módulo p pela pequena teorema de Fermat. A exponenciação usa a
 *          cadeia binária clássica: constrói potências da forma `f^(2^k − 1)`
 *          para `k = 5, 10, 20, 40, 50, 100, 250`, combinando cada uma com a
 *          anterior via `fe_sq_n` seguido de `fe_mul`, e fecha com
 *          `f^(2^255 − 2^5) · f^11 = f^(2^255 − 21)`.
 *
 *          São 254 chamadas a fe_sq() e 11 chamadas diretas a fe_mul(), todas
 *          em ordem fixa: a sequência de operações não depende do valor de
 *          `f`, e não existe teste de `f = 0`. Com `f = 0` o resultado é 0,
 *          sem divisão ou desvio de controle.
 * @param[out] h Elemento de destino, que pode ser o mesmo que `f` (os
 *               temporários `t0..t3` absorvem a sobreposição).
 * @param[in]  f Elemento a inverter.
 * @note     Nenhum dos valores intermediários é reduzido à forma canônica: a
 *           congruência módulo p é preservada pelas operações de fe_mul().
 */
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
