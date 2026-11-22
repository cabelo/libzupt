/*
 * ZUPT - AES-256 Block Cipher (FIPS 197)
 * Portable C with algebraic S-box; optional runtime-dispatched AES-NI.
 * FRAMA-C: ACSL-annotated (v2.0.0)
 */
/**
 * @cond PORT
 * @file   zupt_aes256.c
 * @brief  Implementação do cifrador de bloco AES-256 (FIPS 197).
 * @details Contém a expansão de chave e a cifra de um único bloco de 16 bytes
 * em duas variantes: uma portátil, em C11, e uma que usa as
 * instruções AES-NI quando o processador x86 as suporta em tempo de
 * execução. As funções de modo (CTR) e o tratamento de arquivos estão
 * em outros módulos; aqui só se trabalha com blocos inteiros.
 *
 * A S-box é calculada algebricamente (inverso multiplicativo em
 * GF(2⁸) seguido da transformação afim de FIPS 197) em vez de vir de
 * uma tabela consultada por índice derivado do dado. Isso elimina a
 * superfície de leitura de cache que a consulta de tabela formava.
 * @note   Os pré-processadores `ZUPT_FORCE_PORTABLE_AES`, `__GNUC__`,
 * `__clang__`, `__x86_64__` e `__i386__` escolhem o ramo compilado;
 * eles não são macros definidas por este módulo, por isso não são
 * documentadas aqui.
 * @warning Comportamento de tempo constante depende do compilador e
 * da arquitetura alvo e continua sujeito a revisão; a variante
 * AES-NI depende da ordem em que a chave é expandida e carregada.
 * @see    zupt_aes256_init, zupt_aes256_encrypt_block, zupt_aes256_ctx
 * @endcond
 * @cond INGLES
 * @file   zupt_aes256.c
 * @brief  Implementation of the AES-256 block cipher (FIPS 197).
 * @details Contains the key expansion and the encryption of a single 16-byte
 * block in two variants: a portable one, in C11, and one that uses the
 * AES-NI instructions when the x86 processor supports them at runtime.
 * The mode functions (CTR) and file handling are
 * in other modules; only whole blocks are processed here.
 *
 * The S-box is computed algebraically (multiplicative inverse in
 * GF(2⁸) followed by the FIPS 197 affine transformation) instead of coming from
 * a table indexed by a data-derived value. This eliminates the
 * cache read surface that table lookup formed.
 * @note   The preprocessors `ZUPT_FORCE_PORTABLE_AES`, `__GNUC__`,
 * `__clang__`, `__x86_64__` and `__i386__` select the compiled branch;
 * they are not macros defined by this module, so they are
 * not documented here.
 * @warning Constant-time behavior depends on the compiler and
 * on the target architecture and remains subject to review; the AES-NI
 * variant depends on the order in which the key is expanded and loaded.
 * @see    zupt_aes256_init, zupt_aes256_encrypt_block, zupt_aes256_ctx
 * @endcond */
#include "zupt.h"
#include "zupt_acsl.h"
#include <string.h>

/**
 * @cond PORT
 * @brief   Multiplica dois elementos de GF(2⁸) pelo método do xtime.
 * @details Acumula condicionalmente `a` em `out` a cada bit de `b`, reduzindo
 * `a` módulo o polinômio 0x1B (x⁸+x⁴+x³+x+1) a cada dobragem. A
 * redução usa máscara aritmética em vez de ramificação, e o corpo é
 * percorrido sempre em 8 iterações, independentemente do valor de
 * `b`. É a multiplicação usada pelo cálculo da S-box.
 * @param[in] a Fator, visto como elemento de GF(2⁸).
 * @param[in] b Multiplicador, visto como elemento de GF(2⁸).
 * @return  Produto em GF(2⁸).
 * @see     gmul, aes_sbox
 * @endcond
 * @cond INGLES
 * @brief   Multiplies two elements of GF(2⁸) by the xtime method.
 * @details Conditionally accumulates `a` into `out` for each bit of `b`, reducing
 * `a` modulo the polynomial 0x1B (x⁸+x⁴+x³+x+1) at each doubling. The
 * reduction uses an arithmetic mask instead of branching, and the body is
 * always executed in 8 iterations, regardless of the value of
 * `b`. It is the multiplication used by the S-box computation.
 * @param[in] a Factor, viewed as an element of GF(2⁸).
 * @param[in] b Multiplier, viewed as an element of GF(2⁸).
 * @return  Product in GF(2⁸).
 * @see     gmul, aes_sbox
 * @endcond */
static uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t out = 0;
    for (unsigned i = 0; i < 8; ++i) {
        out ^= (uint8_t)(a & (uint8_t)(0u - (b & 1u)));
        a = (uint8_t)((a << 1) ^ (0x1bu & (0u - (a >> 7))));
        b >>= 1;
    }
    return out;
}
/**
 * @cond PORT
 * @brief   Rotação circular à esquerda de um byte.
 * @details Coloca os `n` bits mais significativos na parte baixa. É usada
 * pela transformação afim de aes_sbox() com `n` em 1..4; com `n`
 * igual a 0 a parcela `x >> (8u - n)` desloca por 8, o que é
 * comportamento indefinido, então o valor 0 não deve ser passado.
 * @param[in] x Byte a rotacionar.
 * @param[in] n Número de posições de rotação, esperado em 1..7.
 * @return  Byte rotacionado.
 * @see     aes_sbox
 * @endcond
 * @cond INGLES
 * @brief   Circular left rotation of a byte.
 * @details Places the `n` most significant bits in the low part. It is used
 * by the affine transformation of aes_sbox() with `n`
 * in 1..4; with `n`
 * equal to 0 the term `x >> (8u - n)` shifts by 8, which is
 * undefined behavior, so the value 0 must not be passed.
 * @param[in] x Byte to rotate.
 * @param[in] n Number of rotation positions, expected in 1..7.
 * @return  Rotated byte.
 * @see     aes_sbox
 * @endcond */
static uint8_t rotl8(uint8_t x, unsigned n) {
    return (uint8_t)((x << n) | (x >> (8u - n)));
}
/**
 * @cond PORT
 * @brief   S-box de AES em GF(2⁸), calculada algebricamente.
 * @details Obtém o inverso multiplicativo de `x` como `x^254`, encadeado por
 * multiplicações sucessivas por 2 (x², x³, x⁶, x¹², x¹⁵, x³⁰, x⁶⁰,
 * x¹²⁰, x²⁴⁰, x²⁵²), e aplica a transformação afim de FIPS 197:
 * `y ^ rotl8(y,1) ^ rotl8(y,2) ^ rotl8(y,3) ^ rotl8(y,4) ^ 0x63`.
 * O expoente 254 faz de 0 seu próprio inverso, de modo que a S-box
 * está definida também para a entrada nula. Nenhuma tabela indexada
 * por segredo é consultada.
 * @param[in] x Byte de entrada.
 * @return  Byte de saída da S-box.
 * @see     gf_mul, rotl8
 * @endcond
 * @cond INGLES
 * @brief   AES S-box in GF(2⁸), computed algebraically.
 * @details Obtains the multiplicative inverse of `x` as `x^254`, chained by
 * successive multiplications by 2 (x², x³, x⁶, x¹², x¹⁵, x³⁰, x⁶⁰,
 * x¹²⁰, x²⁴⁰, x²⁵²), and applies the FIPS 197 affine transformation:
 * `y ^ rotl8(y,1) ^ rotl8(y,2) ^ rotl8(y,3) ^ rotl8(y,4) ^ 0x63`.
 * The exponent 254 makes 0 its own inverse, so the S-box
 * is also defined for the zero input. No table indexed
 * by a secret is consulted.
 * @param[in] x Input byte.
 * @return  S-box output byte.
 * @see     gf_mul, rotl8
 * @endcond */
static uint8_t aes_sbox(uint8_t x) {
    /* x^254 in GF(2^8), including inverse(0) = 0. */
    uint8_t x2 = gf_mul(x, x);
    uint8_t x3 = gf_mul(x2, x);
    uint8_t x6 = gf_mul(x3, x3);
    uint8_t x12 = gf_mul(x6, x6);
    uint8_t x15 = gf_mul(x12, x3);
    uint8_t x30 = gf_mul(x15, x15);
    uint8_t x60 = gf_mul(x30, x30);
    uint8_t x120 = gf_mul(x60, x60);
    uint8_t x240 = gf_mul(x120, x120);
    uint8_t x252 = gf_mul(x240, x12);
    uint8_t y = gf_mul(x252, x2);
    return (uint8_t)(y ^ rotl8(y, 1) ^ rotl8(y, 2) ^
                     rotl8(y, 3) ^ rotl8(y, 4) ^ 0x63u);
}

/**
 * @cond PORT
 * @var   RCON
 * @brief Constantes de rodada da expansão de chave AES, em GF(2⁸).
 * @details `RCON[i] = 3^(i-1)` calculado em GF(2⁸) com o polinômio 0x1B, ou
 * seja 1, 2, 4, 8, 16, 32, 64, 128, 27 (0x1B) e 54 (0x36); a posição
 * 0 vale 0 e não é consumida. zupt_aes256_init() usa apenas os
 * índices 1..7, obtidos de `i/8` para as palavras 8..56 da chave de
 * rodada — os demais valores sobram da forma geral da tabela.
 * @see     zupt_aes256_init
 * @endcond
 * @cond INGLES
 * @var   RCON
 * @brief Round constants of the AES key expansion, in GF(2⁸).
 * @details `RCON[i] = 3^(i-1)` computed in GF(2⁸) with the polynomial 0x1B, that is,
 * 1, 2, 4, 8, 16, 32, 64, 128, 27 (0x1B) and 54 (0x36); position
 * 0 is 0 and is not consumed. zupt_aes256_init() uses only the
 * indices 1..7, obtained from `i/8` for words 8..56 of the round
 * key — the remaining values come from the general form of the table.
 * @see     zupt_aes256_init
 * @endcond */
static const uint8_t RCON[11] = {0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

/* ─── GF(2^8) multiply ─── */
/**
 * @cond PORT
 * @brief   Dobragem em GF(2⁸), isto é, multiplicação por x.
 * @details Desloca para a esquerda e, quando o bit 7 do original estava
 * aceso, xoriza com o polinômio de redução 0x1B. A máscara
 * `(x>>7)&1` evita ramificação.
 * @param[in] x Elemento de GF(2⁸).
 * @return  Produto por x em GF(2⁸).
 * @see     gmul
 * @endcond
 * @cond INGLES
 * @brief   Doubling in GF(2⁸), that is, multiplication by x.
 * @details Shifts left and, when bit 7 of the original was
 * set, xors with the reduction polynomial 0x1B. The mask
 * `(x>>7)&1` avoids branching.
 * @param[in] x Element of GF(2⁸).
 * @return  Product by x in GF(2⁸).
 * @see     gmul
 * @endcond */
static inline uint8_t xtime(uint8_t x) { return (x<<1)^(((x>>7)&1)*0x1b); }
/**
 * @cond PORT
 * @brief   Produto em GF(2⁸) usado pela etapa MixColumns.
 * @details Espalhar-and-add de sempre oito iterações: acumula `a`
 * condicionalmente pelo bit menos significativo de `b` e dobra `a`
 * com xtime(). Equivalente a gf_mul(), mas mantida separada e
 * inlinada para os multiplicadores fixos 2 e 3 de MixColumns.
 * @param[in] a Fator, visto como elemento de GF(2⁸).
 * @param[in] b Multiplicador, visto como elemento de GF(2⁸).
 * @return  Produto em GF(2⁸).
 * @see     gf_mul, xtime
 * @endcond
 * @cond INGLES
 * @brief   Product in GF(2⁸) used by the MixColumns step.
 * @details Spread-and-add of always eight iterations: conditionally accumulates `a`
 * by the least significant bit of `b` and doubles `a`
 * with xtime(). Equivalent to gf_mul(), but kept separate and
 * inlined for the fixed MixColumns multipliers 2 and 3.
 * @param[in] a Factor, viewed as an element of GF(2⁸).
 * @param[in] b Multiplier, viewed as an element of GF(2⁸).
 * @return  Product in GF(2⁸).
 * @see     gf_mul, xtime
 * @endcond */
static inline uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t r=0;
    for (int i=0;i<8;i++) { r ^= (uint8_t)(a & (uint8_t)(0u - (b & 1u))); a=xtime(a); b>>=1; }
    return r;
}

/* ─── Key Expansion (AES-256: 14 rounds, 60 round-key words) ─── */
/* FRAMA-C: AES-256 key schedule expansion */
/*@ requires \valid(c);
  @ requires \valid_read(key + (0..31));
  @ assigns c->rk[0..59];
  @ ensures \initialized(&c->rk[0..59]);
*/
void zupt_aes256_init(zupt_aes256_ctx *c, const uint8_t key[32]) {
    uint32_t *rk = c->rk;
    for (int i=0;i<8;i++)
        rk[i] = ((uint32_t)key[4*i]<<24)|((uint32_t)key[4*i+1]<<16)|
                ((uint32_t)key[4*i+2]<<8)|key[4*i+3];
    for (int i=8;i<60;i++) {
        uint32_t t = rk[i-1];
        if (i%8==0) {
            t = ((uint32_t)aes_sbox((t>>16)&0xFF)<<24)|((uint32_t)aes_sbox((t>>8)&0xFF)<<16)|
                ((uint32_t)aes_sbox(t&0xFF)<<8)|aes_sbox(t>>24);
            t ^= (uint32_t)RCON[i/8]<<24;
        } else if (i%8==4) {
            t = ((uint32_t)aes_sbox(t>>24)<<24)|((uint32_t)aes_sbox((t>>16)&0xFF)<<16)|
                ((uint32_t)aes_sbox((t>>8)&0xFF)<<8)|aes_sbox(t&0xFF);
        }
        rk[i] = rk[i-8]^t;
    }
}


#if !defined(ZUPT_FORCE_PORTABLE_AES) && (defined(__GNUC__) || defined(__clang__)) && (defined(__x86_64__) || defined(__i386__))
#include <wmmintrin.h>
/**
 * @cond PORT
 * @brief   Cifra de um único bloco com as instruções AES-NI.
 * @details Reconstrói a chave de rodada em `round_key` byte a byte a partir
 * das palavras de 32 bits do contexto, que ficam armazenadas em
 * ordem grande-endian, e carrega o resultado como `__m128i`. Aplica
 * AddRoundKey com `_mm_xor_si128` na rodada 0, `_mm_aesenc_si128`
 * nas rodadas 1 a 13 (que já fazem SubBytes, ShiftRows e MixColumns)
 * e `_mm_aesenclast_si128` na rodada 14. As leituras e escritas são
 * não alinhadas (`_mm_loadu_si128`/`_mm_storeu_si128`), então o
 * endereço de `in` e `out` não precisa estar alinhado.
 * @param[in]  c   Contexto com as 60 palavras de chave de rodada expandidas.
 * @param[in]  in  Bloco de 16 bytes em claro.
 * @param[out] out Bloco cifrado de 16 bytes.
 * @note   Só existe no ramo em que `ZUPT_FORCE_PORTABLE_AES` não está
 * definido, o compilador é GCC/Clang e a arquitetura é x86. É
 * chamada por zupt_aes256_encrypt_block() após o teste
 * `__builtin_cpu_supports("aes")`, de modo que o código é executado
 * apenas em processadores com a extensão.
 * @note   `round_key` é apagado com zupt_secure_wipe() antes do retorno para
 * não deixar chave de rodada na pilha.
 * @see    zupt_aes256_encrypt_block
 * @endcond
 * @cond INGLES
 * @brief   Encryption of a single block with the AES-NI instructions.
 * @details Rebuilds the round key in `round_key` byte by byte from
 * the context's 32-bit words, which are stored in
 * big-endian order, and loads the result as `__m128i`. Applies
 * AddRoundKey with `_mm_xor_si128` in round 0, `_mm_aesenc_si128`
 * in rounds 1 to 13 (which already perform SubBytes, ShiftRows and MixColumns)
 * and `_mm_aesenclast_si128` in round 14. The reads and writes are
 * unaligned (`_mm_loadu_si128`/`_mm_storeu_si128`), so the
 * addresses of `in` and `out` do not need to be aligned.
 * @param[in]  c   Context with the 60 expanded round-key words.
 * @param[in]  in  16-byte plaintext block.
 * @param[out] out 16-byte encrypted block.
 * @note   Only exists in the branch where `ZUPT_FORCE_PORTABLE_AES` is not
 * defined, the compiler is GCC/Clang and the architecture is x86. It is
 * called by zupt_aes256_encrypt_block() after the test
 * `__builtin_cpu_supports("aes")`, so the code runs
 * only on processors with the extension.
 * @note   `round_key` is wiped with zupt_secure_wipe() before the return so as
 * not to leave the round key on the stack.
 * @see    zupt_aes256_encrypt_block
 * @endcond */
__attribute__((target("aes,sse2")))
static void aesni_encrypt_block(const zupt_aes256_ctx *c,
                                 const uint8_t in[16], uint8_t out[16]) {
    uint8_t round_key[16];
    __m128i state = _mm_loadu_si128((const __m128i *)(const void *)in);
    for (unsigned round = 0; round < 15; ++round) {
        for (unsigned i = 0; i < 16; ++i)
            round_key[i] = (uint8_t)(c->rk[round * 4 + i / 4] >> (24 - 8 * (i % 4)));
        __m128i key = _mm_loadu_si128((const __m128i *)(const void *)round_key);
        if (round == 0) state = _mm_xor_si128(state, key);
        else if (round == 14) state = _mm_aesenclast_si128(state, key);
        else state = _mm_aesenc_si128(state, key);
    }
    _mm_storeu_si128((__m128i *)(void *)out, state);
    zupt_secure_wipe(round_key, sizeof(round_key));
}
#endif

/* ─── Single block encryption ─── */
/* FRAMA-C: AES-256 single-block encrypt */
/*@ requires \valid_read(&c->rk[0..59]);
  @ requires \valid_read(in + (0..15));
  @ requires \valid(out + (0..15));
  @ requires \separated(in + (0..15), out + (0..15));
  @ assigns out[0..15];
  @ ensures \initialized(out + (0..15));
*/
void zupt_aes256_encrypt_block(const zupt_aes256_ctx *c, const uint8_t in[16], uint8_t out[16]) {
#if !defined(ZUPT_FORCE_PORTABLE_AES) && (defined(__GNUC__) || defined(__clang__)) && (defined(__x86_64__) || defined(__i386__))
    if (__builtin_cpu_supports("aes")) {
        aesni_encrypt_block(c, in, out);
        return;
    }
#endif
    uint8_t s[16];
    const uint32_t *rk = c->rk;
    /* AddRoundKey(0) */
    for (int i=0;i<16;i++)
        s[i] = in[i]^(uint8_t)(rk[i/4]>>((3-i%4)*8));
    /* Rounds 1-13 */
    for (int r=1;r<=13;r++) {
        uint8_t t[16];
        /* SubBytes */
        for (int i=0;i<16;i++) t[i]=aes_sbox(s[i]);
        /* ShiftRows */
        uint8_t u[16];
        u[0]=t[0]; u[1]=t[5]; u[2]=t[10]; u[3]=t[15];
        u[4]=t[4]; u[5]=t[9]; u[6]=t[14]; u[7]=t[3];
        u[8]=t[8]; u[9]=t[13]; u[10]=t[2]; u[11]=t[7];
        u[12]=t[12]; u[13]=t[1]; u[14]=t[6]; u[15]=t[11];
        /* MixColumns */
        for (int col=0;col<4;col++) {
            uint8_t a0=u[col*4],a1=u[col*4+1],a2=u[col*4+2],a3=u[col*4+3];
            s[col*4+0]=gmul(a0,2)^gmul(a1,3)^a2^a3;
            s[col*4+1]=a0^gmul(a1,2)^gmul(a2,3)^a3;
            s[col*4+2]=a0^a1^gmul(a2,2)^gmul(a3,3);
            s[col*4+3]=gmul(a0,3)^a1^a2^gmul(a3,2);
        }
        /* AddRoundKey */
        for (int i=0;i<16;i++)
            s[i] ^= (uint8_t)(rk[r*4+i/4]>>((3-i%4)*8));
    }
    /* Round 14 (no MixColumns) */
    {
        uint8_t t[16];
        for (int i=0;i<16;i++) t[i]=aes_sbox(s[i]);
        uint8_t u[16];
        u[0]=t[0]; u[1]=t[5]; u[2]=t[10]; u[3]=t[15];
        u[4]=t[4]; u[5]=t[9]; u[6]=t[14]; u[7]=t[3];
        u[8]=t[8]; u[9]=t[13]; u[10]=t[2]; u[11]=t[7];
        u[12]=t[12]; u[13]=t[1]; u[14]=t[6]; u[15]=t[11];
        for (int i=0;i<16;i++)
            out[i] = u[i]^(uint8_t)(rk[56+i/4]>>((3-i%4)*8));
    }
}
