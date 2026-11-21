/*
 * Zupt — Backup-oriented compression with AES-256 encryption
 * Copyright (c) 2026 Cristian Cezar Moisés
 * SPDX-License-Identifier: MIT
 *
 * Keccak-f[1600] permutation with SHA3-256, SHA3-512, SHAKE-128, SHAKE-256.
 * Implements FIPS 202 (SHA-3 Standard).
 * Required by ML-KEM-768 (FIPS 203) for hashing and sampling.
 *
 * FRAMA-C: ACSL-annotated (v2.0.0)
 */
/**
 * @file   zupt_keccak.c
 * @brief  Implementação da permutação Keccak-f[1600] e da construção em
 *         esponja com SHA3-256, SHA3-512, SHAKE-128 e SHAKE-256.
 * @details O arquivo contém a permutação (keccakf()), as quatro etapas da
 *          esponja (keccak_init(), keccak_absorb(), keccak_finalize(),
 *          keccak_squeeze()) e as primitivas públicas de uma passada e
 *          incrementais declaradas em include/zupt_keccak.h.
 *
 *          A permutação executa 24 rodadas, cada uma na ordem θ (theta),
 *          ρ+π combinadas, χ (chi) e ι (iota). O estado é tratado como matriz
 *          5×5 indexada por `i = x + 5y`: a etapa θ percorre uma coluna somando
 *          `st[i]`, `st[i+5]`, `st[i+10]`, `st[i+15]` e `st[i+20]`. θ e ι
 *          operam sobre o estado no lugar; ρ+π escrevem em um buffer
 *          temporário de 25 lanes porque χ precisa ler os valores antes da
 *          rotação e da permutação.
 *
 *          As três tabelas internas (KECCAK_RC, KECCAK_ROT, KECCAK_PI)
 *          reproduzem os parâmetros publicados da permutação, o que foi
 *          confirmado em execução contra os vetores conhecidos: SHA3-256 da
 *          mensagem vazia começa em `a7ffc6f8bf1ed766`, SHA3-256 de "abc" em
 *          `3a985da74fe225b2`, SHA3-512 de "abc" em `b751850b1a57168a` e
 *          SHAKE-128 de "abc" em `5881092dd818bf5c`. Mensagens maiores que a
 *          taxa e sequências incrementais com tamanhos irregulares também
 *          coincidem com os mesmos valores.
 *
 *          A conversão entre bytes e lanes é little-endian nas duas
 *          direções: na absorção, dentro de cada grupo de 8 bytes o de índice
 *          menor (`buf[k*8]`) é o byte menos significativo do lane e o de
 *          índice maior é o mais significativo; no squeeze a leitura segue a
 *          mesma regra. O resultado, portanto, não depende da endianidade da
 *          máquina.
 *
 *          Diferença entre SHA3 e SHAKE neste código: além da taxa, apenas o
 *          sufixo de domínio escrito no padding muda — 0x06 para SHA3-256 e
 *          SHA3-512, 0x1F para SHAKE-128 e SHAKE-256. A saída do SHA3 é
 *          sempre mais curta que a taxa, então uma única extração basta; as
 *          variantes SHAKE são usadas como XOF (função de saída estendida, do
 *          inglês extendable-output function) e podem extrair mais de um
 *          bloco da taxa.
 *
 *          Não há alocação dinâmica (todas as funções usam variáveis em
 *          pilha) nem primitivas de sincronização, e nenhum estado ou buffer
 *          sensível é apagado ao final. Os blocos de anotação ACSL (ANSI/ISO C
 *          Specification Language), que começam com barra, estrela e arroba,
 *          servem à verificação com Frama-C e não participam do código
 *          compilado.
 */
#include "zupt_keccak.h"
#include "zupt_acsl.h"
#include <string.h>

/* ═══════════════════════════════════════════════════════════════════
 * KECCAK-f[1600] ROUND CONSTANTS
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * @brief  Constantes de rodada usadas pela etapa ι (iota) de Keccak-f[1600].
 * @details São os 24 valores consumidos um por rodada, na ordem de `round` em
 *          keccakf(), e aplicados por XOR somente à lane `st[0]`. É o único
 *          passo da permutação que distingue as rodadas entre si: sem ele todas
 *          as rodadas seriam idênticas e a permutação degeneraria. O valor tem
 *          poucos bits armados — entre 1 e 6 nesta sequência — e só os 64 bits
 *          baixos da definição do padrão aparecem na tabela.
 * @note   A sequência começa em 0x0000000000000001 e termina em
 *         0x8000000080008008, coincidindo com a tabela publicada para
 *         Keccak-f[1600] em FIPS 202 (Federal Information Processing
 *         Standards, o padrão que define SHA-3).
 */
static const uint64_t KECCAK_RC[24] = {
    UINT64_C(0x0000000000000001), UINT64_C(0x0000000000008082),
    UINT64_C(0x800000000000808A), UINT64_C(0x8000000080008000),
    UINT64_C(0x000000000000808B), UINT64_C(0x0000000080000001),
    UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008009),
    UINT64_C(0x000000000000008A), UINT64_C(0x0000000000000088),
    UINT64_C(0x0000000080008009), UINT64_C(0x000000008000000A),
    UINT64_C(0x000000008000808B), UINT64_C(0x800000000000008B),
    UINT64_C(0x8000000000008089), UINT64_C(0x8000000000008003),
    UINT64_C(0x8000000000008002), UINT64_C(0x8000000000000080),
    UINT64_C(0x000000000000800A), UINT64_C(0x800000008000000A),
    UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008080),
    UINT64_C(0x0000000080000001), UINT64_C(0x8000000080008008)
};

/**
 * @brief  Deslocamentos circulares da etapa ρ (rho), por índice linear de lane.
 * @details `KECCAK_ROT[i]` é a quantidade de bits à esquerda aplicada à lane
 *          `st[i]` em keccakf(), na mesma numeração linear `i = x + 5y` das
 *          lanes usada por `st` e por KECCAK_PI. O deslocamento da lane
 *          `st[0]` é 0 — a única entrada nula da tabela — e os demais variam
 *          entre 1 e 62, todos estritamente menores que 64 para que a rotação
 *          nunca precise do caso especial de deslocamento nulo além do primeiro.
 * @note   Os valores coincidem com os deslocamentos publicados para
 *         Keccak-f[1600], lidos na ordem linear desta tabela; a correspondência
 *         foi confirmada em execução, pois ρ+π aplicadas com esta tabela e com
 *         KECCAK_PI reproduzem os digestos de referência de SHA3-256,
 *         SHA3-512 e SHAKE-128.
 */
/* Rotation offsets per FIPS 202 */
static const int KECCAK_ROT[25] = {
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14
};

/**
 * @brief  Índices de destino da etapa π (pi) de Keccak-f[1600].
 * @details `KECCAK_PI[i]` é o índice da lane que recebe o valor rotacionado de
 *          `st[i]` na etapa ρ+π de keccakf(). Na numeração linear `i = x + 5y`
 *          das lanes de coordenadas (x, y), o destino é
 *          `y + 5·((2x + 3y) mod 5)`, que é a permutação π do padrão escrita
 *          como tabela de índices. A tabela é bijetiva — cada índice de 0 a 24
 *          aparece exatamente uma vez —, então nenhuma lane é perdida nem
 *          sobrescrita por outra.
 * @note   π é a etapa que espalha a difusão entre linhas e colunas: sem ela,
 *         θ e χ continuariam operando apenas dentro das mesmas linhas e a
 *         permutação não misturaria o estado inteiro.
 */
/* Pi permutation indices */
static const int KECCAK_PI[25] = {
     0, 10, 20,  5, 15,
    16,  1, 11, 21,  6,
     7, 17,  2, 12, 22,
    23,  8, 18,  3, 13,
    14, 24,  9, 19,  4
};

/**
 * @brief  Rotação circular à esquerda de um valor de 64 bits por `n` bits.
 * @details Junta, na parte de baixo do resultado, os bits que saem pelo topo,
 *          de modo que nenhum bit de `x` se perde. É usada pela etapa ρ (rho) de
 *          keccakf() com os deslocamentos lidos de KECCAK_ROT, que variam de 0 a
 *          62.
 * @param x Valor de 64 bits a girar.
 * @param n Quantidade de bits à esquerda; deve ser no máximo 63.
 * @return O valor girado, `(x << n) | (x >> (64 - n))`, ou o próprio `x` quando
 *         `n` é 0.
 * @note O teste contra zero é necessário: deslocar um valor de 64 bits por 64 ou
 *       mais posições é comportamento indefinido na linguagem, e a lane `st[0]`
 *       tem deslocamento 0 em KECCAK_ROT.
 */
#define ROL64(x, n) ((n) ? (((x) << (n)) | ((x) >> (64 - (n)))) : (x))

/* ═══════════════════════════════════════════════════════════════════
 * KECCAK-f[1600] PERMUTATION (24 rounds)
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * @brief  Aplica a permutação Keccak-f[1600] em lugar sobre as 25 lanes do
 *         estado.
 * @details Executa 24 rodadas, cada uma na sequência θ (theta), ρ (rho) +
 *          π (pi), χ (chi) e ι (iota), todas operando sobre o mesmo vetor
 *          `st`. Na numeração linear `i = x + 5y`, uma coluna é o conjunto de
 *          índices com mesmo `x` — `st[i]`, `st[i+5]`, `st[i+10]`, `st[i+15]`
 *          e `st[i+20]` — e uma linha é o bloco de cinco índices consecutivos
 *          a partir de `j` múltiplo de 5.
 *
 *          θ soma as cinco lanes de cada coluna em `bc[i]` e XOR-ia em todas as
 *          lanes da coluna com o termo `bc[i-1] ^ rotl(bc[i+1], 1)`, com os
 *          índices de coluna tomados módulo 5. ρ+π giram cada lane por
 *          `KECCAK_ROT[i]` bits à esquerda e escrevem o resultado na lane
 *          `KECCAK_PI[i]`; o destino é o buffer temporário `tmp` porque χ precisa
 *          ler os valores de antes de ρ. χ é o passo não linear: linha a linha,
 *          cada lane recebe `tmp[j+i] ^ ((~tmp[j+i+1]) & tmp[j+i+2])`, com os
 *          índices dentro da linha tomados módulo 5. ι fecha a rodada aplicando
 *          `KECCAK_RC[round]` por XOR apenas em `st[0]`.
 *
 *          θ, ρ+π, χ e ι usam exatamente os deslocamentos e constantes das
 *          tabelas KECCAK_RC, KECCAK_ROT e KECCAK_PI definidas acima, o que foi
 *          confirmado executando a esponja inteira contra os digestos de
 *          referência de SHA3-256, SHA3-512 e SHAKE-128.
 * @param[in,out] st As 25 lanes do estado, modificadas em lugar pela permutação.
 * @note   A função não conhece taxa, sufixo de domínio nem endianidade: recebe
 *         apenas as lanes já montadas e devolve as lanes permutadas, servindo
 *         tanto à absorção quanto ao squeeze.
 * @warning `st` precisa ter exatamente 25 lanes; nenhum índice é validado.
 * @see     KECCAK_RC, KECCAK_ROT, KECCAK_PI
 */
static void keccakf(uint64_t st[25]) {
    for (int round = 0; round < 24; round++) {
        uint64_t bc[5], t;

        /* θ (theta) */
        for (int i = 0; i < 5; i++)
            bc[i] = st[i] ^ st[i+5] ^ st[i+10] ^ st[i+15] ^ st[i+20];
        for (int i = 0; i < 5; i++) {
            t = bc[(i+4)%5] ^ ROL64(bc[(i+1)%5], 1);
            for (int j = 0; j < 25; j += 5) st[j+i] ^= t;
        }

        /* ρ (rho) + π (pi) */
        uint64_t tmp[25];
        for (int i = 0; i < 25; i++)
            tmp[KECCAK_PI[i]] = ROL64(st[i], KECCAK_ROT[i]);

        /* χ (chi) */
        for (int j = 0; j < 25; j += 5)
            for (int i = 0; i < 5; i++)
                st[j+i] = tmp[j+i] ^ ((~tmp[j+(i+1)%5]) & tmp[j+(i+2)%5]);

        /* ι (iota) */
        st[0] ^= KECCAK_RC[round];
    }
}

/* ═══════════════════════════════════════════════════════════════════
 * SPONGE CONSTRUCTION
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * @brief  Inicializa o contexto esponja com a taxa e o sufixo de domínio dados.
 * @details Apaga o contexto inteiro (`st`, `buf`, `rate`, `pt` e `dsuf`) e
 *          escreve nele a taxa em bytes e o sufixo que o padding de
 *          keccak_finalize() usará. É o único ponto onde a variante da primitiva
 *          — SHA3-256, SHA3-512, SHAKE-128 ou SHAKE-256 — é escolhida: as
 *          funções keccak_absorb(), keccak_finalize() e keccak_squeeze() são
 *          comuns a todas e derivam o comportamento apenas de `rate` e `dsuf`.
 * @param[out] ctx  Contexto a preparar.
 * @param[in]  rate Taxa em bytes: precisa ser múltiplo de 8 e não passar de 200,
 *                  o tamanho de `buf`; as variantes deste módulo usam 72, 136
 *                  e 168.
 * @param[in]  dsuf Sufixo de domínio escrito no padding: 0x06 para SHA3 e 0x1F
 *                  para SHAKE.
 * @post `st` e `buf` todo-zero, `pt` igual a 0, `rate` e `dsuf` como fornecidos.
 * @warning Não há validação de `rate`: valor não múltiplo de 8 faz o número de
 *          lanes montadas por bloco ser truncado na divisão por 8, e valor maior
 *          que 200 escreve fora de `buf`.
 * @see     zupt_shake128_init(), zupt_shake256_init()
 */
static void keccak_init(zupt_keccak_ctx *ctx, size_t rate, uint8_t dsuf) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->rate = rate;
    ctx->dsuf = dsuf;
}

/**
 * @brief  Absorve `len` bytes na esponja, incorporando e permutando cada bloco
 *         completo de taxa.
 * @details Copia os bytes para o bloco corrente em `buf` a partir de `pt`, na
 *          quantidade que couber (`rate - pt` ou o que resta de `data`, o menor
 *          dos dois). Quando `pt` atinge a taxa, os `rate` bytes de `buf` são
 *          montados em lanes de 64 bits little-endian — a lane `k` é formada de
 *          `buf[k*8+7]` como byte mais significativo até `buf[k*8]` como menos
 *          significativo —, XOR-adas às `rate/8` primeiras lanes de `st` e a
 *          permutação keccakf() é aplicada; `pt` volta a 0 e a cópia continua.
 *          Assim uma chamada com mensagem várias vezes maior que a taxa executa
 *          tantas permutações quantos blocos completos houver, sem estourar
 *          `buf`.
 *
 *          Ao final, `pt` marca a posição onde keccak_finalize() escreverá o
 *          sufixo de domínio: 0 quando a mensagem termina exatamente num limite
 *          de bloco, um valor entre 1 e `rate-1` quando resta um bloco parcial.
 * @param[in,out] ctx  Contexto já inicializado por keccak_init().
 * @param[in]     data `len` bytes a absorver.
 * @param[in]     len  Número de bytes de `data`; 0 não altera o contexto.
 * @note   `buf` não é limpo quando um bloco é consumido: a cauda com os bytes do
 *         bloco anterior continua lá. Ela nunca chega a ser incorporada, porque
 *         o bloco só é XOR-ado ao estado quando `pt` atinge a taxa — momento em
 *         que todos os `rate` bytes foram escritos por `data` — e
 *         keccak_finalize() zera exatamente a parte não escrita do bloco final.
 * @warning `ctx` precisa ter `rate` já definida por keccak_init(). Com `rate`
 *          zero o espaço livre calculado é 0, `chunk` fica 0 e cada iteração do
 *          laço apenas aplica uma permutação, sem nunca avançar `i`: o laço não
 *          termina.
 * @see     keccak_finalize()
 */
static void keccak_absorb(zupt_keccak_ctx *ctx, const uint8_t *data, size_t len) {
    size_t i = 0;
    while (i < len) {
        size_t avail = ctx->rate - ctx->pt;
        size_t chunk = (len - i) < avail ? (len - i) : avail;
        for (size_t j = 0; j < chunk; j++)
            ctx->buf[ctx->pt + j] = data[i + j];
        ctx->pt += chunk;
        i += chunk;
        if (ctx->pt == ctx->rate) {
            /* XOR buffer into state (little-endian lanes) */
            for (size_t k = 0; k < ctx->rate / 8; k++) {
                uint64_t lane = 0;
                for (int b = 7; b >= 0; b--)
                    lane = (lane << 8) | ctx->buf[k*8 + b];
                ctx->st[k] ^= lane;
            }
            keccakf(ctx->st);
            ctx->pt = 0;
        }
    }
}

/**
 * @brief  Fecha a absorção com o padding da esponja e deixa o estado pronto para
 *         o squeeze.
 * @details Escreve o sufixo de domínio `dsuf` em `buf[pt]`, preenche de zeros o
 *          intervalo `buf[pt+1 .. rate-1]` e põe o bit final da regra de padding
 *          em `buf[rate-1]` por OU com 0x80 — é o "1" que fecha a sequência de
 *          zeros depois do sufixo, na última posição do bloco. Esse último bloco
 *          é então montado em lanes little-endian, XOR-ado às `rate/8` primeiras
 *          lanes de `st` e permutado por keccakf(). Por fim `pt` volta a 0, que
 *          passa a ser a posição de leitura dentro da faixa de saída da taxa.
 * @param[in,out] ctx Contexto com toda a mensagem já absorvida por
 *                    keccak_absorb() e com `pt` menor que `rate`.
 * @post `pt` igual a 0 e último bloco já incorporado e permutado no estado.
 * @warning A chamada pressupõe `pt` menor que `rate`. Se `pt` for igual a
 *          `rate` — situação possível depois de um squeeze que consumiu um bloco
 *          inteiro —, o tamanho do preenchimento de zeros, `rate - pt - 1`, é
 *          calculado em inteiro sem sinal e vira um valor enorme, o que faz
 *          `memset` escrever muito além de `buf`. Chamar duas vezes a função tem
 *          o outro problema: o segundo padding é aplicado sobre o estado já
 *          permutado, produzindo uma saída que não corresponde a nenhuma
 *          primitiva.
 * @see     keccak_squeeze()
 */
static void keccak_finalize(zupt_keccak_ctx *ctx) {
    /* Pad: domain suffix + 10*1 padding */
    ctx->buf[ctx->pt] = ctx->dsuf;
    memset(ctx->buf + ctx->pt + 1, 0, ctx->rate - ctx->pt - 1);
    ctx->buf[ctx->rate - 1] |= 0x80;
    /* XOR final block into state */
    for (size_t k = 0; k < ctx->rate / 8; k++) {
        uint64_t lane = 0;
        for (int b = 7; b >= 0; b--)
            lane = (lane << 8) | ctx->buf[k*8 + b];
        ctx->st[k] ^= lane;
    }
    keccakf(ctx->st);
    ctx->pt = 0;
}

/**
 * @brief  Extrai `len` bytes do fluxo de saída de uma esponja já finalizada.
 * @details Lê a partir de `pt` dentro da faixa de taxa do estado: o byte de
 *          índice `n` da saída é o byte `n mod 8` da lane `n / 8`, little-endian
 *          (a lane é lida deslocando 8·(n mod 8) bits e truncando em 8 bits), de
 *          modo que a extração não dependa da endianidade da máquina. Há no
 *          máximo `rate - pt` bytes disponíveis; quando o consumo atinge a taxa,
 *          keccakf() é aplicada antes de continuar, gerando o próximo bloco do
 *          fluxo. Por isso chamadas sucessivas reproduzem o mesmo fluxo contínuo
 *          de um XOF, e `len` não tem limite superior além do espaço em `out`.
 * @param[in,out] ctx Contexto já finalizado por keccak_finalize(); `pt` é a
 *                    posição corrente de leitura dentro da taxa.
 * @param[out]    out `len` bytes de saída.
 * @param[in]     len Número de bytes a extrair; 0 não escreve nem permuta.
 * @note   O squeeze altera o estado: ao esgotar a taxa, o bloco seguinte é
 *         derivado do estado já permutado. Depois de qualquer extração não é
 *         possível voltar a absorver.
 * @warning `ctx` deve estar finalizado: chamar o squeeze antes de
 *          keccak_finalize() extrai bytes do estado de absorção em andamento,
 *          não de uma derivação completa.
 * @see     keccak_finalize()
 */
static void keccak_squeeze(zupt_keccak_ctx *ctx, uint8_t *out, size_t len) {
    size_t i = 0;
    while (i < len) {
        if (ctx->pt == ctx->rate) {
            keccakf(ctx->st);
            ctx->pt = 0;
        }
        /* Extract bytes from state (little-endian) */
        size_t avail = ctx->rate - ctx->pt;
        size_t chunk = (len - i) < avail ? (len - i) : avail;
        for (size_t j = 0; j < chunk; j++) {
            size_t byte_idx = ctx->pt + j;
            out[i + j] = (uint8_t)(ctx->st[byte_idx / 8] >> (8 * (byte_idx % 8)));
        }
        ctx->pt += chunk;
        i += chunk;
    }
}

/* ═══════════════════════════════════════════════════════════════════
 * SHA3-256: rate=136 bytes (1088 bits), capacity=512 bits
 * ═══════════════════════════════════════════════════════════════════ */

/* FRAMA-C: SHA3-256 one-shot hash */
/*@ requires \valid_read(data + (0..len-1));
  @ requires \valid(out + (0..31));
  @ requires \separated(data + (0..len-1), out + (0..31));
  @ assigns out[0..31];
  @ ensures \initialized(out + (0..31));
*/
void zupt_sha3_256(const uint8_t *data, size_t len, uint8_t out[32]) {
    zupt_keccak_ctx ctx;
    keccak_init(&ctx, 136, 0x06); /* SHA3 domain suffix */
    keccak_absorb(&ctx, data, len);
    keccak_finalize(&ctx);
    keccak_squeeze(&ctx, out, 32);
}

/* ═══════════════════════════════════════════════════════════════════
 * SHA3-512: rate=72 bytes (576 bits), capacity=1024 bits
 * ═══════════════════════════════════════════════════════════════════ */

/* FRAMA-C: SHA3-512 one-shot hash */
/*@ requires \valid_read(data + (0..len-1));
  @ requires \valid(out + (0..63));
  @ requires \separated(data + (0..len-1), out + (0..63));
  @ assigns out[0..63];
  @ ensures \initialized(out + (0..63));
*/
void zupt_sha3_512(const uint8_t *data, size_t len, uint8_t out[64]) {
    zupt_keccak_ctx ctx;
    keccak_init(&ctx, 72, 0x06);
    keccak_absorb(&ctx, data, len);
    keccak_finalize(&ctx);
    keccak_squeeze(&ctx, out, 64);
}

/* ═══════════════════════════════════════════════════════════════════
 * SHAKE-128: rate=168 bytes (1344 bits)
 * ═══════════════════════════════════════════════════════════════════ */

/* FRAMA-C: SHAKE-128 extendable output function */
/*@ requires \valid_read(data + (0..dlen-1));
  @ requires \valid(out + (0..olen-1));
  @ requires \separated(data + (0..dlen-1), out + (0..olen-1));
  @ assigns out[0..olen-1];
  @ ensures \initialized(out + (0..olen-1));
*/
void zupt_shake128(const uint8_t *data, size_t dlen, uint8_t *out, size_t olen) {
    zupt_keccak_ctx ctx;
    keccak_init(&ctx, 168, 0x1F); /* SHAKE domain suffix */
    keccak_absorb(&ctx, data, dlen);
    keccak_finalize(&ctx);
    keccak_squeeze(&ctx, out, olen);
}

void zupt_shake128_init(zupt_keccak_ctx *ctx)    { keccak_init(ctx, 168, 0x1F); }
void zupt_shake128_absorb(zupt_keccak_ctx *ctx, const uint8_t *data, size_t len) {
    keccak_absorb(ctx, data, len);
}
void zupt_shake128_finalize(zupt_keccak_ctx *ctx) { keccak_finalize(ctx); }
void zupt_shake128_squeeze(zupt_keccak_ctx *ctx, uint8_t *out, size_t len) {
    keccak_squeeze(ctx, out, len);
}

/* ═══════════════════════════════════════════════════════════════════
 * SHAKE-256: rate=136 bytes (1088 bits)
 * ═══════════════════════════════════════════════════════════════════ */

/* FRAMA-C: SHAKE-256 extendable output function */
/*@ requires \valid_read(data + (0..dlen-1));
  @ requires \valid(out + (0..olen-1));
  @ requires \separated(data + (0..dlen-1), out + (0..olen-1));
  @ assigns out[0..olen-1];
  @ ensures \initialized(out + (0..olen-1));
*/
void zupt_shake256(const uint8_t *data, size_t dlen, uint8_t *out, size_t olen) {
    zupt_keccak_ctx ctx;
    keccak_init(&ctx, 136, 0x1F);
    keccak_absorb(&ctx, data, dlen);
    keccak_finalize(&ctx);
    keccak_squeeze(&ctx, out, olen);
}

void zupt_shake256_init(zupt_keccak_ctx *ctx)    { keccak_init(ctx, 136, 0x1F); }
void zupt_shake256_absorb(zupt_keccak_ctx *ctx, const uint8_t *data, size_t len) {
    keccak_absorb(ctx, data, len);
}
void zupt_shake256_finalize(zupt_keccak_ctx *ctx) { keccak_finalize(ctx); }
void zupt_shake256_squeeze(zupt_keccak_ctx *ctx, uint8_t *out, size_t len) {
    keccak_squeeze(ctx, out, len);
}
