/*
 * Zupt — Backup-oriented compression with AES-256 encryption
 * Copyright (c) 2026 Cristian Cezar Moisés
 * SPDX-License-Identifier: MIT
 *
 * Keccak-f[1600] sponge: SHA3-256, SHA3-512, SHAKE-128, SHAKE-256
 * Required by ML-KEM-768 (FIPS 203).
 * Pure C11, zero dependencies, no dynamic allocation.
 */
/**
 * @file   zupt_keccak.h
 * @brief  Interface pública do sponge Keccak-f[1600]: SHA3-256, SHA3-512,
 *         SHAKE-128 e SHAKE-256.
 * @details Este cabeçalho expõe duas primitivas de saída fixa (SHA3-256 e
 *          SHA3-512), duas funções de saída estendida (SHAKE-128 e
 *          SHAKE-256) e a API (interface de programação de aplicações)
 *          incremental correspondente, limitada às variantes SHAKE. Todas
 *          operam sobre a mesma permutação
 *          Keccak-f[1600] — 25 lanes de 64 bits, 24 rodadas — aplicada
 *          na construção em esponja; o que distingue as primitivas é a
 *          taxa consumida por iteração da permutação e o sufixo de domínio
 *          injetado no padding:
 *          - SHA3-256: taxa 136 bytes, capacidade 512 bits, sufixo 0x06;
 *          - SHA3-512: taxa 72 bytes, capacidade 1024 bits, sufixo 0x06;
 *          - SHAKE-128: taxa 168 bytes, capacidade 256 bits, sufixo 0x1F;
 *          - SHAKE-256: taxa 136 bytes, capacidade 512 bits, sufixo 0x1F.
 *
 *          A capacidade é o complemento da taxa dentro dos 1600 bits do
 *          estado (1600 − 8·taxa) e não aparece como campo explícito do
 *          contexto: decorre de `rate`. O sufixo de domínio é a única
 *          diferença algorítmica entre a família SHA3 e a família SHAKE
 *          nesta implementação; com sufixo e taxa trocados, a mesma
 *          máquina interna produziria um valor diferente.
 *
 *          Não há alocação dinâmica: as funções de uma passada usam um
 *          contexto em pilha de sizeof(zupt_keccak_ctx) bytes (424 no
 *          compilador de referência), e a API incremental trabalha sobre o
 *          contexto fornecido pelo chamador.
 *
 *          Esta interface é a base de hash usada pelo ML-KEM-768 (mecanismo
 *          de encapsulamento de chave baseado em redes modulares)
 *          implementado em src/zupt_mlkem.c (G e H em SHA3-256/SHA3-512,
 *          amostragem e derivação de chave em SHAKE-128/SHAKE-256).
 * @warning O cabeçalho não envolve as declarações com `extern "C"`: quando
 *          incluído de uma unidade de tradução C++, os nomes são manglados e
 *          a definição compilada como C não é resolvida na ligação.
 *          Consumidores C++ existentes devem declarar as funções de que
 *          precisam dentro de um bloco `extern "C"` próprio.
 * @warning Nenhuma função deste módulo apaga o estado depois de produzir a
 *          saída: chamador que tratar material sensível deve limpar o
 *          contexto (ou os buffers de entrada/saída) por outros meios.
 * @see    src/zupt_keccak.c
 */
#ifndef ZUPT_KECCAK_H
#define ZUPT_KECCAK_H

#include <stdint.h>
#include <stddef.h>

/**
 * @struct zupt_keccak_ctx
 * @brief  Estado de uma computação em esponja Keccak-f[1600].
 * @details O contexto guarda simultaneamente as 25 lanes do estado interno
 *          (`st`), o bloco de bytes em acumulação (`buf`), a taxa em bytes
 *          (`rate`), a posição corrente dentro de `buf` (`pt`) e o sufixo de
 *          domínio do padding (`dsuf`). `keccak_init()` em src/zupt_keccak.c
 *          zera o contexto inteiro e fixa `rate` e `dsuf`; a partir daí
 *          `pt` percorre o intervalo [0, rate] e cada vez que atinge `rate`
 *          o bloco acumulado é incorporado a `st` (lane a lane, little-endian)
 *          e a permutação é aplicada. Durante o squeeze, `pt` passa a
 *          representar a posição de leitura dentro da faixa de saída da taxa.
 *
 *          `buf` tem 200 bytes — o maior valor de taxa usado por este módulo é
 *          168 — e não é limpo quando um bloco é consumido: os bytes do último
 *          bloco absorvido permanecem ali até serem sobrescritos.
 * @note    Nenhum campo é validado por comparação com valores esperados:
 *          `rate` deve ser múltiplo de 8 e no máximo 200, e `dsuf` deve
 *          corresponder à variante desejada.
 */
/* Sponge state: 25 × 64-bit lanes = 200 bytes */
typedef struct {
    uint64_t st[25];                   /**< 25 lanes de 64 bits do estado interno; a endianidade só aparece quando os lanes são lidos ou escritos como bytes. */
    uint8_t  buf[200]; /**< Bloco corrente em bytes, preenchido até `rate` antes de ser incorporado a `st`. */ /* absorption buffer */
    size_t   rate;     /**< Taxa, em bytes: quantidade de bytes por bloco (136, 168 ou 72); o restante dos 1600 bits é capacidade. */ /* rate in bytes */
    size_t   pt;       /**< Posição do próximo byte livre em `buf` durante a absorção; durante o squeeze, posição corrente de leitura. */ /* position in buf */
    uint8_t  dsuf;     /**< Sufixo de domínio colocado no padding: 0x06 para SHA3, 0x1F para SHAKE. */ /* domain suffix: 0x06 for SHA3, 0x1F for SHAKE */
} zupt_keccak_ctx;

/**
 * @brief Calcula o digest SHA3-256 (32 bytes) de `data` em uma única passada.
 * @details Monta um contexto em pilha com taxa 136 bytes e sufixo de domínio
 *          0x06, absorve os `len` bytes, aplica o padding final e extrai 32
 *          bytes do estado. Como a saída (32) é menor que a taxa (136), a
 *          extração não precisa de permutação adicional após o padding.
 * @param[in]  data Buffer a hashizar; `len` bytes válidos.
 * @param[in]  len  Número de bytes de `data`; 0 produz o digest da mensagem
 *                  vazia (a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa
 *                  82d80a4b80f8434a).
 * @param[out] out  Os 32 bytes do digest.
 * @warning  Nenhum dos dois ponteiros é verificado contra NULL. `out` não
 *           deve sobrepor `data` — requisito que a anotação ACSL (ANSI/ISO C
 *           Specification Language) `\separated`, adjunta à implementação,
 *           descreve.
 * @see      zupt_shake256(), src/zupt_keccak.c
 */
/* SHA3-256: 32-byte output */
void zupt_sha3_256(const uint8_t *data, size_t len, uint8_t out[32]);

/**
 * @brief Calcula o digest SHA3-512 (64 bytes) de `data` em uma única passada.
 * @details Mesma construção de zupt_sha3_256(), porém com taxa 72 bytes
 *          (capacidade 1024 bits) e sufixo de domínio 0x06. A saída de 64
 *          bytes cabe na taxa, então também não há permutação extra de
 *          extração. Por ter a menor taxa deste módulo, uma mensagem de
 *          72 bytes ou mais provoca pelo menos uma permutação durante a
 *          absorção.
 * @param[in]  data Buffer a hashizar; `len` bytes válidos.
 * @param[in]  len  Número de bytes de `data`; 0 produz o digest da mensagem
 *                  vazia (a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859
 *                  e0d1dcc1475c80a6...).
 * @param[out] out  Os 64 bytes do digest.
 * @warning  Nenhum dos dois ponteiros é verificado contra NULL. `out` não
 *           deve sobrepor `data`.
 * @see      zupt_sha3_256(), src/zupt_keccak.c
 */
/* SHA3-512: 64-byte output */
void zupt_sha3_512(const uint8_t *data, size_t len, uint8_t out[64]);

/**
 * @brief Calcula SHAKE-128 sobre `data` e devolve `olen` bytes de saída.
 * @details Função de saída estendida (XOF): taxa 168 bytes e sufixo de
 *          domínio 0x1F. Após o padding, os `olen` bytes são lidos do estado
 *          e, sempre que a faixa da taxa se esgota, a permutação é aplicada
 *          para gerar o próximo trecho — por isso `olen` não tem limite
 *          superior além do espaço que o chamador aloca para `out`.
 * @param[in]  data Bytes a absorver; `dlen` bytes válidos.
 * @param[in]  dlen Número de bytes de `data`.
 * @param[out] out  Os `olen` bytes derivados do estado.
 * @param[in]  olen Quantidade de bytes a extrair; pode ser maior que a taxa.
 * @note     O prefixo de 32 bytes da saída de "abc" é
 *           5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8,
 *           igual ao valor publicado para SHAKE-128.
 * @warning  Nenhum ponteiro é verificado contra NULL; `out` não deve
 *           sobrepor `data`.
 * @see      zupt_shake128_init(), zupt_shake256()
 */
/* SHAKE-128: extendable output */
void zupt_shake128(const uint8_t *data, size_t dlen, uint8_t *out, size_t olen);

/**
 * @brief Calcula SHAKE-256 sobre `data` e devolve `olen` bytes de saída.
 * @details XOF de taxa 136 bytes (mesma taxa do SHA3-256) e sufixo de
 *          domínio 0x1F. O sufixo é o que separa esta primitiva do
 *          SHA3-256: com taxa idêntica, o padding diferente produz estados
 *          e saídas distintos. A extração repete a permutação a cada
 *          136 bytes consumidos.
 * @param[in]  data Bytes a absorver; `dlen` bytes válidos.
 * @param[in]  dlen Número de bytes de `data`.
 * @param[out] out  Os `olen` bytes derivados do estado.
 * @param[in]  olen Quantidade de bytes a extrair.
 * @note     É a primitiva usada pelo ML-KEM-768 para amostragem de ruído por
 *           distribuição binomial centrada (CBD, do inglês centered binomial
 *           distribution) e para a derivação do segredo compartilhado.
 * @warning  Nenhum ponteiro é verificado contra NULL; `out` não deve
 *           sobrepor `data`.
 * @see      zupt_shake256_init(), zupt_sha3_256()
 */
/* SHAKE-256: extendable output */
void zupt_shake256(const uint8_t *data, size_t dlen, uint8_t *out, size_t olen);

/**
 * @brief Prepara o contexto para uma derivação SHAKE-128 incremental.
 * @details Zera o contexto inteiro e fixa taxa 168 bytes e sufixo de domínio
 *          0x1F. É o primeiro passo da sequência init → absorb → finalize →
 *          squeeze, usada pelo ML-KEM-768 para gerar o fluxo de bits da
 *          amostragem por rejeição.
 * @param[out] ctx Contexto a inicializar.
 * @post `st` e `buf` todo-zero, `pt` igual a 0, `rate` igual a 168 e `dsuf`
 *       igual a 0x1F.
 * @note Chamar sobre um contexto já usado reinicia a derivação: o estado é
 *       zerado, não retomado.
 * @see      zupt_shake128_absorb(), zupt_shake128_finalize(), zupt_shake128_squeeze()
 */
/* Incremental SHAKE-128 for ML-KEM sampling */
void zupt_shake128_init(zupt_keccak_ctx *ctx);

/**
 * @brief Acumula mais `len` bytes na derivação SHAKE-128 em andamento.
 * @details Os bytes são copiados para o bloco corrente a partir de `pt`; cada
 *          vez que `pt` atinge a taxa (168) o bloco é incorporado ao estado
 *          lane a lane (little-endian) e a permutação é aplicada, reiniciando
 *          `pt`. Pode ser chamada quantas vezes for necessário, com tamanhos
 *          arbitrários; `len` igual a 0 não altera o contexto.
 * @param[in,out] ctx  Contexto já inicializado por zupt_shake128_init().
 * @param[in]     data `len` bytes a absorver.
 * @param[in]     len  Número de bytes de `data`.
 * @note    O bloco consumido não é apagado de `buf`; ele apenas é
 *          sobrescrito à medida que novos bytes chegam.
 * @warning `ctx` deve ter sido inicializado: um contexto com `rate` zero faz
 *          o cálculo do espaço livre subtrair de um inteiro sem sinal.
 * @see     zupt_shake128_finalize()
 */
void zupt_shake128_absorb(zupt_keccak_ctx *ctx, const uint8_t *data, size_t len);

/**
 * @brief Aplica o padding final da derivação SHAKE-128, abrindo o squeeze.
 * @details Escreve o sufixo de domínio (0x1F) em `buf[pt]`, preenche o
 *          restante do bloco com zeros e põe o bit final em `buf[rate-1]`
 *          por OU com 0x80; então incorpora esse último bloco ao estado e
 *          aplica a permutação. Depois disto `pt` volta a 0 e a extração
 *          começa do início da faixa de saída da taxa.
 * @param[in,out] ctx Contexto com toda a mensagem já absorvida.
 * @post    `pt` igual a 0; o estado contém o bloco de padding já incorporado.
 * @warning Chamar duas vezes, ou chamar com `pt` igual a `rate` (situação em
 *          que um squeeze anterior consumiu exatamente um bloco inteiro), não
 *          é suportado: o segundo padding recomeça do meio do estado já
 *          permutado e, no caso `pt == rate`, o preenchimento de zeros recebe
 *          um tamanho calculado como negativo.
 * @see     zupt_shake128_squeeze()
 */
void zupt_shake128_finalize(zupt_keccak_ctx *ctx);

/**
 * @brief Extrai `len` bytes do fluxo SHAKE-128 já finalizado.
 * @details Lê os bytes da faixa de saída das lanes (little-endian) a partir
 *          de `pt`. Quando `pt` chega a `rate` (168), a permutação é aplicada
 *          antes de continuar, de modo que chamadas sucessivas reproduzem o
 *          fluxo contínuo do XOF. `len` igual a 0 não escreve nem permuta.
 * @param[in,out] ctx Contexto finalizado por zupt_shake128_finalize().
 * @param[out]    out `len` bytes de saída; pode ser nulo apenas se `len` for 0.
 * @param[in]     len Número de bytes a extrair; não há limite superior, além
 *                    do espaço disponível em `out`.
 * @note    O squeeze altera o estado: após esgotar a taxa, o bloco seguinte é
 *          derivado do estado já permutado, o que é justamente o mecanismo do
 *          XOF. Não é possível voltar a absorver depois do squeeze.
 * @see     zupt_shake128()
 */
void zupt_shake128_squeeze(zupt_keccak_ctx *ctx, uint8_t *out, size_t len);

/* Incremental SHAKE-256 */
/**
 * @brief Prepara o contexto para uma derivação SHAKE-256 incremental.
 * @details Equivalente a zupt_shake128_init() com taxa 136 bytes; zera o
 *          contexto e fixa taxa e sufixo de domínio (0x1F).
 * @param[out] ctx Contexto a inicializar.
 * @post `st` e `buf` todo-zero, `pt` igual a 0, `rate` igual a 136 e `dsuf`
 *       igual a 0x1F.
 * @see      zupt_shake256_absorb(), zupt_shake256_finalize(), zupt_shake256_squeeze()
 */
void zupt_shake256_init(zupt_keccak_ctx *ctx);

/**
 * @brief Acumula mais `len` bytes na derivação SHAKE-256 em andamento.
 * @details Mesma mecânica de zupt_shake128_absorb(), com a taxa de 136 bytes:
 *          bloco cheio é XOR-ado ao estado little-endian e permutado.
 * @param[in,out] ctx  Contexto já inicializado por zupt_shake256_init().
 * @param[in]     data `len` bytes a absorver.
 * @param[in]     len  Número de bytes de `data`; 0 é uma chamada vazia.
 * @warning `ctx` deve ter sido inicializado (ver zupt_shake128_absorb()).
 */
void zupt_shake256_absorb(zupt_keccak_ctx *ctx, const uint8_t *data, size_t len);

/**
 * @brief Aplica o padding final da derivação SHAKE-256, abrindo o squeeze.
 * @details Padding de sufixo 0x1F com bit final na última posição do bloco,
 *          seguido da incorporação do bloco e de uma permutação; `pt` volta
 *          a 0.
 * @param[in,out] ctx Contexto com toda a mensagem já absorvida.
 * @post    `pt` igual a 0 e último bloco incorporado ao estado.
 * @warning Não suportado chamar duas vezes, nem chamar com `pt` igual a
 *          `rate` (ver o warning correspondente em
 *          zupt_shake128_finalize()).
 */
void zupt_shake256_finalize(zupt_keccak_ctx *ctx);

/**
 * @brief Extrai `len` bytes do fluxo SHAKE-256 já finalizado.
 * @details Lê little-endian a partir de `pt` e permuta o estado cada vez que
 *          os 136 bytes da taxa são consumidos, permitindo estender a saída
 *          por chamadas sucessivas.
 * @param[in,out] ctx Contexto finalizado por zupt_shake256_finalize().
 * @param[out]    out `len` bytes de saída.
 * @param[in]     len Número de bytes a extrair.
 * @note    `len` igual a 0 não escreve nada e não permuta o estado.
 * @see     zupt_shake256()
 */
void zupt_shake256_squeeze(zupt_keccak_ctx *ctx, uint8_t *out, size_t len);

#endif
