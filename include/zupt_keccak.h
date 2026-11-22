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
 * @cond PORT
 * @file   zupt_keccak.h
 * @brief  Interface pública do sponge Keccak-f[1600]: SHA3-256, SHA3-512,
 * SHAKE-128 e SHAKE-256.
 * @details Este cabeçalho expõe duas primitivas de saída fixa (SHA3-256 e
 * SHA3-512), duas funções de saída estendida (SHAKE-128 e
 * SHAKE-256) e a API (interface de programação de aplicações)
 * incremental correspondente, limitada às variantes SHAKE. Todas
 * operam sobre a mesma permutação
 * Keccak-f[1600] — 25 lanes de 64 bits, 24 rodadas — aplicada
 * na construção em esponja; o que distingue as primitivas é a
 * taxa consumida por iteração da permutação e o sufixo de domínio
 * injetado no padding:
 * - SHA3-256: taxa 136 bytes, capacidade 512 bits, sufixo 0x06;
 * - SHA3-512: taxa 72 bytes, capacidade 1024 bits, sufixo 0x06;
 * - SHAKE-128: taxa 168 bytes, capacidade 256 bits, sufixo 0x1F;
 * - SHAKE-256: taxa 136 bytes, capacidade 512 bits, sufixo 0x1F.
 *
 * A capacidade é o complemento da taxa dentro dos 1600 bits do
 * estado (1600 − 8·taxa) e não aparece como campo explícito do
 * contexto: decorre de `rate`. O sufixo de domínio é a única
 * diferença algorítmica entre a família SHA3 e a família SHAKE
 * nesta implementação; com sufixo e taxa trocados, a mesma
 * máquina interna produziria um valor diferente.
 *
 * Não há alocação dinâmica: as funções de uma passada usam um
 * contexto em pilha de sizeof(zupt_keccak_ctx) bytes (424 no
 * compilador de referência), e a API incremental trabalha sobre o
 * contexto fornecido pelo chamador.
 *
 * Esta interface é a base de hash usada pelo ML-KEM-768 (mecanismo
 * de encapsulamento de chave baseado em redes modulares)
 * implementado em src/zupt_mlkem.c (G e H em SHA3-256/SHA3-512,
 * amostragem e derivação de chave em SHAKE-128/SHAKE-256).
 * @warning O cabeçalho não envolve as declarações com `extern "C"`: quando
 * incluído de uma unidade de tradução C++, os nomes são manglados e
 * a definição compilada como C não é resolvida na ligação.
 * Consumidores C++ existentes devem declarar as funções de que
 * precisam dentro de um bloco `extern "C"` próprio.
 * @warning Nenhuma função deste módulo apaga o estado depois de produzir a
 * saída: chamador que tratar material sensível deve limpar o
 * contexto (ou os buffers de entrada/saída) por outros meios.
 * @see    src/zupt_keccak.c
 * @endcond
 * @cond INGLES
 * @file   zupt_keccak.h
 * @brief  Public interface of the Keccak-f[1600] sponge: SHA3-256, SHA3-512,
 * SHAKE-128 and SHAKE-256.
 * @details This header exposes two fixed-output primitives (SHA3-256 and
 * SHA3-512), two extendable-output functions (SHAKE-128 and
 * SHAKE-256) and the corresponding incremental API (application
 * programming interface), limited to the SHAKE variants. All of them
 * operate on the same permutation,
 * Keccak-f[1600] — 25 lanes of 64 bits, 24 rounds — applied
 * in the sponge construction; what distinguishes the primitives is the
 * rate consumed per permutation iteration and the domain suffix
 * injected into the padding:
 * - SHA3-256: rate 136 bytes, capacity 512 bits, suffix 0x06;
 * - SHA3-512: rate 72 bytes, capacity 1024 bits, suffix 0x06;
 * - SHAKE-128: rate 168 bytes, capacity 256 bits, suffix 0x1F;
 * - SHAKE-256: rate 136 bytes, capacity 512 bits, suffix 0x1F.
 *
 * The capacity is the complement of the rate within the 1600 bits of
 * the state (1600 − 8·rate) and does not appear as an explicit field of
 * the context: it follows from `rate`. The domain suffix is the only
 * algorithmic difference between the SHA3 family and the SHAKE family
 * in this implementation; with the suffix and the rate swapped, the same
 * internal machine would produce a different value.
 *
 * There is no dynamic allocation: the single-pass functions use a
 * stack context of sizeof(zupt_keccak_ctx) bytes (424 in the
 * reference compiler), and the incremental API works on the
 * context provided by the caller.
 *
 * This interface is the hash base used by ML-KEM-768 (the key
 * encapsulation mechanism based on module lattices)
 * implemented in src/zupt_mlkem.c (G and H over SHA3-256/SHA3-512,
 * sampling and key derivation over SHAKE-128/SHAKE-256).
 * @warning The header does not wrap the declarations with `extern "C"`: when
 * included from a C++ translation unit, the names are mangled and
 * the definition compiled as C is not resolved at link time.
 * Existing C++ consumers must declare the functions they
 * need inside their own `extern "C"` block.
 * @warning No function in this module wipes the state after producing the
 * output: a caller handling sensitive material must clear the
 * context (or the input/output buffers) by other means.
 * @see    src/zupt_keccak.c
 * @endcond */
#ifndef ZUPT_KECCAK_H
#define ZUPT_KECCAK_H

#include <stdint.h>
#include <stddef.h>

/**
 * @cond PORT
 * @struct zupt_keccak_ctx
 * @brief  Estado de uma computação em esponja Keccak-f[1600].
 * @details O contexto guarda simultaneamente as 25 lanes do estado interno
 * (`st`), o bloco de bytes em acumulação (`buf`), a taxa em bytes
 * (`rate`), a posição corrente dentro de `buf` (`pt`) e o sufixo de
 * domínio do padding (`dsuf`). `keccak_init()` em src/zupt_keccak.c
 * zera o contexto inteiro e fixa `rate` e `dsuf`; a partir daí
 * `pt` percorre o intervalo [0, rate] e cada vez que atinge `rate`
 * o bloco acumulado é incorporado a `st` (lane a lane, little-endian)
 * e a permutação é aplicada. Durante o squeeze, `pt` passa a
 * representar a posição de leitura dentro da faixa de saída da taxa.
 *
 * `buf` tem 200 bytes — o maior valor de taxa usado por este módulo é
 * 168 — e não é limpo quando um bloco é consumido: os bytes do último
 * bloco absorvido permanecem ali até serem sobrescritos.
 * @note    Nenhum campo é validado por comparação com valores esperados:
 * `rate` deve ser múltiplo de 8 e no máximo 200, e `dsuf` deve
 * corresponder à variante desejada.
 * @endcond
 * @cond INGLES
 * @struct zupt_keccak_ctx
 * @brief  State of a Keccak-f[1600] sponge computation.
 * @details The context holds simultaneously the 25 lanes of the internal
 * state (`st`), the block of bytes being accumulated (`buf`), the rate in bytes
 * (`rate`), the current position inside `buf` (`pt`) and the domain
 * suffix of the padding (`dsuf`). `keccak_init()` in src/zupt_keccak.c
 * zeroes the whole context and sets `rate` and `dsuf`; from then on
 * `pt` walks the range [0, rate] and each time it reaches `rate`
 * the accumulated block is incorporated into `st` (lane by lane, little-endian)
 * and the permutation is applied. During the squeeze, `pt` comes to
 * represent the read position within the rate output range.
 *
 * `buf` is 200 bytes long — the largest rate value used by this module is
 * 168 — and is not wiped when a block is consumed: the bytes of the last
 * absorbed block remain there until they are overwritten.
 * @note    No field is validated by comparison against expected values:
 * `rate` must be a multiple of 8 and at most 200, and `dsuf` must
 * match the desired variant.
 * @endcond */
/* Sponge state: 25 × 64-bit lanes = 200 bytes */
typedef struct {
    /**
     * @cond PORT
     * 25 lanes de 64 bits do estado interno; a endianidade só aparece quando os lanes são lidos ou escritos como bytes.
     * @endcond
     * @cond INGLES
     * 25 lanes of 64 bits of the internal state; endianness only shows up when the lanes are read or written as bytes.
     * @endcond */
    uint64_t st[25];
    /**
     * @cond PORT
     * Bloco corrente em bytes, preenchido até `rate` antes de ser incorporado a `st`.
     * @endcond
     * @cond INGLES
     * Current block in bytes, filled up to `rate` before being incorporated into `st`.
     * @endcond */
    uint8_t  buf[200]; /* absorption buffer */
    /**
     * @cond PORT
     * Taxa, em bytes: quantidade de bytes por bloco (136, 168 ou 72); o restante dos 1600 bits é capacidade.
     * @endcond
     * @cond INGLES
     * Rate, in bytes: number of bytes per block (136, 168 or 72); the remainder of the 1600 bits is capacity.
     * @endcond */
    size_t   rate; /* rate in bytes */
    /**
     * @cond PORT
     * Posição do próximo byte livre em `buf` durante a absorção; durante o squeeze, posição corrente de leitura.
     * @endcond
     * @cond INGLES
     * Position of the next free byte in `buf` during absorption; during the squeeze, the current read position.
     * @endcond */
    size_t   pt; /* position in buf */
    /**
     * @cond PORT
     * Sufixo de domínio colocado no padding: 0x06 para SHA3, 0x1F para SHAKE.
     * @endcond
     * @cond INGLES
     * Domain suffix placed in the padding: 0x06 for SHA3, 0x1F for SHAKE.
     * @endcond */
    uint8_t  dsuf; /* domain suffix: 0x06 for SHA3, 0x1F for SHAKE */
} zupt_keccak_ctx;

/**
 * @cond PORT
 * @brief Calcula o digest SHA3-256 (32 bytes) de `data` em uma única passada.
 * @details Monta um contexto em pilha com taxa 136 bytes e sufixo de domínio
 * 0x06, absorve os `len` bytes, aplica o padding final e extrai 32
 * bytes do estado. Como a saída (32) é menor que a taxa (136), a
 * extração não precisa de permutação adicional após o padding.
 * @param[in]  data Buffer a hashizar; `len` bytes válidos.
 * @param[in]  len  Número de bytes de `data`; 0 produz o digest da mensagem
 * vazia (a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa
 * 82d80a4b80f8434a).
 * @param[out] out  Os 32 bytes do digest.
 * @warning  Nenhum dos dois ponteiros é verificado contra NULL. `out` não
 * deve sobrepor `data` — requisito que a anotação ACSL (ANSI/ISO C
 * Specification Language) `\separated`, adjunta à implementação,
 * descreve.
 * @see      zupt_shake256(), src/zupt_keccak.c
 * @endcond
 * @cond INGLES
 * @brief Computes the SHA3-256 digest (32 bytes) of `data` in a single pass.
 * @details Builds a stack context with rate 136 bytes and domain suffix
 * 0x06, absorbs the `len` bytes, applies the final padding and extracts 32
 * bytes from the state. Since the output (32) is smaller than the rate (136), the
 * extraction does not need an additional permutation after the padding.
 * @param[in]  data Buffer to hash; `len` valid bytes.
 * @param[in]  len  Number of bytes of `data`; 0 produces the digest of the
 * empty message (a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa
 * 82d80a4b80f8434a).
 * @param[out] out  The 32 bytes of the digest.
 * @warning  Neither pointer is checked against NULL. `out` must
 * not overlap `data` — a requirement described by the ACSL (ANSI/ISO C
 * Specification Language) `\separated` annotation attached to the implementation.
 * @see      zupt_shake256(), src/zupt_keccak.c
 * @endcond */
/* SHA3-256: 32-byte output */
void zupt_sha3_256(const uint8_t *data, size_t len, uint8_t out[32]);

/**
 * @cond PORT
 * @brief Calcula o digest SHA3-512 (64 bytes) de `data` em uma única passada.
 * @details Mesma construção de zupt_sha3_256(), porém com taxa 72 bytes
 * (capacidade 1024 bits) e sufixo de domínio 0x06. A saída de 64
 * bytes cabe na taxa, então também não há permutação extra de
 * extração. Por ter a menor taxa deste módulo, uma mensagem de
 * 72 bytes ou mais provoca pelo menos uma permutação durante a
 * absorção.
 * @param[in]  data Buffer a hashizar; `len` bytes válidos.
 * @param[in]  len  Número de bytes de `data`; 0 produz o digest da mensagem
 * vazia (a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859
 * e0d1dcc1475c80a6...).
 * @param[out] out  Os 64 bytes do digest.
 * @warning  Nenhum dos dois ponteiros é verificado contra NULL. `out` não
 * deve sobrepor `data`.
 * @see      zupt_sha3_256(), src/zupt_keccak.c
 * @endcond
 * @cond INGLES
 * @brief Computes the SHA3-512 digest (64 bytes) of `data` in a single pass.
 * @details Same construction as zupt_sha3_256(), but with rate 72 bytes
 * (capacity 1024 bits) and domain suffix 0x06. The 64-byte
 * output fits within the rate, so there is also no extra
 * extraction permutation. Because it has the smallest rate of this module, a
 * message of 72 bytes or more triggers at least one permutation during
 * absorption.
 * @param[in]  data Buffer to hash; `len` valid bytes.
 * @param[in]  len  Number of bytes of `data`; 0 produces the digest of the
 * empty message (a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859
 * e0d1dcc1475c80a6...).
 * @param[out] out  The 64 bytes of the digest.
 * @warning  Neither pointer is checked against NULL. `out` must
 * not overlap `data`.
 * @see      zupt_sha3_256(), src/zupt_keccak.c
 * @endcond */
/* SHA3-512: 64-byte output */
void zupt_sha3_512(const uint8_t *data, size_t len, uint8_t out[64]);

/**
 * @cond PORT
 * @brief Calcula SHAKE-128 sobre `data` e devolve `olen` bytes de saída.
 * @details Função de saída estendida (XOF): taxa 168 bytes e sufixo de
 * domínio 0x1F. Após o padding, os `olen` bytes são lidos do estado
 * e, sempre que a faixa da taxa se esgota, a permutação é aplicada
 * para gerar o próximo trecho — por isso `olen` não tem limite
 * superior além do espaço que o chamador aloca para `out`.
 * @param[in]  data Bytes a absorver; `dlen` bytes válidos.
 * @param[in]  dlen Número de bytes de `data`.
 * @param[out] out  Os `olen` bytes derivados do estado.
 * @param[in]  olen Quantidade de bytes a extrair; pode ser maior que a taxa.
 * @note     O prefixo de 32 bytes da saída de "abc" é
 * 5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8,
 * igual ao valor publicado para SHAKE-128.
 * @warning  Nenhum ponteiro é verificado contra NULL; `out` não deve
 * sobrepor `data`.
 * @see      zupt_shake128_init(), zupt_shake256()
 * @endcond
 * @cond INGLES
 * @brief Computes SHAKE-128 over `data` and returns `olen` bytes of output.
 * @details Extendable-output function (XOF): rate 168 bytes and domain
 * suffix 0x1F. After the padding, the `olen` bytes are read from the state
 * and, whenever the rate range is exhausted, the permutation is applied
 * to generate the next chunk — therefore `olen` has no upper limit
 * beyond the space the caller allocates for `out`.
 * @param[in]  data Bytes to absorb; `dlen` valid bytes.
 * @param[in]  dlen Number of bytes of `data`.
 * @param[out] out  The `olen` bytes derived from the state.
 * @param[in]  olen Number of bytes to extract; it may be larger than the rate.
 * @note     The 32-byte prefix of the output of "abc" is
 * 5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8,
 * equal to the published value for SHAKE-128.
 * @warning  No pointer is checked against NULL; `out` must not
 * overlap `data`.
 * @see      zupt_shake128_init(), zupt_shake256()
 * @endcond */
/* SHAKE-128: extendable output */
void zupt_shake128(const uint8_t *data, size_t dlen, uint8_t *out, size_t olen);

/**
 * @cond PORT
 * @brief Calcula SHAKE-256 sobre `data` e devolve `olen` bytes de saída.
 * @details XOF de taxa 136 bytes (mesma taxa do SHA3-256) e sufixo de
 * domínio 0x1F. O sufixo é o que separa esta primitiva do
 * SHA3-256: com taxa idêntica, o padding diferente produz estados
 * e saídas distintos. A extração repete a permutação a cada
 * 136 bytes consumidos.
 * @param[in]  data Bytes a absorver; `dlen` bytes válidos.
 * @param[in]  dlen Número de bytes de `data`.
 * @param[out] out  Os `olen` bytes derivados do estado.
 * @param[in]  olen Quantidade de bytes a extrair.
 * @note     É a primitiva usada pelo ML-KEM-768 para amostragem de ruído por
 * distribuição binomial centrada (CBD, do inglês centered binomial
 * distribution) e para a derivação do segredo compartilhado.
 * @warning  Nenhum ponteiro é verificado contra NULL; `out` não deve
 * sobrepor `data`.
 * @see      zupt_shake256_init(), zupt_sha3_256()
 * @endcond
 * @cond INGLES
 * @brief Computes SHAKE-256 over `data` and returns `olen` bytes of output.
 * @details XOF with rate 136 bytes (the same rate as SHA3-256) and domain
 * suffix 0x1F. The suffix is what separates this primitive from
 * SHA3-256: with an identical rate, the different padding produces
 * distinct states and outputs. The extraction repeats the permutation every
 * 136 bytes consumed.
 * @param[in]  data Bytes to absorb; `dlen` valid bytes.
 * @param[in]  dlen Number of bytes of `data`.
 * @param[out] out  The `olen` bytes derived from the state.
 * @param[in]  olen Number of bytes to extract.
 * @note     It is the primitive used by ML-KEM-768 for noise sampling by
 * centered binomial distribution (CBD) and for the derivation of the shared
 * secret.
 * @warning  No pointer is checked against NULL; `out` must not
 * overlap `data`.
 * @see      zupt_shake256_init(), zupt_sha3_256()
 * @endcond */
/* SHAKE-256: extendable output */
void zupt_shake256(const uint8_t *data, size_t dlen, uint8_t *out, size_t olen);

/**
 * @cond PORT
 * @brief Prepara o contexto para uma derivação SHAKE-128 incremental.
 * @details Zera o contexto inteiro e fixa taxa 168 bytes e sufixo de domínio
 * 0x1F. É o primeiro passo da sequência init → absorb → finalize →
 * squeeze, usada pelo ML-KEM-768 para gerar o fluxo de bits da
 * amostragem por rejeição.
 * @param[out] ctx Contexto a inicializar.
 * @post `st` e `buf` todo-zero, `pt` igual a 0, `rate` igual a 168 e `dsuf`
 * igual a 0x1F.
 * @note Chamar sobre um contexto já usado reinicia a derivação: o estado é
 * zerado, não retomado.
 * @see      zupt_shake128_absorb(), zupt_shake128_finalize(), zupt_shake128_squeeze()
 * @endcond
 * @cond INGLES
 * @brief Prepares the context for an incremental SHAKE-128 derivation.
 * @details Zeroes the whole context and sets rate 168 bytes and domain suffix
 * 0x1F. It is the first step of the init → absorb → finalize →
 * squeeze sequence, used by ML-KEM-768 to generate the bit stream of
 * rejection sampling.
 * @param[out] ctx Context to initialize.
 * @post `st` and `buf` all-zero, `pt` equal to 0, `rate` equal to 168 and `dsuf`
 * equal to 0x1F.
 * @note Calling it over an already used context restarts the derivation: the state is
 * zeroed, not resumed.
 * @see      zupt_shake128_absorb(), zupt_shake128_finalize(), zupt_shake128_squeeze()
 * @endcond */
/* Incremental SHAKE-128 for ML-KEM sampling */
void zupt_shake128_init(zupt_keccak_ctx *ctx);

/**
 * @cond PORT
 * @brief Acumula mais `len` bytes na derivação SHAKE-128 em andamento.
 * @details Os bytes são copiados para o bloco corrente a partir de `pt`; cada
 * vez que `pt` atinge a taxa (168) o bloco é incorporado ao estado
 * lane a lane (little-endian) e a permutação é aplicada, reiniciando
 * `pt`. Pode ser chamada quantas vezes for necessário, com tamanhos
 * arbitrários; `len` igual a 0 não altera o contexto.
 * @param[in,out] ctx  Contexto já inicializado por zupt_shake128_init().
 * @param[in]     data `len` bytes a absorver.
 * @param[in]     len  Número de bytes de `data`.
 * @note    O bloco consumido não é apagado de `buf`; ele apenas é
 * sobrescrito à medida que novos bytes chegam.
 * @warning `ctx` deve ter sido inicializado: um contexto com `rate` zero faz
 * o cálculo do espaço livre subtrair de um inteiro sem sinal.
 * @see     zupt_shake128_finalize()
 * @endcond
 * @cond INGLES
 * @brief Accumulates another `len` bytes in the SHAKE-128 derivation in progress.
 * @details The bytes are copied into the current block starting at `pt`; each
 * time `pt` reaches the rate (168) the block is incorporated into the state
 * lane by lane (little-endian) and the permutation is applied, resetting
 * `pt`. It can be called as many times as needed, with arbitrary
 * sizes; `len` equal to 0 does not change the context.
 * @param[in,out] ctx  Context already initialized by zupt_shake128_init().
 * @param[in]     data `len` bytes to absorb.
 * @param[in]     len  Number of bytes of `data`.
 * @note    The consumed block is not erased from `buf`; it is only
 * overwritten as new bytes arrive.
 * @warning `ctx` must have been initialized: a context with `rate` zero makes
 * the free-space computation subtract from an unsigned integer.
 * @see     zupt_shake128_finalize()
 * @endcond */
void zupt_shake128_absorb(zupt_keccak_ctx *ctx, const uint8_t *data, size_t len);

/**
 * @cond PORT
 * @brief Aplica o padding final da derivação SHAKE-128, abrindo o squeeze.
 * @details Escreve o sufixo de domínio (0x1F) em `buf[pt]`, preenche o
 * restante do bloco com zeros e põe o bit final em `buf[rate-1]`
 * por OU com 0x80; então incorpora esse último bloco ao estado e
 * aplica a permutação. Depois disto `pt` volta a 0 e a extração
 * começa do início da faixa de saída da taxa.
 * @param[in,out] ctx Contexto com toda a mensagem já absorvida.
 * @post    `pt` igual a 0; o estado contém o bloco de padding já incorporado.
 * @warning Chamar duas vezes, ou chamar com `pt` igual a `rate` (situação em
 * que um squeeze anterior consumiu exatamente um bloco inteiro), não
 * é suportado: o segundo padding recomeça do meio do estado já
 * permutado e, no caso `pt == rate`, o preenchimento de zeros recebe
 * um tamanho calculado como negativo.
 * @see     zupt_shake128_squeeze()
 * @endcond
 * @cond INGLES
 * @brief Applies the final padding of the SHAKE-128 derivation, opening the squeeze.
 * @details Writes the domain suffix (0x1F) into `buf[pt]`, fills the
 * rest of the block with zeros and sets the final bit in `buf[rate-1]`
 * by OR with 0x80; then it incorporates that last block into the state and
 * applies the permutation. After this, `pt` goes back to 0 and extraction
 * starts from the beginning of the rate output range.
 * @param[in,out] ctx Context with the whole message already absorbed.
 * @post    `pt` equal to 0; the state contains the padding block already incorporated.
 * @warning Calling it twice, or calling it with `pt` equal to `rate` (a situation
 * in which a previous squeeze consumed exactly one full block), is not
 * supported: the second padding restarts from the middle of the state
 * already permuted and, in the case `pt == rate`, the zero filling receives
 * a size computed as negative.
 * @see     zupt_shake128_squeeze()
 * @endcond */
void zupt_shake128_finalize(zupt_keccak_ctx *ctx);

/**
 * @cond PORT
 * @brief Extrai `len` bytes do fluxo SHAKE-128 já finalizado.
 * @details Lê os bytes da faixa de saída das lanes (little-endian) a partir
 * de `pt`. Quando `pt` chega a `rate` (168), a permutação é aplicada
 * antes de continuar, de modo que chamadas sucessivas reproduzem o
 * fluxo contínuo do XOF. `len` igual a 0 não escreve nem permuta.
 * @param[in,out] ctx Contexto finalizado por zupt_shake128_finalize().
 * @param[out]    out `len` bytes de saída; pode ser nulo apenas se `len` for 0.
 * @param[in]     len Número de bytes a extrair; não há limite superior, além
 * do espaço disponível em `out`.
 * @note    O squeeze altera o estado: após esgotar a taxa, o bloco seguinte é
 * derivado do estado já permutado, o que é justamente o mecanismo do
 * XOF. Não é possível voltar a absorver depois do squeeze.
 * @see     zupt_shake128()
 * @endcond
 * @cond INGLES
 * @brief Extracts `len` bytes from the SHAKE-128 stream already finalized.
 * @details Reads the bytes from the output range of the lanes (little-endian) starting
 * at `pt`. When `pt` reaches `rate` (168), the permutation is applied
 * before continuing, so successive calls reproduce the continuous
 * stream of the XOF. `len` equal to 0 writes nothing and permutes nothing.
 * @param[in,out] ctx Context finalized by zupt_shake128_finalize().
 * @param[out]    out `len` bytes of output; may be null only if `len` is 0.
 * @param[in]     len Number of bytes to extract; there is no upper limit, apart
 * from the space available in `out`.
 * @note    The squeeze changes the state: after exhausting the rate, the next block is
 * derived from the already permuted state, which is precisely the mechanism of
 * the XOF. It is not possible to absorb again after the squeeze.
 * @see     zupt_shake128()
 * @endcond */
void zupt_shake128_squeeze(zupt_keccak_ctx *ctx, uint8_t *out, size_t len);

/* Incremental SHAKE-256 */
/**
 * @cond PORT
 * @brief Prepara o contexto para uma derivação SHAKE-256 incremental.
 * @details Equivalente a zupt_shake128_init() com taxa 136 bytes; zera o
 * contexto e fixa taxa e sufixo de domínio (0x1F).
 * @param[out] ctx Contexto a inicializar.
 * @post `st` e `buf` todo-zero, `pt` igual a 0, `rate` igual a 136 e `dsuf`
 * igual a 0x1F.
 * @see      zupt_shake256_absorb(), zupt_shake256_finalize(), zupt_shake256_squeeze()
 * @endcond
 * @cond INGLES
 * @brief Prepares the context for an incremental SHAKE-256 derivation.
 * @details Equivalent to zupt_shake128_init() with rate 136 bytes; zeroes the
 * context and sets the rate and the domain suffix (0x1F).
 * @param[out] ctx Context to initialize.
 * @post `st` and `buf` all-zero, `pt` equal to 0, `rate` equal to 136 and `dsuf`
 * equal to 0x1F.
 * @see      zupt_shake256_absorb(), zupt_shake256_finalize(), zupt_shake256_squeeze()
 * @endcond */
void zupt_shake256_init(zupt_keccak_ctx *ctx);

/**
 * @cond PORT
 * @brief Acumula mais `len` bytes na derivação SHAKE-256 em andamento.
 * @details Mesma mecânica de zupt_shake128_absorb(), com a taxa de 136 bytes:
 * bloco cheio é XOR-ado ao estado little-endian e permutado.
 * @param[in,out] ctx  Contexto já inicializado por zupt_shake256_init().
 * @param[in]     data `len` bytes a absorver.
 * @param[in]     len  Número de bytes de `data`; 0 é uma chamada vazia.
 * @warning `ctx` deve ter sido inicializado (ver zupt_shake128_absorb()).
 * @endcond
 * @cond INGLES
 * @brief Accumulates another `len` bytes in the SHAKE-256 derivation in progress.
 * @details Same mechanics as zupt_shake128_absorb(), with the 136-byte rate:
 * a full block is XOR-ed into the state little-endian and permuted.
 * @param[in,out] ctx  Context already initialized by zupt_shake256_init().
 * @param[in]     data `len` bytes to absorb.
 * @param[in]     len  Number of bytes of `data`; 0 is an empty call.
 * @warning `ctx` must have been initialized (see zupt_shake128_absorb()).
 * @endcond */
void zupt_shake256_absorb(zupt_keccak_ctx *ctx, const uint8_t *data, size_t len);

/**
 * @cond PORT
 * @brief Aplica o padding final da derivação SHAKE-256, abrindo o squeeze.
 * @details Padding de sufixo 0x1F com bit final na última posição do bloco,
 * seguido da incorporação do bloco e de uma permutação; `pt` volta
 * a 0.
 * @param[in,out] ctx Contexto com toda a mensagem já absorvida.
 * @post    `pt` igual a 0 e último bloco incorporado ao estado.
 * @warning Não suportado chamar duas vezes, nem chamar com `pt` igual a
 * `rate` (ver o warning correspondente em
 * zupt_shake128_finalize()).
 * @endcond
 * @cond INGLES
 * @brief Applies the final padding of the SHAKE-256 derivation, opening the squeeze.
 * @details Padding with suffix 0x1F and the final bit at the last position of the block,
 * followed by the incorporation of the block and a permutation; `pt` goes
 * back to 0.
 * @param[in,out] ctx Context with the whole message already absorbed.
 * @post    `pt` equal to 0 and the last block incorporated into the state.
 * @warning Calling it twice is not supported, nor calling it with `pt` equal to
 * `rate` (see the corresponding warning in
 * zupt_shake128_finalize()).
 * @endcond */
void zupt_shake256_finalize(zupt_keccak_ctx *ctx);

/**
 * @cond PORT
 * @brief Extrai `len` bytes do fluxo SHAKE-256 já finalizado.
 * @details Lê little-endian a partir de `pt` e permuta o estado cada vez que
 * os 136 bytes da taxa são consumidos, permitindo estender a saída
 * por chamadas sucessivas.
 * @param[in,out] ctx Contexto finalizado por zupt_shake256_finalize().
 * @param[out]    out `len` bytes de saída.
 * @param[in]     len Número de bytes a extrair.
 * @note    `len` igual a 0 não escreve nada e não permuta o estado.
 * @see     zupt_shake256()
 * @endcond
 * @cond INGLES
 * @brief Extracts `len` bytes from the SHAKE-256 stream already finalized.
 * @details Reads little-endian starting at `pt` and permutes the state every time
 * the 136 bytes of the rate are consumed, allowing the output
 * to be extended by successive calls.
 * @param[in,out] ctx Context finalized by zupt_shake256_finalize().
 * @param[out]    out `len` bytes of output.
 * @param[in]     len Number of bytes to extract.
 * @note    `len` equal to 0 writes nothing and does not permute the state.
 * @see     zupt_shake256()
 * @endcond */
void zupt_shake256_squeeze(zupt_keccak_ctx *ctx, uint8_t *out, size_t len);

#endif
