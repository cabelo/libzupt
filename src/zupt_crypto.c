/*
 * Zupt — Backup-oriented compression with AES-256 encryption
 * Copyright (c) 2026 Cristian Cezar Moisés
 * SPDX-License-Identifier: MIT
 *
 * Cryptographic operations:
 * - HMAC-SHA256, PBKDF2, AES-256-CTR, Encrypt-then-MAC (v0.2+)
 * - Hybrid PQ KEM: ML-KEM-768 + X25519 (v0.7.0)
 *
 * FRAMA-C: ACSL-annotated (v2.0.0)
 */
/**
 * @file  zupt_crypto.c
 * @brief Primitivas de confidencialidade e autenticação da libzupt.
 * @details Este módulo implementa, sobre as primitivas de outros arquivos
 *          (SHA-256, AES-256, Keccak/SHA3, XXH64, ML-KEM-768 e X25519):
 *          - o gerador de bytes aleatórios do sistema operacional usado pela
 *            biblioteca (@ref zupt_random_bytes);
 *          - HMAC-SHA256 (RFC 2104) e PBKDF2-HMAC-SHA256 (RFC 8018);
 *          - o modo CTR do AES-256, com despacho AES-NI/AVX quando a
 *            biblioteca é compilada com `-DZUPT_USE_JASMIN` e o processador
 *            oferece as instruções, e com caminho portátil em C por tabela
 *            S-box nos demais casos;
 *          - o envelope Encrypt-then-MAC por bloco (@ref zupt_encrypt_buffer,
 *            @ref zupt_decrypt_buffer), que cifra com AES-256-CTR e autentica
 *            `nonce || texto cifrado` com HMAC-SHA256;
 *          - a derivação de chave por senha (@ref zupt_derive_keys), que
 *            produz @ref zupt_keyring_t a partir de senha, salt e nonce base;
 *          - o KEM híbrido pós-quântico ML-KEM-768 + X25519 (v0.7.0), com
 *            geração/exportação de chaves no formato "ZKEY" e os núcleos de
 *            encapsulamento e decapsulamento usados pelos arquivadores.
 *
 *          Tamanhos fixos usados neste arquivo: chave AES 32 bytes
 *          (ZUPT_AES_KEY_SIZE), nonce 16 bytes (ZUPT_NONCE_SIZE), MAC
 *          32 bytes (ZUPT_HMAC_SIZE), salt 32 bytes (ZUPT_SALT_SIZE), bloco
 *          AES 16 bytes, cabeçalho de envelope híbrido 1137 bytes.
 *
 *          As anotações ACSL do Frama-C são comentários de verificação formal
 *          em blocos próprios (`/*&#42;@ ... &#42;/`) e não alteram o código
 *          compilado.
 * @warning Não há garantia de tempo constante neste arquivo como um todo.
 *          Onde o código afirma tal propriedade, o mecanismo está indicado no
 *          comentário da função (por exemplo acumulação XOR sem saída
 *          antecipada, ou primitiva gerada pelo Jasmin).
 * @see docs/FORMAT.md, include/zupt.h, include/zupt_cxx.h,
 *      include/zupt_jasmin.h, include/zupt_cpuid.h
 */
/**
 * @def    _GNU_SOURCE
 * @brief  Ativa as extensões GNU da libc neste arquivo.
 * @details É a primeira linha de código do arquivo, como exige a libc: a
 *          macro precisa estar definida antes de qualquer inclusão de cabeçalho para
 *          que os cabeçalhos exponham as interfaces não padronizadas. Ela é
 *          necessária para o uso de funções de tempo/monotônico e para as
 *          variantes de manipulação de memória disponíveis apenas sob o
 *          modo GNU; sem ela, a compilação pode reprovar a vinculação.
 * @note    Definida por este arquivo, e não pelo sistema de build. */
#define _GNU_SOURCE
#include "zupt.h"
#include "zupt_acsl.h"
#include "zupt_cxx.h"
#include "zupt_jasmin.h"
#include "zupt_cpuid.h"  /* JASMIN-VERIFIED: AES-NI dispatch */
#include <stdlib.h>
#include <string.h>
#include <time.h>
#if defined(__linux__)
  #include <sys/syscall.h>
  #include <unistd.h>
#endif
#if !defined(_WIN32)
  #include <fcntl.h>
  #include <sys/stat.h>
  #include <unistd.h>
#endif

/* ═══════════════════════════════════════════════════════════════════
 * RANDOM BYTES (OS-native CSPRNG — NO FALLBACK)
 *
 * If the OS CSPRNG is unavailable, this aborts. Using rand() would
 * make salt/nonce predictable and destroy all security guarantees.
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * @brief Preenche `buf` com `len` bytes obtidos do CSPRNG do sistema.
 * @details Não existe alternativa derivada de `rand()`: quando nenhuma fonte
 *          de entropia do sistema operacional responde, a função escreve em
 *          `stderr` e encerra o processo com `exit(1)`, porque salt e nonce
 *          previsíveis invalidariam as garantias do restante da biblioteca.
 *
 *          Ramos, na ordem em que são tentados:
 *          - `_WIN32`: carrega `advapi32.dll` com `LoadLibraryA` e resolve
 *            `SystemFunction036` (RtlGenRandom). Se a DLL carrega, a função
 *            resolve e RtlGenRandom retorna sucesso para o intervalo pedido,
 *            a DLL é liberada com `FreeLibrary` e a função retorna. Se a DLL
 *            carrega mas a função não resolve, ou RtlGenRandom falha, a DLL é
 *            liberada e o fluxo continua para o encerramento fatal; se a DLL
 *            não carrega, vai direto ao encerramento fatal.
 *          - `_WIN32` não definido e `__linux__` e `SYS_getrandom` definidos:
 *            tenta `syscall(SYS_getrandom, buf, len, 0)` com flags 0 (bloqueia
 *            até o entropiador estar inicializado). O resultado só é aceito
 *            quando `r == len`, isto é, quando o sistema entregou os
 *            `len` bytes de uma vez; qualquer outro resultado (erro parcial ou
 *            completo) segue para o próximo ramo.
 *          - Fonte final fora de `_WIN32`: abre `/dev/urandom` em modo binário
 *            e lê `len` bytes com `fread`. Aceita apenas se `fread` devolve
 *            exatamente `len`; caso contrário cai no encerramento fatal.
 *
 * @note No ramo Linux, quando `SYS_getrandom` falha de forma parcial, os
 *       bytes já escritos em `buf` permanecem e são sobrescritos pelo
 *       `fread` de `/dev/urandom`.
 * @param[out] buf Buffer de destino com `len` bytes graváveis.
 * @param[in]  len Quantidade de bytes aleatórios desejada. O tipo de `len` é
 *                `size_t`; no ramo Windows é convertido para `ULONG` e no
 *                ramo Linux é comparado com o `ssize_t` retornado pelo
 *                syscall.
 * @pre `buf` é ponteiro válido para `len` bytes graváveis.
 * @post Em retorno normal, todos os `len` bytes de `buf` foram escritos pela
 *       fonte aceita.
 * @warning A função nunca retorna erro: a falha da fonte termina o processo.
 *          Com `len == 0`, um `syscall` bem-sucedido devolve 0 e a função
 *          retorna sem escrever nada; em `/dev/urandom`, `fread` com `len == 0`
 *          também devolve 0 e o retorno acontece sem escrita.
 * @see zupt_derive_keys, zupt_hybrid_keygen, hybrid_encrypt_core
 */
void zupt_random_bytes(uint8_t *buf, size_t len) {
#ifdef _WIN32
    /* Windows: RtlGenRandom (SystemFunction036) */
    HMODULE lib = LoadLibraryA("advapi32.dll");
    if (lib) {
        typedef BOOLEAN(WINAPI *RtlGenRandomFunc)(PVOID, ULONG);
        RtlGenRandomFunc fn = (RtlGenRandomFunc)(void(*)(void))GetProcAddress(lib, "SystemFunction036");
        if (fn && fn(buf, (ULONG)len)) { FreeLibrary(lib); return; }
        FreeLibrary(lib);
    }
    fprintf(stderr, "FATAL: Windows CSPRNG (RtlGenRandom) unavailable.\n");
    exit(1);
#else
    /* Linux/macOS/BSD: try getrandom(2) first, then /dev/urandom */
  #if defined(__linux__)
    #if defined(SYS_getrandom)
    ssize_t r = syscall(SYS_getrandom, buf, len, 0);
    if (r == (ssize_t)len) return;
    #endif
  #endif
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        size_t r = fread(buf, 1, len, f);
        fclose(f);
        if (r == len) return;
    }
    fprintf(stderr, "FATAL: /dev/urandom unavailable. Cannot generate secure random bytes.\n");
    exit(1);
#endif
}

/* ═══════════════════════════════════════════════════════════════════
 * HMAC-SHA256 (RFC 2104)
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * @brief Calcula HMAC-SHA256 de `data` com a chave `key` (RFC 2104).
 * @details Constrói `inner = SHA-256(ipad || data)` e
 *          `mac = SHA-256(opad || inner)`, onde ipad e opad são a chave
 *          tratada, estendida com zeros até 64 bytes e XOR com `0x36` e
 *          `0x5c` respectivamente.
 *
 *          Quando `klen > 64`, a chave é substituída pelo seu SHA-256 (32
 *          bytes) antes de montar os pads, conforme a RFC. A chave original
 *          não é alterada: o parâmetro local `key` passa a apontar para o
 *          digest em pilha `k_hash`.
 *
 *          Os buffers `k_pad` (64), `inner` (32) e `k_hash` (32) são limpos
 *          com @ref zupt_secure_wipe antes do retorno. `k_hash` é limpo mesmo
 *          quando `klen <= 64` e ele nunca foi escrito.
 * @param[in]  key  Chave do MAC, de `klen` bytes legíveis.
 * @param[in]  klen Comprimento da chave, em bytes. A restrição ACSL admite
 *                  até 256 bytes; quando `klen > 64` o valor é reduzido a 32
 *                  após o pré-hash.
 * @param[in]  data Mensagem autenticada, de `dlen` bytes legíveis.
 * @param[in]  dlen Comprimento da mensagem, em bytes.
 * @param[out] mac  Digest de saída; exatamente 32 bytes são escritos.
 * @note `key` e `data` devem ser disjuntos de `mac`, conforme as cláusulas
 *       `\separated` da anotação ACSL adjunta; `mac` pode coincidir com um
 *       buffer distinto do de entrada e não é lido pela função.
 * @post Os 32 bytes de `mac` ficam inicializados; nenhum outro objeto é
 *       modificado.
 * @see zupt_sha256, zupt_pbkdf2_sha256, zupt_encrypt_buffer,
 *      zupt_decrypt_buffer
 */
/* FRAMA-C: HMAC-SHA256 (RFC 2104) */
/*@ requires klen <= 256;
  @ requires \valid_read(key + (0..klen-1));
  @ requires \valid_read(data + (0..dlen-1));
  @ requires \valid(mac + (0..31));
  @ requires \separated(key + (0..klen-1), mac + (0..31));
  @ requires \separated(data + (0..dlen-1), mac + (0..31));
  @ assigns mac[0..31];
  @ ensures \initialized(mac + (0..31));
*/
void zupt_hmac_sha256(const uint8_t *key, size_t klen,
                      const uint8_t *data, size_t dlen,
                      uint8_t mac[32]) {
    uint8_t k_pad[64];
    uint8_t k_hash[32];

    /* If key > 64 bytes, hash it first */
    if (klen > 64) {
        zupt_sha256(key, klen, k_hash);
        key = k_hash; klen = 32;
    }

    /* ipad = key XOR 0x36 */
    memset(k_pad, 0x36, 64);
    for (size_t i = 0; i < klen; i++) k_pad[i] ^= key[i];

    /* inner = SHA256(ipad || data) */
    zupt_sha256_ctx ctx;
    zupt_sha256_init(&ctx);
    zupt_sha256_update(&ctx, k_pad, 64);
    zupt_sha256_update(&ctx, data, dlen);
    uint8_t inner[32];
    zupt_sha256_final(&ctx, inner);

    /* opad = key XOR 0x5c */
    memset(k_pad, 0x5c, 64);
    for (size_t i = 0; i < klen; i++) k_pad[i] ^= key[i];

    /* mac = SHA256(opad || inner) */
    zupt_sha256_init(&ctx);
    zupt_sha256_update(&ctx, k_pad, 64);
    zupt_sha256_update(&ctx, inner, 32);
    zupt_sha256_final(&ctx, mac);

    /* Wipe sensitive data */
    zupt_secure_wipe(k_pad, 64);
    zupt_secure_wipe(inner, 32);
    zupt_secure_wipe(k_hash, 32);
}

/* ═══════════════════════════════════════════════════════════════════
 * PBKDF2-HMAC-SHA256 (RFC 8018)
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * @brief Deriva `olen` bytes com PBKDF2-HMAC-SHA256 (RFC 8018).
 * @details Para cada número de bloco `i` (começando em 1), calcula
 *          `U_1 = HMAC-SHA256(pw, salt || INT_32_BE(i))` e encadeia
 *          `U_j = HMAC-SHA256(pw, U_{j-1})` por mais `iterations - 1` passos,
 *          acumulando `T_i = U_1 XOR U_2 XOR ... XOR U_iterations`. Os bytes
 *          de `T_1`, `T_2`, ... são concatenados e truncados a `olen`, que é
 *          escrito em `output`.
 *
 *          O bloco de entrada do HMAC é montado em `salt_block` (256 bytes em
 *          pilha): primeiro `effective_slen` bytes de `salt`, depois os 4
 *          bytes de `block_num` em big-endian. Apenas os primeiros
 *          `effective_slen + 4` bytes são lidos pelo HMAC.
 *
 *          `effective_slen` é `slen` limitado a 252. A limitação existe para
 *          caber em `salt_block` (252 + 4 = 256); bytes de salt além de 252
 *          são ignorados silenciosamente, sem erro. A própria biblioteca
 *          sempre passa ZUPT_SALT_SIZE (32), e o contrato ACSL exige
 *          `slen <= 252`, de modo que o clamp é uma rede de segurança.
 *
 *          Por bloco derivado, `u` (32), `t` (32) e `salt_block` (256) são
 *          limpos com @ref zupt_secure_wipe ao fim da iteração.
 * @param[in]  pw       Senha (ou segredo prévio) de `pwlen` bytes legíveis.
 * @param[in]  pwlen    Comprimento da senha, em bytes. `zupt_derive_keys`
 *                      passa `strlen(pw)`, o que descarta um NUL interno.
 * @param[in]  salt     Salt de `slen` bytes legíveis.
 * @param[in]  slen     Comprimento do salt, em bytes. Valores acima de 252
 *                      são truncados para 252.
 * @param[in]  iterations Número de iterações do laço XOR. Deve ser >= 1; com
 *                        1, `T_1 = U_1` e o laço interno não executa.
 * @param[out] output   Destino dos bytes derivados, com `olen` bytes graváveis.
 * @param[in]  olen     Comprimento desejado, em bytes. O contrato ACSL exige
 *                      `0 < olen <= 64`, o que corresponde a no máximo dois
 *                      blocos de 32 bytes.
 * @pre `iterations >= 1`. A função não valida o valor em tempo de execução.
 * @post Os `olen` bytes de `output` ficam inicializados; o restante do buffer
 *       não é tocado.
 * @note O custo cresce linearmente com `iterations` (duas primitivas HMAC por
 *       passo, e cada HMAC executa dois SHA-256). O padrão da biblioteca é
 *       ZUPT_KDF_ITERATIONS (600000).
 * @see zupt_hmac_sha256, zupt_derive_keys, ZUPT_KDF_ITERATIONS
 */
/* FRAMA-C: PBKDF2-HMAC-SHA256 (RFC 8018) */
/*@ requires pwlen <= 256;
  @ requires slen <= 252;
  @ requires olen > 0 && olen <= 64;
  @ requires iterations >= 1;
  @ requires \valid_read(pw + (0..pwlen-1));
  @ requires \valid_read(salt + (0..slen-1));
  @ requires \valid(output + (0..olen-1));
  @ assigns output[0..olen-1];
  @ ensures \initialized(output + (0..olen-1));
*/
void zupt_pbkdf2_sha256(const uint8_t *pw, size_t pwlen,
                        const uint8_t *salt, size_t slen,
                        uint32_t iterations,
                        uint8_t *output, size_t olen) {
    /* Clamp salt length to fit in the stack buffer.
     * ZUPT always passes ZUPT_SALT_SIZE (32) so this is a safety net. */
    size_t effective_slen = slen;
    if (effective_slen > 252) effective_slen = 252;

    uint32_t block_num = 1;
    size_t pos = 0;

    while (pos < olen) {
        /* U_1 = HMAC(pw, salt || INT_32_BE(block_num)) */
        uint8_t salt_block[256];
        memcpy(salt_block, salt, effective_slen);
        salt_block[effective_slen+0] = (uint8_t)(block_num >> 24);
        salt_block[effective_slen+1] = (uint8_t)(block_num >> 16);
        salt_block[effective_slen+2] = (uint8_t)(block_num >> 8);
        salt_block[effective_slen+3] = (uint8_t)(block_num);

        uint8_t u[32], t[32];
        zupt_hmac_sha256(pw, pwlen, salt_block, effective_slen + 4, u);
        memcpy(t, u, 32);

        /* U_2 .. U_c: XOR chain */
        for (uint32_t i = 1; i < iterations; i++) {
            zupt_hmac_sha256(pw, pwlen, u, 32, u);
            for (int j = 0; j < 32; j++) t[j] ^= u[j];
        }

        /* Copy to output */
        size_t chunk = olen - pos;
        if (chunk > 32) chunk = 32;
        memcpy(output + pos, t, chunk);
        pos += chunk;
        block_num++;

        /* Wipe per-block intermediates */
        zupt_secure_wipe(u, 32);
        zupt_secure_wipe(t, 32);
        zupt_secure_wipe(salt_block, sizeof(salt_block));
    }
}

/* ═══════════════════════════════════════════════════════════════════
 * AES-256-CTR MODE
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * @brief Cifra (ou decifra) `len` bytes em modo AES-256-CTR.
 * @details CTR é um modo de fluxo simétrico: para cada bloco, gera-se a
 *          keystream `AES-256-ECB(key, counter)` e faz-se XOR com os dados.
 *          Por isso a mesma função serve para cifrar e para decifrar.
 *
 *          O bloco de contagem inicial é uma cópia dos 16 bytes de `nonce`.
 *          A cada bloco processado, a contagem é incrementada em big-endian
 *          apenas nos bytes 8..15: o carry pode propagar de 15 até 8, mas
 *          nunca toca os bytes 0..7. O campo de contagem efetivo é de 64 bits
 *          e, ao estourar, volta ao valor inicial — a keystream passaria a se
 *          repetir.
 *
 *          Despacho (em tempo de execução, não de compilação):
 *          - Sob `-DZUPT_USE_JASMIN`, quando `zupt_cpu.has_aesni &&
 *            zupt_cpu.has_avx` são ambos verdadeiros, usa as primitivas
 *            assembly geradas pelo Jasmin:
 *            * blocos completos (>= 4): processados em pipeline de 4 por
 *              `zupt_aes256_ctr4`, que atualiza `counter` in-place;
 *            * os 0 a 3 blocos completos restantes, um a um por
 *              `zupt_aes256_blk`, com o incremento manual de contador
 *              descrito acima;
 *            * a cauda de 1 a 15 bytes: é copiada para um bloco de 16 bytes
 *              zerado, cifrada por `zupt_aes256_blk`, e só os
 *              `tail_bytes` primeiros bytes do resultado vão para `out`.
 *              Os temporários e o contador são limpos com
 *              @ref zupt_secure_wipe e a função retorna.
 *            Os dois flags são exigidos porque o assembly usa codificação VEX
 *            (vaesenc, vmovdqu, vpxor), que requer AVX além de AES-NI, e
 *            suporte do sistema operacional ao estado YMM; testar apenas
 *            AES-NI produziria SIGILL num processador com AES-NI sem AVX.
 *            Quando qualquer dos flags é zero, o controle cai no caminho
 *            portátil abaixo.
 *          - Caminho portátil (sem `-DZUPT_USE_JASMIN`, ou dispatch recusado):
 *            expande as rodadas uma vez com @ref zupt_aes256_init e, em laço
 *            por bloco, chama @ref zupt_aes256_encrypt_block sobre `counter`
 *            escrevendo `keystream`, XORa `chunk` bytes (até 16) com a entrada
 *            e incrementa o contador. A cauda é tratada pelo próprio laço,
 *            que limita `chunk` ao que resta, sem estender o buffer.
 *
 *          No fim de ambos os caminhos, os materiais intermediários
 *          (`ctx`, `counter`, `keystream`, temporários da cauda) são limpos
 *          com @ref zupt_secure_wipe.
 * @param[in]  key   Chave AES-256 (32 bytes legíveis).
 * @param[in]  nonce Vetor de inicialização/contagem inicial (16 bytes
 *                   legíveis). Deve ser único por (chave, fluxo).
 * @param[in]  in    Dados de entrada, `len` bytes legíveis.
 * @param[out] out   Dados de saída, `len` bytes graváveis.
 * @param[in]  len   Comprimento dos dados, em bytes. `len == 0` faz o laço
 *                   portátil não executar e não escreve nada.
 * @pre Os buffers `in` e `out` são disjuntos, conforme a cláusula
 *      `\separated` da anotação ACSL adjunta; cifra em lugar (in-place) não é
 *      coberta pelo contrato.
 * @post Os `len` bytes de `out` ficam inicializados.
 * @note Sob `-DZUPT_USE_JASMIN` a escolha do caminho depende da instância
 *       global `zupt_cpu` (declarada em include/zupt_cpuid.h). Nesta revisão
 *       do repositório o cabeçalho não define a variável nem
 *       `zupt_detect_cpu`, de modo que um vínculo que não as forneça lê zeros
 *       e o dispatch escolhe o caminho portátil.
 * @warning Os comentários de include/zupt_jasmin.h afirmam verificação de
 *          tempo constante pelo Jasmin para as primitivas assembly; essa
 *          garantia refere-se ao assembly gerado, não a este wrapper, que tem
 *          ramificações dependentes do comprimento (pipeline de 4, cauda).
 * @see zupt_aes256_init, zupt_aes256_encrypt_block, zupt_aes256_ctr4,
 *      zupt_aes256_blk, zupt_cpu
 */
/* FRAMA-C: AES-256-CTR stream cipher */
/*@ requires \valid_read(key + (0..31));
  @ requires \valid_read(nonce + (0..15));
  @ requires \valid_read(in + (0..len-1));
  @ requires \valid(out + (0..len-1));
  @ requires \separated(in + (0..len-1), out + (0..len-1));
  @ assigns out[0..len-1];
  @ ensures \initialized(out + (0..len-1));
*/
void zupt_aes256_ctr(const uint8_t key[32], const uint8_t nonce[16],
                     const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t counter[16], keystream[16];
    memcpy(counter, nonce, 16);

#ifdef ZUPT_USE_JASMIN
    /* JASMIN-VERIFIED: AES-NI path — constant-time, no T-table leakage.
     * The Jasmin-generated assembly uses VEX-encoded instructions (vaesenc,
     * vmovdqu, vpxor, etc.) which require BOTH AES-NI AND AVX support.
     * Checking only has_aesni would SIGILL on CPUs with AES-NI but no AVX,
     * or where the OS hasn't enabled XSAVE for YMM state. */
    if (zupt_cpu.has_aesni && zupt_cpu.has_avx) {
        size_t full_blocks = len / 16;
        size_t tail_bytes = len % 16;

        if (full_blocks >= 4) {
            /* 4-block pipeline: processes 4 blocks per iteration */
            size_t pipe_blocks = (full_blocks / 4) * 4;
            zupt_aes256_ctr4(out, in, key, counter, pipe_blocks);
            size_t pipe_bytes = pipe_blocks * 16;
            in += pipe_bytes;
            out += pipe_bytes;
            full_blocks -= pipe_blocks;
        }

        /* Remaining 0-3 full blocks: single-block path */
        size_t pos = 0;
        for (size_t b = 0; b < full_blocks; b++) {
            zupt_aes256_blk(out + pos, in + pos, key, counter);
            pos += 16;
            /* Increment counter (big-endian, last 8 bytes) */
            for (int i = 15; i >= 8; i--) {
                if (++counter[i] != 0) break;
            }
        }
        in += pos;
        out += pos;

        /* Tail: partial last block */
        if (tail_bytes > 0) {
            uint8_t tmp_in[16], tmp_out[16];
            memset(tmp_in, 0, 16);
            memcpy(tmp_in, in, tail_bytes);
            zupt_aes256_blk(tmp_out, tmp_in, key, counter);
            memcpy(out, tmp_out, tail_bytes);
            zupt_secure_wipe(tmp_in, 16);
            zupt_secure_wipe(tmp_out, 16);
        }

        zupt_secure_wipe(counter, 16);
        zupt_secure_wipe(keystream, 16);
        return;
    }
#endif

    /* C table-based fallback */
    zupt_aes256_ctx ctx;
    zupt_aes256_init(&ctx, key);

    size_t pos = 0;
    while (pos < len) {
        zupt_aes256_encrypt_block(&ctx, counter, keystream);

        size_t chunk = len - pos;
        if (chunk > 16) chunk = 16;
        for (size_t i = 0; i < chunk; i++)
            out[pos + i] = in[pos + i] ^ keystream[i];
        pos += chunk;

        /* Increment counter (big-endian, last 8 bytes) */
        for (int i = 15; i >= 8; i--) {
            if (++counter[i] != 0) break;
        }
    }

    zupt_secure_wipe(&ctx, sizeof(ctx));
    zupt_secure_wipe(keystream, 16);
}

/* ═══════════════════════════════════════════════════════════════════
 * KEY DERIVATION
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * @brief Monta um @ref zupt_keyring_t derivando chave de cifra e chave de MAC
 *        de uma senha com PBKDF2-HMAC-SHA256.
 * @details Ordem das operações:
 *          1. `kr->canary_head` e `kr->canary_tail` recebem ZUPT_CANARY
 *             (0xDEADCAFEBABEFACEULL), reescrevendo os canários existentes.
 *          2. `kr->salt` recebe os 32 bytes de `salt`, `kr->base_nonce`
 *             recebe os 16 bytes de `nonce`, `kr->iterations` recebe
 *             `iterations` e `kr->active` passa a 1.
 *          3. Deriva 64 bytes com @ref zupt_pbkdf2_sha256 sobre
 *             `strlen(pw)` bytes da senha e os 32 bytes de `salt`, por
 *             `iterations` iterações; os 32 primeiros bytes vão para
 *             `kr->enc_key` e os 32 seguintes para `kr->mac_key`.
 *          4. Limpa o material derivado em pilha com @ref zupt_secure_wipe.
 *          5. Chama @ref zupt_mlock_keys sobre `enc_key` (ZUPT_AES_KEY_SIZE)
 *             e `mac_key` (ZUPT_HMAC_SIZE) para tentar impedir que as páginas
 *             sejam trocadas para disco. O retorno é ignorado: em falha, a
 *             função chamada emite um aviso em `stderr` e a derivação continua
 *             normalmente.
 *
 *          A senha é tratada como string terminada em NUL: o comprimento
 *             usado no PBKDF2 é `strlen(pw)`, então bytes após um NUL
 *             interno não entram na derivação.
 *
 *          `nonce` não entra na derivação de chave: o PBKDF2 recebe apenas
 *          senha e salt. Ele é copiado para `kr->base_nonce`, que serve de
 *          base para o nonce por bloco em @ref zupt_encrypt_buffer.
 * @param[out] kr        Keyring a preencher. Depois do retorno,
 *                       `active == 1` e os canários valem ZUPT_CANARY.
 * @param[in]  pw        Senha, como string terminada em NUL de até 255
 *                       caracteres (limite do contrato ACSL).
 * @param[in]  salt      Salt da derivação: 32 bytes legíveis (ZUPT_SALT_SIZE).
 * @param[in]  nonce     Nonce base: 16 bytes legíveis (ZUPT_NONCE_SIZE).
 * @param[in]  iterations Custo de PBKDF2. `iterations >= 1` é exigência do
 *                        contrato ACSL e do contrato de
 *                        @ref zupt_pbkdf2_sha256, não verificada em execução.
 * @post `kr->enc_key`, `kr->mac_key`, `kr->salt`, `kr->base_nonce`,
 *       `kr->iterations` e `kr->active` foram escritos.
 * @note Os canários são reescritos sem verificar os valores anteriores, e o
 *       keyring não é zerado: campos que existiam antes permanecem.
 * @see zupt_pbkdf2_sha256, zupt_keyring_init, zupt_keyring_check,
 *      zupt_mlock_keys, ZUPT_KDF_ITERATIONS
 */
/* FRAMA-C: Key derivation from password + salt */
/*@ requires \valid(kr);
  @ requires \valid_read(salt + (0..31));
  @ requires \valid_read(nonce + (0..15));
  @ requires strlen(pw) <= 255;
  @ requires iterations >= 1;
  @ assigns kr->enc_key[0..31], kr->mac_key[0..31], kr->salt[0..31],
  @         kr->base_nonce[0..15], kr->iterations, kr->active;
  @ ensures kr->active == 1;
*/
void zupt_derive_keys(zupt_keyring_t *kr, const char *pw,
                      const uint8_t salt[32], const uint8_t nonce[16],
                      uint32_t iterations) {
    /* Init canaries if not already set */
    kr->canary_head = ZUPT_CANARY;
    kr->canary_tail = ZUPT_CANARY;

    memcpy(kr->salt, salt, ZUPT_SALT_SIZE);
    memcpy(kr->base_nonce, nonce, ZUPT_NONCE_SIZE);
    kr->iterations = iterations;
    kr->active = 1;

    /* Derive 64 bytes: 32 enc_key + 32 mac_key */
    uint8_t material[64];
    zupt_pbkdf2_sha256((const uint8_t *)pw, strlen(pw),
                       salt, ZUPT_SALT_SIZE,
                       iterations, material, 64);
    memcpy(kr->enc_key, material, 32);
    memcpy(kr->mac_key, material + 32, 32);

    zupt_secure_wipe(material, 64);

    /* Lock key material in RAM — prevent swap to disk */
    zupt_mlock_keys(kr->enc_key, ZUPT_AES_KEY_SIZE);
    zupt_mlock_keys(kr->mac_key, ZUPT_HMAC_SIZE);
}

/* ═══════════════════════════════════════════════════════════════════
 * ENCRYPT-THEN-MAC
 *
 * Output format: [16-byte per-block nonce] [ciphertext] [32-byte HMAC]
 * The HMAC covers the nonce and ciphertext.
 * Per-block nonce = base_nonce XOR (block_seq as LE 8 bytes in low half)
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * @brief Cifra um bloco de dados e produz o envelope Encrypt-then-MAC.
 * @details Ordem exata das operações, que define o que é autenticado:
 *          1. Calcula o tamanho do pacote `*olen = 16 + plen + 32`
 *             (ZUPT_NONCE_SIZE + texto cifrado + ZUPT_HMAC_SIZE) e aloca o
 *             buffer com `malloc`. Se a alocação falhar, devolve NULL e
 *             `*olen` já foi escrita.
 *          2. Deriva o nonce do bloco: copia os 16 bytes de
 *             `kr->base_nonce` e XORa os 8 bytes mais baixos (índices 0..7)
 *             com `block_seq` em little-endian. Os bytes 8..15 permanecem
 *             iguais ao nonce base.
 *          3. Grava o nonce do bloco em `pkg[0..15]`.
 *          4. Cifra com @ref zupt_aes256_ctr usando `kr->enc_key` e esse
 *             nonce, escrevendo o texto cifrado em `pkg + 16`.
 *          5. Calcula, com @ref zupt_hmac_sha256 e `kr->mac_key`
 *             (ZUPT_HMAC_SIZE bytes), o MAC sobre `pkg[0 .. 16+plen-1]`, isto
 *             é, `nonce || texto cifrado`, e o grava em `pkg + 16 + plen`.
 *
 *          A cifra acontece antes do MAC (Encrypt-then-MAC), e o HMAC cobre o
 *          nonce: um nonce alterado é detectado. O valor de `block_seq` em si
 *          não é autenticado como campo separado — ele é recuperado do nonce
 *          gravado, e @ref zupt_decrypt_buffer confere esse nonce contra o
 *          `block_seq` esperado.
 * @param[in]  kr        Keyring ativo, com `enc_key`, `mac_key` e
 *                       `base_nonce` válidos (contrato ACSL exige
 *                       `kr->active == 1`).
 * @param[in]  plain     Dados em claro, `plen` bytes legíveis.
 * @param[in]  plen      Comprimento dos dados em claro, em bytes. `plen == 0`
 *                       produz um pacote de 48 bytes (nonce + MAC).
 * @param[in]  block_seq Sequência do bloco, que distingue o nonce entre
 *                       blocos do mesmo arquivo. O chamador é responsável por
 *                       não repetir `(kr, block_seq)`: a mesma combinação
 *                       reaproveita a keystream.
 * @param[out] olen      Recebe o tamanho total do pacote devolvido.
 * @return Buffer recém-alocado com o envelope, ou NULL se `malloc` falhar.
 * @retval != NULL Pacote de `*olen` bytes; o chamador é dono da memória.
 * @retval NULL    Falha de alocação.
 * @pre `kr->active == 1`, conforme a anotação ACSL adjunta; a função não
 *      verifica os canários nem `active` em tempo de execução.
 * @see zupt_decrypt_buffer, zupt_aes256_ctr, zupt_hmac_sha256
 */
/* FRAMA-C: Encrypt-then-MAC: produces [nonce][ciphertext][HMAC] */
/*@ requires \valid_read(&kr->enc_key[0..31]);
  @ requires \valid_read(&kr->mac_key[0..31]);
  @ requires \valid_read(&kr->base_nonce[0..15]);
  @ requires kr->active == 1;
  @ requires \valid_read(plain + (0..plen-1));
  @ requires \valid(olen);
  @ assigns *olen;
  @ ensures *olen == 16 + plen + 32;
*/
uint8_t *zupt_encrypt_buffer(const zupt_keyring_t *kr,
                              const uint8_t *plain, size_t plen,
                              uint64_t block_seq, size_t *olen) {
    *olen = ZUPT_NONCE_SIZE + plen + ZUPT_HMAC_SIZE;
    uint8_t *pkg = (uint8_t *)malloc(*olen);
    if (!pkg) return NULL;

    /* Derive per-block nonce */
    uint8_t nonce[16];
    memcpy(nonce, kr->base_nonce, 16);
    for (int i = 0; i < 8; i++)
        nonce[i] ^= (uint8_t)(block_seq >> (i * 8));

    /* Store nonce */
    memcpy(pkg, nonce, 16);

    /* Encrypt */
    zupt_aes256_ctr(kr->enc_key, nonce, plain, pkg + 16, plen);

    /* MAC over nonce + ciphertext */
    zupt_hmac_sha256(kr->mac_key, ZUPT_HMAC_SIZE,
                     pkg, 16 + plen,
                     pkg + 16 + plen);

    return pkg;
}

/**
 * @brief Verifica o MAC de um envelope Encrypt-then-MAC e devolve o texto em claro.
 * @details Sequência, na ordem em que o código executa:
 *          1. Rejeita pacotes com menos de 48 bytes
 *             (ZUPT_NONCE_SIZE + ZUPT_HMAC_SIZE) devolvendo NULL. Neste ramo
 *             `*olen` não é escrita.
 *          2. Calcula `clen = pkglen - 48` e grava `*olen = clen`.
 *          3. Recomputa o MAC esperado com @ref zupt_hmac_sha256 sobre
 *             `pkg[0 .. 16+clen-1]` (`nonce || texto cifrado`) usando
 *             `kr->mac_key`.
 *          4. Compara com o MAC armazenado em `pkg + 16 + clen`:
 *            - sob `-DZUPT_USE_JASMIN`, por `zupt_mac_verify_ct`, primitiva
 *              assembly cuja documentação (include/zupt_jasmin.h) descreve
 *              acumulação XOR sobre 4 palavras de 64 bits;
 *            - sem Jasmin, por laço que acumula em `diff` o OR dos XORs dos 32
 *              bytes, sem interromper no primeiro byte distinto.
 *          5. Acumula em `diff` a diferença entre o nonce gravado no pacote e
 *             o nonce esperado, recomposto como `kr->base_nonce[i]` XOR do
 *             byte little-endian correspondente de `block_seq` para
 *             `i < 8`. Isso vincula cada bloco autenticado à sua posição e ao
 *             nonce base: um pacote válido para uma posição não passa na outra.
 *          6. Limpa `expected_mac` com @ref zupt_secure_wipe.
 *          7. Aloca e decifra ANTES de examinar `diff`, de modo que um
 *             atacante que meça o tempo não distinguisha MAC válido de MAC
 *             inválido pela ausência do trabalho de decifração (o comentário
 *             do código denomina isto "timing oracle"). A decifração usa o
 *             nonce lido do próprio pacote, `pkg[0..15]`.
 *          8. Se `diff != 0`, limpa `plain` com @ref zupt_secure_wipe, libera
 *             a memória e devolve NULL; caso contrário devolve `plain`.
 * @param[in]  kr      Keyring ativo, com `enc_key`, `mac_key` e
 *                     `base_nonce` válidos (contrato ACSL exige
 *                     `kr->active == 1`).
 * @param[in]  pkg     Envelope completo: nonce (16) + texto cifrado + MAC (32).
 * @param[in]  pkglen  Tamanho do envelope, em bytes. Deve ser >= 48 para que
 *                     a função prossiga.
 * @param[in]  block_seq Posição do bloco, usada para recompor o nonce esperado.
 *                       Chamar com a posição errada faz a autenticação falhar,
 *                       mesmo com chave e conteúdo corretos.
 * @param[out] olen    Recebe o comprimento do texto em claro,
 *                     `pkglen - 48`, quando a função prossegue além do teste
 *                     de tamanho mínimo.
 * @return Texto em claro recém-alocado, ou NULL.
 * @retval != NULL Buffer de `*olen` bytes com o conteúdo autenticado; o
 *                 chamador é dono da memória.
 * @retval NULL    Pacote curto (< 48 bytes), falha de `malloc`, ou MAC ou
 *                 nonce não conferem.
 * @note Quando `clen == 0`, o buffer devolvido tem 1 byte alocado (malloc não
 *       aceita tamanho zero) e `*olen == 0`.
 * @warning A comparação de MAC percorre os 32 bytes inteiros e a decifração é
 *          feita mesmo em caso de falha; o Jasmin afirma verificação de tempo
 *          constante apenas para a primitiva assembly que ele gera. Não há,
 *          neste caminho, verificação de canário do keyring.
 * @see zupt_encrypt_buffer, zupt_mac_verify_ct, ZUPT_ERR_AUTH_FAIL
 */
/* FRAMA-C: Decrypt with MAC verification (Encrypt-then-MAC) */
/*@ requires \valid_read(&kr->enc_key[0..31]);
  @ requires \valid_read(&kr->mac_key[0..31]);
  @ requires kr->active == 1;
  @ requires pkglen >= 48;
  @ requires \valid_read(pkg + (0..pkglen-1));
  @ requires \valid(olen);
  @ assigns *olen;
  @ behavior auth_ok:
  @   ensures \result != \null ==> *olen == pkglen - 48;
  @ behavior auth_fail:
  @   ensures \result == \null ==> *olen == pkglen - 48;
*/
uint8_t *zupt_decrypt_buffer(const zupt_keyring_t *kr,
                              const uint8_t *pkg, size_t pkglen,
                              uint64_t block_seq, size_t *olen) {
    if (pkglen < ZUPT_NONCE_SIZE + ZUPT_HMAC_SIZE) return NULL;

    size_t clen = pkglen - ZUPT_NONCE_SIZE - ZUPT_HMAC_SIZE;
    *olen = clen;

    /* Verify HMAC — constant-time comparison via XOR accumulation */
    uint8_t expected_mac[32];
    zupt_hmac_sha256(kr->mac_key, ZUPT_HMAC_SIZE,
                     pkg, ZUPT_NONCE_SIZE + clen,
                     expected_mac);

    const uint8_t *stored_mac = pkg + ZUPT_NONCE_SIZE + clen;
#ifdef ZUPT_USE_JASMIN
    /* JASMIN-VERIFIED: CT MAC comparison — 4×u64 XOR accumulation.
     * Proven constant-time by Jasmin type system. */
    uint64_t diff = zupt_mac_verify_ct(expected_mac, stored_mac);
#else
    /* CT-REQUIRED: XOR accumulation fallback */
    uint64_t diff = 0;
    for (int i = 0; i < 32; i++)
        diff |= (uint64_t)(expected_mac[i] ^ stored_mac[i]);
#endif

    /* Bind each authenticated block to its position and the header nonce. */
    for (int i = 0; i < ZUPT_NONCE_SIZE; i++) {
        uint8_t expected_nonce = kr->base_nonce[i];
        if (i < 8) expected_nonce ^= (uint8_t)(block_seq >> (i * 8));
        diff |= (uint64_t)(expected_nonce ^ pkg[i]);
    }

    zupt_secure_wipe(expected_mac, 32);

    /* CT-REQUIRED: Always decrypt even on MAC failure to prevent timing oracle.
     * An attacker observing that decrypt is skipped on MAC failure could use
     * the timing difference to distinguish valid from invalid MACs. */
    uint8_t *plain = (uint8_t *)malloc(clen ? clen : 1);
    if (!plain) return NULL;

    const uint8_t *nonce = pkg;
    zupt_aes256_ctr(kr->enc_key, nonce, pkg + 16, plain, clen);

    if (diff != 0) {
        /* Authentication failed — wipe and discard decrypted data */
        zupt_secure_wipe(plain, clen);
        free(plain);
        return NULL;
    }

    return plain;
}

/* ═══════════════════════════════════════════════════════════════════
 * HYBRID POST-QUANTUM KEM: ML-KEM-768 + X25519 (v0.7.0)
 *
 * Security model: Secure if EITHER ML-KEM-768 OR X25519 is secure.
 * Application-specific construction; see docs/FORMAT.md and SECURITY.md.
 *
 * Key file format (.zupt-key):
 *   [4B]  magic "ZKEY"
 *   [1B]  version 0x01
 *   [1B]  flags: bit0=has_private
 *   [2B]  reserved
 *   [1184B] ml_kem_pk
 *   [32B]   x25519_pk
 *   [2400B] ml_kem_sk  (only if has_private)
 *   [32B]   x25519_sk  (only if has_private)
 *   [8B]  xxh64 checksum of all above
 * ═══════════════════════════════════════════════════════════════════ */

#include "zupt_mlkem.h"
#include "zupt_x25519.h"
#include "zupt_keccak.h"

/**
 * @def ZKEY_MAGIC
 * @brief Assinatura dos arquivos de chave híbrida: os 4 bytes "ZKEY".
 * @details Comparada com `memcmp` nos offsets 0..3 em @ref zupt_hybrid_keygen,
 *          @ref zupt_hybrid_export_pubkey, @ref read_pubkey,
 *          @ref read_privkey, @ref parse_pubkey_buf e
 *          @ref parse_privkey_buf.
 * @see ZKEY_VERSION
 */
#define ZKEY_MAGIC "ZKEY"
/**
 * @def ZKEY_VERSION
 * @brief Versão de formato gravada e exigida pelo código deste arquivo.
 * @details Expande para @ref ZUPT_KEY_FORMAT_VERSION, definido em
 *          include/zupt_cxx.h como 2. O banner acima, neste arquivo, descreve
 *          o campo como "version 0x01", e @ref parse_privkey_buf aceita a
 *          versão 1 quando chamada pelo caminho de recuperação legada.
 * @see ZUPT_KEY_FORMAT_VERSION, parse_privkey_buf
 */
#define ZKEY_VERSION ZUPT_KEY_FORMAT_VERSION
/**
 * @def ZKEY_FLAG_PRIVATE
 * @brief Valor do byte 5 quando o registro contém as chaves privadas.
 * @details Gravado em @ref zupt_hybrid_keygen, exigido em
 *          @ref zupt_hybrid_export_pubkey, @ref read_privkey e
 *          @ref parse_privkey_buf. Nos registros apenas públicos o byte 5 é
 *          comparado com 0 (@ref parse_pubkey_buf, e @ref
 *          zupt_hybrid_export_pubkey ao escrever o destino).
 */
#define ZKEY_FLAG_PRIVATE 0x01
/**
 * @def ZKEY_PUB_SIZE
 * @brief Tamanho, em bytes, do registro público sem checksum: 8 + 1184 + 32.
 * @details Cabeçalho (magic 4, versão 1, flags 1, reservados 2) mais a chave
 *          de encapsulação ML-KEM-768 (1184) e a chave pública X25519 (32).
 *          @ref zupt_hybrid_export_pubkey escreve ZKEY_PUB_SIZE + 8 bytes,
 *          incluindo os 8 bytes de checksum.
 */
#define ZKEY_PUB_SIZE  (8 + 1184 + 32)        /* header + ml_kem_pk + x25519_pk */
/**
 * @def ZKEY_PRIV_SIZE
 * @brief Tamanho, em bytes, do registro privado sem checksum:
 *        8 + 1184 + 32 + 2400 + 32.
 * @details Acrescenta ao registro público a chave de decapsulação ML-KEM-768
 *          (2400) e a chave privada X25519 (32). Usado em @ref
 *          zupt_hybrid_keygen, que escreve ZKEY_PRIV_SIZE + 8 bytes. Os
 *          leitores (@ref read_privkey, @ref parse_privkey_buf) conferem esse
 *          comprimento por `fread` ou por comparação explícita de `len`.
 */
#define ZKEY_PRIV_SIZE (8 + 1184 + 32 + 2400 + 32) /* + ml_kem_sk + x25519_sk */

/**
 * @brief Gera um par de chaves híbridas ML-KEM-768 + X25519 e o grava em arquivo.
 * @details Ordem das operações:
 *          1. @ref zupt_mlkem768_keygen gera a chave pública (1184 bytes) e a
 *             chave de decapsulação (2400 bytes); se devolver -1, a função
 *             devolve -1 imediatamente.
 *          2. @ref zupt_random_bytes obtém o escalar X25519 (32 bytes) e
 *             @ref zupt_x25519_base deriva a chave pública correspondente.
 *          3. Abre `keyfile` para escrita.
 *          4. Monta o registro "ZKEY" privado em um buffer zerado por `calloc`
 *             de ZKEY_PRIV_SIZE + 8 bytes: magic, versão, flags, reservados,
 *             `ml_pk`, `x_pk`, `ml_sk`, `x_sk`.
 *          5. Calcula @ref zupt_xxh64 sobre os ZKEY_PRIV_SIZE primeiros bytes
 *             (semente 0) e grava o resultado little-endian nos 8 bytes
 *             finais, por @ref zupt_le64_put.
 *          6. Escreve os ZKEY_PRIV_SIZE + 8 bytes, fecha o arquivo e limpa com
 *             @ref zupt_secure_wipe as chaves secretas em pilha e o buffer.
 *
 *          Ramos de plataforma na abertura do arquivo:
 *          - `!_WIN32`: `open` com `O_WRONLY | O_CREAT | O_NOFOLLOW |
 *            O_NONBLOCK` e modo 0600, de forma que o arquivo nasce sem
 *             permissão de leitura por outros (evita `fopen` + `chmod`, que
 *             deixaria o arquivo brevemente no modo do umask). Depois,
 *             `fstat` exige: arquivo regular (`S_ISREG`), exatamente um link
 *             (`st_nlink == 1`), dono igual a `geteuid()`, e ainda `fchmod(fd,
 *             0600)` e `ftruncate(fd, 0)` com sucesso; qualquer falha fecha o
 *             descritor, limpa `ml_sk` e `x_sk` e devolve -1. Por fim
 *             `fdopen(fd, "wb")`; se retornar NULL, fecha o descritor, limpa
 *             `ml_sk` e `x_sk` e devolve -1.
 *          - `_WIN32`: `fopen(keyfile, "wb")` sem nenhum controle de modo; o
 *             comentário do cabeçalho da API correspondente (include/zupt_cxx.h)
 *             delega a proteção ao ACL do diretório, controlado pelo chamador.
 * @param[in] keyfile Caminho do arquivo onde o registro privado é gravado.
 * @return 0 em caso de sucesso, -1 em erro.
 * @retval 0   Registro completo escrito e arquivo fechado com sucesso
 *             (`written == ZKEY_PRIV_SIZE + 8 && fclose == 0`).
 * @retval -1  `zupt_mlkem768_keygen` falhou; abertura/fstat/fchmod/ftruncate/
 *             fdopen recusados (POSIX); `fopen` recusado (Windows); `calloc`
 *             falhou; `fwrite` parcial; ou `fclose` com erro.
 * @note O registro escrito contém as chaves secretas em claro, conforme o
 *       comentário do próprio código. Os caminhos de erro do ramo Windows e o
 *       da falha de `calloc` devolvem -1 sem limpar `ml_sk` e `x_sk` da pilha.
 * @see zupt_hybrid_export_pubkey, read_privkey, ZKEY_PRIV_SIZE
 */
int zupt_hybrid_keygen(const char *keyfile) {
    uint8_t ml_pk[MLKEM_PUBLICKEYBYTES], ml_sk[MLKEM_SECRETKEYBYTES];
    uint8_t x_sk[32], x_pk[32];

    /* Generate ML-KEM-768 keypair */
    if (zupt_mlkem768_keygen(ml_pk, ml_sk) != 0) return -1;

    /* Generate X25519 keypair */
    zupt_random_bytes(x_sk, 32);
    zupt_x25519_base(x_pk, x_sk);

    /* Write private key file. The file holds the X25519 and ML-KEM secret
     * keys in the clear, so it must never be world/group readable. Create it
     * with 0600 atomically (via open) rather than fopen + chmod, which would
     * briefly expose the file with the umask-default mode. */
#if !defined(_WIN32)
    int fd = open(keyfile, O_WRONLY | O_CREAT | O_NOFOLLOW | O_NONBLOCK, 0600);
    if (fd < 0) {
        zupt_secure_wipe(ml_sk, sizeof(ml_sk));
        zupt_secure_wipe(x_sk, sizeof(x_sk));
        return -1;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_nlink != 1 ||
        st.st_uid != geteuid() || fchmod(fd, 0600) != 0 || ftruncate(fd, 0) != 0) {
        close(fd);
        zupt_secure_wipe(ml_sk, sizeof(ml_sk));
        zupt_secure_wipe(x_sk, sizeof(x_sk));
        return -1;
    }
    FILE *f = fdopen(fd, "wb");
    if (!f) {
        close(fd);
        zupt_secure_wipe(ml_sk, sizeof(ml_sk));
        zupt_secure_wipe(x_sk, sizeof(x_sk));
        return -1;
    }
#else
    FILE *f = fopen(keyfile, "wb");
    if (!f) return -1;
#endif

    size_t total = ZKEY_PRIV_SIZE;
    uint8_t *buf = (uint8_t *)calloc(total + 8, 1); /* +8 for checksum */
    if (!buf) { fclose(f); return -1; }

    memcpy(buf, ZKEY_MAGIC, 4);
    buf[4] = ZKEY_VERSION;
    buf[5] = ZKEY_FLAG_PRIVATE;
    buf[6] = buf[7] = 0; /* reserved */
    memcpy(buf + 8, ml_pk, 1184);
    memcpy(buf + 8 + 1184, x_pk, 32);
    memcpy(buf + 8 + 1184 + 32, ml_sk, 2400);
    memcpy(buf + 8 + 1184 + 32 + 2400, x_sk, 32);

    /* Checksum */
    uint64_t ck = zupt_xxh64(buf, total, 0);
    zupt_le64_put(buf + total, ck);

    size_t written = fwrite(buf, 1, total + 8, f);
    int closed = fclose(f);

    zupt_secure_wipe(ml_sk, sizeof(ml_sk));
    zupt_secure_wipe(x_sk, 32);
    zupt_secure_wipe(buf, total + 8);
    free(buf);

    return (written == total + 8 && closed == 0) ? 0 : -1;
}

/**
 * @brief Deriva um arquivo de chave pública "ZKEY" a partir de um arquivo privado.
 * @details Lê os 8 bytes de cabeçalho de `privfile` e exige: magic "ZKEY",
 *          byte 4 igual a @ref ZKEY_VERSION (isto é, 2), byte 5 igual a @ref
 *          ZKEY_FLAG_PRIVATE e bytes 6 e 7 iguais a zero. Em seguida lê os
 *          1216 bytes de material público (`ml_pk` de 1184 + `x_pk` de 32) e
 *          fecha o arquivo de origem.
 *
 *          Escreve em `pubfile`, por `fopen(..., "wb")`, um buffer de
 *          ZKEY_PUB_SIZE + 8 bytes com magic, @ref ZKEY_VERSION, byte 5 igual
 *          a zero (sem chave privada), reservados zerados e os 1216 bytes
 *          públicos copiados. O checksum @ref zupt_xxh64 (semente 0) dos
 *          primeiros ZKEY_PUB_SIZE bytes é gravado little-endian nos 8 bytes
 *          finais, por @ref zupt_le64_put.
 *
 *          Não há controle de modo de permissão na criação de `pubfile` em
 *          nenhuma plataforma, e o checksum de origem não é verificado: o
 *          conteúdo público é copiado como está. O conteúdo das chaves também
 *          não é validado (não se chama
 *          @ref zupt_mlkem768_public_key_check).
 * @param[in]  privfile Caminho do arquivo privado "ZKEY".
 * @param[out] pubfile  Caminho do arquivo público a criar/sobrescrever.
 * @return 0 em caso de sucesso, -1 em erro.
 * @retval 0   Registro público completo escrito (`written == ZKEY_PUB_SIZE + 8`).
 * @retval -1  Origem não abre, cabeçalho inválido (magic, versão != 2, flag
 *             != 1, reservados != 0) ou leitura curta dos 1216 bytes, destino
 *             não abre, ou `fwrite` parcial.
 * @note Divergência com a API de buffers correspondente,
 *       `zupt_hybrid_export_pubkey_c` em src/zupt_cxx.c, que aceita chave
 *       privada de versão 1 ou 2. Este caminho recusa a versão 1.
 * @see zupt_hybrid_keygen, parse_pubkey_buf, ZKEY_PUB_SIZE
 */
int zupt_hybrid_export_pubkey(const char *privfile, const char *pubfile) {
    FILE *f = fopen(privfile, "rb");
    if (!f) return -1;

    uint8_t hdr[8];
    if (fread(hdr, 1, 8, f) != 8 || memcmp(hdr, ZKEY_MAGIC, 4) != 0 || hdr[4] != ZKEY_VERSION ||
        hdr[5] != ZKEY_FLAG_PRIVATE || hdr[6] || hdr[7]) {
        fclose(f); return -1;
    }

    uint8_t pk_data[1184 + 32];
    if (fread(pk_data, 1, 1216, f) != 1216) { fclose(f); return -1; }
    fclose(f);

    /* Write public key file */
    FILE *out = fopen(pubfile, "wb");
    if (!out) return -1;

    size_t total = ZKEY_PUB_SIZE;
    uint8_t buf[ZKEY_PUB_SIZE + 8];
    memcpy(buf, ZKEY_MAGIC, 4);
    buf[4] = ZKEY_VERSION;
    buf[5] = 0; /* no private key */
    buf[6] = buf[7] = 0;
    memcpy(buf + 8, pk_data, 1216);

    uint64_t ck = zupt_xxh64(buf, total, 0);
    zupt_le64_put(buf + total, ck);

    size_t written = fwrite(buf, 1, total + 8, out);
    fclose(out);
    return (written == total + 8) ? 0 : -1;
}

/* Read public key from a .zupt-key file (works for both pub and priv files) */
/**
 * @brief Lê o material público de um arquivo "ZKEY" (público ou privado).
 * @details Lê os 8 bytes de cabeçalho e exige magic "ZKEY", byte 4 igual a
 *          @ref ZKEY_VERSION, e bytes 6 e 7 iguais a zero. O byte 5 (flag de
 *          chave privada) NÃO é verificado, o que permite ler tanto registros
 *          públicos quanto privados. Depois lê, nesta ordem, os 1184 bytes de
 *          `ml_pk` e os 32 bytes de `x_pk`, e fecha o arquivo.
 *
 *          O checksum de 8 bytes que @ref zupt_hybrid_keygen e
 *          @ref zupt_hybrid_export_pubkey gravam no fim do arquivo não é lido
 *          nem verificado aqui.
 * @param[in]  path   Caminho do arquivo "ZKEY".
 * @param[out] ml_pk  Destino da chave de encapsulação ML-KEM-768 (1184 bytes).
 * @param[out] x_pk   Destino da chave pública X25519 (32 bytes).
 * @return 0 quando o cabeçalho confere e as duas leituras são completas.
 * @retval 0   Sucesso.
 * @retval -1  Arquivo não abre, cabeçalho inválido, ou `fread` curto em
 *             qualquer dos dois campos.
 * @note O arquivo é fechado em todos os caminhos de erro.
 * @see read_privkey, parse_pubkey_buf, zupt_hybrid_encrypt_init
 */
static int read_pubkey(const char *path, uint8_t ml_pk[1184], uint8_t x_pk[32]) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    uint8_t hdr[8];
    if (fread(hdr, 1, 8, f) != 8 || memcmp(hdr, ZKEY_MAGIC, 4) != 0 || hdr[4] != ZKEY_VERSION || hdr[6] || hdr[7]) {
        fclose(f); return -1;
    }
    if (fread(ml_pk, 1, 1184, f) != 1184) { fclose(f); return -1; }
    if (fread(x_pk, 1, 32, f) != 32) { fclose(f); return -1; }
    fclose(f);
    return 0;
}

/* Read private key from a .zupt-key file */
/**
 * @brief Lê o material público e o material secreto de um arquivo "ZKEY" privado.
 * @details Valida o cabeçalho de 8 bytes: magic "ZKEY", byte 4 igual a
 *          @ref ZKEY_VERSION, byte 5 igual a @ref ZKEY_FLAG_PRIVATE e bytes
 *          6 e 7 iguais a zero. Em seguida lê, nesta ordem e cada leitura
 *          inteira: 1184 bytes para `ml_pk`, 32 para `x_pk`, 2400 para `ml_sk`
 *          e 32 para `x_sk`, e fecha o arquivo.
 *
 *          Diferente de @ref parse_privkey_buf, não aceita a versão 1 legada,
 *          e o checksum final do arquivo não é verificado.
 * @param[in]  path   Caminho do arquivo "ZKEY" privado.
 * @param[out] ml_pk  Chave pública ML-KEM-768 (1184 bytes).
 * @param[out] x_pk   Chave pública X25519 (32 bytes).
 * @param[out] ml_sk  Chave de decapsulação ML-KEM-768 (2400 bytes). Contém
 *                    material secreto; quem chama deve limpá-la.
 * @param[out] x_sk   Chave privada X25519 (32 bytes). Contém material secreto;
 *                    quem chama deve limpá-la.
 * @return 0 quando o cabeçalho confere e as quatro leituras são completas.
 * @retval 0   Sucesso.
 * @retval -1  Arquivo não abre, cabeçalho inválido, ou `fread` curto em
 *             qualquer campo.
 * @warning Os buffers `ml_sk` e `x_sk` podem conter material secreto parcial
 *          mesmo em retorno de erro (a função não os limpa). Os chamadores
 *          deste módulo (@ref zupt_hybrid_decrypt_init) os limpam com
 *          @ref zupt_secure_wipe.
 * @see read_pubkey, parse_privkey_buf, zupt_hybrid_decrypt_init
 */
static int read_privkey(const char *path, uint8_t ml_pk[1184], uint8_t x_pk[32],
                        uint8_t ml_sk[2400], uint8_t x_sk[32]) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    uint8_t hdr[8];
    if (fread(hdr, 1, 8, f) != 8 || memcmp(hdr, ZKEY_MAGIC, 4) != 0 || hdr[4] != ZKEY_VERSION ||
        hdr[5] != ZKEY_FLAG_PRIVATE || hdr[6] || hdr[7]) {
        fclose(f); return -1;
    }
    if (fread(ml_pk, 1, 1184, f) != 1184) { fclose(f); return -1; }
    if (fread(x_pk, 1, 32, f) != 32) { fclose(f); return -1; }
    if (fread(ml_sk, 1, 2400, f) != 2400) { fclose(f); return -1; }
    if (fread(x_sk, 1, 32, f) != 32) { fclose(f); return -1; }
    fclose(f);
    return 0;
}

/* Parse a public key directly from an in-memory buffer (no temp files). */
/**
 * @brief Parseia um registro público "ZKEY" vindo de um buffer, sem disco.
 * @details Exige comprimento exatamente igual a 8 + 1184 + 32 (1224), magic
 *          "ZKEY", byte 4 igual a @ref ZKEY_VERSION, byte 5 igual a 0 (sem
 *          chave privada) e bytes 6 e 7 iguais a zero. Copia os 1184 bytes de
 *          `ml_pk` e os 32 de `x_pk`.
 *
 *          Compara o comprimento do buffer, ao contrário de
 *          @ref read_pubkey, que não conhece o tamanho do arquivo. Não verifica
 *          checksum nem conteúdo das chaves.
 * @param[in]  buf Registro público serializado.
 * @param[in]  len Comprimento do buffer, em bytes.
 * @param[out] ml_pk Destino da chave de encapsulação ML-KEM-768 (1184 bytes).
 * @param[out] x_pk  Destino da chave pública X25519 (32 bytes).
 * @return 0 quando o buffer tem o tamanho e o cabeçalho exigidos.
 * @retval 0   Sucesso.
 * @retval -1  `buf` é nulo, `len != 1224`, magic inválida, versão !=
 *             @ref ZKEY_VERSION, byte 5 != 0, ou reservados != 0.
 * @see parse_privkey_buf, read_pubkey, zupt_hybrid_encrypt_init_mem
 */
static int parse_pubkey_buf(const uint8_t *buf, size_t len,
                            uint8_t ml_pk[1184], uint8_t x_pk[32]) {
    if (!buf || len != (size_t)(8 + 1184 + 32)) return -1;
    if (memcmp(buf, ZKEY_MAGIC, 4) != 0 || buf[4] != ZKEY_VERSION ||
        buf[5] != 0 || buf[6] || buf[7]) return -1;
    memcpy(ml_pk, buf + 8, 1184);
    memcpy(x_pk, buf + 8 + 1184, 32);
    return 0;
}

/**
 * @brief Lê um segredo híbrido de um buffer em memória, sem arquivos.
 * @details Valida o cabeçalho do formato `ZKEY` e copia, na ordem, a chave
 *          pública ML-KEM-768, a chave pública X25519, a chave secreta
 *          ML-KEM-768 e a chave secreta X25519. Compara exatamente o
 *          comprimento esperado, o magic, a versão e a flag de privado.
 *          Usado pelas variantes `_mem` das rotinas de inicialização, que
 *          recebem a chave já em memória.
 * @param[in]  buf    Buffer com o segredo serializado.
 * @param[in]  len    Tamanho de `buf` em bytes.
 * @param[out] ml_pk  Recebe a chave pública ML-KEM-768 (1184 bytes).
 * @param[out] x_pk   Recebe a chave pública X25519 (32 bytes).
 * @param[out] ml_sk  Recebe a chave secreta ML-KEM-768 (2400 bytes).
 * @param[out] x_sk   Recebe a chave secreta X25519 (32 bytes).
 * @param[in]  legacy Diferente de zero aceita a versão 1 do cabeçalho; zero
 *                    exige a versão corrente.
 * @retval  0 Leitura bem-sucedida.
 * @retval -1 Buffer nulo, comprimento errado, magic inválido, versão
 *            inesperada, flag de privado ausente ou bytes de reserva
 *            diferentes de zero.
 * @note    Não limpa os buffers de saída em caso de erro; a limpeza é de
 *          responsabilidade do chamador. */
/* Parse a private key directly from an in-memory buffer (no temp files). */
static int parse_privkey_buf(const uint8_t *buf, size_t len,
                             uint8_t ml_pk[1184], uint8_t x_pk[32],
                             uint8_t ml_sk[2400], uint8_t x_sk[32], int legacy) {
    if (!buf || len != (size_t)(8 + 1184 + 32 + 2400 + 32)) return -1;
    if (memcmp(buf, ZKEY_MAGIC, 4) != 0 || buf[4] != (legacy ? 1 : ZKEY_VERSION) ||
        buf[5] != ZKEY_FLAG_PRIVATE || buf[6] || buf[7]) return -1;
    memcpy(ml_pk, buf + 8, 1184);
    memcpy(x_pk, buf + 8 + 1184, 32);
    memcpy(ml_sk, buf + 8 + 1184 + 32, 2400);
    memcpy(x_sk, buf + 8 + 1184 + 32 + 2400, 32);
    return 0;
}

/**
 * @brief Decapsulação ML-KEM-768 do formato legado (v1 do envelope).
 * @details Declaração externa de símbolo de compatibilidade, deliberadamente
 *          ausente dos cabeçalhos instalados. É chamada apenas por
 *          `hybrid_decrypt_core` na rota `legacy`, para decapsular envelopes
 *          escritos por versões anteriores da biblioteca, cujo
 *          encapsulamento não corresponde ao algoritmo FIPS-203 atual. Os
 *          parâmetros são, nesta ordem, o segredo compartilhado de saída,
 *          o texto cifrado da encapsulamentação e a chave secreta.
 * @return 0 quando o segredo compartilhado foi derivado com sucesso,
 *         diferente de zero em caso de falha.
 * @warning Não faz parte da API pública: não está em nenhum cabeçalho de
 *          `include/` e pode desaparecer em versões futuras. */
/* Internal compatibility symbol, deliberately absent from installed headers. */
extern int zupt_legacy_mlkem768_decaps(uint8_t *, const uint8_t *, const uint8_t *);

/**
 * @brief Verifica se todos os bytes de um intervalo são zero.
 * @details Acumula com OR bit a bit e só compara no fim, de modo a percorrer
 *          o intervalo inteiro sem saída antecipada — a comparação de um
 *          segredo compartilhado X25519 contra zero é sensível: um resultado
 *          todo-zero indica a função de baixo nível fraca (cofator).
 * @param[in] p   Intervalo a examinar.
 * @param[in] len Número de bytes de `p`.
 * @return 1 se todos os bytes são zero, 0 caso contrário. */
static int all_zero(const uint8_t *p, size_t len) {
    uint8_t nonzero = 0;
    for (size_t i = 0; i < len; ++i) nonzero |= p[i];
    return nonzero == 0;
}

/**
 * @brief Deriva a chave de 64 bytes do segredo compartilhado híbrido.
 * @details Combina o segredo do ML-KEM-768 e o do X25519 com uma função de
 *          derivação por hash (SHA3-512) sobre uma entrada de formato
 *          fixo. Dois formatos existem:
 *          - <b>Corrente</b> (`legacy == 0`): concatena `ml_ss`, `x_ss`,
 *            o texto cifrado da encapsulamentação, a chave pública efêmera
 *            e a cadeia de contexto `libzupt/hybrid/v2`. Os segredos são
 *            concatenados, não combinados por XOR, o que separa os domínios
 *            das duas primitivas.
 *          - <b>Legado</b> (`legacy != 0`): XOR dos dois segredos, seguido
 *            do texto cifrado, da chave efêmera e da constante
 *            `ZUPT-HYBRID-v1` (com o NUL final, como na época).
 *          Os dois formatos produzem chaves diferentes: um envelope v2 só
 *          pode ser lido pela rota corrente.
 * @param[in]  ml_ss   Segredo compartilhado ML-KEM-768 (32 bytes).
 * @param[in]  x_ss    Segredo compartilhado X25519 (32 bytes).
 * @param[in]  ct      Texto cifrado da encapsulamentação (1088 bytes).
 * @param[in]  eph_pk  Chave pública efêmera X25519 (32 bytes).
 * @param[in]  legacy  Diferente de zero seleciona o formato legado.
 * @param[out] key     Recebe as 64 bytes derivadas (32 de cifra, 32 de MAC).
 * @note    O buffer de entrada em pilha é limpo com `zupt_secure_wipe`
 *          antes do retorno, em ambas as rotas. */
static void hybrid_kdf(const uint8_t ml_ss[32], const uint8_t x_ss[32],
                       const uint8_t ct[1088], const uint8_t eph_pk[32],
                       int legacy, uint8_t key[64]) {
    if (legacy) {
        uint8_t input[32 + 1088 + 32 + 15];
        for (size_t i = 0; i < 32; ++i) input[i] = ml_ss[i] ^ x_ss[i];
        memcpy(input + 32, ct, 1088);
        memcpy(input + 1120, eph_pk, 32);
        /* Historical format includes the terminating NUL. */
        memcpy(input + 1152, "ZUPT-HYBRID-v1", 15);
        zupt_sha3_512(input, sizeof(input), key);
        zupt_secure_wipe(input, sizeof(input));
    } else {
        static const char context[] = "libzupt/hybrid/v2";
        uint8_t input[64 + 1088 + 32 + sizeof(context) - 1];
        memcpy(input, ml_ss, 32);
        memcpy(input + 32, x_ss, 32);
        memcpy(input + 64, ct, 1088);
        memcpy(input + 1152, eph_pk, 32);
        memcpy(input + 1184, context, sizeof(context) - 1);
        zupt_sha3_512(input, sizeof(input), key);
        zupt_secure_wipe(input, sizeof(input));
    }
}

/*
 * HYBRID ENCRYPT INIT (v2): ML-KEM-768 + X25519, then domain-separated SHA3-512.
 * Header: discriminator 0x03 || ml_ct[1088] || eph_pk[32] || nonce[16].
 * Concatenate both component secrets and the encapsulation transcript; the
 * legacy XOR/Kyber-era behavior is isolated in explicit recovery only.
 */
/* FRAMA-C: Hybrid PQ encrypt init — ML-KEM-768 + X25519 KEM */
/*@ requires \valid(kr);
  @ requires \valid_read(pubkeyfile);
  @ requires \valid(enc_hdr + (0..1199));
  @ requires \valid(enc_hdr_len);
  @ assigns kr->enc_key[0..31], kr->mac_key[0..31], kr->base_nonce[0..15],
  @         kr->iterations, kr->active;
  @ assigns enc_hdr[0..1199], *enc_hdr_len;
  @ ensures \result == 0 ==> kr->active == 1;
  @ ensures \result == 0 ==> *enc_hdr_len == 1137;
*/
/* Shared encapsulation + KDF core, used by both the file- and memory-based
 * encrypt-init entry points. Takes the already-parsed recipient public keys. */
/**
 * @brief Núcleo de encapsulamentação + derivação do lado do emissor.
 * @details Executa a parte comum das rotinas de inicialização de cifra, que
 *          variam apenas em como obtêm as chaves do destinatário (arquivo ou
 *          memória):
 *          1. encapsula com ML-KEM-768 na chave pública recebida;
 *          2. gera um par X25519 efêmero e deriva o segredo compartilhado
 *             contra a chave pública do destinatário;
 *          3. rejeita o resultado se o segredo X25519 for todo-zero;
 *          4. deriva a chave de 64 bytes com `hybrid_kdf` no formato
 *             corrente e monta o keyring (canaries, chaves, nonce aleatório,
 *             `iterations = 0`, `active = 1`);
 *          5. fixa as chaves na RAM com `zupt_mlock_keys`;
 *          6. escreve o cabeçalho do envelope: discriminador de formato (1
 *             byte), texto cifrado do ML-KEM (1088), chave pública efêmera
 *             (32) e nonce base (16) — 1137 bytes;
 *          7. limpa os intermediários.
 * @param[out] kr          Keyring a popular.
 * @param[in]  ml_pk       Chave pública ML-KEM-768 do destinatário (1184).
 * @param[in]  x_pk        Chave pública X25519 do destinatário (32).
 * @param[out] enc_hdr     Buffer de cabeçalho (capacidade mínima 1137 bytes).
 * @param[out] enc_hdr_len Recebe o tamanho do cabeçalho escrito.
 * @retval  0 Sucesso: keyring ativo e cabeçalho de 1137 bytes escrito.
 * @retval -1 Falha na encapsulamentação ou segredo X25519 degenerado; nesse
 *            caso o keyring não é marcado como ativo, mas os campos já
 *            escritos permanecem no buffer.
 * @see zupt_hybrid_encrypt_init(), zupt_hybrid_encrypt_init_mem() */
static int hybrid_encrypt_core(zupt_keyring_t *kr,
                               const uint8_t ml_pk[1184], const uint8_t x_pk[32],
                               uint8_t *enc_hdr, size_t *enc_hdr_len) {
    /* ML-KEM-768 encapsulation */
    uint8_t ml_ct[1088], ml_ss[32];
    if (zupt_mlkem768_encaps(ml_ct, ml_ss, ml_pk) != 0) return -1;

    /* X25519 ECDH */
    uint8_t eph_sk[32], eph_pk[32], x_ss[32];
    zupt_random_bytes(eph_sk, 32);
    zupt_x25519_base(eph_pk, eph_sk);
    zupt_x25519(x_ss, eph_sk, x_pk);

    if (all_zero(x_ss, sizeof(x_ss))) {
        zupt_secure_wipe(ml_ss, sizeof(ml_ss));
        zupt_secure_wipe(x_ss, sizeof(x_ss));
        zupt_secure_wipe(eph_sk, sizeof(eph_sk));
        return -1;
    }
    uint8_t archive_key[64];
    hybrid_kdf(ml_ss, x_ss, ml_ct, eph_pk, 0, archive_key);

    /* Set up keyring */
    kr->canary_head = ZUPT_CANARY;
    memcpy(kr->enc_key, archive_key, 32);
    memcpy(kr->mac_key, archive_key + 32, 32);
    zupt_random_bytes(kr->base_nonce, ZUPT_NONCE_SIZE);
    kr->iterations = 0;
    kr->active = 1;
    kr->canary_tail = ZUPT_CANARY;

    /* Lock key material in RAM */
    zupt_mlock_keys(kr->enc_key, ZUPT_AES_KEY_SIZE);
    zupt_mlock_keys(kr->mac_key, ZUPT_HMAC_SIZE);

    /* Build encryption header: enc_type(1) + ml_ct(1088) + eph_pk(32) + base_nonce(16) */
    enc_hdr[0] = ZUPT_ENVELOPE_FORMAT;
    memcpy(enc_hdr + 1, ml_ct, 1088);
    memcpy(enc_hdr + 1 + 1088, eph_pk, 32);
    memcpy(enc_hdr + 1 + 1088 + 32, kr->base_nonce, 16);
    *enc_hdr_len = 1 + 1088 + 32 + 16;  /* 1137 bytes */

    /* Wipe all intermediates */
    zupt_secure_wipe(ml_ss, 32);
    zupt_secure_wipe(x_ss, 32);
    zupt_secure_wipe(eph_sk, 32);
    zupt_secure_wipe(archive_key, 64);

    return 0;
}

int zupt_hybrid_encrypt_init(zupt_keyring_t *kr, const char *pubkeyfile,
                              uint8_t *enc_hdr, size_t *enc_hdr_len) {
    uint8_t ml_pk[1184], x_pk[32];
    if (read_pubkey(pubkeyfile, ml_pk, x_pk) != 0) return -1;
    return hybrid_encrypt_core(kr, ml_pk, x_pk, enc_hdr, enc_hdr_len);
}

int zupt_hybrid_encrypt_init_mem(zupt_keyring_t *kr,
                                  const uint8_t *pubkey, size_t pubkey_len,
                                  uint8_t *enc_hdr, size_t *enc_hdr_len) {
    uint8_t ml_pk[1184], x_pk[32];
    if (parse_pubkey_buf(pubkey, pubkey_len, ml_pk, x_pk) != 0) return -1;
    return hybrid_encrypt_core(kr, ml_pk, x_pk, enc_hdr, enc_hdr_len);
}

/*
 * HYBRID DECRYPT INIT: Decapsulate with ML-KEM + X25519, derive archive keys.
 */
/* FRAMA-C: Hybrid PQ decrypt init — ML-KEM-768 + X25519 decaps */
/*@ requires \valid(kr);
  @ requires \valid_read(privkeyfile);
  @ requires enc_hdr_len >= 1137;
  @ requires \valid_read(enc_hdr + (0..enc_hdr_len-1));
  @ assigns kr->enc_key[0..31], kr->mac_key[0..31], kr->base_nonce[0..15],
  @         kr->iterations, kr->active;
  @ ensures \result == 0 ==> kr->active == 1;
*/
/* Shared decapsulation + KDF core, used by both the file- and memory-based
 * decrypt-init entry points. Takes the already-parsed recipient secret keys;
 * the caller owns and wipes ml_sk/x_sk. */
/**
 * @brief Núcleo de decapsulação + derivação do lado do receptor.
 * @details Parte comum das rotinas de inicialização de decifra, que variam
 *          apenas em como obtêm as chaves secretas (arquivo ou memória):
 *          1. valida o tamanho do cabeçalho (1137 bytes) e o discriminador
 *             de formato, aceitando 2 para o modo legado e o formato
 *             corrente caso contrário;
 *          2. decapsula o ML-KEM-768, pela rota legada ou pela corrente, de
 *             acordo com `legacy`;
 *          3. deriva o segredo X25519 entre a chave secreta do receptor e a
 *             chave pública efêmera do cabeçalho, rejeitando o resultado
 *             todo-zero;
 *          4. deriva a chave de 64 bytes com `hybrid_kdf` no mesmo formato
 *             usado na cifra e monta o keyring — aqui o nonce base vem do
 *             cabeçalho, e não de aleatoriedade;
 *          5. fixa as chaves na RAM e limpa os intermediários.
 * @param[out] kr          Keyring a popular.
 * @param[in]  ml_sk       Chave secreta ML-KEM-768 do receptor (2400 bytes).
 * @param[in]  x_sk        Chave secreta X25519 do receptor (32 bytes).
 * @param[in]  enc_hdr     Cabeçalho do envelope lido.
 * @param[in]  enc_hdr_len Tamanho do cabeçalho (deve ser 1137).
 * @param[in]  legacy      Diferente de zero aceita o formato de envelope v1.
 * @retval  0 Sucesso: keyring ativo.
 * @retval -1 Argumento nulo, cabeçalho com tamanho ou discriminador errado,
 *            falha na decapsulação ou segredo X25519 degenerado.
 * @note    A função não limpa `ml_sk` nem `x_sk`: o chamador é dono desses
 *          buffers.
 * @see zupt_hybrid_decrypt_init(), zupt_hybrid_decrypt_init_mem() */
static int hybrid_decrypt_core(zupt_keyring_t *kr,
                               const uint8_t ml_sk[2400], const uint8_t x_sk[32],
                               const uint8_t *enc_hdr, size_t enc_hdr_len, int legacy) {
    if (!kr || !enc_hdr || enc_hdr_len != 1137) return -1;
    if (enc_hdr[0] != (legacy ? 2 : ZUPT_ENVELOPE_FORMAT)) return -1;

    const uint8_t *ml_ct  = enc_hdr + 1;
    const uint8_t *eph_pk = enc_hdr + 1 + 1088;
    const uint8_t *nonce  = enc_hdr + 1 + 1088 + 32;

    /* ML-KEM-768 decapsulation */
    uint8_t ml_ss[32];
    int ret = legacy ? zupt_legacy_mlkem768_decaps(ml_ss, ml_ct, ml_sk)
                     : zupt_mlkem768_decaps(ml_ss, ml_ct, ml_sk);
    if (ret != 0) return -1;

    /* X25519 ECDH with ephemeral pubkey */
    uint8_t x_ss[32];
    zupt_x25519(x_ss, x_sk, eph_pk);

    if (all_zero(x_ss, sizeof(x_ss))) {
        zupt_secure_wipe(ml_ss, sizeof(ml_ss));
        zupt_secure_wipe(x_ss, sizeof(x_ss));
        return -1;
    }
    uint8_t archive_key[64];
    hybrid_kdf(ml_ss, x_ss, ml_ct, eph_pk, legacy, archive_key);

    kr->canary_head = ZUPT_CANARY;
    memcpy(kr->enc_key, archive_key, 32);
    memcpy(kr->mac_key, archive_key + 32, 32);
    memcpy(kr->base_nonce, nonce, ZUPT_NONCE_SIZE); /* Read from enc_hdr, NOT random */
    kr->iterations = 0;
    kr->active = 1;
    kr->canary_tail = ZUPT_CANARY;

    /* Lock key material in RAM */
    zupt_mlock_keys(kr->enc_key, ZUPT_AES_KEY_SIZE);
    zupt_mlock_keys(kr->mac_key, ZUPT_HMAC_SIZE);

    zupt_secure_wipe(ml_ss, 32);
    zupt_secure_wipe(x_ss, 32);
    zupt_secure_wipe(archive_key, 64);

    return 0;
}

int zupt_hybrid_decrypt_init(zupt_keyring_t *kr, const char *privkeyfile,
                              const uint8_t *enc_hdr, size_t enc_hdr_len) {
    uint8_t ml_pk[1184], x_pk[32], ml_sk[2400], x_sk[32];
    if (read_privkey(privkeyfile, ml_pk, x_pk, ml_sk, x_sk) != 0) return -1;
    int r = hybrid_decrypt_core(kr, ml_sk, x_sk, enc_hdr, enc_hdr_len, 0);
    zupt_secure_wipe(ml_sk, sizeof(ml_sk));
    zupt_secure_wipe(x_sk, 32);
    return r;
}

int zupt_hybrid_decrypt_init_mem(zupt_keyring_t *kr,
                                  const uint8_t *privkey, size_t privkey_len,
                                  const uint8_t *enc_hdr, size_t enc_hdr_len) {
    uint8_t ml_pk[1184], x_pk[32], ml_sk[2400], x_sk[32];
    if (parse_privkey_buf(privkey, privkey_len, ml_pk, x_pk, ml_sk, x_sk, 0) != 0) return -1;
    int r = hybrid_decrypt_core(kr, ml_sk, x_sk, enc_hdr, enc_hdr_len, 0);
    zupt_secure_wipe(ml_sk, sizeof(ml_sk));
    zupt_secure_wipe(x_sk, 32);
    return r;
}

/* Called only by the explicit legacy recovery API, which also checks a trusted
 * SHA-256 digest before returning any plaintext to its caller. */
int zupt_hybrid_decrypt_init_legacy_mem(zupt_keyring_t *kr,
    const uint8_t *privkey, size_t privkey_len,
    const uint8_t *enc_hdr, size_t enc_hdr_len) {
    uint8_t ml_pk[1184], x_pk[32], ml_sk[2400], x_sk[32];
    if (parse_privkey_buf(privkey, privkey_len, ml_pk, x_pk, ml_sk, x_sk, 1) != 0) return -1;
    int ret = hybrid_decrypt_core(kr, ml_sk, x_sk, enc_hdr, enc_hdr_len, 1);
    zupt_secure_wipe(ml_sk, sizeof(ml_sk));
    zupt_secure_wipe(x_sk, sizeof(x_sk));
    return ret;
}
