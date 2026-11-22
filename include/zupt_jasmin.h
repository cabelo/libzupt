/*
 * Zupt — Jasmin Verified Crypto Declarations
 * Copyright (c) 2026 Cristian Cezar Moisés — MIT License
 *
 * Extern declarations for Jasmin-compiled assembly functions.
 * These replace C fallbacks when built with -DZUPT_USE_JASMIN.
 *
 * Calling convention: System V AMD64 ABI.
 * Pointer args passed in RDI, RSI, RDX, RCX, R8, R9.
 *
 * v2.0.0: All 4 Jasmin functions wired and active.
 */
/**
 * @cond PORT
 * @file  zupt_jasmin.h
 * @brief Declarações `extern` das primitivas compiladas pelo Jasmin.
 * @details O Jasmin é uma linguagem de criptografia verificada; o assembly
 * gerado por ele substitui os equivalentes em C quando a biblioteca
 * é compilada com `-DZUPT_USE_JASMIN`. Fora dessa configuração o
 * a condição de pré-processador sobre `ZUPT_USE_JASMIN` deixa o arquivo vazio (além do guarda de
 * inclusão) e os caminhos em C de src/zupt_aes256.c,
 * src/zupt_mlkem.c, src/zupt_x25519.c e src/zupt_crypto.c continuam
 * ativos.
 *
 * Convenção de chamada: System V AMD64 ABI — argumentos de ponteiro
 * em RDI, RSI, RDX, RCX, R8 e R9. As funções são portanto específicas
 * de amd64.
 * @warning São primitivas assembly de origem externa. A verificação coberta
 * pelo Jasmin aplica-se ao assembly gerado, não ao comportamento da
 * biblioteca como um todo, e depende do layout de memória assumido
 * (ver as notas de cada função).
 * @warning Nesta revisão do repositório não há arquivos de assembly
 * (`.s`/`.S`) nem fonte `.jasmin` destas cinco funções. Compilar com
 * `-DZUPT_USE_JASMIN` sem vincular a biblioteca Jasmin correspondente
 * produz símbolos não definidos na etapa de link.
 * @endcond
 * @cond INGLES
 * @file  zupt_jasmin.h
 * @brief `extern` declarations of the primitives compiled by Jasmin.
 * @details Jasmin is a verified cryptography language; the assembly
 * it generates replaces the C equivalents when the library
 * is compiled with `-DZUPT_USE_JASMIN`. Outside that configuration, the
 * preprocessor condition on `ZUPT_USE_JASMIN` leaves the file empty (apart from the include guard) and the C paths in src/zupt_aes256.c,
 * src/zupt_mlkem.c, src/zupt_x25519.c and src/zupt_crypto.c remain
 * active.
 *
 * Calling convention: System V AMD64 ABI — pointer arguments
 * in RDI, RSI, RDX, RCX, R8 and R9. The functions are therefore
 * specific to amd64.
 * @warning These are external-origin assembly primitives. The verification covered
 * by Jasmin applies to the generated assembly, not to the behavior of the
 * library as a whole, and depends on the assumed memory layout
 * (see the notes of each function).
 * @warning In this repository revision there are no assembly files
 * (`.s`/`.S`) nor `.jasmin` source for these five functions. Compiling with
 * `-DZUPT_USE_JASMIN` without linking the corresponding Jasmin library
 * produces undefined symbols in the link step.
 * @endcond */
#ifndef ZUPT_JASMIN_H
#define ZUPT_JASMIN_H

#ifdef ZUPT_USE_JASMIN
#include <stdint.h>

/* JASMIN-VERIFIED: CT MAC comparison (4×u64 XOR accumulation).
 * Returns 0 if all 32 bytes match, nonzero if any differ.
 * Replaces XOR loop in zupt_decrypt_buffer(). */
/**
 * @cond PORT
 * @brief Compara 32 bytes de MAC acumulando XOR sobre 4 palavras de 64 bits.
 * @details Substitui o laço XOR que comparava MAC esperado e calculado em
 * zupt_decrypt_buffer(). Percorre os 32 bytes por palavras de 64
 * bits e acumula as diferenças, sem interromper no primeiro byte
 * distinto.
 * @param[in] expected MAC esperado (32 bytes legíveis).
 * @param[in] actual   MAC calculado (32 bytes legíveis).
 * @return 0 quando os 32 bytes coincidem; diferente de zero quando algum byte
 * difere.
 * @pre    Ambos os buffers têm 32 bytes válidos.
 * @endcond
 * @cond INGLES
 * @brief Compares 32 bytes of MAC by accumulating XOR over 4 words of 64 bits.
 * @details Replaces the XOR loop that compared the expected MAC and the computed MAC in
 * zupt_decrypt_buffer(). Walks the 32 bytes by 64-bit
 * words and accumulates the differences, without stopping at the first byte
 * that differs.
 * @param[in] expected Expected MAC (32 readable bytes).
 * @param[in] actual   Computed MAC (32 readable bytes).
 * @return 0 when the 32 bytes match; different from zero when some byte
 * differs.
 * @pre    Both buffers have 32 valid bytes.
 * @endcond */
extern uint64_t zupt_mac_verify_ct(const void *expected, const void *actual);

/**
 * @cond PORT
 * @brief Seleção condicional de 32 bytes, mascarada sobre 4 palavras de 64 bits.
 * @details Substitui o `cmov` usado em `zupt_mlkem768_decaps()`. Copia `a` para
 * `out` quando `cond == 0` e cópia `b` quando `cond != 0`.
 * @param[out] out  Destino dos 32 bytes selecionados.
 * @param[in]  a    Valor escolhido quando `cond == 0`.
 * @param[in]  b    Valor escolhido quando `cond != 0`.
 * @param[in]  cond Condição: 0 seleciona `a`; qualquer outro valor seleciona `b`.
 * @pre    `out`, `a` e `b` apontam para áreas de 32 bytes válidas, não
 * sobrepostas.
 * @note   Não retorna valor; o resultado é escrito em `out`.
 * @endcond
 * @cond INGLES
 * @brief Conditional selection of 32 bytes, masked over 4 words of 64 bits.
 * @details Replaces the `cmov` used in `zupt_mlkem768_decaps()`. Copies `a` to
 * `out` when `cond == 0` and copies `b` when `cond != 0`.
 * @param[out] out  Destination of the 32 selected bytes.
 * @param[in]  a    Value chosen when `cond == 0`.
 * @param[in]  b    Value chosen when `cond != 0`.
 * @param[in]  cond Condition: 0 selects `a`; any other value selects `b`.
 * @pre    `out`, `a` and `b` point to valid 32-byte areas, which do not
 * overlap.
 * @note   Does not return a value; the result is written into `out`.
 * @endcond */
extern void zupt_ct_select_32(void *out, const void *a,
                               const void *b, uint64_t cond);

/**
 * @cond PORT
 * @brief Troca condicional de dois elementos de campo, por XOR mascarado.
 * @details Substitui `fe_cswap` de `src/zupt_x25519.c`. Não faz nada quando
 * `cond == 0`; troca `a` e `b` in place quando `cond == 1`.
 * @param[in,out] a    Primeiro elemento (também recebe o valor trocado).
 * @param[in,out] b    Segundo elemento (também recebe o valor trocado).
 * @param[in]     cond Condição: 0 não troca; 1 troca.
 * @pre    Ambos os elementos têm o layout de 4 palavras de 64 bits
 * (`donna64`) esperado pela implementação Jasmin.
 * @endcond
 * @cond INGLES
 * @brief Conditional swap of two field elements, by masked XOR.
 * @details Replaces `fe_cswap` from `src/zupt_x25519.c`. Does nothing when
 * `cond == 0`; swaps `a` and `b` in place when `cond == 1`.
 * @param[in,out] a    First element (also receives the swapped value).
 * @param[in,out] b    Second element (also receives the swapped value).
 * @param[in]     cond Condition: 0 does not swap; 1 swaps.
 * @pre    Both elements have the layout of 4 words of 64 bits
 * (`donna64`) expected by the Jasmin implementation.
 * @endcond */
extern void zupt_fe_cswap(void *a, void *b, uint64_t cond);

/* JASMIN-VERIFIED: AES-256 single-block encrypt via AES-NI.
 * out = AES-256-ECB(key, ctr) XOR in.
 * FIX v2.0.0: Stack offset bug resolved — round keys at correct
 * 16-byte aligned offsets. Requires AES-NI (checked via CPUID).
 *
 * Args (System V ABI):
 *   out_ptr (RDI): destination for 16-byte result
 *   in_blk  (RSI): pointer to 16-byte plaintext block
 *   key     (RDX): pointer to 32-byte AES-256 key (two u128)
 *   ctr_blk (RCX): pointer to 16-byte counter block
 */
extern void zupt_aes256_blk(void *out, const void *in,
                              const void *key, const void *ctr);

/* JASMIN-VERIFIED: AES-256-CTR 4-block pipeline via AES-NI.
 * Processes nblocks×16 bytes with 4-way interleaving.
 * Counter is updated in-place (big-endian increment in bytes [8..15]).
 * Requires AES-NI. Falls back to zupt_aes256_blk for remaining 1-3 blocks.
 *
 * Args: out(RDI), in(RSI), key(RDX), ctr(RCX), nblocks(R8)
 */
extern void zupt_aes256_ctr4(void *out, const void *in,
                               const void *key, void *ctr,
                               uint64_t nblocks);

#endif /* ZUPT_USE_JASMIN */
#endif /* ZUPT_JASMIN_H */
