/*
 * Zupt — Backup-oriented compression with AES-256 encryption
 * Copyright (c) 2026 Cristian Cezar Moisés
 * SPDX-License-Identifier: MIT
 *
 * ML-KEM-768 (FIPS 203, formerly CRYSTALS-Kyber).
 * Post-quantum key encapsulation mechanism.
 *
 * Parameters (ML-KEM-768):
 *   k = 3, η₁ = 2, η₂ = 2, d_u = 10, d_v = 4
 *   Public key:  1184 bytes
 *   Secret key:  2400 bytes
 *   Ciphertext:  1088 bytes
 *   Shared secret: 32 bytes
 *
 * SECURITY NOTE: This implementation must undergo independent review
 * before deployment in high-assurance contexts. It targets correctness
 * against NIST test vectors and constant-time operation.
 */
/**
 * @file   zupt_mlkem.h
 * @brief  Interface pública do KEM pós-quântico ML-KEM-768 (FIPS 203).
 * @details Este cabeçalho expõe a geração de chaves, o encapsulamento e o
 *          decapsulamento do mecanismo de encapsulamento de chave ML-KEM na
 *          parameterização 768, sobre o anel de polinômios
 *          R = Z_q[x]/(x^256 + 1), com q = 3329.
 *
 *          Layout dos objetos, conforme as constantes abaixo e a seção 5 de
 *          FIPS 203:
 *          - chave pública (encapsulation key): 1184 = 3*256*12/8 (t_hat em
 *            ByteEncode_12) + 32 (semente rho);
 *          - chave secreta (decapsulation key): 2400 = 1152 (s em
 *            ByteEncode_12) + 1184 (chave pública copiada) + 32 (SHA3-256 da
 *            chave pública, em sk[2336..2367], tag verificada por
 *            zupt_mlkem768_secret_key_check()) + 32 (semente z, em
 *            sk[2368..2399]); a semente d usada apenas em KeyGen não é
 *            armazenada;
 *          - texto cifrado: 1088 = 3*256*10/8 (u comprimido em 10 bits) +
 *            256*4/8 (v comprimido em 4 bits);
 *          - segredo compartilhado: 32 bytes.
 *
 *          O decapsulamento aplica a transformação Fujisaki-Okamoto: um texto
 *          cifrado inválido não produz erro; produz um valor pseudoraleativo
 *            derivado de z e do texto cifrado ("implicit rejection"),
 *          de modo que o chamador não possa distinguir falha de sucesso a
 *          partir do retorno.
 *
 *          Nota: o cabeçalho de licença acima declara, como objetivo, a
 *          correção contra vetores de teste do NIST e operação em tempo
 *          constante; os mecanismos concretos usados para isso estão
 *          descritos na implementação (src/zupt_mlkem.c). Esta interface não
 *          faz garantias de ausência de canais laterais por si só.
 */
#ifndef ZUPT_MLKEM_H
#define ZUPT_MLKEM_H

#include <stdint.h>

/** @brief Dimensão k do KEM (ML-KEM-768 usa k = 3). */
#define MLKEM_K     3
/** @brief Grau do anel de polinômios: número de coeficientes por polinômio (x^256 + 1). */
#define MLKEM_N     256
/** @brief Módulo do anel: q = 3329 (primo, 12 bits). */
#define MLKEM_Q     3329
/** @brief Parâmetro de distribuição binomial centrada usada para a chave e o ruído vetorial. */
#define MLKEM_ETA1  2
/** @brief Parâmetro de distribuição binomial centrada usada para o ruído escalar. */
#define MLKEM_ETA2  2
/** @brief Bits mantidos na compressão do componente u do texto cifrado. */
#define MLKEM_DU    10
/** @brief Bits mantidos na compressão do componente v do texto cifrado. */
#define MLKEM_DV    4

/** @brief Tamanho, em bytes, da chave pública (encapsulation key) de saída/entrada. */
#define MLKEM_PUBLICKEYBYTES    1184
/** @brief Tamanho, em bytes, da chave secreta (decapsulation key). */
#define MLKEM_SECRETKEYBYTES    2400
/** @brief Tamanho, em bytes, do texto cifrado. */
#define MLKEM_CIPHERTEXTBYTES   1088
/** @brief Tamanho, em bytes, do segredo compartilhado. */
#define MLKEM_SSBYTES           32

/**
 * @brief Verificação de formato da chave pública (FIPS 203, Algoritmo 20).
 * @details Aplica ByteDecode_12/ByteEncode_12 sobre os 1152 bytes do
 *          componente t_hat (os 32 bytes finais de rho não são verificados) e
 *          acumula, com OR bit a bit, os casos em que qualquer dos dois
 *          coeficientes decodificados de cada triade de bytes é maior ou igual
 *          a q = 3329. Não aceita a chave como válida a partir de qualquer
 *          teste criptográfico: apenas da codificação.
 * @param[in] pk Chave pública a verificar; exatamente 1184 bytes legíveis.
 * @return   0 para codificação válida, -1 para chave inválida.
 * @retval   0  Todos os 384 pares de coeficientes de t_hat são menores que q.
 * @retval   -1 `pk` é ponteiro nulo, ou algum coeficiente decodificado é
 *              >= 3329.
 * @note     Não altera o conteúdo de `pk` e não limpa memória interna.
 * @see      zupt_mlkem768_encaps()
 */
int zupt_mlkem768_public_key_check(const uint8_t pk[1184]);

/**
 * @brief Verificação de integridade da chave secreta por hash (FIPS 203, Algoritmo 21).
 * @details Recomputa SHA3-256 sobre os 1184 bytes da chave pública embutida na
 *          chave secreta (offset 1152) e compara, com OR bit a bit sobre os 32
 *          bytes, com o campo de verificação gravado em offset 2336.
 * @param[in] sk Chave secreta a verificar; exatamente 2400 bytes legíveis.
 * @return   0 se o hash confere, -1 caso contrário.
 * @retval   0  SHA3-256(sk[1152..2335]) == sk[2336..2367].
 * @retval   -1 `sk` é ponteiro nulo, ou o hash não confere.
 * @note     O buffer de hash temporário é limpo com zupt_secure_wipe() antes
 *           do retorno. A comparação percorre os 32 bytes inteiros (sem saída
 *           antecipada).
 */
int zupt_mlkem768_secret_key_check(const uint8_t sk[2400]);

/**
 * @brief KeyGen: gera um par de chaves ML-KEM-768.
 * @details Obtém duas sementes aleatórias de 32 bytes (`d` e `z`) do gerador
 *          do library e deriva delas a chave K-PKE e a chave decapsulation,
 *          conforme detalhado em mlkem_keygen_internal() (src/zupt_mlkem.c).
 * @param[out] pk Chave pública de saída (1184 bytes, layout acima).
 * @param[out] sk Chave secreta de saída (2400 bytes, layout acima).
 * @return   0 em caso de sucesso.
 * @retval   0   Chaves geradas e escritas por completo.
 * @retval   -1  `pk` ou `sk` é ponteiro nulo.
 * @post     `sk` contém a chave pública em sk[1152..2335], o SHA3-256 dela em
 *           sk[2336..2367] e a semente z em sk[2368..2399].
 * @note     As sementes temporárias são limpas antes do retorno.
 * @see      zupt_mlkem768_encaps(), zupt_mlkem768_decaps()
 */
int zupt_mlkem768_keygen(uint8_t pk[MLKEM_PUBLICKEYBYTES],
                          uint8_t sk[MLKEM_SECRETKEYBYTES]);

/**
 * @brief Encapsulate: produz texto cifrado e segredo compartilhado a partir da chave pública.
 * @details Verifica a chave pública, gera uma mensagem `m` aleatória de 32
 *          bytes, deriva (ko, kr) = G(m || H(pk)) com SHA3-512, criptografa
 *          `m` sob `pk` com aleatoriedade kr[32..63] e devolve ko. O segredo
 *          compartilhado é o primeiro bloco de 32 bytes de G, sem KDF final
 *          adicional.
 * @param[out] ct Texto cifrado de saída (1088 bytes).
 * @param[out] ss Segredo compartilhado de saída (32 bytes).
 * @param[in]  pk Chave pública de entrada (1184 bytes).
 * @return    0 em caso de sucesso.
 * @retval    0   Texto cifrado e segredo escritos.
 * @retval    -1  `ct`, `ss` ou `pk` é nulo, ou a chave pública rejeita na
 *                 verificação de codificação de zupt_mlkem768_public_key_check().
 * @post      `m` é limpo antes do retorno.
 * @see       zupt_mlkem768_public_key_check()
 */
int zupt_mlkem768_encaps(uint8_t ct[MLKEM_CIPHERTEXTBYTES],
                          uint8_t ss[MLKEM_SSBYTES],
                          const uint8_t pk[MLKEM_PUBLICKEYBYTES]);

/**
 * @brief Decapsulate: recupera o segredo compartilhado a partir do texto cifrado e da chave secreta.
 * @details Descomprime o texto cifrado, executa a decifração K-PKE para obter
 *          a mensagem `m`, recriptografa `m` com a chave pública embutida na
 *          chave secreta e compara o resultado byte a byte com o texto cifrado
 *          recebido. Em caso de igualdade, o segredo é ko = G(m || H(pk))[0..31];
 *          em caso de diferença, o segredo é J(z || c) = SHAKE-256(z || c).
 *          A escolha entre os dois valores é feita por seleção condicional.
 * @param[out] ss Segredo compartilhado de saída (32 bytes).
 * @param[in]  ct Texto cifrado de entrada (1088 bytes).
 * @param[in]  sk Chave secreta de entrada (2400 bytes).
 * @return    0 em caso de sucesso.
 * @retval    0  Segredo escrito — inclusive quando o texto cifrado é inválido
 *                (rejeição implícita).
 * @retval    -1 `ss`, `ct` ou `sk` é nulo, ou a chave secreta falha na
 *                verificação de hash de zupt_mlkem768_secret_key_check().
 * @warning   CT-REQUIRED: Implicit rejection — invalid ciphertext produces a
 *            pseudorandom shared secret (no distinguishable failure). A
 *            igualdade de saída entre texto cifrado válido e inválido é
 *            observável apenas no valor, não no código de retorno.
 * @post      Todas as variáveis intermediárias sensíveis da pilha são limpas
 *            antes do retorno.
 * @see       zupt_mlkem768_secret_key_check()
 */
int zupt_mlkem768_decaps(uint8_t ss[MLKEM_SSBYTES],
                          const uint8_t ct[MLKEM_CIPHERTEXTBYTES],
                          const uint8_t sk[MLKEM_SECRETKEYBYTES]);

#endif
