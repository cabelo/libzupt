/*
 * Zupt — Backup-oriented compression with AES-256 encryption
 * Copyright (c) 2026 Cristian Cezar Moisés
 * SPDX-License-Identifier: MIT
 *
 * X25519 Diffie-Hellman key agreement (RFC 7748).
 * Montgomery ladder — constant-time by construction.
 */
/**
 * @file   zupt_x25519.h
 * @brief  Interface pública da concordância de chave X25519 (RFC 7748).
 * @details Expõe a função Diffie-Hellman da curva Montgomery Curve25519, que
 *          calcula a multiplicação escalar do ponto de coordenada afim `u`
 *          fornecido pelo escalar de 32 bytes, retornando a coordenada u do
 *          resultado em 32 bytes little-endian (a coordenada v não é
 *          reconstruída nem verificada).
 *
 *          A aritmética do corpo GF(2^255 - 19) usa 5 limbos de 51 bits
 *          internamente. A multiplicação é o produto escolar 5×51 cujos
 *          termos de índice ≥ 5 são dobrados de volta multiplicados por 19
 *          (2^255 ≡ 19 mod p), seguida de propagação de carry; a inversão é
 *          exponenciação binária por z^(2^255-21) = z^(p-2) (ver
 *          src/zupt_x25519.c).
 *
 *          Não há verificação de subgrupo, de ponto de ordem baixa, nem de
 *          igualdade a zero: a função sempre escreve 32 bytes. Cabe ao
 *          chamador rejeitar resultados todo-zero — o consumidor interno
 *          as rotinas internas `hybrid_encrypt_core` e
 *          `hybrid_decrypt_core`, de `src/zupt_crypto.c`, em
 *          src/zupt_crypto.c faz essa checagem antes de derivar chaves.
 *
 *          Nota: o cabeçalho de licença acima afirma "constant-time by
 *          construction". Os mecanismos observáveis correspondentes estão
 *          descritos na implementação; esta interface não faz garantias
 *          próprias.
 * @see    src/zupt_x25519.c
 */
#ifndef ZUPT_X25519_H
#define ZUPT_X25519_H

#include <stdint.h>

/**
 * @brief X25519(scalar, point) → result. All inputs/outputs are 32 bytes.
 * @details Copia o escalar, aplica o clamping da RFC 7748 (bit 0,1,2 de
 *          byte 0 zerados; bit 255 zerado; bit 254 posto a 1), executa a
 *          escada de Montgomery sobre os bits 254..0 do escalar tratado com
 *          máscara, inverte a coordenada z por exponenciação
 *          (z^(2^255-21)) e multiplica por x para obter a coordenada afim.
 *          Nenhum valor de entrada é rejeitado: qualquer sequência de 32
 *          bytes é aceita como ponto e como escalar.
 * @param[out] out    Coordenada u do resultado (32 bytes little-endian).
 * @param[in]  scalar Escalar privado (32 bytes little-endian; é clampado
 *                    internamente, a cópia de entrada não é alterada).
 * @param[in]  point  Coordenada u do ponto de entrada (32 bytes
 *                    little-endian; a máscara de bit alto do byte 31 é
 *                    aplicada na decodificação do corpo).
 * @note     CT-REQUIRED: Montgomery ladder is inherently constant-time. A
 *           ordem de operações por iteração é fixa e a seleção do ponto é
 *           feita por troca condicional (fe_cswap), sem ramificação sobre o
 *           bit do escalar.
 * @warning  `out` não deve sobrepor `scalar` nem `point`, conforme os
 *           requisitos ACSL `\separated` adjuntos à implementação.
 * @pre      Os três buffers têm exatamente 32 bytes válidos.
 * @see      zupt_x25519_base()
 */
void zupt_x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]);

/**
 * @brief X25519 com o ponto base padrão (u = 9).
 * @details Monta em pilha o vetor little-endian do ponto base (byte 0 = 9,
 *          demais bytes zero) e delega a zupt_x25519(). Usado para
 *          geração de chave: public = X25519(private, basepoint).
 * @param[out] out    Chave pública resultante (32 bytes).
 * @param[in]  scalar Escalar privado (32 bytes, clampado internamente).
 * @note     Equivalente a zupt_x25519(out, scalar, basepoint) com basepoint
 *           = {9, 0, ...}. Não valida o escalar além do clamping.
 * @see      zupt_x25519()
 */
void zupt_x25519_base(uint8_t out[32], const uint8_t scalar[32]);

#endif
