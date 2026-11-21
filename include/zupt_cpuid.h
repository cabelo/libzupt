/*
 * Zupt — CPU Feature Detection
 * Copyright (c) 2026 Cristian Cezar Moisés — MIT License
 */
/**
 * @file  zupt_cpuid.h
 * @brief Detecção de extensões de conjunto de instruções da CPU.
 * @details Declara a estrutura de recursos, a função de detecção e a
 *          instância global lida pelo dispatch de src/zupt_crypto.c. A
 *          detecção acontece em tempo de execução (instrução CPUID) e não em
 *          tempo de compilação, o que permite que a mesma binária escolha o
 *          caminho AES-NI/AVX quando o processador o oferece.
 * @see zupt_cpu_features_t, zupt_detect_cpu, zupt_cpu
 */
#ifndef ZUPT_CPUID_H
#define ZUPT_CPUID_H

#include <stdint.h>

/**
 * @struct zupt_cpu_features_t
 * @brief Resultado da detecção de instruções do processador.
 * @details Cada campo assume 0 (ausente) ou 1 (presente), como exige o
 *          contrato ACSL adjunto a zupt_detect_cpu(). Os bits indicados nos
 *          comentários são os testados pelo protocolo CPUID descrito na
 *          implementação.
 */
typedef struct {
    int has_aesni;   /**< CPUID.01H:ECX[25] — instruções AES-NI */
    int has_avx;     /**< AVX (SSE com codificação VEX) — exige CPUID e suporte XSAVE do sistema operacional */
    int has_pclmul;  /**< CPUID.01H:ECX[1]  — CLMUL (multiplicação sem carry) */
    int has_avx2;    /**< CPUID.07H:EBX[5]  — AVX2 (SIMD de 256 bits) */
    int has_sse41;   /**< CPUID.01H:ECX[19] — SSE4.1 */
} zupt_cpu_features_t;

/**
 * @brief Preenche a estrutura com as extensões presentes no processador.
 * @details Executa a sequência de instruções CPUID necessária e grava os
 *          resultados em `f`. A implementação deve estar ligada ao programa:
 *          o cabeçalho apenas declara a função.
 * @param[out] f Estrutura a preencher; todos os cinco campos são escritos.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho
 *       mas não possui definição em `src/`. Quem consome zupt_cpu (por
 *       exemplo o dispatch AES-NI em src/zupt_crypto.c) precisa, portanto, de
 *       uma definição fornecida fora da biblioteca, ou o campo lê o valor
 *       zero da instância global.
 * @see zupt_cpu
 */
/*@ assigns f->has_aesni, f->has_avx, f->has_pclmul, f->has_avx2, f->has_sse41;
  @ ensures f->has_aesni == 0 || f->has_aesni == 1;
  @ ensures f->has_avx == 0 || f->has_avx == 1;
  @ ensures f->has_pclmul == 0 || f->has_pclmul == 1;
  @ ensures f->has_avx2 == 0 || f->has_avx2 == 1;
  @ ensures f->has_sse41 == 0 || f->has_sse41 == 1;
*/
void zupt_detect_cpu(zupt_cpu_features_t *f);

/* Global instance — set once at program start */
/**
 * @var zupt_cpu
 * @brief Instância global dos recursos de CPU, definida pelo programa
 *        vinculador.
 * @details É declarada `extern` aqui; a leitura em src/zupt_crypto.c
 *          (`zupt_cpu.has_aesni && zupt_cpu.has_avx`) decide o caminho
 *          AES-NI/AVX do dispatch. Sem uma definição da variável, o link
 *          falha; quando definida e não inicializada, os campos valem 0 e o
 *          dispatch escolhe o caminho portátil.
 * @see zupt_detect_cpu
 */
extern zupt_cpu_features_t zupt_cpu;

#endif /* ZUPT_CPUID_H */
