/*
 * Zupt — CPU Feature Detection
 * Copyright (c) 2026 Cristian Cezar Moisés — MIT License
 */
/**
 * @cond PORT
 * @file  zupt_cpuid.h
 * @brief Detecção de extensões de conjunto de instruções da CPU.
 * @details Declara a estrutura de recursos, a função de detecção e a
 * instância global lida pelo dispatch de src/zupt_crypto.c. A
 * detecção acontece em tempo de execução (instrução CPUID) e não em
 * tempo de compilação, o que permite que a mesma binária escolha o
 * caminho AES-NI/AVX quando o processador o oferece.
 * @see zupt_cpu_features_t, zupt_detect_cpu, zupt_cpu
 * @endcond
 * @cond INGLES
 * @file  zupt_cpuid.h
 * @brief Detection of CPU instruction set extensions.
 * @details Declares the features structure, the detection function and the
 * global instance read by the dispatch in src/zupt_crypto.c. Detection
 * happens at runtime (CPUID instruction) and not at compile
 * time, which allows the same binary to choose the
 * AES-NI/AVX path when the processor offers it.
 * @see zupt_cpu_features_t, zupt_detect_cpu, zupt_cpu
 * @endcond */
#ifndef ZUPT_CPUID_H
#define ZUPT_CPUID_H

#include <stdint.h>

/**
 * @cond PORT
 * @struct zupt_cpu_features_t
 * @brief Resultado da detecção de instruções do processador.
 * @details Cada campo assume 0 (ausente) ou 1 (presente), como exige o
 * contrato ACSL adjunto a zupt_detect_cpu(). Os bits indicados nos
 * comentários são os testados pelo protocolo CPUID descrito na
 * implementação.
 * @endcond
 * @cond INGLES
 * @struct zupt_cpu_features_t
 * @brief Result of the processor instruction detection.
 * @details Each field takes 0 (absent) or 1 (present), as required by the
 * ACSL contract attached to zupt_detect_cpu(). The bits shown in the
 * comments are the ones tested by the CPUID protocol described in the
 * implementation.
 * @endcond */
typedef struct {
    /**
     * @cond PORT
     * CPUID.01H:ECX[25] — instruções AES-NI
     * @endcond
     * @cond INGLES
     * CPUID.01H:ECX[25] — AES-NI instructions
     * @endcond */
    int has_aesni;
    /**
     * @cond PORT
     * AVX (SSE com codificação VEX) — exige CPUID e suporte XSAVE do sistema operacional
     * @endcond
     * @cond INGLES
     * AVX (SSE with VEX encoding) — requires CPUID and OS XSAVE support
     * @endcond */
    int has_avx;
    /**
     * @cond PORT
     * CPUID.01H:ECX[1]  — CLMUL (multiplicação sem carry)
     * @endcond
     * @cond INGLES
     * CPUID.01H:ECX[1]  — CLMUL (carry-less multiplication)
     * @endcond */
    int has_pclmul;
    /**
     * @cond PORT
     * CPUID.07H:EBX[5]  — AVX2 (SIMD de 256 bits)
     * @endcond
     * @cond INGLES
     * CPUID.07H:EBX[5]  — AVX2 (256-bit SIMD)
     * @endcond */
    int has_avx2;
    /**
     * @cond PORT
     * CPUID.01H:ECX[19] — SSE4.1
     * @endcond
     * @cond INGLES
     * CPUID.01H:ECX[19] — SSE4.1
     * @endcond */
    int has_sse41;
} zupt_cpu_features_t;

/**
 * @cond PORT
 * @brief Preenche a estrutura com as extensões presentes no processador.
 * @details Executa a sequência de instruções CPUID necessária e grava os
 * resultados em `f`. A implementação deve estar ligada ao programa:
 * o cabeçalho apenas declara a função.
 * @param[out] f Estrutura a preencher; todos os cinco campos são escritos.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho
 * mas não possui definição em `src/`. Quem consome zupt_cpu (por
 * exemplo o dispatch AES-NI em src/zupt_crypto.c) precisa, portanto, de
 * uma definição fornecida fora da biblioteca, ou o campo lê o valor
 * zero da instância global.
 * @see zupt_cpu
 * @endcond
 * @cond INGLES
 * @brief Fills the structure with the extensions present on the processor.
 * @details Executes the CPUID instruction sequence required and writes the
 * results into `f`. The implementation must be linked into the program:
 * the header only declares the function.
 * @param[out] f Structure to fill; all five fields are written.
 * @note In this repository revision, the symbol is declared in this header
 * but has no definition in `src/`. Code that consumes zupt_cpu (for
 * example the AES-NI dispatch in src/zupt_crypto.c) therefore needs
 * a definition provided outside the library, or else the field reads the
 * zero value of the global instance.
 * @see zupt_cpu
 * @endcond */
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
 * @cond PORT
 * @var zupt_cpu
 * @brief Instância global dos recursos de CPU, definida pelo programa
 * vinculador.
 * @details É declarada `extern` aqui; a leitura em src/zupt_crypto.c
 * (`zupt_cpu.has_aesni && zupt_cpu.has_avx`) decide o caminho
 * AES-NI/AVX do dispatch. Sem uma definição da variável, o link
 * falha; quando definida e não inicializada, os campos valem 0 e o
 * dispatch escolhe o caminho portátil.
 * @see zupt_detect_cpu
 * @endcond
 * @cond INGLES
 * @var zupt_cpu
 * @brief Global instance of the CPU features, defined by the program
 * that links the library.
 * @details It is declared `extern` here; the read in src/zupt_crypto.c
 * (`zupt_cpu.has_aesni && zupt_cpu.has_avx`) decides the
 * AES-NI/AVX dispatch path. Without a definition of the variable, linking
 * fails; when defined and not initialized, the fields equal 0 and the
 * dispatch chooses the portable path.
 * @see zupt_detect_cpu
 * @endcond */
extern zupt_cpu_features_t zupt_cpu;

#endif /* ZUPT_CPUID_H */
