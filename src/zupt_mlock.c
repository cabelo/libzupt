/*
 * Zupt — Memory Locking for Key Material
 * Copyright (c) 2026 Cristian Cezar Moisés
 * SPDX-License-Identifier: MIT
 *
 * Prevents key material from being swapped to disk.
 * Uses mlock() on Linux/BSD, VirtualLock() on Windows.
 * Failure is non-fatal (logged as warning) — some environments
 * restrict mlock to privileged processes (RLIMIT_MEMLOCK).
 *
 * Usage:
 *   zupt_mlock_keys(&kr, sizeof(kr));   // After key derivation
 *   zupt_munlock_keys(&kr, sizeof(kr)); // After archive complete
 */
/**
 * @file  zupt_mlock.c
 * @brief Bloqueio de memória para material de chave, por plataforma.
 * @details O módulo oferece um par de funções que tentam impedir que regiões
 *          com material de chave sejam trocadas para disco (swapping) e, ao
 *          final do uso, limpam a região antes de liberar o bloqueio.
 *
 *          A escolha do mecanismo é feita em tempo de compilação:
 *          - Linux, FreeBSD, OpenBSD, NetBSD e Apple: `mlock()`/`munlock()`
 *            de `<sys/mman.h>`.
 *          - Windows (`_WIN32`): `VirtualLock()`/`VirtualUnlock()` de
 *            `<windows.h>`.
 *          - Demais plataformas: não há mecanismo; zupt_mlock_keys() apenas
 *            devolve -1 e zupt_munlock_keys() só executa a limpeza.
 *
 *          Nenhum dos caminhos propaga erro fatal: falha de bloqueio é
 *          reportada em `stderr` e devolve -1, pois ambientes com
 *          `RLIMIT_MEMLOCK` restrito (containers, contas sem privilégio)
 *          recusam o bloqueio. O chamador deve tratar -1 como "material de
 *          chave continua swappable", e não como falha da operação criptográfica.
 * @see zupt_secure_wipe, zupt_keyring_t
 */
#include "zupt.h"
#include <stdio.h>

#if defined(__linux__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__APPLE__)
#include <sys/mman.h>

/**
 * @brief Bloqueia uma região de memória contra swapping (POSIX/BSD/Apple).
 * @details Chama `mlock(ptr, len)`. Em caso de recusa do sistema, imprime um
 *          aviso em `stderr` e devolve -1, sem alterar o conteúdo da região.
 * @param[in,out] ptr Início da região a bloquear (normalmente um
 *                    zupt_keyring_t ou buffer com material de chave).
 * @param[in]     len Quantidade de bytes da região.
 * @retval 0  Região bloqueada.
 * @retval -1 Sistema recusou o bloqueio (por exemplo limite de memória
 *            bloqueável); a região permanece potencialmente swapável.
 * @note Em muitos sistemas o bloqueio é arredondado aos limites de página;
 *       páginas compartilhadas com outro mapeamento podem não ser bloqueadas
 *       da forma esperada.
 * @see zupt_munlock_keys
 */
int zupt_mlock_keys(void *ptr, size_t len) {
    if (mlock(ptr, len) != 0) {
        fprintf(stderr, "  Warning: mlock() failed — keys may be swappable to disk\n");
        return -1;
    }
    return 0;
}

/**
 * @brief Limpa a região e remove o bloqueio de memória (POSIX/BSD/Apple).
 * @details Executa primeiro zupt_secure_wipe() e só depois `munlock()`, de
 *          modo que o conteúdo sensível seja zerado enquanto a página ainda
 *          está garantidamente residente. O retorno de `munlock()` não é
 *          verificado.
 * @param[in,out] ptr Início da região a limpar e desbloquear.
 * @param[in]     len Quantidade de bytes da região.
 * @note A função não devolve código de erro: a limpeza é feita
 *       independentemente do resultado de `munlock()`.
 * @see zupt_mlock_keys, zupt_secure_wipe
 */
void zupt_munlock_keys(void *ptr, size_t len) {
    zupt_secure_wipe(ptr, len);
    munlock(ptr, len);
}

#elif defined(_WIN32)
#include <windows.h>

/**
 * @brief Bloqueia uma região de memória contra swapping (Windows).
 * @details Chama `VirtualLock(ptr, len)`. Em caso de recusa, imprime um aviso
 *          em `stderr` e devolve -1.
 * @param[in,out] ptr Início da região a bloquear.
 * @param[in]     len Quantidade de bytes da região.
 * @retval 0  Região bloqueada.
 * @retval -1 `VirtualLock()` falhou; a região permanece potencialmente
 *            swapável.
 * @note O Windows também limita a memória bloqueável por processo
 *       (quota de working set), então falhas são esperadas em regiões grandes.
 * @see zupt_munlock_keys
 */
int zupt_mlock_keys(void *ptr, size_t len) {
    if (!VirtualLock(ptr, len)) {
        fprintf(stderr, "  Warning: VirtualLock() failed — keys may be swappable to disk\n");
        return -1;
    }
    return 0;
}

/**
 * @brief Limpa a região e remove o bloqueio de memória (Windows).
 * @details Chama zupt_secure_wipe() antes de `VirtualUnlock()`. O retorno de
 *          `VirtualUnlock()` não é verificado.
 * @param[in,out] ptr Início da região a limpar e desbloquear.
 * @param[in]     len Quantidade de bytes da região.
 * @see zupt_mlock_keys, zupt_secure_wipe
 */
void zupt_munlock_keys(void *ptr, size_t len) {
    zupt_secure_wipe(ptr, len);
    VirtualUnlock(ptr, len);
}

#else
/* Fallback: no mlock available */
/**
 * @brief Bloqueio de memória indisponível nesta plataforma.
 * @details Este ramo é compilado quando a plataforma não é nem POSIX/BSD/Apple
 *          nem Windows. Não existe mecanismo de bloqueio, de modo que os
 *          argumentos são ignorados.
 * @param[in,out] ptr Ignorado neste ramo.
 * @param[in]     len Ignorado neste ramo.
 * @retval -1 Sempre, indicando que o material de chave não pôde ser
 *            bloqueado contra swapping.
 * @see zupt_munlock_keys
 */
int zupt_mlock_keys(void *ptr, size_t len) {
    (void)ptr; (void)len;
    return -1;
}

/**
 * @brief Apenas limpa a região (plataforma sem bloqueio de memória).
 * @details Sem mecanismo nativo de desbloqueio, resta executar a limpeza
 *          segura do material de chave.
 * @param[in,out] ptr Início da região a limpar.
 * @param[in]     len Quantidade de bytes da região.
 * @see zupt_secure_wipe
 */
void zupt_munlock_keys(void *ptr, size_t len) {
    zupt_secure_wipe(ptr, len);
}

#endif
