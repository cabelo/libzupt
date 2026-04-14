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
#include "zupt.h"
#include <stdio.h>

#if defined(__linux__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__APPLE__)
#include <sys/mman.h>

int zupt_mlock_keys(void *ptr, size_t len) {
    if (mlock(ptr, len) != 0) {
        fprintf(stderr, "  Warning: mlock() failed — keys may be swappable to disk\n");
        return -1;
    }
    return 0;
}

void zupt_munlock_keys(void *ptr, size_t len) {
    zupt_secure_wipe(ptr, len);
    munlock(ptr, len);
}

#elif defined(_WIN32)
#include <windows.h>

int zupt_mlock_keys(void *ptr, size_t len) {
    if (!VirtualLock(ptr, len)) {
        fprintf(stderr, "  Warning: VirtualLock() failed — keys may be swappable to disk\n");
        return -1;
    }
    return 0;
}

void zupt_munlock_keys(void *ptr, size_t len) {
    zupt_secure_wipe(ptr, len);
    VirtualUnlock(ptr, len);
}

#else
/* Fallback: no mlock available */
int zupt_mlock_keys(void *ptr, size_t len) {
    (void)ptr; (void)len;
    return -1;
}

void zupt_munlock_keys(void *ptr, size_t len) {
    zupt_secure_wipe(ptr, len);
}

#endif
