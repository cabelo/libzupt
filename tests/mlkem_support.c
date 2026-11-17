/* Deterministic KAT support only; never part of an installed library. */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
void zupt_secure_wipe(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) *p++ = 0;
}
void zupt_random_bytes(uint8_t *ptr, size_t len) {
    (void)ptr;
    (void)len;
    /* KATs must use explicit official seeds, never replacement randomness. */
    abort();
}
