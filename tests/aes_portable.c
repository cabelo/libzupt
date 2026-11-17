/* AES-256 known-answer tests, including the forced portable algebraic S-box. */
#include "zupt.h"
#include <string.h>

int main(void) {
    static const uint8_t expected[16] = {
        0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,
        0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89};
    static const uint8_t zero_expected[16] = {
        0xdc,0x95,0xc0,0x78,0xa2,0x40,0x89,0x89,
        0xad,0x48,0xa2,0x14,0x92,0x84,0x20,0x87};
    uint8_t key[32], input[16], output[16];
    for (unsigned i = 0; i < 32; ++i) key[i] = (uint8_t)i;
    for (unsigned i = 0; i < 16; ++i) input[i] = (uint8_t)(17 * i);
    zupt_aes256_ctx ctx;
    zupt_aes256_init(&ctx, key);
    zupt_aes256_encrypt_block(&ctx, input, output);
    if (memcmp(output, expected, 16)) return 1;
    memset(key, 0, sizeof(key));
    memset(input, 0, sizeof(input));
    zupt_aes256_init(&ctx, key);
    zupt_aes256_encrypt_block(&ctx, input, output);
    return memcmp(output, zero_expected, 16) ? 1 : 0;
}
