// SPDX-License-Identifier: MIT
#include "zupt.hpp"
#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    static const auto keys = zupt::KeyGenerator().generateKeyPair();
    if (size < zupt::HYBRID_ENC_HEADER_SIZE) return 0;
    size_t length = 0;
    auto* result = zupt_hybrid_decrypt(keys.secret_key.data(), keys.secret_key.size(),
        data + zupt::HYBRID_ENC_HEADER_SIZE, size - zupt::HYBRID_ENC_HEADER_SIZE,
        data, zupt::HYBRID_ENC_HEADER_SIZE, &length);
    if (result) {
        zupt::secureWipe(result, length);
        zupt_free(result);
    }
    return 0;
}
