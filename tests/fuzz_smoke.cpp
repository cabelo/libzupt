// SPDX-License-Identifier: MIT
#include "zupt.hpp"
#include <iostream>

int main() {
    const auto keys = zupt::KeyGenerator().generateKeyPair();
    const std::vector<uint8_t> input(73, 0x51);
    const auto sealed = zupt::Encryptor(keys.public_key).encryptMemory(input);
    size_t cases = 0;
    auto reject = [&](const std::vector<uint8_t>& ct, const std::vector<uint8_t>& hdr) {
        size_t length = 123;
        auto* result = zupt_hybrid_decrypt(keys.secret_key.data(), keys.secret_key.size(),
            ct.data(), ct.size(), hdr.data(), hdr.size(), &length);
        const bool rejected = !result && length == 0;
        zupt_free(result);
        ++cases;
        if (!rejected) throw std::runtime_error("Altered envelope was accepted");
    };
    try {
        for (size_t i = 0; i < sealed.first.size(); ++i) {
            auto ct = sealed.first;
            ct[i] ^= static_cast<uint8_t>(1u << (i % 8));
            reject(ct, sealed.second);
        }
        for (size_t i = 0; i < sealed.second.size(); ++i) {
            auto header = sealed.second;
            header[i] ^= static_cast<uint8_t>(1u << (i % 8));
            reject(sealed.first, header);
        }
        for (size_t i = 0; i < sealed.first.size(); ++i) {
            auto ct = sealed.first;
            ct.resize(i);
            reject(ct, sealed.second);
        }
        std::cout << cases << " mutation/truncation rejection cases passed\n";
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
