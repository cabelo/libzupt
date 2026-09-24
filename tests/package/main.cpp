// SPDX-License-Identifier: MIT
#include <zupt.hpp>
#include <zupt_cxx.h>
#include <cstring>

int main() {
    if (std::strcmp(zupt::getVersion(), EXPECTED_VERSION) != 0) return 1;
    const auto keys = zupt::KeyGenerator().generateKeyPair();
    zupt::Encryptor encryptor(keys.public_key);
    const auto encrypted = encryptor.encryptMemory(std::vector<uint8_t>{1, 2, 3});
    const auto result = zupt::Decryptor(keys.secret_key).decryptMemory(
        encrypted.first, encrypted.second);
    return result == std::vector<uint8_t>{1, 2, 3} ? 0 : 1;
}
