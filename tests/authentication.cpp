// SPDX-License-Identifier: MIT
#include "zupt.hpp"
#include "zupt_cxx.h"
#include <algorithm>
#include <cstdlib>
#include <iostream>

static int failures = 0;

static void check(bool ok, const char* message) {
    if (!ok) {
        std::cerr << "FAIL: " << message << '\n';
        ++failures;
    }
}

static void rejects(zupt::Decryptor& decryptor, const zupt::KeyPair& keys,
                    const std::vector<uint8_t>& ciphertext,
                    const std::vector<uint8_t>& header, const char* message) {
    bool rejected = false;
    try {
        decryptor.decryptMemory(ciphertext, header);
    } catch (const zupt::ZuptError& error) {
        rejected = error.code() == zupt::ErrorCode::ERR_AUTH_FAIL;
    }
    check(rejected, message);
    size_t size = 0;
    auto* result = zupt_hybrid_decrypt(keys.secret_key.data(), keys.secret_key.size(),
        ciphertext.data(), ciphertext.size(), header.data(), header.size(), &size);
    check(result == nullptr, message);
    std::free(result);
}

int main() {
    const auto keys = zupt::KeyGenerator().generateKeyPair();
    zupt::Encryptor encryptor(keys.public_key);
    zupt::Decryptor decryptor(keys.secret_key);
    auto [empty, emptyHeader] = encryptor.encryptMemory(nullptr, 0);
    check(empty.size() == 52, "empty plaintext must carry an authenticated record");
    check(decryptor.decryptMemory(empty, emptyHeader).empty(), "empty roundtrip");
    rejects(decryptor, keys, {}, emptyHeader, "reject missing ciphertext");
    if (!empty.empty()) {
        empty.back() ^= 1;
        rejects(decryptor, keys, empty, emptyHeader, "authenticate empty record");
    }

    constexpr size_t blockSize = 4 * 1024 * 1024;
    std::vector<uint8_t> input(2 * blockSize, 0x41);
    std::fill(input.begin() + blockSize, input.end(), 0x42);
    auto [ciphertext, header] = encryptor.encryptMemory(input);
    check(decryptor.decryptMemory(ciphertext, header) == input, "two-block roundtrip");
    auto changed = ciphertext;
    std::rotate(changed.begin(), changed.begin() + blockSize + 52, changed.end());
    rejects(decryptor, keys, changed, header, "reject reordered blocks");
    changed = ciphertext;
    std::copy(ciphertext.begin(), ciphertext.begin() + blockSize + 52,
              changed.begin() + blockSize + 52);
    rejects(decryptor, keys, changed, header, "reject replayed block");
    changed = ciphertext;
    changed.resize(changed.size() + 52, 0);
    rejects(decryptor, keys, changed, header, "reject unauthenticated zero terminator");
    changed = ciphertext;
    changed.pop_back();
    rejects(decryptor, keys, changed, header, "reject truncated block");
    changed = ciphertext;
    std::fill(changed.begin(), changed.begin() + 4, 0xff);
    rejects(decryptor, keys, changed, header, "reject overflowing record length");
    changed[0] = 1;
    changed[1] = 0;
    changed[2] = 0x40;
    changed[3] = 0;
    rejects(decryptor, keys, changed, header, "reject payload beyond block limit");
    header.back() ^= 1;
    rejects(decryptor, keys, ciphertext, header, "authenticate header nonce");
    return failures ? 1 : 0;
}
