// SPDX-License-Identifier: MIT
#include "zupt.hpp"
#include <cstdio>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>

static std::vector<uint8_t> read(const std::string& path) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) throw std::runtime_error("Cannot read " + path);
    std::vector<uint8_t> result((std::istreambuf_iterator<char>(stream)), {});
    if (stream.bad()) throw std::runtime_error("Read failed: " + path);
    return result;
}

static void writeNew(const std::string& path, const std::vector<uint8_t>& data) {
    FILE* file = std::fopen(path.c_str(), "wbx");
    if (!file) throw std::runtime_error("Cannot create a new output file: " + path);
    const auto count = std::fwrite(data.data(), 1, data.size(), file);
    const auto close = std::fclose(file);
    if (count != data.size() || close != 0) throw std::runtime_error("Write failed: " + path);
}

int main(int argc, char** argv) {
    if (argc != 7) {
        std::cerr << "Usage: zupt_migrate old-private.key old-ciphertext old-header "
                     "trusted-plaintext-sha256 new-public.key new-ciphertext\n"
                     "Obtain the expected digest from an independent trusted source.\n";
        return 2;
    }
    try {
        const std::string digestText(argv[4]);
        if (digestText.size() != 64) throw std::runtime_error("Expected a 64-digit SHA-256");
        uint8_t digest[32];
        auto nibble = [](char c) -> unsigned {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            throw std::runtime_error("Invalid SHA-256 digit");
        };
        for (unsigned i = 0; i < 32; ++i)
            digest[i] = static_cast<uint8_t>((nibble(digestText[2*i]) << 4) | nibble(digestText[2*i+1]));
        auto keyBytes = read(argv[1]);
        zupt::SecureBuffer key(keyBytes.data(), keyBytes.size());
        zupt::secureWipe(keyBytes.data(), keyBytes.size());
        const auto ciphertext = read(argv[2]);
        const auto header = read(argv[3]);
        size_t length = 0;
        auto* raw = zupt_hybrid_decrypt_legacy(key.data(), key.size(),
            ciphertext.data(), ciphertext.size(), header.data(), header.size(), digest, &length);
        if (!raw) throw std::runtime_error("Legacy recovery or trusted digest verification failed");
        auto cleanup = [length](uint8_t* ptr) {
            zupt::secureWipe(ptr, length);
            zupt_free(ptr);
        };
        std::unique_ptr<uint8_t, decltype(cleanup)> plaintext(raw, cleanup);
        const auto publicKey = zupt::KeyGenerator().loadPublicKey(argv[5]);
        auto encrypted = zupt::Encryptor(publicKey).encryptMemory(plaintext.get(), length);
        plaintext.reset();
        writeNew(argv[6], encrypted.first);
        writeNew(std::string(argv[6]) + ".header", encrypted.second);
        std::cout << "Recovered digest verified; wrote a v2 envelope and its header.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
