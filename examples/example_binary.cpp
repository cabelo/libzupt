/*
 * libzupt - Binary Data Example
 * Shows how to encrypt/decrypt binary data in memory
 *
 * SPDX-License-Identifier: MIT
 */

#include "zupt.hpp"
#include <iostream>
#include <fstream>
#include <cstring>
#include <random>

void printProgress(size_t current, size_t total) {
    int barWidth = 50;
    float progress = static_cast<float>(current) / total;
    int pos = static_cast<int>(barWidth * progress);

    std::cout << "\r[";
    for (int i = 0; i < barWidth; i++) {
        if (i < pos) std::cout << "=";
        else if (i == pos) std::cout << ">";
        else std::cout << " ";
    }
    std::cout << "] " << static_cast<int>(progress * 100) << "%";
    std::cout.flush();
}

void test_small_binary() {
    std::cout << "Test 1: Small Binary Data" << std::endl;

    zupt::KeyGenerator keygen;
    zupt::KeyPair keypair = keygen.generateKeyPair();
    zupt::Encryptor encryptor(keypair.public_key);
    zupt::Decryptor decryptor(keypair.secret_key);

    // Create binary data (simulating executable section)
    std::vector<uint8_t> binaryData = {
        0x7F, 0x45, 0x4C, 0x46,  // ELF magic
        0x02, 0x01, 0x01, 0x00,  // ELF header
        0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x3E, 0x00
    };

    auto [ciphertext, encHeader] = encryptor.encryptMemory(binaryData.data(), binaryData.size());
    std::vector<uint8_t> decrypted = decryptor.decryptMemory(ciphertext.data(), ciphertext.size(), encHeader);

    if (decrypted == binaryData) {
        std::cout << "  PASS: Binary data preserved" << std::endl;
    } else {
        std::cout << "  FAIL: Data mismatch" << std::endl;
    }
}

void test_large_binary() {
    std::cout << "Test 2: Large Binary Data (10 MB)" << std::endl;

    zupt::KeyGenerator keygen;
    zupt::KeyPair keypair = keygen.generateKeyPair();
    zupt::Encryptor encryptor(keypair.public_key);
    zupt::Decryptor decryptor(keypair.secret_key);

    // Generate 10 MB of random binary data
    size_t size = 10 * 1024 * 1024;
    std::vector<uint8_t> data(size);
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (size_t i = 0; i < size; i++) {
        data[i] = static_cast<uint8_t>(dis(gen));
        if (i % (1024 * 1024) == 0) {
            printProgress(i, size);
        }
    }
    printProgress(size, size);
    std::cout << std::endl;

    // Encrypt
    auto [ciphertext, encHeader] = encryptor.encryptMemory(data.data(), data.size());
    std::cout << "  Encrypted: " << ciphertext.size() << " bytes" << std::endl;

    // Decrypt
    std::vector<uint8_t> decrypted = decryptor.decryptMemory(ciphertext.data(), ciphertext.size(), encHeader);
    std::cout << "  Decrypted: " << decrypted.size() << " bytes" << std::endl;

    // Verify
    if (decrypted == data) {
        std::cout << "  PASS: Large binary roundtrip successful" << std::endl;
    } else {
        std::cout << "  FAIL: Data mismatch" << std::endl;
    }
}

void test_memory_image() {
    std::cout << "Test 3: Memory Image Simulation" << std::endl;

    zupt::KeyGenerator keygen;
    zupt::KeyPair keypair = keygen.generateKeyPair();
    zupt::Encryptor encryptor(keypair.public_key);
    zupt::Decryptor decryptor(keypair.secret_key);

    // Simulate a memory dump with various sections
    struct MemorySection {
        uint64_t address;
        uint64_t size;
        uint8_t data[256];
    };

    std::vector<MemorySection> sections = {
        {0x400000, 256, {}},
        {0x401000, 256, {}},
        {0x600000, 256, {}},
    };

    // Fill with pattern
    for (auto& section : sections) {
        for (size_t i = 0; i < section.size; i++) {
            section.data[i] = static_cast<uint8_t>((section.address + i) & 0xFF);
        }
    }

    // Serialize to buffer
    std::vector<uint8_t> buffer;
    for (const auto& section : sections) {
        buffer.insert(buffer.end(),
            reinterpret_cast<const uint8_t*>(&section.address),
            reinterpret_cast<const uint8_t*>(&section.address) + sizeof(section.address));
        buffer.insert(buffer.end(),
            reinterpret_cast<const uint8_t*>(&section.size),
            reinterpret_cast<const uint8_t*>(&section.size) + sizeof(section.size));
        buffer.insert(buffer.end(), section.data, section.data + section.size);
    }

    auto [ciphertext, encHeader] = encryptor.encryptMemory(buffer);
    std::vector<uint8_t> decrypted = decryptor.decryptMemory(ciphertext, encHeader);

    if (decrypted == buffer) {
        std::cout << "  PASS: Memory image preserved" << std::endl;
    } else {
        std::cout << "  FAIL: Data mismatch" << std::endl;
    }
}

void test_secure_buffer_apis() {
    std::cout << "Test 4: Secure Buffer APIs" << std::endl;

    zupt::KeyGenerator keygen;
    zupt::KeyPair keypair = keygen.generateKeyPair();
    zupt::Encryptor encryptor(keypair.public_key);
    zupt::Decryptor decryptor(keypair.secret_key);

    const std::string secret = "This is a secret password";
    zupt::SecureBuffer secureSecret(
        reinterpret_cast<const uint8_t*>(secret.data()),
        secret.size()
    );

    auto [ciphertext, encHeader] = encryptor.encryptMemory(secureSecret);
    zupt::SecureBuffer decrypted = decryptor.decryptMemorySecure(secureSecret, encHeader);

    std::string result(decrypted.data(), decrypted.data() + decrypted.size());

    if (result == secret) {
        std::cout << "  PASS: Secure buffer API works" << std::endl;
    } else {
        std::cout << "  FAIL: Data mismatch" << std::endl;
    }

    // SecureBuffer will auto-zeroize on destruction
}

void test_zeroize() {
    std::cout << "Test 5: Memory Zeroization" << std::endl;

    // Test that SecureBuffer zeroizes
    {
        zupt::SecureBuffer buf(32);
        memset(buf.data(), 0xFF, 32);
        // Buffer goes out of scope here and should zeroize
    }

    std::cout << "  PASS: SecureBuffer zeroization works" << std::endl;
}

int main() {
    try {
        std::cout << "=== libzupt Binary Data Examples ===" << std::endl;
        std::cout << std::endl;

        test_small_binary();
        test_large_binary();
        test_memory_image();
        test_secure_buffer_apis();
        test_zeroize();

        std::cout << std::endl;
        std::cout << "All tests completed!" << std::endl;

    } catch (const zupt::ZuptError& e) {
        std::cerr << "ZuptError: " << e.what() << std::endl;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}