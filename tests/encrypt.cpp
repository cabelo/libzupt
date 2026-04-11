/*
 * libzupt - Encryption Test
 * Tests encryption functionality
 *
 * SPDX-License-Identifier: MIT
 */

#include "zupt.hpp"
#include <iostream>
#include <fstream>
#include <cassert>

void test_basic_encryption() {
    std::cout << "Test: Basic Encryption" << std::endl;

    zupt::KeyGenerator keygen;
    zupt::KeyPair keypair = keygen.generateKeyPair();

    const std::string plaintext = "Hello, Post-Quantum World!";
    zupt::Encryptor encryptor(keypair.public_key);

    auto [ciphertext, encHeader] = encryptor.encryptMemory(
        reinterpret_cast<const uint8_t*>(plaintext.data()),
        plaintext.size()
    );

    // Verify ciphertext is larger than plaintext (due to overhead)
    assert(ciphertext.size() > plaintext.size());

    // Verify header size
    assert(encHeader.size() == zupt::HYBRID_ENC_HEADER_SIZE);

    std::cout << "  PASS: Ciphertext generated" << std::endl;
    std::cout << "  PASS: Encryption header size correct" << std::endl;
}

void test_empty_data_encryption() {
    std::cout << "Test: Empty Data Encryption" << std::endl;

    zupt::KeyGenerator keygen;
    zupt::KeyPair keypair = keygen.generateKeyPair();
    zupt::Encryptor encryptor(keypair.public_key);

    auto [ciphertext, encHeader] = encryptor.encryptMemory(nullptr, 0);

    // Empty data should produce empty ciphertext
    assert(ciphertext.empty());
    assert(encHeader.size() == zupt::HYBRID_ENC_HEADER_SIZE);

    std::cout << "  PASS: Empty data encryption works" << std::endl;
}

void test_large_data_encryption() {
    std::cout << "Test: Large Data Encryption" << std::endl;

    zupt::KeyGenerator keygen;
    zupt::KeyPair keypair = keygen.generateKeyPair();
    zupt::Encryptor encryptor(keypair.public_key);

    // Create 10MB of random data
    size_t size = 10 * 1024 * 1024;
    std::vector<uint8_t> data(size);
    auto randData = zupt::randomBytes(size);
    std::copy(randData.begin(), randData.end(), data.begin());

    auto [ciphertext, encHeader] = encryptor.encryptMemory(data.data(), size);

    // Verify ciphertext is larger (encryption overhead)
    assert(ciphertext.size() > size);

    std::cout << "  PASS: Large data (" << size / (1024*1024) << " MB) encrypted" << std::endl;
}

void test_secure_buffer_encryption() {
    std::cout << "Test: Secure Buffer Encryption" << std::endl;

    zupt::KeyGenerator keygen;
    zupt::KeyPair keypair = keygen.generateKeyPair();
    zupt::Encryptor encryptor(keypair.public_key);

    const std::string plaintext = "Secure buffer test";
    zupt::SecureBuffer buffer(reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size());

    auto [ciphertext, encHeader] = encryptor.encryptMemory(buffer);

    // Verify ciphertext is larger than plaintext
    assert(ciphertext.size() > plaintext.size());

    // Buffer should still be valid
    assert(buffer.size() == plaintext.size());

    std::cout << "  PASS: Secure buffer encryption works" << std::endl;
}

void test_null_pointer_handling() {
    std::cout << "Test: Null Pointer Handling" << std::endl;

    zupt::KeyGenerator keygen;
    zupt::KeyPair keypair = keygen.generateKeyPair();
    zupt::Encryptor encryptor(keypair.public_key);

    // Encrypting null with size > 0 should throw
    bool threw = false;
    try {
        encryptor.encryptMemory(nullptr, 100);
    } catch (const zupt::ZuptError& e) {
        threw = true;
        assert(e.code() == zupt::ErrorCode::ERR_INVALID);
    }
    assert(threw);

    std::cout << "  PASS: Null pointer correctly rejected" << std::endl;
}

int main() {
    try {
        std::cout << "=== libzupt Encryption Tests ===" << std::endl;
        std::cout << std::endl;

        test_basic_encryption();
        test_empty_data_encryption();
        test_large_data_encryption();
        test_secure_buffer_encryption();
        test_null_pointer_handling();

        std::cout << std::endl;
        std::cout << "All tests passed!" << std::endl;
        return 0;

    } catch (const zupt::ZuptError& e) {
        std::cerr << "FAILED: " << e.what() << std::endl;
        std::cerr << "Error code: " << static_cast<int>(e.code()) << std::endl;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "FAILED: " << e.what() << std::endl;
        return 1;
    }
}