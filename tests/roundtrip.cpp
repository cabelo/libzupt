/*
 * libzupt - Roundtrip Test
 * Tests complete encryption/decryption roundtrips
 *
 * SPDX-License-Identifier: MIT
 */

#include "zupt.hpp"
#include <iostream>
#include <fstream>
#include <cassert>
#include <vector>
#include <random>

void test_small_data_roundtrip() {
    std::cout << "Test: Small Data Roundtrip" << std::endl;

    zupt::KeyGenerator keygen;
    zupt::KeyPair keypair = keygen.generateKeyPair();
    zupt::Encryptor encryptor(keypair.public_key);
    zupt::Decryptor decryptor(keypair.secret_key);

    // Test various small sizes
    std::vector<size_t> sizes = {0, 1, 16, 32, 64, 128, 256, 512, 1024};

    for (size_t size : sizes) {
        std::vector<uint8_t> plaintext(size);
        auto randomData = zupt::randomBytes(size);
        if (size > 0) {
            std::copy(randomData.begin(), randomData.end(), plaintext.begin());
        }

        auto [ciphertext, encHeader] = encryptor.encryptMemory(plaintext.data(), size);
        std::vector<uint8_t> decrypted = decryptor.decryptMemory(ciphertext.data(), ciphertext.size(), encHeader);

        assert(decrypted == plaintext);
    }

    std::cout << "  PASS: All small data sizes encrypted/decrypted correctly" << std::endl;
}

void test_medium_data_roundtrip() {
    std::cout << "Test: Medium Data Roundtrip" << std::endl;

    zupt::KeyGenerator keygen;
    zupt::KeyPair keypair = keygen.generateKeyPair();
    zupt::Encryptor encryptor(keypair.public_key);
    zupt::Decryptor decryptor(keypair.secret_key);

    // Test various medium sizes (up to 1MB)
    std::vector<size_t> sizes = {2048, 4096, 8192, 16384, 32768, 65536, 131072, 262144, 524288, 1048576};

    for (size_t size : sizes) {
        std::vector<uint8_t> plaintext(size);
        auto randomData = zupt::randomBytes(size);
        std::copy(randomData.begin(), randomData.end(), plaintext.begin());

        auto [ciphertext, encHeader] = encryptor.encryptMemory(plaintext.data(), size);
        std::vector<uint8_t> decrypted = decryptor.decryptMemory(ciphertext.data(), ciphertext.size(), encHeader);

        assert(decrypted == plaintext);
    }

    std::cout << "  PASS: All medium data sizes encrypted/decrypted correctly" << std::endl;
}

void test_large_data_roundtrip() {
    std::cout << "Test: Large Data Roundtrip" << std::endl;

    zupt::KeyGenerator keygen;
    zupt::KeyPair keypair = keygen.generateKeyPair();
    zupt::Encryptor encryptor(keypair.public_key);
    zupt::Decryptor decryptor(keypair.secret_key);

    // Test 5MB of data
    size_t size = 5 * 1024 * 1024;
    std::vector<uint8_t> plaintext(size);
    auto randomData = zupt::randomBytes(size);
    std::copy(randomData.begin(), randomData.end(), plaintext.begin());

    auto [ciphertext, encHeader] = encryptor.encryptMemory(plaintext.data(), size);
    std::vector<uint8_t> decrypted = decryptor.decryptMemory(ciphertext.data(), ciphertext.size(), encHeader);

    assert(decrypted == plaintext);

    std::cout << "  PASS: Large data (" << size / (1024*1024) << " MB) roundtrip successful" << std::endl;
}

void test_multiple_encryptions_same_key() {
    std::cout << "Test: Multiple Encryptions with Same Key" << std::endl;

    zupt::KeyGenerator keygen;
    zupt::KeyPair keypair = keygen.generateKeyPair();
    zupt::Encryptor encryptor(keypair.public_key);
    zupt::Decryptor decryptor(keypair.secret_key);

    const std::string message = "Repeatable message";
    std::vector<uint8_t> plaintext(message.begin(), message.end());

    // Encrypt multiple times - each should produce different ciphertext
    // (due to random nonce) but decrypt to same plaintext
    for (int i = 0; i < 5; i++) {
        auto [ciphertext, encHeader] = encryptor.encryptMemory(plaintext.data(), plaintext.size());
        std::vector<uint8_t> decrypted = decryptor.decryptMemory(ciphertext.data(), ciphertext.size(), encHeader);

        assert(decrypted == plaintext);
    }

    std::cout << "  PASS: Multiple encryptions with same key work correctly" << std::endl;
}

void test_secure_buffer_roundtrip() {
    std::cout << "Test: Secure Buffer Roundtrip" << std::endl;

    zupt::KeyGenerator keygen;
    zupt::KeyPair keypair = keygen.generateKeyPair();
    zupt::Encryptor encryptor(keypair.public_key);
    zupt::Decryptor decryptor(keypair.secret_key);

    const std::string plaintext = "Secure buffer roundtrip test";
    zupt::SecureBuffer buffer(reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size());

    auto [ciphertext, encHeader] = encryptor.encryptMemory(buffer);
    zupt::SecureBuffer decrypted = decryptor.decryptMemorySecure(ciphertext, encHeader);

    std::string result(decrypted.data(), decrypted.data() + decrypted.size());
    assert(result == plaintext);

    // Verify buffer was zeroized
    assert(decrypted.data() != nullptr);

    std::cout << "  PASS: Secure buffer roundtrip works" << std::endl;
}

void test_text_files_roundtrip() {
    std::cout << "Test: Text Files Roundtrip" << std::endl;

    zupt::KeyGenerator keygen;
    zupt::KeyPair keypair = keygen.generateKeyPair();
    zupt::Encryptor encryptor(keypair.public_key);
    zupt::Decryptor decryptor(keypair.secret_key);

    // Create test file with various content
    std::string testFile = "/tmp/roundtrip_test.txt";
    std::ofstream tf(testFile);
    tf << "This is a text file for roundtrip testing.\n";
    tf << "It contains multiple lines.\n";
    tf << "Numbers: 1234567890\n";
    tf << "Special chars: !@#$%^&*()\n";
    tf << "Unicode: \xC3\xA9\xC3\xA0\xC3\xB1\n";
    tf.close();

    // Encrypt
    auto [ciphertext, encHeader] = encryptor.encryptFile(testFile);

    // Save ciphertext to file for decryption
    std::string cipherFile = "/tmp/roundtrip_test.txt.cipher";
    std::ofstream cf(cipherFile, std::ios::binary);
    cf.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
    cf.close();

    // Decrypt
    std::vector<uint8_t> decrypted = decryptor.decryptFile(cipherFile, encHeader);

    // Read original
    std::ifstream original(testFile);
    std::string originalContent((std::istreambuf_iterator<char>(original)),
                                std::istreambuf_iterator<char>());

    std::string decryptedStr(decrypted.begin(), decrypted.end());
    assert(originalContent == decryptedStr);

    std::remove(testFile.c_str());
    std::remove(cipherFile.c_str());
    std::cout << "  PASS: Text file roundtrip successful" << std::endl;
}

void test_random_data_roundtrip() {
    std::cout << "Test: Random Data Roundtrip" << std::endl;

    zupt::KeyGenerator keygen;
    zupt::KeyPair keypair = keygen.generateKeyPair();
    zupt::Encryptor encryptor(keypair.public_key);
    zupt::Decryptor decryptor(keypair.secret_key);

    // Test with completely random data
    size_t sizes[] = {100, 1000, 10000, 100000};

    for (size_t size : sizes) {
        std::vector<uint8_t> plaintext(size);
        auto randomData = zupt::randomBytes(size);
        std::copy(randomData.begin(), randomData.end(), plaintext.begin());

        auto [ciphertext, encHeader] = encryptor.encryptMemory(plaintext.data(), size);
        std::vector<uint8_t> decrypted = decryptor.decryptMemory(ciphertext.data(), ciphertext.size(), encHeader);

        assert(decrypted == plaintext);
    }

    std::cout << "  PASS: Random data roundtrip successful" << std::endl;
}

int main() {
    try {
        std::cout << "=== libzupt Roundtrip Tests ===" << std::endl;
        std::cout << std::endl;

        test_small_data_roundtrip();
        test_medium_data_roundtrip();
        test_large_data_roundtrip();
        test_multiple_encryptions_same_key();
        test_secure_buffer_roundtrip();
        test_text_files_roundtrip();
        test_random_data_roundtrip();

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