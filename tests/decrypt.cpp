/*
 * libzupt - Decryption Test
 * Tests decryption functionality
 *
 * SPDX-License-Identifier: MIT
 */

#include "zupt.hpp"
#include <iostream>
#include <fstream>
#include <cassert>

void test_basic_decryption() {
    std::cout << "Test: Basic Decryption" << std::endl;

    zupt::KeyGenerator keygen;
    zupt::KeyPair keypair = keygen.generateKeyPair();

    const std::string plaintext = "Hello, Decryption World!";
    zupt::Encryptor encryptor(keypair.public_key);
    zupt::Decryptor decryptor(keypair.secret_key);

    auto [ciphertext, encHeader] = encryptor.encryptMemory(
        reinterpret_cast<const uint8_t*>(plaintext.data()),
        plaintext.size()
    );

    std::vector<uint8_t> decrypted = decryptor.decryptMemory(ciphertext.data(), ciphertext.size(), encHeader);
    std::string result(decrypted.begin(), decrypted.end());

    assert(result == plaintext);
    std::cout << "  PASS: Decryption successful" << std::endl;
}

void test_empty_data_decryption() {
    std::cout << "Test: Empty Data Decryption" << std::endl;

    zupt::KeyGenerator keygen;
    zupt::KeyPair keypair = keygen.generateKeyPair();
    zupt::Encryptor encryptor(keypair.public_key);
    zupt::Decryptor decryptor(keypair.secret_key);

    auto [ciphertext, encHeader] = encryptor.encryptMemory(nullptr, 0);

    std::vector<uint8_t> decrypted = decryptor.decryptMemory(ciphertext.data(), ciphertext.size(), encHeader);
    assert(decrypted.empty());

    std::cout << "  PASS: Empty data decryption works" << std::endl;
}

void test_mismatched_keys() {
    std::cout << "Test: Mismatched Keys" << std::endl;

    zupt::KeyGenerator keygen;
    zupt::KeyPair keypair1 = keygen.generateKeyPair();
    zupt::KeyPair keypair2 = keygen.generateKeyPair();

    const std::string plaintext = "Test message";
    zupt::Encryptor encryptor(keypair1.public_key);
    zupt::Decryptor decryptor(keypair2.secret_key);

    auto [ciphertext, encHeader] = encryptor.encryptMemory(
        reinterpret_cast<const uint8_t*>(plaintext.data()),
        plaintext.size()
    );

    // Decryption with wrong key should fail
    bool threw = false;
    try {
        decryptor.decryptMemory(ciphertext.data(), ciphertext.size(), encHeader);
    } catch (const zupt::ZuptError& e) {
        threw = true;
        assert(e.code() == zupt::ErrorCode::ERR_AUTH_FAIL);
    }
    assert(threw);

    std::cout << "  PASS: Wrong key correctly rejected" << std::endl;
}

void test_corrupted_ciphertext() {
    std::cout << "Test: Corrupted Ciphertext" << std::endl;

    zupt::KeyGenerator keygen;
    zupt::KeyPair keypair = keygen.generateKeyPair();
    zupt::Encryptor encryptor(keypair.public_key);
    zupt::Decryptor decryptor(keypair.secret_key);

    const std::string plaintext = "Test message";
    auto [ciphertext, encHeader] = encryptor.encryptMemory(
        reinterpret_cast<const uint8_t*>(plaintext.data()),
        plaintext.size()
    );

    // Corrupt the ciphertext
    std::vector<uint8_t> corrupt = ciphertext;
    if (!corrupt.empty()) {
        corrupt[corrupt.size() / 2] ^= 0xFF;
    }

    // Decryption with corrupted data should fail
    bool threw = false;
    try {
        decryptor.decryptMemory(corrupt.data(), corrupt.size(), encHeader);
    } catch (const zupt::ZuptError& e) {
        threw = true;
        assert(e.code() == zupt::ErrorCode::ERR_AUTH_FAIL);
    }
    assert(threw);

    std::cout << "  PASS: Corrupted ciphertext correctly rejected" << std::endl;
}

void test_corrupted_header() {
    std::cout << "Test: Corrupted Header" << std::endl;

    zupt::KeyGenerator keygen;
    zupt::KeyPair keypair = keygen.generateKeyPair();
    zupt::Encryptor encryptor(keypair.public_key);
    zupt::Decryptor decryptor(keypair.secret_key);

    const std::string plaintext = "Test message";
    auto [ciphertext, encHeader] = encryptor.encryptMemory(
        reinterpret_cast<const uint8_t*>(plaintext.data()),
        plaintext.size()
    );

    // Corrupt the header
    std::vector<uint8_t> corruptHeader = encHeader;
    corruptHeader[corruptHeader.size() / 2] ^= 0xFF;

    // Decryption with corrupted header should fail
    bool threw = false;
    try {
        decryptor.decryptMemory(ciphertext.data(), ciphertext.size(), corruptHeader);
    } catch (const zupt::ZuptError& e) {
        threw = true;
        assert(e.code() == zupt::ErrorCode::ERR_INVALID);
    }
    assert(threw);

    std::cout << "  PASS: Corrupted header correctly rejected" << std::endl;
}

void test_file_decryption() {
    std::cout << "Test: File Decryption" << std::endl;

    zupt::KeyGenerator keygen;
    zupt::KeyPair keypair = keygen.generateKeyPair();
    zupt::Encryptor encryptor(keypair.public_key);
    zupt::Decryptor decryptor(keypair.secret_key);

    // Create test file
    std::string testFile = "/tmp/test_decrypt.txt";
    std::ofstream tf(testFile);
    tf << "Line 1: Secret data\n";
    tf << "Line 2: More secrets\n";
    tf << "Line 3: End\n";
    tf.close();

    // Encrypt
    auto [ciphertext, encHeader] = encryptor.encryptFile(testFile);

    // Save ciphertext to file for decryption
    std::string cipherFile = "/tmp/test_decrypt.txt.cipher";
    std::ofstream cf(cipherFile, std::ios::binary);
    cf.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
    cf.close();

    // Decrypt
    std::vector<uint8_t> decrypted = decryptor.decryptFile(cipherFile, encHeader);

    // Verify
    std::ifstream expected(testFile);
    std::string expectedContent((std::istreambuf_iterator<char>(expected)),
                                std::istreambuf_iterator<char>());
    std::string decryptedStr(decrypted.begin(), decrypted.end());

    assert(expectedContent == decryptedStr);

    // Clean up
    std::remove(testFile.c_str());
    std::remove(cipherFile.c_str());

    std::cout << "  PASS: File encryption/decryption works" << std::endl;
}

int main() {
    try {
        std::cout << "=== libzupt Decryption Tests ===" << std::endl;
        std::cout << std::endl;

        test_basic_decryption();
        test_empty_data_decryption();
        test_mismatched_keys();
        test_corrupted_ciphertext();
        test_corrupted_header();
        test_file_decryption();

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