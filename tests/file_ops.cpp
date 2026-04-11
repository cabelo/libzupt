/*
 * libzupt - File Operations Test
 * Tests file-based encryption/decryption
 *
 * SPDX-License-Identifier: MIT
 */

#include "zupt.hpp"
#include <iostream>
#include <fstream>
#include <cassert>
void test_file_encryption() {
    std::cout << "Test: File Encryption" << std::endl;

    zupt::KeyGenerator keygen;
    zupt::KeyPair keypair = keygen.generateKeyPair();
    zupt::Encryptor encryptor(keypair.public_key);

    // Create test file
    std::string testFile = "/tmp/file_enc_test.txt";
    std::ofstream tf(testFile);
    tf << "Test content for file encryption\n";
    tf << "Multiple lines of data\n";
    tf << "End of file\n";
    tf.close();

    // Encrypt
    auto [ciphertext, encHeader] = encryptor.encryptFile(testFile);

    // Verify ciphertext is larger than original
    std::ifstream orig(testFile, std::ios::binary | std::ios::ate);
    size_t origSize = orig.tellg();
    assert(ciphertext.size() > origSize);

    // Verify header
    assert(encHeader.size() == zupt::HYBRID_ENC_HEADER_SIZE);

    // Clean up
    std::remove(testFile.c_str());
    std::cout << "  PASS: File encryption works" << std::endl;
}

void test_file_decryption() {
    std::cout << "Test: File Decryption" << std::endl;

    zupt::KeyGenerator keygen;
    zupt::KeyPair keypair = keygen.generateKeyPair();
    zupt::Encryptor encryptor(keypair.public_key);
    zupt::Decryptor decryptor(keypair.secret_key);

    // Create test file
    std::string testFile = "/tmp/file_dec_test.txt";
    std::ofstream tf(testFile);
    tf << "Content for file decryption test\n";
    tf << "Line 2\n";
    tf << "Line 3\n";
    tf.close();

    // Encrypt
    auto [ciphertext, encHeader] = encryptor.encryptFile(testFile);

    // Save ciphertext to file for decryption
    std::string cipherFile = "/tmp/file_dec_test.txt.cipher";
    std::ofstream cf(cipherFile, std::ios::binary);
    cf.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
    cf.close();

    // Decrypt
    std::vector<uint8_t> decrypted = decryptor.decryptFile(cipherFile, encHeader);

    // Read original
    std::ifstream orig(testFile);
    std::string origContent((std::istreambuf_iterator<char>(orig)),
                            std::istreambuf_iterator<char>());

    std::string decryptedStr(decrypted.begin(), decrypted.end());
    assert(origContent == decryptedStr);

    std::remove(testFile.c_str());
    std::remove(cipherFile.c_str());
    std::cout << "  PASS: File decryption works" << std::endl;
}

void test_binary_file_roundtrip() {
    std::cout << "Test: Binary File Roundtrip" << std::endl;

    zupt::KeyGenerator keygen;
    zupt::KeyPair keypair = keygen.generateKeyPair();
    zupt::Encryptor encryptor(keypair.public_key);
    zupt::Decryptor decryptor(keypair.secret_key);

    // Create binary file with various byte values
    std::string testFile = "/tmp/binary_test.bin";
    std::ofstream tf(testFile, std::ios::binary);
    for (int i = 0; i < 256; i++) {
        tf << static_cast<char>(i);
    }
    tf.close();

    // Encrypt
    auto [ciphertext, encHeader] = encryptor.encryptFile(testFile);

    // Save ciphertext to file for decryption
    std::string cipherFile = "/tmp/binary_test.bin.cipher";
    std::ofstream cf(cipherFile, std::ios::binary);
    cf.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
    cf.close();

    // Decrypt
    std::vector<uint8_t> decrypted = decryptor.decryptFile(cipherFile, encHeader);

    // Verify
    std::ifstream orig(testFile, std::ios::binary);
    std::string origContent((std::istreambuf_iterator<char>(orig)),
                            std::istreambuf_iterator<char>());

    std::string decryptedStr(decrypted.begin(), decrypted.end());
    assert(origContent == decryptedStr);

    std::remove(testFile.c_str());
    std::remove(cipherFile.c_str());
    std::cout << "  PASS: Binary file roundtrip works" << std::endl;
}

void test_large_file() {
    std::cout << "Test: Large File" << std::endl;

    zupt::KeyGenerator keygen;
    zupt::KeyPair keypair = keygen.generateKeyPair();
    zupt::Encryptor encryptor(keypair.public_key);
    zupt::Decryptor decryptor(keypair.secret_key);

    // Create 2MB binary file
    std::string testFile = "/tmp/large_file_test.bin";
    std::ofstream tf(testFile, std::ios::binary);
    for (int i = 0; i < 2048 * 1024; i++) {
        tf << static_cast<char>(i & 0xFF);
    }
    tf.close();

    // Encrypt
    auto [ciphertext, encHeader] = encryptor.encryptFile(testFile);
    std::cout << "  Encrypted size: " << ciphertext.size() / 1024 << " KB" << std::endl;

    // Save ciphertext to file for decryption
    std::string cipherFile = "/tmp/large_file_test.bin.cipher";
    std::ofstream cf(cipherFile, std::ios::binary);
    cf.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
    cf.close();

    // Decrypt
    std::vector<uint8_t> decrypted = decryptor.decryptFile(cipherFile, encHeader);

    // Verify
    std::ifstream orig(testFile, std::ios::binary);
    std::string origContent((std::istreambuf_iterator<char>(orig)),
                            std::istreambuf_iterator<char>());

    std::string decryptedStr(decrypted.begin(), decrypted.end());
    assert(origContent == decryptedStr);

    std::remove(testFile.c_str());
    std::remove(cipherFile.c_str());
    std::cout << "  PASS: Large file roundtrip works" << std::endl;
}

void test_empty_file() {
    std::cout << "Test: Empty File" << std::endl;

    zupt::KeyGenerator keygen;
    zupt::KeyPair keypair = keygen.generateKeyPair();
    zupt::Encryptor encryptor(keypair.public_key);
    zupt::Decryptor decryptor(keypair.secret_key);

    // Create empty file
    std::string testFile = "/tmp/empty_file_test.txt";
    std::ofstream tf(testFile);
    tf.close();

    // Encrypt
    auto [ciphertext, encHeader] = encryptor.encryptFile(testFile);

    // Save ciphertext to file for decryption
    std::string cipherFile = "/tmp/empty_file_test.txt.cipher";
    std::ofstream cf(cipherFile, std::ios::binary);
    cf.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
    cf.close();

    // Decrypt
    std::vector<uint8_t> decrypted = decryptor.decryptFile(cipherFile, encHeader);
    assert(decrypted.empty());

    std::remove(testFile.c_str());
    std::remove(cipherFile.c_str());
    std::cout << "  PASS: Empty file handling works" << std::endl;
}

void test_special_filenames() {
    std::cout << "Test: Special Filenames" << std::endl;

    zupt::KeyGenerator keygen;
    zupt::KeyPair keypair = keygen.generateKeyPair();
    zupt::Encryptor encryptor(keypair.public_key);
    zupt::Decryptor decryptor(keypair.secret_key);

    // Test with path separator in filename
    std::string testFile = "/tmp/special_test_file.txt";
    std::ofstream tf(testFile);
    tf << "Special filename test\n";
    tf.close();

    auto [ciphertext, encHeader] = encryptor.encryptFile(testFile);

    // Save ciphertext to file for decryption
    std::string cipherFile = "/tmp/special_test_file.txt.cipher";
    std::ofstream cf(cipherFile, std::ios::binary);
    cf.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
    cf.close();

    std::vector<uint8_t> decrypted = decryptor.decryptFile(cipherFile, encHeader);

    std::ifstream orig(testFile);
    std::string origContent((std::istreambuf_iterator<char>(orig)),
                            std::istreambuf_iterator<char>());

    std::string decryptedStr(decrypted.begin(), decrypted.end());
    assert(origContent == decryptedStr);

    std::remove(testFile.c_str());
    std::remove(cipherFile.c_str());
    std::cout << "  PASS: Special filename handling works" << std::endl;
}

int main() {
    try {
        std::cout << "=== libzupt File Operations Tests ===" << std::endl;
        std::cout << std::endl;

        test_file_encryption();
        test_file_decryption();
        test_binary_file_roundtrip();
        test_large_file();
        test_empty_file();
        test_special_filenames();

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