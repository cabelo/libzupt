/*
 * libzupt - Basic Example
 * Shows how to generate keys, encrypt and decrypt data in memory
 *
 * SPDX-License-Identifier: MIT
 */

#include "zupt.hpp"
#include <iostream>
#include <fstream>
#include <cstring>

void printHex(const std::vector<uint8_t>& data, const char* label = nullptr) {
    if (label) {
        std::cout << label << ": ";
    }
    std::cout << "[";
    for (size_t i = 0; i < std::min(size_t(16), data.size()); i++) {
        if (i > 0) std::cout << " ";
        printf("%02x", data[i]);
    }
    if (data.size() > 16) {
        std::cout << " ...";
    }
    std::cout << "]" << std::endl;
}

int main() {
    try {
        std::cout << "libzupt - Hybrid Post-Quantum Encryption Example" << std::endl;
        std::cout << "Library version: " << zupt::getVersion() << std::endl;
        std::cout << std::endl;

        /* Step 1: Generate key pair */
        std::cout << "Step 1: Generating hybrid key pair (ML-KEM-768 + X25519)..." << std::endl;
        zupt::KeyGenerator keygen;
        zupt::KeyPair keypair = keygen.generateKeyPair();

        std::cout << "  Public key size: " << keypair.public_key.size() << " bytes" << std::endl;
        std::cout << "  Secret key size: " << keypair.secret_key.size() << " bytes" << std::endl;
        printHex(keypair.public_key, "Public key (first 16 bytes)");
        std::cout << std::endl;

        /* Step 2: Encrypt data in memory */
        std::cout << "Step 2: Encrypting data in memory..." << std::endl;
        const std::string plaintext = "Hello, Post-Quantum World! This is a secret message.";
        std::cout << "  Plaintext: " << plaintext << std::endl;

        zupt::Encryptor encryptor(keypair.public_key);
        auto [ciphertext, encHeader] = encryptor.encryptMemory(
            reinterpret_cast<const uint8_t*>(plaintext.data()),
            plaintext.size()
        );

        std::cout << "  Ciphertext size: " << ciphertext.size() << " bytes" << std::endl;
        std::cout << "  Encryption header size: " << encHeader.size() << " bytes" << std::endl;
        printHex(ciphertext, "Ciphertext (first 16 bytes)");
        std::cout << std::endl;

        /* Step 3: Decrypt data in memory */
        std::cout << "Step 3: Decrypting data in memory..." << std::endl;
        zupt::Decryptor decryptor(keypair.secret_key);
        std::vector<uint8_t> decrypted = decryptor.decryptMemory(ciphertext.data(), ciphertext.size(), encHeader);

        std::string decryptedStr(decrypted.begin(), decrypted.end());
        std::cout << "  Decrypted: " << decryptedStr << std::endl;
        std::cout << std::endl;

        /* Step 4: Verify decryption */
        std::cout << "Step 4: Verifying decryption..." << std::endl;
        if (decryptedStr == plaintext) {
            std::cout << "  SUCCESS: Decrypted text matches original!" << std::endl;
        } else {
            std::cout << "  ERROR: Decrypted text does not match!" << std::endl;
            return 1;
        }
        std::cout << std::endl;

        /* Step 5: Save keys to files */
        std::cout << "Step 5: Saving keys to files..." << std::endl;
        keygen.saveKeyPair(keypair, "/tmp/test_keypair.key");
        keygen.exportPublicKey("/tmp/test_keypair.key", "/tmp/test_pubkey.key");
        std::cout << "  Saved private key to: /tmp/test_keypair.key" << std::endl;
        std::cout << "  Saved public key to: /tmp/test_pubkey.key" << std::endl;
        std::cout << std::endl;

        /* Step 6: Demonstrate file encryption */
        std::cout << "Step 6: Encrypting a file..." << std::endl;
        const std::string testFile = "/tmp/testfile.txt";
        const std::string encFile = "/tmp/testfile.zupt";

        // Create test file
        std::ofstream tf(testFile);
        tf << "This is a test file for libzupt file encryption.\n";
        tf << "Line 2: More secret data.\n";
        tf << "Line 3: End of file.\n";
        tf.close();

        // Encrypt file
        auto [fileCiphertext, fileEncHeader] = encryptor.encryptFile(testFile);
        std::cout << "  Encrypted file size: " << fileCiphertext.size() << " bytes" << std::endl;

        // Save encrypted data
        std::ofstream ef(encFile, std::ios::binary);
        ef.write(reinterpret_cast<const char*>(fileCiphertext.data()), fileCiphertext.size());
        ef.close();

        // Decrypt file
        std::vector<uint8_t> fileDecrypted = decryptor.decryptFile(encFile, fileEncHeader);
        std::cout << "  Decrypted file content:" << std::endl;
        std::cout << std::string(fileDecrypted.begin(), fileDecrypted.end());

        std::cout << std::endl;
        std::cout << "All examples completed successfully!" << std::endl;

    } catch (const zupt::ZuptError& e) {
        std::cerr << "ZuptError: " << e.what() << std::endl;
        std::cerr << "Error code: " << static_cast<int>(e.code()) << std::endl;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}