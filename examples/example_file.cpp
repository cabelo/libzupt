/*
 * libzupt - File Encryption Example
 * Shows how to encrypt and decrypt files using the library
 *
 * SPDX-License-Identifier: MIT
 */

#include "zupt.hpp"
#include <iostream>
#include <fstream>
// filesystem not available in GCC 7, remove unused include

void printUsage(const char* prog) {
    std::cout << "Usage:" << std::endl;
    std::cout << "  " << prog << " encrypt <public_key_file> <input_file> <output_file>" << std::endl;
    std::cout << "  " << prog << " decrypt <private_key_file> <input_file> <output_file> <enc_header_file>" << std::endl;
    std::cout << "  " << prog << " genkey <output_private_key> [output_public_key]" << std::endl;
}

int cmdEncrypt(const std::string& pubkeyFile, const std::string& inputFile,
               const std::string& outputFile) {
    try {
        // Load public key
        zupt::KeyGenerator keygen;
        std::vector<uint8_t> publicKey = keygen.loadPublicKey(pubkeyFile);
        std::cout << "Loaded public key from: " << pubkeyFile << std::endl;

        // Create encryptor
        zupt::Encryptor encryptor(publicKey);

        // Encrypt file
        auto [ciphertext, encHeader] = encryptor.encryptFile(inputFile);

        // Save ciphertext
        std::ofstream out(outputFile, std::ios::binary);
        out.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
        out.close();
        std::cout << "Encrypted data saved to: " << outputFile << std::endl;

        // Save encryption header (needed for decryption)
        std::string headerFile = outputFile + ".header";
        std::ofstream hout(headerFile, std::ios::binary);
        hout.write(reinterpret_cast<const char*>(encHeader.data()), encHeader.size());
        hout.close();
        std::cout << "Encryption header saved to: " << headerFile << std::endl;

        std::cout << "Encryption complete." << std::endl;
        return 0;

    } catch (const zupt::ZuptError& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}

int cmdDecrypt(const std::string& privkeyFile, const std::string& inputFile,
               const std::string& outputFile, const std::string& headerFile) {
    try {
        // Load private key
        zupt::KeyGenerator keygen;
        zupt::KeyPair keypair = keygen.loadKeyPair(privkeyFile);
        std::cout << "Loaded private key from: " << privkeyFile << std::endl;

        // Create decryptor
        zupt::Decryptor decryptor(keypair.secret_key);

        // Load ciphertext
        std::ifstream in(inputFile, std::ios::binary | std::ios::ate);
        if (!in) {
            throw zupt::ZuptError(zupt::ErrorCode::ERR_IO, "Cannot open input file");
        }
        std::streamsize size = in.tellg();
        in.seekg(0, std::ios::beg);
        std::vector<uint8_t> ciphertext(size);
        in.read(reinterpret_cast<char*>(ciphertext.data()), size);
        in.close();
        std::cout << "Loaded ciphertext from: " << inputFile << std::endl;

        // Load encryption header
        std::ifstream hin(headerFile, std::ios::binary | std::ios::ate);
        if (!hin) {
            throw zupt::ZuptError(zupt::ErrorCode::ERR_IO, "Cannot open header file");
        }
        size = hin.tellg();
        hin.seekg(0, std::ios::beg);
        std::vector<uint8_t> encHeader(size);
        hin.read(reinterpret_cast<char*>(encHeader.data()), size);
        hin.close();
        std::cout << "Loaded encryption header from: " << headerFile << std::endl;

        // Decrypt file
        std::vector<uint8_t> decrypted = decryptor.decryptMemory(ciphertext.data(), ciphertext.size(), encHeader);

        // Save decrypted data
        std::ofstream out(outputFile, std::ios::binary);
        out.write(reinterpret_cast<const char*>(decrypted.data()), decrypted.size());
        out.close();
        std::cout << "Decrypted data saved to: " << outputFile << std::endl;

        std::cout << "Decryption complete." << std::endl;
        return 0;

    } catch (const zupt::ZuptError& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}

int cmdGenKey(const std::string& privKeyFile, std::string* pubKeyFile) {
    try {
        zupt::KeyGenerator keygen;
        zupt::KeyPair keypair = keygen.generateKeyPair();

        // Save private key
        keygen.saveKeyPair(keypair, privKeyFile);
        std::cout << "Private key saved to: " << privKeyFile << std::endl;

        // Optionally save public key
        if (pubKeyFile) {
            keygen.exportPublicKey(privKeyFile, *pubKeyFile);
            std::cout << "Public key saved to: " << *pubKeyFile << std::endl;
        }

        std::cout << "Key generation complete." << std::endl;
        return 0;

    } catch (const zupt::ZuptError& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }

    std::string cmd = argv[1];

    if (cmd == "encrypt") {
        if (argc != 5) {
            std::cerr << "Error: encrypt requires 4 arguments" << std::endl;
            printUsage(argv[0]);
            return 1;
        }
        return cmdEncrypt(argv[2], argv[3], argv[4]);

    } else if (cmd == "decrypt") {
        if (argc != 6) {
            std::cerr << "Error: decrypt requires 5 arguments" << std::endl;
            printUsage(argv[0]);
            return 1;
        }
        return cmdDecrypt(argv[2], argv[3], argv[4], argv[5]);

    } else if (cmd == "genkey") {
        if (argc != 3 && argc != 4) {
            std::cerr << "Error: genkey requires 2 or 3 arguments" << std::endl;
            printUsage(argv[0]);
            return 1;
        }
        std::string* pubFile = (argc == 4) ? new std::string(argv[3]) : nullptr;
        int result = cmdGenKey(argv[2], pubFile);
        if (pubFile) delete pubFile;
        return result;

    } else {
        std::cerr << "Unknown command: " << cmd << std::endl;
        printUsage(argv[0]);
        return 1;
    }
}
