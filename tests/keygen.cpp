/*
 * libzupt - Key Generation Test
 * Tests key generation and key file I/O
 *
 * SPDX-License-Identifier: MIT
 */

#include "zupt.hpp"
#include <iostream>
#include <fstream>
#include <cassert>
#include <cstdlib>

void test_key_generation() {
    std::cout << "Test: Key Generation" << std::endl;

    zupt::KeyGenerator keygen;
    zupt::KeyPair keypair = keygen.generateKeyPair();

    // Verify key sizes
    assert(keypair.public_key.size() == zupt::HYBRID_PUB_KEY_SIZE);
    assert(keypair.secret_key.size() == zupt::HYBRID_PRIV_KEY_SIZE);

    // Verify magic bytes
    assert(memcmp(keypair.public_key.data(), "ZKEY", 4) == 0);
    assert(memcmp(keypair.secret_key.data(), "ZKEY", 4) == 0);

    // Verify version byte
    assert(keypair.public_key[4] == 0x01);
    assert(keypair.secret_key[4] == 0x01);

    // Verify private key flag
    assert((keypair.secret_key[5] & 0x01) == 0x01);
    assert((keypair.public_key[5] & 0x01) == 0x00);

    std::cout << "  PASS: Key sizes are correct" << std::endl;
    std::cout << "  PASS: Key format is correct" << std::endl;
}

void test_key_file_io() {
    std::cout << "Test: Key File I/O" << std::endl;

    zupt::KeyGenerator keygen;
    zupt::KeyPair keypair = keygen.generateKeyPair();

    // Save to file
    std::string tmpfile = "/tmp/test_keypair.key";
    keygen.saveKeyPair(keypair, tmpfile);

    // Load from file
    zupt::KeyPair loaded = keygen.loadKeyPair(tmpfile);

    // Verify loaded keys match
    assert(loaded.public_key == keypair.public_key);
    assert(loaded.secret_key == keypair.secret_key);

    // Clean up
    std::remove(tmpfile.c_str());

    std::cout << "  PASS: Key save/load roundtrip" << std::endl;
}

void test_public_key_export() {
    std::cout << "Test: Public Key Export" << std::endl;

    zupt::KeyGenerator keygen;
    zupt::KeyPair keypair = keygen.generateKeyPair();

    std::string privfile = "/tmp/test_priv.key";
    std::string pubfile = "/tmp/test_pub.key";

    keygen.saveKeyPair(keypair, privfile);
    keygen.exportPublicKey(privfile, pubfile);

    // Load and verify
    std::vector<uint8_t> loaded_pub = keygen.loadPublicKey(pubfile);
    assert(loaded_pub == keypair.public_key);

    // Verify public key file doesn't have private key flag
    assert((loaded_pub[5] & 0x01) == 0x00);

    // Clean up
    std::remove(privfile.c_str());
    std::remove(pubfile.c_str());

    std::cout << "  PASS: Public key export works correctly" << std::endl;
}

void test_keypair_roundtrip() {
    std::cout << "Test: Keypair Roundtrip" << std::endl;

    zupt::KeyGenerator keygen;

    // Generate multiple keypairs
    for (int i = 0; i < 3; i++) {
        zupt::KeyPair kp = keygen.generateKeyPair();

        std::string privfile = "/tmp/roundtrip_priv_" + std::to_string(i) + ".key";
        std::string pubfile = "/tmp/roundtrip_pub_" + std::to_string(i) + ".key";

        keygen.saveKeyPair(kp, privfile);
        keygen.exportPublicKey(privfile, pubfile);

        zupt::KeyPair loaded = keygen.loadKeyPair(privfile);
        std::vector<uint8_t> pubLoaded = keygen.loadPublicKey(pubfile);

        assert(loaded.public_key == kp.public_key);
        assert(loaded.secret_key == kp.secret_key);
        assert(pubLoaded == kp.public_key);

        std::remove(privfile.c_str());
        std::remove(pubfile.c_str());
    }

    std::cout << "  PASS: Multiple keypair roundtrips successful" << std::endl;
}

int main() {
    try {
        std::cout << "=== libzupt Key Generation Tests ===" << std::endl;
        std::cout << std::endl;

        test_key_generation();
        test_key_file_io();
        test_public_key_export();
        test_keypair_roundtrip();

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