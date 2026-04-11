#!/usr/bin/env python3
"""
libzupt - Basic Encryption/Decryption Example
Shows how to use the library for basic memory encryption/decryption
"""

import sys
sys.path.insert(0, __import__('os').path.dirname(__file__))

import zupt


def main():
    print("=" * 60)
    print("libzupt - Basic Encryption/Decryption Example")
    print("=" * 60)
    print()

    # Generate key pair
    print("1. Generating key pair...")
    keygen = zupt.KeyGenerator()
    keypair = keygen.generate_keypair()
    print(f"   Public key size: {len(keypair.public_key)} bytes")
    print(f"   Secret key size: {len(keypair.secret_key)} bytes")
    print()

    # Create encryptor and decryptor
    encryptor = zupt.Encryptor(keypair.public_key)
    decryptor = zupt.Decryptor(keypair.secret_key)

    # Encrypt some data
    message = b"Hello, Post-Quantum World! This is a secret message."
    print(f"2. Encrypting message: {message.decode()}")
    ciphertext, enc_header = encryptor.encrypt(message)
    print(f"   Ciphertext size: {len(ciphertext)} bytes")
    print(f"   Header size: {len(enc_header)} bytes")
    print()

    # Decrypt
    print("3. Decrypting...")
    decrypted = decryptor.decrypt(ciphertext, list(enc_header))
    print(f"   Decrypted: {decrypted.decode()}")
    print()

    # Verify
    assert decrypted == message, "Decryption failed!"
    print("4. Verification: SUCCESS - Decrypted message matches original")
    print()

    # Demonstrate error with wrong key
    print("5. Testing with wrong key...")
    keygen2 = zupt.KeyGenerator()
    keypair2 = keygen2.generate_keypair()
    decryptor_wrong = zupt.Decryptor(keypair2.secret_key)

    try:
        decryptor_wrong.decrypt(ciphertext, list(enc_header))
        print("   ERROR: Should have failed!")
    except RuntimeError as e:
        print(f"   Correctly rejected with error: {e}")
    print()

    print("=" * 60)
    print("All examples passed!")
    print("=" * 60)


if __name__ == "__main__":
    main()