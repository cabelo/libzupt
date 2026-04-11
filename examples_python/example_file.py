#!/usr/bin/env python3
"""
libzupt - File Encryption/Decryption Example
Shows how to encrypt and decrypt files
"""

import sys
import os
import tempfile
sys.path.insert(0, os.path.dirname(__file__))

import zupt


def main():
    print("=" * 60)
    print("libzupt - File Encryption/Decryption Example")
    print("=" * 60)
    print()

    # Generate key pair
    print("1. Generating key pair...")
    keygen = zupt.KeyGenerator()
    keypair = keygen.generate_keypair()
    print("   Key pair generated")
    print()

    # Create encryptor and decryptor
    encryptor = zupt.Encryptor(keypair.public_key)
    decryptor = zupt.Decryptor(keypair.secret_key)

    # Create a temporary test file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        test_file = f.name
        f.write("This is a secret text file.\n")
        f.write("Line 2: Contains sensitive information.\n")
        f.write("Line 3: End of file.\n")

    print(f"2. Created test file: {test_file}")
    with open(test_file, 'rb') as f:
        original_content = f.read()
    print(f"   Original content:\n{original_content.decode()}")

    # Encrypt the file
    print("3. Encrypting file...")
    ciphertext, enc_header = encryptor.encrypt_file(test_file)
    print(f"   Ciphertext size: {len(ciphertext)} bytes")
    print(f"   Header size: {len(enc_header)} bytes")
    print()

    # Save ciphertext to a file
    cipher_file = test_file + ".enc"
    with open(cipher_file, 'wb') as f:
        f.write(ciphertext)
    print(f"4. Saved ciphertext to: {cipher_file}")
    print()

    # Decrypt the file
    print("5. Decrypting file...")
    decrypted = decryptor.decrypt_file(cipher_file, enc_header)
    print(f"   Decrypted size: {len(decrypted)} bytes")
    print(f"   Decrypted content:\n{decrypted.decode()}")

    # Verify
    assert decrypted == original_content, "Decryption failed!"
    print()

    # Clean up
    os.remove(test_file)
    os.remove(cipher_file)
    print("6. Cleaned up temporary files")
    print()

    print("=" * 60)
    print("File encryption/decryption example passed!")
    print("=" * 60)


if __name__ == "__main__":
    main()