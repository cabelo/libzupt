#!/usr/bin/env python3
"""
libzupt - SecureBuffer Example
Shows how to use SecureBuffer for zeroizing sensitive data
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

import zupt


def main():
    print("=" * 60)
    print("libzupt - SecureBuffer Example")
    print("=" * 60)
    print()

    # Create a SecureBuffer from bytes
    print("1. Creating SecureBuffer from bytes...")
    secret = b"My secret password123"
    buffer = zupt.SecureBuffer(secret)
    print(f"   Buffer size: {len(buffer)} bytes")
    print(f"   Buffer content: {buffer.to_string()}")
    print()

    # Create a SecureBuffer with specific size
    print("2. Creating empty SecureBuffer...")
    empty_buffer = zupt.SecureBuffer(64)
    print(f"   Empty buffer size: {len(empty_buffer)} bytes")
    print()

    # Encrypt using SecureBuffer
    print("3. Encrypting with SecureBuffer...")
    keygen = zupt.KeyGenerator()
    keypair = keygen.generate_keypair()
    encryptor = zupt.Encryptor(keypair.public_key)
    decryptor = zupt.Decryptor(keypair.secret_key)

    ciphertext, enc_header = encryptor.encrypt_secure(buffer)
    print(f"   Ciphertext size: {len(ciphertext)} bytes")
    print()

    # Decrypt to SecureBuffer (zeroized on destruction)
    print("4. Decrypting to SecureBuffer...")
    decrypted_buffer = decryptor.decrypt_secure(ciphertext, enc_header)
    print(f"   Decrypted buffer size: {len(decrypted_buffer)} bytes")
    print(f"   Decrypted content: {decrypted_buffer.to_string()}")
    print()

    # Verify
    assert decrypted_buffer.to_bytes() == secret
    print("5. Verification: SUCCESS")
    print()

    # Demonstrate secure wiping
    print("6. Securely wiping buffer...")
    buffer.zeroize()
    print("   Buffer zeroized (content is now zero)")
    print()

    print("=" * 60)
    print("SecureBuffer example passed!")
    print("=" * 60)


if __name__ == "__main__":
    main()