#!/usr/bin/env python3
"""
libzupt - Key Generation and Key Management Example
Shows how to generate keys and manage them
"""

import sys
import os
import tempfile
sys.path.insert(0, os.path.dirname(__file__))

import zupt


def main():
    print("=" * 60)
    print("libzupt - Key Generation and Management Example")
    print("=" * 60)
    print()

    # Create a temporary directory for keys
    with tempfile.TemporaryDirectory() as tmpdir:
        priv_key_file = os.path.join(tmpdir, "private.key")
        pub_key_file = os.path.join(tmpdir, "public.key")

        # Generate a key pair
        print("1. Generating key pair...")
        keygen = zupt.KeyGenerator()
        keypair = keygen.generate_keypair()
        print(f"   Public key: {len(keypair.public_key)} bytes")
        print(f"   Private key: {len(keypair.secret_key)} bytes")
        print()

        # Save the key pair
        print("2. Saving key pair...")
        keygen.save_keypair(keypair, priv_key_file)
        print(f"   Saved to: {priv_key_file}")
        print()

        # Export public key
        print("3. Exporting public key...")
        keygen.export_public_key(priv_key_file, pub_key_file)
        print(f"   Saved to: {pub_key_file}")
        print()

        # Load the key pair back
        print("4. Loading key pair...")
        loaded_keypair = keygen.load_keypair(priv_key_file)
        print(f"   Loaded public key: {len(loaded_keypair.public_key)} bytes")
        print(f"   Loaded private key: {len(loaded_keypair.secret_key)} bytes")
        assert loaded_keypair.public_key == keypair.public_key
        assert loaded_keypair.secret_key == keypair.secret_key
        print("   Keys match!")
        print()

        # Load public key only
        print("5. Loading public key only...")
        loaded_pub = keygen.load_public_key(pub_key_file)
        print(f"   Loaded public key: {len(loaded_pub)} bytes")
        assert loaded_pub == keypair.public_key
        print("   Public key matches!")
        print()

        # Demonstrate key sizes
        print("6. Key sizes (bytes):")
        print(f"   ML-KEM public key: {zupt.MLKEM_PUBLICKEYBYTES}")
        print(f"   X25519 public key: {zupt.X25519_KEYBYTES}")
        print(f"   Hybrid public key: {zupt.HYBRID_PUB_KEY_SIZE}")
        print(f"   Hybrid private key: {zupt.HYBRID_PRIV_KEY_SIZE}")
        print(f"   Encryption header: {zupt.HYBRID_ENC_HEADER_SIZE}")
        print()

    print("=" * 60)
    print("Key management example passed!")
    print("=" * 60)


if __name__ == "__main__":
    main()