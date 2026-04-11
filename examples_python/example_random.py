#!/usr/bin/env python3
"""
libzupt - Random Bytes and Hashing Example
Shows how to generate random bytes and compute hashes
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

import zupt


def main():
    print("=" * 60)
    print("libzupt - Random Bytes and Hashing Example")
    print("=" * 60)
    print()

    # Generate random bytes
    print("1. Generating random bytes...")
    random_bytes = zupt.random_bytes(32)
    print(f"   Generated {len(random_bytes)} random bytes:")
    print(f"   {random_bytes.hex()}")
    print()

    # Generate a nonce
    print("2. Generating AES nonce...")
    nonce = zupt.random_bytes(zupt.AES_NONCE_SIZE)
    print(f"   Nonce ({len(nonce)} bytes): {nonce.hex()}")
    print()

    # Compute SHA-256 hash
    print("3. Computing SHA-256 hash...")
    data = b"Hello, Post-Quantum World!"
    sha256_hash = zupt.sha256(data)
    print(f"   Data: {data}")
    print(f"   SHA-256: {sha256_hash.hex()}")
    print()

    # Compute SHA3-512 hash
    print("4. Computing SHA3-512 hash...")
    sha3_512_hash = zupt.sha3_512(data)
    print(f"   Data: {data}")
    print(f"   SHA3-512: {sha3_512_hash.hex()}")
    print()

    # Use random bytes for key generation simulation
    print("5. Simulating key derivation...")
    salt = zupt.random_bytes(16)
    print(f"   Salt: {salt.hex()}")
    derived_key = zupt.sha256(salt + b"my-secret-password")
    print(f"   Derived key (32 bytes): {derived_key.hex()}")
    print()

    print("=" * 60)
    print("Random bytes and hashing example passed!")
    print("=" * 60)


if __name__ == "__main__":
    main()