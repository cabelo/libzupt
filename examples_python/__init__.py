"""
libzupt - Python bindings for Hybrid Post-Quantum Encryption

This package provides Python bindings for the libzupt C++ library,
which implements hybrid post-quantum encryption using ML-KEM-768
and X25519.

Usage:
    import zupt

    # Generate key pair
    keygen = zupt.KeyGenerator()
    keypair = keygen.generate_keypair()

    # Encrypt data
    encryptor = zupt.Encryptor(keypair.public_key)
    ciphertext, header = encryptor.encrypt(b"secret message")

    # Decrypt data
    decryptor = zupt.Decryptor(keypair.secret_key)
    decrypted = decryptor.decrypt(ciphertext, header)

See the example_*.py files for more detailed examples.
"""

from zupt import *

__version__ = zupt.__version__
__author__ = "Cristian Cezar Moisés"

__all__ = [
    # Classes
    'KeyGenerator',
    'Encryptor',
    'Decryptor',
    'SecureBuffer',
    'KeyPair',
    'ZuptError',
    # Constants
    'MLKEM_PUBLICKEYBYTES',
    'MLKEM_SECRETKEYBYTES',
    'MLKEM_CIPHERTEXTBYTES',
    'MLKEM_SSBYTES',
    'X25519_KEYBYTES',
    'HYBRID_PUB_KEY_SIZE',
    'HYBRID_PRIV_KEY_SIZE',
    'HYBRID_ENC_HEADER_SIZE',
    'AES_KEY_SIZE',
    'AES_NONCE_SIZE',
    'HMAC_SIZE',
    # Functions
    'random_bytes',
    'sha256',
    'sha3_512',
    'secure_wipe',
]