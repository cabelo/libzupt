#!/usr/bin/env python3
"""Cross-implementation ML-KEM-768 checks using pqcrypto (test dependency)."""
import argparse
import ctypes
import importlib.metadata
import json
from pathlib import Path


def main():
    from pqcrypto.kem import ml_kem_768 as reference
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", required=True)
    parser.add_argument("--iterations", type=int, default=100)
    args = parser.parse_args()
    if args.iterations < 1:
        parser.error("iterations must be positive")
    lib = ctypes.CDLL(str(Path(args.library).resolve()))
    for name, n in [("keygen", 2), ("encaps", 3), ("decaps", 3)]:
        fn = getattr(lib, "zupt_mlkem768_" + name)
        fn.argtypes = [ctypes.c_void_p] * n
        fn.restype = ctypes.c_int
    for _ in range(args.iterations):
        pk, sk = reference.keygen()
        ct, ss = ctypes.create_string_buffer(1088), ctypes.create_string_buffer(32)
        assert lib.zupt_mlkem768_encaps(ct, ss, pk) == 0
        assert reference.decaps(sk, ct.raw) == ss.raw
        own_pk, own_sk = ctypes.create_string_buffer(1184), ctypes.create_string_buffer(2400)
        assert lib.zupt_mlkem768_keygen(own_pk, own_sk) == 0
        ciphertext, expected = reference.encaps(own_pk.raw)
        out = ctypes.create_string_buffer(32)
        assert lib.zupt_mlkem768_decaps(out, ciphertext, own_sk) == 0
        assert out.raw == expected
        changed = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
        assert lib.zupt_mlkem768_decaps(out, changed, own_sk) == 0
        assert out.raw == reference.decaps(own_sk.raw, changed)
    print(json.dumps({"suite": "ML-KEM-768 interop", "reference": "pqcrypto",
                      "reference_version": importlib.metadata.version("pqcrypto"),
                      "passed": args.iterations * 3, "failed": 0}))


if __name__ == "__main__":
    main()
