#!/usr/bin/env python3
"""Compare SHA/SHAKE/HMAC to Python and AES-CTR to SP 800-38A vectors."""
import argparse
import ctypes
import hashlib
import hmac
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", required=True)
    args = parser.parse_args()
    lib = ctypes.CDLL(str(Path(args.library).resolve()))
    count = 0
    for size in [0, 1, 15, 16, 17, 63, 64, 65, 71, 72, 73, 135, 136, 137, 168, 1024]:
        data = bytes(i % 256 for i in range(size))
        for name in ["sha256", "sha3_256", "sha3_512", "shake128", "shake256"]:
            fn = getattr(lib, "zupt_" + name)
            shake = name.startswith("shake")
            out_size = 79 if shake else 64 if name.endswith("512") else 32
            fn.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p] + ([ctypes.c_size_t] if shake else [])
            fn.restype = None
            output = ctypes.create_string_buffer(out_size)
            fn(data, size, output, *([out_size] if shake else []))
            reference_name = name.replace("shake", "shake_") if shake else name
            digest = getattr(hashlib, reference_name)(data)
            expected = digest.digest(out_size) if shake else digest.digest()
            assert output.raw == expected, (name, size)
            count += 1
        fn = lib.zupt_hmac_sha256
        fn.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
        fn.restype = None
        key = bytes(range(100))
        output = ctypes.create_string_buffer(32)
        fn(key, len(key), data, len(data), output)
        assert output.raw == hmac.digest(key, data, "sha256")
        count += 1
    key = bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
    iv = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    plain = bytes.fromhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
                          "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
    expected = bytes.fromhex("601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c5"
                             "2b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6")
    lib.zupt_aes256_ctr.argtypes = [ctypes.c_void_p] * 4 + [ctypes.c_size_t]
    lib.zupt_aes256_ctr.restype = None
    for size in [0, 1, 15, 16, 17, 31, 32, 63, 64]:
        output = ctypes.create_string_buffer(max(1, size))
        lib.zupt_aes256_ctr(key, iv, plain[:size], output, size)
        assert output.raw[:size] == expected[:size], ("AES-CTR", size)
        count += 1
    print(json.dumps({"suite": "primitive reference checks", "passed": count, "failed": 0}))


if __name__ == "__main__":
    main()
