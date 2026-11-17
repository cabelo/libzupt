#!/usr/bin/env python3
"""Test explicit, digest-checked v1 recovery and default downgrade rejection."""
import argparse
import ctypes
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", required=True)
    args = parser.parse_args()
    lib = ctypes.CDLL(str(Path(args.library).resolve()))
    values = {}
    path = Path(__file__).resolve().parents[1] / "tests/vectors/legacy-v1.rsp"
    for line in path.read_text().splitlines():
        if " = " in line:
            key, value = line.split(" = ", 1)
            values[key] = bytes.fromhex(value)
    common = [ctypes.c_void_p, ctypes.c_size_t] * 3
    lib.zupt_hybrid_decrypt.argtypes = common + [ctypes.POINTER(ctypes.c_size_t)]
    lib.zupt_hybrid_decrypt.restype = ctypes.c_void_p
    lib.zupt_hybrid_decrypt_legacy.argtypes = common + [ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t)]
    lib.zupt_hybrid_decrypt_legacy.restype = ctypes.c_void_p
    # Use the library allocator's matching release function on every platform.
    lib.zupt_free.argtypes = [ctypes.c_void_p]
    lib.zupt_free.restype = None
    key, ciphertext, header = (values[k] for k in ["key", "ciphertext", "header"])
    params = [key, len(key), ciphertext, len(ciphertext), header, len(header)]
    length = ctypes.c_size_t(99)
    assert not lib.zupt_hybrid_decrypt(*params, ctypes.byref(length))
    assert length.value == 0
    for digest, should_pass in [(values["sha256"], True), (bytes(32), False), (None, False)]:
        ptr = lib.zupt_hybrid_decrypt_legacy(*params, digest, ctypes.byref(length))
        if should_pass:
            assert ptr and ctypes.string_at(ptr, length.value) == values["plaintext"]
        else:
            assert not ptr and length.value == 0
        if ptr:
            lib.zupt_free(ptr)
    print(json.dumps({"suite": "legacy migration", "passed": 4, "failed": 0}))


if __name__ == "__main__":
    main()
