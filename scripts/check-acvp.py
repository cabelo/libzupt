#!/usr/bin/env python3
"""Offline FIPS 203 regression vectors; this is not CAVP/CMVP validation."""
import argparse
import ctypes
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", required=True)
    parser.add_argument("--vectors", type=Path,
                        default=Path(__file__).resolve().parents[1] / "tests/vectors")
    args = parser.parse_args()
    lib = ctypes.CDLL(str(Path(args.library).resolve()))
    pointer = ctypes.c_void_p
    functions = {
        "zupt_test_mlkem_keygen": 4, "zupt_test_mlkem_encaps": 4,
        "zupt_mlkem768_decaps": 3, "zupt_mlkem768_public_key_check": 1,
        "zupt_mlkem768_secret_key_check": 1,
    }
    for name, count in functions.items():
        fn = getattr(lib, name)
        fn.argtypes = [pointer] * count
        fn.restype = ctypes.c_int

    def buf(value):
        data = bytes.fromhex(value)
        return ctypes.create_string_buffer(data, len(data))

    passed = failed = 0

    def check(ok, label):
        nonlocal passed, failed
        if ok:
            passed += 1
        else:
            failed += 1
            print("FAIL:", label)

    data = json.loads((args.vectors / "acvp-keygen.json").read_text())
    for group in data["testGroups"]:
        for test in group["tests"]:
            pk, sk = ctypes.create_string_buffer(1184), ctypes.create_string_buffer(2400)
            ret = lib.zupt_test_mlkem_keygen(pk, sk, buf(test["d"]), buf(test["z"]))
            check(ret == 0 and pk.raw == bytes.fromhex(test["ek"])
                  and sk.raw == bytes.fromhex(test["dk"]), f"KeyGen tcId={test['tcId']}")

    data = json.loads((args.vectors / "acvp-encap-decap.json").read_text())
    for group in data["testGroups"]:
        operation = group["function"]
        for test in group["tests"]:
            label = f"{operation} tcId={test['tcId']}"
            if operation == "encapsulation":
                ct, ss = ctypes.create_string_buffer(1088), ctypes.create_string_buffer(32)
                ret = lib.zupt_test_mlkem_encaps(ct, ss, buf(test["ek"]), buf(test["m"]))
                check(ret == 0 and ct.raw == bytes.fromhex(test["c"])
                      and ss.raw == bytes.fromhex(test["k"]), label)
                # Also decapsulate every valid encapsulation fixture.
                out = ctypes.create_string_buffer(32)
                ret = lib.zupt_mlkem768_decaps(out, buf(test["c"]), buf(test["dk"]))
                check(ret == 0 and out.raw == bytes.fromhex(test["k"]), label + " / decaps")
            elif operation == "decapsulation":
                out = ctypes.create_string_buffer(32)
                ret = lib.zupt_mlkem768_decaps(out, buf(test["c"]), buf(test["dk"]))
                check(ret == 0 and out.raw == bytes.fromhex(test["k"]), label)
            elif operation == "encapsulationKeyCheck":
                ret = lib.zupt_mlkem768_public_key_check(buf(test["ek"]))
                check((ret == 0) == test["testPassed"], label)
            elif operation == "decapsulationKeyCheck":
                ret = lib.zupt_mlkem768_secret_key_check(buf(test["dk"]))
                check((ret == 0) == test["testPassed"], label)
            else:
                raise ValueError(f"Unsupported ACVP operation: {operation}")
    print(json.dumps({"suite": "FIPS203 ACVP ML-KEM-768", "passed": passed,
                      "failed": failed, "nist_certification": False}))
    return bool(failed)


if __name__ == "__main__":
    raise SystemExit(main())
