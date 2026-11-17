#!/usr/bin/env python3
import argparse
from pathlib import Path
import subprocess
import tempfile


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--example", required=True)
    p.add_argument("--migrate", required=True)
    args = p.parse_args()
    values = {}
    source = Path(__file__).resolve().parents[1] / "tests/vectors/legacy-v1.rsp"
    for line in source.read_text().splitlines():
        if " = " in line:
            key, value = line.split(" = ", 1)
            values[key] = bytes.fromhex(value)
    with tempfile.TemporaryDirectory(prefix="libzupt-migration-") as temp:
        root = Path(temp)
        for name in ["key", "ciphertext", "header"]:
            (root / name).write_bytes(values[name])
        def run(*argv):
            subprocess.run([str(a) for a in argv], check=True, capture_output=True, text=True)
        run(args.example, "genkey", root / "new.key", root / "new.pub")
        common = [args.migrate, root / "key", root / "ciphertext", root / "header"]
        bad = subprocess.run([str(a) for a in common + ["00" * 32, root / "new.pub", root / "bad"]],
                             capture_output=True)
        assert bad.returncode != 0 and not (root / "bad").exists()
        run(*common, values["sha256"].hex(), root / "new.pub", root / "new.cipher")
        run(args.example, "decrypt", root / "new.key", root / "new.cipher",
            root / "restored", root / "new.cipher.header")
        assert (root / "restored").read_bytes() == values["plaintext"]
    print("End-to-end v1-to-v2 migration and digest rejection passed")


if __name__ == "__main__":
    main()
