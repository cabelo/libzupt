#!/usr/bin/env python3
"""Build twice in different directories and compare installed library bytes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cmake", default="cmake")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    if "SOURCE_DATE_EPOCH" not in env:
        env["SOURCE_DATE_EPOCH"] = subprocess.check_output(
            ["git", "-C", str(root), "log", "-1", "--format=%ct"], text=True).strip()
    inventories = []
    with tempfile.TemporaryDirectory(prefix="libzupt-repro-") as temp:
        for name in ["first", "different-build-path"]:
            build = Path(temp) / name
            install = build / "install"
            command = [args.cmake, "-S", str(root), "-B", str(build),
                       "-DCMAKE_BUILD_TYPE=Release", "-DCMAKE_INSTALL_LIBDIR=lib",
                       "-DLIBZUPT_BUILD_TESTS=OFF", "-DLIBZUPT_BUILD_EXAMPLES=OFF", "-DLIBZUPT_BUILD_PYTHON=OFF",
                       "-DCMAKE_C_FLAGS=-ffile-prefix-map=" + str(root) + "=. -ffile-prefix-map=" + str(build) + "=.build",
                       "-DCMAKE_CXX_FLAGS=-ffile-prefix-map=" + str(root) + "=. -ffile-prefix-map=" + str(build) + "=.build"]
            for step in [command, [args.cmake, "--build", str(build), "--parallel", "2"],
                         [args.cmake, "--install", str(build), "--prefix", str(install)]]:
                result = subprocess.run(step, env=env, capture_output=True, text=True)
                if result.returncode:
                    raise RuntimeError(result.stdout + result.stderr)
            inventory = {}
            for path in sorted((install / "lib").glob("*")):
                if path.is_file() and not path.is_symlink():
                    inventory[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
            if not inventory:
                raise RuntimeError("No installed libraries to compare")
            inventories.append(inventory)
    if inventories[0] != inventories[1]:
        raise RuntimeError("Builds differ: " + json.dumps(inventories, indent=2))
    print(json.dumps({"suite": "same-toolchain reproducible build", "matched": inventories[0],
                      "source_date_epoch": env["SOURCE_DATE_EPOCH"]}))


if __name__ == "__main__":
    main()
