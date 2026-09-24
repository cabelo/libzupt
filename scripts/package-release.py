#!/usr/bin/env python3
"""Package a verified, signed libzupt tag; never publish or read credentials."""
import argparse
import gzip
import hashlib
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tag", help="signed release tag, for example v1.0.14")
    parser.add_argument("output", type=Path, help="new directory outside the checkout")
    args = parser.parse_args()
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", args.tag):
        parser.error("expected a vMAJOR.MINOR.PATCH tag")
    root = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    if output == root or root in output.parents:
        parser.error("release artifacts must be outside the checkout")
    for tool in ("git", "zupt"):
        if not shutil.which(tool):
            parser.error(f"required tool not found: {tool}")
    git = ("git", "-C", str(root))
    run(*git, "verify-tag", args.tag)
    header = run(*git, "show", f"{args.tag}:include/libzupt_version.h",
                 capture_output=True, text=True).stdout
    version = args.tag[1:]
    if f'#define LIBZUPT_VERSION_STRING "{version}"' not in header:
        parser.error("tag does not match the library version")
    changes = run(*git, "show", f"{args.tag}:CHANGES.md",
                  capture_output=True, text=True).stdout
    match = re.search(rf"^## {re.escape(args.tag)}\b.*?(?=^## |\Z)",
                      changes, re.MULTILINE | re.DOTALL)
    if not match:
        parser.error("no changelog entry for this release")
    notes = match.group(0).strip() + "\n"
    if len(notes.encode()) > 4096:
        parser.error("release notes exceed the archive comment limit (4096 bytes)")
    output.mkdir(parents=True, exist_ok=False)
    stem = f"libzupt-{version}-src"
    with tempfile.TemporaryDirectory(prefix="libzupt-release-") as directory:
        scratch = Path(directory)
        source = scratch / f"{stem}.tar"
        run(*git, "archive", "--format=tar", f"--prefix=libzupt-{version}/",
            f"--output={source}", args.tag)
        with source.open("rb") as src, (output / f"{stem}.tar.gz").open("wb") as dst:
            with gzip.GzipFile(filename="", mode="wb", fileobj=dst, compresslevel=9, mtime=0) as gz:
                shutil.copyfileobj(src, gz)
        (output / "release-notes.txt").write_text(notes, encoding="utf-8")
        archive = output / f"{stem}.zupt"
        run("zupt", "compress", "-l", "9", "--solid", "--comment-file",
            str(output / "release-notes.txt"), str(archive), source.name, cwd=scratch)
        run("zupt", "test", str(archive))
        restored = scratch / "restored"
        restored.mkdir()
        run("zupt", "extract", "-o", str(restored), str(archive))
        if hashlib.sha256(source.read_bytes()).digest() != hashlib.sha256(
                (restored / source.name).read_bytes()).digest():
            raise RuntimeError("archive roundtrip differs from the tagged source")
    with (output / "SHA256SUMS").open("w", encoding="ascii") as checksums:
        for suffix in (".tar.gz", ".zupt"):
            artifact = output / (stem + suffix)
            digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
            checksums.write(f"{digest}  {artifact.name}\n")
            print(f"{artifact.name}: {artifact.stat().st_size} bytes; SHA-256 {digest}")
    print(f"Verified source packages for {args.tag}: {output}")


if __name__ == "__main__":
    main()
