#!/usr/bin/env python3
"""Generate an SPDX 2.3 inventory of source files, not a vulnerability scan."""
import argparse
import datetime
import hashlib
import json
import os
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root, output = args.root.resolve(), args.output.resolve()
    version = (root / "include/libzupt_version.h").read_text().split('LIBZUPT_VERSION_STRING "')[1].split('"')[0]
    files, sha1s = [], []
    skip = {".git", "__pycache__", "node_modules", "target", "build", ".venv"}
    tracked = subprocess.run(["git", "-C", str(root), "ls-files", "--cached", "--others",
                              "--exclude-standard", "-z"], capture_output=True)
    if tracked.returncode == 0:
        candidates = [root / name.decode("utf-8") for name in tracked.stdout.split(b"\0") if name]
    else:
        candidates = list(root.rglob("*"))
    for path in sorted(candidates):
        rel = path.relative_to(root)
        if any(p in skip for p in rel.parts) or path.resolve() == output:
            continue
        if path.is_symlink():
            continue
        if not path.is_file():
            continue
        data = path.read_bytes()
        sha256, sha1 = hashlib.sha256(data).hexdigest(), hashlib.sha1(data).hexdigest()
        sha1s.append(sha1)
        files.append({"SPDXID": "SPDXRef-File-" + hashlib.sha256(rel.as_posix().encode()).hexdigest()[:24],
                      "fileName": "./" + rel.as_posix(),
                      "checksums": [{"algorithm": "SHA256", "checksumValue": sha256},
                                    {"algorithm": "SHA1", "checksumValue": sha1}],
                      "licenseConcluded": "NOASSERTION", "licenseInfoInFiles": ["NOASSERTION"],
                      "copyrightText": "NOASSERTION"})
    tree_hash = hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch is None:
        stamp = subprocess.run(["git", "-C", str(root), "log", "-1", "--format=%ct"],
                               capture_output=True, text=True)
        epoch = stamp.stdout.strip() if stamp.returncode == 0 else str(int((root / "include/libzupt_version.h").stat().st_mtime))
    created = datetime.datetime.fromtimestamp(int(epoch),
                                               datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    package_id = "SPDXRef-Package-libzupt"
    document = {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
                "name": "libzupt-" + version + "-source",
                "documentNamespace": "https://github.com/cabelo/libzupt/spdx/" + tree_hash,
                "creationInfo": {"created": created, "creators": ["Tool: libzupt-source-sbom"]},
                "packages": [{"SPDXID": package_id, "name": "libzupt", "versionInfo": version,
                              "downloadLocation": "https://github.com/cabelo/libzupt",
                              "filesAnalyzed": True, "licenseConcluded": "NOASSERTION",
                              "licenseDeclared": "MIT", "copyrightText": "NOASSERTION",
                              "packageVerificationCode": {"packageVerificationCodeValue":
                                  hashlib.sha1("".join(sorted(sha1s)).encode()).hexdigest()}}],
                "files": files,
                "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
                                   "relatedSpdxElement": package_id}] +
                    [{"spdxElementId": package_id, "relationshipType": "CONTAINS",
                      "relatedSpdxElement": f["SPDXID"]} for f in files]}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=2) + "\n")
    print(json.dumps({"source_files": len(files), "output": str(output), "tree_sha256": tree_hash}))


if __name__ == "__main__":
    main()
