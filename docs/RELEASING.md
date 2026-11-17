# Maintainer release procedure

Use a reviewed version/commit, align `include/libzupt_version.h` and CHANGES.md,
and run the default suite, installed consumers, interop, sanitizers and platform
jobs. Record outstanding platform/audit limitations. Never infer a higher
external score or certification from these checks.

Sign the maintainer commit and release tag using the maintainer's own key.
Do not embed credentials, signing keys or customer data in source/packages.

```sh
git verify-commit HEAD
git tag -s v2.0.0 -m "Release libzupt 2.0.0"
git verify-tag v2.0.0
python3 scripts/package-release.py v2.0.0 ../libzupt-2.0.0-release
bash scripts/sign-release.sh ../libzupt-2.0.0-release FULL_GPG_FINGERPRINT
```

The existing packaging workflow requires Python 3.12+, Git and the `zupt`
compressor. It verifies the signed tag/version, exports tagged sources, creates
reproducible gzip plus a level-9 solid `.zupt` source archive, tests/extracts the
archive and compares restored bytes. It inventories exactly the exported tag
as SPDX 2.3 JSON and checksums source assets, SBOM and release notes.

`sign-release.sh` verifies SHA256SUMS before signing. Publish the checksum
signature and the maintainer's public-key fingerprint through a separately
trusted channel. A signature is not a vulnerability scan or cryptographic audit.
The source SBOM describes this source tree, not every downstream OS/runtime
or separately installed binding dependency. Retain binding lockfiles and scan
those dependencies with the tools appropriate to the deployment.

CI creates tested binary artifacts and source inventories, but does not sign
with a maintainer key or publish a GitHub Release as a bot. After verifying the
actual tag-job results, publish the reviewed files with the maintainer account.
A GPG signature cannot be generated without the real maintainer key.

To inspect an unsigned source inventory independently:

```sh
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) python3 scripts/generate-sbom.py \
  --output ../libzupt-source.spdx.json
```

Source inventories, benchmark output, generated API docs and validation working
notes belong outside the source checkout. Link actual release/CI evidence in
any retest request.
