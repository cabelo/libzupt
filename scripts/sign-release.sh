#!/usr/bin/env bash
set -euo pipefail
if [ "$#" -ne 2 ]; then
    echo "Usage: sign-release.sh artifact-directory full-GPG-fingerprint" >&2
    exit 2
fi
artifact_dir="$1"
signing_fingerprint="$2"
case "$signing_fingerprint" in
    *[!0-9A-Fa-f]*|'') echo "Use a full hexadecimal GPG fingerprint" >&2; exit 2 ;;
esac
if [ "${#signing_fingerprint}" -lt 40 ]; then
    echo "Use a full fingerprint, not a short key ID" >&2
    exit 2
fi
cd "$artifact_dir"
sha256sum --check SHA256SUMS
gpg --local-user "$signing_fingerprint" --armor --detach-sign \
    --output SHA256SUMS.asc SHA256SUMS
gpg --verify SHA256SUMS.asc SHA256SUMS
