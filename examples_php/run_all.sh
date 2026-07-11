#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

for example in \
    example_basic.php \
    example_file.php \
    example_keygen.php \
    example_random.php \
    example_secure_buffer.php
do
    printf '\n>>> Executando %s\n\n' "$example"
    php -d ffi.enable=1 "$example"
done
