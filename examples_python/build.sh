#!/usr/bin/env bash
set -euo pipefail
binding_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$binding_dir/.."
pybind11_dir="$(python3 -m pybind11 --cmakedir)"
cmake -S "$project_dir" -B "$project_dir/build" \
    -DCMAKE_BUILD_TYPE=Release -DLIBZUPT_BUILD_PYTHON=ON -Dpybind11_DIR="$pybind11_dir"
cmake --build "$project_dir/build" --config Release --parallel 2
printf 'Set PYTHONPATH to %s/build/examples_python and run the examples.\n' "$project_dir"
