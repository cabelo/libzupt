# Verification and limits

Run the complete default suite:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DLIBZUPT_BUILD_PYTHON=OFF
cmake --build build --config Release --parallel 2
ctest --test-dir build -C Release --output-on-failure --output-junit tests.xml
```

## What the checks establish

| Check | Evidence | Limit |
| --- | --- | --- |
| Offline ACVP | 105 ML-KEM-768 checks; pinned NIST source | Not CAVP/CMVP certification |
| Primitive references | SHA/SHAKE/HMAC comparisons; AES KAT/CTR vectors | Not a side-channel audit |
| Mutation/length tests | Header/ciphertext modifications, all prefix truncations, whole-block removal | Bounded regression cases |
| Legacy recovery | Public v1 fixture, trusted digest required, normal downgrade rejected | Does not establish a missing legacy digest |
| Installed package | Shared/static consumer after relocation | Per tested platform/toolchain |
| Cross implementation | Both KEM directions and modified-ciphertext rejection against pqcrypto | Primitive, not whole application-format interoperability |

```sh
python3 -m pip install pqcrypto==1.0.0
python3 scripts/check-interop.py --library build/libzupt.so --iterations 100
python3 scripts/benchmark.py --library build/libzupt.so --output ../benchmark.json
python3 scripts/check-reproducible.py
```

The benchmark includes 10 warmups and at least 100 measured iterations for
key generation, encapsulation and decapsulation. It records nearest-rank p95/
p99, CPU/architecture and the library hash. Python/ctypes overhead is included.
It does not predict production throughput or compare different hardware.
Reproducibility means byte-identical installed libraries from the same sources,
toolchain and environment in different build directories; it does not claim
identical binaries across different compilers or operating systems.

## Sanitizers

```sh
cmake -S . -B asan -DCMAKE_BUILD_TYPE=Debug -DLIBZUPT_SANITIZERS=ON \
  -DLIBZUPT_BUILD_PYTHON=OFF -DLIBZUPT_BUILD_EXAMPLES=OFF
cmake --build asan --parallel 2
ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 \
  ctest --test-dir asan --output-on-failure -LE python
```

Python/ctypes checks run against the normal build; loading an ASan-instrumented
shared library into an uninstrumented Python process needs runtime preloading.
LeakSanitizer may not run under ptrace/restricted process inspection. If a local
run requires `detect_leaks=0`, record that limitation and do not report leak
checking as passed. GitHub Linux CI retains leak detection.

## Coverage-guided fuzzing

```sh
cmake -S . -B fuzz -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
  -DLIBZUPT_SANITIZERS=ON -DLIBZUPT_BUILD_FUZZERS=ON \
  -DLIBZUPT_BUILD_TESTS=OFF -DLIBZUPT_BUILD_EXAMPLES=OFF -DLIBZUPT_BUILD_PYTHON=OFF
cmake --build fuzz --parallel 2
mkdir -p ../fuzz-corpus
fuzz/zupt_fuzz_decrypt ../fuzz-corpus -max_total_time=60 -max_len=8192
```

The bounded mutation test is separate from libFuzzer. A short fuzz run is not
an exhaustive parser or cryptographic audit. Preserve crash inputs and report
the exact commit, compiler, flags and duration.

## Binding/platform coverage

Core CI executes tests on Linux GCC/Clang, ARM64, macOS and Windows. Binding CI
has separate Linux jobs. Inspect each job result; a configured matrix or a
native build alone is not a passing language/runtime test. Do not publish a
passing badge, count or platform claim for an unexecuted check.
