# Qtonic retest evidence checklist

Prepare a request after the reviewed changes have a published version/tag and
public per-platform test results. Do not send a claim of FIPS 140-3 validation,
independent audit, or a guaranteed score increase.

| Registry field | Proposed correction / evidence |
| --- | --- |
| Category | Library / SDK for hybrid file and memory encryption; not a CA/PKI product |
| Algorithms | ML-KEM-768, X25519, SHA3-512, AES-256-CTR, HMAC-SHA256 |
| NIST category | ML-KEM-768 targets category 3; distinguish algorithm from module validation |
| Languages | Native C/C++; bindings/examples in Python, Go, Rust, Java, Node.js, .NET and PHP; attach actual test matrix |
| Documentation | README, API reference, FORMAT, SECURITY, MIGRATION and TESTING, pinned to reviewed tag |
| Correctness | 105 offline ACVP checks plus independent KEM interop results |
| Supply chain | Signed tag, source SBOM, signed SHA256SUMS, reproducibility report and binding lockfiles |
| Limits | Independent audit / FIPS 140-3 validation remain unclaimed; attach pending platform results honestly |

Ask the evaluator to identify the commit, methodology version, executed commands,
evidence artifacts and rationale for each dimension, including Documentation
and the contested Quantum Resistance label. Request corrected metadata and a
fresh evaluation of the published tag through the same public rubric.
The evaluator controls its own score and publication gates.

Suggested maintainer request:

> Please reassess libzupt at the reviewed release tag linked below. The release
> corrects ML-KEM-768 behavior against final FIPS 203, versions the application
> format, authenticates complete messages and provides explicit digest-checked
> legacy recovery. Please review the attached reproducible test evidence and
> metadata corrections. These results are implementation evidence, not a claim
> of FIPS 140-3 validation or a completed independent cryptographic audit.

Replace the release/tag/evidence links with actual published URLs before sending.
