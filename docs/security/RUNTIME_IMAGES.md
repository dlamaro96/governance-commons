# Runtime image security

The application uses a pinned minimal Debian runtime with Node 24.22.3 and its
required C++ libraries. The source worker uses pinned Python 3.14.10/Alpine 3.24.
Both retain package inventories, source and tests. See the [decision](../adr/0019-minimal-runtime-images.md).

The Temporal SDK family is pinned together at 1.26.0, including its Rustls
0.23.46 dependency. The Python build and runtime share OpenSSL packages
3.5.9-r1 and zlib 1.4-r0. The [local comparison](../verification/runtime-security-patches-local.json)
records the removed findings and retains every remaining Debian finding.
Compatibility checks and hosted scans qualify their own exact images and revisions.

The `Runtime image security` workflow builds both images on native Linux amd64 and
arm64, checks shipped source and runtime imports, runs the Python worker tests and
scans the exact image IDs. It runs for pull requests, main, manual dispatch and
weekly. The development workflow also audits the installed JavaScript lock.
Neither workflow publishes images or deploys infrastructure.

To scan an existing local image:

```sh
./dev test --suite image-security
```

The command scans both built images into a new `.local/image-security/` directory.
To inspect an individual image or use an existing scanner instead:

```sh
python3 policies/test_scan_images.py
python3 policies/scan_images.py --install \
  --image "$(docker image inspect governance-commons:dev --format '{{.Id}}')" \
  --profile application --output .local/image-scan-application
python3 policies/scan_images.py --install \
  --image "$(docker image inspect governance-commons-python:dev --format '{{.Id}}')" \
  --profile python-worker --output .local/image-scan-python
```

Each output directory must be new. `--install` retrieves the pinned public Trivy
archive and checks its recorded digest and byte size before extracting the binary;
no downloaded installer is executed. `--scanner /absolute/path/to/trivy` instead
uses an existing exact-version scanner and records its binary digest. This is
checksum verification, not an independent signing assertion.

`summary.json` records the revision, dirty state, control hashes, image, scanner,
database timestamp, result and full finding counts. `image.json` retains the full
scanner report and package inventory. A report from a dirty tree does not certify
its base Git revision. The database must be at most 48 hours old. High and critical
findings fail regardless of fix availability; low, medium and unknown findings
remain visible. Scan errors, missing package scopes and suppressed results fail.

These checks cover the two application images. They do not certify infrastructure
images, all deployment profiles, exploitability, DAST, an independent penetration
test or the full release gates. The required-check setting for this new workflow
must be qualified on real hosted and fork runs before it is advertised as enforced.
