# ADR 0019: Minimal, inventoried runtime images

Status: accepted for development; cross-platform and release qualification remain separate.

The application and source workers previously inherited Debian utilities and Python
package installers that the services do not use. A current vulnerability database
reported high and critical findings in those images. Updating the Debian suite
alone retained many of those packages and findings.

Keep the pinned Node 24.22.3 binary and frozen production dependency closure. Run
them on the pinned distroless Debian 13 no-SSL base with the matching distroless
GCC runtime libraries. Copy their package metadata and copyright files alongside
the actual libraries. The runtime contains no shell or package manager. Node uses
its bundled TLS implementation; removing an unused system OpenSSL library does
not remove or certify Node's TLS implementation. Temporal's native bridge must
load and the real workflow worker must become healthy before adoption.

The API qualification runner previously used GNU `timeout`. Its replacement is
a separate Node supervisor inside the container, preserving the 1,740-second
deadline, ten-second TERM/KILL grace and 1,800-second host bound. It owns a child
process group and cleans its descendants on normal exit, failure, timeout or
forwarded termination. Qualification must exercise blocked event loops and
descendants as well as the real API suite; removing the timeout is not acceptable.

The Python worker uses pinned Python 3.14.10 on Alpine 3.24, with the same uv-managed
psycopg lock and production virtual environment. Its musllinux wheels are already
present in the frozen lock. Runtime pip and ensurepip are removed because all
dependencies are installed in the builder. Worker source, tests and lock metadata
remain in the image. Real PostgreSQL TLS, source scanning and existing worker
tests remain necessary compatibility checks for this libc change.

Build and scan both native Linux architectures in the runtime-security workflow.
The pinned scanner retains all severities and full package inventories; any high
or critical finding fails, including an unfixed finding. Missing image/language
coverage, malformed output, an outdated database or scanner failure also fails.
No ignore list or exception is introduced. Weekly scans detect newly disclosed
vulnerabilities in pinned components. Scan passes are scoped to their immutable
image and database; infrastructure images, application testing, independent review
and supported-release approval remain separate obligations.

References: [distroless images and package selection](https://github.com/GoogleContainerTools/distroless),
[official Python images](https://hub.docker.com/_/python), and
[Trivy vulnerability scanning](https://trivy.dev/docs/latest/scanner/vulnerability/).
