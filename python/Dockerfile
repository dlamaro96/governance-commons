# SPDX-License-Identifier: Apache-2.0
FROM ghcr.io/astral-sh/uv:0.13.9@sha256:d3b601f0c7b118bc1753febf7c41cc80981df678445e0254284eecf84db79a7d AS uv
FROM python:3.14.10-alpine3.24@sha256:5862d971d1f0ae26b258cefa4e893556b1d3aba81bd2ff30888704ad378bab67 AS runtime-base
RUN apk add --no-cache --upgrade libcrypto3=3.5.9-r1 libssl3=3.5.9-r1 zlib=1.4-r0

FROM runtime-base AS dependencies
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /worker
COPY python/pyproject.toml python/uv.lock ./
RUN UV_PYTHON_DOWNLOADS=never uv sync --frozen --no-dev --no-cache

FROM runtime-base AS runtime
WORKDIR /worker
# Runtime executes the frozen venv; package installers are build-only.
RUN rm -rf /usr/local/lib/python3.14/site-packages/pip /usr/local/lib/python3.14/site-packages/pip-*.dist-info /usr/local/lib/python3.14/ensurepip \
    && rm -f /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.14
# Same interpreter/base and venv path; uv is confined to the dependency stage.
COPY --from=dependencies /worker/.venv ./.venv
COPY python/pyproject.toml python/uv.lock ./
COPY python/governance_workers ./governance_workers
COPY python/tests ./tests
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001
EXPOSE 8080
CMD ["/worker/.venv/bin/python", "-m", "governance_workers.server"]
