# SPDX-License-Identifier: Apache-2.0
FROM ghcr.io/astral-sh/uv:0.11.14@sha256:1025398289b62de8269e70c45b91ffa37c373f38118d7da036fb8bb8efc85d97 AS uv
FROM python:3.15.2-alpine3.24@sha256:0f9552bb28711333da16915ec146f5e6bb44a7fdac9ced15dc17c2e0206346dd AS runtime-base
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
