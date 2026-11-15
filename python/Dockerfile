# SPDX-License-Identifier: Apache-2.0
FROM ghcr.io/astral-sh/uv:0.11.14@sha256:1025398289b62de8269e70c45b91ffa37c373f38118d7da036fb8bb8efc85d97 AS uv
FROM python:3.14.5-slim-bookworm@sha256:a9bee15510a364124aa24692899d269835683b883de42f7ebec8c293cf679ccb
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /worker
COPY python/pyproject.toml python/uv.lock ./
RUN uv sync --frozen --no-dev --no-cache
COPY python/governance_workers ./governance_workers
COPY python/tests ./tests
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001
EXPOSE 8080
CMD ["/worker/.venv/bin/python", "-m", "governance_workers.server"]
