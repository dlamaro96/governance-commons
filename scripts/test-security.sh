#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu
cd "$(dirname "$0")/.."
docker compose --env-file .local/runtime.env -f deploy/compose/compose.yaml exec -T api pnpm test:integration
