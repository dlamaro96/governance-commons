#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu
cd "$(dirname "$0")/.."
docker compose --project-name governance-commons --env-file .local/runtime.env -f deploy/compose/compose.yaml \
  run --rm --no-deps -T migrate node --import tsx scripts/search-test-fixture.ts prepare
python3 policies/api_evidence.py run
