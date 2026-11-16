#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu
cd "$(dirname "$0")/.."
docker compose --env-file .local/runtime.env -f deploy/compose/compose.yaml exec -T api sh -c 'exec node --import tsx --test --test-concurrency=1 tests/integration/*.test.ts'
if [ -d .local/toolchain/node/bin ]; then PATH="$PWD/.local/toolchain/node/bin:$PWD/.local/pnpm/node_modules/.bin:$PATH"; export PATH; fi
if [ -z "${GC_BROWSER_EXECUTABLE:-}" ] && [ -x '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' ]; then GC_BROWSER_EXECUTABLE='/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'; export GC_BROWSER_EXECUTABLE; fi
pnpm exec playwright test tests/e2e/vertical-slice.spec.ts
