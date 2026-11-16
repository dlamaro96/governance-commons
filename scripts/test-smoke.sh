#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu
cd "$(dirname "$0")/.."
sh scripts/test-security.sh
if [ -d .local/toolchain/node/bin ]; then PATH="$PWD/.local/toolchain/node/bin:$PWD/.local/pnpm/node_modules/.bin:$PATH"; export PATH; fi
if [ -z "${GC_BROWSER_EXECUTABLE:-}" ] && [ -x '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' ]; then GC_BROWSER_EXECUTABLE='/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'; export GC_BROWSER_EXECUTABLE; fi
pnpm exec playwright test tests/e2e/vertical-slice.spec.ts
