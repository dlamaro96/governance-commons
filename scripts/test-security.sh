#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu
cd "$(dirname "$0")/.."
python3 policies/api_evidence.py run
