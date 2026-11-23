#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu
cd "$(dirname "$0")/.."
mkdir -p .local/image-security
scan_output=$(mktemp -d "$PWD/.local/image-security/run-XXXXXXXX")
python3 policies/test_scan_images.py
python3 policies/scan_images.py --install \
  --image "$(docker image inspect governance-commons:dev --format '{{.Id}}')" \
  --profile application --output "$scan_output/application"
python3 policies/scan_images.py --install \
  --image "$(docker image inspect governance-commons-python:dev --format '{{.Id}}')" \
  --profile python-worker --output "$scan_output/python-worker"
