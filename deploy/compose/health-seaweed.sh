#!/usr/bin/env sh
# SPDX-License-Identifier: Apache-2.0
set -eu
# The image entrypoint drops privileges to seaweed (1000:1000). Running a
# root-only readability check would hide the bind-mount ownership regression.
su-exec seaweed test -r /run/secrets/seaweedfs/s3.json
# HTTP 200 alone precedes leader election and cannot serve bucket writes.
wget -q -T 3 -O - http://127.0.0.1:9333/cluster/status | grep -q '"IsLeader":true'
wget -q -T 3 -O - http://127.0.0.1:9333/dir/status | grep -q '"Url":"seaweedfs:8080"'
wget -q -T 3 -O /dev/null http://127.0.0.1:8888/
# The S3 listener must be ready and deny an unsigned ListBuckets request.
# Authenticated readiness is checked separately by the launcher using API env.
response=$(wget -S -T 3 -O /dev/null http://127.0.0.1:8333/ 2>&1 || true)
printf '%s\n' "$response" | grep -q 'HTTP/1.1 403 Forbidden'
