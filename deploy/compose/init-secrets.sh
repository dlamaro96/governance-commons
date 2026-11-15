#!/usr/bin/env sh
# SPDX-License-Identifier: Apache-2.0
set -eu
# Docker secret file-mode remapping is not reliable with Compose bind mounts.
# This network-isolated one-shot copies to a dedicated volume, with exact service owners.
cp /input/postgres-init.sql /bootstrap/postgres/postgres-init.sql
cp /input/source-init.sql /bootstrap/source/source-init.sql
cp /input/governance-realm.json /bootstrap/identity/governance-realm.json
cp /input/seaweed-s3.json /bootstrap/object/s3.json
chmod 600 /bootstrap/postgres/* /bootstrap/source/* /bootstrap/identity/* /bootstrap/object/*
chown 999:999 /bootstrap/postgres/postgres-init.sql /bootstrap/source/source-init.sql
chown 1000:0 /bootstrap/identity/governance-realm.json
chown 1000:1000 /bootstrap/object/s3.json
