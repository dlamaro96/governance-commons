#!/usr/bin/env sh
# SPDX-License-Identifier: Apache-2.0
set -eu
psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --set ON_ERROR_STOP=1 --file /bootstrap/source-init.sql
