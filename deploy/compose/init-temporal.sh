#!/usr/bin/env sh
# SPDX-License-Identifier: Apache-2.0
set -eu
for database in temporal temporal_visibility; do
  if [ "$database" = temporal ]; then component=temporal; else component=visibility; fi
  temporal-sql-tool --plugin postgres12 --ep postgres -p 5432 -u temporal --db "$database" setup-schema -v 0.0
  temporal-sql-tool --plugin postgres12 --ep postgres -p 5432 -u temporal --db "$database" update-schema -d "/etc/temporal/schema/postgresql/v12/$component/versioned"
done
