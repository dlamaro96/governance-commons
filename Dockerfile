# SPDX-License-Identifier: Apache-2.0
FROM node:24.22.3-bookworm-slim@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54 AS dependencies
ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH
WORKDIR /app
RUN npm install --global pnpm@10.32.1 --ignore-scripts --no-audit --no-fund
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/web/package.json ./apps/web/package.json
COPY packages/ui/package.json ./packages/ui/package.json

FROM dependencies AS build
RUN pnpm install --frozen-lockfile
COPY . .
RUN pnpm build

FROM dependencies AS production-dependencies
# Install a fresh production closure; pruning the build tree can retain dev tools.
# Temporal's workflow bundler and tsx's transpiler remain runtime dependencies.
RUN pnpm install --prod --frozen-lockfile

FROM node:24.22.3-bookworm-slim@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54 AS runtime
WORKDIR /app
# The base includes package managers; services execute Node directly.
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack /opt/yarn-* \
    && rm -f /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack /usr/local/bin/yarn /usr/local/bin/yarnpkg
# Preserve source and tests for immutable-image attestation and native gates.
# .dockerignore excludes host/build node_modules and generated dist directories.
COPY --from=production-dependencies /app/node_modules ./node_modules
COPY . .
COPY --from=build /app/apps/web/dist ./apps/web/dist
USER 1000:1000
EXPOSE 4310
CMD ["node", "--import", "tsx", "apps/api/src/index.ts"]
