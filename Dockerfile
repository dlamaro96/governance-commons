# SPDX-License-Identifier: Apache-2.0
FROM node:24.22.3-bookworm-slim@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54
ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH
WORKDIR /app
RUN npm install --global pnpm@10.32.1 --ignore-scripts --no-audit --no-fund
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/web/package.json ./apps/web/package.json
COPY packages/ui/package.json ./packages/ui/package.json
RUN pnpm install --frozen-lockfile
COPY . .
RUN pnpm build
USER 1000:1000
EXPOSE 4310
CMD ["pnpm", "api/start"]
