# SPDX-License-Identifier: Apache-2.0
FROM node:26.13.1-bookworm-slim@sha256:5df79989ed685e09f0a98019db4cebfb22fb9df1a53c0161664a011f7ff6b0f1 AS dependencies
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

# Supply the exact Node binary plus its C++ runtime to the maintained no-SSL base.
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:532c7a94f9e96ba9db75eb9388f4227751131c7cb0a411d1a8521af4096135de AS cxx-runtime
FROM dependencies AS runtime-libraries
COPY --from=cxx-runtime /usr/lib/*-linux-gnu/libgcc_s.so.1 /runtime-libraries/
COPY --from=cxx-runtime /usr/lib/*-linux-gnu/libstdc++.so.6* /runtime-libraries/
COPY --from=cxx-runtime /var/lib/dpkg/status.d/gcc-14-base* /var/lib/dpkg/status.d/libgcc-s1* /var/lib/dpkg/status.d/libstdc++6* /runtime-root/var/lib/dpkg/status.d/
COPY --from=cxx-runtime /usr/share/doc/gcc-14-base /runtime-root/usr/share/doc/gcc-14-base
COPY --from=cxx-runtime /usr/share/doc/libgcc-s1 /runtime-root/usr/share/doc/libgcc-s1
COPY --from=cxx-runtime /usr/share/doc/libstdc++6 /runtime-root/usr/share/doc/libstdc++6
RUN set -eu; case "$(uname -m)" in aarch64) multiarch=aarch64-linux-gnu ;; x86_64) multiarch=x86_64-linux-gnu ;; *) exit 1 ;; esac; \
    mkdir -p "/runtime-root/usr/lib/$multiarch"; mv /runtime-libraries/* "/runtime-root/usr/lib/$multiarch/"

FROM gcr.io/distroless/base-nossl-debian13:nonroot@sha256:4006ac92504be607b70de01d1f64f38288c69fcd8faa820f6d3aed266ea32ac5 AS runtime
WORKDIR /app
COPY --from=runtime-libraries /runtime-root/ /
COPY --from=dependencies /usr/local/bin/node /usr/local/bin/node
# Preserve package inventory, source and tests for scanning and native gates.
COPY --from=production-dependencies /app/node_modules ./node_modules
COPY . .
COPY --from=build /app/apps/web/dist ./apps/web/dist
USER 1000:1000
EXPOSE 4310
CMD ["node", "--import", "tsx", "apps/api/src/index.ts"]
