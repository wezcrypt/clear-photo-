# VoidMail application image (api, mx bridge, worker, migrate, admin share one image).
ARG NODE_IMAGE=node:22-bookworm-slim@sha256:43ac6c60b8f89723f746e8a92ce91abd5017e627ce1ddfe4238355d3a30b772c
FROM ${NODE_IMAGE} AS build
WORKDIR /app
COPY package.json package-lock.json ./
# The optional buildca secret is only for build environments behind a TLS-intercepting proxy; it is not kept in any layer.
RUN --mount=type=secret,id=buildca,required=false \
    if [ -s /run/secrets/buildca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/buildca; fi; \
    npm ci --no-audit --no-fund
COPY tsconfig.json ./
COPY src ./src
RUN npm run build && npm prune --omit=dev --no-audit --no-fund

FROM ${NODE_IMAGE}
ENV NODE_ENV=production \
    WEB_DIST=/app/dist/web \
    BLOB_DIR=/data/blobs \
    HTTP_HOST=0.0.0.0
WORKDIR /app
COPY --from=build /app/package.json ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
RUN mkdir -p /data/blobs && chown -R node:node /data
USER node
EXPOSE 8080 2424 2425
CMD ["node", "dist/server/main.js", "api"]
