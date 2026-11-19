# mamori: one Node.js process and one SQLite file.
# Build:  docker build -t mamori .
# Run:    see "Running with Docker" in README.md

# The base image is pinned by digest so a re-tagged image cannot slip in.
FROM node:24-slim@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54 AS build
WORKDIR /app
COPY package.json package-lock.json .npmrc ./
RUN npm ci --ignore-scripts
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN npm run build && npm prune --omit=dev --ignore-scripts

FROM node:24-slim@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54
ENV NODE_ENV=production \
    MAMORI_CONFIG=/data/mamori.config.json
WORKDIR /app
COPY --from=build /app/package.json ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
# The config, database, encryption key and connector credentials live in /data.
# Relative paths in the config are relative to /data.
RUN mkdir /data && chown node:node /data
VOLUME ["/data"]
USER node
WORKDIR /data
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s CMD ["node", "-e", "fetch('http://127.0.0.1:3000/healthz').then(r => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]
CMD ["node", "/app/dist/main.js"]
