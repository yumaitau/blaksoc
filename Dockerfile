# syntax=docker/dockerfile:1.7
# Two runtime targets from one build: `web` (Next.js standalone) and `worker`
# (BullMQ jobs + migrations). Both run as non-root on a minimal Node base.

ARG NODE_VERSION=22-alpine

FROM node:${NODE_VERSION} AS deps
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-lock.yaml ./
RUN --mount=type=cache,id=pnpm,target=/root/.local/share/pnpm/store pnpm install --frozen-lockfile

FROM deps AS build
COPY . .
ENV NEXT_TELEMETRY_DISABLED=1
RUN pnpm build && pnpm build:worker

FROM node:${NODE_VERSION} AS prod-deps
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-lock.yaml ./
RUN --mount=type=cache,id=pnpm,target=/root/.local/share/pnpm/store pnpm install --frozen-lockfile --prod

FROM node:${NODE_VERSION} AS web
WORKDIR /app
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 PORT=3000 HOSTNAME=0.0.0.0
RUN addgroup -S blaksoc && adduser -S blaksoc -G blaksoc
COPY --from=build --chown=blaksoc:blaksoc /app/.next/standalone ./
COPY --from=build --chown=blaksoc:blaksoc /app/.next/static ./.next/static
USER blaksoc
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s CMD wget -qO- http://127.0.0.1:3000/api/health || exit 1
CMD ["node", "server.js"]

FROM node:${NODE_VERSION} AS worker
WORKDIR /app
ENV NODE_ENV=production
RUN addgroup -S blaksoc && adduser -S blaksoc -G blaksoc
COPY --from=prod-deps /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY --from=build /app/drizzle ./drizzle
COPY --from=build /app/src/db/sql ./src/db/sql
COPY package.json ./
USER blaksoc
# Override with ["node","dist/db/migrate.mjs"] for the migration job.
CMD ["node", "dist/worker/index.mjs"]
