FROM node:22-slim

RUN corepack enable

WORKDIR /app

# Bring in the whole ts-mls repo. Build context should be the repo root.
COPY package.json pnpm-lock.yaml ./
COPY src ./src
COPY interop ./interop

# Install peer/dev deps at root (crypto providers, noble/hpke) so that the
# interop server can import from ../src without missing peer packages.
RUN pnpm install --frozen-lockfile --ignore-scripts

WORKDIR /app/interop
RUN pnpm install --ignore-scripts

EXPOSE 50053

ENTRYPOINT ["pnpm", "start"]
