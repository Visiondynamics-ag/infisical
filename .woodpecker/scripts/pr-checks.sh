#!/bin/sh
set -eu
set +x
cd "$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"

. .woodpecker/scripts/validate-source.sh
git diff --check

# Run the existing upstream Node quality commands. Install only in this
# disposable CI checkout; remove generated dependencies before image building.
cleanup() { rm -rf -- frontend/node_modules backend/node_modules; }
trap cleanup EXIT HUP INT TERM
export CI=true
export NEXT_TELEMETRY_DISABLED=1
export npm_config_cache=/tmp/infisical-npm-cache
export npm_config_audit=false
export npm_config_fund=false
[ "$(node -p 'process.versions.node.split(".")[0]')" = 26 ] || { echo "Node 26 is required" >&2; exit 1; }
npm install --global npm@11.21.1 --prefix /tmp/infisical-npm-toolchain --ignore-scripts
export PATH="/tmp/infisical-npm-toolchain/bin:$PATH"
(cd frontend && npm ci --ignore-scripts && npm run lint && npm run type:check)
rm -rf -- frontend/node_modules
(cd backend && npm ci && npm run lint && npm run type:check && npm run test:unit -- --maxWorkers=1 --minWorkers=1 --no-file-parallelism)
git diff --exit-code -- frontend/package-lock.json backend/package-lock.json
printf '%s\n' 'Infisical Node source checks passed'
