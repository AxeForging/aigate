#!/usr/bin/env bash
# Opt-in live check of the model judges against the built-in eval corpus.
# Never runs in CI. Needs Cloudflare credentials in your shell:
#
#   AIGATE_CF_ACCOUNT=… AIGATE_CF_TOKEN=… scripts/judge-live.sh
#
# Only the masked, synthetic corpus is sent (52 cases × each model + chain).
set -euo pipefail

for v in AIGATE_CF_ACCOUNT AIGATE_CF_TOKEN; do
	[[ -n ${!v:-} ]] || { echo "judge-live: set $v first (nothing was sent)" >&2; exit 2; }
done

REPO=$(cd "$(dirname "$0")/.." && pwd)
BIN=$(mktemp -d)/aigate
trap 'rm -rf "$(dirname "$BIN")"' EXIT
(cd "$REPO" && go build -o "$BIN" .)

# A throwaway HOME so the run uses the default chain (rules → clef-flash → clef)
# and writes nothing to your real ~/.aigate.
HOME=$(mktemp -d) "$BIN" judge eval "$@"
