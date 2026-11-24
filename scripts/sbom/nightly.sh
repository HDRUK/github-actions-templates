#!/usr/bin/env bash
# Scan every stored SBOM with Grype and load the results into BigQuery.
# Needs: BUCKET, DATASET (project.dataset). One bad SBOM is skipped, not fatal.
set -uo pipefail
cd "$(dirname "$0")"

scan_date=$(date -u +%F)
: > findings.ndjson; : > inventory.ndjson
skipped=0

# Object names look like: <branches|releases>/<org>/<repo>/<layer>/<ref>.cdx.json
for uri in $(gcloud storage ls "gs://${BUCKET}/**.cdx.json"); do
  IFS=/ read -r _kind org repo layer file <<<"${uri#gs://${BUCKET}/}"
  args=(--arg scan_date "$scan_date" --arg repo "$org/$repo" --arg layer "$layer" --arg ref "${file%.cdx.json}" --arg uri "$uri")

  if gcloud storage cp -q "$uri" sbom.json \
     && grype sbom:sbom.json -o json | jq -c "${args[@]}" -f flatten.jq >> findings.ndjson \
     && jq -c "${args[@]}" -f inventory.jq sbom.json >> inventory.ndjson; then
    :
  else
    echo "::warning::Skipped $uri"
    skipped=$((skipped + 1))
  fi
done

for table in findings inventory; do
  [ -s "$table.ndjson" ] && bq load --source_format=NEWLINE_DELIMITED_JSON "${DATASET}.${table}" "$table.ndjson"
done

echo "fixable_criticals=$(jq -s '[.[] | select(.severity == "Critical" and .fix_state == "fixed")] | length' findings.ndjson)" >> "${GITHUB_OUTPUT:-/dev/null}"
[ "$skipped" -eq 0 ]
