#!/usr/bin/env bash
# Tests for the two jq filters that turn Grype/CycloneDX output into BigQuery rows.
set -euo pipefail
cd "$(dirname "$0")"

fail=0
check() { # description, jq expression that must be true, input
  if ! jq -e "$2" <<<"$3" >/dev/null; then echo "FAIL: $1"; fail=1; else echo "ok:   $1"; fi
}
flatten() { jq -c --arg scan_date 2099-01-02 --arg repo o/r --arg layer app --arg ref dev --arg uri gs://b/x -f flatten.jq; }

rows=$(flatten < fixtures/grype_sample.json | jq -s .)

check "one row per match"            'length == 3' "$rows"
check "fixed vuln maps all fields"   '.[0] | .vuln_id == "CVE-2099-0001" and .severity == "Critical" and .cvss_score == 9.8
                                      and .package_name == "example-lib" and .package_type == "npm"
                                      and .fix_state == "fixed" and .fixed_in == "2.0.1,2.1.0"' "$rows"
check "severity casing normalised"   '.[1].severity == "High"' "$rows"
check "unfixed vuln, no cvss"        '.[1] | .cvss_score == null and .fix_state == "not-fixed" and .fixed_in == ""' "$rows"
check "missing fix block is unknown" '.[2] | .fix_state == "unknown" and .severity == "Negligible"' "$rows"
check "context carried onto rows"    'all(.[]; .repo == "o/r" and .layer == "app" and .ref == "dev" and .sbom_uri == "gs://b/x")' "$rows"
check "no matches gives no rows"     'length == 0' "$(echo '{"matches": []}' | flatten | jq -s .)"
check "empty report gives no rows"   'length == 0' "$(echo '{}' | flatten | jq -s .)"

inv=$(jq -c --arg scan_date 2099-01-02 --arg repo o/r --arg layer app --arg ref dev --arg uri gs://b/x -f inventory.jq < fixtures/sbom_sample.cdx.json)
check "inventory row" '.component_count == 2 and .sha == "abc123" and .generated_at == "2099-01-01T01:02:03Z"' "$inv"

exit $fail
