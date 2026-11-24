# Grype JSON -> one row per finding, newline-delimited for `bq load`.
# Args: scan_date, repo, layer, ref, uri
def capitalise: ascii_downcase | (.[0:1] | ascii_upcase) + .[1:];

.matches[]? | {
  scan_date: $scan_date, repo: $repo, layer: $layer, ref: $ref,
  vuln_id: .vulnerability.id,
  severity: ((.vulnerability.severity // "Unknown") | capitalise),
  cvss_score: ([.vulnerability.cvss[]?.metrics.baseScore | select(. != null)] | max),
  package_name: .artifact.name,
  package_version: .artifact.version,
  package_type: .artifact.type,
  fix_state: (.vulnerability.fix.state // "unknown"),
  fixed_in: ((.vulnerability.fix.versions // []) | join(",")),
  sbom_uri: $uri
}
