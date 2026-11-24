# CycloneDX SBOM -> one inventory row. Args: scan_date, repo, layer, ref, uri
{
  scan_date: $scan_date, repo: $repo, layer: $layer, ref: $ref,
  sha: .metadata.component.version,
  generated_at: .metadata.timestamp,
  component_count: (.components // [] | length),
  sbom_uri: $uri
}
