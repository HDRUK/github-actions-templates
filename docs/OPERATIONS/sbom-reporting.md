# SBOM reporting (Superset)

Superset reads `sbom.findings` and `sbom.inventory` through its existing BigQuery connection
(`bigquery://<project>/sbom`, `sqlalchemy-bigquery`). Always filter on the latest `scan_date`
(`scan_date = (SELECT MAX(scan_date) FROM sbom.findings)`) to avoid double counting.

## Dashboards

1. **Application layer.** Open critical/high fixable findings by repo, trend by `scan_date`, top offending packages.
2. **Container layer.** Findings by repo and package; packages affecting many repos; trend.
3. **Coverage.** Repos with an SBOM versus not; repos whose newest `generated_at` is older than N days.
4. **Releases.** Findings for tag and `release/*` refs only.

## Starter SQL

```sql
-- Fixable critical/high by repo, app layer
SELECT repo, severity, COUNT(*) AS findings
FROM sbom.findings
WHERE layer = 'app' AND fix_state = 'fixed' AND severity IN ('Critical', 'High')
  AND scan_date = (SELECT MAX(scan_date) FROM sbom.findings)
GROUP BY repo, severity ORDER BY findings DESC;

-- Container packages affecting the most repos
SELECT package_name, package_version, COUNT(DISTINCT repo) AS repos, COUNT(*) AS findings
FROM sbom.findings
WHERE layer = 'container' AND scan_date = (SELECT MAX(scan_date) FROM sbom.findings)
GROUP BY package_name, package_version ORDER BY repos DESC;

-- Stale SBOMs
SELECT repo, layer, ref, MAX(generated_at) AS last_generated
FROM sbom.inventory
WHERE scan_date = (SELECT MAX(scan_date) FROM sbom.inventory)
GROUP BY repo, layer, ref
HAVING last_generated < TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 14 DAY);
```

Artifact Registry's own scanning will still show language-package CVEs for images in the GCP console.
That is expected: the app/container ownership split lives here, not in the GCP UI.
