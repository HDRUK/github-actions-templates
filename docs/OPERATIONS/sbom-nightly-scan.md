# SBOM nightly scan

`.github/workflows/sbom-nightly-scan.yaml` runs at 03:00 UTC (edit the cron to change) and on demand
(**Actions > SBOM nightly estate scan > Run workflow**).

1. `grype db update` for a fresh vulnerability database.
2. Lists `gs://<SBOM_BUCKET>/latest/**/*.cdx.json`.
3. For each SBOM, runs `grype sbom:<file>` and flattens the result.
4. Appends rows to `sbom.findings` and `sbom.inventory` with `bq load`.

## Failure handling

- A malformed or unscannable SBOM is logged as a warning and skipped. The rest are processed and loaded.
- If any were skipped the step exits non-zero at the end so the run is visibly red. This never affects application builds.
- A repository with no SBOM in the bucket is simply absent; the coverage dashboard shows it as not covered.

## Slack (optional)

If `SBOM_SLACK_WEBHOOK_URL` (or the existing `SLACK_WEBHOOK_URL`) is set, a message is posted when the
run failed or any **fixable critical** finding exists. With neither set the step is skipped. It reports
the current total, not what is new since yesterday.

## Re-running

Re-run via workflow dispatch. Re-running on the same day appends duplicate rows for that `scan_date`;
dashboards should filter on the latest `scan_date`, or delete that day's partition first.
