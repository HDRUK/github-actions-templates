# github-actions-templates
Centralized GitHub Actions workflows and reusable pipelines for CI/CD automation


## SBOM scanning

Images built via `docker-build.yaml` can generate SBOMs, scanned nightly into BigQuery. Switched on per repository with the
`SBOM_ENABLED` variable. See `docs/ARCHITECTURE/sbom-pipeline.md`. Run the tests with `scripts/sbom/test.sh`.
