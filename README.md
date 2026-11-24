# github-actions-templates
Centralized GitHub Actions workflows and reusable pipelines for CI/CD automation


## SBOM scanning

Central SBOM generation and CVE scanning for images built via `docker-build.yaml`, controlled by
`SBOM_*` variables. See `docs/ARCHITECTURE/sbom-pipeline.md`, `docs/CONVENTIONS/sbom-feature-flags.md`
and `docs/OPERATIONS/`. Run the script tests with `cd scripts/sbom && PYTHONPATH=. python3 -m unittest discover -s tests`.
