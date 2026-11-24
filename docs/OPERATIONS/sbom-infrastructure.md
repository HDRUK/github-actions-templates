# SBOM infrastructure requirements

The pipeline code **assumes this infrastructure already exists**. Nothing here is created or applied by the
workflows. Implement it in Terraform. Names are placeholders.

## 1. GCS bucket (`SBOM_BUCKET`)

- Uniform bucket-level access, public access prevention enforced, no public IAM.
- Located alongside the BigQuery dataset where possible.
- Lifecycle rule: delete objects older than **90 days** with `matchesPrefix: ["history/"]`. Do not expire `latest/` or `releases/`.
- Consider object versioning off (`latest/` is overwritten on every build).

| Principal | Role | Why |
| --- | --- | --- |
| CI service account (`SBOM_GCP_SERVICE_ACCOUNT`) | `roles/storage.objectCreator`; overwrite of `latest/` needs `storage.objects.delete`, so use a custom role with `objects.create` + `objects.delete` scoped by IAM condition to prefixes `latest/`, `history/`, `releases/` | write SBOMs |
| Nightly scan service account | `roles/storage.objectViewer` | read `latest/` |
| Security team group | `roles/storage.objectViewer` | audit |

SBOMs list the full dependency inventory of each application: treat them as security-sensitive.

## 2. Workload Identity Federation

- Provider attribute condition restricted to the organisation, e.g. `assertion.repository_owner == 'HDRUK'`.
- The CI service account is impersonated via `roles/iam.workloadIdentityUser` for the pool principal set.
- Container SBOM attach also needs `roles/artifactregistry.writer` on the image repository (and read for Syft to pull by digest) for the CI service account.
- The nightly scan runs in `github-actions-templates` and needs its own service account (or the same one) with: bucket read, `roles/bigquery.dataEditor` on the `sbom` dataset, `roles/bigquery.jobUser` on the project.

## 3. BigQuery dataset `sbom`

```sql
CREATE TABLE sbom.findings (
  scan_date DATE NOT NULL,
  repo STRING, layer STRING, ref STRING, sha STRING,
  image_digest STRING,
  vuln_id STRING, severity STRING, cvss_score FLOAT64,
  package_name STRING, package_version STRING, package_type STRING,
  fix_state STRING, fixed_in STRING,
  sbom_uri STRING, grype_db_built TIMESTAMP
)
PARTITION BY scan_date
CLUSTER BY layer, repo;

CREATE TABLE sbom.inventory (
  scan_date DATE NOT NULL,
  repo STRING, layer STRING, ref STRING, sha STRING,
  generated_at TIMESTAMP, component_count INT64,
  syft_version STRING, sbom_uri STRING
)
PARTITION BY scan_date
CLUSTER BY layer, repo;
```

Superset already has BigQuery access: confirm its identity has `roles/bigquery.dataViewer` on this dataset
(and `jobUser` on the project) once it exists.

## 4. GitHub configuration

See [sbom-feature-flags.md](../CONVENTIONS/sbom-feature-flags.md). Organisation variables scoped to selected
repositories: `SBOM_ENABLED`, `SBOM_BUCKET`, `SBOM_GCP_WIF_PROVIDER`, `SBOM_GCP_SERVICE_ACCOUNT`.
On `github-actions-templates`: `SBOM_BUCKET`, `SBOM_BQ_DATASET`, WIF vars, optional Slack secret.

## 5. Checklist

- [ ] Bucket, lifecycle rule, IAM
- [ ] WIF provider condition and service account bindings
- [ ] BigQuery dataset and both tables
- [ ] Artifact Registry writer for the CI service account
- [ ] Superset dataset access verified
- [ ] GitHub variables set for pilot repositories only
