# SBOM infrastructure requirements

The pipeline assumes this already exists; nothing here is created by the workflows. Implement it in Terraform.
How it is used is in [sbom-pipeline.md](../ARCHITECTURE/sbom-pipeline.md).

## GCS bucket (`SBOM_BUCKET`)

- Uniform bucket-level access, public access prevention on, no public IAM.
- Lifecycle rule: delete objects older than 90 days where the prefix is `branches/`. Leave `releases/` alone.

| Who | Access | Why |
|---|---|---|
| CI service account | create and overwrite objects (`storage.objects.create` and `delete`, e.g. a custom role) | upload SBOMs |
| Nightly scan service account | `roles/storage.objectViewer` | read SBOMs |
| Security team | `roles/storage.objectViewer` | audit |

## Workload Identity Federation

- Provider attribute condition limited to the organisation, e.g. `assertion.repository_owner == 'HDRUK'`.
- The CI service account must be able to read the image in Artifact Registry (Syft pulls the pushed image by digest) and attach the SBOM to it (`roles/artifactregistry.writer` on the image repository), as well as write to the bucket.
- The nightly scan service account also needs `roles/bigquery.dataEditor` on the `sbom` dataset and `roles/bigquery.jobUser` on the project.

## BigQuery dataset `sbom`

```sql
CREATE TABLE sbom.findings (
  scan_date DATE NOT NULL, repo STRING, layer STRING, ref STRING,
  vuln_id STRING, severity STRING, cvss_score FLOAT64,
  package_name STRING, package_version STRING, package_type STRING,
  fix_state STRING, fixed_in STRING, sbom_uri STRING
)
PARTITION BY scan_date CLUSTER BY layer, repo;

CREATE TABLE sbom.inventory (
  scan_date DATE NOT NULL, repo STRING, layer STRING, ref STRING,
  sha STRING, generated_at TIMESTAMP, component_count INT64, sbom_uri STRING
)
PARTITION BY scan_date CLUSTER BY layer, repo;
```

Superset already has BigQuery access: confirm its identity can read this dataset.

## Checklist

- [ ] Bucket, lifecycle rule, IAM
- [ ] WIF provider condition and service account bindings (including image read and Artifact Registry writer)
- [ ] BigQuery dataset and both tables
- [ ] Superset can read the dataset
- [ ] GitHub variables set for pilot repositories only
