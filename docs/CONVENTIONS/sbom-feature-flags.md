# SBOM feature flags

SBOM jobs are controlled by GitHub Actions **configuration variables** (`vars`), set at
organisation level (scoped to selected repositories for staged rollout) with
repository-level overrides. Nothing is hard-coded in consuming repositories.

## Variables

**`SBOM_ENABLED`** (`true` / `false`, default: unset = off)
The on/off switch for the whole feature. Anything other than `true` means no SBOM job runs for that repository and
nothing in the build changes. Nothing below has any effect unless this is `true`.

**`SBOM_APP_ENABLED`** (`true` / `false`, default `true`)
Controls the *application* SBOM: the list of npm, pip and composer packages the app depends on, read from its lockfiles.
Set to `false` to skip it for a repository while leaving the container SBOM running. If the app job is switched off this
way it still starts for a few seconds, sees the flag, and finishes without doing anything.

**`SBOM_CONTAINER_ENABLED`** (`true` / `false`, default `true`)
Controls the *container* SBOM: the operating system packages and binaries inside the image that was just pushed.
Set to `false` to skip it while leaving the app SBOM running.

**`SBOM_UPLOAD_AR`** (`true` / `false`, default `true`)
Whether the container SBOM is also attached to the image in Google Artifact Registry, so it is visible next to the image
in the GCP console. The SBOM is always copied to the GCS bucket whether this is on or not. Only applies when the
container SBOM runs.

**`SBOM_BUCKET`** (bucket name, required)
The GCS bucket where every SBOM is stored. It must already exist. If it is missing or wrong, the upload fails and so does the build.

**`SBOM_GCP_WIF_PROVIDER`** and **`SBOM_GCP_SERVICE_ACCOUNT`** (default: the existing `WIF_PROVIDER` / `WIF_SERVICE_ACCOUNT` secrets)
How the SBOM jobs log in to Google Cloud without stored keys (Workload Identity Federation). Set these if the SBOM jobs should use a dedicated service account that can write to the bucket. If unset, the jobs reuse the identity that pushes images, which only works if that identity has been given write access to the SBOM bucket.

**`SBOM_EXCLUDES`** (space separated paths, default `./node_modules ./tests/fixtures`)
Paths the app SBOM ignores, so cache folders and test fixtures containing deliberately old or fake dependencies do not show up as real findings. Setting it replaces the default list rather than adding to it.

## Nightly scan settings

These are set on the `github-actions-templates` repository, not on application repositories.

**`SBOM_BQ_DATASET`** (`project.dataset`, required)
The BigQuery dataset the nightly scan writes its results to, which Superset reads.

**`SBOM_SLACK_WEBHOOK_URL`** (secret, optional)
If set (or if the existing `SLACK_WEBHOOK_URL` secret is), the nightly scan posts a Slack message when the run fails or fixable critical findings exist. If neither is set, no message is sent.

There is deliberately no gating variable. Findings never fail builds.

## Behaviour

- **Flag off or unset:** the job-level `if` is false, so no runner starts, no GCP authentication happens and a build behaves exactly as before.
- **Pull requests:** never run, regardless of flags.
- **Kill switch:** set `SBOM_ENABLED=false` at organisation or repository level; effective on the next run, no PR needed.
- **Enable one repository:** set `SBOM_ENABLED=true` as a repository variable, or add the repository to the organisation variable's selected repositories.
- **Failure behaviour:** when enabled, Syft/Grype/upload errors fail the build. An outage of the Grype database host, GCS or workload identity federation can therefore fail builds in every enabled repository. Mitigations: cached database, SBOM jobs run beside the build, and the kill switch above.

The gate logic is `decide_gate` in `scripts/sbom/sbom_lib.py` (unit tested). The job-level
`if` repeats only the master switch and pull request check so a disabled repo costs nothing.
