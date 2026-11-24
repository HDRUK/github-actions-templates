"""Pure logic for the central SBOM pipeline.

Kept free of I/O and third-party dependencies so it can be unit tested and run
unchanged on a GitHub runner. See docs/ARCHITECTURE/sbom-pipeline.md.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Optional

LAYERS = ("app", "container")
_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


# --------------------------------------------------------------------------
# Run gate
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class Gate:
    run_app: bool
    run_container: bool
    upload_ar: bool


def _truthy(value: Optional[str], default: bool = False) -> bool:
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() == "true"


def decide_gate(vars: dict, event_name: str) -> Gate:
    """Decide which SBOM steps run. Everything is off unless SBOM_ENABLED=true,
    and nothing ever runs for pull requests."""
    off = Gate(False, False, False)
    if event_name.startswith("pull_request"):
        return off
    if not _truthy(vars.get("SBOM_ENABLED")):
        return off
    run_container = _truthy(vars.get("SBOM_CONTAINER_ENABLED"), default=True)
    return Gate(
        run_app=_truthy(vars.get("SBOM_APP_ENABLED"), default=True),
        run_container=run_container,
        upload_ar=run_container and _truthy(vars.get("SBOM_UPLOAD_AR"), default=True),
    )


# --------------------------------------------------------------------------
# Storage paths
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class Paths:
    latest: str
    history: Optional[str]
    release: Optional[str]


def sanitise_ref(ref: str) -> str:
    for prefix in ("refs/heads/", "refs/tags/"):
        if ref.startswith(prefix):
            ref = ref[len(prefix):]
    out = _SAFE.sub("-", ref.replace("/", "-"))
    out = re.sub(r"\.{2,}", "-", out).strip("-.")
    out = re.sub(r"-{2,}", "-", out)
    return out or "unknown"


def _is_release(ref: str) -> bool:
    return ref.startswith("refs/tags/") or ref.startswith("refs/heads/release/") or ref.startswith("release/")


def build_paths(bucket: str, repo: str, layer: str, ref: str, sha: str) -> Paths:
    """Top-level prefixes (history/, latest/, releases/) exist so a GCS lifecycle
    rule can expire only `history/` by prefix."""
    if layer not in LAYERS:
        raise ValueError(f"layer must be one of {LAYERS}, got {layer!r}")
    safe = sanitise_ref(ref)
    base = f"{repo}/{layer}"
    latest = f"gs://{bucket}/latest/{base}/{safe}.cdx.json"
    leaf = f"{base}/{safe}/{sha}.cdx.json"
    if _is_release(ref):
        return Paths(latest, None, f"gs://{bucket}/releases/{leaf}")
    return Paths(latest, f"gs://{bucket}/history/{leaf}", None)


# --------------------------------------------------------------------------
# Grype / CycloneDX flattening
# --------------------------------------------------------------------------
def _severity(value: Optional[str]) -> str:
    return (value or "Unknown").strip().capitalize()


def flatten_grype(grype: dict, *, scan_date, repo, layer, ref, sha, image_digest, sbom_uri) -> list:
    db = (grype.get("descriptor") or {}).get("db") or {}
    built = (db.get("status") or {}).get("built") or db.get("built")
    rows = []
    for m in grype.get("matches") or []:
        vuln = m.get("vulnerability") or {}
        art = m.get("artifact") or {}
        fix = vuln.get("fix") or {}
        scores = [
            c["metrics"]["baseScore"]
            for c in vuln.get("cvss") or []
            if isinstance(c.get("metrics"), dict) and c["metrics"].get("baseScore") is not None
        ]
        rows.append({
            "scan_date": scan_date, "repo": repo, "layer": layer, "ref": ref, "sha": sha,
            "image_digest": image_digest,
            "vuln_id": vuln.get("id"), "severity": _severity(vuln.get("severity")),
            "cvss_score": max(scores) if scores else None,
            "package_name": art.get("name"), "package_version": art.get("version"),
            "package_type": art.get("type"),
            "fix_state": fix.get("state") or "unknown",
            "fixed_in": ",".join(fix.get("versions") or []),
            "sbom_uri": sbom_uri, "grype_db_built": built,
        })
    return rows


def _syft_version(sbom: dict) -> Optional[str]:
    tools = (sbom.get("metadata") or {}).get("tools")
    items = tools.get("components", []) if isinstance(tools, dict) else (tools or [])
    for t in items:
        if t.get("name") == "syft":
            return t.get("version")
    return None


def inventory_row(sbom: dict, *, scan_date, repo, layer, ref, sha, sbom_uri) -> dict:
    return {
        "scan_date": scan_date, "repo": repo, "layer": layer, "ref": ref, "sha": sha,
        "generated_at": (sbom.get("metadata") or {}).get("timestamp"),
        "component_count": len(sbom.get("components") or []),
        "syft_version": _syft_version(sbom), "sbom_uri": sbom_uri,
    }


def summarise(rows: list, title: str) -> str:
    order = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]
    counts = {s: [0, 0] for s in order}
    for r in rows:
        c = counts.setdefault(r["severity"], [0, 0])
        c[0] += 1
        c[1] += r["fix_state"] == "fixed"
    lines = [f"### {title}", "", f"{len(rows)} findings (report only, never fails the build).", "",
             "| Severity | Findings | Fixable |", "|---|---|---|"]
    lines += [f"| {s} | {n} | {f} |" for s, (n, f) in counts.items() if n]
    return "\n".join(lines) + "\n"


def count_fixable_criticals(rows: list) -> int:
    return sum(1 for r in rows if r["severity"] == "Critical" and r["fix_state"] == "fixed")


# --------------------------------------------------------------------------
# Nightly scan
# --------------------------------------------------------------------------
@dataclass
class ScanResult:
    findings: list = field(default_factory=list)
    inventory: list = field(default_factory=list)
    errors: list = field(default_factory=list)  # (uri, message)


_LATEST = re.compile(r"^gs://[^/]+/latest/(?P<repo>[^/]+/[^/]+)/(?P<layer>app|container)/(?P<ref>[^/]+)\.cdx\.json$")


def process_sboms(uris, fetch: Callable[[str], str], scan: Callable[[str], dict], scan_date: str) -> ScanResult:
    """Scan each SBOM independently; one bad SBOM is recorded and skipped."""
    import json

    res = ScanResult()
    for uri in uris:
        try:
            m = _LATEST.match(uri)
            if not m:
                raise ValueError("unrecognised SBOM path layout")
            text = fetch(uri)
            sbom = json.loads(text)
            ctx = dict(scan_date=scan_date, repo=m["repo"], layer=m["layer"], ref=m["ref"], sbom_uri=uri)
            meta = (sbom.get("metadata") or {}).get("component") or {}
            sha = meta.get("version")
            props = {p.get("name"): p.get("value") for p in (sbom.get("metadata") or {}).get("properties") or []}
            ctx["sha"] = sha
            inv = inventory_row(sbom, **ctx)
            found = flatten_grype(
                scan(text), image_digest=props.get("sbom:image_digest"), **ctx)
            res.inventory.append(inv)
            res.findings.extend(found)
        except Exception as exc:  # noqa: BLE001 - deliberate: never abort the run
            res.errors.append((uri, f"{type(exc).__name__}: {exc}"))
    return res

