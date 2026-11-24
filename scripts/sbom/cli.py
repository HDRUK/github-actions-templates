#!/usr/bin/env python3
"""Thin command line wrapper used by the SBOM composite actions and nightly workflow.

Subcommands: gate, paths, annotate, report, nightly. All logic lives in sbom_lib.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import sbom_lib


def _emit(outputs: dict) -> None:
    lines = [f"{k}={str(v).lower() if isinstance(v, bool) else v}" for k, v in outputs.items() if v is not None]
    target = os.environ.get("GITHUB_OUTPUT")
    if target:
        with open(target, "a") as fh:
            fh.write("\n".join(lines) + "\n")
    print("\n".join(lines))


def cmd_gate(a) -> int:
    names = ("SBOM_ENABLED", "SBOM_APP_ENABLED", "SBOM_CONTAINER_ENABLED", "SBOM_UPLOAD_AR")
    g = sbom_lib.decide_gate({n: os.environ.get(n, "") for n in names}, a.event)
    _emit({"run_app": g.run_app, "run_container": g.run_container, "upload_ar": g.upload_ar})
    return 0


def cmd_paths(a) -> int:
    p = sbom_lib.build_paths(a.bucket, a.repo, a.layer, a.ref, a.sha)
    _emit({"latest": p.latest, "history": p.history, "release": p.release})
    return 0


def cmd_annotate(a) -> int:
    """Record layer/digest inside the SBOM so the nightly scan needs no side data."""
    path = Path(a.file)
    sbom = json.loads(path.read_text())
    meta = sbom.setdefault("metadata", {})
    props = meta.setdefault("properties", [])
    for name, value in (("sbom:layer", a.layer), ("sbom:image_digest", a.digest)):
        if value:
            props.append({"name": name, "value": value})
    path.write_text(json.dumps(sbom))
    return 0


def cmd_report(a) -> int:
    """Flatten a Grype result and write a job summary. Findings never affect the exit code."""
    grype = json.loads(Path(a.grype).read_text())
    rows = sbom_lib.flatten_grype(
        grype, scan_date=dt.date.today().isoformat(), repo=a.repo, layer=a.layer, ref=a.ref, sha=a.sha,
        image_digest=a.digest, sbom_uri=a.sbom_uri)
    md = sbom_lib.summarise(rows, title=f"SBOM scan: {a.layer} layer")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as fh:
            fh.write(md)
    print(md)
    return 0


def _run(cmd: list, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw)


def cmd_nightly(a) -> int:
    scan_date = dt.date.today().isoformat()
    uris = [u for u in _run(["gcloud", "storage", "ls", f"gs://{a.bucket}/latest/**/*.cdx.json"]).stdout.split() if u]

    def fetch(uri: str) -> str:
        return _run(["gcloud", "storage", "cat", uri]).stdout

    def scan(text: str) -> dict:
        with tempfile.NamedTemporaryFile("w", suffix=".cdx.json") as fh:
            fh.write(text)
            fh.flush()
            return json.loads(_run(["grype", f"sbom:{fh.name}", "-o", "json"]).stdout)

    res = sbom_lib.process_sboms(uris, fetch, scan, scan_date)
    for table, rows in (("findings", res.findings), ("inventory", res.inventory)):
        if not rows:
            continue
        with tempfile.NamedTemporaryFile("w", suffix=".ndjson", delete=False) as fh:
            fh.write("\n".join(json.dumps(r) for r in rows) + "\n")
        _run(["bq", "load", "--source_format=NEWLINE_DELIMITED_JSON", f"{a.dataset}.{table}", fh.name])
    print(f"scanned={len(uris)} findings={len(res.findings)} inventory={len(res.inventory)} errors={len(res.errors)}")
    for uri, msg in res.errors:
        print(f"::warning title=SBOM skipped::{uri}: {msg}", file=sys.stderr)
    _emit({"fixable_criticals": sbom_lib.count_fixable_criticals(res.findings), "errors": len(res.errors)})
    return 1 if res.errors else 0  # alerts, never affects builds


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="sbom")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("gate"); s.add_argument("--event", required=True); s.set_defaults(fn=cmd_gate)
    s = sub.add_parser("paths")
    for n in ("bucket", "repo", "layer", "ref", "sha"):
        s.add_argument(f"--{n}", required=True)
    s.set_defaults(fn=cmd_paths)
    s = sub.add_parser("annotate"); s.add_argument("file"); s.add_argument("--layer", required=True)
    s.add_argument("--digest"); s.set_defaults(fn=cmd_annotate)
    s = sub.add_parser("report"); s.add_argument("grype")
    for n in ("repo", "layer", "ref", "sha", "sbom-uri"):
        s.add_argument(f"--{n}", required=True)
    s.add_argument("--digest"); s.set_defaults(fn=cmd_report)
    s = sub.add_parser("nightly"); s.add_argument("--bucket", required=True); s.add_argument("--dataset", required=True)
    s.set_defaults(fn=cmd_nightly)
    a = p.parse_args(argv)
    a.sbom_uri = getattr(a, "sbom_uri", None)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
