import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import cli


class CliTests(unittest.TestCase):
    def test_gate_writes_outputs_and_defaults_off(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "out"
            with mock.patch.dict(os.environ, {"GITHUB_OUTPUT": str(out)}, clear=True):
                cli.main(["gate", "--event", "push"])
            self.assertEqual(out.read_text().split(), ["run_app=false", "run_container=false", "upload_ar=false"])

    def test_annotate_adds_properties_and_skips_empty(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "s.cdx.json"
            f.write_text(json.dumps({"metadata": {}}))
            cli.main(["annotate", str(f), "--layer", "container", "--digest", "sha256:abc"])
            props = {p["name"]: p["value"] for p in json.loads(f.read_text())["metadata"]["properties"]}
            self.assertEqual(props, {"sbom:layer": "container", "sbom:image_digest": "sha256:abc"})

    def test_report_never_fails_on_critical_findings(self):
        fix = Path(__file__).parent / "fixtures" / "grype_sample.json"
        with tempfile.TemporaryDirectory() as d:
            summary = Path(d) / "summary.md"
            with mock.patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(summary)}):
                rc = cli.main(["report", str(fix), "--repo", "o/r", "--layer", "app", "--ref", "dev",
                               "--sha", "abc", "--sbom-uri", "gs://b/x"])
            self.assertEqual(rc, 0)
            self.assertIn("Critical", summary.read_text())


if __name__ == "__main__":
    unittest.main()
