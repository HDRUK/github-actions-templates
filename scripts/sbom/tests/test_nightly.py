import json
import unittest
from pathlib import Path

from sbom_lib import process_sboms

FIX = Path(__file__).parent / "fixtures"
GOOD = (FIX / "sbom_sample.cdx.json").read_text()
GRYPE = json.loads((FIX / "grype_sample.json").read_text())


class NightlyTests(unittest.TestCase):
    def run_it(self, store, scan=None):
        scan = scan or (lambda text: GRYPE)
        return process_sboms(list(store), fetch=lambda uri: store[uri], scan=scan, scan_date="2099-01-02")

    def test_malformed_sbom_is_skipped_and_others_processed(self):
        store = {
            "gs://b/latest/o/r1/app/dev.cdx.json": GOOD,
            "gs://b/latest/o/r2/app/dev.cdx.json": "{not json",
            "gs://b/latest/o/r3/container/dev.cdx.json": GOOD,
        }
        res = self.run_it(store)
        self.assertEqual(len(res.inventory), 2)
        self.assertEqual(len(res.findings), 6)
        self.assertEqual([e[0] for e in res.errors], ["gs://b/latest/o/r2/app/dev.cdx.json"])

    def test_scan_failure_on_one_sbom_does_not_abort_run(self):
        calls = []

        def scan(text):
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("grype exploded")
            return GRYPE

        store = {"gs://b/latest/o/a/app/dev.cdx.json": GOOD, "gs://b/latest/o/b/app/dev.cdx.json": GOOD}
        res = self.run_it(store, scan)
        self.assertEqual(len(res.errors), 1)
        self.assertEqual(len(res.inventory), 1)

    def test_repo_layer_ref_parsed_from_uri(self):
        res = self.run_it({"gs://b/latest/ExampleOrg/example-repo/container/feat-x.cdx.json": GOOD})
        row = res.inventory[0]
        self.assertEqual((row["repo"], row["layer"], row["ref"]),
                         ("ExampleOrg/example-repo", "container", "feat-x"))

    def test_unparseable_uri_is_an_error_not_a_crash(self):
        res = self.run_it({"gs://b/latest/weird.cdx.json": GOOD})
        self.assertEqual(len(res.errors), 1)

    def test_empty_run_is_fine(self):
        res = self.run_it({})
        self.assertEqual((res.findings, res.inventory, res.errors), ([], [], []))


if __name__ == "__main__":
    unittest.main()
