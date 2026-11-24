import json
import unittest
from pathlib import Path

from sbom_lib import flatten_grype, inventory_row, summarise

FIX = Path(__file__).parent / "fixtures"
META = dict(scan_date="2099-01-02", repo="o/r", layer="app", ref="dev", sha="abc",
            image_digest=None, sbom_uri="gs://b/x.cdx.json")


def load(name):
    return json.loads((FIX / name).read_text())


class FlattenTests(unittest.TestCase):
    def setUp(self):
        self.rows = flatten_grype(load("grype_sample.json"), **META)

    def test_one_row_per_match(self):
        self.assertEqual(len(self.rows), 3)

    def test_fixed_vuln_mapping(self):
        r = self.rows[0]
        self.assertEqual(r["vuln_id"], "CVE-2099-0001")
        self.assertEqual(r["severity"], "Critical")
        self.assertEqual(r["cvss_score"], 9.8)  # highest base score
        self.assertEqual((r["package_name"], r["package_version"], r["package_type"]),
                         ("example-lib", "2.0.0", "npm"))
        self.assertEqual((r["fix_state"], r["fixed_in"]), ("fixed", "2.0.1,2.1.0"))

    def test_unfixed_os_vuln(self):
        r = self.rows[1]
        self.assertEqual(r["severity"], "High")  # normalised casing
        self.assertIsNone(r["cvss_score"])
        self.assertEqual((r["fix_state"], r["fixed_in"]), ("not-fixed", ""))
        self.assertEqual(r["package_type"], "deb")

    def test_missing_fix_and_cvss_blocks_default_safely(self):
        r = self.rows[2]
        self.assertEqual(r["fix_state"], "unknown")
        self.assertEqual(r["severity"], "Negligible")
        self.assertIsNone(r["cvss_score"])

    def test_context_and_db_freshness_carried(self):
        for r in self.rows:
            self.assertEqual(r["repo"], "o/r")
            self.assertEqual(r["layer"], "app")
            self.assertEqual(r["sbom_uri"], "gs://b/x.cdx.json")
            self.assertEqual(r["grype_db_built"], "2099-01-01T00:00:00Z")

    def test_no_matches_gives_no_rows(self):
        self.assertEqual(flatten_grype({"matches": []}, **META), [])
        self.assertEqual(flatten_grype({}, **META), [])

    def test_inventory_row(self):
        row = inventory_row(load("sbom_sample.cdx.json"), **{k: v for k, v in META.items()
                                                             if k != "image_digest"})
        self.assertEqual(row["component_count"], 2)
        self.assertEqual(row["syft_version"], "9.9.9")
        self.assertEqual(row["generated_at"], "2099-01-01T01:02:03Z")

    def test_summary_counts_by_severity_and_fixable(self):
        md = summarise(self.rows, title="App layer")
        self.assertIn("App layer", md)
        self.assertIn("Critical", md)
        self.assertIn("3", md)



class CriticalCountTests(unittest.TestCase):
    def test_counts_only_fixable_criticals(self):
        from sbom_lib import count_fixable_criticals
        rows = [{"severity": "Critical", "fix_state": "fixed"}, {"severity": "Critical", "fix_state": "not-fixed"},
                {"severity": "High", "fix_state": "fixed"}]
        self.assertEqual(count_fixable_criticals(rows), 1)


if __name__ == "__main__":
    unittest.main()
