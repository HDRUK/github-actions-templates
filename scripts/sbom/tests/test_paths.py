import unittest
from sbom_lib import build_paths, sanitise_ref


class PathTests(unittest.TestCase):
    def test_branch_with_slash_is_sanitised(self):
        self.assertEqual(sanitise_ref("feat/GAT-123_thing"), "feat-GAT-123_thing")

    def test_ref_prefixes_stripped(self):
        self.assertEqual(sanitise_ref("refs/heads/dev"), "dev")
        self.assertEqual(sanitise_ref("refs/tags/v1.2.3"), "v1.2.3")

    def test_traversal_and_odd_characters_are_neutralised(self):
        out = sanitise_ref("../../etc/pass wd;rm")
        self.assertNotIn("/", out)
        self.assertNotIn("..", out)
        self.assertNotIn(" ", out)
        self.assertNotIn(";", out)

    def test_empty_ref_gets_placeholder(self):
        self.assertEqual(sanitise_ref(""), "unknown")
        self.assertEqual(sanitise_ref("///"), "unknown")

    def test_branch_build_paths(self):
        p = build_paths("b", "ExampleOrg/example-repo", "app", "refs/heads/feat/x", "abc123")
        self.assertEqual(p.history, "gs://b/history/ExampleOrg/example-repo/app/feat-x/abc123.cdx.json")
        self.assertEqual(p.latest, "gs://b/latest/ExampleOrg/example-repo/app/feat-x.cdx.json")
        self.assertIsNone(p.release)

    def test_tag_goes_to_releases_not_history(self):
        p = build_paths("b", "o/r", "container", "refs/tags/v1.0.0", "abc123")
        self.assertEqual(p.release, "gs://b/releases/o/r/container/v1.0.0/abc123.cdx.json")
        self.assertIsNone(p.history)

    def test_release_branch_counts_as_release(self):
        p = build_paths("b", "o/r", "app", "refs/heads/release/1.4.0", "abc123")
        self.assertEqual(p.release, "gs://b/releases/o/r/app/release-1.4.0/abc123.cdx.json")

    def test_bad_layer_rejected(self):
        with self.assertRaises(ValueError):
            build_paths("b", "o/r", "image", "dev", "abc123")

    def test_latest_always_set(self):
        self.assertTrue(build_paths("b", "o/r", "app", "refs/tags/v1", "s").latest)


if __name__ == "__main__":
    unittest.main()
