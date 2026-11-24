import unittest
from sbom_lib import decide_gate


def gate(**overrides):
    base = dict(vars={"SBOM_ENABLED": "true"}, event_name="push")
    base.update(overrides)
    return decide_gate(**base)


class GateTests(unittest.TestCase):
    def test_unset_flag_runs_nothing(self):
        g = decide_gate(vars={}, event_name="push")
        self.assertEqual((g.run_app, g.run_container, g.upload_ar), (False, False, False))

    def test_flag_false_runs_nothing_even_if_layers_true(self):
        g = decide_gate(vars={"SBOM_ENABLED": "false", "SBOM_APP_ENABLED": "true",
                              "SBOM_CONTAINER_ENABLED": "true"}, event_name="push")
        self.assertFalse(g.run_app or g.run_container or g.upload_ar)

    def test_pull_requests_never_run(self):
        for event in ("pull_request", "pull_request_target"):
            g = gate(event_name=event)
            self.assertFalse(g.run_app or g.run_container, event)

    def test_enabled_defaults_both_layers_and_ar_on(self):
        g = gate()
        self.assertEqual((g.run_app, g.run_container, g.upload_ar), (True, True, True))

    def test_layer_toggles(self):
        g = gate(vars={"SBOM_ENABLED": "true", "SBOM_APP_ENABLED": "false"})
        self.assertEqual((g.run_app, g.run_container), (False, True))
        g = gate(vars={"SBOM_ENABLED": "true", "SBOM_CONTAINER_ENABLED": "false"})
        self.assertEqual((g.run_app, g.run_container, g.upload_ar), (True, False, False))

    def test_ar_upload_toggle(self):
        g = gate(vars={"SBOM_ENABLED": "true", "SBOM_UPLOAD_AR": "false"})
        self.assertTrue(g.run_container)
        self.assertFalse(g.upload_ar)

    def test_value_parsing_is_case_and_whitespace_tolerant(self):
        g = gate(vars={"SBOM_ENABLED": " TRUE "})
        self.assertTrue(g.run_app)

    def test_garbage_value_is_treated_as_false(self):
        g = gate(vars={"SBOM_ENABLED": "yes please"})
        self.assertFalse(g.run_app)


if __name__ == "__main__":
    unittest.main()
