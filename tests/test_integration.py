"""End-to-end: triage the shipped sample logs and check the whole narrative is caught."""

import contextlib
import io
import json
import os
import tempfile
import unittest

from logtriage.cli import main
from logtriage.engine import triage
from logtriage.report import render_json, render_markdown
from logtriage.settings import Settings

DATA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
AUTH = os.path.join(DATA, "sample_auth.log")
ACCESS = os.path.join(DATA, "sample_access.log")


class SampleTriageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.incident = triage([AUTH, ACCESS], Settings(year=2026))

    def rule_ids(self):
        return {alert.rule_id for alert in self.incident.alerts}

    def test_every_rule_fires(self):
        self.assertEqual(
            self.rule_ids(),
            {"SSH-001", "SSH-002", "SSH-003", "SSH-004", "WEB-001", "WEB-002", "WEB-003", "WEB-004"},
        )

    def test_no_processing_errors(self):
        self.assertEqual(self.incident.errors, [])

    def test_every_line_parsed(self):
        self.assertEqual(self.incident.failed_lines, 0)
        self.assertEqual(self.incident.events, 74)

    def test_the_compromise_is_critical(self):
        criticals = [a for a in self.incident.alerts if a.severity.value == "Critical"]
        self.assertEqual([a.rule_id for a in criticals], ["SSH-003"])
        self.assertEqual(criticals[0].entities["user"], "deploy")

    def test_exposed_git_file_is_high(self):
        exposed = next(a for a in self.incident.alerts if a.rule_id == "WEB-003")
        self.assertEqual(exposed.severity.value, "High")
        self.assertIn("/.git/HEAD", exposed.entities["paths"])

    def test_report_reads_like_an_incident(self):
        text = render_markdown(self.incident)
        self.assertIn("SSH-003", text)
        self.assertIn("2026-03-14 03:16", text)
        self.assertIn("203.0.113.77", text)
        self.assertIn("## Timeline", text)

    def test_json_round_trip(self):
        payload = json.loads(render_json(self.incident))
        self.assertEqual(len(payload["alerts"]), len(self.incident.alerts))
        self.assertTrue(all(a["evidence"] for a in payload["alerts"]))

    def test_exit_code_reflects_severity(self):
        self.assertEqual(self.incident.exit_code("High"), 1)

    def test_allowlisting_drops_a_source(self):
        incident = triage([AUTH], Settings(year=2026, allowlist=["203.0.113.5"]))
        self.assertNotIn("SSH-001", {a.rule_id for a in incident.alerts})

    def test_directory_input_is_accepted(self):
        incident = triage([DATA], Settings(year=2026))
        self.assertEqual(len(incident.sources), 2)


class CliTests(unittest.TestCase):
    def test_full_cli_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            markdown_path = os.path.join(tmp, "incident.md")
            json_path = os.path.join(tmp, "incident.json")
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                code = main([AUTH, ACCESS, "--year", "2026", "--no-color",
                             "--markdown", markdown_path, "--json", json_path])
            self.assertEqual(code, 1)
            self.assertTrue(os.path.getsize(markdown_path) > 800)
            with open(json_path, encoding="utf-8") as handle:
                self.assertIn("alerts", json.load(handle))
            self.assertIn("Markdown report written", buffer.getvalue())

    def test_missing_file_reports_an_error_and_exits_two(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = main(["definitely-not-here.log"])
        self.assertEqual(code, 2)
        self.assertIn("No readable log files", err.getvalue())

    def test_clean_threshold_can_be_disabled(self):
        with contextlib.redirect_stdout(io.StringIO()):
            code = main([AUTH, ACCESS, "--year", "2026", "--fail-on", "never"])
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
