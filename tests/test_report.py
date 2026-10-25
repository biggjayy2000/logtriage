"""The report is what an analyst hands to someone else, so it gets asserted."""

import json
import unittest

from logtriage.models import Alert, Incident, Severity
from logtriage.report import render_console, render_json, render_markdown

from .support import at


def sample_incident() -> Incident:
    return Incident(
        sources=["data/sample_auth.log", "data/sample_access.log"],
        started="2026-03-14 05:00:00",
        duration=0.02,
        events=74,
        failed_lines=2,
        first_event=at(0),
        last_event=at(3600),
        alerts=[
            Alert(
                rule_id="SSH-003",
                title="Successful login after repeated failures",
                severity=Severity.CRITICAL,
                summary="'deploy' logged in from 203.0.113.77 after 3 failed attempts",
                count=4,
                first_seen=at(60),
                last_seen=at(120),
                entities={"ip": "203.0.113.77", "user": "deploy"},
                evidence=["Mar 14 03:01:00 web01 sshd[1]: Failed password for deploy ..."],
                recommendation="Treat the account as compromised.",
                mitre="T1078 - Valid Accounts",
            ),
            Alert(
                rule_id="WEB-001",
                title="Directory and file scanning",
                severity=Severity.MEDIUM,
                summary="26 client-error responses to 198.51.100.7",
                count=26,
                first_seen=at(300),
                last_seen=at(360),
                entities={"ip": "198.51.100.7"},
                evidence=["198.51.100.7 - - [...] \"GET /admin HTTP/1.1\" 404 162"],
                recommendation="Rate-limit the source.",
                mitre="T1595 - Active Scanning",
            ),
        ],
    )


class MarkdownTests(unittest.TestCase):
    def setUp(self):
        self.text = render_markdown(sample_incident())

    def test_metadata_and_sections(self):
        self.assertIn("# Security Log Triage", self.text)
        self.assertIn("**Events parsed:** 74", self.text)
        self.assertIn("## Summary", self.text)
        self.assertIn("## Timeline", self.text)
        self.assertIn("## Alerts", self.text)

    def test_summary_counts(self):
        self.assertIn("| Critical | 1 |", self.text)
        self.assertIn("| Medium | 1 |", self.text)

    def test_critical_listed_before_medium(self):
        self.assertLess(self.text.index("SSH-003"), self.text.index("WEB-001"))

    def test_evidence_is_fenced(self):
        self.assertIn("```", self.text)
        self.assertIn("Failed password for deploy", self.text)

    def test_unparsed_lines_are_reported_not_hidden(self):
        self.assertIn("**Unparsed lines:** 2", self.text)


class JsonTests(unittest.TestCase):
    def test_machine_readable(self):
        payload = json.loads(render_json(sample_incident()))
        self.assertEqual(payload["counts"]["Critical"], 1)
        self.assertEqual(payload["alerts"][0]["rule_id"], "SSH-003")
        self.assertEqual(payload["alerts"][0]["mitre"], "T1078 - Valid Accounts")


class ConsoleTests(unittest.TestCase):
    def test_colour_toggle(self):
        self.assertNotIn("\033[", render_console(sample_incident(), color=False))
        self.assertIn("\033[", render_console(sample_incident(), color=True))

    def test_quiet_mode_is_shorter(self):
        verbose = render_console(sample_incident(), color=False, verbose=True)
        quiet = render_console(sample_incident(), color=False, verbose=False)
        self.assertLess(len(quiet), len(verbose))


class ExitCodeTests(unittest.TestCase):
    def test_critical_fails_the_run(self):
        self.assertEqual(sample_incident().exit_code("High"), 1)

    def test_clean_incident_passes(self):
        incident = sample_incident()
        incident.alerts = []
        self.assertEqual(incident.exit_code("High"), 0)

    def test_medium_only_passes_a_high_threshold(self):
        incident = sample_incident()
        incident.alerts = [a for a in incident.alerts if a.severity is Severity.MEDIUM]
        self.assertEqual(incident.exit_code("High"), 0)
        self.assertEqual(incident.exit_code("Medium"), 1)


if __name__ == "__main__":
    unittest.main()
