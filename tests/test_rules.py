"""Rules are the product. Each one gets a 'fires' and a 'stays quiet' case."""

import unittest

from logtriage.rules import ssh, web
from logtriage.settings import Settings

from .support import http, ssh_fail, ssh_success


def ids(alerts):
    return {alert.rule_id for alert in alerts}


class BruteForceTests(unittest.TestCase):
    def test_fires_at_threshold(self):
        events = [ssh_fail(seconds=i * 10) for i in range(5)]
        self.assertEqual(ids(ssh.brute_force(events, Settings())), {"SSH-001"})

    def test_quiet_below_threshold(self):
        events = [ssh_fail(seconds=i * 10) for i in range(4)]
        self.assertEqual(ssh.brute_force(events, Settings()), [])

    def test_quiet_when_failures_are_spread_out(self):
        # Six failures, but ten minutes apart: no five-minute window is over the line.
        events = [ssh_fail(seconds=i * 900) for i in range(6)]
        self.assertEqual(ssh.brute_force(events, Settings()), [])

    def test_allowlisted_source_is_ignored(self):
        events = [ssh_fail(seconds=i) for i in range(10)]
        self.assertEqual(ssh.brute_force(events, Settings(allowlist=["203.0.113.5"])), [])

    def test_alert_carries_evidence_and_mitre(self):
        alert = ssh.brute_force([ssh_fail(seconds=i * 5) for i in range(6)], Settings())[0]
        self.assertTrue(alert.evidence)
        self.assertIn("T1110", alert.mitre)
        self.assertEqual(alert.count, 6)


class SprayTests(unittest.TestCase):
    def test_fires_for_many_users(self):
        events = [ssh_fail(user=f"user{i}", seconds=i * 60) for i in range(5)]
        self.assertEqual(ids(ssh.password_spray(events, Settings())), {"SSH-002"})

    def test_quiet_for_one_user_repeatedly(self):
        events = [ssh_fail(user="root", seconds=i * 60) for i in range(8)]
        self.assertEqual(ssh.password_spray(events, Settings()), [])


class SuccessAfterFailuresTests(unittest.TestCase):
    def test_critical_when_login_follows_failures(self):
        events = [ssh_fail(seconds=i * 5) for i in range(3)] + [ssh_success(seconds=60)]
        alerts = ssh.success_after_failures(events, Settings())
        self.assertEqual(ids(alerts), {"SSH-003"})
        self.assertEqual(alerts[0].severity.value, "Critical")

    def test_quiet_when_success_is_too_late(self):
        events = [ssh_fail(seconds=i * 5) for i in range(3)] + [ssh_success(seconds=3600)]
        self.assertEqual(ssh.success_after_failures(events, Settings()), [])

    def test_quiet_without_failures(self):
        self.assertEqual(ssh.success_after_failures([ssh_success()], Settings()), [])


class MultiIPTests(unittest.TestCase):
    def test_two_addresses_shortly_apart(self):
        events = [ssh_success(ip="192.0.2.55", seconds=0), ssh_success(ip="203.0.113.140", seconds=90)]
        self.assertEqual(ids(ssh.multi_ip_login(events, Settings())), {"SSH-004"})

    def test_same_address_repeatedly_is_fine(self):
        events = [ssh_success(ip="192.0.2.55", seconds=i * 30) for i in range(4)]
        self.assertEqual(ssh.multi_ip_login(events, Settings()), [])


class WebScanningTests(unittest.TestCase):
    def test_fires_on_error_burst(self):
        events = [http(path=f"/guess{i}", status=404, seconds=i) for i in range(25)]
        self.assertEqual(ids(web.scanning(events, Settings())), {"WEB-001"})

    def test_quiet_below_threshold(self):
        events = [http(path=f"/guess{i}", status=404, seconds=i) for i in range(24)]
        self.assertEqual(web.scanning(events, Settings()), [])

    def test_normal_browsing_is_not_scanning(self):
        events = [http(path="/", status=200, seconds=i) for i in range(40)]
        self.assertEqual(web.scanning(events, Settings()), [])


class LoginBruteForceTests(unittest.TestCase):
    def test_fires_on_repeated_401(self):
        events = [http(path="/login", status=401, method="POST", seconds=i * 5) for i in range(8)]
        self.assertEqual(ids(web.login_bruteforce(events, Settings())), {"WEB-002"})

    def test_get_requests_do_not_count(self):
        events = [http(path="/login", status=401, method="GET", seconds=i * 5) for i in range(20)]
        self.assertEqual(web.login_bruteforce(events, Settings()), [])


class SensitivePathTests(unittest.TestCase):
    def test_exposed_file_is_high(self):
        events = [http(path="/.git/HEAD", status=200)]
        alerts = web.sensitive_paths(events, Settings())
        self.assertEqual(alerts[0].severity.value, "High")

    def test_missing_file_is_medium(self):
        events = [http(path="/.env", status=404)]
        alerts = web.sensitive_paths(events, Settings())
        self.assertEqual(alerts[0].severity.value, "Medium")

    def test_ordinary_paths_are_ignored(self):
        self.assertEqual(web.sensitive_paths([http(path="/products")], Settings()), [])


class InjectionTests(unittest.TestCase):
    def test_union_select_is_detected(self):
        events = [http(path="/product?id=1%27%20UNION%20SELECT%20username")]
        self.assertEqual(ids(web.injection_attempts(events, Settings())), {"WEB-004"})

    def test_script_tag_is_detected(self):
        events = [http(path="/search?q=%3Cscript%3Ealert(1)%3C/script%3E")]
        self.assertEqual(ids(web.injection_attempts(events, Settings())), {"WEB-004"})

    def test_normal_query_is_quiet(self):
        events = [http(path="/search?q=shoes"), http(path="/products?page=2")]
        self.assertEqual(web.injection_attempts(events, Settings()), [])


if __name__ == "__main__":
    unittest.main()
