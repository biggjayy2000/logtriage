"""Parsers are where logs become usable, so they get the edge cases."""

import unittest
from datetime import datetime

from logtriage.parsers import detect, parse_lines, sshd, web


class SSHDTests(unittest.TestCase):
    def test_failed_password(self):
        event = sshd.parse("Mar 14 03:10:02 web01 sshd[2411]: Failed password for root from 203.0.113.5 port 51422 ssh2", 2026)
        self.assertIsNotNone(event)
        self.assertEqual((event.kind, event.user, event.ip), ("auth_failed", "root", "203.0.113.5"))
        self.assertEqual(event.timestamp, datetime(2026, 3, 14, 3, 10, 2))

    def test_failed_for_invalid_user(self):
        event = sshd.parse("Mar 14 03:11:20 web01 sshd[2414]: Failed password for invalid user oracle from 203.0.113.5 port 1 ssh2", 2026)
        self.assertEqual((event.kind, event.user), ("auth_failed", "oracle"))

    def test_invalid_user_line_counts_as_failure(self):
        event = sshd.parse("Mar 14 03:12:00 web01 sshd[2421]: Invalid user jsmith from 198.51.100.9", 2026)
        self.assertEqual((event.kind, event.user, event.ip), ("auth_failed", "jsmith", "198.51.100.9"))

    def test_accepted_publickey(self):
        event = sshd.parse("Mar 14 02:58:11 web01 sshd[2201]: Accepted publickey for deploy from 192.0.2.44 port 51210 ssh2", 2026)
        self.assertEqual((event.kind, event.user), ("auth_success", "deploy"))

    def test_failure_counted_before_success_is_not_ignored(self):
        # A success line must never be parsed as a failure.
        event = sshd.parse("Mar 14 03:16:20 web01 sshd[2455]: Accepted password for deploy from 203.0.113.77 port 40122 ssh2", 2026)
        self.assertEqual(event.kind, "auth_success")

    def test_unrelated_line_is_skipped(self):
        self.assertIsNone(sshd.parse("Mar 14 03:16:20 web01 sshd[2455]: Connection closed by 203.0.113.77 port 40122", 2026))

    def test_garbage_is_skipped(self):
        self.assertIsNone(sshd.parse("this is not a log line", 2026))
        self.assertIsNone(sshd.parse("", 2026))


class WebTests(unittest.TestCase):
    def test_combined_request(self):
        event = web.parse(
            '198.51.100.7 - - [14/Mar/2026:04:02:16 +0000] "GET /.git/HEAD HTTP/1.1" 200 23 "-" "Nuclei"'
        )
        self.assertEqual((event.ip, event.method, event.status), ("198.51.100.7", "GET", 200))
        self.assertEqual(event.target, "/.git/HEAD")
        self.assertEqual(event.path, "/.git/HEAD")

    def test_query_string_split_from_path(self):
        event = web.parse(
            '203.0.113.9 - - [14/Mar/2026:04:05:01 +0000] "GET /product?id=1 HTTP/1.1" 500 431 "-" "sqlmap"'
        )
        self.assertEqual(event.path, "/product")
        self.assertIn("id=1", event.target)

    def test_timezone_converted_to_utc(self):
        event = web.parse(
            '198.51.100.7 - - [14/Mar/2026:05:02:16 +0100] "GET / HTTP/1.1" 200 23 "-" "x"'
        )
        self.assertEqual(event.timestamp, datetime(2026, 3, 14, 4, 2, 16))

    def test_garbage_is_skipped(self):
        self.assertIsNone(web.parse("not a log line"))
        self.assertIsNone(web.parse('1.2.3.4 - - [bad-date] "GET / HTTP/1.1" 200 1'))


class DispatchTests(unittest.TestCase):
    def test_detect_identifies_both_formats(self):
        self.assertEqual(detect("Mar 14 03:10:02 web01 sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2"), "sshd")
        self.assertEqual(detect('1.2.3.4 - - [14/Mar/2026:04:02:16 +0000] "GET / HTTP/1.1" 200 23 "-" "x"'), "web")
        self.assertIsNone(detect("random text"))

    def test_parse_lines_counts_unparsed(self):
        lines = [
            "Mar 14 03:10:02 web01 sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2",
            "garbage",
            '1.2.3.4 - - [14/Mar/2026:04:02:16 +0000] "GET / HTTP/1.1" 200 23 "-" "x"',
            "",
        ]
        events, failed = parse_lines(lines, year=2026)
        self.assertEqual(len(events), 2)
        self.assertEqual(failed, 1)

    def test_events_are_sorted_by_time(self):
        lines = [
            '1.2.3.4 - - [14/Mar/2026:04:02:16 +0000] "GET / HTTP/1.1" 200 23 "-" "x"',
            "Mar 14 03:10:02 web01 sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2",
        ]
        events, _ = parse_lines(lines, year=2026)
        self.assertLess(events[0].timestamp, events[1].timestamp)


if __name__ == "__main__":
    unittest.main()
