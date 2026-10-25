"""Thresholds live in one place, so an analyst can tune noise without editing rules."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Iterable, List


def _is_private(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False


@dataclass
class Settings:
    # SSH
    ssh_fail_threshold: int = 5
    ssh_fail_window_minutes: int = 5
    ssh_spray_user_threshold: int = 5
    ssh_spray_window_minutes: int = 15
    ssh_success_fail_threshold: int = 3
    ssh_success_window_minutes: int = 15
    ssh_multi_ip_window_minutes: int = 10

    # Web
    web_scan_threshold: int = 25
    web_scan_window_minutes: int = 5
    web_login_fail_threshold: int = 8
    web_login_window_minutes: int = 5
    web_injection_severity: str = "High"

    # Global
    allowlist: List[str] = field(default_factory=list)
    year: int = 0

    def is_allowed(self, ip: str) -> bool:
        return ip in self.allowlist

    @classmethod
    def from_args(cls, allowlist: Iterable[str] = (), year: int = 0) -> "Settings":
        return cls(allowlist=list(allowlist), year=year)

    def describe(self) -> List[str]:
        return [
            f"SSH brute force: {self.ssh_fail_threshold} failures / {self.ssh_fail_window_minutes} min",
            f"SSH spray: {self.ssh_spray_user_threshold} users / {self.ssh_spray_window_minutes} min",
            f"SSH success after failure: {self.ssh_success_fail_threshold} failures / "
            f"{self.ssh_success_window_minutes} min",
            f"Web scanning: {self.web_scan_threshold} client errors / {self.web_scan_window_minutes} min",
            f"Web login failures: {self.web_login_fail_threshold} / {self.web_login_window_minutes} min",
        ]
