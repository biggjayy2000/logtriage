"""Rule registry. Each rule is (events, settings) -> list[Alert], so adding one is a function."""

from . import ssh, web

RULES = (
    ("SSH brute force", ssh.brute_force),
    ("SSH password spraying", ssh.password_spray),
    ("SSH success after failures", ssh.success_after_failures),
    ("SSH multi-IP login", ssh.multi_ip_login),
    ("Web scanning", web.scanning),
    ("Web login brute force", web.login_bruteforce),
    ("Web sensitive paths", web.sensitive_paths),
    ("Web injection attempts", web.injection_attempts),
)

__all__ = ["RULES"]
