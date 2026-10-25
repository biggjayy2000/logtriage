# Security Log Triage

- **Sources:** data/sample_auth.log, data/sample_access.log
- **Analysed:** 2026-10-25 08:28:27 (0.01s)
- **Events parsed:** 74
- **Covering:** 2026-03-14 02:58:11 to 2026-03-14 04:22:19
- **Alerts:** 8

## Summary

| Severity | Alerts |
| --- | --- |
| Critical | 1 |
| High | 5 |
| Medium | 2 |
| Low | 0 |
| Info | 0 |

## Timeline

| First seen | Severity | Rule | What happened |
| --- | --- | --- | --- |
| 2026-03-14 03:10:02 | High | `SSH-001` | 7 failed SSH logins from 203.0.113.5 within 5 minutes, against 3 username(s) |
| 2026-03-14 03:11:40 | High | `SSH-002` | 6 distinct usernames tried from 198.51.100.9 within 15 minutes |
| 2026-03-14 03:16:00 | Critical | `SSH-003` | 'deploy' logged in from 203.0.113.77 after 3 failed attempts in the preceding 15 minutes |
| 2026-03-14 03:20:00 | Medium | `SSH-004` | 'jsmith' logged in from 2 different addresses within 10 minutes |
| 2026-03-14 04:02:10 | Medium | `WEB-001` | 26 client-error responses to 198.51.100.7 within 5 minutes |
| 2026-03-14 04:02:12 | High | `WEB-003` | 8 request(s) for sensitive paths from 198.51.100.7; 1 returned content |
| 2026-03-14 04:05:01 | High | `WEB-004` | 3 request(s) from 203.0.113.9 contained injection-shaped input (<script, etc/passwd, union select) |
| 2026-03-14 04:09:00 | High | `WEB-002` | 9 failed logins to /login from 192.0.2.77 within 5 minutes |

## Alerts

### 1. [Critical] Successful login after repeated failures

- **Rule:** `SSH-003`  
- **Occurrences:** 4  
- **Window:** 2026-03-14 03:16:00 to 2026-03-14 03:16:20
- **IP:** 203.0.113.77
- **Account:** deploy
- **MITRE ATT&CK:** T1078 - Valid Accounts

**Evidence**

```
Mar 14 03:16:00 web01 sshd[2450]: Failed password for deploy from 203.0.113.77 port 40100 ssh2
Mar 14 03:16:12 web01 sshd[2450]: Failed password for deploy from 203.0.113.77 port 40105 ssh2
Mar 14 03:16:18 web01 sshd[2450]: Failed password for deploy from 203.0.113.77 port 40111 ssh2
Mar 14 03:16:20 web01 sshd[2455]: Accepted password for deploy from 203.0.113.77 port 40122 ssh2
```

**Next step:** Treat the account as compromised: force a password reset, revoke sessions and keys, review what the account touched, and check for persistence.

### 2. [High] SSH brute-force attempts

- **Rule:** `SSH-001`  
- **Occurrences:** 7  
- **Window:** 2026-03-14 03:10:02 to 2026-03-14 03:11:20
- **IP:** 203.0.113.5
- **Usernames:** admin, oracle, root
- **MITRE ATT&CK:** T1110.001 - Brute Force: Password Guessing

**Evidence**

```
Mar 14 03:10:02 web01 sshd[2411]: Failed password for root from 203.0.113.5 port 51422 ssh2
Mar 14 03:10:16 web01 sshd[2411]: Failed password for root from 203.0.113.5 port 51426 ssh2
Mar 14 03:10:31 web01 sshd[2412]: Failed password for admin from 203.0.113.5 port 51431 ssh2
Mar 14 03:11:20 web01 sshd[2414]: Failed password for invalid user oracle from 203.0.113.5 port 51461 ssh2
```

**Next step:** Block the source, disable password authentication for external SSH, require keys, and consider fail2ban or a bastion host.

### 3. [High] Password spraying

- **Rule:** `SSH-002`  
- **Occurrences:** 6  
- **Window:** 2026-03-14 03:11:40 to 2026-03-14 03:19:45
- **IP:** 198.51.100.9
- **Usernames:** awilson, jsmith, kgarcia, lbrown, mchen, tpatel
- **MITRE ATT&CK:** T1110.003 - Brute Force: Password Spraying

**Evidence**

```
Mar 14 03:11:40 web01 sshd[2421]: Invalid user jsmith from 198.51.100.9
Mar 14 03:13:05 web01 sshd[2422]: Invalid user awilson from 198.51.100.9
Mar 14 03:14:20 web01 sshd[2423]: Invalid user mchen from 198.51.100.9
Mar 14 03:19:45 web01 sshd[2426]: Invalid user lbrown from 198.51.100.9
```

**Next step:** Spraying targets many accounts with few guesses to dodge lockouts. Block the source, alert on distributed attempts, and enforce MFA for all remote access.

### 4. [High] Sensitive path probing (content returned)

- **Rule:** `WEB-003`  
- **Occurrences:** 8  
- **Window:** 2026-03-14 04:02:12 to 2026-03-14 04:02:22
- **IP:** 198.51.100.7
- **Paths:** /.env, /.git/HEAD, /actuator/env, /backup.zip, /config.php, /phpmyadmin
- **MITRE ATT&CK:** T1083 - File and Directory Discovery

**Evidence**

```
198.51.100.7 - - [14/Mar/2026:04:02:12 +0000] "GET /wp-login.php HTTP/1.1" 404 162 "-" "Mozilla/5.0 (compatible; Nuclei)"
198.51.100.7 - - [14/Mar/2026:04:02:13 +0000] "GET /.env HTTP/1.1" 404 162 "-" "Mozilla/5.0 (compatible; Nuclei)"
198.51.100.7 - - [14/Mar/2026:04:02:15 +0000] "GET /backup.zip HTTP/1.1" 404 162 "-" "Mozilla/5.0 (compatible; Nuclei)"
198.51.100.7 - - [14/Mar/2026:04:02:22 +0000] "GET /actuator/env HTTP/1.1" 404 162 "-" "Mozilla/5.0 (compatible; Nuclei)"
```

**Next step:** Remove the files from the web root, deny dotfiles at the server, and rotate any credential the exposed file contained.

### 5. [High] Injection payloads in requests

- **Rule:** `WEB-004`  
- **Occurrences:** 3  
- **Window:** 2026-03-14 04:05:01 to 2026-03-14 04:06:12
- **IP:** 203.0.113.9
- **Patterns:** <script, etc/passwd, union select
- **MITRE ATT&CK:** T1190 - Exploit Public-Facing Application

**Evidence**

```
203.0.113.9 - - [14/Mar/2026:04:05:01 +0000] "GET /product?id=1%27%20UNION%20SELECT%20username%20FROM%20users-- HTTP/1.1" 500 431 "-" "sqlmap/1.8"
203.0.113.9 - - [14/Mar/2026:04:05:40 +0000] "GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1" 200 1892 "-" "Mozilla/5.0"
203.0.113.9 - - [14/Mar/2026:04:06:12 +0000] "GET /download?file=../../../../etc/passwd HTTP/1.1" 400 226 "-" "Mozilla/5.0"
```

**Next step:** Confirm the parameter is handled with prepared statements or output encoding. A 500 or a 200 with unusual content is worth reproducing by hand.

### 6. [High] Login endpoint brute force

- **Rule:** `WEB-002`  
- **Occurrences:** 9  
- **Window:** 2026-03-14 04:09:00 to 2026-03-14 04:10:00
- **IP:** 192.0.2.77
- **Path:** /login
- **MITRE ATT&CK:** T1110.001 - Brute Force: Password Guessing

**Evidence**

```
192.0.2.77 - - [14/Mar/2026:04:09:00 +0000] "POST /login HTTP/1.1" 401 61 "-" "python-requests/2.31"
192.0.2.77 - - [14/Mar/2026:04:09:07 +0000] "POST /login HTTP/1.1" 401 61 "-" "python-requests/2.31"
192.0.2.77 - - [14/Mar/2026:04:09:14 +0000] "POST /login HTTP/1.1" 401 61 "-" "python-requests/2.31"
192.0.2.77 - - [14/Mar/2026:04:10:00 +0000] "POST /login HTTP/1.1" 401 61 "-" "python-requests/2.31"
```

**Next step:** Rate-limit and lock out per account and per source, add a CAPTCHA after a few failures, and require MFA on accounts with access.

### 7. [Medium] Account used from multiple addresses

- **Rule:** `SSH-004`  
- **Occurrences:** 2  
- **Window:** 2026-03-14 03:20:00 to 2026-03-14 03:21:30
- **Account:** jsmith
- **Source addresses:** 192.0.2.55, 203.0.113.140
- **MITRE ATT&CK:** T1078 - Valid Accounts

**Evidence**

```
Mar 14 03:20:00 web01 sshd[2470]: Accepted publickey for jsmith from 192.0.2.55 port 40200 ssh2
Mar 14 03:21:30 web01 sshd[2472]: Accepted publickey for jsmith from 203.0.113.140 port 40204 ssh2
```

**Next step:** Confirm with the account owner - a VPN, a jump host, or a scripted job explains some of these. If not, treat it as credential sharing or theft.

### 8. [Medium] Directory and file scanning

- **Rule:** `WEB-001`  
- **Occurrences:** 26  
- **Window:** 2026-03-14 04:02:10 to 2026-03-14 04:02:36
- **IP:** 198.51.100.7
- **Top paths:** /admin (1), /wp-admin (1), /wp-login.php (1), /.env (1)
- **MITRE ATT&CK:** T1595 - Active Scanning

**Evidence**

```
198.51.100.7 - - [14/Mar/2026:04:02:10 +0000] "GET /admin HTTP/1.1" 404 162 "-" "Mozilla/5.0 (compatible; Nuclei)"
198.51.100.7 - - [14/Mar/2026:04:02:11 +0000] "GET /wp-admin HTTP/1.1" 404 162 "-" "Mozilla/5.0 (compatible; Nuclei)"
198.51.100.7 - - [14/Mar/2026:04:02:12 +0000] "GET /wp-login.php HTTP/1.1" 404 162 "-" "Mozilla/5.0 (compatible; Nuclei)"
198.51.100.7 - - [14/Mar/2026:04:02:36 +0000] "GET /Dockerfile HTTP/1.1" 404 162 "-" "Mozilla/5.0 (compatible; Nuclei)"
```

**Next step:** Rate-limit the source, front the site with a WAF, and make sure error pages do not confirm which paths exist.

## Method

SSH auth logs and web access logs are normalised, then evaluated against fixed detection rules with explicit thresholds. Times come from the log lines themselves; syslog entries have no year, so it is supplied at runtime.
