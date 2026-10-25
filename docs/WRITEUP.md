# logtriage — portfolio writeup

A Python tool that reads SSH auth logs and web access logs, runs eight detection rules over them, and
produces an incident summary: severity counts, a timeline, and every alert with the log lines that
caused it.

---

## CARL

### Context

My previous project was offensive — a scanner that finds weaknesses in a web app. Applying for SOC
Analyst roles, I kept running into the same interview question from the other side: *"How would you
detect this?"* Reading about detections is not the same as writing one, and the tools that do this
properly (Splunk, Elastic, Sentinel) are heavy to stand up and hide their logic behind queries I did
not write.

I wanted something small enough to read end to end, where every rule was mine to justify — including
the ones that should *not* fire.

### Action

I built a dependency-free triage tool in Python. Two parsers normalise OpenSSH syslog lines and
Apache/Nginx combined access logs into a single event type, so a mixed folder of logs works in one run.

Eight detection rules sit on top: SSH brute force, password spraying, success-after-failure,
multi-IP account use, web directory scanning, login endpoint brute force, sensitive path probing, and
injection-shaped input. Each alert carries the raw log lines, the entities involved, a MITRE ATT&CK
mapping, and a concrete next step.

Two decisions mattered more than the rules themselves.

**Sliding windows, not buckets.** My first version grouped events by minute. A burst of five failures
at 10:05:59 and five more at 10:06:01 then looked like two quiet minutes — a real brute force would
have slipped straight through. Replacing that with a two-pointer sliding window made the detections
correct for split bursts, and it is still linear time.

**Tuning is configuration, not code.** Thresholds and windows live in one `settings.py`, and
`--allowlist` suppresses known scanners, because a pentest or an uptime monitor will otherwise drown
the report. Detection work is mostly noise management; pretending otherwise would make the tool a toy.

I wrote 61 tests, and the ones I care about are the *negative* cases: 40 normal requests must not look
like scanning, eight failures for one username must not look like spraying, a success an hour later
must not look like a compromise.

### Result

Against the shipped sample logs — 74 events covering a deliberate attack narrative — it produces 8
alerts in about 10 milliseconds: 1 Critical, 5 High, 2 Medium. The critical one is the story the logs
tell: three failed passwords for `deploy`, then a successful login from the same address four seconds
later.

The report opens with a severity table and a timeline, then one section per alert with the evidence
fenced underneath. Unparsed lines are counted and reported rather than dropped, because a detection
tool that hides its blind spots is worse than no tool.

### Learned

**A detection is a claim about behaviour, so the negative case is the test that matters.** Anyone can
write a rule that fires on `Failed password`. The engineering is proving it stays quiet on a Tuesday
afternoon of legitimate traffic.

**Window shape is a correctness issue, not a tuning detail.** Bucketed time is the default in most
quick implementations, and it is wrong in a way that only shows up when the attack straddles a
boundary.

**Honest limitations read as competence.** I wanted an impossible-travel rule. Without a
geo-IP database I could not compute distance, so `SSH-004` reports multiple source addresses in a
short window instead of pretending to know geography. Saying that out loud in the README is better
than a rule that quietly guesses.

---

## Resume bullets

Pick two or three:

- Built a dependency-free Python log triage tool that normalises OpenSSH and Apache/Nginx logs and runs
  eight detection rules mapped to MITRE ATT&CK, producing severity-ranked incident reports in Markdown
  and JSON.
- Implemented sliding-window detection for brute force, password spraying, and success-after-failure,
  replacing naive time bucketing that missed attacks spanning a minute boundary.
- Wrote 61 tests covering both firing and non-firing cases, including false-positive checks on normal
  browsing and single-user login failures.
- Analysed a 74-event sample incident end to end, surfacing a credential compromise as Critical with
  the supporting log lines and a remediation step.

## For the interview

**"Walk me through a detection."** Use `SSH-003`, success after failure. The interesting part is not
the counting — it is that a successful login is only suspicious *relative to* the failures that
preceded it, within a bounded window, from the same source. That is a behavioural claim, not a
signature.

**"How do you deal with false positives?"** Thresholds and windows in one place, allowlisting for
known scanners, and a test per rule that asserts it stays quiet on normal traffic. Then measure:
count what fires on a quiet day before trusting the rule.

**"What's missing?"** No baselining per user or host, no geolocation, no state between runs, and no
cross-host correlation. A slow campaign under the threshold is invisible, and that is the honest
weakness of threshold detection.
