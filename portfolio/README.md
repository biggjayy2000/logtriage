# Portfolio assets — logtriage

Rendered from a real run over the shipped sample logs. The terminal page contains the exact bytes the
CLI printed, with ANSI colour codes translated to CSS; it is a rendering of terminal output, not a
photograph of a terminal window.

| File | What it shows | Use it for |
| --- | --- | --- |
| `screenshots/terminal-run.png` | Full triage: 74 events, 1 Critical / 5 High / 2 Medium, every rule firing | Portfolio card, README top |
| `screenshots/report-top.png` | The incident report: summary table, timeline, first alert with evidence | Proving the deliverable, not just the detector |
| `screenshots/report-full.png` | The whole report on one page | Drive portfolio, "full report" link |

Supporting files: `terminal_ansi.txt` (raw capture), `report-from-run.md` (the report),
`build_shots.py` (renders the pages), `shots/` (intermediate HTML).

## Regenerate

```bash
cd logtriage

python -m logtriage data/sample_auth.log data/sample_access.log --year 2026 \
  --markdown portfolio/report-from-run.md > portfolio/terminal_ansi.txt 2>&1
python portfolio/build_shots.py
python -m http.server 8011 --bind 127.0.0.1 --directory portfolio/shots &

CHROME="/c/Program Files/Google/Chrome/Application/chrome.exe"
"$CHROME" --headless=new --hide-scrollbars --force-device-scale-factor=2 \
  --window-size=1280,770 --screenshot=portfolio/screenshots/terminal-run.png \
  http://127.0.0.1:8011/terminal-run.html
```

## Pairing with websec-audit

The two projects are deliberately opposite sides of the same coin: `websec-audit` finds weaknesses in
a web app, `logtriage` detects the traffic those weaknesses produce. If a portfolio page groups them,
say that — "offence and defence from the same lab logs" is a stronger story than two unrelated repos.
