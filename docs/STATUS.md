# Implementation status

Last updated: 2026-11-12 · version 0.1.0

This file records what was actually built and **how each part was verified**.
"Verified locally" means the automated tests passed on the development
machine (Windows 11, Python 3.12). That machine has no Kali, WSL, Docker or
any of the external tools.

## Verified locally (216 unit tests)

| Area | What the tests prove |
|---|---|
| Input validation | Option injection, shell syntax, control characters and malformed values are rejected |
| Scope guard | Out-of-scope IPs, wider networks, look-alike domains and domains resolving outside the scope are blocked; passive mode blocks active actions; empty scope blocks everything |
| Configuration | Missing, empty and malformed `scope.yaml` never crash and fail closed |
| Database | Migrations, host/port upsert, atomic writes, findings, audit |
| Subprocess manager | No shell, fixed binary list, authorization required, timeout kills the process, audit events |
| Engine | Full lifecycle, confirmation, rate limiting, failure handling |
| Parsers | Nmap XML, arp-scan, Masscan (current and legacy format), tshark fields |
| Network Discovery | Whole pipeline: authorize → spawn process → parse → enrich → store |
| Reports | JSON, Markdown, HTML, CSV; escaping of tool-controlled text; CSV formula neutralisation |
| Interface | Menus, blocking messages, confirmations, inventory, report writing, configuration |
| Entry point | `python main.py --check` and an interactive session were run for real |

**Important limit:** in these tests the external tools are replaced by a
stand-in program that prints sample output. The samples were written by hand
in each tool's documented format; they are not captures from real runs.

## Verified on Kali (GitHub Actions, `kalilinux/kali-rolling`, 2026-11-12)

The `kali` CI job passed on a clean Kali container (Python 3.14.8,
nmap 7.991, arp-scan 1.10.0, masscan 1.3.2, tshark 4.6.9):

- `scripts/install.sh` ran end to end: packages installed, `.venv` created,
  database initialized at schema version 2, 216 unit tests passed.
- `python main.py --check` started and really executed each tool's probe.
- 8 integration tests passed with the real tools, loopback only: version
  detection of all four tools; nmap host discovery, port scan and
  service/OS detection of `127.0.0.1`, parsed and stored; an out-of-scope
  target (`8.8.8.8`) blocked without any process being started.

## Not verified yet

| Item | How to verify |
|---|---|
| arp-scan, Masscan and tshark beyond version detection | Their parsers are tested only against hand-written samples. Run them on Kali with root against a lab network in scope. |
| The interactive interface on a Kali terminal | Run `python main.py` on Kali. It was run interactively only on Windows. |
| Multi-host results from real nmap | The CI scan saw one host (loopback). Scan a lab subnet. |
| PDF reports | Install WeasyPrint and generate one |
| `scripts/update.sh` | Syntax-checked only |
| Termux | Untested |

## Not implemented

- Modules 02–06: OSINT, Web Security Assessment, Wi-Fi Security Audit,
  Password Security Lab, Vulnerability Intelligence. The database tables and
  report sections they will use already exist and are empty.
- Netdiscover (arp-scan covers the same need).
- Web interface, Docker image.
- Public release: the GitHub repository exists but is private.

## Deviations from the plan

- Tests were written together with the code rather than strictly before it.
- The report engine was built in full instead of the JSON/Markdown subset
  planned for the first milestone.
- `App` takes the engine instead of separate database/settings/scope objects.
