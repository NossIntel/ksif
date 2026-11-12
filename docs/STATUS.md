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

## Not verified yet

| Item | How to verify |
|---|---|
| `scripts/install.sh` on a clean Kali | Push to GitHub: the `kali` CI job runs it in `kalilinux/kali-rolling`. Or run it on a Kali machine. |
| Real execution and parsing of nmap, arp-scan, masscan, tshark | `pytest -m integration -v` on Kali (also run by the `kali` CI job, loopback only) |
| ARP scan and passive capture on a real network | Manual run on Kali with root and an interface listed in the scope |
| PDF reports | Install WeasyPrint and generate one |
| The CI workflow itself | It has never run; it may need adjustments on first push |
| Termux | Untested |

Shell scripts passed `bash -n` (syntax only).

## Not implemented

- Modules 02–06: OSINT, Web Security Assessment, Wi-Fi Security Audit,
  Password Security Lab, Vulnerability Intelligence. The database tables and
  report sections they will use already exist and are empty.
- Netdiscover (arp-scan covers the same need).
- Web interface, Docker image.
- Publication on GitHub.

## Deviations from the plan

- Tests were written together with the code rather than strictly before it.
- The report engine was built in full instead of the JSON/Markdown subset
  planned for the first milestone.
- `App` takes the engine instead of separate database/settings/scope objects.
