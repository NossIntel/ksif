# KSIF — Kali Security Intelligence Framework

A modular, scope-enforced terminal framework for security assessment on Kali
Linux. KSIF drives well-known tools, interprets their output, stores the
results in SQLite and produces technical reports.

> **Authorized use only.** Run KSIF exclusively against systems you own or
> have explicit written permission to assess. KSIF refuses any target that is
> not in your allowlist, but the legal responsibility is always yours.

## Status

Version 0.1.0. See [docs/STATUS.md](docs/STATUS.md) for exactly what is
implemented and how each part was verified.

| # | Module | Status |
|---|---|---|
| 01 | Network Discovery | **Implemented** (nmap, arp-scan, masscan, tshark) |
| 02 | OSINT Intelligence | Not implemented |
| 03 | Web Security Assessment | Not implemented |
| 04 | Wi-Fi Security Audit | Not implemented |
| 05 | Password Security Lab | Not implemented |
| 06 | Vulnerability Intelligence | Not implemented |
| 07 | Asset Inventory | **Implemented** |
| 08 | Report Generator | **Implemented** (HTML, Markdown, JSON, CSV; PDF with WeasyPrint) |
| 09 | Configuration | **Implemented** |

Modules that are not implemented appear in the menu as `not yet available`.
Nothing is simulated.

## Install (Kali Linux / Debian)

```bash
git clone <your-repository-url> ksif
cd ksif
bash scripts/install.sh
```

The installer detects the distribution, installs the system packages
(`nmap arp-scan masscan tshark python3-venv`), creates `.venv`, installs the
Python packages, initializes the database and runs the test suite. It never
runs a scan. Details: [docs/installation.md](docs/installation.md).

## Configure the scope

KSIF starts in **passive mode** with an **empty scope**. Edit
`config/scope.yaml`:

```yaml
engagement: "Home lab audit"
ips: ["192.168.56.10"]
subnets: ["192.168.56.0/24"]
domains: ["lab.example.com", "*.lab.example.com"]
interfaces: ["eth0"]
```

## Run

```bash
.venv/bin/python main.py            # interactive interface
sudo .venv/bin/python main.py       # needed for OS detection, ARP scan, capture
.venv/bin/python main.py --check    # tools, scope and configuration
```

```
[01] Network Discovery        [06] Vulnerability Intelligence
[02] OSINT Intelligence       [07] Asset Inventory
[03] Web Security Assessment  [08] Report Generator
[04] Wi-Fi Security Audit     [09] Configuration
[05] Password Security Lab    [10] Exit
```

A typical first session: `09` → switch to active mode → `01` → *Host
discovery* → `192.168.56.0/24` → confirm → `08` → HTML report. Full guide:
[docs/usage.md](docs/usage.md).

## Safety model

- **Allowlist.** Every target is checked against `scope.yaml`. Networks must be
  fully inside an authorized subnet; a domain used in an active operation must
  resolve only to in-scope addresses.
- **Passive / active mode.** Passive mode blocks everything that sends traffic
  to a target.
- **Confirmation.** Active actions ask `y/N`; intrusive actions require typing
  the target again.
- **No shell, fixed tools.** Processes are started without a shell, from a
  fixed list of binaries, with arguments built by typed functions. Users never
  pass free-form flags.
- **Hard limits.** Nmap `--max-rate` ≤ 1000 and timing ≤ T4; Masscan
  `--rate` ≤ 1000; captures ≤ 300 s.
- **Audit trail.** Operator, UTC time, exact command, target and the scope
  decision go to `logs/audit.jsonl` and to the database.

More: [docs/architecture.md](docs/architecture.md), [SECURITY.md](SECURITY.md).

## Dependencies

- Python ≥ 3.12, `rich`, `pyyaml` (tests: `pytest`, `pytest-asyncio`).
- Optional: `weasyprint` for PDF reports.
- External tools: `nmap`, `arp-scan`, `masscan`, `tshark`. A missing tool only
  disables the actions that need it.

## Tests

```bash
.venv/bin/python -m pytest                    # unit tests, any OS
.venv/bin/python -m pytest -m integration -v  # real tools, loopback only (Kali)
```

## Documentation

- [Architecture](docs/architecture.md)
- [Installation](docs/installation.md)
- [Usage](docs/usage.md)
- [Network Discovery module](docs/modules/network_discovery.md)
- [Implementation status](docs/STATUS.md)
- [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md)

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).

---

## Português

O KSIF é um framework modular de terminal para avaliação de segurança no Kali
Linux, com escopo de análise obrigatório. Ele executa ferramentas
consolidadas, interpreta as saídas, armazena os resultados em SQLite e gera
relatórios.

**Uso somente autorizado:** analise apenas sistemas próprios ou com permissão
expressa.

Instalação: `bash scripts/install.sh`. Depois edite `config/scope.yaml` com os
alvos autorizados e inicie com `.venv/bin/python main.py`. O sistema começa em
modo passivo e com escopo vazio; nada ativo é executado até você alterar os
dois na tela Configuration.

Nesta versão estão implementados Network Discovery, Asset Inventory, Report
Generator e Configuration. Os módulos 02 a 06 ainda não existem e aparecem no
menu como `not yet available`. O estado detalhado e o que foi verificado estão
em [docs/STATUS.md](docs/STATUS.md).
