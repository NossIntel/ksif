# KSIF — Kali Security Intelligence Framework

A modular, scope-enforced terminal framework for security assessment on Kali
Linux. KSIF drives well-known tools, interprets their output, stores the
results in SQLite and produces technical reports.

> **Authorized use only.** Run KSIF exclusively against systems you own or
> have explicit written permission to assess. KSIF refuses any target that is
> not in your allowlist, but the legal responsibility is always yours.

## Status

Version 0.2.0. See [docs/STATUS.md](docs/STATUS.md) for exactly what is
implemented and how each part was verified.

| # | Module | Status |
|---|---|---|
| 01 | Network Discovery | **Implemented** (nmap, arp-scan, masscan, tshark) |
| 02 | OSINT Intelligence | **Implemented** (whois, dig, subfinder, amass, theHarvester, TLS) |
| 03 | Web Security Assessment | **Implemented** (whatweb, security headers, nikto, nuclei, wpscan) |
| 04 | Wi-Fi Security Audit | **Implemented** (nmcli, iw — passive listing only) |
| 05 | Password Security Lab | **Implemented** (offline strength, policy, breach and hash auditing) |
| 06 | Vulnerability Intelligence | **Implemented** (NVD, EPSS, CISA KEV correlation) |
| 07 | Asset Inventory | **Implemented** |
| 08 | Report Generator | **Implemented** (HTML, Markdown, JSON, CSV; PDF with WeasyPrint) |
| 09 | Configuration | **Implemented** |

29 actions across the six modules. Nothing is simulated: every integration
detects its tool, runs it for real and parses its real output.

## Interfaces

KSIF has two front ends over the same engine and the same security policy:

- **Terminal (TUI):** `python main.py` — the primary interface, best on Kali.
- **Graphical (GUI):** `python gui.py` — a Tkinter desktop window. A packaged
  Windows executable (`KSIF.exe`) is produced by `scripts/build_exe.py`; it
  bundles every Python dependency, so it runs with nothing to install. External
  security tools are still detected at runtime, so on Windows (where most Kali
  tools are absent) the GUI runs but most actions show as unavailable — full
  function is on Kali. See [docs/gui.md](docs/gui.md).

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
- [Usage](docs/usage.md) · [Graphical interface & building the exe](docs/gui.md)
- Modules: [Network Discovery](docs/modules/network_discovery.md) ·
  [OSINT](docs/modules/osint.md) · [Web Security](docs/modules/web_security.md) ·
  [Wi-Fi Audit](docs/modules/wifi_audit.md) · [Password Lab](docs/modules/password_lab.md) ·
  [Vulnerability Intelligence](docs/modules/vulnerability_intelligence.md)
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

Nesta versão estão implementados os seis módulos (Network Discovery, OSINT,
Web Security, Wi-Fi Audit, Password Lab e Vulnerability Intelligence), além de
Asset Inventory, Report Generator e Configuration — 29 ações no total. Nada é
simulado: cada integração detecta a ferramenta, executa de verdade e interpreta
a saída real.

Há duas interfaces sobre o mesmo motor: o terminal (`python main.py`, ideal no
Kali) e a interface gráfica (`python gui.py`, em Tkinter). O
`scripts/build_exe.py` gera um `KSIF.exe` para Windows que embute todas as
dependências Python — abre sem instalar nada. As ferramentas externas (nmap,
nuclei, nmcli…) são de Linux; no Windows o `.exe` abre e funciona como GUI, mas
a maioria das ações aparece como indisponível, pois essas ferramentas não
existem lá. A função plena é no Kali.

Limites de segurança mantidos nos novos módulos: OSINT é só passivo; Wi-Fi é só
listagem passiva (sem desautenticação, injeção ou captura); o laboratório de
senhas é 100% offline sobre material seu; o WPScan exige que o site esteja
listado como próprio. O estado detalhado e o que foi verificado estão em
[docs/STATUS.md](docs/STATUS.md).
