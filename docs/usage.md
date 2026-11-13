# Usage

## 1. Define the scope

Edit `config/scope.yaml`. Everything not listed is refused.

```yaml
engagement: "Internal lab assessment 2026-11"
ips: ["192.168.56.10"]
subnets: ["192.168.56.0/24", "fd00:56::/64"]
domains: ["lab.example.com", "*.lab.example.com"]
interfaces: ["eth0"]
```

Rules:

- A network target must be fully inside one of `subnets`.
- `example.com` matches only itself; `*.example.com` matches its subdomains.
- For active operations a domain must resolve only to addresses that are also
  in `ips`/`subnets`.
- `interfaces` are the ones KSIF may capture on or ARP-scan from.

Invalid entries are dropped and shown in *Configuration* as `scope problem`.

## 2. Start

```bash
.venv/bin/python main.py
sudo .venv/bin/python main.py     # for actions marked "requires root"
```

The header always shows operator, mode, engagement and scope size.

## 3. Choose the mode

KSIF starts in **passive** mode. `09 Configuration → 1` switches to active
after you confirm you are authorized. The choice is saved to
`config/settings.yaml` and written to the audit log.

## 4. Network Discovery (`01`)

| Action | Level | Root | Tool |
|---|---|---|---|
| Host discovery (ping sweep) | active | no | nmap |
| ARP scan (local segment) | active | yes | arp-scan |
| Port scan | active | no | nmap |
| Service, version and OS detection | active | yes | nmap |
| Topology (traceroute) | active | yes | nmap |
| Fast sweep (rate-capped) | intrusive | yes | masscan |
| Passive capture | passive | yes | tshark |

Example session:

```
ksif> 01
network_discovery> 01
Target (cidr, domain, ipv4, ipv6): 192.168.56.0/24
Proceed? [y/N]: y
```

The status column of the module menu tells you why an action cannot run
(`missing tool: nmap`, `requires root`).

Outcomes:

- **COMPLETED** — results are shown and stored.
- **BLOCKED** — refused before anything ran; the reason is shown.
- **FAILED** — the tool ran but its output was incomplete or it timed out.
  Nothing partial is stored; the raw output path is shown.

### Built-in help for every action

Pick an action by its number and KSIF first shows a **How to use** panel: what
to enter, which tool it needs (and whether it is installed), whether it needs
root, and an example of the exact command. After you type the target and
parameters it shows **Command that will run** with your real values, then asks
for confirmation. The same command is stored with the operation and in the
audit log, so you can repeat it by hand. The GUI shows the same text in the
*How to use & exact command* box (button **Preview command**).

## 5. Asset Inventory (`07`)

Hosts, ports and services, subnet map, findings, vulnerabilities, OSINT
records, Wi-Fi networks and operation history, all read from the database.

## 6. Reports (`08`)

Report on everything stored or on one operation, as `html`, `markdown`,
`json`, `csv` or `pdf`. Files go to `reports/`. Each report contains the
environment, authorized scope, date and time, tools used, hosts, ports,
services and versions, issues, evidence, risk rating, recommendations and an
executive summary. Sections with no data are omitted.

## 7. Configuration (`09`)

Switch mode, change operator, reload `scope.yaml`, run every tool's self-test,
and read the audit log.

## Files

| Path | Content |
|---|---|
| `config/settings.yaml` | Operator, mode, rate limit, timeout, paths |
| `config/scope.yaml` | Allowlist |
| `database/ksif.db` | All results |
| `logs/ksif.log` | Application log (JSON Lines) |
| `logs/audit.jsonl` | Audit trail |
| `logs/raw/` | Raw tool output per operation |
| `reports/` | Generated reports |

The operator name comes from `settings.yaml`, else `$KSIF_OPERATOR`, else the
system user.
