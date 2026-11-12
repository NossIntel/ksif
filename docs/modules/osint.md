# Module 02 — OSINT Intelligence

Open-source intelligence about a domain in your scope. Every action is
**passive**: it queries registries, DNS, certificate data and public sources.
It does not send intrusive traffic to the target's own infrastructure.

## Actions

| Action | Tool | What it does |
|---|---|---|
| WHOIS lookup | whois | Registrar, creation/expiry dates, name servers |
| DNS records | dig | A, AAAA, MX, NS, TXT, SOA, CNAME; flags weak SPF |
| Subdomain discovery | subfinder / amass | Passive subdomain enumeration |
| TLS certificate | (built-in) | Protocol, cipher, issuer, expiry; flags weak/expired TLS |
| Public emails and hosts | theHarvester | Emails and hostnames from public sources |
| Correlate stored OSINT | (built-in) | Summarises and cross-references what was collected |

## Commands

| Action | Command |
|---|---|
| WHOIS | `whois <domain>` |
| DNS | `dig +noall +answer +nocomments <domain> A AAAA MX NS TXT SOA CNAME` |
| Subdomains | `subfinder -silent -all -d <domain>` or `amass enum -passive -silent -d <domain>` |
| Emails/hosts | `theHarvester -d <domain> -b crtsh,bing,duckduckgo` |

The TLS check is done in Python through the engine's authorized HTTP/TLS client,
which only connects to the authorized target and records the request.

## Findings

Domain expiring or expired, weak SPF (`+all`), weak TLS protocol (TLS 1.1 or
older), expired or soon-to-expire certificate, and a large external attack
surface (many subdomains). Collected items are stored as OSINT records for the
report and the inventory.

## Notes

- Results are only as reliable as the public sources. KSIF stores what the tools
  return; verify before acting.
- `theHarvester` output varies by version; KSIF parses the emails and hosts that
  belong to the queried domain and ignores the rest.
