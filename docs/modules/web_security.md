# Module 03 — Web Security Assessment

Assess a web target that is in your scope. Fingerprinting and the header check
are light; nikto and nuclei are active scans; wpscan is restricted to WordPress
sites you own.

## Actions

| Action | Tool | What it does |
|---|---|---|
| Technology fingerprint | whatweb | Server, frameworks, libraries; flags version disclosure |
| Security header check | (built-in) | HSTS, CSP, X-Frame-Options, cookies, version leaks |
| Server misconfiguration scan | nikto | Known issues and exposed files |
| Template scan | nuclei | Community templates; maps CVEs to vulnerabilities |
| WordPress assessment | wpscan | Core/plugin issues (owned sites only) |

## Security header check

Done in Python through the authorized HTTP client. It aligns with the OWASP
Secure Headers project and flags: missing HSTS (on HTTPS), missing or weak CSP,
no clickjacking protection, missing `X-Content-Type-Options: nosniff`, missing
Referrer-Policy / Permissions-Policy, a `Server`/`X-Powered-By` header that
leaks a version, and cookies without `Secure`/`HttpOnly`.

## Commands

| Action | Command |
|---|---|
| Fingerprint | `whatweb --color=never --no-errors -a 3 <target>` |
| nikto | `nikto -host <target> -nointeractive -ask no -maxtime 120s` |
| nuclei | `nuclei -u <target> -jsonl -silent -no-color -severity low,medium,high,critical` |
| wpscan | `wpscan --url <url> --format json --no-banner --random-user-agent --enumerate vp,vt,u` |

## WordPress (wpscan)

`web.wpscan` refuses any host that is not listed under `wordpress_sites` in
`scope.yaml`, and it asks you to confirm ownership first. If `WPSCAN_API_TOKEN`
is set in the environment, it is passed to wpscan for vulnerability data.

## Findings and vulnerabilities

Header issues, fingerprint version disclosure and nikto items become findings.
nuclei and wpscan results that carry a CVE also become entries in the
vulnerabilities table, where module 06 can enrich them with EPSS/KEV.
