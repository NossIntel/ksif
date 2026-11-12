"""Vulnerability-intelligence sources: NVD, EPSS and CISA KEV.

These are public reference databases. The functions here build the request
URLs and parse the JSON responses; the network call itself goes through the
engine's ``IntelHttpClient``, which only talks to this fixed set of hosts.
"""

from __future__ import annotations

import re
from urllib.parse import quote

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

_SEVERITY_FROM_SCORE = (
    (9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.1, "low"), (0.0, "info"),
)


def nvd_search_url(keyword: str, results: int = 20) -> str:
    """Build an NVD keyword-search URL."""
    clean = re.sub(r"[^A-Za-z0-9.\- ]", " ", keyword).strip()
    return f"{NVD_URL}?keywordSearch={quote(clean)}&resultsPerPage={max(1, min(results, 100))}"


def severity_from_score(score: float | None) -> str:
    """Map a CVSS base score to a severity label."""
    if score is None:
        return "unknown"
    for threshold, label in _SEVERITY_FROM_SCORE:
        if score >= threshold:
            return label
    return "info"


def parse_nvd(data: dict | None) -> list[dict]:
    """Parse an NVD 2.0 response into CVE records."""
    if not isinstance(data, dict):
        return []
    records: list[dict] = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue
        summary = ""
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                summary = desc.get("value", "")
                break
        score, sev = _best_cvss(cve.get("metrics", {}))
        records.append({
            "cve_id": cve_id.upper(), "cvss": score,
            "severity": sev or severity_from_score(score), "summary": summary,
        })
    return records


def _best_cvss(metrics: dict) -> tuple[float | None, str | None]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for metric in metrics.get(key, []):
            data = metric.get("cvssData", {})
            score = data.get("baseScore")
            if score is not None:
                sev = data.get("baseSeverity") or metric.get("baseSeverity")
                return float(score), (sev.lower() if isinstance(sev, str) else None)
    return None, None


def epss_url(cve_ids: list[str]) -> str:
    """Build an EPSS batch URL for up to ~100 CVEs."""
    joined = ",".join(c.upper() for c in cve_ids[:100])
    return f"{EPSS_URL}?cve={quote(joined)}"


def parse_epss(data: dict | None) -> dict[str, float]:
    """Map CVE id -> EPSS probability."""
    if not isinstance(data, dict):
        return {}
    scores: dict[str, float] = {}
    for row in data.get("data", []):
        cve, value = row.get("cve"), row.get("epss")
        if cve and value is not None:
            try:
                scores[cve.upper()] = float(value)
            except (TypeError, ValueError):
                continue
    return scores


def parse_kev(data: dict | None) -> set[str]:
    """Return the set of CVE ids in the CISA KEV catalog."""
    if not isinstance(data, dict):
        return set()
    return {row["cveID"].upper() for row in data.get("vulnerabilities", []) if row.get("cveID")}


def priority(cvss: float | None, epss: float | None, kev: bool) -> float:
    """Combine CVSS, EPSS and KEV into a single 0-10 priority score.

    KEV (known exploited) dominates; otherwise exploit probability raises an
    already-severe issue above a merely theoretical one.
    """
    base = cvss if cvss is not None else 4.0
    score = base * (0.6 + 0.4 * (epss if epss is not None else 0.0))
    if kev:
        score = max(score, 9.0) + 1.0
    return round(min(score, 11.0), 2)
