"""Wi-Fi tool integrations: passive listing only.

KSIF only *lists* nearby networks and reads their advertised security, the same
information any device sees while choosing a network. It never transmits to
them: there is no deauthentication, no injection, and no capture of other
people's traffic or handshakes. Detailed auditing is meant for access points
whose BSSID you listed as your own in scope.yaml.
"""

from __future__ import annotations

import re

from core.validator import validate_interface
from integrations.base import ToolIntegration


def band_of(freq_mhz: int) -> str:
    """Map a frequency in MHz to a band label."""
    if 2400 <= freq_mhz <= 2500:
        return "2.4GHz"
    if 5150 <= freq_mhz <= 5925:
        return "5GHz"
    if 5925 <= freq_mhz <= 7125:
        return "6GHz"
    return ""


def normalize_security(raw: str) -> str:
    """Normalise a security string to a compact label (weakest first)."""
    text = raw.upper()
    if not text or text in ("--", "NONE"):
        return "OPEN"
    labels = []
    if "WEP" in text:
        labels.append("WEP")
    if "WPA3" in text or "SAE" in text:
        labels.append("WPA3")
    if re.search(r"WPA2|RSN", text):
        labels.append("WPA2")
    if re.search(r"WPA1|(?<!WPA)WPA(?![23])", text):
        labels.append("WPA1")
    if "802.1X" in text or "EAP" in text:
        labels.append("802.1X")
    return " ".join(dict.fromkeys(labels)) or "OPEN"


def weakest(security: str) -> str:
    """Return the weakest protection present: open < wep < wpa1 < wpa2 < wpa3."""
    text = security.upper()
    if text == "OPEN" or not text:
        return "open"
    if "WEP" in text:
        return "wep"
    if "WPA1" in text and "WPA2" not in text and "WPA3" not in text:
        return "wpa1"
    if "WPA2" in text and "WPA3" not in text:
        return "wpa2"
    if "WPA3" in text:
        return "wpa3"
    return "unknown"


def _split_terse(line: str) -> list[str]:
    """Split an ``nmcli -t`` line on unescaped ':' (BSSID colons are escaped)."""
    fields, current, i = [], [], 0
    while i < len(line):
        char = line[i]
        if char == "\\" and i + 1 < len(line):
            current.append(line[i + 1])
            i += 2
            continue
        if char == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(char)
        i += 1
    fields.append("".join(current))
    return fields


class NmcliIntegration(ToolIntegration):
    """Passive Wi-Fi listing via NetworkManager's ``nmcli`` (no root needed)."""

    binary = "nmcli"
    install_hint = "sudo apt install network-manager"
    probe_arg = "--version"
    version_pattern = r"version (\d+\.\d+(?:\.\d+)*)"
    FIELDS = "SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY"

    def scan_args(self, rescan: bool = False) -> list[str]:
        return ["-t", "-f", self.FIELDS, "dev", "wifi", "list", "--rescan", "yes" if rescan else "no"]

    def parse(self, output: str) -> list[dict]:
        """One dict per network (deduplicated by BSSID)."""
        networks: dict[str, dict] = {}
        for line in output.splitlines():
            if not line.strip():
                continue
            parts = _split_terse(line)
            if len(parts) < 6:
                continue
            ssid, bssid, chan, freq, signal, security = parts[:6]
            bssid = bssid.lower()
            if not re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", bssid):
                continue
            freq_mhz = _int(re.sub(r"\D", "", freq))
            networks[bssid] = {
                "bssid": bssid, "ssid": ssid, "channel": _int(chan),
                "band": band_of(freq_mhz or 0), "security": normalize_security(security),
                "signal": _int(signal),
            }
        return list(networks.values())


class IwIntegration(ToolIntegration):
    """Passive Wi-Fi scan via ``iw`` (needs root)."""

    binary = "iw"
    install_hint = "sudo apt install iw"
    probe_arg = "--version"
    version_pattern = r"iw version (\d+\.\d+(?:\.\d+)*)"

    def scan_args(self, interface: str) -> list[str]:
        return ["dev", validate_interface(interface), "scan"]

    def parse(self, output: str) -> list[dict]:
        """Parse ``iw dev <if> scan`` BSS blocks."""
        networks: list[dict] = []
        current: dict | None = None
        for raw in output.splitlines():
            line = raw.strip()
            bss = re.match(r"^BSS ([0-9a-f:]{17})", line)
            if bss:
                if current:
                    networks.append(_finish_iw(current))
                current = {"bssid": bss.group(1).lower(), "ssid": "", "channel": None,
                           "freq": 0, "signal": None, "wpa": False, "rsn": False,
                           "sae": False, "privacy": False}
                continue
            if current is None:
                continue
            if line.startswith("SSID:"):
                current["ssid"] = line[5:].strip()
            elif line.startswith("freq:"):
                current["freq"] = _int(re.sub(r"\D", "", line.split(":", 1)[1]))
            elif line.startswith("signal:"):
                current["signal"] = _int(re.sub(r"[^0-9-]", "", line.split(":", 1)[1].split()[0]))
            elif "DS Parameter set: channel" in line or "primary channel:" in line:
                current["channel"] = _int(re.sub(r"\D", "", line.split("channel")[-1]))
            elif line.startswith("RSN:"):
                current["rsn"] = True
            elif line.startswith("WPA:"):
                current["wpa"] = True
            elif "Authentication suites:" in line and "SAE" in line:
                current["sae"] = True
            elif "capability:" in line and "Privacy" in line:
                current["privacy"] = True
        if current:
            networks.append(_finish_iw(current))
        return networks


def _finish_iw(bss: dict) -> dict:
    parts = []
    if bss["sae"]:
        parts.append("WPA3")
    if bss["rsn"]:
        parts.append("WPA2")
    if bss["wpa"]:
        parts.append("WPA1")
    if not parts and bss["privacy"]:
        parts.append("WEP")
    security = normalize_security(" ".join(parts)) if parts else "OPEN"
    return {"bssid": bss["bssid"], "ssid": bss["ssid"], "channel": bss["channel"],
            "band": band_of(bss["freq"] or 0), "security": security, "signal": bss["signal"]}


def _int(value: str) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
