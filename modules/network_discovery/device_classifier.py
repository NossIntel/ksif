"""Heuristic guess of the kind of device behind a host.

The result is a hint for the inventory, derived from open ports first, then
the OS fingerprint, then the MAC vendor. It is never presented as a fact."""

from __future__ import annotations

from core.models import Host

_NETWORK_VENDORS = ("technicolor", "tp-link", "netgear", "cisco", "ubiquiti", "mikrotik", "huawei",
                    "zte", "d-link", "asustek", "arris", "juniper", "aruba", "intelbras", "sagemcom")
_MOBILE_VENDORS = ("apple", "samsung", "xiaomi", "motorola", "oneplus", "oppo")
_IOT_VENDORS = ("espressif", "tuya", "shelly", "sonoff", "amazon technologies", "google")
_PRINTER_VENDORS = ("brother", "hewlett", "canon", "epson", "lexmark", "kyocera", "xerox")
_CAMERA_VENDORS = ("hikvision", "dahua", "axis communications", "reolink")
_NAS_VENDORS = ("synology", "qnap", "western digital")


def classify_device(host: Host) -> str:
    """Return a coarse device type for *host* (``unknown`` when there is no signal)."""
    ports = {p.number for p in host.ports if p.state.startswith("open")}
    vendor = (host.vendor or "").lower()
    os_guess = (host.os_guess or "").lower()

    if ports & {9100, 515, 631}:
        return "printer"
    if ports & {554, 8554, 37777}:
        return "network-camera"
    if 445 in ports and ports & {3389, 135, 139}:
        return "windows-host"
    if 53 in ports and ports & {80, 443} and any(v in vendor for v in _NETWORK_VENDORS):
        return "router"
    if ports & {2049, 5000, 5001, 548} and (any(v in vendor for v in _NAS_VENDORS) or 2049 in ports):
        return "nas"
    if ports & {1883, 8883}:
        return "iot"

    if "windows" in os_guess:
        return "windows-host"
    if any(word in os_guess for word in ("openwrt", "routeros", "ios 1", "junos", "router", "wap")):
        return "router"
    if any(word in os_guess for word in ("android", "iphone", "ios")):
        return "mobile"

    if any(v in vendor for v in _PRINTER_VENDORS) and not ports & {22, 3389}:
        return "printer"
    if any(v in vendor for v in _CAMERA_VENDORS):
        return "network-camera"
    if any(v in vendor for v in _NAS_VENDORS):
        return "nas"
    if any(v in vendor for v in _NETWORK_VENDORS):
        return "router"
    if any(v in vendor for v in _IOT_VENDORS) or "raspberry" in vendor:
        return "iot"
    if any(v in vendor for v in _MOBILE_VENDORS) and not ports:
        return "mobile"

    if len(ports & {25, 80, 443, 3306, 5432, 8080, 8443, 6379, 27017}) >= 2:
        return "server"
    if 22 in ports or "linux" in os_guess:
        return "linux-host"
    return "unknown"
