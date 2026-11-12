# Module 04 — Wi-Fi Security Audit

**Passive only.** KSIF lists nearby networks and reads the security they
advertise — the same information any device sees while choosing a network. It
never transmits to a network, never deauthenticates clients, and never captures
traffic or handshakes. `aireplay-ng`, `mdk4` and similar tools are deliberately
absent from the allowlist and cannot be run.

## Actions

| Action | Tool | Root | What it does |
|---|---|---|---|
| Scan nearby networks | nmcli | no | List SSID, BSSID, channel, band, security, signal |
| Scan on interface | iw | yes | Same, on a specific interface |
| Audit stored networks | (built-in) | no | Flag weak security on access points you own |

## Owned access points

Weak-security findings (open, WEP, WPA1) are raised **only** for the BSSIDs you
listed under `bssids` in `scope.yaml`. Networks you do not own are stored for
inventory but never flagged — auditing someone else's network is not your call
to make.

```yaml
bssids: ["aa:bb:cc:dd:ee:ff"]   # your own access point(s)
```

## Commands

| Action | Command |
|---|---|
| nmcli scan | `nmcli -t -f SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY dev wifi list --rescan no` |
| iw scan | `iw dev <interface> scan` |

## Findings

For your own access points: open/WEP (high), WPA1-only (medium), and a hidden
SSID (info, with a note that hiding the SSID adds little security). WPA2 and
WPA3 are reported as adequate.

## Deliberately excluded

Deauthentication, packet injection, handshake capture, and cracking of Wi-Fi
keys are out of scope for KSIF and will not be added.
