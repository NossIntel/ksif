# Module 01 — Network Discovery

Inventory of the networks listed in your scope.

## What it produces

- Live hosts (IPv4 and IPv6), hostnames.
- MAC addresses and manufacturers. The vendor comes from the tool output, or
  from the OUI files shipped with nmap/arp-scan
  (`/usr/share/nmap/nmap-mac-prefixes`, `/usr/share/arp-scan/ieee-oui.txt`).
- Open ports, protocols, services, products and versions.
- Operating system guess with its accuracy.
- A probable device type (`router`, `printer`, `windows-host`, `linux-host`,
  `network-camera`, `nas`, `mobile`, `iot`, `server`, `unknown`). This is a
  heuristic from ports, OS guess and vendor — a hint, not a fact.
- Subnet map (/24 for IPv4, /64 for IPv6) and traceroute-based links.

## Commands KSIF runs

| Action | Command |
|---|---|
| Host discovery | `nmap -sn -oX - <target>` |
| Port scan | `nmap -oX - -T3 --max-rate 300 --top-ports 1000 <target>` (or `-p <ports>`) |
| Service and OS | `nmap -oX - -T3 --max-rate 300 … -sV -O <target>` |
| Topology | `nmap -oX - -T3 --max-rate 300 --top-ports 100 --traceroute <target>` |
| ARP scan | `arp-scan --interface=<if> --retry=2 <network>` |
| Fast sweep | `masscan -p <ports> --rate <≤1000> -oJ - <network>` |
| Passive capture | `tshark -i <if> -a duration:<≤300> -n -l -T fields -E separator=/t -e eth.src -e ip.src -e ipv6.src -e _ws.col.Protocol` |

`-6` is added for IPv6 targets. The exact command of every operation is stored
in the database and the audit log. Users cannot add flags; in particular no
NSE scripts are ever passed.

## Limits

- arp-scan and Masscan are IPv4 only.
- Passive capture stores no packets: only source addresses and a count per
  protocol. To inspect traffic in the Wireshark GUI, capture separately.
- Netdiscover is not integrated; arp-scan covers the same need.
- A scan that times out or returns incomplete XML is marked failed and
  nothing from it is stored.
