"""Dark terminal theme and the KSIF banner."""

from __future__ import annotations

from rich.theme import Theme

from core.models import Intrusiveness

THEME = Theme(
    {
        "ksif.banner": "bold green",
        "ksif.title": "bold cyan",
        "ksif.key": "bold green",
        "ksif.dim": "grey58",
        "ksif.ok": "bold green",
        "ksif.warn": "bold yellow",
        "ksif.err": "bold red",
        "ksif.passive": "bold cyan",
        "ksif.active": "bold yellow",
        "sev.critical": "bold white on red",
        "sev.high": "bold red",
        "sev.medium": "yellow",
        "sev.low": "cyan",
        "sev.info": "grey58",
        "sev.unknown": "grey58",
    }
)

BANNER = r"""
 ██╗  ██╗███████╗██╗███████╗
 ██║ ██╔╝██╔════╝██║██╔════╝
 █████╔╝ ███████╗██║█████╗
 ██╔═██╗ ╚════██║██║██╔══╝
 ██║  ██╗███████║██║██║
 ╚═╝  ╚═╝╚══════╝╚═╝╚═╝
"""
ASCII_BANNER = r"""
 _  __ ____  ___ _____
| |/ // ___||_ _|  ___|
| ' / \___ \ | || |_
| . \  ___) || ||  _|
|_|\_\|____/|___|_|
"""
TAGLINE = "Kali Security Intelligence Framework"
LEVEL_STYLE = {
    Intrusiveness.PASSIVE: "ksif.passive",
    Intrusiveness.ACTIVE: "ksif.active",
    Intrusiveness.INTRUSIVE: "ksif.err",
}
