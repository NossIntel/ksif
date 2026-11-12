#!/usr/bin/env bash
# Report which external tools KSIF can use. Never fails: missing tools only
# disable the actions that need them.
set -u

TOOLS=(nmap arp-scan masscan tshark)

version_of() {
    case "$1" in
        tshark) "$1" -v 2>&1 | head -n 1 ;;
        *) "$1" --version 2>&1 | grep -m1 -E '[0-9]+\.[0-9]+' ;;
    esac
}

printf '%-12s %-9s %s\n' "TOOL" "STATUS" "VERSION"
missing=0
for tool in "${TOOLS[@]}"; do
    if command -v "$tool" >/dev/null 2>&1; then
        printf '%-12s %-9s %s\n' "$tool" "ok" "$(version_of "$tool" | cut -c1-60)"
    else
        printf '%-12s %-9s %s\n' "$tool" "missing" "sudo apt install $tool"
        missing=$((missing + 1))
    fi
done

if command -v python3 >/dev/null 2>&1; then
    printf '%-12s %-9s %s\n' "python3" "ok" "$(python3 --version 2>&1)"
else
    printf '%-12s %-9s %s\n' "python3" "missing" "sudo apt install python3"
fi

echo
if [ "$missing" -gt 0 ]; then
    echo "$missing tool(s) missing: the related actions will show as unavailable."
else
    echo "All external tools found."
fi
exit 0
