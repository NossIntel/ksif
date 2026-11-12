# Module 05 — Password Security Lab

Everything here is **offline** and limited to material you control. KSIF performs
no online password attack against any service, network or account. There is no
Hydra/Medusa-style tool; the only hash tool is John the Ripper, used to audit
the strength of hashes you own.

## Actions

| Action | Target | Tool | What it does |
|---|---|---|---|
| Analyse one password | (typed) | — | Entropy, character classes, weak-pattern check |
| Audit a password list | file | — | Policy statistics for a list you own |
| Check against a compromised list | file | — | Match your passwords against a local breach list |
| Audit your own hashes | file | john | Offline dictionary audit of hashes you own |

Each action except "Analyse one password" asks you to confirm that you own, or
are authorized to audit, the material.

## Strength analysis

Pure-Python: estimates entropy from length and character variety, and downgrades
the verdict for well-known weak patterns (common passwords, single repeated
character, keyboard/alphabet sequences, all digits, single character class).
Passwords you type are never stored; list statistics use masked labels (first
character + length), never the full password.

## Hash auditing (john)

You provide a hash file and a wordlist:

```
john --wordlist=<wordlist> [--format=<fmt>] <hashfile>
john --show [--format=<fmt>] <hashfile>
```

KSIF reports how many hashes were recovered from the wordlist — a measure of how
weak they are — and recommends resets and a slow hash (bcrypt/argon2) if many
fall. This is a strength-auditing use of your own hashes; it is not an attack on
a third party.

## Not included

No online/network password guessing, no attacks against services or accounts,
and no cracking of material you do not own.
