# Security Policy

## Intended use

KSIF is for assessing systems you own or are explicitly authorized to assess.
Unauthorized scanning may be illegal where you live. The allowlist reduces
mistakes; it does not make an unauthorized assessment acceptable.

## Guarantees the code is built to keep

- No operation runs against a target outside `config/scope.yaml`.
- No process is started through a shell, and only binaries in
  `core/subprocess_manager.ALLOWED_BINARIES` can be started.
- User input never becomes a command-line option.
- Every executed command is recorded in the audit trail.
- No credentials are stored in the code. Nothing is sent to third parties.

A way to break any of these is a vulnerability.

## Reporting a vulnerability

Please do not open a public issue. Use the repository's **Security → Report a
vulnerability** (private advisory) and include the version, steps to
reproduce, and the impact. You should get a first answer within 7 days.

## Out of scope for contributions

Pull requests adding capabilities whose main use is attacking third parties
will not be merged. Examples: denial of service, deauthentication or other
interference with networks, online credential guessing against services or
accounts, exploitation or post-exploitation, and anything meant to evade
detection.

## Data on disk

`database/`, `logs/` and `reports/` contain details about the assessed
environment. They are excluded from git; protect and delete them according to
your engagement rules.
