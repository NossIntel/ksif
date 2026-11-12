# Contributing

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m pytest
```

Unit tests run on any OS. Integration tests need the real tools:

```bash
.venv/bin/python -m pytest -m integration -v   # targets loopback only
```

## Rules

1. **Processes** are started only through `SubprocessManager`. A test fails
   the build if `subprocess`, `os.system` or `shell=True` appears elsewhere.
2. **Arguments** are built by typed functions in `integrations/`. Never accept
   free-form flags; validate every value with `core/validator.py`.
3. **Targets** always go through `Engine.execute`, so the scope check cannot
   be skipped.
4. **Parsers** raise `ParseError` on incomplete output. Never return partial
   results as if they were complete.
5. **No simulated features.** An integration must detect the tool, really run
   it in `self_test`, and parse its real output. Add a fixture in the tool's
   real format and an integration test.
6. **Interface and logic stay separate.** Modules do not print; `ui/` does not
   decide.
7. Type hints and docstrings on public functions. No credentials in code.
8. Every change comes with tests, and `pytest` must pass.

See [docs/architecture.md](docs/architecture.md) for how to add a module, and
[SECURITY.md](SECURITY.md) for what will not be accepted.

## Commits and pull requests

Small, focused commits with a clear message (`feat:`, `fix:`, `docs:`,
`test:`, `chore:`). In the pull request, say what you verified and how,
including anything you could not test.
