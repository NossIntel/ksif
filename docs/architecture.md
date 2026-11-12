# Architecture

## Layers

```
ui/            Rich terminal interface. Presentation only.
   │  calls
core/engine    Operation lifecycle and security policy.
   │  runs
modules/       Domain logic: orchestrates integrations, returns typed results.
   │  uses
integrations/  One file per tool: command builders + output parsers.
   │  executes through
core/subprocess_manager   The only place that starts a process.
```

A layer only talks to the one below it. The interface never builds a command;
a module never prints; an integration never decides whether a target is
allowed.

## Core

| File | Responsibility |
|---|---|
| `core/validator.py` | Parses and normalizes targets, ports, interfaces. Rejects anything that starts with `-` or contains whitespace, control characters or shell syntax. |
| `core/config.py` | Loads `settings.yaml` and `scope.yaml`. Scope loading never raises: bad entries are dropped and reported. |
| `core/permissions.py` | `ScopeGuard.authorize(target, intrusiveness)` returns an `Authorization` or raises. |
| `core/subprocess_manager.py` | Starts processes with `exec` (no shell), from `ALLOWED_BINARIES`, only with an `Authorization` whose target appears verbatim in the arguments. |
| `core/logger.py` | JSON Lines application log and the audit trail. |
| `core/database.py` | SQLite access and versioned migrations (`core/migrations/NNN_*.sql`). |
| `core/engine.py` | Action registry and `Engine.execute`. |

## Life of an operation

1. The interface calls `engine.execute(action_id, raw_target, params, confirm=…)`.
2. The target is validated and its kind checked against the action.
3. `ScopeGuard` checks mode and allowlist. A domain used actively is resolved
   and every resolved address must be in scope.
4. Required tools and root privileges are checked.
5. The operator confirms (active: `y/N`; intrusive: retype the target).
6. The rate limiter waits if needed.
7. The handler builds arguments through an integration, runs the tool, saves
   the raw output under `logs/raw/`, and parses it.
8. Hosts and findings are stored in one transaction and the operation is
   closed as `completed`.

Any refusal in steps 2–5 is stored as a `blocked` operation with an audit
event, and no process is started. Any exception in step 7 closes the operation
as `failed`; nothing partial is stored, and the raw output stays on disk.

## Data

SQLite, one file. Main tables: `operations`, `audit_log`, `hosts`, `ports`,
`host_sightings`, `findings`, `vulnerabilities`, `osint_records`,
`wifi_networks`, `reports`. Every result row points to the operation that
produced it.

## Adding a module

1. Add integrations under `integrations/` by subclassing `ToolIntegration`
   (`binary`, `install_hint`, `version_pattern`, typed argument builders, a
   parser that raises `ParseError` on incomplete output).
2. Add the binary to `ALLOWED_BINARIES` and the class to
   `integrations/registry.py`.
3. Create `modules/<name>/actions.py` with async handlers and a
   `register(engine)` function, and list it in `MODULES` in `main.py`.
4. Use the module key from `ui/app.py:MAIN_MENU`; the menu picks up the
   actions automatically.

Handlers receive an `ActionContext` and must run tools only through
`ctx.runner.run(..., authorization=ctx.authorization)`.
