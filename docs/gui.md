# Graphical interface and the Windows executable

KSIF has a Tkinter desktop GUI over the same engine as the terminal UI. Every
operation still goes through `Engine.execute`, so the scope allowlist, the
passive/active mode and the confirmation prompts behave exactly as in the TUI.

## Run from source

```bash
python gui.py
```

Tkinter ships with Python, so no extra package is required for the GUI itself
(the `rich`/`pyyaml` runtime dependencies still apply).

## Layout

- **Header:** operator, mode, engagement and scope size, with buttons to toggle
  mode, reload the scope, run the tool check, generate a report and view the
  inventory.
- **Modules / Actions:** pick a module on the left, then an action. The action's
  intrusiveness and availability (e.g. `missing tool: nmap`) are shown.
- **Target and parameters:** a target field (with a *Browse* button for file
  actions) and one field per parameter.
- **Live log and Results:** the tool's output streams into the log while it
  runs; the parsed result (hosts, findings, vulnerabilities, Wi-Fi networks)
  appears below, colour-coded by severity.

Actions run one at a time in a worker thread, so the window stays responsive.
Confirmation and consent prompts appear as dialogs.

## Build a standalone executable

```bash
python scripts/build_exe.py            # windowed GUI build
python scripts/build_exe.py --console  # keep a console for debugging
```

This uses PyInstaller to produce `dist/KSIF` (`dist/KSIF.exe` on Windows), a
single file that bundles every Python dependency. It installs PyInstaller
automatically if it is missing.

On first launch the executable creates `config/`, `database/`, `logs/` and
`reports/` next to itself, exactly like running from source. Edit
`config/scope.yaml` beside the executable before running active operations.

### What the executable does and does not contain

- **Bundled:** the Python runtime, `rich`, `pyyaml`, KSIF itself and all its
  modules. Nothing needs to be installed or downloaded to open the GUI.
- **Not bundled:** the external security tools (nmap, nuclei, nmcli, john, …).
  They are Linux tools, detected at runtime. On Windows the GUI opens and the
  offline features work (password strength, report generation, inventory), but
  network/Wi-Fi/web actions that need those tools show as unavailable. Run KSIF
  on Kali Linux for full function.

### Platform note

Build the executable on the platform you will run it on: a Windows build
produces a `.exe` for Windows, a Linux build produces a Linux binary. The CI
`windows-build` job produces a Windows `KSIF.exe` artifact on every push.
