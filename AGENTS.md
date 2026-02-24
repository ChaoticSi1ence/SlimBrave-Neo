# AGENTS.md — SlimBrave

## Project Overview

SlimBrave is a Brave Browser debloater with two platform implementations:

- **Windows:** `SlimBrave.ps1` — PowerShell GUI that sets registry policies
- **Linux:** `slimbrave.py` — Python 3 curses TUI that writes JSON policies to `/etc/brave/policies/managed/`

The Python version is the primary focus of this document. It uses **only the
Python standard library** (no third-party dependencies). It requires root
privileges to write Chromium enterprise policy files.

## Repository Structure

```
SlimBrave.ps1          # Windows PowerShell GUI (main branch)
slimbrave.py           # Linux Python 3 curses TUI (add-linux-tui branch)
Presets/*.json         # Shared preset configs (policy key lists + DnsMode)
```

## Running the Application

```bash
sudo python3 slimbrave.py                        # interactive TUI
sudo python3 slimbrave.py --import preset.json   # CLI: import & apply
sudo python3 slimbrave.py --export out.json      # CLI: export current policy
sudo python3 slimbrave.py --reset                # CLI: delete policy file
sudo python3 slimbrave.py --policy-file /path    # override policy file path
sudo python3 slimbrave.py --import p.json --doh-templates URL  # custom DoH
```

- Requires **root** (`os.geteuid() == 0`). The script exits with an error if
  not run as root.
- Policies are written to `/etc/brave/policies/managed/slimbrave.json`.
- After applying, restart Brave and verify at `brave://policy`.
- The TUI auto-detects Brave installations (Arch, deb/rpm, Flatpak, Snap,
  PATH fallback) and warns if Brave is not found.
- CLI flags (`--import`, `--export`, `--reset`) run non-interactively and exit.
  No flags launches the interactive curses TUI.

## Build, Lint, and Test Commands

There is no build step or formal test suite. The project is a single-file
Python script with stdlib-only dependencies.

### Syntax check

```bash
python3 -m py_compile slimbrave.py
```

### Linting (not currently configured, but recommended)

```bash
ruff check slimbrave.py            # preferred
flake8 slimbrave.py --max-line-length 100
```

### Running a single test

No test framework is set up. If tests are added, use `pytest`:

```bash
pytest                                      # all tests
pytest tests/test_policy.py                 # single file
pytest tests/test_policy.py::test_apply     # single function
```

### Type checking (not currently configured)

```bash
mypy slimbrave.py
```

## Code Style Guidelines

All conventions below are derived from the existing codebase. Follow them for
consistency.

### Imports

- **Stdlib only.** Do not add third-party dependencies.
- One `import module` per line, alphabetically ordered (no `from` imports).

### Naming Conventions

| Element                | Convention         | Example                                  |
|------------------------|--------------------|------------------------------------------|
| Module-level constants | `UPPER_SNAKE_CASE` | `POLICY_DIR`, `CP_NORMAL`, `ROW_HEADER`  |
| Functions              | `snake_case`       | `detect_brave()`, `apply_policy()`       |
| Local variables        | `snake_case`       | `cursor_pos`, `scroll_offset`            |
| Function parameters    | `snake_case`       | `status_msg`, `btn_idx`                  |

- Functions use the `verb_object` pattern: `load_existing_policy`,
  `sync_rows_with_policy`, `build_rows`.
- Boolean variables: prefer `is_`, `status_ok`, `found` prefixes.

### Formatting

- **Line length:** stay under 100 characters.
- **Indentation:** 4 spaces, no tabs.
- **Strings:** f-strings for interpolation; double quotes preferred.
- **Trailing commas:** used in multi-line collections.
- **Blank lines:** two before top-level functions; one between logical sections
  inside functions.

### Docstrings

- Module-level docstring at the top of the file (triple double-quotes).
- One-line docstrings for functions. Multi-line only for complex functions.

### Type Hints

Not currently used. If adding them, follow PEP 484 style:
`def apply_policy(rows: list[dict]) -> tuple[bool, str]:`

### Error Handling

- I/O functions return `(bool, str)` tuples (success flag + message). Do
  **not** raise exceptions for expected failures.
- Catch `curses.error` silently in drawing code (terminal boundary writes).
- Catch `KeyboardInterrupt` at the top level for clean Ctrl+C exit.
- Catch `FileNotFoundError` when detecting optional tools (e.g., `flatpak`).

### Constants and Data Definitions

- Row types: `ROW_HEADER = 0`, `ROW_FEATURE = 1`, `ROW_DNS = 2`,
  `ROW_DNS_TEMPLATE = 3`.
- Color pair IDs: `CP_NORMAL = 1`, `CP_HEADER = 2`, etc.
- Focus zones: `FOCUS_LIST = 0`, `FOCUS_BUTTONS = 1`, `FOCUS_PROMPT = 2`.
- Feature definitions live in the `CATEGORIES` list. Each category dict has
  `"name"` (str) and `"features"` (list of dicts with `"name"`, `"key"`, and
  `"value"` — the Chromium policy key and its enforcement value).

## Architecture

### Data Flow

1. `CATEGORIES` -> `build_rows()` produces a flat list of displayable rows.
2. `load_existing_policy()` reads the on-disk JSON;
   `sync_rows_with_policy()` pre-checks rows matching existing policy.
3. User toggles features in the curses TUI.
4. `apply_policy()` collects checked rows into a dict and writes the JSON file.
5. `reset_policy()` deletes the policy file and unchecks all rows.
6. `import_settings()` / `export_settings()` handle PS1-compatible JSON
   configs (with BOM/encoding handling for PowerShell exports).

### TUI Layout

- **Line 0:** Title bar with Brave install method indicator.
- **Line 1:** Key hints.
- **Lines 2 to max_y-4:** Scrollable feature list (`^^^`/`vvv` indicators).
- **Line max_y-2:** Button bar (Import, Export, Apply, Reset, Quit).
- **Line max_y-1:** Status line (green = success, red = error) or text
  input prompt (for file paths during import/export).
- Three focus zones (`FOCUS_LIST`, `FOCUS_BUTTONS`, `FOCUS_PROMPT`).

## Adding New Features

1. Add a feature dict to the appropriate category in `CATEGORIES`:
   ```python
   {"name": "Disable New Thing", "key": "ChromiumPolicyKey", "value": False},
   ```
2. The TUI picks it up automatically via `build_rows()` — no GUI code changes.
3. Update `SlimBrave.ps1` to keep platform parity (same key/value).
4. Update affected preset JSON files in `Presets/` if applicable.
5. Use the official Chromium enterprise policy key name. Verify at
   `brave://policy` after applying.

## Platform Parity

- The Python and PowerShell versions must expose the **same set of features**
  using the same Chromium policy keys.
- Preset JSON files are shared. The `"Features"` array contains policy key
  names (strings), not platform-specific values.
- When adding or modifying features, update **both** `slimbrave.py` and
  `SlimBrave.ps1`.
