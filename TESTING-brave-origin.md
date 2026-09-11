# Testing the Brave Origin branch

Checklist for finishing the verification of `brave-origin-detection` (PR #25)
before it merges. Tick a box, note the machine, keep the output if it differs
from what is written here. Linux only; the Windows script is untouched.

Every check below runs the scripts from a clone of this branch:

```bash
git clone -b brave-origin-detection https://github.com/ChaoticSi1ence/SlimBrave-Neo.git
cd SlimBrave-Neo
```

Root is `sudo python3 …` on most systems. On a polkit-only box (CachyOS with
no sudo password) use `pkexec env SUDO_USER=$USER python3 …` — the scripts
find your home through `SUDO_USER`.

## Already verified

| Check | Where | Result |
|---|---|---|
| Origin reads `/etc/brave/policies/managed` | CachyOS, `brave-origin-bin 1.94.121` | source (`brave_main_delegate.cc`, no branding guard), binary strings, inotify watches on the directory, `chrome://policy` listing every imported key as Platform / Machine / Mandatory / OK |
| deb and rpm layout | artifacts of v1.94.121, unpacked with bsdtar | `/opt/brave.com/brave-origin/{brave,brave-origin}`, `/usr/bin/brave-origin-stable`, bare `brave-origin` via update-alternatives; binary byte-identical to the AUR one |
| No Flatpak or Snap of Origin | Flathub and Snap store APIs, `flathub/com.brave.Browser`, the `brave` snap squashfs | only `com.brave.Browser` and `brave`, both regular Brave |
| Detection, import, export, reset, TUI | CachyOS, Origin only | see the expected strings below; all matched |
| Unit tests | this branch | 489 pass, ruff clean; CI runs them on Ubuntu, macOS and Windows |

## Quick detection probe, no root needed

Prints what the detector sees on any box. Run it first on every machine.

```bash
python3 - <<'EOF'
import importlib.util, json
spec = importlib.util.spec_from_file_location("m", "slimbrave-linux.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
info = m.detect_brave()
print(json.dumps({k: v for k, v in info.items() if k != "installations"}, indent=1))
for i in info["installations"]:
    print(i["channel"], "|", i["app_path"], "|", i["prefs_path"], "| origin_only =", i["origin_only"])
EOF
```

## Expected strings

Launch note, Origin the only Brave on the machine:

    Brave Origin found: policies apply; rows for features it removes are inert.

Launch note, Origin beside a regular Brave:

    Origin beside Brave: one policy file serves both; every row stays live.

Import of `Presets/Brave Origin Preset.json` on an Origin-only machine:

    Imported from …/Brave Origin Preset.json; 13 keys built into Brave Origin left unmanaged
    Settings applied to Origin. Restart Brave to see changes.

and `/etc/brave/policies/managed/slimbrave.json` holds exactly two keys,
`BraveP3AEnabled` and `BraveStatsPingEnabled`, both `false`.

Export while that file holds a key Origin compiles out (only reachable with a
file written earlier beside a regular Brave):

    Note: N keys built into Brave Origin left out of the export

Reset:

    Removed /etc/brave/policies/managed/slimbrave.json (Origin)

TUI, Origin only: title `[arch (Brave Origin)]`, `[deb/rpm (Brave Origin)]` or
`[unknown (Brave Origin)]`; Brave Features header `0/3 on`; twelve rows there
and Wayback Machine under Performance & Bloat drawn as
`[-] Disable Brave Rewards (built into Origin)`, dimmed; Space on one does
nothing; the description pane starts with `Built into Brave Origin:`.

TUI, mixed: title `[arch: Stable, Origin]` or `[deb/rpm: Stable, Origin]`;
Brave Features `0/15 on`; no `[-]` anywhere.

## To do: one machine per row

### Debian / Ubuntu, `brave-origin` deb, Origin only

- [ ] `sudo apt install brave-origin` per brave.com/origin/linux, never install `brave-browser`.
- [ ] Probe: `method` is `deb/rpm (Brave Origin)`, `path` is `/opt/brave.com/brave-origin/brave-origin`, one installation `origin`, `origin_only = True`, `warnings` empty, the Origin-only note.
- [ ] `sudo python3 slimbrave-linux.py --import "Presets/Brave Origin Preset.json"` prints the import strings above and writes the two-key file.
- [ ] Start Origin, open `brave://policy`, press Reload policies: both keys listed, source Platform, status OK.
- [ ] TUI as root shows the Origin-only frame described above. `q` to quit.
- [ ] `sudo python3 slimbrave-linux.py --reset` prints the reset string; the file is gone.
- [ ] Running check: with Origin open, `--import` again ends with `Brave is running: …`. Origin's launcher there is `brave-origin-stable`, whose comm truncates to `brave-origin-st`; the profile's SingletonLock is what should catch it.

### Fedora or openSUSE, `brave-origin` rpm, Origin only

- [ ] Same steps as the deb row. The rpm's `%post` makes `/usr/bin/brave-origin` an update-alternatives link; if a distro ships without `update-alternatives`, `which brave-origin` fails but `/opt/brave.com/brave-origin/brave-origin` is still probed, so detection must still say `deb/rpm (Brave Origin)`.

### Mixed machine, regular Brave and Origin side by side

Any of: Arch `brave-bin` + `brave-origin-bin`; deb `brave-browser` + `brave-origin`; Flatpak `com.brave.Browser` + native Origin.

- [ ] Probe: two installations, `stable` first, `origin_only = False` on both, the mixed note.
- [ ] Do this once with regular Brave installed but **never launched** (no `~/.config/BraveSoftware/Brave-Browser`): the `stable` record must still be there.
- [ ] `sudo python3 slimbrave-linux.py --channels origin --import "Presets/Brave Origin Preset.json"`: the file must hold all fifteen keys, no `built into` message. Narrowing with `--channels` must not drop keys regular Brave reads.
- [ ] TUI shows the mixed frame, every row live.
- [ ] Open `brave://policy` in **both** browsers after the import: both list the keys.

### Origin beta or nightly, alone

`sudo apt install brave-origin-beta` (or `-nightly`), or AUR `brave-origin-beta-bin`.

- [ ] Probe: `method` is `unknown (Brave Origin)` (the launcher on `PATH`), one installation `origin-beta` or `origin-nightly` with `prefs_path` under `Brave-Origin-Beta` or `Brave-Origin-Nightly`, `origin_only = True`, `warnings` empty.
- [ ] `--channels origin-beta --import …` works and the rows are inert in the TUI.

### Regular Brave only, no Origin anywhere — regression

One each of Arch `brave-bin`, deb `brave-browser`, Flatpak, Snap.

- [ ] Probe output is identical to `main` for the same machine: same `method`, same `path`, `notes` is `[]`, and `origin_only = False` is the only new field.
- [ ] TUI is identical to `main`: Brave Features `0/15 on`, no `[-]`, no note on the status line.
- [ ] Import of the Brave Origin preset writes all fifteen keys, no `built into` message.

### `--policy-file` override on an Origin-only machine

- [ ] `sudo python3 slimbrave-linux.py --policy-file /etc/brave/policies/managed/test.json`: every row live, no note on the status line, title `[policy-file override]`. Reset the same way afterwards.

### `slimbrave-mac.py` on Linux

It carries the same code and runs on Linux.

- [ ] Repeat the probe with `slimbrave-mac.py` in place of `slimbrave-linux.py` on any Origin box: same output.

### CI

- [ ] PR #25 checks green: pytest + ruff on the three runners, the TUI smoke test on Ubuntu and macOS, PSScriptAnalyzer.

## When everything above is ticked

Delete this file in the merge commit, or keep it as `docs/` if the checklist
is worth re-running on the next Origin release. The `is_brave_origin_branded`
guards in brave-core's `.gni` files are the trigger for re-checking the
thirteen-key list; `PsstEnabled` joins it the day the project exposes that key.
