# Security Policy

## Official Distribution

**The only official source of SlimBrave Neo is this GitHub repository:**

> https://github.com/ChaoticSi1ence/SlimBrave-Neo

Any other website, repository, installer, executable, or download link claiming
to be SlimBrave Neo is **not affiliated with this project**. If you found a copy
elsewhere, do not trust it.

### What "official" looks like

The real project ships **source code only** — no compiled binaries, no
installers, no executables. Every entry point is a human-readable script you
can read before running:

| Platform | File | Type |
|----------|------|------|
| Linux    | `slimbrave-linux.py` | Python 3 (stdlib only) |
| macOS    | `slimbrave-mac.py`   | Python 3 (stdlib only) |
| Windows  | `SlimBrave.ps1`      | PowerShell |

The `Presets/` directory contains JSON configuration files. The repository also
contains `tests/`, `.github/`, `ruff.toml`, and `assets/` — none of which
execute on your machine. The three scripts above are the only code that runs
locally.

### What official does *not* include

- **No `.exe`, `.msi`, `.pkg`, `.deb`, `.rpm`, `.AppImage`, or `.dmg` installer.**
- **No precompiled binary of any kind.** The project has zero dependencies and
  does not need to be compiled.
- **No browser extension.**
- **No standalone website** outside this GitHub repo.

If someone offers you a "SlimBrave" installer, executable, or signed binary,
**it is not from this project**. Report it and do not run it.

### How to verify you're running an authentic copy

Use one of these two methods:

1. **Clone the repo directly:**

   ```
   git clone https://github.com/ChaoticSi1ence/SlimBrave-Neo.git
   ```

2. **Or download a script directly from the raw URL on `github.com`:**

   ```
   https://raw.githubusercontent.com/ChaoticSi1ence/SlimBrave-Neo/main/slimbrave-linux.py
   https://raw.githubusercontent.com/ChaoticSi1ence/SlimBrave-Neo/main/slimbrave-mac.py
   https://raw.githubusercontent.com/ChaoticSi1ence/SlimBrave-Neo/main/SlimBrave.ps1
   ```

The URL bar must show `github.com/ChaoticSi1ence/SlimBrave-Neo` or
`raw.githubusercontent.com/ChaoticSi1ence/SlimBrave-Neo`. Anything else is not
from this project.

### Release integrity: checksums and signed tags

Both methods above prove *where* a file came from, not *what* it is. `main` is
a moving branch — a fetch from `.../main/SlimBrave.ps1` returns whatever was
merged minutes ago, and no checksum can cover a target that changes. For a
copy you can actually verify, use a release tag.

**Project policy, from v1.9.5 onward:**

- **Tag signing is not yet in place.** There is no maintainer signing key
  published today, so do not expect `git verify-tag` to succeed and do not
  treat an unsigned tag as evidence of tampering. This section will be
  updated with the key fingerprint if and when signing is set up; until
  then the SHA-256 sums below are the integrity check this project
  actually offers.

- **Each release publishes SHA-256 sums** for all three scripts, in the
  release notes and as a `SHA256SUMS` file attached to that release. Compute
  them locally and compare:

  ```powershell
  Get-FileHash -Algorithm SHA256 .\SlimBrave.ps1
  ```

  ```
  sha256sum slimbrave-linux.py            # Linux
  shasum -a 256 slimbrave-mac.py          # macOS
  ```

If the sums do not match, do not run the script — re-download from a tag and
check again, and if it still differs, report it (see below).

**Maintainer checklist at release time** — the sums are only worth anything if
this is done every time:

1. Tag the reviewed commit with `git tag -a vX.Y.Z` (use `-s` once a signing
   key exists) and push the tag.
2. Generate the sums from a clean checkout **of that tag**, not from a working
   tree: `sha256sum SlimBrave.ps1 slimbrave-linux.py slimbrave-mac.py > SHA256SUMS`.
3. Paste the sums into the release notes and attach `SHA256SUMS`.
4. Never move or re-cut a published tag. If a release is bad, yank it and cut
   a new version.

---

## What this tool does with elevated privileges

SlimBrave Neo writes **managed enterprise policy** — machine-wide settings
Brave reads at startup. Writing those requires Administrator on Windows and
root (`sudo`) on Linux/macOS, so the tool asks for elevation and you should
know exactly what it does with it.

What it never does, on any platform: it makes **no network connections** (the
scripts import no HTTP client and shell out to no downloader), installs no
service, daemon, scheduled task, launch agent or startup entry, runs nothing in
the background after it exits, and touches no path outside the ones listed
below. Every write is either a policy location, the Shields-exception scrub
described under each platform, or the JSON config file you pick yourself in the
Import/Export dialog (`--import` / `--export` on Linux and macOS).

### Windows — `SlimBrave.ps1`

The script self-elevates by relaunching itself through UAC (`Start-Process
-Verb RunAs`). Declining the prompt changes nothing. If you were prompted for
separate admin credentials, the relaunch forwards your own profile path and SID
so the per-user cleanup below still targets *your* account and not the admin's.

It writes to exactly three places:

| Location | What happens there |
|----------|--------------------|
| `HKLM:\SOFTWARE\Policies\BraveSoftware\Brave` | One value per ticked option (or one numbered subkey for list policies), plus `DnsOverHttpsMode` / `DnsOverHttpsTemplates`. Created only when you press Apply — opening the app writes nothing. |
| `HKCU:\SOFTWARE\Policies\BraveSoftware\Brave` (or `HKEY_USERS\<your SID>\...` when elevated as another account) | Values are only **removed** here, never written, so a leftover user-scope policy cannot override the machine one. |
| `%LOCALAPPDATA%\BraveSoftware\<channel>\User Data\<profile>\Preferences`, for **every interactive account on the machine** | Only the `profile.content_settings.exceptions.braveShields` entries for `http://*,*` and `https://*,*` are deleted. Nothing else in the file is read back out or changed. Covers Stable/Beta/Nightly/Dev and every profile (`Default`, `Profile 1`, ...). The policy this tool writes is machine-wide, so the scrub follows it: your own profile root plus every other interactive account (`S-1-5-21-*` in the ProfileList registry key) whose Brave data is readable; the status line says when other users' profiles were cleaned. Skipped entirely while Brave is running, because Brave would overwrite the file on its next save. |

Those Shields entries are a leak from **pre-1.x SlimBrave**, which wrote
content-setting exceptions straight into the profile. Removing the registry
policy does not roll them back, so unchecking "Disable Brave Shields" would
otherwise leave Shields stuck off.

**Reset is scoped to this tool's own keys.** It removes only the policy names
SlimBrave Neo manages, in both scopes, and the two DNS values. It does not
delete the `...\Policies\BraveSoftware\Brave` key itself and does not touch
other values inside it — a group-policy `ExtensionInstallForcelist`,
`URLBlocklist`, `ProxySettings` or anything another tool set survives.

Reset clears the managed **values** outright; that is what a reset is for. Both
Reset and Apply are stricter about **list** policies: one is removed only when
the list on disk is byte-for-byte the one SlimBrave writes, so an
`ExtensionInstallBlocklist` an admin or a GPO owns is left in place and both
actions report how many they skipped.

### Linux — `slimbrave-linux.py`

Root is needed for one file: `/etc/brave/policies/managed/slimbrave.json`
(mode `0644`, written atomically). That single file is the entire policy
footprint — every Brave channel reads it, because brave-core hardcodes the
directory. `--policy-file` can point elsewhere, but only inside
`/etc/brave/policies/managed` or `/etc/chromium/policies/managed`; anything
else is refused.

The Shields-exception scrub runs over
`~/.config/BraveSoftware/<channel>/<profile>/Preferences` for the invoking
user (resolved from `SUDO_USER`, not from root's home), plus the Flatpak
profile under `~/.var/app/com.brave.Browser` when present. It is done in a
forked child that drops to that user's uid/gid first, so root never follows a
path component inside someone's home directory.

`--reset` unlinks the policy file it wrote. Nothing else in
`/etc/brave/policies/managed` is touched.

### macOS — `slimbrave-mac.py`

Root writes `/Library/Managed Preferences/com.brave.Browser.plist`, and the
matching `com.brave.Browser.beta` / `com.brave.Browser.nightly` plists for
whichever channels you select. `--policy-file` can only target
`/Library/Managed Preferences` or `/Library/Preferences`; anything else is
refused.

With `--persist on`, the policy is instead delivered as a **Configuration
Profile** (identifier `io.github.slimbrave-neo.brave-policy`) — Apple's
supported path, because macOS 13+ can clear directly-written managed plists at
reboot. The profile is staged into a private per-run `0700` temp directory and
handed to System Settings; **you approve the install yourself** in Device
Management. The tool also runs `killall cfprefsd` so the new values are picked
up without a reboot.

The Shields-exception scrub is the same as Linux, over
`~/Library/Application Support/BraveSoftware/<channel>/<profile>/Preferences`,
with the same privilege drop.

`--reset` removes the plists it wrote and removes the Configuration Profile by
identifier. No other managed preference is touched.

### How to undo everything

| Platform | Undo |
|----------|------|
| Windows  | Run the script and press **Reset**. |
| Linux    | `sudo python3 slimbrave-linux.py --reset` — or just `sudo rm /etc/brave/policies/managed/slimbrave.json`. |
| macOS    | `sudo python3 slimbrave-mac.py --reset`. If a Configuration Profile was installed, it can also be removed by hand in System Settings → General → Device Management. |

Then restart Brave and check `brave://policy` — none of the keys the tool
manages should still be listed. On Linux and macOS the Shields-exception scrub
happens on reset too; on Windows it happens unless Brave is running, in which
case the status bar at the bottom of the window tells you to close Brave and
reset again.

---

## Reporting a Vulnerability

If you believe you have found a security issue in SlimBrave Neo, please report
it privately rather than opening a public issue.

Use GitHub's **Private Vulnerability Reporting**:
https://github.com/ChaoticSi1ence/SlimBrave-Neo/security/advisories/new

Please include:

- The affected file and, if possible, a line number
- A description of the impact
- Steps to reproduce, or proof-of-concept if you have one

I'll acknowledge the report within a reasonable window and work with you on a
fix and disclosure timeline.

---

## Reporting Impersonation

If you find a repository, website, or download that is pretending to be
SlimBrave Neo, please report it so other users aren't misled:

- Open an issue on this repo (public is fine for impersonation reports —
  these are not vulnerabilities in the code)
- Or email/DM via the contact listed on the ChaoticSi1ence GitHub profile

Useful information to include: the URL, a screenshot, and how you found it
(e.g. a specific Google search). Search-ranking abuse is the most common
pattern, so knowing the query helps.
