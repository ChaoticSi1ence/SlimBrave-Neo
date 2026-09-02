# SlimBrave Neo — Fluent GUI (beta)

A rebuilt Windows interface in the visual language of the Windows 11 Settings
app. It manages the same 78 policies as the shipping tool, through the same
enterprise-policy mechanism, and writes to the same place.

This lives on the `experiment/fluent-gui` branch. The released tool
(`SlimBrave.ps1` on `main`) is unchanged and unaffected — run whichever you
prefer, but not both at once.

Still pure PowerShell 5.1 with no dependencies. Every control is drawn by hand
with GDI+, so there is nothing to install.

## Try it

```powershell
git clone --branch experiment/fluent-gui https://github.com/ChaoticSi1ence/SlimBrave-Neo.git
cd SlimBrave-Neo\prototypes\fluent
powershell -ExecutionPolicy Bypass -File .\fluent3.ps1
```

No git? Download `fluent3.ps1`, `engine.ps1` and `catalog.json` from this
folder into the same directory and run the last line. All three are required.

It relaunches itself as Administrator — machine policy cannot be written
without it — and opens showing whatever policy is already on the machine.
**Restart Brave after applying**, then check `brave://policy`.

## What is different

**Every policy explains itself.** Each row carries a plain-English description
under its title — *"Stops the daily usage ping that counts this install in
Brave's active-user statistics"* — rather than hiding it in a tooltip. Where
the text is longer than the row, a chevron expands it in place.

**Navigate, or don't.** A sidebar splits the policies into seven categories.
If you would rather not click through them, **All Options** lists all 78 in one
scroll with section headers.

**Presets are cards.** Each shows what it is, who it is for, and how many
policies it sets. Loading one stages the change; nothing is written until you
press Apply.

**Permissions are dropdowns.** The eight site-permission policies offer the
values Chromium actually accepts — *Not managed*, *Ask*, *Block*, and *Allow*
only on the keys where an Allow state exists.

**Clicking a label does nothing.** Only the toggle and the dropdown respond,
each within its own bounds. Opening a menu is reversible; flipping a
machine-wide policy is not.

## What it writes

Exactly what the shipping tool writes, to
`HKLM\SOFTWARE\Policies\BraveSoftware\Brave`, with the same types per policy.

- **Apply** writes the policies you have set and removes the ones you have not.
- **Reset** removes only the keys SlimBrave Neo manages. Policies set by group
  policy or another tool are left alone.
- **Re-sync** re-reads the registry into the interface.
- **Export / Import** use the same JSON format as the released tool, so configs
  move between the two.
- **Secure and custom DNS modes require a valid `https://` template.** Apply
  refuses without one: those modes send DNS over HTTPS only, so a missing or
  malformed resolver means nothing resolves at all, and the setting cannot be
  changed from `brave://settings` because it is machine policy.

## Beta, and what that means

Verified end to end on a real machine — reading live policy, exporting,
resetting and applying all produce correct registry state — but it has not had
the years of use the shipping script has.

Not yet included:

- **No leaked-preference repair.** The released tool scrubs stale Shields
  exceptions that pre-1.x versions wrote into the browser profile. If you have
  used a very old SlimBrave on this machine, run the released `SlimBrave.ps1`
  once to clean those up.
- **No search on the All Options page.**
- Only the Windows GUI is rebuilt; the Linux and macOS TUIs are unchanged.

If something behaves differently from the released tool, that is a bug worth
reporting — please open an issue and mention you were on this branch.
