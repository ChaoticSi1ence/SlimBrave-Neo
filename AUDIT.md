# SlimBrave Neo — Policy Audit and Plan

**Read this first, before any change to this repository.** It is the master
record for the project, written for the AI doing the work (humans read the
README) and enforced by `tests/test_audit.py`. Every policy key the tool writes and the
evidence it is trusted on, what is deliberately left out and why, how each
platform is reached, what Brave Origin changes, what comes next, and the
procedure and commands to re-verify all of it. Rows state what is true of the
shipping Brave at the pins below; the ledger says when each section was last
checked and against what; git history holds everything else.

**How to read a row.** `Status` is the verdict: ✅ dispatched and effective ·
⚠️ dispatched but inert (Considered and rejected only) or platform- or
channel-limited, caveat in the label, or
deprecated upstream yet still applied while its successor does not work in
Brave, caveat in the description · ⛔ deprecated upstream, not exposed · ❌
does not exist · 💀 dead: YAML present, handler gone · 🕓 not yet in a
shipping Brave, watch. A lock-only row (Notes open "lock only") changes
nothing on a default install: it holds a value Brave already uses against
another writer (a settings toggle, Ad Block Only Mode, Sync, an extension, a
stored value or a change of default). Its description names any side
effect, then what Brave already does and what the lock keeps; the label
carries no suffix and presets keep the row. `Min` is the Chromium
milestone from `supported_on`, never a Brave version unless it says
branch-probed. `Dispatch` names what proves the browser reads the key: a
`brave_simple_policy_map.h` entry with its buildflag guard, a handler
brave-core registers in its `chromium_src/` override of the factory (the five
`DefaultBrave*Setting` keys), or the Chromium handler list (`factory` = `configuration_policy_handler_list_factory.cc` plus
a `pref_mapping/<Key>.json` that is not `Policy was removed`). **restart** =
`dynamic_refresh: false`; **browser-wide** = `per_profile: false`. When a row
and the source disagree, the source wins and the row is wrong: fix the row.

**How to update this file.** The H2 section names are the anchors — keep
them. Tables keep their column order; `Status` uses only the six glyphs
above. A pass runs the procedure at the end, fixes rows to match the source,
replaces its rows in the ledger below, and adds one line to the done log with
a tag, PR or commit. Nothing is appended as narrative and no row is marked
stale: a row states the present. Adding a key means, in one change: the four
conditions under "What the project does" met and cited in the row, the row
itself, the three scripts, the presets that want it, the tests, and a done-log
line. Removing a key moves its row to Considered and rejected with the
tiebreaker source and adds the key, with the value SlimBrave wrote, to
`SlimBrave.ps1`'s `$script:retiredPolicies` (the PS1 writes values one by
one; the Python scripts rewrite their whole policy file or profile on
Apply). `tests/test_audit.py` parses this file and fails CI when it
and the scripts disagree — see that section.

**Verification ledger.** Updated in place by each pass — replace the row, do
not append.

| Section | Last verified | Against | Method |
|---|---|---|---|
| Brave-specific keys | 2026-10-24 | brave-core `v1.98.60` (`52db4b25c`), `v1.98.61` (`1535669c4`), `1.99.x` (`22cd59b84`), master (`1e6f00267`); brave-variations `main` (`165f9af46`) | YAML + `brave_simple_policy_map.h` guards resolved through `.gni` + feature defaults and Griffin studies; one auditor per key group, one verifier per group that tried to refute every material finding |
| Chromium-inherited keys | 2026-10-24 | Chromium 156.0.8078.48 (`d0c02bfad08e`), `chromium/main` `7b96745f7dfb` (158.0.8123.0); brave-core `v1.98.60` | YAML + `configuration_policy_handler_list_factory.cc` + `pref_mapping/<Key>.json` at the tag, brave-core `chromium_src/`, `patches/`, `rewrite/`; same auditor and verifier scheme |
| Content-setting enums | 2026-10-24 | Chromium 156.0.8078.48, `chromium/main` `7b96745f7dfb` | schema `items:` of each `Default*Setting` key; `content_settings_registry.cc` `valid_settings`; the three scripts' import tests |
| `HardwareAccelerationModeEnabled` off state | 2026-10-24 | Chromium 156.0.8078.48, `chromium/main` `7b96745f7dfb` | YAML `items:` |
| Platform policy locations | 2026-10-24 (source and binaries); Linux at runtime 2026-09-11 | brave-core `v1.98.60`, Chromium 156.0.8078.48; the 1.98.60 Brave and Origin `win32-x64` zips, the Origin `darwin-x64` zip, the Brave and Origin Linux packages | source chains; binary strings; inotify watches and a policy seen taking effect (2026-09-11, not re-run) |
| Brave Origin on Linux | 2026-10-24 (source and artifacts); runtime 2026-09-11 | brave-core `v1.98.60`, `1.99.x`, master; the 1.98.60 zip, deb and rpm, beta 1.99.44 and nightly 1.100.7 debs; Flathub, Snap store and nixpkgs; a CachyOS install of 1.94.121 | artifacts checked against the GitHub release digests and the apt, rpm and AUR indexes, then unpacked; runtime facts from 2026-09-11 not re-run |
| Considered and rejected | 2026-10-31 (rows added this pass); 2026-10-24 (the rest) | added rows: Chromium 156.0.8078.80 (spot checks at 157.0.8103.30), brave-core `v1.98.64` (overrides spot-checked on `1.99.x`), brave-variations `c73faf3`; the rest as the two key tables | YAML + factory + `pref_mapping/<Key>.json` + brave-core `chromium_src/`, `patches/`, `rewrite/`; one researcher per unit, one reviewer who tried to refute each row, then a red/blue/judge pass |
| Sponsored Ads coverage | 2026-10-24 | brave-core `v1.98.60`, `v1.98.64`, `1.99.x`, `1.100.x`, master; brave-browser#51040, #54917, #57204, #59687; brave-core#35873, #39810, #40173, #40666 (with #40444, #40514, #40532, #40559) | `ads_service_impl.cc`, `view_counter_service.cc`, `brave_settings_ui.cc`, `http_client.cc`, the refreshed NTP panels; source-read, not runtime-tested |
| Ad Block Only Mode provider | 2026-10-24 | brave-core `v1.98.60`, `1.99.x`, master; brave-variations `AdblockOnlyModeStudy` | `ad_block_only_mode_policy_manager.cc`, `features.cc`, `ad_block_component_service_manager.cc`, `policy_map.cc` |

## What the project does

- Writes Chromium and Brave managed policies and, apart from the prefs
  repair below, nothing else: no binary edits, no hosts-file entries, no
  service or flag changes. The rest is delivery plumbing. `SlimBrave.ps1`
  also deletes the user-scope copy
  (`HKU\<SID>` of the invoking user after its elevated relaunch, else `HKCU`)
  of every key it manages, on Apply and Reset; an unticked or reset list
  policy that is not exactly SlimBrave's is left alone in both scopes. Apply
  and Reset also delete, from both scopes, the keys earlier versions wrote and
  this one no longer offers (`$script:retiredPolicies`:
  `AlternateErrorPagesEnabled`, `DNSInterceptionChecksEnabled`,
  `MediaRecommendationsEnabled`, `SafeBrowsingExtendedReportingEnabled`,
  `SafeSitesFilterBehavior`, `ShoppingListEnabled`), each only while it
  still holds the DWORD SlimBrave wrote; the Python scripts rewrite their
  whole policy file or plist, so a retired key goes on the next Apply there. On
  macOS every Apply and Reset first runs `profiles remove` on any installed
  SlimBrave profile and deletes earlier `slimbrave-neo-*` staging dirs; a
  persist-`off` Apply and a Reset then run `killall cfprefsd`; persist `on`
  stages a `.mobileconfig` in a new `slimbrave-neo-*` temp dir and opens
  System Settings for the user to approve it.
- The one write to a file Brave owns is the prefs repair (since v1.4.1,
  `80d461f`, issue #2): every Apply and Reset deletes the `http://*,*` and
  `https://*,*` entries of `profile.content_settings.exceptions.braveShields`
  from each `Default` / `Profile *` `Preferences`. `SlimBrave.ps1` does this
  for every account with Brave data (`ProfileList`, `S-1-5-21-*`) under
  `Brave-Browser{,-Beta,-Nightly,-Dev}`, and not at all while `brave.exe`
  runs; the Python scripts do it only in the invoking user's home
  (`$SUDO_USER`, else `$USER`) for the targeted channels, even while Brave
  runs, with a warning that Brave will overwrite it. These scheme-wide
  exceptions kept Shields off after the Shields list was removed; no
  SlimBrave version writes them itself (see Cross-cutting).
- Three implementations kept in lockstep by tests: `SlimBrave.ps1` (Windows,
  Fluent GUI), `slimbrave-linux.py` (curses TUI), `slimbrave-mac.py` (curses
  TUI; macOS and Linux). Same rows (except as below), in the same order
  within each category (the PS1 GUI puts Shields & Content Protection before
  Brave Features; no test checks category order). Same descriptions: the
  PS1 Tips, held equal by a test; the one variant is the `BraveVPNDisabled`
  row on Linux, which both Python scripts label as having no effect there.
  Same presets: the six `Presets/*.json`, which the PS1 embeds verbatim.
  Import/export files round-trip between all three, with one DoH gap:
  `SlimBrave.ps1` writes and exports a template only with `custom` or
  `secure`, the modes in which every UI enables the template field, but the
  Python scripts also write and export one with `automatic` (`_build_policy`
  and `export_settings` in both). The template can come from an import,
  `--doh-templates`, the policy file read at launch, or text typed under
  `custom`/`secure` before switching mode; their UI then greys the field and
  cannot clear it (What's next). Three exceptions by design:
  `slimbrave-mac.py` on macOS has no `BackgroundModeEnabled` or
  `NetworkServiceSandboxEnabled` row and ignores those keys on import
  without a note; only `SlimBrave.ps1` offers `DynamicCodeSettings`
  (`chrome.win` only), which the Python scripts neither offer nor import,
  also without a note; on a Linux machine whose only Brave is Origin, the
  Python scripts leave the 13 `ORIGIN_BUILTIN_KEYS` unmanaged on import,
  with a note, and out of export.
- **Inventory: 90 rows over 85 distinct keys** (`ChromeVariations`,
  `IncognitoModeAvailability`, `DefaultBraveReferrersSetting`,
  `HardwareAccelerationModeEnabled` and `SafeBrowsingProtectionLevel` have
  two rows each), plus `DnsOverHttpsMode` and `DnsOverHttpsTemplates` from
  the DNS section — 87 keys written, 27 Brave and 60 Chromium
  (`slimbrave-linux.py`). Machines differ: `SlimBrave.ps1` has 91 rows over
  86 keys (88 written), adding the Windows-only `DynamicCodeSettings`;
  `slimbrave-mac.py` on macOS has 88 rows over 83 keys (85 written), since
  `BackgroundModeEnabled` and `NetworkServiceSandboxEnabled` are
  `chrome.win` / `chrome.linux` only; on a Linux machine where every Brave
  found is Origin (and no `--policy-file`), the Python scripts mark the 13
  `ORIGIN_BUILTIN_KEYS` rows inert and write at most 74. Seven categories:
  Telemetry & Reporting, Privacy & Security, Site Permissions, Access
  Controls, Brave Features, Shields & Content Protection, Performance &
  Bloat. Six presets, all derived from the same tables.
- **A key ships only when all four hold:** its YAML exists at the pinned tags
  (Chromium's `policy_definitions/` for Chromium keys, brave-core's
  `BraveSoftware/` for Brave keys; see Sources and pins); the regular
  (non-Origin) Brave build dispatches it on at least one platform the row is
  offered on (a Chromium handler at the Chromium tag, a
  `brave_simple_policy_map.h` entry that is unguarded or whose buildflag is on
  there, or a handler brave-core registers in its `chromium_src/` override of
  `configuration_policy_handler_list_factory.cc`) and accepts it from a
  platform source (no `cloud_only: true` in the YAML and no
  `CloudUserOnlyPolicyChecker` around the handler; see Cross-cutting); the
  value written is a legal schema member meaning what the label says; and
  there is a product reason. Dispatch is not enough: a live reader in the
  regular build must act on the key's value on at least one platform and
  channel the row is offered on. A key no reader acts on anywhere is inert
  (its feature compiled or pinned off on every channel, its reader a helper
  brave-core never runs, or its gate held shut by another policy-only pref at
  its default) and does not ship: it goes to Considered and rejected (⚠️ no-op
  in Brave, or ⚠️ redundant when only another policy could open the gate) with
  the gate as the tiebreaker, and gets a What's next trigger only when that
  gate is a feature or study that could plausibly flip. A `brave://flags`,
  command-line or environment opt-in alone does not make a key live
  (`LaunchOnStartupEnabled`, the Web Bluetooth and File System guards). A
  key live on only some platforms or channels keeps its row, ⚠️ with the
  caveat in its label in every script that offers it there: a map entry
  compiled out of one platform's build (`BraveVPNDisabled` on Linux), or a
  feature off on Release but on by default, in code or by a Griffin study,
  for some Beta or Nightly users (`BravePlaylistEnabled`,
  `BraveLocalAIEnabled`); features Brave Origin compiles out are handled by
  `ORIGIN_BUILTIN_KEYS` instead (see Brave Origin on Linux). A key whose
  reader is live but whose value Brave already uses is a lock: it ships ✅
  (⚠️ if a caveat above also applies), its Notes open "lock only", and its
  description says what it keeps, not what it starts, names what Brave
  already does, and never names a writer SlimBrave's own policies already
  remove. A key that switches off a value users can no longer reach (Brave
  removed the opt-in, but a profile that accepted it earlier keeps it)
  ships and says so: its Notes open "lock with a legacy target" and its
  description names Brave's default and the earlier opt-in it undoes
  (`AccessibilityImageLabelsEnabled`). A key Chromium marks
  `deprecated: true` while its handler
  still applies it and its successor does not yet work in Brave stays,
  marked ⚠️ with the caveat in its description, until the successor works or
  the key stops applying (`AutofillAddressEnabled` and
  `AutofillCreditCardEnabled` at 156; the trigger is in What's next).
  Nothing dead ships — a switch that silently does nothing is worse than no
  switch.
- **This document is enforced.** `tests/test_audit.py` parses the tables here
  and asserts: every key any of the three scripts writes, the
  `SlimBrave.ps1` feature table included, appears in a key table with ✅ or
  ⚠️; nothing in Considered and rejected, and nothing marked ⛔ ❌ 💀 🕓, is
  written by any script; every Considered-and-rejected row names at least
  one key the parser reads; `ORIGIN_BUILTIN_KEYS` in both Python scripts
  equals the set of written Brave keys whose Dispatch is a guarded map entry
  ("map, `ENABLE_…`"), each is named in Brave Origin on Linux, and no
  "map, unguarded" key is in it; the bold rows-over-keys pair above matches
  the feature and choice rows of `slimbrave-linux.py`'s `build_rows()`, and
  the `SlimBrave.ps1` and macOS pairs match the PS1 feature table and
  `slimbrave-mac.py`'s rows on macOS (keys written, categories and presets
  are not asserted); every Status cell uses the vocabulary; every name in
  `SlimBrave.ps1`'s `$script:retiredPolicies`
  is in Considered and rejected, whose row names the value the table
  deletes, and is written by no script; no script labels a row
  "(no effect in Brave)"; every written key whose Notes open "lock only"
  has a description that says what Brave already does; the ledger has rows
  for Brave-specific keys, Chromium-inherited keys, Brave Origin on Linux
  and Considered and rejected,
  and every Last verified cell starts with a `YYYY-MM-DD` date; and the
  document carries no diary markers (stale-as-of stamps, H3 headings that
  open with a year, read-at lines; the exact patterns are in
  `test_no_diary_markers`, and quoting them here would trip it). When it
  fails, the document or the code is wrong — fix whichever disagrees with the
  source.
- Where the policies land:

| Platform | Location | Scope |
|---|---|---|
| Windows | `HKLM\SOFTWARE\Policies\BraveSoftware\Brave` | one key for stable, beta, nightly and Origin — no channel suffix |
| Linux | `/etc/brave/policies/managed/slimbrave.json` | one file for every channel and for Brave Origin |
| macOS | `/Library/Managed Preferences/com.brave.Browser{,.beta,.nightly}.plist`, or a Configuration Profile | one plist or profile payload per selected channel; Brave Origin is a separate app reading `com.brave.Browser.origin{,.beta,.nightly}`, which the tool neither detects nor writes |

## Sources and pins

- **Shipping Brave:** 1.98.60 (Release, 2026-10-21; GitHub's latest release
  and the version the Linux apt index carries for `brave-browser` and
  `brave-origin`) on Chromium **156.0.8078.48** (the tag brave-core
  `v1.98.60`, `52db4b25c`, pins in `package.json:82`; Chromium commit
  `d0c02bfad08e`). `v1.98.61` (2026-10-22), the `1.98.x` head `1535669c4`, is
  a GitHub pre-release on the same Chromium. Chromium policy definitions at
  that tag: tree `65cc5f0`, 1,421 policies (the named ids in `policies.yaml`;
  a file count must skip `.group.details.yaml` and the 36
  `policy_atomic_groups.yaml`). `chromium/main` at `7b96745f7dfb`
  (158.0.8123.0, tree `6178e75`): 1,429 policies, +8/−0 against 156, none
  written by the scripts.
- **Brave policies:** 30 at `v1.98.60` and `v1.98.61`, on `1.99.x`
  (`22cd59b84`) and on master (`1e6f00267`) — the `BraveSoftware/*.yaml` files
  `brave_policies.gni` lists, `.group.details.yaml` not counted, which
  brave-core's `chromium_src/components/policy/resources/policy_templates.py`
  loads from its own tree and merges into Chromium's set
  (`_GetPoliciesAndGroups`, `:23-51`), so they pass the same generator and
  milestone gate (see Version gating); brave-core's `policy_definitions/` tree
  is identical across the four. At the tag each has a handler, subject to its
  row's buildflag: 25 `kBraveSimplePolicyMap` entries
  (`browser/policy/brave_simple_policy_map.h:93-176`; 10 unguarded, 15 under a
  buildflag; `IPFSEnabled`'s is a tombstone) plus the five
  `DefaultBrave*Setting` handlers. 30 on every release branch since `1.94.x`:
  master reverted `BraveSearchResultAdsEnabled` (`cf025361c`) and added
  `PsstEnabled` (`13a8fd8cc`) before `1.95.x` branched, so no branch carries
  both.
- **Branch pins** (`package.json:82`): `v1.94.121` → 152.0.7977.83; `1.95.x`
  (last tag `v1.95.104`) → 153.0.8010.53; `v1.96.59` (`08e68f356`) →
  154.0.8037.58; `1.97.x` (head `545cd6a42` = `v1.97.60`) → 155.0.8059.85,
  every 1.97 Release on 155.0.8059.x (first `v1.97.56` on 155.0.8059.40);
  `v1.98.60`, `v1.98.61` and `1.98.x` → 156.0.8078.48; beta `1.99.x`
  (`22cd59b84` = `v1.99.50`) and master (`1e6f00267`, nightly 1.100.x, past
  tag `v1.100.31`) → 156.0.8078.48 as well. Master moved to 156 at
  `c17642b37`, first tagged as nightly `v1.99.27` (earlier 1.99 nightlies are
  on 155; every 1.100 nightly is on 156), and `1.99.x` branched after it.
  Recent branches were cut a milestone low and upgraded before their first
  Release: `1.94.x` 151→152 (`5d053cbbf`), `1.95.x` 152→153 (`13fb96678`),
  `1.96.x` 153→154 (`ca54d24da`), `1.97.x` 154→155 (`a695c03dd`, #40251),
  `1.98.x` 155→156 (`c124847a3`, #40677).
- **Milestones, not versions.** `supported_on` counts Chromium milestones
  (`cr138`), and the mapping to Brave releases drifts by whole versions:
  `EmailAliasesEnabled` is `chrome.*:147-` yet first ships in Brave 1.92;
  `BraveLocalAIEnabled` is `chrome.*:149-` yet first ships in 1.94;
  `PsstEnabled` is `chrome.*:147-` yet first ships in 1.95. Any Brave
  version in a row label comes from probing the release branches —
  `raw.githubusercontent.com/brave/brave-core/<1.N.x>/components/policy/resources/templates/policy_definitions/BraveSoftware/<Key>.yaml`,
  walking until it stops 404ing — never from milestone arithmetic. Rough
  alignment for orientation only: cr138 ≈ 1.80 … cr156 ≈ 1.98, the milestone
  each minor ships on at Release (minor + 58 for every Release from 1.76 to
  1.98); pre-release pins read low until the branch's upgrade, so beta
  `1.99.x` and master, both on 156 against 157 and 158 at minor + 58, may
  still move.
- **Authorities:** Chromium's `policy_definitions/` YAML and brave-core's
  `BraveSoftware/` YAML for existence and schema (a build's schema holds only
  the keys whose `supported_on` range includes its Chromium milestone; see
  Version gating), a Chromium YAML as amended by brave-core's
  `patches/components-policy-resources-templates-policy_definitions-*.yaml.patch`
  (two at `v1.98.60`, both on written keys and both based on the
  156.0.8078.48 blob: `MetricsReportingEnabled` drops `sensitive: true`,
  `DnsOverHttpsMode` drops `default_for_enterprise_users: 'off'` and the
  managed-devices desc paragraph); `configuration_policy_handler_list_factory.cc`
  and `pref_mapping/<Key>.json` for Chromium dispatch; for Brave dispatch, a
  `brave_simple_policy_map.h` entry or, for the five `DefaultBrave*Setting`
  keys (not in the map, all written), the `browser/policy/handlers/` handler
  that brave-core's
  `chromium_src/chrome/browser/policy/configuration_policy_handler_list_factory.cc:32-36`
  registers; brave-core `chromium_src/`, `patches/` and `rewrite/` for other
  overrides. Source outranks support articles and third-party guides, which
  lag it.

Legend for the tables: **restart** = `dynamic_refresh: false`, the browser must
restart to pick the value up (a row says so when a key's reader applies it
live anyway); **browser-wide** = `per_profile: false`; a `Min`
of `—` means the milestone was not recorded here — read it from the YAML.

## Brave-specific keys

| Key | Status | Min | Type | Dispatch | Notes |
|---|---|---|---|---|---|
| BraveP3AEnabled | ✅ | cr138 | bool | map, unguarded | unset = enabled (the Origin-branded build registers the pref `false`, `components/p3a/p3a_service.cc:96-97`); restart per YAML (`brave://policy` flags a changed value "restart required", the only use Chromium makes of `dynamic_refresh`, `components/policy/core/browser/policy_conversions_client.cc:333-360` at 156.0.8078.48), but applies live: `P3AService` watches `brave.p3a.enabled` and starts or stops reporting (`components/p3a/p3a_service.cc:195-200,289-299`); browser-wide. Also stops P3A's copy of the stats ping's search counts (`Brave.Search.SERP*`, see BraveStatsPingEnabled). Stops the upload, not collection: like the other misc metrics (`browser/misc_metrics/process_misc_metrics.cc:42-63` at `v1.98.64`), two collectors that Griffin turns on for 100% of desktop Release, Beta and Nightly (brave-variations `c73faf3`) keep running with `false`: CAPTCHA counts (`Brave.CaptchaCount.*`, `CaptchaMetricsCollectionStudy`, 1.97.49 and later; `process_misc_metrics.cc:55-56`) and a fingerprint-stability probe that every 10 h loads `brave://version` in a hidden tab and hashes the browser's own canvas, font, WebGL and similar inputs into Local State (`Brave.Shields.FPInput.*`, `FingerprintInputMetrics`; `browser/misc_metrics/profile_misc_metrics_service.cc:76-79`, `fingerprint_frequency_metrics.cc:159-173`). Both features are off in code (`components/misc_metrics/features.cc:13,15`) and neither study sets `policy_restriction`, so either `ChromeVariations` row keeps both from being built |
| BraveStatsPingEnabled | ✅ | cr138 | bool | map, unguarded | unset = enabled; restart per YAML, but every reader checks the pref when it acts, so a change applies live; browser-wide. The pref (`brave.stats.reporting_enabled`) also stops SERP-metrics collection (`browser/serp_metrics/serp_metrics_tab_helper.cc:115-117`), whose search counts the ping carries, and referral initialization and finalization (`components/brave_referrals/browser/brave_referrals_service.cc:471-480,535-543`). P3A carries a bucketed copy of the search counts (`Brave.Search.SERP*`, `browser/serp_metrics/serp_metrics_p3a.cc:83-103`); with collection off it still sends `SERPBrave` = 0 daily until `BraveP3AEnabled` stops P3A |
| BraveGlobalPrivacyControlEnabled | ✅ | cr142 | bool | map, unguarded | lock only — dynamic refresh; unset = enabled, no Settings toggle: `IsGlobalPrivacyControlEnabled` returns true unless the pref is managed (`components/global_privacy_control/global_privacy_control_utils.cc:16-22`), so `true` only outranks Ad Block Only Mode's injected `false` (see Cross-cutting; the mode exists only in an English UI, `components/brave_shields/core/common/brave_shield_constants.h:160-161`, so in any other UI language the key changes nothing) and pins against a default flip. The signal sits behind `kBraveGlobalPrivacyControl`, on by default (`chromium_src/third_party/blink/common/features.cc:40`); `brave://flags/#brave-global-privacy-control-enabled` turns it off and the policy cannot override that. No Shields check (`browser/net/global_privacy_control_network_delegate_helper.cc:28-31`): the header goes out where Shields are down |
| BraveDeAmpEnabled | ✅ | cr140 | bool | map, unguarded | lock only — dynamic refresh; the pref defaults on with a Settings toggle (`components/de_amp/common/pref_names.cc:13`), so the key locks it and outranks Ad Block Only Mode's injected `false` (see Cross-cutting). No Shields check (`components/de_amp/browser/de_amp_body_handler.cc:102-105`), so it works where Shields are off. `brave://flags/#brave-de-amp` turns the feature off and the policy cannot override it |
| BraveDebouncingEnabled | ✅ | cr140 | bool | map, unguarded | lock only — dynamic refresh; the pref defaults on with a Settings toggle (`components/debounce/core/browser/debounce_service.cc:55`), so the key locks it and outranks Ad Block Only Mode's injected `false` (see Cross-cutting). No Shields check (`components/debounce/content/browser/debounce_navigation_throttle.cc:99-101`), so it works where Shields are off. `brave://flags/#brave-debounce` turns the feature off and the policy cannot override it: no `DebounceService` is built (`browser/debounce/debounce_service_factory.cc:46-47`) |
| BraveTrackingQueryParametersFilteringEnabled | ✅ | cr142 | bool | map, unguarded | lock only — dynamic refresh; only effective while Shields are up (`browser/net/brave_site_hacks_network_delegate_helper.cc:77-78`); unset = enabled, no user toggle (the pref is read only when managed, `:58-67`), so `true` only keeps filtering on against Ad Block Only Mode's injected `false` (see Cross-cutting; English UI only, `brave_shield_constants.h:160-161`, so elsewhere the key changes nothing). The parameter list is the Query Filter component, on by default (`components/query_filter/common/features.cc:13`) |
| BraveReduceLanguageEnabled | ✅ | cr140 | bool | map, unguarded | lock only — dynamic refresh; the pref (`brave.reduce_language`) defaults on with a Settings toggle, so the key locks it. It outranks Ad Block Only Mode's injected `false` (see Cross-cutting), but the mode also injects `DefaultBraveFingerprintingV2Setting` = 1 (`components/brave_policy/ad_block_only_mode/ad_block_only_mode_policy_manager.cc:98-99`), under which both readers bail, so under the mode the key works only alongside `DefaultBraveFingerprintingV2Setting` = 3 (Maximum Privacy); `brave://flags/#brave-reduce-language` turns the feature off and the policy cannot override it. It governs the `Accept-Language` header (cut to the first language) and the local-font allowlist, both only where Shields are up and fingerprinting is not off: `ShouldDoReduceLanguage` (`components/brave_shields/core/browser/brave_shields_utils.cc:374-390`) bails when Shields are down, when fingerprinting is `ALLOW` for the site (e.g. `DefaultBraveFingerprintingV2Setting` = 1) or on a `BRAVE_WEBCOMPAT_LANGUAGE` exception. `navigator.languages` is farbling's, not this key's (`chromium_src/third_party/blink/renderer/core/frame/navigator_language.cc:19-38`). The font allowlist exists on Windows and macOS and, on Linux, only for Ubuntu 20.04, Ubuntu 22.04 and Fedora (`third_party/blink/renderer/brave_font_whitelist.cc:1799,1960-1985`; distro read before the sandbox, `app/brave_main_delegate.cc:172-176`; master adds Ubuntu 24.04); elsewhere the list is empty and every font is allowed. The fixed `en-US,en;q=0.9` (`browser/net/brave_reduce_language_network_delegate_helper.cc:45,148-151`) applies only at Strict, which `kBraveShowStrictFingerprintingMode` (off by default, `components/brave_shields/core/common/features.cc:91-92`) hides; a stored Block reads as Standard (`brave_shields_utils.cc:599-604`) |
| BraveRewardsDisabled | ✅ | cr105 | bool | map, `ENABLE_BRAVE_REWARDS` | true = disable; restart. **Also stops Sponsored Ads, except Brave Search's.** The ads service does not start (`AdsServiceImpl::CanStartBatAdsService`, `ads_service_impl.cc:307-312`), so no notification ads, no NTP sponsored wallpapers (`view_counter_service.cc:240-257`) and no ad event or conversion reporting. Brave Search's result ads are server-side and still show (brave-browser#51040, wontfix). The policy hides the Settings "Enable Sponsored Ads" toggle (`brave_settings_ui.cc:281-283`) and the refreshed NTP's sponsored toggles. Edge, until restart: a sponsored-images component registered before the policy landed, or re-registered by turning "Show background images" off and on (`view_counter_service.cc:339-343,403-425`), lets refreshed-NTP sponsored-site tiles appear, since they need no ads service (`sponsored_sites_facade.cc:123-139`). Not all ads traffic stops: every regular profile still builds its ads service, whose `HttpClient` fetches `static.ads.brave.com/v1/ohttp/hpkekeyconfig` (`components/brave_ads/core/browser/network/http_client.cc:132-135`) while Griffin's `BraveAdsObliviousHttpStudy` (all channels, no `policy_restriction`) sets `kShouldSupportOhttp`; either `ChromeVariations` row stops it. brave-browser#54917 (open, unmilestoned) would decouple ads startup from Rewards; then this row stops covering ads and a new key is needed. Source-read at `v1.98.60`, not runtime-tested |
| BraveWalletDisabled | ✅ | cr106 | bool | map, `ENABLE_BRAVE_WALLET` | true = disable; restart. Guard `enable_brave_wallet = !is_brave_origin_branded` (`components/brave_wallet/common/buildflags/buildflags.gni:9`); no feature gate (`browser/brave_wallet/brave_wallet_context_utils.cc:17-36`). Removes the wallet service, toolbar button, side panel and settings page, and also disables web3 and decentralized DNS: no `window.ethereum` / `window.solana` providers (`browser/brave_content_browser_client.cc:1056-1066`) and no ENS/SNS/Unstoppable Domains resolution (`browser/net/decentralized_dns_network_delegate_helper.cc:46-51`) |
| BraveVPNDisabled | ⚠️ no-op on Linux | cr112 | bool | map, `ENABLE_BRAVE_VPN` | **Windows, macOS, Android, iOS only.** `enable_brave_vpn = enable_brave_vpn_v1 \|\| enable_brave_vpn_v2`, both `(is_win \|\| is_android \|\| is_mac \|\| is_ios) && !is_brave_origin_branded` (`components/brave_vpn/common/buildflags/buildflags.gni:11-22`) — no `is_linux`, so the map entry is compiled out of Linux builds and the key is a silent no-op there while `brave://policy` still shows it applied (the 1.98.60 Linux binary lacks the target pref). On Windows and macOS it hides the toolbar button, NTP card, settings section and welcome offer (`components/brave_vpn/common/brave_vpn_utils.cc:207-228`). The Linux row is labelled rather than removed; `slimbrave-mac.py` gives it the same label on Linux. **Trigger:** `is_linux` joining the buildflag with `kBraveVPN` on for Linux (brave-browser#15817, #56726, open, unmilestoned); then drop the Linux label from both Python scripts. Restart |
| BraveAIChatEnabled | ✅ | cr121 | bool | map, `ENABLE_AI_CHAT` | false = disable Leo; restart. Guard `enable_ai_chat = !is_brave_origin_branded`, so every regular build, Linux included. `IsAIChatEnabled` = `kAIChat` (on by default) **and** not managed `false` (`components/ai_chat/core/browser/utils.cc:102-106,131-134`; `kAIChat` at `components/ai_chat/core/common/features.cc:22,65-67`, both at `v1.98.64`); `false` removes the service (`browser/ai_chat/ai_chat_service_factory.cc:51`) and with it the sidebar item, toolbar button, omnibox provider, context menu, NTP input and `brave://leo-ai`. Does not cover on-device models (see BraveLocalAIEnabled), nor the browser-wide Brave WebMCP Tool Scripts component (`eingdhelnaolbpcdkgddekhifcjfkalf`): its registration reads only `kAIChat` and Blink `kWebMCP`, both on in code with no brave-core override, Griffin study or policy, and no pref (`chromium_src/chrome/browser/component_updater/registration.cc:64-70` at `v1.98.64`), so `EnsureInstalled` fetches it when missing (`components/web_mcp/core/browser/web_mcp_component_installer.cc:136-141`) and the periodic component update check keeps it current (`components/component_updater/component_updater_service.cc:438-466` at 156.0.8078.80). Nothing uses it under the policy: `WebMcpInjector` is built only behind `IsAllowedForContext` (`browser/ui/tabs/brave_tab_features.cc:92-99`). Only the rejected `ComponentUpdatesEnabled` stops the download; the description carries the caveat |
| BraveLocalAIEnabled | ⚠️ feature off on Release | cr149 — **Brave 1.94**, branch-probed | bool | map, `ENABLE_LOCAL_AI` | false = unregister and uninstall the on-device model components, EmbeddingGemma (`components/local_ai/core/local_models_updater.cc:88-101,128-137`) and the speech models (`on_device_speech_models_component_installer.cc:134-140`), and make `IsHistoryEmbeddingsFeatureEnabled()` false (`rewrite/chrome/browser/history_embeddings/history_embeddings_utils.cc.yaml:42-45`): no vector index of history, no "Semantic history search" toggle in brave://settings/privacy, no history tool for Leo. **Feature off on Release:** history search needs `kHistoryEmbeddings`, off at 156.0.8078.48 and pinned off by brave-core (`rewrite/components/history_embeddings/core/history_embeddings_features.cc.yaml:7-13`); the speech models need `kBraveOnDeviceSpeechRecognition`, off in code (`components/local_ai/core/features.cc:10-11`, `v1.98.64`; same on `1.100.x` and master); Griffin's `BraveOnDeviceSpeechRecognitionStudy` (brave-variations#1942) enables it only on desktop Nightly 1.101+ (100%, `min_version: '156.1.101.1'`, no `policy_restriction`, so either `ChromeVariations` row filters it out), with no Beta or Release study. From 1.100 the speech model also needs the user opt-in `kOnDeviceSpeechModelEnabled` (default false), which this key's `false` clears along with the offer (`components/local_ai/core/on_device_speech_models_component_installer.cc:141-143` on `1.100.x`). Griffin turns `HistoryEmbeddings` on for desktop Nightly (100%) and Beta (50%, brave-variations#1936), with no Release study and no `policy_restriction`, so either `ChromeVariations` row filters both out; where it is on, EmbeddingGemma downloads at launch while indexing stays a per-profile opt-in. On Release the key only blocks a `brave://flags#brave-history-embeddings` opt-in. It is the only policy lever: Chromium's `HistorySearchSettings` and `GenAiDefaultSettings` never reach Brave. Separate buildflag (`ENABLE_LOCAL_AI`) and prefs from AI Chat. Restart for history search; the model registrars apply a change live; browser-wide. In five presets, all but Strict Parental Controls |
| BraveShieldsDisabledForUrls | ✅ | cr107 | list | map, unguarded | scheme-wide patterns, see Cross-cutting; browser-wide; restart per YAML but applies live: Chromium's content-settings `PolicyProvider` re-reads the list on change (`components/content_settings/core/browser/content_settings_policy_provider.cc:451-455` at 156.0.8078.48). Where Shields are off, all five `DefaultBrave*` rows, `BraveTrackingQueryParametersFilteringEnabled` and `BraveReduceLanguageEnabled` do nothing; with `https://*` and `http://*` that is every web page. De-AMP, Debouncing and GPC have no Shields check and keep working. A policy Shields-off creates no Shields-down `COOKIES` rule, because only the pref provider's own `BRAVE_SHIELDS` rules feed them (`components/content_settings/core/browser/brave_content_settings_pref_provider.cc:1041-1042`). So third-party cookie blocking and `BlockThirdPartyCookies` keep working on listed sites. Ephemeral storage's tab-close cleanup does read the policy-aware Shields state and is skipped there (`browser/ephemeral_storage/ephemeral_storage_tab_helper.cc:231-242`, `components/ephemeral_storage/ephemeral_storage_service.cc:246-248`), as the DefaultBraveRemember1PStorageSetting row notes. Source-read, not runtime-tested |
| BraveShieldsEnabledForUrls | ✅ | cr107 | list | map, unguarded | counterpart of the row above; browser-wide; restart per YAML but applies live. Pins Shields on for matched sites, and the ad-block, scripts, fingerprinting, cookie and storage controls grey out (`components/brave_shields/resources/panel_new/components/advanced_settings.tsx:85`). Their cookies are not pinned. The panel's main toggle stays clickable (`panel_new/components/main_card.tsx:84-87`) and, like the `IDC_TOGGLE_SHIELDS` command (`browser/ui/browser_commands.cc:509-525`), writes a user `BRAVE_SHIELDS` BLOCK with no managed check (`components/brave_shields/core/browser/brave_shields_utils.cc:220-226`). The policy outranks that rule for Shields. But `BravePrefProvider` turns every user Shields-down rule into a `COOKIES` ALLOW (Wildcard, site) rule (`components/content_settings/core/browser/brave_content_settings_pref_provider.cc:1041-1089`). That explicit setting lifts third-party cookie blocking on the site, voiding `BlockThirdPartyCookies` there, and gives third-party frames persistent rather than ephemeral storage (`chromium_src/components/content_settings/core/common/cookie_settings_base.cc:150-170,266-270`). The panel then reads the policy-aware state again and shows Shields on (`browser/ui/webui/brave_shields/shields_panel_data_handler.cc:314-316`), so it offers no way to remove the rule while the policy is set. The per-site HTTPS-upgrade dropdown does not grey out (`brave_shields_tab_helper.cc:425-441`), so a per-site HTTPS mode stays settable unless `DefaultBraveHttpsUpgradeSetting` is set too. It is the only key that stops a user dropping Shields per site, which would void every `DefaultBrave*` enforcer there. If the identical pattern is in both lists this one wins (`content_settings_policy_provider.cc:47-48`); the scripts keep the two rows mutually exclusive. Source-read, not runtime-tested |
| BraveNewsDisabled | ✅ | cr138 | bool | map, `ENABLE_BRAVE_NEWS` | true = disable; restart. Unset, News stays off until the user opts in on the new tab page (`brave.today.opted_in`, default `false`). `true` makes `brave_news::IsEnabled` false whatever the user chose (`components/brave_news/common/pref_names.cc:34-41`), so the feed is never fetched, and hides News on the new tab page, the RSS page action and its commands. Edge: the sidebar News item checks only `kBraveNewsSidebar` and the opt-in (`components/sidebar/browser/sidebar_service.cc:770-783`), so a profile that opted in before the policy keeps a button that opens an empty panel. `kBraveNewsNewUserOptIn`, which would opt every new profile in, is off by default with no study (see What's next). Source-read, not runtime-tested |
| BraveTalkDisabled | ✅ | cr138 | bool | map, `ENABLE_BRAVE_TALK` | true = disable; restart. Removes Talk's browser entry points: the new tab page widget (`browser/ui/webui/brave_new_tab_page_refresh/new_tab_page_initializer.cc:242-244`), the sidebar item and the `IDC_SHOW_BRAVE_TALK` command (`browser/ui/brave_browser_command_controller.cc:398-402`). No navigation check reads the pref: `talk.brave.com` still opens as a website |
| BravePlaylistEnabled | ⚠️ feature off on Release/Beta | cr139 | bool | map, `ENABLE_PLAYLIST` | **Key live, feature off outside Nightly.** `kPlaylist` is `FEATURE_DISABLED_BY_DEFAULT` on every non-iOS build (`components/playlist/core/common/features.cc:13-19`), `IsPlaylistAllowed()` needs feature **and** no policy `false` (`components/playlist/core/browser/utils.cc:18-29`), and the only enabling study, `DefaultPlaylistStudy`, is Nightly-only (no `policy_restriction`). `false` bites on Nightly and wherever the user turns on `brave://flags/#playlist`; on Release and Beta it is a guard. The YAML's "enabled by default" is wrong for desktop. Restart |
| BraveWebDiscoveryEnabled | ✅ | cr138 | bool | map, `ENABLE_WEB_DISCOVERY` | unset = **disabled** (`browser/brave_profile_prefs.cc:551`); `false` locks it off and, the pref being managed, suppresses both opt-in prompts: the search.brave.com infobar (`browser/web_discovery/web_discovery_cta_util.cc:85-92`) and the welcome flow's Web Discovery step. Restart per YAML, but the collector watches the pref and applies a change live (`browser/extensions/brave_component_loader.cc:42-45`) |
| BraveSpeedreaderEnabled | ✅ | cr138 | bool | map, `ENABLE_SPEEDREADER` | desktop only; restart. Maps to `brave.speedreader.feature_enabled` (default `true`): `false` makes `IsAllowedForSite` return false (`components/speedreader/speedreader_service.cc:98-103`) and hides the page action, read-aloud included |
| BraveWaybackMachineEnabled | ✅ | cr138 | bool | map, `ENABLE_BRAVE_WAYBACK_MACHINE` | desktop only; unset = enabled. `false` stops the archive.org offer after a 404, 408, 410, 451, 500, 502-504, 509, 520, 521 or 523-526 response (`components/brave_wayback_machine/brave_wayback_machine_utils.cc:52-72`) and hides the URL-bar icon and Settings toggle; it also stops the offer bubble opening by itself: `kWaybackMachineAutoShowBubble` is off in code (`components/brave_wayback_machine/features.cc:10`; flag `brave://flags#brave-wayback-machine-auto-show-bubble`) but on through Griffin `WaybackMachineAutoShowBubble` for 10% of desktop Release and all desktop Beta and Nightly (brave-variations 1430e90ba, #1934, 2026-10-29; no `policy_restriction`, so either `ChromeVariations` row filters it out; Performance Focused and Brave Origin write this key without one and rely on it). With the pref false the tab helper resets before `kNeedToCheck` (`brave_wayback_machine_tab_helper.cc:72-75`; same gate on 1.99.x), the only state that auto-shows (`browser/ui/views/page_action/wayback_machine_page_action_controller.cc:141-146,186-189`), and `ShowBubble` refuses `kInitial` (`:165`); archive.org is contacted only after the user accepts (`wayback_machine_bubble_view.cc:134-136`). The auto-check toggle (`kWaybackMachineAutoCheck`, off, no study) has no reader on `v1.98.64`, 1.99.x, 1.100.x or master, so nothing is claimed for it. Restart per YAML, but applies live (`brave_wayback_machine_tab_helper.cc:49-53`) |
| TorDisabled | ✅ | cr78 (Win) / cr93 (mac, Linux) | bool | map, `ENABLE_TOR` | desktop only; browser-wide (Local State `tor.tor_disabled`). `true` drops "New private window with Tor", closes every Tor window and deletes the Tor client and its data (`browser/extensions/brave_extension_management.cc:55-65,80-87`). Restart per YAML, but applies live |
| EmailAliasesEnabled | ✅ | cr147 — **Brave 1.92**, branch-probed | bool | map, `ENABLE_EMAIL_ALIASES` | **Feature on via Griffin, off in code.** Desktop only (`ENABLE_EMAIL_ALIASES`). `kEmailAliases` is `FEATURE_DISABLED_BY_DEFAULT` (`components/email_aliases/features.cc:13`), but brave-variations `EmailAliasesStudy_Release` (#1835) enables it at 100% on Release Windows/macOS/Linux from 1.94.113, and `EmailAliasesStudy` on Nightly and Beta. `false` removes the service (`browser/email_aliases/email_aliases_service_factory.cc:56-59`) and with it the settings page, context-menu entry and autofill suggestions; with `kBraveAccount` off it also hides the Settings Brave Account row; the account service and `brave://account` stay registered browser-wide while `kEmailAliases` is on (`components/brave_account/features.cc:22-28`, `browser/browser_context_keyed_service_factories.cc:243`), but logged out they send nothing until a sign-in flow starts (`components/brave_account/logged_out_state.cc:14-28`), and no YAML controls Brave Account. Neither study sets `policy_restriction`, so either `ChromeVariations` row filters them out and `false` is then a guard. Restart |
| DefaultBraveAdblockSetting | ✅ | cr142 | int enum | own `IntRangePolicyHandlerBase` handler, unguarded (`chromium_src/chrome/browser/policy/configuration_policy_handler_list_factory.cc:32-36`) → `brave.profile.managed_default_content_settings.*` pref → content-settings policy provider (brave-core patch + `rewrite/` twin) | 1 = allow ads, 2 = block. Locks only `BRAVE_ADS`: standard network ad/tracker blocking (`browser/net/url_context.cc:535-537`). Cosmetic filtering (element hiding, scriptlets), the domain-block interstitial and Aggressive mode key off the unmanaged `BRAVE_COSMETIC_FILTERING`, which "Allow all trackers & ads" in the Shields panel or "Disabled" in `brave://settings/shields` still sets to `ALLOW` (`components/brave_shields/core/browser/brave_shields_settings_service.cc:123-148`); this key greys neither control. At 1, network blocking stops while cosmetic filtering keeps its default (brave-browser#59662, open). **All five `DefaultBrave*`** lock the type's default and void per-site exceptions for it (`content_settings_policy_provider.cc:274-276` at 156.0.8078.48), but every consumer checks Shields first, so a site with Shields off escapes them. **Trigger:** a fix for #59662 that also manages `BRAVE_COSMETIC_FILTERING`; then this row and the scripts' "Cosmetic filtering … is not locked" text change |
| DefaultBraveFingerprintingV2Setting | ✅ | cr141 | int enum | same | 1 = off, 3 = standard (no 2: retired Strict, outside the schema enum and ignored by the handler, `browser/policy/handlers/brave_fingerprinting_v2_policy_handler.cc:57-62`). Pins only the site-level `BRAVE_FINGERPRINTING_V2` mode, over the user's per-site mode and the remote list's (`components/brave_shields/core/browser/brave_shields_utils.cc:591-608`). Per-API `BRAVE_WEBCOMPAT_*` `ALLOW` rules are unmanaged and still switch farbling off for one API on one site: Brave's remote list and the user's toggles in the panel's fingerprinting details, which neither this key nor `BraveShieldsEnabledForUrls` greys (`panel_new/components/advanced_settings.tsx:306-310`) |
| DefaultBraveHttpsUpgradeSetting | ⚠️ unenforced where Griffin moves to upstream HTTPS-First (25% of Release) | cr142 | int enum | same | 1 = allow HTTP, 2 = strict, 3 = standard. Every enforcing reader needs `kBraveHttpsByDefault` (`HttpsByDefault`, on in code, `chromium_src/net/base/features.cc:31-33`). With it on, 2 upgrades every navigation and turns a failed upgrade into a warning (Chromium's Ask-before-HTTP dialog on desktop; `components/brave_shields/core/browser/brave_shields_utils.cc:683-719`), 3 upgrades unless the host is on Brave's exceptions list, 1 turns upgrading off; all only where Shields are up. **Griffin switches that path off:** brave-variations `TransitionToUpstreamHttpsUpgrade` (#1891, #1939) disables `HttpsByDefault` and enables `TransitionToUpstreamHttpsUpgrades` and `HttpsFirstBalancedMode` for all of desktop Beta and Nightly and 25% of desktop Release (from 1.97.41). There the key is read once per profile: `MigrateHttpsUpgradeSettings` (`browser/profiles/brave_profile_manager.cc:88-143`) copies it into upstream HTTPS-First as **user** prefs (1 → off, 2 → strict, 3 → Balanced); the Shields HTTPS controls are hidden and the upstream setting shows in `brave://settings/security`, where the user can lower it. The study sets no `policy_restriction`, so either `ChromeVariations` row (Maximum Privacy carries 1) keeps Brave's path and this key enforced. **Trigger:** the Release share rising, or brave-core removing `kBraveHttpsByDefault` (brave-core#39916 calls the transition code a step "before removing Brave's implementation"); then re-verify. Chromium's `HttpsOnlyMode` is the lock on the upstream path (see What's next) |
| DefaultBraveReferrersSetting | ✅ | cr142 | int enum | same | 1 = permissive, 2 = cap to strict origin; both exposed as mutually exclusive rows (issue #9); never put 1 in a preset. 2 is Brave's own default, so the key locks it and voids per-site `ALLOW` exceptions, including those Brave's webcompat list adds. The cap acts only on cross-origin requests from a page with Shields up (`components/brave_shields/content/browser/brave_shields_util.cc:38-64`); 1 lifts it, so a page's own `unsafe-url` policy sends the full URL cross-origin |
| DefaultBraveRemember1PStorageSetting | ✅ | cr142 | int enum | same | 1 = remember, 2 = forget when the site's last tab closes. Cleanup is skipped for any eTLD+1 where a visited host had Shields off or cookies on Allow (`browser/ephemeral_storage/ephemeral_storage_tab_helper.cc:231-243`). Inert whenever `kBraveShredFeature` is on: Auto Shred then decides (default `NEVER`, `components/ephemeral_storage/ephemeral_storage_service.cc:385-389`), and its migration copies user rules, not the policy (no Auto Shred policy exists). Off by default on desktop (`components/brave_shields/core/common/features.cc:70-75`) with no desktop study, but `brave://flags/#brave-shred` lets a user escape a forced 2. **Trigger:** the feature turning on for desktop, in code or by a study (brave-browser#49999); then re-label the row ⚠️ and weigh a replacement lock, `CookiesSessionOnlyForUrls` or `DefaultCookiesSetting` = 4, either of which outranks Shields-down and every per-site cookie rule (see Considered and rejected) |

Brave keys that exist and are **not exposed**:

| Key | Status | Why not |
|---|---|---|
| BraveSyncUrl | ✅ exists, unexposed | a custom sync-server URL (unguarded `brave_simple_policy_map.h:106-107` entry into `brave_sync.sync_service_url`, honoured only when managed and `https`, ahead of `--sync-url`: `chromium_src/components/sync/service/sync_service_impl.cc:23-32` at `v1.98.60`), not a debloat toggle; self-hosters write it by hand |
| PsstEnabled | ⚠️ feature off on Release/Beta | `chrome.*:147-` — **Brave 1.95**, branch-probed. Dispatched into `brave.psst.settings.enable_psst` (`brave_simple_policy_map.h:160-163`) under `ENABLE_PSST` (desktop, compiled out of Origin); regular Brave in Origin mode defaults it `false`, not user-settable (`brave_origin_service_factory.cc:240-246`). Inert on Release and Beta: `kEnablePsst` is `FEATURE_DISABLED_BY_DEFAULT` (`components/psst/core/common/features.cc:10`), and the only enabling study, `EnablePsstStudy` (#1906), is Nightly-only (100%, desktop, no `policy_restriction`). Where the feature is on, the rules component installs at launch whatever the policy says (`psst_component_installer.cc:136-146`) and `false` stops only page processing. PSST injects per-site scripts into logged-in origins and drives the account through settings URLs flipping switches. **Trigger:** `kEnablePsst` on for Release, in code or by a Release study; `EnablePsstStudy` gaining Beta is the leading indicator. Then add a checkbox writing `false`, label Brave 1.95+, restart note, no promise that `false` stops the download; the key joins `ORIGIN_BUILTIN_KEYS` |
| IPFSEnabled | ⛔ | `deprecated: true`; the feature (local node, `ipfs://` scheme) left Brave in 1.69.153 (Aug 2024), only a `DEPRECATE_IPFS` tombstone remains (`brave_simple_policy_map.h:152-155` at `v1.98.60`, into the migration-only `brave.ipfs.enabled`, which nothing reads). Decentralized DNS still rewrites ENS contenthash records to the public IPFS gateway `https://inbrowser.link` (`browser/net/decentralized_dns_network_delegate_helper.cc:119-124`, `components/ipfs/ipfs_utils.h:16`) without reading the key; `BraveWalletDisabled` stops that (`brave_wallet::IsAllowed`, same helper `:49-51`). **Do not re-add**; the YAML is the tiebreaker |

## Chromium-inherited keys

Dispatch for every row is `factory` unless the Notes say otherwise.

| Key | Status | Min | Type | Written | Notes |
|---|---|---|---|---|---|
| MetricsReportingEnabled | ✅ | cr8 | bool | false | restart; browser-wide. Chromium marks it `sensitive: true`, which blocks it from a platform source on a Windows/Mac machine that is not domain-joined or MDM-managed (156.0.8078.48 `components/policy/core/common/async_policy_loader.cc:110-119`; Linux never filters); brave-core patches that flag out of the YAML, the only reason an HKLM write works on a home PC. Brave sends no UMA/UKM (`chromium_src/components/metrics/enabled_state_provider.cc:13-15`), so in practice the key governs crash-report upload to `cr.brave.com` (fully on Linux and macOS; Windows below): upstream `ApplyMetricsReportingPolicy()` copies the pref into the crash-upload consent (`chrome/browser/metrics/metrics_reporting_state.cc:203-209`), honoured because brave-core forces `GOOGLE_CHROME_BRANDING` there (`chromium_src/components/metrics/metrics_service_accessor.cc:16-19`). Brave defaults the pref to false on Release and in Brave Origin but **true on Beta and Nightly** (`browser/metrics/metrics_reporting_util.cc:21-39`), and outside Origin the first-run welcome page pre-ticks *Send diagnostic reports* and writes it on Finish (`components/brave_welcome_ui/components/help-improve/index.tsx:63-67,96`, `browser/ui/webui/welcome_page/welcome_dom_handler.cc:194-203`), so a Release user who clicks through has it on. Any managed value hides that checkbox (`browser/ui/webui/welcome_page/brave_welcome_ui.cc:181-183`), suppresses Brave's post-crash "quit unexpectedly" dialog (`metrics_reporting_util.cc:41-60`) and removes Send now on `brave://crashes` (156.0.8078.80 `chrome/browser/ui/webui/crashes/crashes_ui.cc:203-205`). **Windows is narrower:** Brave's always-false `IsReportingEnabled()` makes every startup's `StartMetricsRecording` call `SetUploadConsent(false)` whatever the pref (156.0.8078.80 `chrome/browser/metrics/chrome_metrics_services_manager_client.cc:374-395`, `components/metrics_services_manager/metrics_services_manager.cc:379-383`), and crashpad's early policy read uses `…\Brave-Browser` (see Platform policy locations), so there the key reaches crashpad only through the `usagestats` value the browser copies: it blocks uploads of crashes before metrics start, from the second launch under it, and manual sends, while Brave keeps later uploads off by itself. Source-derived, not run |
| SafeBrowsingProtectionLevel | ✅ | cr83 | int enum | 0 (no protection) or 1 (standard) | 0/1/2 valid; 0 and 1 are two mutually exclusive rows (`Group = "safebrowsing"`). Brave proxies Safe Browsing through its own hosts: `components/static_redirect_helper/static_redirect_helper.cc:85-105` (`v1.98.60`) rewrites `safebrowsing.googleapis.com`, `sb-ssl.google.com` and `safebrowsing.google.com` to `*.brave.com`, so Google receives the proxied lookups but never learns which client made them, not even its IP. Upstream's hash-prefix real-time lookups, whose OHTTP relay the rewrite does not cover, never run in Brave: they require `HasGoogleChromeBranding()` (`components/safe_browsing/core/common/hashprefix_realtime/hash_realtime_utils.cc:25-31,107-110` at 156.0.8078.48). Value 2 behaves as 1: brave-core makes `IsEnhancedProtectionEnabled()` false (`chromium_src/components/safe_browsing/core/common/safe_browsing_prefs.cc:8`). Turning it off buys almost no privacy and costs the phishing/malware interstitials; 0 is in no preset. 1 locks Standard: `SafeBrowsingPolicyHandler` sets `safebrowsing.enabled` true and `safebrowsing.enhanced` false (156.0.8078.80 `components/safe_browsing/core/common/safe_browsing_policy_handler.cc:190-193`), and with `safebrowsing.enabled` managed, the generated pref behind `brave://settings/security` is enforced and refuses a change (`chrome/browser/safe_browsing/generated_safe_browsing_pref.cc:62-66,158-163`). Brave's page override leaves that alone; it hides only the Enhanced radio (`browser/resources/settings/br/security_page.ts:31-38`, `v1.98.64`). 1 is in Strict Parental Controls, where it stops DisableSafeBrowsingProceedAnyway being undone in settings. PhishGuard's saved-password-reuse pings, which carry the page URL, also go to `sb-ssl.brave.com` although brave-core means to cancel them (see What's next, `PasswordProtectionWarningTrigger`) |
| UrlKeyedAnonymizedDataCollectionEnabled | ✅ | cr69 | bool | false | lock only — the pref defaults to false (156.0.8078.80 `components/unified_consent/unified_consent_service.cc:198-199`) and is not syncable, and nothing in desktop Brave turns it on by itself: the Settings toggle is compiled out (`patches/chrome-browser-resources-settings-privacy_page-personalization_options.html.patch:34-41`), and Sync's enable path needs `IsReplaceSyncPromosWithSignInPromosEnabled()`, which brave-core forces false (`rewrite/components/sync/base/features.cc.yaml:18-30`). Its one user switch is the Privacy Guide's "Make searches and browsing better" step (`privacy_guide_msbb_fragment.html.ts:25-26`), whose link Brave hides (`browser/resources/settings/br/privacy_page.ts:59`) and whose route `brave://settings/privacy/guide` exists only while the browser is unmanaged (`chrome/browser/ui/webui/settings/settings_ui.cc:364-367`, `route.ts:27-28`); any platform policy, SlimBrave's included, removes it, since Brave hides managed UI only when every policy is `POLICY_SOURCE_BRAVE` (`chromium_src/chrome/browser/ui/managed_ui.cc:21-31`). So the key overrides a true set there before SlimBrave was applied and pins against a default flip. Most readers are off in Brave (commerce behind `kShoppingList`, Optimization Guide hints behind `kOptimizationHints`); one Brave leaves in place is the omnibox, which sends the current page URL with zero-prefix suggest requests to a Google default search engine only while this is true and search suggestions are on (Brave defaults them off, `browser/brave_profile_prefs.cc:249-251`; `components/omnibox/browser/base_search_provider.cc:465-490`); not runtime-tested. Legacy half of a `SimpleDeprecatingPolicyHandler` (factory `:2680-2687`) whose successor `UrlKeyedMetricsAllowed` is still `future_on` only, so this key is the one that applies — see Considered and rejected |
| AccessibilityImageLabelsEnabled | ✅ | cr84 | bool | false | lock with a legacy target. The pref defaults to false but is synced (`chrome/browser/sync/prefs/chrome_syncable_prefs_database.cc:1782-1785` at 156.0.8078.80), and Brave removed both ways to turn it on: the context-menu opt-in in 1.42 (brave-browser#24047) and the Settings toggle in 1.78 (brave-browser#45533; now `chromium_src/chrome/browser/resources/settings/a11y_page/a11y_page.html.ts.lit_mangler.ts:30-37` at `v1.98.64`). A profile that accepted earlier keeps true with no UI to clear it. While true and a screen reader runs, unlabeled images are POSTed to `ckintersect-pa.googleapis.com` with `google_apis::GetAPIKey()` (`chrome/browser/accessibility/accessibility_labels_service.cc:203-206,238-252`; `services/image_annotation/annotator.cc:825-851`, the Manta route off by default). Brave's placeholder key likely gets the request refused, but the image bytes are sent (source-read). Dispatched on desktop (factory `:595-597`), per-profile, dynamic; `false` turns it off there and locks it everywhere |
| AutofillAddressEnabled | ⚠️ deprecated, still applied | cr69 | bool | false | `deprecated: true` at 156.0.8078.48 ("deprecated in M156, please use AutofillSettings", `34ae451dfc`) but uncapped and still applied, also at 157.0.8103.21 and main: `AutofillSettingsPolicyHandler` (factory `:2656-2657`) sets `autofill.profile_enabled` false (`components/autofill/core/browser/permissions/autofill_policy_handler.cc:101-105`), read with no feature gate by `ChromeAutofillClient::IsAutofillProfileEnabled` (`chrome/browser/ui/autofill/chrome_autofill_client.cc:1042-1045`). Deprecation is a label: handlers run on a deprecated policy like any other (`components/policy/core/browser/configuration_policy_handler_list.cc:83-97`) and `brave://policy` shows its status as `Deprecated`. Kept, with that caveat in the description, because the successor `AutofillSettings` is inert in Brave (see Considered and rejected): writing it instead would leave address Autofill on |
| AutofillCreditCardEnabled | ⚠️ deprecated, still applied | cr63 | bool | false | `deprecated: true` at 156.0.8078.48 by the same change, uncapped and still applied: the same handler sets `autofill.credit_card_enabled` false (`autofill_policy_handler.cc:107-111`), read with no feature gate by `ChromePaymentsAutofillClient::IsAutofillPaymentMethodsEnabled` (`chrome/browser/ui/autofill/payments/chrome_payments_autofill_client.cc:868-874`). Same `Deprecated` status and the same reason to keep it as AutofillAddressEnabled |
| PasswordManagerEnabled | ✅ | cr8 | bool | false | pref `credentials_enable_service`; false stops offer-to-save and password generation (both gated by `IsSavingAndFillingEnabled()`, 156.0.8078.48 `chrome/browser/password_manager/chrome_password_manager_client.cc:302-317`), but passwords already saved still autofill — `IsFillingEnabled()` does not read the pref (YAML: "previously saved passwords will still work") |
| BrowserSignin | ✅ | cr70 | int enum | 0 (disable) | lock only — restart; browser-wide. Off ChromeOS, `BrowserSigninPolicyHandler` maps 0 to `signin.allowed_on_next_startup` false (156.0.8078.48 `chrome/browser/policy/browser_signin_policy_handler.cc:64-75`), copied into `signin.allowed` at the next start. Brave has no Chrome account sign-in; that pref backs the `brave://settings/extensions` "Allow Google login for extensions" toggle, which brave-core already defaults off (`chromium_src/chrome/browser/profiles/pref_service_builder_utils.cc:31-32`), so 0 locks it off. The toggle does not gate extension sign-in: without official Google API keys `BRAVE_RUN` sends `chrome.identity.getAuthToken` down the web-auth flow (`chromium_src/chrome/browser/extensions/api/identity/identity_get_auth_token_function.cc:19-23`, `v1.98.64`), whose interactivity is the caller's flag OR'd with the sign-in status (`:42-44`), so an interactive call still opens Google's sign-in popup. The toggle reaches `signin.allowed` only where a Google OAuth client is configured: `signin.allowed` = `IsDiceSignInAllowed() && signin.allowed_on_next_startup` (156.0.8078.80 `chrome/browser/signin/account_consistency_mode_manager.cc:125-134`), which needs `HasOAuthClientConfigured()` (`:66-68`). brave-core takes a client only from the build environment (`build/commands/lib/buildArgs.ts:22-23`; its in-tree CI sets one only for the ASan builder, `infra/config/gn_args.py:113-137`); a string search of the 1.98.60 Linux binary found none, and Windows and macOS are unchecked (What's next). Where a client exists, `true` turns on DICE account consistency (`:97-104`; brave-core's hook is empty off Android), which 0 prevents. It does not touch Brave Account, Brave's own sign-in, offered on Release desktop through Email Aliases (`components/brave_account/features.cc:17-29`) |
| WebRtcIPHandling | ✅ | cr91 | string enum | disable_non_proxied_udp | Brave keeps the upstream default and exposes the same pref as the "WebRTC IP handling policy" dropdown in `brave://settings/privacy`; the managed value outranks it. `disable_non_proxied_udp` turns off network-adapter enumeration, UDP, STUN and TURN over UDP (156.0.8078.48 `third_party/blink/renderer/platform/p2p/port_allocator.cc:36-45`), so ICE runs over TCP only — through the configured proxy if there is one — and a call needs a TCP path. Tor windows already force this value |
| QuicAllowed | ✅ | cr43 | bool | false | restart; browser-wide. A managed false that arrives at runtime applies live: `ProfileNetworkContextService` watches the pref and calls `SystemNetworkContextManager::DisableQuic()` for every context (156.0.8078.48 `chrome/browser/net/profile_network_context_service.cc:681-692`); lifting it needs a restart. It covers HTTP(S) loads, not WebTransport, which opens its own QUIC connection without checking `IsQuicEnabled()` (`net/quic/dedicated_web_transport_http3_client.cc:636-674`; source-read); WebRTC media is UDP either way. No brave-core override and no Griffin study |
| BlockThirdPartyCookies | ✅ | cr10 | bool | true | lock only — brave-core already defaults `profile.cookie_controls_mode` to block third-party (`browser/profiles/profile_util.cc:31-36`); the key locks it through `CookieSettingsPolicyHandler` (156.0.8078.48 `components/content_settings/core/browser/cookie_settings_policy_handler.cc:25-33`), so the Shields global "allow all cookies" choice stops applying while per-site Shields exceptions still do (they are explicit `COOKIES` rules, `components/content_settings/core/browser/brave_content_settings_pref_provider.cc:877-880`). Extensions (`privacy.websites.thirdPartyCookiesAllowed`, 156.0.8078.80 `chrome/browser/extensions/pref_mapping.cc:80`) and Brave Sync (`SYNCABLE_PREF`, 156.0.8078.80 `components/content_settings/core/browser/cookie_settings.cc:79-82`; brave-core's allowlist falls through to Chromium's, `chromium_src/components/sync_preferences/common_syncable_prefs_database.cc:127-134`) are locked out too. Brave hides the upstream cookies-page radio group (`browser/resources/settings/br/cookies_page.ts:18-25`), so the Shields control is the only user path. Ad Block Only Mode injects `false` at lower priority (see Cross-cutting) |
| ForceGoogleSafeSearch | ✅ | cr41 | bool | true | simple map → `settings.force_google_safesearch` (factory `:959-961`); `GoogleURLLoaderThrottle` adds `safe=active&ssui=on` to Google Search URLs (156.0.8078.48 `chrome/common/google_url_loader_throttle.cc:177-183`). No brave-core override of that path |
| ForceYouTubeRestrict | ✅ | cr55 | int enum | 2 (strict) | 0/1/2 valid; only 2 is written (no Moderate row). Simple map → `settings.force_youtube_restrict` (factory `:970-972` at 156.0.8078.80, unguarded); per-profile, applies live (`chrome/browser/profiles/renderer_updater.cc:74,84`). `GoogleURLLoaderThrottle`, the same throttle as ForceGoogleSafeSearch, sets `YouTube-Restrict: Strict` on requests and redirects (`chrome/common/google_url_loader_throttle.cc:185-195,257-266`): browser side for navigations, embedded frames included (`chrome/browser/chrome_content_browser_client.cc:6088-6089,6156`), and renderer side for subresources (`chrome/renderer/url_loader_throttle_provider_impl.cc:254`). It does so only for `youtube.<tld>` hosts and their subdomains (`components/safe_search_api/safe_search_util.cc:99-106`, `components/google/core/common/google_util.cc:121-127`). Google's header method also names `www.youtube-nocookie.com`, `youtubei.googleapis.com` and `youtube.googleapis.com` (Google Workspace admin help, Control YouTube content available to users); those get no header, so videos embedded from youtube-nocookie.com play unrestricted. Brave runs both throttle paths (`browser/brave_content_browser_client.cc:1206`, `renderer/brave_content_renderer_client.cc:353-355`, `v1.98.64`) and never references the pref or the header; its proxying factory keeps cors-exempt headers across redirects (`browser/net/brave_proxying_url_loader_factory.cc:315-316`). The Strict Parental Controls resolver, Cloudflare for Families, forces Google SafeSearch by DNS but not YouTube (DoH query 2026-10-31: `www.youtube.com` returned ordinary addresses, not `restrict.youtube.com`), so this is the preset's only YouTube control |
| DisableSafeBrowsingProceedAnyway | ✅ | cr22 | bool | true | factory `:360-362` at 156.0.8078.80, unguarded; per-profile, applies live: the blocking-page factory reads the pref for each page (`chrome/browser/safe_browsing/chrome_safe_browsing_blocking_page_factory.cc:68`). True sets `overridable` false and disables the keyboard override (`components/security_interstitials/core/safe_browsing_loud_error_ui.cc:88-89`), turns `CMD_PROCEED` into back-to-safety (`:133-143`) and writes no allowlist entry (`components/safe_browsing/content/browser/base_blocking_page.cc:120-122`). The billing page keeps a proceed button that does nothing (`safe_browsing_loud_error_ui.cc:327`). Covers malware, phishing and unwanted-software warnings; not certificate errors, download warnings or Shields' domain-block page. Brave uses this UI on desktop (`safe_browsing_mode = 1`, `build/args/desktop_defaults.gni:10`), its subclass reroutes only `CMD_OPEN_HELP_CENTER` (`chromium_src/components/safe_browsing/content/browser/base_blocking_page.cc`, `v1.98.64`), and nothing in brave-core reads the pref. Inert while Safe Browsing is off, and Brave leaves No protection selectable (`browser/resources/settings/br/security_page.ts:31-38` hides only Enhanced), so Strict Parental Controls pairs it with SafeBrowsingProtectionLevel = 1. No per-site escape on an unmanaged machine: `SafeBrowsingAllowlistDomains` is `sensitive: true` |
| SSLErrorOverrideAllowed | ✅ | cr44 | bool | false | factory `:1095-1097` at 156.0.8078.80, unguarded; per-profile, applies live. On each certificate error the navigation throttle passes the pref as `user_can_proceed_past_interstitial`, unless `SSLErrorOverrideAllowedForOrigins` (not offered) lists the origin (`chrome/browser/chrome_content_browser_client_navigation_throttles.cc:218-228`, `chrome/browser/policy/policy_util.cc:24-26`). False sets `HARD_OVERRIDE_DISABLED` (`components/security_interstitials/content/ssl_error_handler.cc:556`, `components/security_interstitials/core/ssl_error_options_mask.cc:51-53`), and `SSLErrorUI` drops `CMD_PROCEED` (`components/security_interstitials/core/ssl_error_ui.cc:196-197`). The typed bypass sends that same command (`components/security_interstitials/core/browser/resources/interstitial_large.js:51-55`), so HSTS pages lose it too. No brave-core reference to the pref; its `ssl_blocking_page_base.cc` override only redefines `IsSafeBrowsingPolicyManaged` (`v1.98.64`), and Brave's own proceed pages (Shields domain block, request-OTR, decentralized DNS) are not SSL pages. Breaks self-signed routers, NAS boxes, printers and local dev servers for every account on the machine. In Strict Parental Controls as the certificate twin of DisableSafeBrowsingProceedAnyway; it closes no filter bypass there (Cloudflare for Families answers blocked names with 0.0.0.0, not a certificate page). Not in Maximum Privacy |
| IncognitoModeAvailability | ✅ | cr14 | int enum | 1 or 2 | 0 = enabled, 1 = disabled, 2 = forced, as two mutually exclusive rows; restart per YAML, but open windows pick a change up (156.0.8078.48 `chrome/browser/ui/browser_command_controller.cc:2058-2070`). In Brave `tor::IsIncognitoDisabledOrForced` treats 1 and 2 alike (`browser/tor/util.cc:17-34`), so either row also removes Tor windows. With 2 every window is off the record. Leo and Rewards need a regular profile (`browser/ai_chat/ai_chat_utils.cc:18`, `browser/brave_rewards/rewards_util.cc:16`), so they are unavailable, and so is Wallet unless its private-windows setting is on (`browser/brave_wallet/brave_wallet_context_utils.cc:31-33`). On Windows with parental-controls activity logging, upstream turns 0 and 2 into 1 (156.0.8078.80 `chrome/browser/prefs/incognito_mode_prefs.cc:136-138,182-187`), and Brave's Tor check copies the rule (`browser/tor/util.cc:28-31`) |
| SyncDisabled | ✅ | cr8 | bool | true | governs Brave Sync: `syncer::SyncPolicyHandler` sets `sync.managed`, and brave-core's `BraveSyncServiceImpl` (`chromium_src/chrome/browser/sync/sync_service_factory.cc:11-18`) keeps upstream's `GetDisableReasons()`, so `brave://settings/braveSync` shows Sync disabled by the administrator. Side effect: the resulting `StopAndClear(kEnterprisePolicy)` runs Brave's override, which clears the sync code (`components/sync/service/brave_sync_service_impl.cc:207-227`), so the device leaves its sync chain and must rejoin with a code once the policy is removed |
| BackgroundModeEnabled | ⚠️ Win/Linux only | cr19 | bool | false | **Windows and Linux only** (`chrome.win:19-`, `chrome.linux:19-`; the factory entry sits under a Windows/Linux guard, 156.0.8078.48 `:2008-2012`); browser-wide (local state `background_mode.enabled`). Unmanaged default on (156.0.8078.80 `chrome/browser/background/extensions/background_mode_manager.cc:351`; no brave-core override). Background mode starts only while an enabled extension holds the `background` permission, or a hosted app has a background page (`background_application_list_model.cc:252-262`, `background_mode_manager.cc:825-828`), and no brave-core component extension does, so without a user-installed one the key only locks *Continue running background apps when Brave is closed* in Settings > System (`app/settings_brave_strings.grdp:331-333`; `chrome/browser/resources/settings/system_page/system_page.html.ts:15-19`). With one, false also stops Brave staying resident and, on Windows, registering to launch at sign-in (`background_mode_manager.cc:399-401,847-848`). `slimbrave-mac.py` also runs on Linux, so it builds the row only under `sys.platform.startswith("linux")`; on macOS a preset naming the key has it silently ignored |
| AlwaysOpenPdfExternally | ✅ | cr55 | bool | true | pref `plugins.always_open_pdf_externally` (desktop only); true turns the PDF viewer off (156.0.8078.48 `chrome/browser/plugins/plugin_prefs.cc:52-54`), so a PDF downloads and opens only when the user opens it: auto-open needs *Always open in system viewer* (`download.open_pdf_in_system_reader`) or a user or `AutoOpenFileTypes` entry (156.0.8078.80 `chrome/browser/download/download_prefs.cc:492-506,618-626`), and Brave's `download.prompt_for_download` default (true, `browser/brave_profile_prefs.cc:222-223`) shows Save As first. No brave-core override. **Visible to sites:** `navigator.pdfViewerEnabled` turns false and `navigator.plugins`/`navigator.mimeTypes` go empty in every Shields mode, because Blink lists the PDF entries only while the viewer is available (156.0.8078.80 `third_party/blink/renderer/modules/plugins/dom_plugin_array.cc:56-67`, `navigator_plugins.cc:75-76`) and brave-core's plugin farbling runs inside that block (`patches/third_party-blink-renderer-modules-plugins-dom_plugin_array.cc.patch:9-10`); the per-site randomized list becomes a constant. In no preset for that reason |
| TranslateEnabled | ✅ | cr12 | bool | false | Brave translates through its own `translate.brave.com`, not Google: `kUseBraveTranslateGo` is on by default (`components/translate/core/common/brave_translate_features.cc:13-14`) and brave-core's overrides of `translate_script.cc` and `translate_util.cc` point the script and requests there; Google is reached only under a test switch. Auto-translate is off (`kBraveEnableAutoTranslate`). A managed false also refuses manual translation (156.0.8078.48 `components/translate/core/browser/translate_prefs.cc:193-200`). The key removes the feature, not a Google data flow |
| SpellcheckEnabled | ✅ | cr65 | bool | false | desktop only; mutually exclusive with SpellCheckServiceEnabled |
| SearchSuggestEnabled | ✅ | cr8 | bool | false | Brave registers the default false (`browser/brave_profile_prefs.cc:249-251`) but flips it to true for every regular profile when the desktop first run found an OS-locale region of AR, AT, BR, CA, DE, ES, FR, GB, IN, IT, MX or US; a locale with no region counts as US (`browser/search_engines/search_engine_provider_util.cc:35-38,140-164`). On those installs the key is what turns suggestions off, and it locks the toggle |
| PrintingEnabled | ✅ | cr8 | bool | false | Also removes Save as PDF. The pref gates `PrintViewManager::GetPrintPreviewParams` (156.0.8078.80 `chrome/browser/printing/print_view_manager.cc:392-395`). Brave's print-preview extractor needs that call, so extraction fails with `PrinterSettingsInvalid` (`browser/screenshot/print_preview_extractor_internal.cc:406-410`); brave-core never reads `kPrintingEnabled`. Leo then cannot read docs.google.com, watermark.silverchair.com or scanned PDFs (text PDFs go through `PDFDocumentHelper`, `components/ai_chat/content/browser/associated_web_contents_content.cc:204-242,467-475`). The Screenshot tool's Full page fails silently on PDFs and those hosts (`browser/ui/screenshot/screenshot_controller.cc:283-290`; hosts `components/screenshot/content/pdf_utils.h:19-23`; the bubble passes `base::DoNothing()`, `browser/ui/views/toolbar/screenshot_bubble_view.cc:109`). Unlike with DeveloperToolsAvailability, the error resets the tool (`screenshot_controller.cc:328-334,462-469`). Leo's screenshots of ordinary pages use PaintPreview and still work. Maximum Privacy also writes `BraveAIChatEnabled` false, so there it loses Save as PDF and Full page on PDFs and the two hosts. Source-read, not runtime-tested |
| DefaultBrowserSettingEnabled | ✅ | cr11 | bool | false | desktop only; browser-wide. Any managed value stops the startup default-browser prompt (156.0.8078.48 `chrome/browser/ui/startup/default_browser_prompt/default_browser_prompt.cc:85-90`). `false` also replaces the *Make default* button in `brave://settings` with 'Brave cannot determine or set the default browser' (156.0.8078.80 `chrome/browser/resources/settings/default_browser_page/default_browser_page.ts:106-111`). Brave's `brave://welcome` opens only on first run (`browser/ui/startup/brave_startup_tab_provider_impl.cc:24-25`) and offers *Set as default* without reading `isDisabledByPolicy` (`components/brave_welcome_ui/components/welcome/index.tsx:37-38,95`). With this key false, the click hits the `CHECK(!DefaultBrowserIsDisabledByPolicy())` in `DefaultBrowserHandler::SetAsDefaultBrowser` (`chrome/browser/ui/webui/settings/settings_default_browser_handler.cc:126`) and crashes the browser — click *Skip*. The unlinked `brave://welcome-new` has the same unchecked step (`browser/resources/brave_welcome_page/components/welcome_step.tsx:27,56`). brave-browser#60038 (closed 2026-10-28) reports the crash at runtime on 1.97.59 for Linux. Its fix, brave-core#40997, hides the button under the policy on both pages, but only on 1.100.x and master (first tag `v1.100.41`), not on 1.98.x or 1.99.x |
| DeveloperToolsAvailability | ✅ | cr68 | int enum | 2 (disallowed) | 2 = `DeveloperToolsDisallowed`. Does **not** stop the CDP port or pipe opening — see RemoteDebuggingAllowed: 2 refuses CDP attach to profile targets (`chrome/browser/devtools/chrome_devtools_manager_delegate.cc:412-421` at 156.0.8078.48), but the browser target has no profile and passes, and its `Storage.getCookies` still returns every cookie of the last-used profile. Applies live. Also forces `extensions.ui.developer_mode` false, locking Developer mode off on `brave://extensions` and refusing *Load unpacked* (`chrome/browser/policy/developer_tools_policy_handler.cc:283-288`). No brave-core override. Also refuses Brave's own internal DevTools attach. The Screenshot tool's Full page on ordinary pages goes through CDP (`browser/ui/screenshot/devtools_full_page_extractor.cc:57-58`). `SimpleDevToolsProtocolClient` ignores the refused `AttachClient` (156.0.8078.80 `components/devtools/simple_devtools_protocol_client/simple_devtools_protocol_client.cc:51-56`), the command is dropped (`content/browser/devtools/devtools_agent_host_impl.cc:353-358`) and nothing times out. The window's `ScreenshotController` then stays busy (`browser/ui/screenshot/screenshot_controller.cc:187-188`) and greys all three modes until the window closes. PDFs and the print-preview hosts take the print-preview path instead (see PrintingEnabled). The View page source shortcut and menu show `DevToolsPolicyDialog` (`chrome/browser/ui/browser_command_controller.cc:942-951`); per the YAML, a typed `view-source:` URL is blocked only when `view-source:*` is in `URLBlocklist`. `chrome.debugger` attaches are refused too (`chrome/browser/extensions/api/debugger/debugger_api.cc:594-598`). Source-read, not runtime-tested |
| DnsOverHttpsMode | ✅ | cr78 | string enum | off / automatic / secure | browser-wide. Stock Chromium forces DoH **off** whenever this key is unmanaged on a machine that is domain-joined or carries *any* machine-level policy (156.0.8078.48 `chrome/browser/net/stub_resolver_config_reader.cc:245-271`) — every SlimBrave machine once it writes its first key. brave-core overrides that (`chromium_src/chrome/browser/net/stub_resolver_config_reader.cc:166-168`), so **Not managed** keeps Brave's own automatic DoH; the companion YAML patch only drops ChromeOS metadata. On Windows with Brave VPN connected over IKEv2 and its DNS helper not live, Brave forces secure DoH to `chrome.cloudflare-dns.com` unless this key is managed or already `secure`; managed and not `secure`, it shows a policy-warning dialog instead (`browser/brave_vpn/dns/brave_vpn_dns_observer_service_win.cc:175-198`). So a managed `automatic` (the Balanced Privacy, Performance Focused and Developer presets) or `off` stops Brave VPN forcing secure DoH there: `ShouldOverride` returns false for any managed mode (`chromium_src/chrome/browser/net/stub_resolver_config_reader.cc:32-44` at `v1.98.64`), and `kBraveVPNDnsProtection`, which gates the override, is on by default (`components/brave_vpn/common/features.cc:29-30`). WireGuard skips this path; Brave Origin has no VPN |
| DnsOverHttpsTemplates | ✅ | cr80 | string | URL template | browser-wide. **Required** for `secure` and `custom`, optional for `automatic` (unset = Chromium's upgrade of the system resolver; Brave's fallback provider hook, off on Release, appends `https://brave.cloudflare-dns.com/dns-query` on Beta and Nightly via the Griffin study `BraveFallbackDoHStudy`, which `ChromeVariations` 1 or 2 filters out), ignored for `off`. `secure` with an empty or unparseable template destroys name resolution: no secure transaction is possible and the system-resolver fallback is gated on `secure_dns_mode != kSecure` (156.0.8078.48 `net/dns/host_resolver_manager.cc:1366-1370`). All three scripts refuse an empty template for `custom`/`secure`; only `SlimBrave.ps1` also refuses a non-https or unparseable one (`Test-DohTemplate`), and the Python scripts also write a template with `automatic` (see What the project does) |
| PasswordLeakDetectionEnabled | ✅ | cr79 | bool | false | lock only: Brave defaults `profile.password_manager_leak_detection` to false (`browser/brave_profile_prefs.cc:268-271`) and hides the settings switch (`browser/resources/settings/br/security_page.ts:50-58`); the copy on upstream's bundled security page would show if the off-by-default `kBundledSecuritySettings` turned on, locked when the key is set. The key locks off the online breach-list check Chromium runs on credentials after a successful sign-in and on saved logins edited in the Password Manager (`leak_detection/leak_detection_check_impl.cc:225-237` at 156.0.8078.48) |
| NetworkPredictionOptions | ✅ | cr38 | int enum | 2 (never predict) | lock only (at 2) — 0 = always, 2 = never (1 deprecated, read as 0). Brave defaults `net.network_prediction_options` to 2 (`browser/brave_profile_prefs.cc:253-257`) and clears any user value on every profile load (`chromium_src/chrome/browser/prefs/browser_prefs.cc:154`), so only Brave Sync restoring a value (the pref is syncable, 156.0.8078.80 `chrome/browser/preloading/preloading_prefs.cc:17-20`), an extension with the `privacy` permission setting `chrome.privacy.network.networkPredictionEnabled` to true (stored as 1, standard preloading, in the extension pref store, which outranks the user store and which the clear does not touch: 156.0.8078.80 `chrome/browser/extensions/pref_mapping.cc:56-57`, `components/prefs/pref_service.cc:344-352`) or a policy of 0 or 1 turns prediction on; Brave has no Preload pages toggle (it deletes the Performance page, `browser/resources/settings/brave_routes.ts:142-145`). Brave never runs the loading predictor whatever the value (`rewrite/chrome/browser/predictors/loading_predictor_config.cc.yaml`: no learned preconnects, `dns-prefetch`/`preconnect` hints or pointer-down preconnects) and never prerenders: the plaster ships `kPrerender2` off (`rewrite/third_party/blink/renderer/platform/runtime_enabled_features.json5.yaml:133-136`), and `PrerenderHostRegistry` rejects every prerender while it is off (156.0.8078.80 `content/browser/preloading/prerender/prerender_host_registry.cc:587-592`). What the pref still gates: speculation-rules prefetch, `<link rel=prerender>` NoStatePrefetch, the address bar's search-result prefetch and the default-search-engine preconnector (156.0.8078.48 `chrome/browser/navigation_predictor/search_engine_preconnector.cc:319-340`), which also needs search suggestions on (see SearchSuggestEnabled). The key adds the in-session lock and outranks Sync and extensions |
| PaymentMethodQueryEnabled | ✅ | cr80 | bool | false | with the pref off Chromium stops consulting payment apps: `canMakePayment()` always resolves **true** (a deliberate lie, so a site must call `show()`) and `hasEnrolledInstrument()` false, so neither reveals saved methods; Secure Payment Confirmation exempt (156.0.8078.48 `components/payments/content/payment_request.cc:717-733,754-767`). The YAML's "no payment methods are available" does not match the code |
| DefaultNotificationsSetting | ✅ | cr10 | int enum | 1 or 2, user-selected; key omitted when Not managed | 1 = allow, 2 = block, both offered. 3 = ask is legal but not offered. The managed default outranks every per-site rule (see Cross-cutting, Content-setting enums), so the Allow a prompt writes to the pref provider (156.0.8078.80 `components/permissions/permission_context_base.cc:883-887`) is never read. Both display paths need GRANTED (`content/browser/notifications/blink_notification_service_impl.cc:174,325`), so under a managed 3 no site can show a notification. Not managed is Brave's normal Ask (`components/content_settings/core/browser/content_settings_registry.cc:158-159`; brave-core does not re-register it). An imported 3 is left unmanaged and named, and a 3 read back from the policy shows as Not managed. Source-read, not runtime-tested |
| DefaultGeolocationSetting | ✅ | cr10 | int enum | 1, 2 or 3; omitted when Not managed | full legal enum 1 = allow, 2 = block, 3 = ask; choice row. 3 works per request: after a prompt Allow, the connection is bound and GRANTED returned (156.0.8078.80 `content/browser/geolocation/geolocation_service_impl.cc:180-246`). But no answer is remembered (see Cross-cutting, Content-setting enums), and Blink drops the connection after each one-shot fix and whenever the tab is hidden (`third_party/blink/renderer/core/geolocation/geolocation.cc:655-660,722-726,777-781,784-795`), so the next request prompts again. Any managed value overrides per-site location settings. `kApproximateGeolocationPermission`, whose delegate would merge one-time grants, is off on desktop (`components/content_settings/core/common/features.cc:42-47`). Source-read, not runtime-tested |
| DefaultSensorsSetting | ✅ | cr88 | int enum | 1, 2 or 3; omitted when Not managed | motion/orientation sensors, a fingerprinting vector; full legal enum 1 = allow, 2 = block, 3 = ask. "3 = ask" holds in Brave only because brave-core force-enables `kSensorsAllowAskBlockPermissionModel` (`rewrite/services/device/public/cpp/device_features.cc.yaml:18-21`): the dedicated `DefaultSensorsSettingPolicyHandler` rewrites 3 to **Allow** when that flag is off (156.0.8078.48 `chrome/browser/policy/default_sensors_setting_policy_handler.cc:30-41`), which is Chromium's code default; Brave compiles out the field-trial testing config that turns it on upstream. Brave also re-registers SENSORS with default **Block** (brave/brave-browser#4789; `chromium_src/components/content_settings/core/browser/content_settings_registry.cc:286-291`), so Not managed in Brave is block-by-default-but-user-changeable. 2 is therefore belt and braces: the managed default is a wildcard `PolicyProvider` rule (156.0.8078.80 `components/content_settings/core/browser/content_settings_policy_provider.cc:703-715`) that outranks the user's choice and per-site allows, earlier ones included. A policy file with 3 taken to a Chromium where the flag is off means Allow |
| ExtensionInstallBlocklist | ✅ | cr86 | list | `["*"]` | blocks all installs and disables (does not uninstall) already-installed extensions, themes and apps included; component extensions (Brave's and Chromium's built-ins) and shared modules are exempt (`StandardManagementPolicyProvider::UserMayLoad`, 156.0.8078.48 `chrome/browser/extensions/standard_management_policy_provider.cc:111-119`); also refuses extensions passed with `--load-extension` or `--disable-extensions-except` before they load (`UnpackedInstaller::LoadFromCommandLine` → `IsLoadingUnpackedAllowed`, 156.0.8078.80 `extensions/browser/unpacked_installer.cc:165-168,353-362`) |
| BrowserGuestModeEnabled | ✅ | cr38 | bool | false | guest windows are an off-the-record session with no saved history and none of the main profile's extensions, which `IncognitoModeAvailability` = 1 does not close (156.0.8078.48 `chrome/browser/prefs/incognito_mode_prefs.cc:95-97`); machine policies still apply inside them (`chrome/browser/policy/profile_policy_connector.cc:521-525`). Dedicated `GuestModePolicyHandler`, Win/Mac/Linux only; Brave's menu honours it (`browser/ui/brave_browser_command_controller.cc:355-365`); browser-wide |
| AllowDeletingBrowserHistory | ✅ | cr57 | bool | false | unguarded simple map into `history.deleting_enabled` (factory `:505-507`, after the `!IS_ANDROID` block that ends at `:504`, at 156.0.8078.80); per-profile, applied live; YAML blob `844ec70095` unchanged through 157.0.8103.30 and main. With `false` the remover skips history and downloads (`chrome/browser/browsing_data/chrome_browsing_data_remover_delegate.cc:401-416`), which covers Clear browsing data and `ClearBrowsingDataOnExitList` (the YAML: that policy does not take precedence); the Downloads page refuses removal (`chrome/browser/ui/webui/downloads/downloads_dom_handler.cc:491,543`), `BrowsingHistoryService::RemoveVisits` refuses the History page and the Forget-me cleaner (`components/history/core/browser/browsing_history_service.cc:403-409`), and Brave's clear-on-exit skips both types (`browser/browsing_data/brave_clear_browsing_data.cc:71-79` at `v1.98.64`). **It does not keep history for review:** Brave's Local history retention dropdown (`brave.history.retention_days`, 1 day to forever, default 90; `browser/brave_profile_prefs.cc:469`, `browser/resources/settings/brave_privacy_page/brave_personalization_options.html:40-43`) sets the expiry threshold (`chromium_src/components/history/core/browser/history_service.cc:37-52`), is not gated on this pref, and no policy maps it (What's next); the YAML adds that the files can be deleted on disk. Machine-wide like every row, so a parent's own profile loses deletion too |
| HighEfficiencyModeEnabled | ✅ | cr108 | bool | true | forces Memory Saver tab discarding on; browser-wide, applied live. `MemorySaverPolicyHandler` sets `performance_tuning.high_efficiency_mode.state` (156.0.8078.48 `chrome/browser/performance_manager/user_tuning/memory_saver_policy_handler.cc:32-36`), applied with no feature gate; no brave-core override of the policy and no Griffin study |
| HardwareAccelerationModeEnabled | ✅ | cr46 | bool | true / false | both states as a mutually exclusive pair (`Group = "hwaccel"`) because unset is not off: Chromium's default is on, absent means user-controlled, `false` means forced off (read once at startup, 156.0.8078.48 `chrome/browser/gpu/gpu_mode_manager.cc:47-52`); `true` only stops the user turning acceleration off — the GPU blocklist still applies. The off state is a troubleshooting lever for a faulty GPU driver, a VM or RDP session, or screen-sharing corruption, not a privacy posture — in no preset, and neither is `true`: it adds nothing on a default install, only the user writes this Local State pref, and the lock would take that lever away. Restart; browser-wide |
| EnableMediaRouter | ✅ | cr52 | bool | false | disables Cast and its LAN device discovery; restart. Brave gives the policy precedence over the `brave://settings/extensions` Media Router toggle (`chromium_src/chrome/browser/media/router/media_router_feature.cc:35-37`). Sticky: a profile created under the policy gets the managed `false` copied into `brave.enable_media_router_on_restart` (`browser/profiles/brave_profile_manager.cc:199-209`), so once the policy is removed Cast stays off until that toggle is turned back on and Brave restarted |
| ChromeVariations | ✅ | cr83 | int enum | 1 or 2 | 0 = all variations, 1 = critical fixes only, 2 = none; browser-wide. Closes the last remote-configuration channel: the Griffin seed from `variations.brave.com` that flips features in an installed browser. Maps to `kVariationsRestrictionsByPolicy`, with no brave-core override. Despite `dynamic_refresh: true` a change takes effect at the next start: studies are applied once per run (156.0.8078.48 `components/variations/service/variations_field_trial_creator.cc:717-720`). The seed is still downloaded; no fetch path reads the pref. 2 refuses every study; 1 admits only studies whose filter sets a `policy_restriction` (156.0.8078.80 `components/variations/study_filtering.cc:222-223`). At brave-variations `c73faf3` (the live seed) two do: `V8IgnitionElideRedundantTdzChecksKillSwitch`, capped at `139.*`, and `EnhancedSecurityEventFieldsWin24H2KillSwitch` (#1943; Windows 10.0.26100+, `154.*`–`158.*`, 5% of Release, all of Beta and Nightly). It turns off `kEnhancedSecurityEventFields`, whose only reader adds the device FQDN and network name to DM-token cloud-reporting uploads (156.0.8078.80 `components/policy/core/common/cloud/reporting_job_configuration_base.cc:66-70`), so it does nothing without cloud management: 1 applies it as 0 does, 2 refuses it, and otherwise the two are equivalent. **Cost** (brave-core lines at `v1.98.64`): Griffin is also how Brave ships protections and fixes its code leaves off, and both values refuse them. `WebGLBalancedFingerprintingProtection` (100% of Release; off in code on every branch, `chromium_src/third_party/blink/common/features.cc:36-37`): at Standard fingerprinting, pages read the unmasked WebGL vendor/renderer and extension list and the WebGPU adapter info (`webgl_rendering_context_base.cc:58-61`, `webgpu/gpu_adapter.cc:37-40`), and no policy value restores it. `BraveCopyCleanLinkFromJsStudy`: URLs that sites write to the clipboard keep their tracking parameters (`browser/brave_content_browser_client.cc:1712`). `BTMGoogleAuthWorkaround`: Chromium's bounce-tracking mitigation runs with its default `bounce` trigger (156.0.8078.80 `content/public/common/content_features.cc:316,353-354`, no brave-core override) and may sign users out of Google (brave-variations#1504, #1577; brave-browser#50411, open; source-read, check in What's next). `brave://flags/#brave-webgl-balanced-fingerprinting-protections` and `#brave-clean-link-js-api` restore the first two. **Code defaults kept:** Focus Mode is offered to every desktop user (`BraveFocusModeStudy` hides it from 75% of Release). On macOS, session cookies are dropped at a normal relaunch even with session restore (`BraveCleanupSessionCookiesOnSessionRestore`; `chromium_src/chrome/browser/profiles/profile_impl.cc:34-46`). **Buys:** both refuse `TransitionToUpstreamHttpsUpgrade` (keeps `DefaultBraveHttpsUpgradeSetting` enforced), `BraveAdsObliviousHttpStudy` (the `hpkekeyconfig` fetch, until brave-core#40666 ships in 1.101), `CaptchaMetricsCollectionStudy` and `FingerprintInputMetrics` (local collection that `BraveP3AEnabled` leaves running), and `EmailAliasesStudy_Release` and `WaybackMachineAutoShowBubble`. Only Maximum Privacy carries 1, because it is what enforces that preset's strict HTTPS; 2 is in no preset because it also refuses critical kill switches. Two mutually exclusive rows |
| SpellCheckServiceEnabled | ✅ | cr22 | bool | false | lock only — already off in Brave with no UI to turn it on: Chromium registers `spellcheck.use_spelling_service` false, Brave re-asserts it (`chromium_src/chrome/browser/profiles/pref_service_builder_utils.cc:27-29`), both settings controls are `_google_chrome`-only, and Brave stubs out the context-menu opt-in. The key locks the Google spelling web service off, even against a stored `true`, while offline dictionaries keep working; it has no effect once `SpellcheckEnabled` is false, hence the mutual exclusion |
| RemoteDebuggingAllowed | ✅ | cr93 | bool | false | blocks `--remote-debugging-port` / `--remote-debugging-pipe`, the CDP cookie-theft vector `DeveloperToolsAvailability` leaves open, and the listener the `brave://inspect` remote-debugging toggle starts: `RemoteDebuggingServer::GetInstance` returns `kDisabledByPolicy` before any of them starts (156.0.8078.48 `chrome/browser/devtools/remote_debugging_server.cc:337-340`). Google Chrome also refuses both switches on the default profile, but only under `GOOGLE_CHROME_BRANDING` (`:169-180`), which Brave never sets, so this key is Brave's only lock. Breaks Puppeteer, Playwright and that toggle; local-tab inspection keeps working. Browser-wide; no restart: set false at runtime, the server and pipe stop (`chrome/browser/browser_process_impl.cc:1107-1124`). Lifting it starts nothing until the toggle is turned back on or the browser relaunched |
| BasicAuthOverHttpEnabled | ✅ | cr88 | bool | false | refuses HTTP Basic auth over cleartext: `HttpAuthHandlerBasic::Factory` returns `ERR_UNSUPPORTED_AUTH_SCHEME` for a challenge from any `http` origin (156.0.8078.48 `net/http/http_auth_handler_basic.cc:128-132`), including a plain-HTTP proxy, so Basic-authenticated `http://` proxies stop working too; HTTPS proxies and the other auth schemes are untouched. Breaks legacy plain-HTTP appliance logins; browser-wide |
| DefaultWebUsbGuardSetting | ✅ | cr67 | int enum | 2 or 3; omitted when Not managed | **2 = block, 3 = ask — no value 1** in the schema, so the row offers Not managed / Ask / Block. Ships enabled in Brave. Breaks Ledger/Trezor web wallets and in-browser firmware flashers |
| DefaultSerialGuardSetting | ✅ | cr86 | int enum | 2 or 3; omitted when Not managed | 2 = block, 3 = ask, no 1; breaks in-browser microcontroller tooling |
| DefaultWebHidGuardSetting | ✅ | cr100 | int enum | 2 or 3; omitted when Not managed | 2 = block, 3 = ask, no 1; may break security keys and gamepad configurators that use WebHID rather than WebAuthn. Block also cuts Brave Wallet's own Ledger connection (source-read): the wallet's ledger bridge uses `TransportWebHID`, `HidService` checks the guard against the wallet's `chrome://` origin (156.0.8078.48 `content/browser/hid/hid_service.cc:439-443`) and Brave's HID overrides run only after that check (`browser/hid/brave_hid_delegate.cc:22-53`), so `requestDevice` and `getDevices` come back empty. The device-API set is USB+Serial+HID because WebBluetooth and File System Access are already feature-disabled in Brave (see Considered and rejected) |
| DefaultLocalFontsSetting | ✅ | cr103 | int enum | 2 or 3; omitted when Not managed | 2 = block, 3 = ask, no 1; `queryLocalFonts()` returns the installed font list, a top-tier fingerprint that Shields' farbling does not cover |
| DefaultWindowManagementSetting | ✅ | cr111 | int enum | 2 or 3; omitted when Not managed | 2 = block, 3 = ask, no 1; stops sites reading the multi-monitor topology. Complementary to `kBraveBlockScreenFingerprinting` (on by default on desktop), which gives `window.screen` one synthetic screen but leaves `getScreenDetails()` listing every real display (156.0.8078.48 `third_party/blink/renderer/modules/screen_details/screen_details.cc:22`) |
| DefaultClipboardSetting | ✅ | cr103 | int enum | 2 or 3; omitted when Not managed | 2 = block, 3 = ask, no 1 in the schema. `CLIPBOARD_READ_WRITE`'s `valid_settings` include Allow (156.0.8078.80 `components/content_settings/core/browser/content_settings_registry.cc:351-355`), so a 1 would apply as a managed Allow; the row offers and imports only 2 and 3 (see Cross-cutting). It is the managed default of `CLIPBOARD_READ_WRITE` (factory `:342-344`, policy provider `:376-377`), the permission behind async `read()`/`readText()` and unsanitized writes. Sanitized writes use `CLIPBOARD_SANITIZED_WRITE`, and a read during the user's own paste is granted without the permission (`third_party/blink/renderer/modules/clipboard/clipboard_promise.cc:56-58,764-794`), so Ctrl+V, the context-menu Paste and copy buttons keep working; Block breaks Paste buttons inside web apps. While set it overrides the user's per-site exceptions (`components/content_settings/core/browser/content_settings_policy_provider.cc:270-279`): under 3 a site allowed earlier prompts again. `chrome://` (Brave's `brave://` pages) is allowlisted and answered Allow before any provider is read (`content_settings_registry.cc:353`, `components/content_settings/core/browser/host_content_settings_map.cc:1083-1101`), so Brave Wallet's paste buttons (`select_address_modal.tsx:479`, `recovery-input.tsx:77`) keep working. brave-core leaves the path alone at `v1.98.64`: only the Android site-settings bridge and the indicator-list patch name it. YAML identical at 157.0.8103.30 and main. In no preset |
| AudioCaptureAllowed | ✅ | cr25 | bool | false | desktop only (factory `:610-612`, in the `!IS_ANDROID` branch `:585-657` at 156.0.8078.80) into `hardware.audio_capture_enabled`; applies live, read on every request. `false` makes `GetDevicePolicy` return `ALWAYS_DENY` (`chrome/browser/media/webrtc/media_stream_device_permissions.cc:47-52`), which `MediaStreamDevicePermissionContext` answers with Block before it reads the content setting (`media_stream_device_permission_context.cc:111-117`, content setting at `:124-128`): no prompt, and per-site Allow exceptions, earlier grants included, stop applying. Extension pages get the same denial from the devices controller's status check (`components/webrtc/media_stream_devices_controller.cc:96-123`); platform apps are refused in `chrome/browser/media/extension_media_access_handler.cc:94-100`. Only `AudioCaptureAllowedUrls` matches are exempt (a bare `*` is ignored, `:37-40`); not written. `true` equals unset (`:47-50`), hence a checkbox, not a choice row. Screen and tab capture are not gated: their access handlers read neither pref. No brave-core override, no Griffin study. Breaks every web call, so in no preset |
| VideoCaptureAllowed | ✅ | cr25 | bool | false | desktop only (factory `:910-912`, in the `!IS_ANDROID` block `:765-943` at 156.0.8078.80) into `hardware.video_capture_enabled`; applies live. Same path as `AudioCaptureAllowed`: the camera context picks `prefs::kVideoCaptureAllowed` (`media_stream_device_permission_context.cc:98-101`) and answers `ALWAYS_DENY` with Block before the content setting (`:111-117`), so no prompt and per-site Allow exceptions stop applying; extension pages likewise, platform apps in `extension_media_access_handler.cc:101-107`. Only `VideoCaptureAllowedUrls` matches are exempt (a bare `*` is ignored); not written. Covers every video input, not just the built-in camera (YAML). `true` equals unset, hence a checkbox. No brave-core override, no Griffin study. Breaks web video calls, so in no preset |
| BlockExternalExtensions | ✅ | cr80 | bool | true | closes the sideload channel bundleware uses: with the pref set, none of the registry or drop-in providers is registered (156.0.8078.48 `chrome/browser/extensions/external_provider_impl.cc:876-916`). On Windows that is Chromium's hard-coded `Software\Google\Chrome\Extensions` key (HKLM 32-bit view and HKCU), which brave-core does not repoint, so a sideload registered for Chrome also reaches Brave; on macOS and Linux the `external_extensions.json` / `<id>.json` drop-ins. Unmanaged, such extensions arrive disabled behind an approval prompt on Windows and macOS and install silently on Linux; with the policy they never load, and any already installed that way, approved or not, is uninstalled at the next launch (`chrome/browser/extensions/external_provider_manager.cc:160-167,174-203`). User-chosen extensions keep working, unlike `ExtensionInstallBlocklist: ["*"]`; restart |
| ExtensionInstallTypeBlocklist | ✅ | cr120 | list | `["command_line"]` | Brave's only lock on `--load-extension`. Google Chrome ignores the switch; a build without `GOOGLE_CHROME_BRANDING` honours it unless Enhanced Safe Browsing is on or this list holds `command_line` (156.0.8078.80 `chrome/browser/extensions/extension_service.cc:162-176,420-440`), and brave-core makes `IsEnhancedProtectionEnabled()` return false (`chromium_src/components/safe_browsing/core/common/safe_browsing_prefs.cc:8` at `v1.98.64`; the same on `1.99.x`, `1.100.x` and master). Factory `:2413-2419` (`ENABLE_EXTENSIONS`, Win/Mac/Linux); no brave-core reference, no Griffin study. Checked once, when the profile's extensions load at startup. Does not cover `--disable-extensions-except`, which still loads an unpacked extension from a path (`extension_service.cc:376,441-448`) because `kDisableDisableExtensionsExceptCommandLineSwitch` is on only in Google Chrome builds (`extensions/common/extension_features.cc:214-220`; brave-core's feature rewrite leaves it alone). Only `ExtensionInstallBlocklist: ["*"]` refuses both, which is why Strict Parental Controls does not carry this key. The check sits under `TODO(crbug.com/401529219)` (see What's next). Per-profile; restart |
| LocalNetworkAccessBlockedForUrls | ✅ | cr139 | list | `["*"]` | per profile, applied live; YAML byte-identical at 156.0.8078.80 and 157.0.8103.30, pref mapping `profile.managed_local_network_access_blocked_for_urls` at both and on main. The content-settings policy provider maps the list to BLOCK for both LNA permissions, `LOCAL_NETWORK` and `LOOPBACK_NETWORK` (156.0.8078.80 `components/content_settings/core/browser/content_settings_policy_provider.cc:171-183`), a policy rule that outranks per-site exceptions, so `StoragePartitionImpl::OnLocalNetworkAccessPermissionRequired` answers denied without a prompt (`content/browser/storage_partition_impl.cc:2215-2300`); LNA has no omnibox indicator (`chrome/browser/ui/content_settings/content_setting_image_model.cc`), so a page just gets failed requests or a frame error page. LNA gates only public-to-local/loopback requests, local and loopback collapsed (`services/network/local_network_access_checker.cc:151-157`, `services/network/public/cpp/ip_address_space_util.cc:418-423`): pages served from a LAN or loopback address, and `file://` (`:436-438`), are unaffected, and main-frame navigations are not checked (`kLocalNetworkAccessForNavigations` off, `content/common/features.cc:444-445`). Covers fetches, subframes and workers (`:426,463-464`), WebSockets and WebTransport, not WebRTC (`services/network/public/cpp/features.cc:218-225,232-233,254-263`; WebRtcIPHandling covers that side). Brave's default is the per-site prompt (both types registered `ASK`, `components/content_settings/core/browser/content_settings_registry.cc:781-797`), with the checks on and no brave-core override of the checker, the permission types or the provider's LNA entries; while LNA blocks, Brave badfilters its own third-party localhost Shields rules (`components/brave_shields/content/browser/ad_block_service.cc:244-253`, `ad_block_localhost_filters_provider.cc:18-26` at `v1.98.64`) and clears its obsolete `brave_localhost_access` setting (`components/content_settings/core/browser/brave_content_settings_pref_provider.cc:57`); Griffin's only LNA study, `PrivateNetworkAccessKillswitch`, is capped at `125.*`. Brave's Site settings offer the same block, unlocked ("Don't allow sites to access other devices on your local network", `app/settings_strings.grdp:3063-3064`). Breaks public web apps that talk to LAN devices or localhost helpers: hosted media-server UIs, cloud setup pages for routers, printers and hubs, hardware-wallet bridges on 127.0.0.1, hosted dev tools. The cr146 `LocalNetwork*` / `LoopbackNetwork*ForUrls` lists take precedence if an admin sets them (YAML). In no preset |
| XSLTEnabled | ✅ | cr146 | bool | false | per profile; dynamic per YAML, but read into a renderer only at its launch: `ChromeContentBrowserClient` appends `--xslt-enabled-policy=false` to each new renderer while the pref is managed (156.0.8078.80 `chrome/browser/chrome_content_browser_client.cc:3037-3043`; brave-core calls the parent first, `browser/brave_content_browser_client.cc:1158-1162` at `v1.98.64`), and XSLT is no process-suitability criterion (JIT and optimizer state are, `content/browser/renderer_host/render_process_host_impl.cc:4963-4970`), so running renderers, which new tabs may reuse, keep XSLT until restart. `XSLTProcessor::IsXSLTEnabled` reads the switch ahead of the CAP-alert exception, Finch and the deprecation origin trial (`third_party/blink/renderer/core/xml/xslt_processor.cc:96-109`), and both `XSLTProcessor` and `xml-stylesheet` processing instructions go through it (`third_party/blink/renderer/core/dom/processing_instruction.cc:79,322`). XSLT is `status: "stable"` at 156.0.8078.80 and 157.0.8103.30 (`third_party/blink/renderer/platform/runtime_enabled_features.json5:7623-7629`, `:7819-7825`); no brave-core override (its runtime-features patch touches only `XSLTSpecialTrial` as context, and XSLT is not in `kBraveDisabledTrialNames`, `chromium_src/third_party/blink/common/origin_trials/origin_trials.cc:26-38`), no Griffin study. Chromium 158 turns XSLT off by default "other than via deprecation trial and enterprise policy" (`61634354c2`, in 158.0.8127.7); the trial allows third-party and insecure tokens, so from then `false` blocks trial origins and CAP alerts only. libxslt is `Security Critical: yes` (`third_party/libxslt/README.chromium`). YAML: temporary, "will be removed in M176" at 157.0.8103.30 and main (M164 at 156). Breaks XSLT-styled RSS/Atom feeds, sitemaps, CAP alerts and legacy XML portals. Maximum Privacy |
| DefaultJavaScriptOptimizerSetting | ✅ | cr133 | int enum | 2 (block) | 1 = allow, 2 = block; per profile; applies to tabs opened after the change: the decision is cached per BrowsingInstance and origin (156.0.8078.80 `content/browser/site_info.cc:149-176`) and is a process-suitability criterion (`content/browser/renderer_host/render_process_host_impl.cc:4968`). The managed default is a policy wildcard rule that outranks per-site exceptions (`components/content_settings/core/browser/content_settings_policy_provider.cc:703-715`), so `AreV8OptimizationsEnabledForSite` is false for every web-safe scheme (`chrome/browser/chrome_content_browser_client.cc:8305-8369`; `brave://` pages keep the optimizers) and the renderer gets `--disable-optimizing-compilers` (`render_process_host_impl.cc:3818-3825`): JavaScript on Ignition and Sparkplug, WebAssembly on Liftoff without tier-up (V8 `c9b3cfca` `src/flags/flag-definitions.h:924-942`). Brave ships it as the user setting "JavaScript optimization & security" ("Reduces performance but makes Brave more resistant to attacks", `app/brave_strings.grd:2693-2694` at `v1.98.64`). Upstream's automatic block on unfamiliar sites needs Enhanced Safe Browsing or `kMigrateToBlockV8OptimizerOnUnfamiliarSites` (`chrome/browser/site_protection/site_familiarity_utils.cc:107-150`), both off in Brave (`chromium_src/components/safe_browsing/core/common/safe_browsing_prefs.cc:8`), and no policy value selects it. `BraveContentBrowserClient::IsJitDisabledForSite` defers upstream (`browser/brave_content_browser_client.cc:1787-1800`), except that with `brave://flags#brave-v8-jitless-mode` on (`kBraveV8JitlessMode`, off by default, no study) it escalates this row to full jitless and WebAssembly disappears. No brave-core override of `JAVASCRIPT_OPTIMIZER`, no Griffin study. Upstream registers a shield-glyph "JavaScript optimizations are disabled" page action, shown wherever optimizers are off, whose bubble says the site's setting is managed (`chrome/browser/ui/browser_actions.cc:803-829`, `chrome/browser/ui/views/js_optimization/js_optimizations_page_action_controller.cc:68-74,100-108`); brave-core does not touch it; rendering in Brave not runtime-checked (What's next). Script-heavy pages run slower; no per-site escape short of unticking. Maximum Privacy only |
| ExternalProtocolDialogShowAlwaysOpenCheckbox | ✅ | cr79 | bool | false | desktop (factory `:2096-2098`, in the `!IS_ANDROID && !IS_CHROMEOS` block `:2045-2132` at 156.0.8078.80) into `external_protocol_dialog.show_always_open_checkbox`; restart per YAML, but the dialog reads the pref each time it opens (`chrome/browser/ui/views/external_protocol_dialog.cc:157-169`), so the next prompt follows it. `false` drops the per-origin 'Always allow' checkbox, which Chromium calls an opt-in to relaxed security (`:159-164`). It does not revoke pairs remembered earlier: `GetBlockState` still returns `DONT_BLOCK` for them (`chrome/browser/external_protocol/external_protocol_handler.cc:441-458`), so the YAML's 'prompted each time' holds only for new pairs. In Brave that includes `mailto:`: brave-core's rewrite drops upstream's mailto fast path (`rewrite/chrome/browser/external_protocol/external_protocol_handler.cc.yaml:15-17`, `v1.98.60` through master) and brave-core#39636 (1.97) made its 'Always allow' stick (brave-browser#16927), so with `false` every mailto link prompts every time. Hardening: CIS Google Chrome benchmark L2 item 2.45 (Tenable's index). No brave-core override of the dialog or pref, no Griffin study. Opt-in, in no preset |
| SitePerProcess | ✅ | cr63 | bool | true | lock only — every site already gets its own process in Brave on desktop. `kSitePerProcess` is on by default off Android (156.0.8078.80 `chrome/common/chrome_features.cc:1700-1706`), and desktop enforces no memory threshold (`components/site_isolation/site_isolation_policy.cc:42-57`, Android only). brave-core uses `kDisableSiteIsolation` only in two browser tests (`v1.98.64`; nothing on `1.99.x` or master), and there is no Griffin study. A managed `true` appends `--site-per-process` at startup (`chrome/browser/chrome_browser_main.cc:1395-1398`; `IsEnterprisePolicyApplicable()` is true on desktop, `components/site_isolation/site_isolation_policy.cc:237-249`). `UseDedicatedProcessesForAllSites()` checks that switch before the opt-out (`content/public/browser/site_isolation_policy.cc:85-92`), so `brave://flags#site-isolation-trial-opt-out` and `--disable-site-isolation-trials` (`chrome/browser/about_flags.cc:1248-1252`) stop working. The opt-out still turns off partial-isolation extras such as isolated sandboxed iframes. `false` turns nothing off on desktop. Restart; browser-wide. Keeps `OriginKeyedProcessesEnabled` effective, since that key needs site-per-process. Maximum Privacy only |
| OriginKeyedProcessesEnabled | ✅ | cr140 | bool | true | restart, browser-wide (factory `:654-656` in the non-Android block at 156.0.8078.80; local state `site_isolation.origin_keyed_processes_enabled`). `kOriginKeyedProcessesByDefault` is off at 156.0.8078.80 (`content/public/common/content_features.cc:875`), 157.0.8103.30 and main, with no testing-config trial, no brave-core override and no Griffin study. So `true` moves Brave from one process per site to one per origin for pages that are origin-keyed agent clusters by default; sites sending `Origin-Agent-Cluster: ?0` stay site-keyed. A managed or recommended value wins (`chrome/browser/chrome_content_browser_client.cc:2749-2773`) unless `brave://flags#origin-keyed-processes-by-default` or the command line overrides the feature, so it sets a default, not a lock. The YAML is recommended-only (`can_be_mandatory: false`), but `SimplePolicyHandler` checks no level (only the schema-validating handlers do, `components/policy/core/browser/configuration_policy_handler.cc:576-582,632-638`), and upstream's pref-mapping test asserts the mandatory value (`components/policy/core/browser/policy_pref_mapping_test.cc:823-831`). Needs site-per-process (`content/public/browser/site_isolation_policy.cc:247-249`; see SitePerProcess), and does nothing if `OriginAgentClusterDefaultEnabled` is false (`chrome_content_browser_client.cc:8722-8731`). Desktop has no origin-isolation memory limit (`kOriginIsolationMemoryThreshold` is off, `components/site_isolation/features.cc:122-123`): the cost is more processes and memory. brave-core runs `OriginKeyedProcessByDefaultBrowserTest` and skips only `OriginAgentClusterBrowserTest.*` and `OriginAgentClusterDisabledBrowserTest.*`, undiagnosed (`test/filters/browser_tests.filter:3043-3044` at `v1.98.64`). Maximum Privacy only |
| NetworkServiceSandboxEnabled | ⚠️ Win/Linux only | cr96 (Win) / cr117 (Linux) | bool | true | **Windows and Linux only** (`chrome.win:96-`, `chrome.linux:117-`; the factory entry sits under a Windows/Linux guard, 156.0.8078.80 `:1988-1992`); restart, browser-wide (local state `net.network_service_sandbox`). Without it Brave's network process runs unsandboxed. `kNetworkServiceSandbox` is off by default (`sandbox/policy/features.cc:20` at 156.0.8078.80 and 157.0.8103.30), and Chrome turns it on only through the Windows-only `NetworkServiceSandboxWindows` trial (`testing/variations/fieldtrial_testing_config.json:12509-12520`). Brave never gets that trial (`disable_fieldtrial_testing_config = true`, `build/args/brave_defaults.gni:11` at `v1.98.64`), and there is no brave-core override (`v1.98.64`, `1.99.x`, master) or Griffin study. The managed value decides (`chrome/browser/net/system_network_context_manager.cc:292-297`; content applies it, `content/browser/service_host/service_process_host_impl.cc:33-35`), with three exceptions. After a failed sandboxed launch or a crash before IPC, it runs unsandboxed until the next Chromium major (`system_network_context_manager.cc:260-266,396-406,410-442`). It is ignored on Windows on ARM and before 10 20H1 (`sandbox/policy/features.cc:138-162`). On Linux it is off for good once any server sends `WWW-Authenticate: Negotiate`: the default `AuthSchemes` includes `negotiate` (`system_network_context_manager.cc:724-725`), and the first challenge sets `net.received_http_auth_negotiate_headers`, which nothing clears (`services/network/network_context.cc:679-686`; `system_network_context_manager.cc:610-614,279-283`). macOS always sandboxes it (`sandbox/policy/features.cc:166-168`). The installer grants the AppContainer ACL the sandbox needs (`chrome/installer/setup/install_worker.cc:991-1000`; brave-core keeps it by including the upstream file at `chromium_src/chrome/installer/setup/install_worker.cc:215`). brave-core skips the upstream Enabled-case test on Windows (`test/filters/browser_tests-win.filter:156` at `v1.98.64`; `1faa83314f` added it as passing locally but failing on CI) and skips `NetworkServiceRestartsFailingLaunches` on all platforms (`browser_tests.filter:3241`). Not yet runtime-checked: the row ships only if `brave://sandbox` on Windows x64 shows the Network Service sandboxed (What's next, Runtime checks owed). `slimbrave-mac.py` builds the row only under `sys.platform.startswith("linux")`, as for BackgroundModeEnabled. Maximum Privacy only |
| DynamicCodeSettings | ⚠️ Windows only | cr127 | int enum | 1 (`DisabledForBrowser`) | **Windows only, and only `SlimBrave.ps1` offers it** (`chrome.win:127-`; factory `:1942-1944` inside the Windows block at 156.0.8078.80; local state `dynamic_code_settings`); restart, browser-wide. A managed `1` applies Arbitrary Code Guard (`MITIGATION_DYNAMIC_CODE_DISABLE_WITH_OPT_OUT`) to the browser process whatever `kBrowserDynamicCodeDisabled` says (`chrome/browser/chrome_browser_main_win.cc:397-427`, "Policy intentionally takes precedence over the feature"; run from `PostEarlyInitialization`, `:661-662`), except under `--single-process`, `--in-process-gpu` or `--no-sandbox`. The feature is off by default (`chrome/browser/browser_features.cc:184` at 156.0.8078.80 and 157.0.8103.30). Chrome turns it on only through the Windows `BrowserDynamicCodeDisabled` trial (`testing/variations/fieldtrial_testing_config.json:3304-3317`), which Brave never gets. brave-core's `browser_features.cc` patch and rewrite leave the feature alone, its `ChromeBrowserMainParts` shim does not override `PostEarlyInitialization` (`chromium_src/chrome/browser/chrome_browser_main.h` at `v1.98.64`), and no Griffin study touches it. The YAML warns of third-party code that must run in the browser process (certain printer drivers). Such code can fail or crash Brave, so the row is opt-in and in no preset. The Python scripts neither offer nor import it |

Every key above fetches 200 at Chromium 156.0.8078.48 and at main
`7b96745f7dfb` (158.0.8123.0), and all 61 YAML files are byte-identical
between the two except `XSLTEnabled`'s, whose text moves the policy's
removal from M164 at 156 to M176 at 157.0.8103.30 and main, and
`AudioCaptureAllowed`'s, to which main adds `android:157-`; none is
upper-bounded or `future_on:`-only on desktop at
either ref, and each has a `pref_mapping/<Key>.json` that does not say
`Policy was removed` at either. Two are `deprecated: true` at the tag, so in
every channel (Release `1.98.x`, Beta `1.99.x` and Nightly master all pin
156.0.8078.48): `AutofillAddressEnabled` and `AutofillCreditCardEnabled`
("deprecated in M156, please use AutofillSettings", `34ae451dfc`). Their
`supported_on` stays uncapped and `autofill::AutofillSettingsPolicyHandler`
(factory `:2656-2657`, unguarded) still maps both to their prefs
(`components/autofill/core/browser/permissions/autofill_policy_handler.cc:95-111`
at the tag, unchanged on main, which changes only the `AutofillSettings`
schema strategy at `:70`), while their successor `AutofillSettings` is
`chrome.*:154-` and dispatched by the same handler but feature-off:
`kAutofillEnableAutofillSettingsEnterprisePolicy` is
`FEATURE_DISABLED_BY_DEFAULT` (`components/autofill/core/common/autofill_features.cc:714-715`
at the tag, `:737-738` on main), with no brave-core override and no Griffin
study (see AutofillAddressEnabled). `SafeBrowsingExtendedReportingEnabled` is
not among them: at the tag its YAML is `deprecated: true` and capped at
`chrome.*:66-144` ("no effect starting with M145"), so the cr156 schema omits
it (see Version gating), the factory registers no handler for it and there is
no `pref_mapping/SafeBrowsingExtendedReportingEnabled.json` at the tag or on
main (see Considered and rejected). The 27 Brave YAMLs the scripts write are
byte-identical across `v1.98.60`, `v1.98.61`, `1.99.x` (`22cd59b84`) and
master (`1e6f00267`). Every Chromium-inherited key is cr111 or older except
`ExtensionInstallTypeBlocklist` (cr120), `DynamicCodeSettings` (cr127),
`DefaultJavaScriptOptimizerSetting` (cr133),
`LocalNetworkAccessBlockedForUrls` (cr139), `OriginKeyedProcessesEnabled`
(cr140) and `XSLTEnabled` (cr146), with `NetworkServiceSandboxEnabled` on
Linux from cr117, and every Brave key cr142 or older except the three
branch-probed rows (`EmailAliasesEnabled` and `PsstEnabled` cr147,
`BraveLocalAIEnabled` cr149), so all are present in any Brave still
receiving updates.

## Brave Origin on Linux

Origin is Brave with Rewards, Wallet, VPN, Leo, News and friends removed at
build time (`is_brave_origin_branded`); free on Linux, a paid upgrade on
Windows and macOS. Artifact facts are read from the shipped 1.98.60
artifacts, each equal to its GitHub release digest and to the apt, rpm and
AUR indexes: `brave-origin_1.98.60_amd64.deb` (sha256 `54a05b1c…e639`),
`brave-origin-1.98.60-1.x86_64.rpm` (`0f8577b0…56f3`) and
`brave-origin-1.98.60-linux-amd64.zip` (`39a69cf1…b6e8`). The runtime facts
— the inotify watches, an `ExtensionInstallForcelist` install, `--import` in
`chrome://policy`, the `chrome://policy/test` injection — rest on a real
1.94.121 install of the AUR zip on CachyOS. `SlimBrave.ps1` has no
Origin-specific code.

- **Origin reads `/etc/brave/policies/managed`, like regular Brave.**
  `app/brave_main_delegate.cc:166-170` (`v1.98.60`) overrides
  `chrome::DIR_POLICY_FILES` to `/etc/brave/policies` under
  `IS_POSIX && !IS_MAC` with no branding or channel guard, and Chromium's
  `config_dir_policy_loader.cc:33-36` appends `managed` and `recommended`.
  The 1.98.60 Origin ELF (byte-identical across zip, deb and rpm) holds
  `/etc/brave/policies` and no `/etc/brave-origin` string, as do the beta
  1.99.44 and nightly 1.100.7 ELFs. At runtime a running Origin watches
  `/etc/brave/policies/managed`, a managed `ExtensionInstallForcelist` there
  installed its extensions without a restart, and this tool's `--import`
  showed every key in `chrome://policy` as Platform / Machine / Mandatory / OK.
- **`/etc/brave-origin/policies/enrollment` is not a policy directory.** It is
  the installer's `ENROLLMENTDIR`
  (`chromium_src/chrome/installer/linux/common/brave-origin/chromium-browser.info:17-18`),
  created by the deb/rpm post-install only when
  `/etc/default/brave-origin[-beta|-nightly]` asks for Device Trust key
  management, and only to hold `DeviceTrustSigningKey`. The browser reads
  nothing there; Chrome Browser Cloud Management, off unless the browser is
  launched with `--enable-chrome-browser-cloud-management`, reads its token
  from `/etc/brave/policies/enrollment`. Never write policies there.
- **Where Origin lives**, every row read from the artifact (stable 1.98.60,
  beta 1.99.44, nightly 1.100.7; Nix from the derivation and Hydra's 1.97.59
  build). Brave's one-command install
  (`curl -fsS https://dl.brave.com/install.sh | FLAVOR=origin sh`) adds no
  layout of its own: apt, dnf, zypper and rpm-ostree get the repo packages
  below, pacman the CachyOS or AUR `brave-origin[-beta|-nightly]-bin`.

| Packaging | Install dir | Binary | Launcher | On `PATH` | Profile |
|---|---|---|---|---|---|
| Arch: AUR `brave-origin-bin` (CachyOS mirrors it); unpacks the upstream zip | `/opt/brave-origin-bin/` | `brave` | `brave-origin`, byte-identical to the deb/rpm launcher | `/usr/bin/brave-origin`, a bash wrapper that reads `brave-origin-flags.conf` and execs the launcher | `~/.config/BraveSoftware/Brave-Origin` |
| deb: `brave-origin`, from the same apt repo as `brave-browser`; both co-install | `/opt/brave.com/brave-origin/` | `brave` | `brave-origin` | `/usr/bin/brave-origin-stable`, shipped symlink; bare `/usr/bin/brave-origin` via `update-alternatives` | same |
| rpm: `brave-origin`, from the `brave-browser-rpm-release` repo (the CDN serves every `brave-browser*.repo` name as that one file; there is no separate Origin repo) | `/opt/brave.com/brave-origin/` | `brave` | `brave-origin` | `/usr/bin/brave-origin-stable`, shipped; bare `/usr/bin/brave-origin` via `update-alternatives` | same |
| Beta, Nightly: `brave-origin-beta`, `brave-origin-nightly` (apt/rpm beta and nightly repos; AUR `*-bin` repackage the deb) | `/opt/brave.com/brave-origin-beta/`, `…-nightly/` | `brave` | `brave-origin-beta`, `-nightly` | `/usr/bin/brave-origin-beta`, `-nightly`; each also registers the bare `brave-origin` alternative (priorities stable 201, beta 151, nightly 1 on deb; 200, 150, 0 on rpm), so without stable Origin a bare `brave-origin` is the beta, else the nightly. AUR: a wrapper, no alternative | `Brave-Origin-Beta`, `Brave-Origin-Nightly` (`common/brave_channel_info_posix.cc:33-38`) |
| Nix: nixpkgs `brave-origin` (1.98.60 on master, 1.97.59 on nixos-unstable, absent from nixos-26.05); repackages the GitHub-release deb | `/nix/store/…-brave-origin-<ver>/opt/brave.com/brave-origin/` | `brave`, only interpreter and rpath patched | the deb's launcher, wrapped | `bin/brave-origin` only, through the installing Nix profile | `~/.config/BraveSoftware/Brave-Origin` |
| Flatpak | no official one: Flathub has only `com.brave.Browser` (brave-browser#55196 asks for Origin, open). Two unofficial Flatpaks (FlatPark's `com.brave.Origin`, `jfrmorales/brave-origin-flatpak`) grant no `host-etc` and so cannot read host policy; a third, `io.github.shyvortex.BraveOrigin`, copies Flathub's `host-etc` grant and `brave.sh` and does read `/etc/brave/policies` | | | | |
| Snap | none: the store has `brave` only, which holds `opt/brave.com/brave/` and no Origin. snapd's `browser-support` grants `/etc/chromium` and nothing under `/etc/brave`, and the `brave` snap adds no plug that would (source only, not confirmed at runtime); that is the mechanism behind the tool's Snap warning | | | | |

- **Names the detector relies on.** Profile: `BraveSoftware/Brave-Origin`
  plus the channel suffix (`chromium_src/chrome/common/chrome_paths_linux.cc:26-27`).
  Package: `brave-origin` (`build/config.gni:72-80`). Desktop ids:
  `brave-origin[-beta|-nightly].desktop`, plus a `NoDisplay=true`
  `com.brave.Origin[.beta|.nightly].desktop` portal twin; `StartupWMClass` is
  the package name. Processes: the browser's comm is `brave` everywhere; the
  launcher's bash process stays alive around it (brave-core drops Chromium's
  `exec -a`) as `brave-origin`, or `brave-origin-st` (comm's 15-character
  cap) from the deb/rpm desktop file's `brave-origin-stable`; the profile's
  `SingletonLock` covers the truncated case.
- **What the tool does with it.** `LINUX_CHANNELS` carries `origin`,
  `origin-beta`, `origin-nightly` (no `origin-dev`: never published).
  `detect_brave()` probes `/opt/brave-origin-bin/brave`,
  `/opt/brave.com/brave-origin/brave-origin` and
  `/opt/brave.com/brave-origin/brave` (still the 1.98.60 layout) and, only
  when no Brave at all has turned up, `brave-origin-stable`, `brave-origin`,
  `brave-origin-beta` and `brave-origin-nightly` on `PATH`; it reports
  `arch (Brave Origin)`, `deb/rpm (Brave Origin)`, `unknown (Brave Origin)`,
  or `arch: Stable, Origin` beside a regular Brave. Beta and Nightly have no
  install-dir probe and point the bare `brave-origin` alternative at their own
  launcher, so a Beta- or Nightly-only deb or rpm install reports
  `unknown (Brave Origin)` and also gets a stable `Origin` record. Origin's
  profiles join prefs repair and the running check; `--channels` accepts the
  three ids.
- **Regular Brave in "Origin mode" is still regular Brave.** On Linux the free
  tier is one click on the Origin card at `brave://settings/system` (shown in
  non-Origin-branded builds while `kBraveOrigin`, on by default, is enabled):
  `BraveOriginService::AcceptFreeTier` (`brave_origin_service.cc:319-324`)
  records a purchase in `Local State`, and `brave://settings/origin` then
  offers the toggles. Same binary, same `Brave-Browser` profile, every feature
  compiled in. Nothing for the detector to do; every row live.
- **A managed file outranks Origin's own layer; it cannot revive what Origin
  compiled out.** Origin enforces its debloat through `BraveBrowserPolicyProvider`
  and `BraveProfilePolicyProvider`, which emit mandatory `POLICY_SOURCE_BRAVE`
  entries at `kBravePriority`, below every browser priority
  (`chromium_src/components/policy/core/common/policy_types.h:16-17`), and
  only once `IsBraveOriginPurchased()` (`brave_browser_policy_provider.cc:65-67`):
  `kBraveOrigin` plus a validated purchase or, on Linux, the accepted free
  tier, which sticks once set. Until then Origin's layer is empty and only Ad
  Block Only Mode writes `POLICY_SOURCE_BRAVE`; the branded build's startup
  dialog stands before the first window until one of the two holds. Chromium
  settles each key on (level, priority) (`policy_map.cc:684-706` at
  156.0.8078.48), so a mandatory platform entry wins every conflict:
  `{"BraveP3AEnabled": true}` would switch P3A back on in Origin. Nothing this
  tool writes points that way.
- **Thirteen rows are dead on Origin, and the tool shows them inert.** Each
  key's `brave_simple_policy_map.h` entry sits under a buildflag whose `.gni`
  is `… && !is_brave_origin_branded`: `BraveRewardsDisabled`,
  `BraveWalletDisabled`, `TorDisabled`, `BraveVPNDisabled`,
  `BraveAIChatEnabled`, `BraveLocalAIEnabled`, `BravePlaylistEnabled`,
  `BraveWebDiscoveryEnabled`, `BraveNewsDisabled`, `BraveTalkDisabled`,
  `BraveSpeedreaderEnabled`, `BraveWaybackMachineEnabled`,
  `EmailAliasesEnabled` (at `v1.98.60`, same on `1.99.x` and master). A
  fourteenth, `PsstEnabled` (`ENABLE_PSST`), is dead on Origin too; the tool
  does not write it, and exposing it would add it to `ORIGIN_BUILTIN_KEYS`.
  Confirmed on the 1.94.121 binary: injecting every Brave key as a mandatory
  machine policy through `chrome://policy/test` made none of the thirteen
  prefs managed, while `brave://policy` listed each as applied (the blind spot
  the `BraveVPNDisabled` row documents); the 1.98.60 Origin ELF holds none of
  their target pref names except `brave.rewards.disabled_by_policy`, which is
  registered unguarded and reached by no policy. `BraveP3AEnabled` and
  `BraveStatsPingEnabled` are dispatched (unguarded); once Origin counts as
  purchased its layer emits both `false`, with no toggle in the branded build,
  so a managed `false` equals what Origin applies and pins it. Origin compiles
  out the usage pinger, but the stats pref still gates referrals and
  SERP-metrics recording, so that key stays live and out of
  `ORIGIN_BUILTIN_KEYS`. `MetricsReportingEnabled` is live: Origin only
  defaults it `false`, so the user can flip it and a managed `false` pins it.
  Everything else — the five unguarded Brave privacy toggles, both Shields
  lists, the `DefaultBrave*` content settings, every Chromium key — is live.
  In the tool: `ORIGIN_BUILTIN_KEYS` in both scripts carries the thirteen;
  when every detected Brave is Origin (`is_origin_only`), `build_rows` marks
  them inert — drawn `[-]`, dimmed, `(built into Origin)`, out of the counts,
  untoggleable, never written or exported, unticked on sync so the next Apply
  drops a stale key; an import that names them reports `13 keys built into
  Brave Origin left unmanaged`. "Only Brave" is judged on the whole machine:
  every record carries the machine-wide `origin_only` verdict, so
  `--channels origin` cannot narrow a mixed machine. Under `--policy-file` the
  rows come from the override record and stay live.
- **Origin parity of the presets.** `browser/brave_origin/brave_origin_service_factory.cc`
  builds Origin's debloat set by walking `kBraveSimplePolicyMap` and keeping
  each pref in `kBraveOriginBrowserMetadata` (4) or
  `kBraveOriginProfileMetadata` (12) — sixteen prefs. Fifteen map to keys this
  project exposes, and for every one the value the project writes equals
  Origin's default (the Brave Origin preset). The sixteenth is `PsstEnabled`,
  inert on Release and Beta (see its row). Each build gets the subset its
  buildflags compile: regular Brave in Origin mode gets sixteen on Windows and
  macOS and fifteen on Linux (no VPN); the branded build keeps only P3A and
  the stats ping. De-AMP, Debouncing, query-parameter filtering, GPC, Reduce
  Language and the two Shields lists are in neither table: Origin leaves the
  five toggles at their enabled-by-default user setting, the direction the
  project forces, and the lists unset.

## Platform policy locations, from source

- **Windows** — `HKLM\SOFTWARE\Policies\BraveSoftware\Brave`. Chromium's
  policy generator emits the registry key from `CHROMIUM_POLICY_KEY` for
  non-Google branding, and brave-core's
  `chromium_src/components/policy/tools/generate_policy_source.py:11` sets it
  to `SOFTWARE\Policies\BraveSoftware\Brave`; `PolicyLoaderWin` is
  Chromium's (brave-core's connector override only appends its own
  browser-level provider). No channel or Origin suffix, so one key serves
  stable, beta, nightly and Origin: the Brave and Origin 1.98.60 `chrome.dll`
  each hold exactly one `SOFTWARE\Policies\BraveSoftware\Brave` (UTF-16LE).
  `BraveSoftware\Brave-Browser` (Origin: `Brave-Origin`) is the install and
  profile dir name, not the policy path, with one early reader: before the
  policy stack exists, crash-report consent reads `MetricsReportingEnabled`
  from `SOFTWARE\Policies\BraveSoftware\Brave-Browser` (Origin:
  `…\Brave-Origin`), HKLM then HKCU (`chrome/install_static/install_util.cc:520-541`
  at 156.0.8078.48). The browser copies the effective metrics pref into the
  updater's `usagestats` at every start, so crash consent follows this tool's
  key once Brave has run under it (at startup; after startup Brave sets
  consent false itself, see the MetricsReportingEnabled row).
  `…\BraveSoftware\Update` is the updater's
  policy key. Matches Brave's own Group Policy documentation and the 1.98.60
  `policy_templates.zip`.
- **Linux** — `/etc/brave/policies/managed`. Chromium's default is
  `/etc/chromium/policies`; brave-core `app/brave_main_delegate.cc:166-170`
  overrides `chrome::DIR_POLICY_FILES` at startup, unconditionally under
  `IS_POSIX && !IS_MAC`, and the platform loader is built only from it, so no
  Brave reads `/etc/chromium/policies`. Channel- and Origin-independent,
  confirmed at runtime on Origin. Flatpak: Flathub `com.brave.Browser`
  (1.98.60) has `--filesystem=host-etc`, and its `brave.sh` symlinks
  `/run/host/etc/brave/policies/{managed,recommended,enrollment}/*.json` into
  the sandbox's `/etc/brave/policies` before each launch; a file first created
  while Brave runs is seen only after a full quit and relaunch, and an edit to
  an already-linked file lands on the loader's 15-minute reload or at
  restart. Snap: the `brave` snap (strict confinement) gets nothing under
  `/etc/brave` from any plug, so where snapd enforces AppArmor the read should
  be denied; source only, not confirmed at runtime. The tool's Snap warning
  rests on this.
- **macOS** — `/Library/Managed Preferences/<bundle id>.plist`, bundle ids
  `com.brave.Browser`, `.beta`, `.nightly`, and for Brave Origin, a separate
  `Brave Origin.app`: `com.brave.Browser.origin`, `.origin.beta`,
  `.origin.nightly` (the shipped 1.98.60 `Brave Origin.app` carries
  `com.brave.Browser.origin`). Chromium keys the loader on the running app's
  own bundle id for non-Google branding (`chrome_browser_policy_connector.cc:332-341`
  at 156.0.8078.48), so each app and channel reads only its own id. A forced
  value is Mandatory, any other Recommended (`policy_loader_mac.mm:108-135`):
  machine-scope values come from `/Library/Managed Preferences/<bundle id>.plist`
  or a System-scope Configuration Profile, while an unforced plist under
  `/Library/Preferences` loads as Recommended. The loader watches only the
  per-user managed plist, so a machine-plist change lands on the 15-minute
  reload, `brave://policy` "Reload policies", or a restart. The ids are
  `MAC_BUNDLE_ID` in brave-core `app/theme/{brave,brave_origin}/BRANDING[.<channel>]`.
  `MAC_CHANNELS` lists only the three regular ids, so the tool neither detects
  nor writes Origin on macOS and falls back to `com.brave.Browser.plist`,
  which Origin never reads (What's next). Brave dropped the Dev channel
  (brave-browser#25248), so no Dev id belongs in `MAC_CHANNELS`.

## Cross-cutting facts

- **`ForUrls` patterns.** Brave's docs' "wildcards are not supported" means
  `*.example.com`, which the parser rejects
  (`components/content_settings/core/common/content_settings_pattern_parser.cc:126-153`
  at 156.0.8078.48). The scheme-wide `https://*` and `http://*` this tool uses
  are valid patterns, any host on any port, and apply. The policy path never
  writes them to the profile: `PolicyProvider` keeps policy content settings
  in memory and is read-only. The Shields keys reach it through brave-core's
  `rewrite/components/content_settings/core/browser/content_settings_policy_provider.cc.yaml`
  plaster (`BRAVE_SHIELDS` Block and Allow, plus the managed defaults of the
  five `DefaultBrave*Setting` keys). The
  `profile.content_settings.exceptions.braveShields` `http://*,*` /
  `https://*,*` entries the repair logic scrubs have no identified writer:
  SlimBrave-Neo#2 reported them after the Shields list was applied and
  removed, and no SlimBrave code but the repair (`80d461f`, v1.4.1) has ever
  touched content settings. The repair is a guard, not a fix for a known
  writer.
- **Ad Block Only Mode writes policies too.** With `kAdblockOnlyMode` on (the
  default on desktop since `v1.96.26`, whatever `ChromeVariations` says) and
  the user's opt-in, `BraveProfilePolicyProvider` injects thirteen values at
  `MANDATORY / USER / POLICY_SOURCE_BRAVE`
  (`components/brave_policy/ad_block_only_mode/ad_block_only_mode_policy_manager.cc:83-135`
  at `v1.98.60`): `BlockThirdPartyCookies=false`, `DefaultCookiesSetting=1`,
  `DefaultJavaScriptSetting=1`, `DefaultBraveAdblockSetting=2`,
  `DefaultBraveFingerprintingV2Setting=1`, `DefaultBraveHttpsUpgradeSetting=3`,
  `DefaultBraveReferrersSetting=1`, `DefaultBraveRemember1PStorageSetting=1`,
  and `BraveReduceLanguageEnabled`, `BraveDeAmpEnabled`,
  `BraveDebouncingEnabled`, `BraveTrackingQueryParametersFilteringEnabled`,
  `BraveGlobalPrivacyControlEnabled` all `false` — eleven of them keys this
  project writes, mostly to the opposite value. The opt-in defaults off (the
  Shields panel offers it after Shields has been switched off five times) and
  exists only in an English UI. Precedence favours this tool: `kBravePriority`
  is the lowest and Chromium compares level before priority
  (`policy_map.cc:706` at 156.0.8078.48), so a mandatory platform value wins;
  a macOS `--policy-file` under `/Library/Preferences` with `--persist off` is
  recommended and loses. With the mode on, `brave://policy` shows a conflict
  warning on each key this tool writes to a different value. Precedence
  covers only those thirteen values: the mode also limits the component
  filter lists to its own set and ignores list toggles
  (`ad_block_component_service_manager.cc:344-347,408-411`), which no policy
  overrides. Outranking an injected value helps only where the mode's other
  injections leave the reader working: its
  `DefaultBraveFingerprintingV2Setting` = 1 stops both readers of
  `BraveReduceLanguageEnabled` unless this tool writes
  `DefaultBraveFingerprintingV2Setting` = 3 too (see that row).
- **Where brave-core overrides live.** `chromium_src/`, `patches/` **and**
  `rewrite/*.yaml` coexist, and overrides move between them across branches
  (the `kSensorsAllowAskBlockPermissionModel` flip was a `chromium_src`
  override at `v1.94.121` and is a `rewrite/` plaster at `v1.98.60`). A
  `rewrite/` plaster generates its `patches/` twin, so the two are one
  override: read the plaster for intent and the patch for the exact result,
  whose `index` base blob should `git hash-object`-match the pinned Chromium
  file. A `chromium_src/` file at the same path is a separate override beside
  them. Searching one directory proves nothing.
- **Content-setting enums are not uniform.** `DefaultNotificationsSetting`,
  `DefaultGeolocationSetting`, `DefaultSensorsSetting` take 1 / 2 / 3. The
  other six permission keys list only 2 / 3 in their schema, but Chromium
  does not enforce the enum: their handlers only type-check, so a 1 reaches
  the managed pref with no error on `brave://policy`; `PolicyProvider` then
  ignores it for WebUSB, Serial and WebHID (Ask/Block only) and applies it as
  a managed Allow for `DefaultLocalFontsSetting`,
  `DefaultWindowManagementSetting` and `DefaultClipboardSetting`
  (`content_settings_registry.cc:354-355,374,384,403,534-535,544-545` at
  156.0.8078.80). This tool offers only the schema's values (for
  notifications only 1 and 2, see its row): a value outside a key's legal
  set is left unmanaged on import and named in the message, and a quoted
  `"1"` or a `true` is rejected in all three implementations. A
  fraction or exponent is not always rejected: the Python scripts accept only
  a JSON integer, but `SlimBrave.ps1` also accepts a `[double]` and rounds it
  — under PowerShell 7 `2.0`, `2e0` and `2.5`; under Windows PowerShell 5.1,
  its elevated host, only exponent forms such as `2e0`, since `2.0` and `2.5`
  arrive as `[decimal]` and are rejected (What's next). A managed
  `Default*Setting` is a Wildcard/Wildcard rule in `PolicyProvider`
  (156.0.8078.80
  `components/content_settings/core/browser/content_settings_policy_provider.cc:270-275,687-690,703-713`).
  `HostContentSettingsMap` reads it before the one-time and pref providers
  and, for these types, without merging one-time grants
  (`host_content_settings_map.cc:1133-1177`, `content_settings_info.cc:98-100`).
  So while it is set, the user's per-site exceptions for that type are
  ignored at any value, and at 3 the answer to a prompt is not remembered.
  The three device guards differ: a granted device is chooser data, not a
  guard exception. At 3, devices granted before or since keep working; at 2
  they stop (`components/permissions/object_permission_context_base.cc:103-111`;
  `chrome/browser/usb/usb_chooser_context.cc:516-524` and its HID and serial
  twins).
- **Version gating.** A key whose `supported_on` range excludes the running
  build's Chromium milestone does nothing, whether newer than that Brave or
  capped below it: the policy generator drops it from the build's schema
  (`components/policy/tools/generate_policy_source.py:129-134` at
  156.0.8078.48), so no handler exists — `SafeBrowsingExtendedReportingEnabled`
  (`chrome.*:66-144`) is not in Brave 1.98's schema. Windows and Linux still
  list such a key in `brave://policy` with the error `Unknown policy.`; the
  macOS loader reads only schema-known names, so there it is not listed. By
  milestone: cr138 (News, Talk, Speedreader, Wayback, P3A, Stats Ping, Web
  Discovery) · cr139 (Playlist) · cr140 (De-AMP, Debouncing, Reduce Language)
  · cr141 (Fingerprinting V2) · cr142 (GPC, Tracking Query Parameters, the
  other four `DefaultBrave*` enforcers) · cr147 (Email Aliases — Brave 1.92) ·
  cr149 (Local AI — Brave 1.94); every other Brave key the scripts write is
  cr121 or older. The highest Chromium-inherited milestone is `XSLTEnabled`
  at cr146.
- **Cloud-only keys never apply from a platform source.** On desktop,
  `IsPolicySupported` drops a key whose YAML sets `features: cloud_only: true`
  from every source but cloud policy, with
  `IDS_POLICY_CLOUD_SOURCE_ONLY_ERROR`, before any handler sees it
  (`components/policy/core/browser/configuration_policy_handler_list.cc:167-175`
  at 156.0.8078.80); `CloudReportingEnabled` is the one exemption (`:208`).
  Separately, a handler the factory wraps in `CloudUserOnlyPolicyChecker`
  refuses anything but user-scope cloud policy
  (`IDS_POLICY_CLOUD_USER_ONLY_ERROR`, `configuration_policy_handler.cc:957-979`)
  whatever its YAML says: `CacheEncryptionEnabled` has no `cloud_only` line
  but is wrapped (factory `:3739-3745`). Everything SlimBrave writes is
  platform policy (HKLM, the Linux JSON, plists), so neither kind can ship;
  no written key is either.

## Considered and rejected — do not add

The source is the tiebreaker in every case: the YAML, the handler registration (Chromium's or brave-core's) and the `pref_mapping` file, and for a key inert in Brave the gate that keeps it so. Each Why-not leads with the deciding fact, cites at most three files with the tag they were read at, and stays under 600 characters. Keys refused by one mechanism share a row, and a trailing-`*` prefix is used only when no written key shares it.

| Key(s) | Status | Why not |
|---|---|---|
| `EnableDoNotTrack` | ❌ | does not exist in Chromium's policy index; DNT has no enterprise policy and nothing reads the name (no YAML and no `policies.yaml` id at 156.0.8078.48 or main, no reference in brave-core `v1.98.60`). The Windows and Linux loaders pass unknown names through, so `brave://policy` lists it with the error `Unknown policy.` (`IDS_POLICY_UNKNOWN`, `policy_conversions_client.cc:496-500`); the macOS loader reads only schema keys (`policy_loader_mac.mm:118-123` at 156.0.8078.48), so there it is not listed. GPC (`BraveGlobalPrivacyControlEnabled`) is the working equivalent |
| `MediaRecommendationsEnabled` | 💀 | **dead key.** The YAML is open (`chrome.*:87-`, no cap, not deprecated) but Chromium removed the handler and the pref with Kaleidoscope in `3e5b1be4a` (2021); `pref_mapping/MediaRecommendationsEnabled.json:3` says `Policy was removed` at 156.0.8078.48 and main, and brave-core never references it. `brave://policy` validates and lists it, but it has done nothing since Chromium 89. No script or preset writes it; `SlimBrave.ps1` Apply and Reset delete a leftover `0` it wrote. The pref-mapping file is the tiebreaker |
| `SafeBrowsingExtendedReportingEnabled` | ❌ removed | removed after cr144: `deprecated: true`, capped `chrome.*:66-144` ("no effect starting with M145") at 156.0.8078.48; Chromium `63b1c79f13` deleted its factory entry and `pref_mapping` file, and brave-core re-adds none. Outside the cr156 schema (see Version gating), so a written value shows in `brave://policy` as `Unknown policy.` on Windows and Linux and is not listed on macOS. Moot anyway: `IsExtendedReportingEnabled()` returns `IsEnhancedProtectionEnabled()` (156.0.8078.48 `components/safe_browsing/core/common/safe_browsing_prefs.cc:193-196`), which brave-core forces false (`chromium_src/components/safe_browsing/core/common/safe_browsing_prefs.cc:8`). Dropped from the three scripts and the Balanced Privacy, Maximum Privacy and Developer presets in v2.3.3; `SlimBrave.ps1` Apply and Reset delete a leftover `0` it wrote. The YAML cap and the missing pref-mapping file are the tiebreaker |
| `SafeSitesFilterBehavior` | ⚠️ dispatched, inert | **filters nothing in Brave and still sends every URL to Google.** Dispatched (factory `:1146-1148`): with 1, every http(s) navigation, iframes and redirects included, is POSTed to `safesearch.googleapis.com/v1:classify` with `key=<google_apis::GetAPIKey()>` (156.0.8078.48 `components/safe_search_api/safe_search/safe_search_url_checker_client.cc:30-39`), query, fragment and credentials stripped. Brave ships no Google API key (no `google_api_key` GN arg, `build/commands/lib/buildArgs.ts:12-36` at `v1.98.60`; the 1.98.60 Linux and Windows binaries hold no `AIza` key), so the request carries Chromium's placeholder `dummytoken` and the API answers HTTP 400; the verdict is `kUnknown`, which loads and is never cached (`components/safe_search_api/url_checker.cc:111-123`): every navigation is looked up again and nothing is blocked. Only a key supplied at run time (`GOOGLE_API_KEY`, `--gaia-config`) would change that. brave-core neither overrides the path nor proxies the host. Dropped from the three scripts and the Strict Parental Controls preset in v2.3.3 (the value does not mean what the label said, and sending every URL to Google is no product reason); the preset's DNS filter does the blocking. `SlimBrave.ps1` Apply and Reset delete a leftover `1` it wrote |
| `PromotionalTabsEnabled` | ⛔ | `deprecated: true`; still dispatched with its live successor `PromotionsEnabled` (`chrome.*:128-`), both into `prefs::kPromotionsEnabled` (factory `:2829-2835` at 156.0.8078.80). Not exposed: see the `PromotionsEnabled` row |
| `IPFSEnabled` | ⛔ | see the Brave table: deprecated, feature gone since 1.69.153. On desktop the `DEPRECATE_IPFS` tombstone (`!is_android && !is_ios`) still maps it to `brave.ipfs.enabled` (`brave_simple_policy_map.h:152-155` at `v1.98.60`), a pref registered only in `RegisterProfilePrefsForMigration` so `ClearDeprecatedIpfsPrefs` can clear it at startup; nothing reads it, so a written value is accepted, flagged deprecated in `brave://policy`, and inert. Same on `1.97.x` and master |
| `PrivacySandboxAdMeasurementEnabled`, `PrivacySandboxAdTopicsEnabled`, `PrivacySandboxSiteEnabledAdsEnabled` | ⛔ dispatched, inert | `deprecated: true` (cr144), uncapped `111-`; still dispatched at 156.0.8078.48 by `PrivacySandboxPolicyHandler` (factory `:3551`) into `privacy_sandbox.m1.*` prefs nothing reads any more (the Topics and Protected Audience implementations are deleted upstream). Brave ships the APIs off regardless: its renderer sets `EnableFledge`, `EnableFencedFrames` and `EnableTopicsAPI` false (`renderer/brave_content_renderer_client.cc:125-130` at `v1.98.64`; see Re-verification procedure, step 7), and `rewrite/` disables `kBrowsingTopics` and `kConversionMeasurement` (asserted in `app/feature_defaults_unittest.cc`) |
| `PrivacySandboxFingerprintingProtectionEnabled`, `PrivacySandboxIpProtectionEnabled` | ❌ removed | removed after cr145 / cr143: `deprecated: true`, capped `140-145` / `138-143`; no handler and no pref-mapping file at 156.0.8078.48; YAMLs unchanged on main |
| `PrivacySandboxPromptEnabled` | 💀 | `deprecated: true` (prompt configuration no longer supported), uncapped `111-`, but no handler reads it and `pref_mapping/PrivacySandboxPromptEnabled.json:3` says `Policy was removed` at 156.0.8078.48 and main |
| `ComponentUpdatesEnabled` | ✅ live, harmful | **freezes the protective components, Shields' filter lists first, and lets the rest update.** An installer that opts in gets `UPDATE_DISABLED` after the update check, which still goes out, so it freezes or never installs (`update_client/component.cc:436-443` at 156.0.8078.80). Opted in: Shields' resources and filter lists (`ad_block_component_installer.cc:84-87` at `v1.98.64`), the user-agent list, NTP images, the CT log list, Root Store, Widevine and WebMCP tool scripts. Opted out: `BraveComponentInstallerPolicy` (Tor, ads resources, Local Data Files; `brave_component_installer.cc:93-96`) |
| `DefaultCookiesSetting` = 4 (session only) | ✅ live, harmful | **voids every per-site cookie rule, Shields-down included.** `4` keeps cookies only until the last window closes (156.0.8078.80 `session_data_service.cc:119-142`; factory `:973-975`), but a managed default overrides user exceptions (`content_settings_policy_provider.cc:270-275,703-715`): user and Shields cookie exceptions, the Shields-down allowance and Google Sign-In's auth exceptions stop applying (`brave_content_settings_pref_provider.cc:941-1088` at `v1.98.64`), so dropping Shields no longer fixes a broken site. Forget First-Party Storage on Close covers desktop; revisit under its trigger |
| `FeedbackSurveysEnabled`, `SafeBrowsingSurveysEnabled` | ⚠️ no-op in Brave | dispatched (`configuration_policy_handler_list_factory.cc:369-371,1037-1039` at 156.0.8078.48), but brave-core's `rewrite/chrome/browser/ui/hats/hats_service_desktop.cc.yaml:15-18` makes `HatsServiceDesktop::RunCommonLaunchChecks` always return an error (`v1.98.60`; same on `1.99.x` and master), and both `CanShowSurvey` and every launch path (`ShowSurvey` → `RunLaunchChecks`) go through it (`chrome/browser/ui/hats/hats_service_desktop.cc:433-434,644-647,712` at 156.0.8078.48); no survey ever launches |
| `BrowserNetworkTimeQueriesEnabled` | ⚠️ no-op in Brave | dispatched on desktop (`configuration_policy_handler_list_factory.cc:2093-2095` at 156.0.8078.48), but `kNetworkTimeServiceQuerying` is force-disabled in Brave on every platform (`rewrite/components/network_time/network_time_tracker.cc.yaml:6-15` and its generated `patches/components-network_time-network_time_tracker.cc.patch:9-13` at `v1.98.60`; same on `1.99.x` and master), and `ShouldIssueTimeQuery` returns on that feature (`AreTimeFetchesEnabled`) before it reads the policy pref (`components/network_time/network_time_tracker.cc:453-456,740-749` at 156.0.8078.48) |
| `DomainReliabilityAllowed` | ⚠️ no-op in Brave | `app/brave_main_delegate.cc:121` (`v1.98.60`; same on `1.99.x` and master) appends `--disable-domain-reliability` unconditionally (from `BasicStartupComplete`, `:136-137`), and `ShouldCreateService` returns false on that switch before it reaches the policy check (`IsDomainReliabilityAllowed`, which reads `domain_reliability.allowed_by_policy`; `chrome/browser/domain_reliability/service_factory.cc:28-34`, `chrome/browser/net/profile_network_context_service.cc:181-184` at 156.0.8078.48) |
| `BuiltInAIAPIsEnabled` | ⚠️ no-op in Brave | each `AIManager::CanCreate*` returns `kUnavailableFeatureNotEnabled` before reading the policy pref (156.0.8078.48 `chrome/browser/ai/ai_manager.cc:737-753`), because Brave ships the base features behind every API the key gates disabled (`AIPromptAPI`, `AISummarizationAPI`, `AIWriterAPI`, `AIRewriterAPI`, `AIProofreadingAPI`; `rewrite/third_party/blink/renderer/platform/runtime_enabled_features.json5.yaml:73-101` at `v1.98.60`). The plaster alone leaves the Blink flags of `AIPromptAPI` and `AISummarizationAPI` on, since both are stable on desktop; this check is what makes the key a no-op. No on-device model backs them either |
| `DefaultWebBluetoothGuardSetting`, `DefaultFileSystemReadGuardSetting`, `DefaultFileSystemWriteGuardSetting` | ⚠️ redundant | already feature-disabled in Brave, which is why the device-API set is USB+Serial+HID. The keys are live upstream, but both APIs sit behind Brave-owned `FEATURE_DISABLED_BY_DEFAULT` features (`chromium_src/third_party/blink/common/features.cc:10,12` at `v1.98.60`; no Griffin study): `kFileSystemAccessAPI` (`chrome://flags#file-system-access-api`) and `kBraveWebBluetoothAPI` (`chrome://flags#brave-web-bluetooth-api`, checked in `browser/bluetooth/brave_bluetooth_delegate.cc:19-20`). The keys bite only if a user turns those flags on |
| `DefaultThirdPartyStoragePartitioningSetting` | ❌ removed | removed after cr145: `deprecated: true`, capped `chrome.*:113-145`; no handler in `configuration_policy_handler_list_factory.cc` and `pref_mapping/DefaultThirdPartyStoragePartitioningSetting.json:3` says `Policy was removed` at 156.0.8078.48 and main (`7b96745f7dfb`) |
| `FirstPartySetsEnabled`, `RelatedWebsiteSetsEnabled`, `FirstPartySetsOverrides`, `RelatedWebsiteSetsOverrides` | ❌ removed | removed after cr152: all four `deprecated: true` and capped (`113-152` / `120-152`, Chromium `6925f9c991`), with their handlers and pref-mapping files deleted, so none is dispatched at 156.0.8078.48; brave-core re-adds none. Moot anyway: Brave's `AreRelatedWebsiteSetsEnabled()` returns false (`components/privacy_sandbox/brave_privacy_sandbox_settings.cc:29-52` at `v1.98.60`) |
| `InsecurePrivateNetworkRequestsAllowed`, `LocalNetworkAccessRestrictionsEnabled` | ❌ removed | removed after cr137 and cr144: `deprecated: true`, capped (`chrome.*:92-137`, `chrome.*:138-144`), no handler and no `pref_mapping` file at 156.0.8078.80. Their job is done by LNA, which is on in Brave and asks per site; its global lock is the list `LocalNetworkAccessBlockedForUrls` = `["*"]`, shipped as Block Local Network Access (see its row), which blocks public sites only and leaves pages served from the LAN or loopback untouched. The cr146 `LocalNetwork*` / `LoopbackNetwork*ForUrls` lists only split that block by target, and the remaining LNA booleans only loosen it |
| `UrlKeyedMetricsAllowed` | 🕓 future_on only | `future_on:` only at 156.0.8078.48 and main, never shipped. Its handler is registered, the new half of a `SimpleDeprecatingPolicyHandler` pair with `UrlKeyedAnonymizedDataCollectionEnabled` (factory `:2680-2687`). A `future_on` key is dropped on the Stable and Beta channels unless `EnableExperimentalPolicies` lists it and honoured on others (`components/policy/core/browser/configuration_policy_handler_list.cc:62-66`), so Brave Release and Beta ignore it and Nightly applies it. Where applied, `false` writes only what `UrlKeyedAnonymizedDataCollectionEnabled = false` already writes, while `true` writes nothing yet still shadows that key, leaving the pref unmanaged |
| `AutofillSettings` | ⚠️ feature off | `supported_on: chrome.*:154-` and dispatched at 156.0.8078.48 (`AutofillSettingsPolicyHandler` → `autofill.types_blocked`), but every reader is gated on `kAutofillEnableAutofillSettingsEnterprisePolicy`, `FEATURE_DISABLED_BY_DEFAULT` at 156.0.8078.48 (`components/autofill/core/common/autofill_features.cc:714-715`), 157.0.8103.21 and main; no brave-core override, no Griffin study. Written today it only fills that pref. Beside the legacy keys it is a hazard: one handler checks all three and applies none if any check fails (`autofill_policy_handler.cc:76-93`, `configuration_policy_handler_list.cc:84-87`), so an `AutofillSettings` value that fails the schema cancels both legacy keys. Redundant even with the feature on: the two legacy keys already block `contact_info`, `identity_docs`, `travel` and `payments` (`autofill_policy_service.cc:28-77`), and `shopping` is Autofill AI, which Brave ships off. It is the successor the legacy keys' `deprecated: true` names — see What's next |
| `AutofillGenAiSettings` | ⚠️ no-op in Brave | `chrome.*:156-` int-enum (`google-sharing`), dispatched at 156.0.8078.48 (factory `:3598-3606`) into the Find-and-Fill-with-Gemini and Autofill-prediction prefs. Both features it governs are shipped off in Brave: Autofill AI needs `kAutofillAiWithDataSchema` and Find and Fill needs `kPersonalContext`, both on upstream and pinned off by brave-core (`rewrite/components/autofill/core/common/autofill_features.cc.yaml:7-23`, `rewrite/components/personal_context/core/personal_context_features.cc.yaml:7-10` at `v1.98.60`); no Griffin study. `2` (Disabled) would change nothing |
| `TryOnYouSettings` | ⚠️ no-op in Brave | `chrome.*:155-` int-enum (unset falls back to `GenAiDefaultSettings`), dispatched on desktop at 156.0.8078.48 into `indigo.policy` (`configuration_policy_handler_list_factory.cc:501-503`, `!IS_ANDROID`; fallback entry `:3685-3686`). Its one reader is `IndigoService`, which `CHECK`s `kIndigo` in its constructor (`chrome/browser/indigo/indigo_service.cc:214`); `kIndigo` is `FEATURE_DISABLED_BY_DEFAULT` (`chrome/common/chrome_features.cc:1285`) with no `brave://flags` entry, and brave-core pins it off (`rewrite/chrome/common/chrome_features.cc.yaml:34-37`, asserted in `app/feature_defaults_unittest.cc:220`, `v1.98.60`; same on `1.99.x` and master); no Griffin study. Try on You never runs, so `2` (Disabled) changes nothing |
| `LaunchOnStartupEnabled` | ⚠️ no-op in Brave | `chrome.win:156-`, browser-wide; dispatched on Windows (factory `:1977-1979` at 156.0.8078.48). Brave never registers itself to open at Windows sign-in or shows the prompts the key suppresses: both need `kLaunchOnStartup` (`chrome/browser/startup/startup_features.cc:12,30-43`), off upstream and pinned off by brave-core (`rewrite/chrome/browser/startup/startup_features.cc.yaml:6-10`); no Griffin study. It bites only if a user turns on `brave://flags#startup-launch` |
| `ShoppingListEnabled` | ⚠️ no-op in Brave | its only functional reader, `IsShoppingListEligible`, fails its first gate: brave-core compiles `kShoppingList` off and reports it overridden (`rewrite/components/commerce/core/commerce_feature_list.cc.yaml:27-30` at `v1.98.64` and master), so `IsRegionLockedFeatureEnabled` is false before the pref is read (`components/commerce/core/commerce_feature_list.cc:306-307` at 156.0.8078.80). Forced on, it needs a Chrome sync account Brave never creates; no Griffin study names it. Dispatched (factory `:2350-2352`). Dropped in v2.4.0; `SlimBrave.ps1` Apply and Reset delete a leftover `0` it wrote |
| `AlternateErrorPagesEnabled` | ⚠️ no-op in Brave | no reader acts on it: `NetErrorTabHelper`'s DNS-error probes never run (an empty `NoTabHelper`, `chromium_src/chrome/browser/ui/tab_helpers.cc:25-26` at `v1.98.64`; a no-op class on Chromium 157), and captive-portal detection, a plain-HTTP probe to `detectportal.brave-http-only.com` after timeouts, SSL errors or slow SSL loads that no desktop policy reaches, ignores it on every ref (`rewrite/components/captive_portal/content/captive_portal_service.cc.yaml`). Dispatched (factory `:950-952` at 156.0.8078.80). Dropped in v2.4.0; `SlimBrave.ps1` Apply and Reset delete a leftover `0` it wrote |
| `DNSInterceptionChecksEnabled`, `IntranetRedirectBehavior` | ⚠️ redundant | the DNS-interception probes and intranet infobar run only while `IntranetRedirectBehavior` holds 3: `IsEnabledByPolicy` checks it before the other key (`chrome/browser/intranet_redirect_detector.cc:264-285` at 156.0.8078.80), and unset is `DISABLE_FEATURE`, as 1 is (`components/omnibox/browser/intranet_redirector_state.cc:23-42`). That pref is policy-only and brave-core names neither key, so only an admin who wants the probes sets it. Dispatched (factory `:645-647`, `:526-528`). `DNSInterceptionChecksEnabled` dropped in v2.4.0; `SlimBrave.ps1` Apply and Reset delete a leftover `0` it wrote |
| `DefaultMediaStreamSetting` | ⛔ | `deprecated: true` (uncapped `chrome.*:22-`, same on main) yet still dispatched at 156.0.8078.48 (`configuration_policy_handler_list_factory.cc:671-673` into `profile.managed_default_content_settings.media_stream`, which the content-settings policy provider applies to both camera and microphone, `components/content_settings/core/browser/content_settings_policy_provider.cc:388-391`); the microphone and camera switches are the `AudioCaptureAllowed` / `VideoCaptureAllowed` rows (Block Microphone Access / Block Camera Access), which block outright and void per-site exceptions instead of setting a default |
| `BraveSearchResultAdsEnabled` | ❌ removed after 1.94.x | exists in no shipping Brave. A one-release key: merged to master 2026-07-20 (brave-core#37955) and reverted by `cf025361c` before `1.95.x` branched, so only 1.94.x and Nightly `v1.95.1`–`v1.95.47` dispatched it; the YAML is absent at `v1.98.60`, `1.99.x` and master. Its replacement, the universal pref `brave.brave_ads.sponsored.enabled` (first in 1.96), gates NTP sponsored images and tiles and the browser side of search result ads, and has no policy key: brave-browser#57204 closed on `1.96.x` with only a Settings toggle, and brave-browser#54917 (ads policy independent of Rewards, open, unmilestoned) plans a `SponsoredAdsEnabled` key with no PR yet. Until a key ships, `BraveRewardsDisabled` keeps the ads service off (see its row). A switch that does nothing is worse than none |
| `CpuPerformanceTierOverride` | ✅ live, harmful | **no real machine reports 0.** The tier is `kUnknown` only for fewer than one core (156.0.8078.80 `cpu_performance.cc:225-242`), so a written 0 marks the browser as managed or DevTools-emulated, where a real tier is one of four populous buckets; sites also read 0 as both top and lowest tier (WICG/cpu-performance#5). Live: dispatched (factory `:336-338`) and used for every new renderer (`chrome_content_browser_client.cc:9729-9740`); no brave-core reader (`v1.98.64` to master), no Griffin study. Revisit if Brave farbles the tier (`navigator_cpu_performance.cc:18-19`) |
| `Disable3DAPIs` | ✅ live, harmful | **does not disable WebGL.** It clears `webgl1_enabled` and `webgl2_enabled` (156.0.8078.80 `chrome_content_browser_client.cc:4712-4714`; factory `:714-716`), which only `HTMLCanvasElement` reads (`html_canvas_element.cc:660-668`); `OffscreenCanvas` hard-codes both on (`offscreen_canvas.h:188-189`, same at 157.0.8103.30), so a page or worker still gets WebGL and the GPU renderer strings through it, and WebGPU is outside the key. Maps, games and design tools on ordinary canvases break instead; no brave-core change. Revisit if `OffscreenCanvas::IsWebGL1Enabled` reads the settings |
| `TranslatorAPIAllowed` | ✅ live, not offered | **a row would go dead within a release.** Brave's Chromium 157 upgrade switches the `Translator` API off in the renderer (`renderer/brave_content_renderer_client.cc:165` at master `dea04e59d7`; `1.100.x` via brave-core#41062, Release due around 2026-11-17). On 1.98.x `false` works: dispatched under `ENABLE_ON_DEVICE_TRANSLATION` (factory `:432-436` at 156.0.8078.80) and read on every `create()` and translate call (`translation_manager_impl.cc:388-392,469-470`); brave-core's plaster leaves the Blink flag stable (`runtime_enabled_features.json5:6612-6621`) |
| `DefaultJavaScriptJitSetting` | ✅ live, harmful | **breaks WebAssembly on every site.** 2 makes every web-safe site run `--jitless` (156.0.8078.80 `render_process_host_impl.cc:3818-3825`; factory `:985-987`), and V8 then hides the `WebAssembly` global (V8 `c9b3cfca` `src/wasm/wasm-js.cc:3428-3430`); Brave builds no interpreter for it (`BRAVE_V8_ENABLE_DRUMBRAKE` unset, `brave_content_browser_client.cc:1167-1176` at `v1.98.64`). Design tools, games and codecs break, and only the admin list `JavaScriptJitAllowedForSites` exempts a site. Disable JavaScript Optimization hardens V8 and keeps WebAssembly. Revisit on its What's next trigger |
| `DefaultJavaScriptSetting` | ✅ live, harmful | the working policy switch for Shields' script blocking, with no value fit to ship. A managed default is a policy-provider rule that outranks Shields' per-site rules (`brave_shields_utils.cc:721-739` at `v1.98.64`; `host_content_settings_map.cc:1133-1145` at 156.0.8078.80); the Shields panel greys its Scripts toggle "(enforced by policy)". `2` blocks scripts on every site, Shields down or not, with no per-site escape; `1` removes Shields' per-site blocking (Ad Block Only Mode injects it). Settings → Shields → Block scripts sets the same default and keeps per-site exceptions |
| `ExtensionDeveloperModeSettings` | ✅ live, not offered | **adds only a lock `DeveloperToolsAvailability` = 2 already gives.** `1` locks Developer mode off, refusing *Load unpacked* and disabling unpacked extensions (156.0.8078.80 `extension_developer_mode_policy_handler.cc:41-48`; factory `:3519`). Chromium already disables them while Developer mode is off, the default, and on Windows and macOS resets the pref if edited outside Brave (`chrome_pref_service_factory.cc:176,213-231`). Maximum Privacy and Strict Parental Controls lock it through `DeveloperToolsAvailability` = 2; in Balanced Privacy it would disable extensions loaded unpacked on purpose |
| `NativeMessagingUserLevelHosts` | ✅ live, not offered | **breaks the password-manager bridges this audience uses.** `false` limits extensions to system-wide native messaging hosts (156.0.8078.80 `chrome/browser/extensions/api/messaging/chrome_messaging_delegate.cc:50-54`; factory `:2114-2116`), so a per-user registration can no longer shadow a system host of the same name, an attack that needs code already running as the user. But Bitwarden Desktop and KeePassXC register their bridges only per user (HKCU, home-directory manifests) on all three platforms, so `false` breaks them, and only an administrator can restore them |
| `HeadlessMode` | ✅ live, not offered | **removes invisibility, not capability.** `2` refuses every `--headless` start (156.0.8078.80 `startup_browser_creator.cc:1019-1025`; factory `:2837`; brave-core leaves the check alone). But headless runs incognito in a temporary profile unless `--user-data-dir` is passed (`headless_mode_init.cc:64-94`), `RemoteDebuggingAllowed` = false already closes the CDP cookie path, and a program that can point Brave at your profile can still open a normal window with an extension passed by `--disable-extensions-except`. It would break headless screenshot, PDF and DOM-dump tools for every account |
| `DesktopSharingHubEnabled` | ✅ live, not offered | **no privacy, security or performance effect.** The address-bar sharing hub its YAML names is gone (156.0.8078.80 `page_action_icon_type.h:32`, `// DEPRECATED: kSharingHub = 17,`). `false` (factory `:2028-2030`) removes only the app menu's Copy link, Send tab to self and Create QR code (`app_menu_model.cc:885-918`), the context-menu QR item and Copy URL, while Brave's Screenshot entry and Copy clean link stay (`browser/ui/toolbar/brave_app_menu_model.cc:357-382` at `v1.98.64`), so it is no share-off switch either. Send tab to self rides Brave Sync, which `SyncDisabled` covers |
| `NewTabPageLocation` | ⚠️ blocked on unmanaged Windows/macOS | **dead in `SlimBrave.ps1` on a home PC.** The YAML is `sensitive: true` and brave-core un-flags only `MetricsReportingEnabled`, so Windows and macOS drop it unless the machine is domain-joined, Entra-joined or MDM-enrolled (156.0.8078.80 `async_policy_loader.cc:110-119`). Not a no-op: on Linux (factory `:520-522`) upstream's new-tab override runs, since Brave's handler returns false for `chrome://newtab` (`brave_content_browser_client.cc:1476-1518` at `v1.98.64`), so `about:blank` replaces the dashboard. Brave's Blank page setting does the same. Reconsider if brave-core drops that flag |
| `LiveCaptionEnabled`, `LiveTranslateEnabled` | ⚠️ no-op in Brave | dispatched on desktop (factory `:2037-2042` at 156.0.8078.80), but Live Caption never runs: brave-core makes `captions::IsLiveCaptionFeatureSupported()` return false (`chromium_src/components/live_caption/caption_util.cc:16-18` at `v1.98.64`), so the controller never observes the pref and the speech host, Live Translate's only caller, is never bound (`chrome/browser/chrome_browser_interface_binders.cc:340-352`). The video PiP window still shows Live Caption and Live Translate toggles that write these prefs; nothing reads them |
| `DefaultIdleDetectionSetting` | ⚠️ redundant | brave-core re-registers `IDLE_DETECTION` with default Block (`chromium_src/components/content_settings/core/browser/content_settings_registry.cc:300-307` at `v1.98.64`) and hides the setting unless its own `kIdleDetection` feature is enabled from the command line, so the API resolves "denied" without a prompt and `2` changes nothing; `3` and `1` would loosen Brave's default. Dispatched (`chrome.*:146-`, factory) |
| `GenAiDefaultSettings`, `CacheEncryptionEnabled`, `TabGroupSharingSettings`, `CloudReportingEnabled`, `CloudProfileReportingEnabled` | ⚠️ cloud-only, ignored | **no platform source can set them:** a value in HKLM, the Linux JSON or a plist is refused, with an error in `brave://policy`, and never reaches a pref. A YAML `cloud_only: true` (all but `CacheEncryptionEnabled`) is dropped by `IsPolicySupported` (`configuration_policy_handler_list.cc:167-175` at 156.0.8078.80); `CacheEncryptionEnabled` and `TabGroupSharingSettings` are wrapped in `CloudUserOnlyPolicyChecker` (factory `:3724-3728,3739-3745`). `CloudReportingEnabled` is exempt (`:208`) but uploads nothing without CBCM enrollment, which Brave lacks. See Cross-cutting |
| `DefaultInsecureContentSetting` | ⚠️ redundant, partial | blockable mixed content is already blocked: `MIXEDSCRIPT` is registered Block (`content_settings_registry.cc:318-326` at 156.0.8078.80) and brave-core leaves it alone. A managed `2` removes only the per-site Allow, with the HTTPS-Upgrades exemption and insecure-download permit it grants; the omnibox "Load unsafe scripts" link stays and sets a per-tab flag that never reads the setting (`mixed_content_settings_tab_helper.cc:40-49`), which the renderer honours first (`content_settings_agent_impl.cc:353-364`). `3` is invalid and acts as unset |
| `PartitionedBlobUrlUsage` | ⚠️ redundant | an escape hatch, not hardening: unmanaged and `true` are the same (`IsBlobUrlPartitioningEnabled` returns the managed value or else true, `chrome/browser/chrome_content_browser_client.cc:9237-9249` at 156.0.8078.80). Only `false` acts, and it only weakens: Brave's own `BlobURLStoreImpl` keeps blob fetches partitioned whatever the pref (`chromium_src/storage/browser/blob/blob_url_store_impl.cc:18-54` at `v1.98.64`), but new renderers get `--disable-blob-url-partitioning`, which drops the forced `noopener` on cross-site blob URL navigations (`local_dom_window.cc:2517-2521`) |
| `PreferSlowCiphers`, `PreferSlowKexAlgorithms` | ✅ live, harmful | **makes every TLS and QUIC ClientHello distinguishable from every other Brave**, which is what the YAML says the policy is for (servers "differentiate between those clients"; "not required for security"). Both apply with no brave-core override (`chrome/browser/ssl/ssl_config_service_manager.cc:343-353` at 156.0.8078.80): `cnsa2` rewrites the advertised groups, ML-KEM-1024 first (`services/network/ssl_config_type_converter.cc:47-55`), `cnsa` applies BoringSSL's CNSA cipher policy (`net/socket/ssl_client_socket_impl.cc:889-893`). The gain (AES-256, ML-KEM-1024) is small beside the fingerprint |
| `GeminiSettings`, `GeminiActOnWebSettings`, `GeminiActOnWebAllowedForURLs`, `GeminiActOnWebBlockedForURLs`, `GeminiSparkSettings` | ⚠️ no-op in Brave | dispatched (factory `:491,3698-3716` at 156.0.8078.80), but every reader is Gemini in Chrome (Glic) or the omnibox @gemini starter pack. Glic never enables without a signed-in Google primary account (`chrome/browser/glic/public/glic_enabling.cc:464-470`), which Brave never has, and Brave's starter pack has no @gemini entry (`chromium_src/components/search_engines/template_url_starter_pack_data.cc:48-49` at `v1.98.64`). Leo creates its agent tasks with `NoEnterprisePolicyChecker()`, so the act-on-web lists do not bind Leo either |
| `AIModeSettings`, `ThirdPartyAiChatSettings`, `SearchContentSharingSettings`, `SmartTabSharingSettings` | ⚠️ no-op in Brave | dispatched, but the features behind them are pinned off: `AimEligibilityService` returns on `omnibox::kAimEnabled` before reading either AI Mode pref, third-party entry point included (`components/omnibox/browser/aim_eligibility_service.cc:326-345,440-449` at 156.0.8078.80), and brave-core pins `kAimEnabled`, `kLensOverlay`, `kLensStandalone` and `kContextualTasks` off (asserted in `app/feature_defaults_unittest.cc` at `v1.98.64`). No Griffin study. A Disabled value changes nothing |
| `HelpMeWriteSettings`, `CreateThemesSettings`, `TabCompareSettings`, `AutofillPredictionSettings`, `VoiceTypingSettings` | ⚠️ no-op in Brave | dispatched (factory `:2421-2436` at 156.0.8078.80), but nothing behind them runs: brave-core pins `kEnableCompose` (Help Me Write), `kCustomizeChromeWallpaperSearch` (Create Themes) and `kAutofillAiWithDataSchema` (Autofill prediction) off (`app/feature_defaults_unittest.cc:149,175,275` at `v1.98.64`); Tab Compare no longer exists upstream; Talk to type needs `kDictation`, off by default, without which its service is not built (`dictation_keyed_service_factory.cc:44`). No Griffin study. `2` changes nothing |
| `HistorySearchSettings` | ⚠️ no-op in Brave | dispatched (factory `:2427` at 156.0.8078.80), but brave-core replaces `IsHistoryEmbeddingsEnabledForProfile` with a function that reads only its own `kBraveHistoryEmbeddingsEnabled`, and hides the upstream setting (`rewrite/chrome/browser/history_embeddings/history_embeddings_utils.cc.yaml:54-56`, `chromium_src/chrome/browser/history_embeddings/history_embeddings_utils.cc:39-47` at `v1.98.64`), so the Chromium pref is never consulted. `BraveLocalAIEnabled` is the lever, and SlimBrave writes it |
| `DevToolsGenAiSettings` | ⚠️ no-op in Brave | dispatched (factory `:2406` at 156.0.8078.80), but `AidaClient::CanUseAida` marks DevTools AI available only under `GOOGLE_CHROME_BRANDING` (`chrome/browser/devtools/aida_client.cc:109-114`), which Brave does not set; brave-core asserts it NotAvailable (`chromium_src/chrome/browser/devtools/aida_client_unittest.cc:8-9` at `v1.98.64`) and pins Console Insights and the AI code features off. The other readers only register the pref or tag logging sessions |
| `GenAILocalFoundationalModelSettings` | ⚠️ no-op in Brave | dispatched (factory `:2741-2746` at 156.0.8078.80, browser-wide), but Chrome's on-device model installs only if `IsOnDeviceExecutionEnabled()`, which is `kOptimizationGuideModelExecution` (`manifest_monitor.cc:40-44`), and brave-core ships that off (`app/feature_defaults_unittest.cc:295` at `v1.98.64`); no Griffin study. Its other readers serve features Brave also ships off. Brave's own on-device models follow `BraveLocalAIEnabled` |
| `ExtensionUnpublishedAvailability` | ⚠️ no-op in Brave | dispatched (factory `:3515-3517` at 156.0.8078.80), but "unpublished" status comes only from `CWSInfoService`, which fetches nothing unless an official Google Chrome API key is built in (`extensions/browser/cws_info_service.cc:308-315`), and Brave ships none (see `SafeSitesFilterBehavior`). No extension is ever flagged, so `1` disables nothing |
| `AutoplayAllowed` | ⚠️ no-op | `false` is code-identical to unset: the only reader returns true when the pref is true or the URL is listed and otherwise falls through to the default autoplay policy (`chrome/browser/policy/policy_util.cc:24-26` at 156.0.8078.80). Brave blocks autoplay with its own `AUTOPLAY` content setting, for which brave-core's policy provider adds no managed default, so no policy reaches it; use brave://settings/content/autoplay |
| `AdsSettingForIntrusiveAdsSites` | ⚠️ no-op in Brave | dispatched (factory `:318-320` at 156.0.8078.80) into `profile.managed_default_content_settings.ads`, but the subresource filter it drives has no rules in Brave: brave-core refuses the Subresource Filter Rules component (`chromium_src/components/component_updater/component_installer.cc:43,66-67` at `v1.98.64`) and ships `kAdTagging` off. `2` blocks nothing; Shields does Brave's ad blocking |
| `AdvancedProtectionAllowed` | ⚠️ no-op in Brave | dispatched on desktop, but enrollment comes only from a signed-in Google primary account (`chrome/browser/safe_browsing/advanced_protection_status_manager_desktop.cc:62-70,97-107` at 156.0.8078.80), which Brave never has (see BrowserSignin). The extra protections, including the download upload to Google, never run, so `false` changes nothing |
| `ApplicationBoundEncryptionEnabled` | ⚠️ redundant | Windows only. App-Bound Encryption is live in Brave on system installs and the support check reacts only to a managed `false` (`chrome/browser/os_crypt/app_bound_encryption_win.cc:87-94` at 156.0.8078.80), so `true` restates the default. `false`, the one value that acts, weakens cookie and password protection against infostealers: never write it |
| `BrowserLabsEnabled` | ⚠️ no-op in Brave | dispatched (factory `:631-633` at 156.0.8078.80), but every reader (toolbar button, app-menu entries) sits behind `IsChromeLabsEnabled()`, which brave-core replaces with `return false;` (`chromium_src/chrome/browser/ui/toolbar/chrome_labs/chrome_labs_utils.cc:10-11` at `v1.98.64`) and upstream already returns false on Stable. Brave has no Chrome Labs UI on any channel |
| `EncryptedClientHelloEnabled` | ⚠️ redundant | `true` behaves as unset and `false` only turns ECH off: the local-state pref defaults to true and `GetEchMode` returns disabled only when it is false (`services/network/ssl_config_service_mojo.cc:89-96` at 156.0.8078.80). No ECH base::Feature is left and brave-core never references the pref, so nothing in Brave can turn ECH off for a lock to stop. Dispatched (factory `:1083-1085`) |
| `DevToolsGoogleDeveloperProgramProfileAvailability` | ⚠️ no-op in Brave | dispatched on desktop (factory `:2409-2411` at 156.0.8078.80), but the DevTools host config hard-codes the GDP profile off outside `GOOGLE_CHROME_BRANDING` (`chrome/browser/devtools/devtools_ui_bindings.cc:2251-2263`), and brave-core also makes `GdpServiceHandler::CanMakeRequest` refuse every request (`chromium_src/chrome/browser/devtools/gdp_service_handler.cc:12` at `v1.98.64`). `2` changes nothing |
| `ForceEphemeralProfiles` | ✅ live, harmful | **deletes profiles.** Dispatched on desktop (factory `:2090-2092` at 156.0.8078.80); written machine-wide, it makes every profile opened while it is set ephemeral, and each is deleted when its last window closes or Brave exits (`ProfileManager::RemoveKeepAlive` → `ScheduleEphemeralProfileForDeletion`, not feature-gated; leftovers go at the next start): bookmarks, passwords, extensions, Shields settings, Rewards and the Wallet keyring. brave-core overrides none of it. Brave's clear-on-exit settings meet the privacy goal without deleting the profile |
| `GoogleSearchSidePanelEnabled` | ⚠️ dispatched, inert | dispatched on desktop (factory `:2376-2379` at 156.0.8078.80) into a pref that `side_panel_prefs.cc:40` registers and nothing reads: the Search Companion it governed is deleted (`chrome/browser/companion` holds only OWNERS and `text_finder`), and brave-core never references it. `false` only shows in `brave://policy` |
| `HideWebStoreIcon` | ⚠️ redundant | brave-core already defaults the pref to true (`browser/brave_profile_prefs.cc:259-261` at `v1.98.64`, asserted in `browser/brave_prefs_browsertest.cc:165-166`) and exposes no setting for it, so `true` only restates Brave's default and `false` would bring the Web Store tile back. Dispatched on desktop (factory) |
| `HistoryClustersVisible` | ⚠️ no-op in Brave | dispatched (factory `:440-442` at 156.0.8078.80), but Journeys needs `kJourneys` (`components/history_clusters/core/config.cc:44-45`), which brave-core ships off with `kJourneysImages` and `kOmniboxHistoryClusterProvider` (`app/feature_defaults_unittest.cc:256` at `v1.98.64`); no Griffin study. Grouped history never appears, and the pref's direct readers also need that flag, so `false` changes nothing |
| `NTPCardsVisible` | ⚠️ no-op in Brave | dispatched on desktop (factory `:784-786` at 156.0.8078.80). Brave's new tab page is its own WebUI and never reads the pref (`browser/ui/webui/brave_web_ui_controller_factory.cc:121-142` at `v1.98.64`). Chromium's page is still reachable by typing brave://new-tab-page, with the Customize Chrome Cards section, but no card has anything to show: brave-core ships the Calendar, Cart and Drive modules off (`rewrite/components/search/ntp_features.cc.yaml:40-77`) and the rest need other policies or a Google account |
| `ProcessIsolationEnabled` | ✅ live, harmful | **does not isolate in Brave and makes startup unsafe.** On a system-level Windows install, `true` routes every later start through an elevator call Brave does not implement (undefined behaviour, untested): the relaunch requests Brave's `IElevator`-derived interface as `IElevator2` and calls `RunIsolatedChrome` (`isolated_browser_support.cc:214-218,280,312` at 156.0.8078.80; `chromium_install_modes.h:294` at `v1.98.64`). The `IsolationState` it writes persists after the policy is removed, because the pref's default is read back from it (`browser_process_impl.cc:516-534,1339-1340`) |
| `PromotionsEnabled` | ⚠️ dispatched, near-inert | not deprecated (`chrome.*:128-`); dispatched with its deprecated alias into `browser.promotions_enabled` (factory `:2829-2835` at 156.0.8078.80). In Brave `false` only blocks the low-priority, non-toast upstream tip bubbles brave-core still registers, such as the yearly Battery Saver bubble (`browser_feature_promo_controller.cc:76-81`; source-read), and the post-update brave.com/whats-new tab, dormant while `WhatsNewStudy` targets 1.65 (`browser/ui/whats_new/whats_new_util.cc:167-171` at `v1.98.64`). Brave's own promos are untouched, so a "Disable promotions" label would overpromise |
| `SignedHTTPExchangeEnabled` | ⚠️ no-op in Brave | the pref's only reader is `AllowSignedExchange`, which brave-core overrides to `return false;` (`browser/brave_content_browser_client.cc:1762-1768` at `v1.98.64`, asserted by its SXG browser tests). Signed Exchanges never load in Brave: `false` changes nothing and `true` cannot turn them on. Dispatched (factory `:879-881` at 156.0.8078.80) |
| `StaticStorageQuotaEnabled` | ⚠️ redundant | static quota is already the default (`kStaticStorageQuota` and its incognito twin are `FEATURE_ENABLED_BY_DEFAULT`, `storage/browser/quota/quota_features.cc:38,42` at 156.0.8078.80; no Griffin study), and Brave pins `navigator.storage.estimate()` at 2 GiB whatever the policy (`chromium_src/third_party/blink/renderer/bindings/modules/v8/v8_storage_estimate.h:25-26` at `v1.98.64`). `false` would only bring back the disk-scaled quota through the deprecated `webkitTemporaryStorage` API, a fingerprinting regression |
| `WebRtcEventLogCollectionAllowed`, `WebRtcTextLogCollectionAllowed` | ⚠️ no-op in Brave | both uploaders return before sending (`patches/chrome-browser-media-webrtc-webrtc_event_log_uploader.cc.patch:9`, `patches/chrome-browser-media-webrtc-webrtc_log_uploader.cc.patch:9` at `v1.98.64`), and brave-core makes every `webrtcLoggingPrivate` call fail in `RphFromRequest`, so no caller can start collection; the upstream extension default needs a cloud-managed profile Brave never has. Brave also defaults both prefs to false (`browser/brave_profile_prefs.cc:289-293`), which gates the newer diagnostic web path. Both dispatched; `false` changes nothing |
| `UserFeedbackAllowed` | ⚠️ typed-URL page only | **its one effect in Brave is to disable brave://feedback, a page reached only by typing it**, from which the user writes and sends any report themselves (`FeedbackUIConfig::IsWebUIEnabled` returns `CanSubmitFeedback`, `chrome/browser/ui/webui/feedback/feedback_ui.cc:162-166` at 156.0.8078.80). Every other entry point is Chrome-branded or removed: `IDC_FEEDBACK` is enabled only under `GOOGLE_CHROME_BRANDING` (`browser_command_controller.cc:2402-2408`), and Brave's Help menu lists only About, Help Center and Report a broken site (`browser/ui/toolbar/brave_app_menu_model.cc:60-65` at `v1.98.64`) |
| `AutomatedPasswordChangeSettings` | ⚠️ no-op in Brave | dispatched on desktop (factory `:2034-2036` at 156.0.8078.80), but the AI password change never runs: on Release the optimization-guide service it needs is not built, and where Beta or Nightly build it, every attempt executes the server model `kPasswordChangeSubmission` and fails without a model-execution manager (`optimization_guide_keyed_service.cc:522-534`), which needs `kOptimizationGuideModelExecution`, shipped off by brave-core (`app/feature_defaults_unittest.cc:295` at `v1.98.64`). `2` changes nothing visible |
| `PasswordSharingEnabled` | ⚠️ no-op in Brave | Brave never offers Google Family password sharing: the Share button exists only in Google-Chrome-branded builds (`<if expr="_google_chrome">`, `chrome/browser/resources/password_manager/credential_details/password_details_card.ts:112-118` at 156.0.8078.80), and the recipient lookup needs a Chrome primary account Brave never has. Under Brave Sync `false` also stops and clears the two password-sharing-invitation data types (`incoming_password_sharing_invitation_data_type_controller.cc:57-59`), which are always empty in Brave |
| `ProtectedContentIdentifiersAllowed` | ⚠️ no-op in Brave | Windows only (factory `:1982-1986` at 156.0.8078.80). No EME session in Windows Brave requests the permission it gates: PlayReady and hardware-secure Widevine are not built (`enable_playready = is_win && is_chrome_branded`, `components/cdm/common/playready.gni:9`), and Brave's opt-in software Widevine sets `identifier = kNotAllowed` for every Windows robustness (`widevine_key_system_info.cc:186-198`). A site that demands `distinctiveIdentifier: "required"` already fails, so `false` has no observable effect |
| `RemoteAccessHost*` (all 20 desktop keys: AllowClientPairing, AllowFileTransfer, AllowGnubbyAuth, AllowPinAuthentication, AllowRelayedConnection, AllowRemoteAccessConnections, AllowRemoteSupportConnections, AllowUiAccessForRemoteAssistance, AllowUrlForwarding, ClientDomainList, ClipboardSizeBytes, DomainList, EnableUserInterface, FirewallTraversal, MatchUsername, MaximumSessionDurationMinutes, RequireCurtain, UdpPortRange, and the deprecated ClientDomain and Domain) | 💀 no browser handler | Chrome Remote Desktop host policies, not browser policies: none has a factory entry, and each `pref_mapping/<Key>.json` says "Not used by the browser, handled by CRD host." at 156.0.8078.80. The host reads only Chrome's or Chromium's policy store (`remoting/host/policy_watcher.cc:57,424-445`), never Brave's, and Brave ships no host. The two ChromeOS-only keys and the capped token keys share the prefix and the verdict |
| `SafeBrowsingProxiedRealTimeChecksAllowed` | ⚠️ no-op in Brave | dispatched (factory `:408-410` at 156.0.8078.80), but its only consumers, the hash-prefix real-time lookup and its OHTTP key fetch, both require `HasGoogleChromeBranding() && kHashPrefixRealTimeLookups` (`components/safe_browsing/core/common/hashprefix_realtime/hash_realtime_utils.cc:25-31,107-110`), never true in Brave. The lookups it restricts never run, so `false` changes nothing |
| `SafeBrowsingDeepScanningEnabled` | ⚠️ redundant | brave-core already defaults the pref to false (`browser/brave_profile_prefs.cc:238-240` at `v1.98.64`) and no settings page exposes it. Its one reader (`safe_browsing_prefs.cc:225-227` at 156.0.8078.80) gates the deep-scan upload prompt, which also needs Enhanced Protection (forced off in Brave) or Advanced Protection (needs a Google account), and a local password prompt for encrypted archives that the false default already turns off. Dispatched on desktop (factory `:2380-2382`) |
| `ShowAppsShortcutInBookmarkBar` | ⚠️ no-op in Brave | the bookmark bar reads the pref only through `ShouldShowAppsShortcutInBookmarkBar()`, which brave-core patches, with `IsAppsShortcutEnabled()`, to return false (`patches/chrome-browser-ui-bookmarks-bookmark_utils.cc.patch:22-31` at `v1.98.64`). The Apps shortcut never appears whatever the key says |

## What's next

Watch list, each with the trigger that turns it into work:

- `PsstEnabled` — dispatched since 1.95 but inert on Release and Beta:
  `kEnablePsst` is off by default, and the only enabling study,
  `EnablePsstStudy` (#1906), is Nightly-only. Trigger: the feature on for
  Release, in code or by a Release study (`EnablePsstStudy` gaining Beta is
  the leading indicator). Then a checkbox writing `false`, labelled Brave
  1.95+, restart note, with no promise that `false` stops the rules download;
  it joins `ORIGIN_BUILTIN_KEYS` too.
- Brave's HTTPS transition — Griffin's `TransitionToUpstreamHttpsUpgrade`
  turns off `HttpsByDefault` for all desktop Beta and Nightly and 25% of
  desktop Release, leaving `DefaultBraveHttpsUpgradeSetting` unenforced there
  (see its row). Chromium's `HttpsOnlyMode` (`force_enabled`, dispatched at
  156.0.8078.48, no brave-core override) is the lock on the upstream path; not
  written. Before it ships, check what `force_enabled` does where
  `HttpsByDefault` is still on (brave-browser#30950 reports it does not lock
  Brave's Shields HTTPS setting there). Trigger: the Release share rising
  above 25%, or brave-core dropping `kBraveHttpsByDefault`; then add an
  `HttpsOnlyMode` = `force_enabled` row beside the Brave one, or replace it.
  Leading indicator: brave-core#40938 (draft, no milestone) turns
  `kBraveHttpsByDefault` off in code on Android only and leaves
  `kTransitionToUpstreamHttpsUpgrades` off. If brave-core turns
  `kBraveHttpsByDefault` off on desktop, `ChromeVariations` keeps that code
  default rather than Brave's upgrader: `MigrateHttpsUpgradeSettings` takes
  its backward branch and strict becomes an unlocked HTTPS-Only user pref
  (`browser/profiles/brave_profile_manager.cc:133-140` at `v1.98.64`). In
  that release, drop "Limit or Disable Variations keeps it enforced" from the
  HTTPS description and the matching README clause, delete
  `test_strict_https_preset_keeps_its_variations_partner`, add
  `HttpsOnlyMode` = `force_enabled`, and re-decide `ChromeVariations` in
  Maximum Privacy.
- `ChromeVariations` trade-off — Griffin is also how Brave turns on
  `kWebGLBalancedFingerprintingProtection` and `kBraveCopyCleanLinkFromJs`
  (off in code on every branch through master) and sets Chromium's BTM
  trigger to none (`BTMGoogleAuthWorkaround`), so either row refuses them
  (see its row). Only Maximum Privacy carries 1. Triggers: (1) brave-core
  turns either feature on in code, as brave-core#40666 did for ads OHTTP:
  drop it from the row, both descriptions and the README, then reconsider 1
  for Balanced Privacy and Developer. (2) `BTMGoogleAuthWorkaround` is capped
  or removed, or brave-core pins `kBtm`'s trigger in code: re-read the BTM
  clause. (3) brave-core#40666 reaches a release (due 1.101): drop the OHTTP
  item from the row's Buys list. (4) `kBraveHttpsByDefault` goes off in code
  on desktop: Maximum Privacy loses its reason for 1; re-decide. The runtime
  checks are under Runtime checks owed below.
- Brave Sponsored Ads (`brave.brave_ads.sponsored.enabled`) — no policy key;
  `BraveRewardsDisabled` keeps the ads service off for now (see its row).
  Trigger: a new ads YAML under `policy_definitions/BraveSoftware` (watch the
  file list; a YAML never names its pref), or brave-browser#54917 gaining a
  milestone. Then a checkbox writing the off value, in every preset that
  carries `BraveRewardsDisabled`; required once #54917 lands, since it would
  decouple ads startup from Rewards. Until then, runtime-check what the
  Rewards row states from source; if it does not hold, correct the row and
  the scripts' Rewards description. Ads OHTTP: the
  `static.ads.brave.com/v1/ohttp/hpkekeyconfig` fetch in the Rewards row
  depends on Griffin only while `kAdsObliviousHttpFeature` is off in code
  with `should_support` false
  (`components/brave_ads/core/browser/network/oblivious_http_feature.cc:10`,
  `oblivious_http_feature.h:22-23`), as at `v1.98.64`, `1.99.x` and
  `1.100.x`. master turns both on (brave-core#40666, milestone 1.101.x; the
  same flip landed and was reverted twice, #40444/#40514 and #40532/#40559).
  Trigger: both on in code on the branch next to ship Release (an uplift to
  1.100.x, or 1.101.x). Then neither `ChromeVariations` value stops the
  fetch, so Maximum Privacy, the one preset whose `ChromeVariations` stops
  it today, no longer does. At the pin pass where Release carries it:
  replace the end of the Rewards row's OHTTP sentence, from 'while
  Griffin's', with 'while Sponsored Ads is on (the default; this policy
  hides its toggle), and neither `ChromeVariations` row stops it'; drop
  'unless Limit or Disable Variations is also set' from the three scripts'
  Rewards description; and run the runtime check below with
  `ChromeVariations` = 1 and 2 as well. The Sponsored Ads key is then the
  only lock. At the 1.99 pin, re-cite the row on `ShouldFetchOhttpKeyConfig`
  (`http_client.cc:131-137` on `1.99.x`), which also needs Sponsored Ads on
  (`brave.brave_ads.sponsored.enabled`, registered `true`) and no connected
  Rewards wallet; a default profile still fetches.
- `BackgroundTabFreezingEnabled` and `ExtensionReviewPromptsEnabled` — both in
  the shipping pin and dispatched, both inert by default: the tab-freezing
  pref gates only the infinite-tabs paths, which need `kInfiniteTabsFreezing`
  or `kInfiniteTabsFreezingOnMemoryPressure`, and every review-prompt reader
  needs `kCWSReviewPromptingNativeUI`; all three are off at 156.0.8078.48 and
  main, with no brave-core override and no Griffin study. Trigger: one of them
  on for desktop Release. Then `ExtensionReviewPromptsEnabled` becomes a
  checkbox writing `false` in Performance & Bloat, in the presets that carry
  `DefaultBrowserSettingEnabled`; `BackgroundTabFreezingEnabled` stays out
  (unset already means on, and `false` only keeps background tabs running).
- `AutofillSettings` and the deprecated Autofill keys — the legacy keys are
  `deprecated: true` at 156 but still applied, and their successor is inert
  (`kAutofillEnableAutofillSettingsEnterprisePolicy` off at 156, 157 and
  main), so both stay, ⚠️ with the deprecation in their descriptions.
  Triggers: (1) the feature on at a shipping pin — replace both keys with one
  `{"url_pattern": "*", "blocked_types": [...]}` entry (`contact_info`,
  `identity_docs`, `travel` for addresses; `payments` for cards) in the three
  scripts, Maximum Privacy (all four types), Balanced Privacy (`payments`)
  and the PS1's embedded presets, and swap the rows between the Chromium
  table and Considered and rejected. (2) The legacy keys capped, their pref
  mapping removed, or the handler's legacy branch deleted at a shipping pin —
  they must go: migrate as in (1) if the feature is on, else drop them and
  say in the README that Brave has no working Autofill policy.
- `BraveGlobalPrivacyControlEnabled` on Chromium's GPC — a proposal on
  brave-browser#57532 (open, not built) would replace Brave's own GPC header
  and `navigator.globalPrivacyControl` with Chromium's off-by-default
  `kUniversalOptOut`, keeping this key's name. Trigger: a brave-core change
  that moves the key's map entry or removes `kBraveGlobalPrivacyControl`;
  then re-read the row and the scripts' description.
- `kBraveNewsNewUserOptIn` — would opt every new profile into News on first
  run, whatever the policy; off by default with no study. Trigger: the
  default flipping or a desktop Release study. Then say so in the News
  description and re-check the sidebar edge in the `BraveNewsDisabled` row.
- WebMCP tool scripts under `BraveAIChatEnabled` = false — still registered
  and downloaded, because the registration reads only process-wide features
  although brave-core's comment there says 'feature/policy state' (see the
  row). Trigger: brave-core gating `RegisterWebMcpComponent` on the policy,
  or `kAIChat` or Blink `kWebMCP` off by default at a shipping pin. Then drop
  the WebMCP sentence from the three scripts' AI Chat description and from
  the row.
- `kSensorsAllowAskBlockPermissionModel` — off upstream, force-enabled by a
  brave-core plaster, which is what makes `DefaultSensorsSetting` = 3 mean
  Ask. Triggers: Chromium enabling it by default (the plaster turns
  redundant; correct the row), or brave-core dropping the plaster or a
  Release study disabling it while the default is off (3 then means Allow:
  drop or relabel the Ask choice in the three scripts).
- `ClearBrowsingDataOnExitList` — dispatched on desktop
  (`BrowsingDataLifetimePolicyHandler`, factory `:2819-2822` in the
  `!IS_ANDROID` branch at 156.0.8078.80; YAML blob `64014ea157` unchanged
  through 157.0.8103.30 and main) and effective from source in a default
  Brave: `ProfileManager::OnBrowserClosed` clears the listed types when a
  profile's last window closes and is not off the record
  (`chrome/browser/profiles/profile_manager.cc:2284-2336`), and Brave's
  `signin.allowed_on_next_startup` default of false
  (`chromium_src/chrome/browser/profiles/pref_service_builder_utils.cc:31-32`
  at `v1.98.64`), copied into `signin.allowed` at profile creation, meets the
  precondition (`chrome_browsing_data_lifetime_manager.cc:447`). Not added:
  brave-browser#52221 (open, 1.86.142 on Linux) reports it clears nothing,
  which the source does not explain; history deletion removes only the
  previous run's session file
  (`components/sessions/core/command_storage_backend.cc:611-619`), so Brave's
  default Continue where you left off reopens the tabs, which can look like
  nothing was cleared. Trigger: its check under Runtime checks owed passes.
  Then add a list row at the end of Privacy & Security writing
  `["browsing_history","download_history","cookies_and_other_site_data","cached_images_and_files"]`
  (never `site_settings`, which wipes per-site Shields settings,
  `brave_browsing_data_remover_delegate.cc:182-184`), in Maximum Privacy only,
  labelled 'Clear History, Cookies and Cache on Exit' and described 'Deletes
  browsing and download history, cookies, site data and cache when a profile's
  last window closes, signing you out of every site; tabs left open still
  reopen. Skipped if a private window closes last, or on a crash or OS
  shutdown. Without Disable Sync, history and tab sync stop.' If the tabs do
  not reopen, replace '; tabs left open still reopen' with '. Passwords and
  site settings stay'. Never in Strict Parental Controls:
  `AllowDeletingBrowserHistory` = false voids its history and downloads half
  (`chrome_browsing_data_remover_delegate.cc:401-416`), so add a test that no
  preset carries both, and change Prevent Deleting History's 'Brave's
  clear-on-exit keeps them too' to 'clear-on-exit keeps them too'. On a fail,
  move it to Considered and rejected with the result and report it on
  brave-browser#52221.
- `SavingBrowserHistoryDisabled` — dispatched unguarded (factory `:411-413` at
  156.0.8078.80; YAML blob `461f3d91cf` unchanged through 157.0.8103.30 and
  main) and effective: non-explicit history access returns null
  (`chrome/browser/history/history_service_factory.cc:39-43`), so visits stop
  being recorded, Recently closed is emptied and Brave Sync's History and Open
  tabs stop, while downloads stay listed. Not added: brave-core builds Brave
  Sync's delegate with an `IMPLICIT_ACCESS` history service
  (`chromium_src/chrome/browser/sync/sync_service_factory.cc:11-18` at
  `v1.98.64`), null when the policy is set at launch, and dereferences it
  unchecked (`browser/sync/brave_sync_service_impl_delegate.cc:112-114`) from
  the first completed sync cycle whenever History is selected, by choice or
  through Sync everything (`components/sync/service/sync_prefs.cc:313-333`);
  the same on `1.99.x`, `1.100.x` and master. That is a source-read crash at
  every launch for a Brave Sync user who ticks the row without Disable Sync.
  It also records more than its name admits: the address bar still saves pages
  opened from it as shortcuts
  (`chrome/browser/ui/omnibox/chrome_omnibox_client.cc:1150-1161`) and site
  icons keep their page URLs
  (`components/favicon/core/favicon_handler.cc:276-277`). Trigger: brave-core
  null-checks `history_service_` or takes it with `EXPLICIT_ACCESS` (worth
  reporting to brave/brave-browser), or its check under Runtime checks owed
  shows no crash. Then a checkbox writing `true` at the end of Privacy &
  Security, in Maximum Privacy only (never Balanced Privacy or Strict Parental
  Controls), labelled 'Don't Save Browsing History' and described 'Brave stops
  adding visits to History and empties the Recently closed menu, but the
  address bar still learns pages you open from it, and site icons are kept.
  Downloads stay listed; history already saved stays until you clear it. Brave
  Sync stops syncing history and open tabs.' If `ClearBrowsingDataOnExitList`
  ships in Maximum Privacy too, re-read this description: that row clears at
  each exit what this one leaves behind.
- `kApproximateGeolocationPermission` — off on desktop at 156.0.8078.80 and
  157.0.8103.30, with no Griffin study at brave-variations `c73faf3`. When
  on, a managed `DefaultGeolocationSetting` also sets
  `GEOLOCATION_WITH_OPTIONS` (`content_settings_policy_provider.cc:691-700`).
  Its delegate merges one-time grants
  (`geolocation_setting_delegate.cc:122-124`), so Ask may keep an answer for
  a while. Trigger: the feature on for desktop, in code or by a study; then
  re-check Location Ask and its description.
- Cookie lock under `BraveShieldsEnabledForUrls` — the panel toggle still
  lifts third-party cookie blocking per site (see its row). The only lock is
  a managed `DefaultCookiesSetting`. It would also void every per-site
  cookie rule, Brave's own Shields-down and `BRAVE_COOKIES` rules included,
  and Ad Block Only Mode injects it too (see Cross-cutting). Not offered
  until it passes the four conditions on its own. Trigger: the runtime check
  below confirming the leak.
- Screenshot under `DeveloperToolsAvailability` = 2 —
  `DevToolsFullPageExtractor` never checks whether its attach succeeded, so
  Full page hangs and greys Screenshot out for the window. The code is the
  same on 1.99.x, 1.100.x and master, and no upstream report was found.
  Trigger: brave-core checking the attach result or adding a timeout; then
  shorten the Screenshot clause in the three scripts' DevTools description.
- `DefaultBrowserSettingEnabled` welcome-page crash — brave-core#40997 fixes
  it on 1.100.x and master; 1.98.x and 1.99.x ship without it. Trigger: the
  first Release carrying #40997 (a 1.100.x Release). Then drop the crash
  sentence from the description in the three scripts and from README's
  Performance & Bloat list, trim the row, and replace the owed runtime check
  with: *Set as default* is hidden on `brave://welcome` under the policy.
- macOS Omaha 4 updater — `kBraveUseOmaha4` is off in code
  (`browser/updater/features.cc:15`) and built only into macOS Brave
  (`browser/updater/buildflags.gni:17`); Griffin `UseOmaha4Study` turns it on
  for 100% of macOS Nightly and 25% of macOS Beta, not Release (no
  `policy_restriction`, so either `ChromeVariations` row keeps Sparkle). The
  updater's usage stats and its BraveUpdater crash uploads follow any
  installed BraveSoftware app's Crashpad uploads flag (156.0.8078.80
  `chrome/updater/usage_stats_permissions_mac.mm:34-38,60-67`), and it sets
  its own flag true and never clears it (`chrome/updater/crash_client.cc:143-156`).
  Trigger: the study reaching macOS Release, or the feature on by default.
  Then confirm on a Mac, with a pre-existing updater and every installed
  channel, that `MetricsReportingEnabled=false` leaves every Crashpad uploads
  flag off, and add a sentence to the MetricsReportingEnabled row. No new
  key.
- Prefs no policy reaches — no BraveSoftware YAML, `brave_simple_policy_map.h`
  entry or Chromium factory entry maps them at `v1.98.64` and 156.0.8078.80:
  the New Tab Page widgets (`brave.new_tab_page.show_stats`,
  `brave.new_tab_page.show_clock`, `brave.new_tab_page.show_background_image`,
  `ntp.shortcust_visible`, `brave.brave_search.show-ntp-search`;
  `NewTabPageLocation` can only replace the whole page), the sidebar
  (`brave.sidebar.sidebar_show_option`; never shown by default on Release,
  always on Beta and Nightly, `browser/ui/sidebar/sidebar_utils.cc:376-400`)
  and social-embed blocking
  (`brave.shields.{fb,twitter,linkedin}_embed_default`; Facebook and X
  allowed by default,
  `components/brave_shields/content/browser/ad_block_service.cc:464-466`).
  The README's 'What no policy reaches' names all three; history retention
  has its own item below. Unreachable but needing nothing: the first-run
  `brave://welcome` (`browser/ui/startup/brave_startup_tab_provider_impl.cc:24-25`;
  see `DefaultBrowserSettingEnabled`), the Settings Brave Origin card
  (`kBraveOrigin`, on in code; sends nothing unless clicked), the
  cookie-notice and switch-to-app list defaults (on,
  `components/brave_shields/core/common/features.cc:29,42-43`; unlockable)
  and Google push messaging (`brave.gcm.channel_status`, registered `false`).
  Trigger: a BraveSoftware YAML or simple-map entry that maps one of these
  prefs; then a row, and the item leaves the README note; for push
  messaging, also its default turning `true`. Griffin-only, Beta and Nightly
  at brave-variations `c73faf3`, no policy: the Brave Search promos
  (`BraveSearchPromotionBannerStudy`, `BraveSearchPromotionButtonStudy`),
  `StripImageMetadataV1` and `BraveRequestOTRTab`. Trigger: a Release study
  or a code default flip; if either privacy feature reaches Release by
  study, say in both `ChromeVariations` descriptions and the README that
  either row holds it back.
- `brave.history.retention_days` (Brave's Local history retention,
  `brave://settings/privacy`) — 1 day to forever, default 90
  (`browser/brave_profile_prefs.cc:469`); it sets the history expiry threshold
  (`chromium_src/components/history/core/browser/history_service.cc:37-52`)
  whatever `AllowDeletingBrowserHistory` says, and no `BraveSoftware/` YAML or
  `brave_simple_policy_map.h` entry maps it at `v1.98.64`, `1.99.x`, `1.100.x`
  or master, so Prevent Deleting History cannot keep history for review.
  Trigger: a brave-core policy for the pref; then lock a long retention in
  Strict Parental Controls and drop the caveat from that row's description.
- `LocalNetworkAccessBlockedForUrls` scope — the row and its description
  rely on LNA gating only public-to-local/loopback requests, with
  main-frame navigations and WebRTC unchecked
  (`kLocalNetworkAccessForNavigations` and
  `kLocalNetworkAccessChecksWebRTC` off at 156.0.8078.80, 157.0.8103.30 and
  main; `local_network_access_checker.cc:151-157`). Trigger: either feature
  on, or the checker gating local-to-loopback requests, in a shipping
  Brave; then re-check the row, the description's 'Pages opened from a
  local address still work' and the README line.
- `XSLTEnabled` — Chromium 158 turns XSLT off by default except via the
  deprecation trial and policy (`61634354c2`, in 158.0.8127.7); no Brave
  channel is on 158 yet. Trigger 1: the first shipping Brave on Chromium
  158 or later; reword the row to say `false` then blocks only
  deprecation-trial origins and CAP-alert documents. The label and
  description already hold, so no script changes. Trigger 2: the YAML
  capped or the XSLT engine deleted (M176 by the YAML's text); move the row
  to Considered and rejected, drop it from the three scripts and Maximum
  Privacy, and add it to `$script:retiredPolicies`.
- `DefaultJavaScriptJitSetting` — rejected because jitless hides the
  `WebAssembly` global and Brave builds no WebAssembly interpreter (see
  Considered and rejected). Trigger: brave-core building V8 with
  `v8_enable_drumbrake` and turning `kBraveWebAssemblyJitless` on by
  default, so its `--wasm-jitless` hook
  (`browser/brave_content_browser_client.cc:1167-1176` at `v1.98.64`) keeps
  WebAssembly working under jitless; then reconsider an opt-in row grouped
  with Disable JavaScript Optimization.
- `TranslatorAPIAllowed` on Chromium 157 — rejected while still live on
  1.98.x, because Brave's Chromium 157 upgrade switches the `Translator` API
  off in the renderer (see Considered and rejected). Trigger: the first
  shipping Brave on 157. Then confirm that `'Translator' in self` is false
  on a secure page (brave-core's
  `renderer/test/translation_web_apis_browsertest.cc` asserts it) and set
  the row to ⚠️ no-op in Brave, citing
  `renderer/brave_content_renderer_client.cc:165`.
- Rejected keys with a known flip trigger. `LiveCaptionEnabled` and
  `LiveTranslateEnabled`: brave-core's `IsLiveCaptionFeatureSupported`
  override stops returning false (1.100.x builds `BraveSodaInstaller` under
  `ENABLE_LOCAL_AI`, and the override still returns false there);
  `LiveTranslateEnabled = false` would then keep caption text from Google's
  translation API. `PromotionsEnabled`: `WhatsNewStudy` targets a shipping
  major again, when `false` would hide the post-update tab; there is still
  no honest promotions label. Re-read the row when either fires.
- `OriginKeyedProcessesEnabled` — if Chromium turns
  `kOriginKeyedProcessesByDefault` on by default (or Griffin does), `true`
  restates the default and locks nothing, because `brave://flags` still
  wins: drop the row then. Each pass also re-checks that a simple handler
  still applies a mandatory value for this recommended-only key.
- `AuthSchemes` without `negotiate` on Linux — would stop any site from
  cancelling `NetworkServiceSandboxEnabled` there
  (`system_network_context_manager.cc:610-614` at 156.0.8078.80). Not
  offered: it breaks Kerberos single sign-on. A candidate for a later
  batch of keys.
- `DynamicCodeSettings` — if Chromium turns `kBrowserDynamicCodeDisabled`
  on by default, the row only locks it; reword the description then.
- `AudioSandboxEnabled` — read straight from the policy service, with no
  factory entry (`chrome/browser/media/audio_service_util.cc:24-44` at
  156.0.8078.80; `pref_mapping/AudioSandboxEnabled.json`: "used directly
  through the policy service"); `chrome.*:79-`, restart, browser-wide; no
  brave-core override, no Griffin study. `true` sandboxes the audio service
  only on Linux. `kAudioServiceSandbox` is on by default on Windows and
  macOS and off on Linux, where the audio service still runs out of process
  (`content/public/common/content_features.cc:161-177` at 156.0.8078.80,
  unchanged at 157.0.8103.30 and main), so on Windows and macOS the key
  restates the default. Not offered: upstream keeps it off on Linux, the
  Linux broker hook allows only ALSA and PulseAudio paths
  (`services/audio/audio_sandbox_hook_linux.cc`), nobody has run it on a
  Brave, and a broken audio sandbox costs sound and microphone with no
  automatic fallback. Trigger: the Linux check that ends this item passes,
  or Chromium turns `kAudioServiceSandbox` on for Linux (then the key is
  only a lock). Then add a row in all three scripts labelled
  `Force Audio Sandbox (Linux; already on for Windows/macOS)`, ⚠️
  platform-limited, in Maximum Privacy, and widen ship condition 2 and the
  `Dispatch` definition to cover keys the browser reads directly from the
  policy service. The check: run a shipping Linux Brave with
  `AudioSandboxEnabled` = true in `/etc/brave/policies/managed`, on
  pipewire-pulse, PulseAudio and plain ALSA. Audio must play, the
  microphone must work in a WebRTC call, the audio service must not
  crash-loop, and its utility process must show `Seccomp: 2` in
  `/proc/<pid>/status`.
- `ExtensionInstallTypeBlocklist` — Chromium marks its `command_line` check
  `TODO(crbug.com/401529219)`, to be dropped once Chrome's `--load-extension`
  removal is fully launched (156.0.8078.80
  `chrome/browser/extensions/extension_service.cc:432-439`; unchanged at
  157.0.8103.30 and main 159.0.8136.0). Triggers: (1)
  `ShouldBlockCommandLineExtension` gone at a shipping pin: move the row to
  Considered and rejected and drop it from the scripts and presets. The row is
  dead if non-Google builds still honour the switch (then say in the README
  that Brave has no lock on it), and redundant if the switch is gone from
  every build. (2) `kDisableDisableExtensionsExceptCommandLineSwitch` on in
  Brave, by upstream default or a brave-core override: drop the
  `--disable-extensions-except` caveat from the three scripts and the README.
- `DownloadRestrictions` — dispatched (factory `:473-475` at 156.0.8078.80,
  unguarded; `chrome.*:61-`, not sensitive; YAML identical at 157.0.8103.30
  and main). Value 3 works in Brave: `ShouldBlockFile` returns true for
  `ALL_FILES` on every download that needs safety checks
  (`chrome/browser/download/chrome_download_manager_delegate.cc:2344-2389`),
  and `OnDownloadTargetDetermined` interrupts it with `FILE_BLOCKED`
  (`:2268-2275`); the Save As skip at `:893-896` is Android-only, and
  brave-core changes only `GetDangerLevel` and the completion gate
  (`browser/download/brave_download_manager_delegate.h:47-50` at `v1.98.64`).
  Not added alone: the YAML calls 3 'Not recommended, except for special use
  cases', and no preset wants it. The key's recommended value is 4, which
  blocks malicious downloads and is the download-side partner of
  `DisableSafeBrowsingProceedAnyway`; it depends on Safe Browsing download
  verdicts through Brave's proxy, which is unverified. Trigger: its check
  under Runtime checks owed. Then add both values as one same-key group in
  Access Controls: 'Block Malicious Downloads' (4, a Strict Parental Controls
  candidate) and 'Block All Downloads' (3, no preset), the latter described
  'Blocks every file download a web page or Save link as starts; saving the
  open page and printing to PDF still work. With Always Open PDF Externally
  ticked, PDFs cannot be opened at all. For kiosk-style lockdowns.' plus its
  mutual-exclusion sentence. The PDF clash stays a warning, not a group: each
  row holds one group, and value 3 needs it for value 4. If value 4 does not
  work in Brave, record 1, 2 and 4 in Considered and rejected and decide 3
  alone.
- `PasswordProtectionWarningTrigger` — value 0 (`chrome.*:69-`; desktop
  factory `:805-807` under `!IS_ANDROID` at 156.0.8078.80) stops PhishGuard's
  saved-password-reuse pings, which carry the page URL, frame URL and referrer
  chain
  (`components/safe_browsing/core/browser/password_protection/password_protection_request.cc:189-196`).
  A managed 0 wins for every account type
  (`chrome/browser/safe_browsing/chrome_password_protection_service.cc:2017-2031`)
  and `IsPingingEnabled` then refuses (`:1732-1735`); unset, desktop pings on
  every saved-password reuse while Safe Browsing is on
  (`:1724-1726,1764-1766`). Brave means to cancel these pings
  (`clientreport/login` is in the `CancelReportingUrl` test of
  `browser/net/brave_block_safebrowsing_urls_unittest.cc`), but they use the
  Safe Browsing network context, which brave-core routes through
  `OnBeforeSystemRequest`; there the block helper's `ERR_ABORTED` is discarded
  and the static redirect overwrites the URL with `sb-ssl.brave.com`
  (`browser/net/brave_system_request_handler.cc:33-45`,
  `components/static_redirect_helper/static_redirect_helper.cc:93-97`,
  `v1.98.64`; identical on `1.99.x`, `1.100.x` and master). Not added: the
  effect rests on that bug, and the cost, PhishGuard's reuse-phishing warning,
  depends on whether the proxy answers (unverified). Brave does not already
  abort the pings, so the key is not a no-op either. The ordering bug reaches
  every `clientreport/*` URL the helper lists and is worth reporting to
  brave-browser (no issue found). Triggers: (a) brave-core honours the block
  in `OnBeforeSystemRequest`: add the key to Considered and rejected as ⚠️
  no-op in Brave, citing the fix. (b) Brave declines, or the next pass finds
  the bug unfixed: run its check under Runtime checks owed, then add a Privacy
  & Security checkbox 'Stop Password Reuse Pings', value 0, in Maximum
  Privacy, with '(security trade-off)' in the label only if the proxy answers,
  described 'Stops Brave sending the page address and recent navigation trail
  to its Safe Browsing proxy when you type a saved password on a site it isn't
  saved for. You lose the warning that such a site may be phishing.' (drop the
  last sentence if the proxy does not answer).
- Brave Origin — real-machine runs of the deb on Debian/Ubuntu, the rpm on
  Fedora/openSUSE, Origin beta and nightly, and mixed machines with regular
  Brave beside Origin. The checklist with exact commands and expected output
  is `TESTING-brave-origin.md` on the `brave-origin-detection` branch.
- nixpkgs `brave-origin` from source — draft NixOS/nixpkgs#551523 would
  replace the deb repackage with a source build under `$out/libexec/`.
  Trigger: it merges; then re-read the whole Nix row of Where Origin lives.
- Tool fixes with no upstream trigger, open until chosen: (1) DoH parity —
  the Python scripts write and export a template with `automatic` and check
  only that a `custom`/`secure` template is non-empty; `SlimBrave.ps1` writes
  one only with `custom`/`secure` and validates it as an absolute https URL
  (`Test-DohTemplate`); pick one behaviour and test it. (2) Linux Origin
  detection: a Beta- or Nightly-only deb/rpm install also gets a stable
  `Origin` record, because the bare `brave-origin` alternative points at its
  launcher (see What the tool does with it). (3) macOS Origin: `MAC_CHANNELS`
  lacks `com.brave.Browser.origin{,.beta,.nightly}` (see Platform policy
  locations). (4) Import names only values a row cannot take (off-enum choices;
  in `SlimBrave.ps1` also a foreign list or an unknown `DnsMode`) and, in the
  Python scripts, Origin built-ins, so a key that matches no row
  (`AlternateErrorPagesEnabled`, `DNSInterceptionChecksEnabled`,
  `MediaRecommendationsEnabled`, `SafeBrowsingExtendedReportingEnabled`,
  `SafeSitesFilterBehavior`, `ShoppingListEnabled`, `BackgroundModeEnabled`
  and `NetworkServiceSandboxEnabled` on macOS, or `DynamicCodeSettings` in
  the Python scripts) is dropped without a word. (5)
  `SlimBrave.ps1` import accepts a float for a choice
  key and rounds it: under PowerShell 7 `2.0`, `2e0` and `2.5`; under Windows
  PowerShell 5.1, the elevated relaunch host, only exponent forms such as
  `2e0`, since `2.0` and `2.5` arrive as `[decimal]` and are rejected and
  named (see Cross-cutting, Content-setting enums); the Python scripts reject
  all of them.
  `MAC_CHANNELS` needs no Dev entry: Brave dropped Dev (brave-browser#25248)
  and its macOS Dev appcast stopped at 1.61.87 (2023-11).
- Runtime checks owed on a shipping Brave:
  - Before merge, and the row ships only if it passes:
    `NetworkServiceSandboxEnabled` = 1 on Windows x64 (Brave 1.98.6x or
    1.99.x). Apply it with `SlimBrave.ps1`, restart Brave and open
    `brave://sandbox`: the Network Service must be listed as sandboxed
    (AppContainer), not unsandboxed. Also load a page in a Tor window with
    Tor allowed, Brave's local SOCKS proxy path, which Chrome's trial never
    covers; if Tor breaks, say so in the description before shipping. If the
    service shows unsandboxed (the failed-launch fallback,
    `system_network_context_manager.cc:260-266,396-406`), the row does not
    ship: take it out of the three scripts, Maximum Privacy and the Chromium
    table, and turn this item into a watch item saying the key is dispatched
    on Windows and Linux (factory `:1988-1992` at 156.0.8078.80) and is the
    only way to sandbox Brave's network process, but `brave://sandbox` on
    Windows x64 showed it unsandboxed with the key set (date, version);
    trigger: a later Brave shows it sandboxed, then add the row back as it
    stands now. On Linux, before release if at all possible: the network
    utility process shows `Seccomp: 2` in `/proc/<pid>/status`, pages load,
    and a `.local` or intranet name still resolves; repeat on the Flatpak
    build, where zypak replaces Chromium's sandbox. If Linux fails, keep the
    row `SlimBrave.ps1`-only (both Python scripts omit it, like
    `DynamicCodeSettings`) and record why here.
  - `DefaultJavaScriptOptimizerSetting` = 2: does the address bar show
    upstream's shield-glyph 'JavaScript optimizations are disabled' page
    action on every page? If it does, add one short sentence to the
    description, trimming elsewhere to stay at 300 characters or fewer, and
    to the README line. Optional: a web tab opened after Apply shows
    `--js-flags=--disable-optimizing-compilers` on its renderer's command
    line in the OS process list.
  - `OriginKeyedProcessesEnabled` = true: `brave://process-internals` shows
    a same-site cross-origin subframe (for example `ogs.google.com` inside
    `www.google.com`) in its own origin-keyed process, and setting
    `brave://flags#origin-keyed-processes-by-default` to Disabled undoes it
    after a restart.
  - `DynamicCodeSettings` = 1 on Windows:
    `Get-ProcessMitigation -Id <browser pid>` shows BlockDynamicCode ON for
    the browser process, and Brave starts, browses, prints through the
    system dialog with a vendor driver, and accepts IME input without
    crashing.
  - `DefaultBrowserSettingEnabled` = false with *Set as default* on the
    first-run welcome page (brave-browser#60038 confirms the crash on
    1.97.59 for Linux; Windows, macOS and 1.98.60 still to run).
  - `BraveRewardsDisabled` = true with no `ChromeVariations`: does Brave
    still fetch `static.ads.brave.com/v1/ohttp/hpkekeyconfig`
    (`brave://net-export`, on a fresh profile's second launch, since a
    desktop applies a Griffin seed only from then)? Source says yes. It can
    be pre-run on Nightly 1.101.x, which carries brave-core#40666: with
    `ChromeVariations` = 1 and with 2, the fetch should still appear, from
    the first launch.
  - The Sponsored Ads items above.
  - `MetricsReportingEnabled` on Windows: with the key unset and
    *Automatically send diagnostic reports* on, does a crash after startup
    (`brave://crash`) get an upload ID on `brave://crashes`? Source says no
    (see its row).
  - `BrowserSignin`: does any shipping build carry a Google OAuth client? On
    Brave Release for Windows, macOS and Linux, with no `BrowserSignin`
    policy applied, turn on "Allow Google login for extensions" in
    `brave://settings/extensions`, restart, and read `signin.allowed` in
    `brave://prefs-internals`. Trigger: false on all three, so the key only
    greys out a dead toggle (a client from the environment or
    `--oauth2-client-id` is an opt-in and does not count); then move it to
    Considered and rejected as ⚠️ no-op in Brave, drop it from the three
    scripts and the Balanced Privacy, Maximum Privacy and Strict Parental
    Controls presets, and add `"BrowserSignin" = 0` to
    `$script:retiredPolicies`. If it turns true on a platform, name that
    platform in the row.
  - `DeveloperToolsAvailability` = 2: on an ordinary page, Screenshot > Full
    page never completes, and all three modes stay greyed in that window
    until it is closed. Ctrl+U and right-click View page source show the
    policy dialog; a typed `view-source:https://example.com` still opens.
  - `DefaultGeolocationSetting` = 3: two `getCurrentPosition` calls on one
    page prompt twice, a reload prompts again, and a site allowed before the
    policy is prompted.
  - Before or with the release: under `BraveShieldsEnabledForUrls`, a
    toggle-off click leaves Shields on but lets a third-party embed keep
    persistent cookies across a tab close, and the site's cookie exceptions
    in `brave://settings` show the change; under
    `BraveShieldsDisabledForUrls`, a listed site's third-party embed still
    gets only ephemeral cookies.
  - `ChromeVariations` = 1 (neither check blocks the row): on Windows 11
    with a TPM and a Google account signed in on the web, still signed in
    after more than 2 hours (brave-browser#50411)? With
    `brave://flags/#brave-webgl-balanced-fingerprinting-protections` on,
    `UNMASKED_RENDERER_WEBGL` reads `Brave`; without it, the GPU renderer.
  - `BraveAIChatEnabled` = false on a fresh 1.98.6x profile: after the first
    launch `brave://components` lists Brave WebMCP Tool Scripts with a
    non-zero version, and `brave://net-export` shows its CRX download.
  - `AudioCaptureAllowed` / `VideoCaptureAllowed` = false (not blocking; Linux
    suffices): in a profile that had granted a site the microphone and camera,
    a `getUserMedia` test page gets `NotAllowedError` with no prompt and the
    earlier Allow ignored, and removing the key brings the prompt back without
    a restart; screen sharing (`getDisplayMedia`) is still offered. Note
    whether Leo's voice input still works (the descriptions promise only sites
    and extensions).
  - `ExternalProtocolDialogShowAlwaysOpenCheckbox` = false (not blocking): on
    an https page, a `mailto:` link's prompt has no 'Always allow' checkbox; a
    site and scheme remembered before Apply still opens without a prompt; the
    next prompt follows a change without a restart, despite `dynamic_refresh:
    false`.
  - Before `ClearBrowsingDataOnExitList` can ship (see its item above; Brave
    1.98.6x or 1.99.x, Linux or Windows, a fresh profile on defaults): write
    only that key with the four types and confirm `brave://policy` shows it
    OK; visit three or four sites, sign in to one, download a file, open and
    close one extra tab and leave two open; close the last window with no
    private window open, wait for the process to exit, and relaunch. Pass:
    pages seen only in the closed tab are gone from `brave://history`,
    `brave://downloads` is empty, the site is signed out and History >
    Recently closed is empty; record whether the two tabs reopen and whether
    Back still reaches earlier pages. Repeat with a private window closed
    last: nothing is cleared. Fail: history or cookies survive.
  - Before `SavingBrowserHistoryDisabled` can ship, unless brave-core fixes
    its Sync delegate first (see its item above): with Brave Sync set up and
    Sync everything on, write the key while Brave is closed, launch, and leave
    Brave open until `brave://sync-internals` shows a completed sync cycle;
    relaunch twice more. Pass: no crash. Also record that new visits stay out
    of `brave://history` and that a page opened by typing its address is still
    suggested by the address bar.
  - Before `DownloadRestrictions` is decided (see its item above): with Safe
    Browsing on, the download-warning samples on
    `testsafebrowsing.appspot.com` get a dangerous verdict through Brave's
    proxy, and with `DownloadRestrictions` = 4 they are blocked with no Keep
    option.
  - Before `PasswordProtectionWarningTrigger` is added (see its item above):
    capture `brave://net-export` while typing a saved password on another
    site, and see whether the `clientreport/login` request goes to
    `sb-ssl.brave.com` and gets a verdict.
  - Optional: `PrintingEnabled` = false, then Screenshot (Ctrl+Shift+S) >
    Full page on a docs.google.com document: no image, and the tool stays
    usable afterwards.
  - Optional: `DefaultNotificationsSetting` = 3, allow the prompt on a test
    site, then run `new Notification('x')`: nothing shows.
  - Optional, since the source is unambiguous: with
    `ExtensionInstallTypeBlocklist` = `["command_line"]`, an extension passed
    with `--load-extension` does not appear in `brave://extensions`, while
    `--disable-extensions-except` with the same folder loads it; with
    `ForceYouTubeRestrict` = 2, YouTube's Restricted Mode toggle shows locked
    on and a youtube-nocookie.com embed still plays a video Restricted Mode
    hides; with `SafeBrowsingProtectionLevel` = 1 and
    `DisableSafeBrowsingProceedAnyway` = true, `brave://settings/security`
    shows the radios as managed and
    `testsafebrowsing.appspot.com/s/malware.html` offers no way through; with
    `SSLErrorOverrideAllowed` = false, self-signed.badssl.com shows no Proceed
    link and typing the bypass phrase does nothing; with
    `AccessibilityImageLabelsEnabled` = false, a profile whose
    `settings.a11y.enable_accessibility_image_labels` is true stops posting to
    `ckintersect-pa.googleapis.com` while NVDA or Orca runs.
- Under consideration, not decided: a Preview (dry-run diff of what Apply will
  change) and a Verify (read the policy location back and compare) — the two
  usability features the Windows-only Brave-Free-Origin project has and this
  one lacks.

## Done log

One line per change to what the tool writes or how this document judges it,
with the reference that carries the detail. Newest first.

| When | What | Reference |
|---|---|---|
| 2026-10-24 | Pass at the new pins (Brave 1.98.60, Chromium 156.0.8078.48), every row re-read. `SafeBrowsingExtendedReportingEnabled` removed (capped at cr144; handler and pref mapping deleted before 156) and `SafeSitesFilterBehavior` removed (blocks nothing in Brave, which ships no Google API key, yet sends every URL to Google): 78 → 76 rows, 74 → 72 keys; `SlimBrave.ps1` Apply and Reset now delete retired keys it wrote. `AutofillAddressEnabled` / `AutofillCreditCardEnabled` → ⚠️ deprecated, still applied (kept by the maintainer's decision while `AutofillSettings` is inert); `DefaultBraveHttpsUpgradeSetting` → ⚠️ (Griffin's `TransitionToUpstreamHttpsUpgrade` turns Brave's upgrader off on Beta, Nightly and part of Release; `ChromeVariations` keeps it); `DNSInterceptionChecksEnabled` → ⚠️ inert (Chromium skips the probes unless `IntranetRedirectBehavior` is 3). New watch items: Brave's HTTPS transition, Chromium's GPC, the News new-user opt-in, `AlternateErrorPagesEnabled` on 157, the sensors Ask model, the nixpkgs source build. Descriptions corrected for QUIC, Sync, Network Prediction, ChromeVariations, Talk, Browser Sign-in, Basic Auth, sideloaded extensions, Local AI, Default Browser, Rewards, Stats Ping and the two Autofill rows | v2.3.3, PR #30 (`b228a18`) |
| 2026-09-28 | Full pass at the new pins (Brave 1.96.59, Chromium 154.0.8037.58), every key re-read through dispatch, feature defaults and Griffin studies. `EmailAliasesEnabled` ⚠️ → ✅ (Griffin enables it on Release); `BravePlaylistEnabled`, `BraveLocalAIEnabled` → ⚠️ feature off on Release/Beta; `SafeBrowsingExtendedReportingEnabled`, `AlternateErrorPagesEnabled`, `ShoppingListEnabled` → ⚠️ inert, kept with a caveat in their labels; `RemoteDebuggingAllowed` loses its restart note; `PsstEnabled` → ⚠️ (dispatched since 1.95); `BraveSearchResultAdsEnabled` → ❌; FirstPartySets / RelatedWebsiteSets → ❌; `AutofillSettings` → ⚠️. Sponsored Ads has no policy key; `BraveRewardsDisabled` keeps the ads service off, so it also stops NTP sponsored wallpapers, not Brave Search's own ads. No key added or removed; labels, descriptions, comments and README corrected | v2.3.2, PR #29 (`e5249d0`); brave-browser#51040, #54917 |
| 2026-09-11 | Brave Origin on Linux: policy directory proven, detection for every packaging, 13 dead keys shown inert on Origin-only machines; nothing changed for other users | v2.3.1, PR #25 (`a5df793`), issue #13 |
| 2026-09-07 | Every key re-read at the shipping tag through dispatch, not only YAML; `MediaRecommendationsEnabled` found dead and removed from all three scripts and four presets: 79 → 78 rows, 75 → 74 keys. Platform location chains, the Ad Block Only Mode provider, Origin preset parity and the `rewrite/` override mechanism recorded | PR #24 (`f0b32d1`), commit `192689f` |
| 2026-09-06 | Keyboard access in the Windows GUI; frames and a description pane in the TUI; TUI smoke test in CI | v2.3.0 |
| 2026-09-03 | `HardwareAccelerationModeEnabled` gained its off state as a mutually exclusive pair; no preset carries it | v2.2.1 |
| 2026-08-29 | All keys re-verified, no change; the `RemoteDebuggingAllowed` `dynamic_refresh` flip on main (`80ad0b9`) noted as not yet shipping | this document's history |
| 2026-08-28 | The eight `Default*Setting` permission rows became choice rows exposing each key's real enum (1/2/3 or ask/block only) | v2.1.0 |
| 2026-08-13 | First full audit: every key checked against source; `EnableDoNotTrack` removed as non-existent; branch probing adopted over `supported_on` arithmetic; the Brave-version column dropped | this document's history |
| 2026-06 to 2026-08 | Keys added in that window: `BraveShieldsEnabledForUrls`, `EmailAliasesEnabled`, the five `DefaultBrave*` enforcers, `PasswordLeakDetectionEnabled`, `NetworkPredictionOptions`, `PaymentMethodQueryEnabled`, `AlternateErrorPagesEnabled`, `ExtensionInstallBlocklist`, `SafeSitesFilterBehavior`, `BrowserGuestModeEnabled`, `HighEfficiencyModeEnabled`, `HardwareAccelerationModeEnabled`, `EnableMediaRouter`, `ChromeVariations`, `SpellCheckServiceEnabled`, `RemoteDebuggingAllowed`, `DNSInterceptionChecksEnabled`, `BasicAuthOverHttpEnabled`, the device-API trio, `DefaultLocalFontsSetting`, `DefaultWindowManagementSetting`, `BlockExternalExtensions`, `BraveLocalAIEnabled` | git log of the three scripts |

## Commands for a pass

Verified to work; the paths are the ones that bit before.

- **Enumerate every Chromium policy name** (the group directories are not
  guessable; a 404 on a guessed path proves nothing):
  `gh api repos/chromium/chromium/contents/components/policy/resources/templates/policy_definitions --jq '.[]|select(.type=="dir")|.name'`,
  then the same call per group with `select(.type=="file")|.name`. Pin to a
  tag with `?ref=<tag>`. To count policies, skip `.group.details.yaml` and the
  `policy_atomic_groups.yaml` files, or count the ids in `policies.yaml`.
- **One Chromium YAML at the pinned tag:**
  `https://raw.githubusercontent.com/chromium/chromium/<tag>/components/policy/resources/templates/policy_definitions/<Group>/<Key>.yaml`
  — read `deprecated`, `supported_on`, `future_on`, `features`, `schema`.
- **brave-core's edits to Chromium policy YAML:** at the tag,
  `ls patches | grep components-policy-resources-templates` and
  `find rewrite -path '*policy/resources/templates*'`. At `v1.98.60` there are
  two patches and nothing in `rewrite/`:
  `…Miscellaneous-MetricsReportingEnabled.yaml.patch` drops `sensitive: true`
  (why an HKLM write works on a home PC; see its row) and
  `…Miscellaneous-DnsOverHttpsMode.yaml.patch` drops
  `default_for_enterprise_users: 'off'`. For those keys read the tag's YAML with
  the patch applied; `chromium_src/components/policy/resources/policy_templates.py`
  only adds the `BraveSoftware` group.
- **Dispatch of a Chromium key:** `chrome/browser/policy/configuration_policy_handler_list_factory.cc`
  at the tag: a `key::k<Key>` entry or, for a key with a dedicated handler
  class (16 of the 61 Chromium keys written at 156.0.8078.48, through 14
  handler classes, e.g.
  `syncer::SyncPolicyHandler`, `SecureDnsPolicyHandler`,
  `autofill::AutofillSettingsPolicyHandler`), the handler source that reads
  `key::k<Key>` and the factory line that registers that class, with any
  `#if BUILDFLAG(...)` around it resolved (`BrowserSigninPolicyHandler` is
  registered only inside a `LegacyPoliciesDeprecatingPolicyHandler`). Then
  `components/policy/test/data/pref_mapping/<Key>.json`
  (`Policy was removed` = dead).
- **Brave YAML at a release branch:**
  `https://raw.githubusercontent.com/brave/brave-core/<1.9N.x>/components/policy/resources/templates/policy_definitions/BraveSoftware/<Key>.yaml`;
  walk branches to find where a key first ships.
- **Brave dispatch and guards:** clone brave-core at the tag
  (`git clone --depth 1 --branch v<ver>`), then `browser/policy/brave_simple_policy_map.h`
  for the `#if BUILDFLAG(...)` around each entry (some have none), and
  `chromium_src/chrome/browser/policy/configuration_policy_handler_list_factory.cc`
  for the handlers brave-core registers itself, unguarded: the five
  `DefaultBrave*` keys, which have no simple-map entry (sources in
  `browser/policy/handlers/`). For what Origin compiles out,
  `grep -rn "is_brave_origin_branded" --include='*.gni' .` over the whole tree
  (24 files at `v1.98.60`); `components/` alone misses
  `browser/brave_stats/buildflags.gni`
  (`enable_brave_stats_updater = !is_brave_origin_branded`), which drops the
  stats updater behind the unguarded `BraveStatsPingEnabled` entry. Search
  `chromium_src/`, `patches/` and `rewrite/` before saying an override lapsed.
- **Origin's own set:** `browser/brave_origin/brave_origin_service_factory.cc`.
- **Runtime proof of the Linux policy dir:** with Brave running, the inotify
  watches in `/proc/<pid>/fdinfo/<fd>` of the browser process map (by inode)
  to `/etc/brave/policies/managed`. To read `chrome://policy` headlessly, drive
  `--remote-debugging-pipe` and walk the shadow DOM: the page is a bare
  `<policy-app>` whose rows render in shadow roots, which neither `innerText`
  nor `--dump-dom` traverses (it prints `document.documentElement.outerHTML`,
  `components/headless/command_handler/headless_command.js:225` at
  156.0.8078.48); `--headless=new --dump-dom chrome://policy` also hung on
  Brave Origin 1.94.121 (not re-tried since). Always pass a scratch
  `--user-data-dir`, or the run creates
  `~/.config/BraveSoftware/Brave-Origin-<Channel>` profiles that make the
  detector report channels that are not installed.

## Re-verification procedure

0. Start in the source, not the templates: `browser/policy/brave_simple_policy_map.h`
   (and, for the `DefaultBrave*Setting` keys, the handlers registered in
   `chromium_src/chrome/browser/policy/configuration_policy_handler_list_factory.cc`)
   proves the browser dispatches a key and shows the `#if BUILDFLAG(...)` guards
   that make one a no-op on a platform (how `BraveVPNDisabled` on Linux and the
   thirteen Origin keys were caught); `browser/brave_origin/brave_origin_service_factory.cc`
   tells you which value Brave itself considers debloated.
1. Diff the key list in each script against the two YAML directories.
2. For any key, read the YAML's `deprecated:`, `supported_on:` and `features:`
   (`dynamic_refresh`, `per_profile` — the restart and browser-wide notes come
   from there). A `cloud_only: true` there, or a `CloudUserOnlyPolicyChecker`
   wrapping the key's handler in the factory (grep next to `key::k<Name>`),
   means no platform source can set the key: reject it. **The YAML is not
   enough:** a policy can be removed from the code and left in the templates
   for years. For every Chromium key confirm dispatch at the tag in
   `configuration_policy_handler_list_factory.cc` (or its
   dedicated handler) **and** read `pref_mapping/<Key>.json` — `Policy was
   removed` means dead. For every Brave key, the `brave_simple_policy_map.h`
   entry or the registering handler, with its buildflag resolved through the
   `.gni`. A dispatched key can still be inert behind a `base::Feature` that is
   `FEATURE_DISABLED_BY_DEFAULT`: find the feature the pref is read alongside
   and say so in the row.
3. Read at the Chromium tag brave-core's `package.json` pins, not only at
   `main`: main says what is coming, the tag says what the installed browser
   does.
4. Never derive a shipping Brave version from `supported_on`; probe the
   release branches.
5. When brave-core is the reason a key is in or out, look in `chromium_src/`,
   `patches/` **and** `rewrite/` before concluding an override lapsed, then
   fetch the file at the tag.
6. `brave://policy` shows a compiled-out or dead key as applied, status OK. It
   cannot tell a dead key from a live one; only the pref's absence, or an
   injection test, can.
7. A `rewrite/` plaster of type `set_blink_runtime_enabled_feature_state`
   changes only the `base::Feature` default (`base_feature_status`). A Blink
   flag whose `status` is `stable` stays on unless a field trial or the
   command line overrides that feature, in either copy mode (156.0.8078.80
   `third_party/blink/renderer/build/scripts/templates/runtime_enabled_features.cc.tmpl:199-210`;
   brave-core `dea04e59d7` says the same). When a row or a rejection relies
   on such a plaster to say a web API is off, also cite the browser-side
   gate on that feature (as `AIManager` and `PrerenderHostRegistry` check
   theirs) or a renderer switch-off in
   `renderer/brave_content_renderer_client.cc`
   (`EnableFeatureFromString(..., false)`, `EnableFledge(false)`).
