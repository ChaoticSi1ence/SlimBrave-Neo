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
⚠️ dispatched but inert or platform-limited, caveat in the label, or
deprecated upstream yet still applied while its successor does not work in
Brave, caveat in the description · ⛔ deprecated upstream, not exposed · ❌
does not exist · 💀 dead: YAML present, handler gone · 🕓 not yet in a
shipping Brave, watch. `Min` is the Chromium
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
tiebreaker source. `tests/test_audit.py` parses this file and fails CI when it
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
| Considered and rejected | 2026-10-24 | as the two key tables | as the two key tables |
| Sponsored Ads coverage | 2026-10-24 | brave-core `v1.98.60`, `1.99.x`, master; brave-browser#51040, #54917, #57204, #59687; brave-core#35873, #39810, #40173 | `ads_service_impl.cc`, `view_counter_service.cc`, `brave_settings_ui.cc`, `http_client.cc`, the refreshed NTP panels; source-read, not runtime-tested |
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
  `MediaRecommendationsEnabled`, `SafeBrowsingExtendedReportingEnabled`,
  `SafeSitesFilterBehavior`), each only while it still holds the DWORD
  SlimBrave wrote; the Python scripts rewrite their whole policy file or
  plist, so a retired key goes on the next Apply there. On
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
  TUI; macOS and Linux). Same rows, in the same order within each category
  (the PS1 GUI puts Shields & Content Protection before Brave Features; no
  test checks category order). Same descriptions: the PS1 Tips, held equal by
  a test; the one variant is the `BraveVPNDisabled` row on Linux, which both
  Python scripts label as having no effect there. Same presets: the six
  `Presets/*.json`, which the PS1 embeds verbatim. Import/export files
  round-trip between all three, with one DoH gap: `SlimBrave.ps1` writes and
  exports a template only with `custom` or `secure`, the modes in which every
  UI enables the template field, but the Python scripts also write and export
  one with `automatic` (`_build_policy` and `export_settings` in both). The
  template can come from an import, `--doh-templates`, the policy file read at
  launch, or text typed under `custom`/`secure` before switching mode; their UI
  then greys the field and cannot clear it (What's next). Two exceptions
  by design: `slimbrave-mac.py` on macOS has no `BackgroundModeEnabled` row
  and ignores that key on import without a note; on a Linux machine whose
  only Brave is Origin, the Python scripts leave the 13 `ORIGIN_BUILTIN_KEYS`
  unmanaged on import, with a note, and out of export.
- **Inventory: 76 rows over 72 distinct keys** (`ChromeVariations`,
  `IncognitoModeAvailability`, `DefaultBraveReferrersSetting` and
  `HardwareAccelerationModeEnabled` have two rows each), plus
  `DnsOverHttpsMode` and `DnsOverHttpsTemplates` from the DNS section — 74
  keys written, 27 Brave and 47 Chromium. Fewer reach some machines:
  `slimbrave-mac.py` on macOS has 75 rows over 71 keys (73 written), since
  `BackgroundModeEnabled` is `chrome.win` / `chrome.linux` only; on a Linux
  machine where every Brave found is Origin (and no `--policy-file`), the
  Python scripts mark the 13 `ORIGIN_BUILTIN_KEYS` rows inert and write at
  most 61. Seven categories: Telemetry & Reporting, Privacy & Security, Site
  Permissions, Access Controls, Brave Features, Shields & Content Protection,
  Performance & Bloat. Six presets, all derived from the same tables.
- **A key ships only when all four hold:** its YAML exists at the pinned tags
  (Chromium's `policy_definitions/` for Chromium keys, brave-core's
  `BraveSoftware/` for Brave keys; see Sources and pins); the regular
  (non-Origin) Brave build dispatches it on at least one platform the row is
  offered on (a Chromium handler at the Chromium tag, a
  `brave_simple_policy_map.h` entry that is unguarded or whose buildflag is on
  there, or a handler brave-core registers in its `chromium_src/` override of
  `configuration_policy_handler_list_factory.cc`); the value written is a
  legal schema member meaning what the label says; and there is a product
  reason. A key inert somewhere — dispatched but without effect (e.g. behind
  an off-by-default feature), or with its map entry compiled out of one
  platform's build (`BraveVPNDisabled` on Linux) — stays only with the caveat
  in its label, in every script that offers the row there; features Brave
  Origin compiles out are handled by `ORIGIN_BUILTIN_KEYS` instead (see Brave
  Origin on Linux). A key Chromium marks `deprecated: true` while its handler
  still applies it and its successor does not yet work in Brave stays,
  marked ⚠️ with the caveat in its description, until the successor works or
  the key stops applying (`AutofillAddressEnabled` and
  `AutofillCreditCardEnabled` at 156; the trigger is in What's next).
  Nothing dead ships — a switch that silently does nothing is worse than no
  switch.
- **This document is enforced.** `tests/test_audit.py` parses the tables here
  and asserts: every key the scripts write appears in a key table with ✅ or
  ⚠️; nothing in Considered and rejected, and nothing marked ⛔ ❌ 💀 🕓, is
  written by any script; `ORIGIN_BUILTIN_KEYS` in both Python scripts equals
  the set of written Brave keys whose Dispatch is a guarded map entry
  ("map, `ENABLE_…`"), each is named in Brave Origin on Linux, and no
  "map, unguarded" key is in it; the bold rows-over-keys pair above matches
  the feature and choice rows of `slimbrave-linux.py`'s `build_rows()` (keys
  written, categories and presets are not asserted); every Status cell uses
  the vocabulary; the ledger has rows for Brave-specific keys,
  Chromium-inherited keys, Brave Origin on Linux and Considered and rejected,
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
| BraveP3AEnabled | ✅ | cr138 | bool | map, unguarded | unset = enabled (the Origin-branded build registers the pref `false`, `components/p3a/p3a_service.cc:96-97`); restart per YAML (`brave://policy` flags a changed value "restart required", the only use Chromium makes of `dynamic_refresh`, `components/policy/core/browser/policy_conversions_client.cc:333-360` at 156.0.8078.48), but applies live: `P3AService` watches `brave.p3a.enabled` and starts or stops reporting (`components/p3a/p3a_service.cc:195-200,289-299`); browser-wide. Also stops P3A's copy of the stats ping's search counts (`Brave.Search.SERP*`, see BraveStatsPingEnabled) |
| BraveStatsPingEnabled | ✅ | cr138 | bool | map, unguarded | unset = enabled; restart per YAML, but every reader checks the pref when it acts, so a change applies live; browser-wide. The pref (`brave.stats.reporting_enabled`) also stops SERP-metrics collection (`browser/serp_metrics/serp_metrics_tab_helper.cc:115-117`), whose search counts the ping carries, and referral initialization and finalization (`components/brave_referrals/browser/brave_referrals_service.cc:471-480,535-543`). P3A carries a bucketed copy of the search counts (`Brave.Search.SERP*`, `browser/serp_metrics/serp_metrics_p3a.cc:83-103`); with collection off it still sends `SERPBrave` = 0 daily until `BraveP3AEnabled` stops P3A |
| BraveGlobalPrivacyControlEnabled | ✅ | cr142 | bool | map, unguarded | dynamic refresh; unset = enabled, no Settings toggle: `IsGlobalPrivacyControlEnabled` returns true unless the pref is managed (`components/global_privacy_control/global_privacy_control_utils.cc:16-22`), so `true` only outranks Ad Block Only Mode's injected `false` (see Cross-cutting) and pins against a default flip. The signal sits behind `kBraveGlobalPrivacyControl`, on by default (`chromium_src/third_party/blink/common/features.cc:40`); `brave://flags/#brave-global-privacy-control-enabled` turns it off and the policy cannot override that |
| BraveDeAmpEnabled | ✅ | cr140 | bool | map, unguarded | dynamic refresh; the pref defaults on with a Settings toggle (`components/de_amp/common/pref_names.cc:13`), so the key locks it and outranks Ad Block Only Mode's injected `false` (see Cross-cutting). No Shields check (`components/de_amp/browser/de_amp_body_handler.cc:102-105`), so it works where Shields are off. `brave://flags/#brave-de-amp` turns the feature off and the policy cannot override it |
| BraveDebouncingEnabled | ✅ | cr140 | bool | map, unguarded | dynamic refresh; the pref defaults on with a Settings toggle (`components/debounce/core/browser/debounce_service.cc:55`), so the key locks it and outranks Ad Block Only Mode's injected `false` (see Cross-cutting). No Shields check (`components/debounce/content/browser/debounce_navigation_throttle.cc:99-101`), so it works where Shields are off. `brave://flags/#brave-debounce` turns the feature off and the policy cannot override it: no `DebounceService` is built (`browser/debounce/debounce_service_factory.cc:46-47`) |
| BraveTrackingQueryParametersFilteringEnabled | ✅ | cr142 | bool | map, unguarded | dynamic refresh; only effective while Shields are up (`browser/net/brave_site_hacks_network_delegate_helper.cc:77-78`); unset = enabled, no user toggle (the pref is read only when managed, `:58-67`), so `true` only keeps filtering on against Ad Block Only Mode's injected `false` (see Cross-cutting). The parameter list is the Query Filter component, on by default (`components/query_filter/common/features.cc:13`) |
| BraveReduceLanguageEnabled | ✅ | cr140 | bool | map, unguarded | dynamic refresh; the pref (`brave.reduce_language`) defaults on with a Settings toggle, so the key locks it and outranks Ad Block Only Mode's injected `false` (see Cross-cutting); `brave://flags/#brave-reduce-language` turns the feature off and the policy cannot override it. It governs the `Accept-Language` header (cut to the first language) and the local-font allowlist, both only where Shields are up and fingerprinting is not off: `ShouldDoReduceLanguage` (`components/brave_shields/core/browser/brave_shields_utils.cc:374-390`) bails when Shields are down, when fingerprinting is `ALLOW` for the site (e.g. `DefaultBraveFingerprintingV2Setting` = 1) or on a `BRAVE_WEBCOMPAT_LANGUAGE` exception. `navigator.languages` is farbling's, not this key's (`chromium_src/third_party/blink/renderer/core/frame/navigator_language.cc:19-38`) |
| BraveRewardsDisabled | ✅ | cr105 | bool | map, `ENABLE_BRAVE_REWARDS` | true = disable; restart. **Also stops Sponsored Ads, except Brave Search's.** The ads service does not start (`AdsServiceImpl::CanStartBatAdsService`, `ads_service_impl.cc:307-312`), so no notification ads, no NTP sponsored wallpapers (`view_counter_service.cc:240-257`) and no ad event or conversion reporting. Brave Search's result ads are server-side and still show (brave-browser#51040, wontfix). The policy hides the Settings "Enable Sponsored Ads" toggle (`brave_settings_ui.cc:281-283`) and the refreshed NTP's sponsored toggles. Edge, until restart: a sponsored-images component registered before the policy landed, or re-registered by turning "Show background images" off and on (`view_counter_service.cc:339-343,403-425`), lets refreshed-NTP sponsored-site tiles appear, since they need no ads service (`sponsored_sites_facade.cc:123-139`). Not all ads traffic stops: every regular profile still builds its ads service, whose `HttpClient` fetches `static.ads.brave.com/v1/ohttp/hpkekeyconfig` (`components/brave_ads/core/browser/network/http_client.cc:132-135`) while Griffin's `BraveAdsObliviousHttpStudy` (all channels, no `policy_restriction`) sets `kShouldSupportOhttp`; either `ChromeVariations` row stops it. brave-browser#54917 (open, unmilestoned) would decouple ads startup from Rewards; then this row stops covering ads and a new key is needed. Source-read at `v1.98.60`, not runtime-tested |
| BraveWalletDisabled | ✅ | cr106 | bool | map, `ENABLE_BRAVE_WALLET` | true = disable; restart. Guard `enable_brave_wallet = !is_brave_origin_branded` (`components/brave_wallet/common/buildflags/buildflags.gni:9`); no feature gate (`browser/brave_wallet/brave_wallet_context_utils.cc:17-36`). Removes the wallet service, toolbar button, side panel and settings page, and also disables web3 and decentralized DNS: no `window.ethereum` / `window.solana` providers (`browser/brave_content_browser_client.cc:1056-1066`) and no ENS/SNS/Unstoppable Domains resolution (`browser/net/decentralized_dns_network_delegate_helper.cc:46-51`) |
| BraveVPNDisabled | ⚠️ no-op on Linux | cr112 | bool | map, `ENABLE_BRAVE_VPN` | **Windows, macOS, Android, iOS only.** `enable_brave_vpn = enable_brave_vpn_v1 \|\| enable_brave_vpn_v2`, both `(is_win \|\| is_android \|\| is_mac \|\| is_ios) && !is_brave_origin_branded` (`components/brave_vpn/common/buildflags/buildflags.gni:11-22`) — no `is_linux`, so the map entry is compiled out of Linux builds and the key is a silent no-op there while `brave://policy` still shows it applied (the 1.98.60 Linux binary lacks the target pref). On Windows and macOS it hides the toolbar button, NTP card, settings section and welcome offer (`components/brave_vpn/common/brave_vpn_utils.cc:207-228`). The Linux row is labelled rather than removed; `slimbrave-mac.py` gives it the same label on Linux. **Trigger:** `is_linux` joining the buildflag with `kBraveVPN` on for Linux (brave-browser#15817, #56726, open, unmilestoned); then drop the Linux label from both Python scripts. Restart |
| BraveAIChatEnabled | ✅ | cr121 | bool | map, `ENABLE_AI_CHAT` | false = disable Leo; restart. Guard `enable_ai_chat = !is_brave_origin_branded`, so every regular build, Linux included. `IsAIChatEnabled` = `kAIChat` (on by default) **and** not managed `false` (`components/ai_chat/core/browser/utils.cc:102-106`); `false` removes the service (`browser/ai_chat/ai_chat_service_factory.cc:51`) and with it the sidebar item, toolbar button, omnibox provider, context menu, NTP input and `brave://leo-ai`. Does not cover on-device models (see BraveLocalAIEnabled) |
| BraveLocalAIEnabled | ⚠️ feature off on Release | cr149 — **Brave 1.94**, branch-probed | bool | map, `ENABLE_LOCAL_AI` | false = unregister and uninstall the on-device model components, EmbeddingGemma (`components/local_ai/core/local_models_updater.cc:88-101,128-137`) and the speech models (`on_device_speech_models_component_installer.cc:134-140`), and make `IsHistoryEmbeddingsFeatureEnabled()` false (`rewrite/chrome/browser/history_embeddings/history_embeddings_utils.cc.yaml:42-45`): no vector index of history, no "Semantic history search" toggle in brave://settings/privacy, no history tool for Leo. **Feature off on Release:** history search needs `kHistoryEmbeddings`, off at 156.0.8078.48 and pinned off by brave-core (`rewrite/components/history_embeddings/core/history_embeddings_features.cc.yaml:7-13`); the speech models need `kBraveOnDeviceSpeechRecognition`, off with no study. Griffin turns `HistoryEmbeddings` on for desktop Nightly (100%) and Beta (50%, brave-variations#1936), with no Release study and no `policy_restriction`, so either `ChromeVariations` row filters both out; where it is on, EmbeddingGemma downloads at launch while indexing stays a per-profile opt-in. On Release the key only blocks a `brave://flags#brave-history-embeddings` opt-in. It is the only policy lever: Chromium's `HistorySearchSettings` and `GenAiDefaultSettings` never reach Brave. Separate buildflag (`ENABLE_LOCAL_AI`) and prefs from AI Chat. Restart for history search; the model registrars apply a change live; browser-wide. In five presets, all but Strict Parental Controls |
| BraveShieldsDisabledForUrls | ✅ | cr107 | list | map, unguarded | scheme-wide patterns, see Cross-cutting; browser-wide; restart per YAML but applies live: Chromium's content-settings `PolicyProvider` re-reads the list on change (`components/content_settings/core/browser/content_settings_policy_provider.cc:451-455` at 156.0.8078.48). Where Shields are off, all five `DefaultBrave*` rows, `BraveTrackingQueryParametersFilteringEnabled` and `BraveReduceLanguageEnabled` do nothing; with `https://*` and `http://*` that is every web page. De-AMP, Debouncing and GPC have no Shields check and keep working |
| BraveShieldsEnabledForUrls | ✅ | cr107 | list | map, unguarded | counterpart of the row above; browser-wide; restart per YAML but applies live. Pins Shields on for matched sites: the panel's main toggle stays clickable but only writes a user rule the policy outranks (`components/brave_shields/resources/panel_new/components/main_card.tsx:84-87`), and the ad-block, scripts, fingerprinting, cookie and storage controls grey out (`panel_new/components/advanced_settings.tsx:85`). The per-site HTTPS-upgrade dropdown does not (`brave_shields_tab_helper.cc:425-441`), so a per-site HTTPS mode stays settable unless `DefaultBraveHttpsUpgradeSetting` is set too. It is the only key that stops a user dropping Shields per site, which would void every `DefaultBrave*` enforcer there. If the identical pattern is in both lists this one wins (`content_settings_policy_provider.cc:47-48`); the scripts keep the two rows mutually exclusive |
| BraveNewsDisabled | ✅ | cr138 | bool | map, `ENABLE_BRAVE_NEWS` | true = disable; restart. Unset, News stays off until the user opts in on the new tab page (`brave.today.opted_in`, default `false`). `true` makes `brave_news::IsEnabled` false whatever the user chose (`components/brave_news/common/pref_names.cc:34-41`), so the feed is never fetched, and hides News on the new tab page, the RSS page action and its commands. Edge: the sidebar News item checks only `kBraveNewsSidebar` and the opt-in (`components/sidebar/browser/sidebar_service.cc:770-783`), so a profile that opted in before the policy keeps a button that opens an empty panel. `kBraveNewsNewUserOptIn`, which would opt every new profile in, is off by default with no study (see What's next). Source-read, not runtime-tested |
| BraveTalkDisabled | ✅ | cr138 | bool | map, `ENABLE_BRAVE_TALK` | true = disable; restart. Removes Talk's browser entry points: the new tab page widget (`browser/ui/webui/brave_new_tab_page_refresh/new_tab_page_initializer.cc:242-244`), the sidebar item and the `IDC_SHOW_BRAVE_TALK` command (`browser/ui/brave_browser_command_controller.cc:398-402`). No navigation check reads the pref: `talk.brave.com` still opens as a website |
| BravePlaylistEnabled | ⚠️ feature off on Release/Beta | cr139 | bool | map, `ENABLE_PLAYLIST` | **Key live, feature off outside Nightly.** `kPlaylist` is `FEATURE_DISABLED_BY_DEFAULT` on every non-iOS build (`components/playlist/core/common/features.cc:13-19`), `IsPlaylistAllowed()` needs feature **and** no policy `false` (`components/playlist/core/browser/utils.cc:18-29`), and the only enabling study, `DefaultPlaylistStudy`, is Nightly-only (no `policy_restriction`). `false` bites on Nightly and wherever the user turns on `brave://flags/#playlist`; on Release and Beta it is a guard. The YAML's "enabled by default" is wrong for desktop. Restart |
| BraveWebDiscoveryEnabled | ✅ | cr138 | bool | map, `ENABLE_WEB_DISCOVERY` | unset = **disabled** (`browser/brave_profile_prefs.cc:551`); `false` locks it off and, the pref being managed, suppresses both opt-in prompts: the search.brave.com infobar (`browser/web_discovery/web_discovery_cta_util.cc:85-92`) and the welcome flow's Web Discovery step. Restart per YAML, but the collector watches the pref and applies a change live (`browser/extensions/brave_component_loader.cc:42-45`) |
| BraveSpeedreaderEnabled | ✅ | cr138 | bool | map, `ENABLE_SPEEDREADER` | desktop only; restart. Maps to `brave.speedreader.feature_enabled` (default `true`): `false` makes `IsAllowedForSite` return false (`components/speedreader/speedreader_service.cc:98-103`) and hides the page action, read-aloud included |
| BraveWaybackMachineEnabled | ✅ | cr138 | bool | map, `ENABLE_BRAVE_WAYBACK_MACHINE` | desktop only; unset = enabled. `false` stops the archive.org offer after a 404, 408, 410, 451 or most 5xx responses (`components/brave_wayback_machine/brave_wayback_machine_utils.cc:52-72`) and hides the URL-bar icon and Settings toggle; it also covers the off-by-default auto-show and auto-check options. Restart per YAML, but applies live (`brave_wayback_machine_tab_helper.cc:49-53`) |
| TorDisabled | ✅ | cr78 (Win) / cr93 (mac, Linux) | bool | map, `ENABLE_TOR` | desktop only; browser-wide (Local State `tor.tor_disabled`). `true` drops "New private window with Tor", closes every Tor window and deletes the Tor client and its data (`browser/extensions/brave_extension_management.cc:55-65,80-87`). Restart per YAML, but applies live |
| EmailAliasesEnabled | ✅ | cr147 — **Brave 1.92**, branch-probed | bool | map, `ENABLE_EMAIL_ALIASES` | **Feature on via Griffin, off in code.** Desktop only (`ENABLE_EMAIL_ALIASES`). `kEmailAliases` is `FEATURE_DISABLED_BY_DEFAULT` (`components/email_aliases/features.cc:13`), but brave-variations `EmailAliasesStudy_Release` (#1835) enables it at 100% on Release Windows/macOS/Linux from 1.94.113, and `EmailAliasesStudy` on Nightly and Beta. `false` removes the service (`browser/email_aliases/email_aliases_service_factory.cc:56-59`) and with it the settings page, context-menu entry and autofill suggestions; with `kBraveAccount` off it also hides the Settings Brave Account row. Neither study sets `policy_restriction`, so either `ChromeVariations` row filters them out and `false` is then a guard. Restart |
| DefaultBraveAdblockSetting | ✅ | cr142 | int enum | own `IntRangePolicyHandlerBase` handler, unguarded (`chromium_src/chrome/browser/policy/configuration_policy_handler_list_factory.cc:32-36`) → `brave.profile.managed_default_content_settings.*` pref → content-settings policy provider (brave-core patch + `rewrite/` twin) | 1 = allow ads, 2 = block. Locks only `BRAVE_ADS`: standard network ad/tracker blocking (`browser/net/url_context.cc:535-537`). Cosmetic filtering (element hiding, scriptlets), the domain-block interstitial and Aggressive mode key off the unmanaged `BRAVE_COSMETIC_FILTERING`, which "Allow all trackers & ads" in the Shields panel or "Disabled" in `brave://settings/shields` still sets to `ALLOW` (`components/brave_shields/core/browser/brave_shields_settings_service.cc:123-148`); this key greys neither control. At 1, network blocking stops while cosmetic filtering keeps its default (brave-browser#59662, open). **All five `DefaultBrave*`** lock the type's default and void per-site exceptions for it (`content_settings_policy_provider.cc:274-276` at 156.0.8078.48), but every consumer checks Shields first, so a site with Shields off escapes them. **Trigger:** a fix for #59662 that also manages `BRAVE_COSMETIC_FILTERING`; then this row and the scripts' "Cosmetic filtering … is not locked" text change |
| DefaultBraveFingerprintingV2Setting | ✅ | cr141 | int enum | same | 1 = off, 3 = standard (no 2: retired Strict, outside the schema enum and ignored by the handler, `browser/policy/handlers/brave_fingerprinting_v2_policy_handler.cc:57-62`). Pins only the site-level `BRAVE_FINGERPRINTING_V2` mode, over the user's per-site mode and the remote list's (`components/brave_shields/core/browser/brave_shields_utils.cc:591-608`). Per-API `BRAVE_WEBCOMPAT_*` `ALLOW` rules are unmanaged and still switch farbling off for one API on one site: Brave's remote list and the user's toggles in the panel's fingerprinting details, which neither this key nor `BraveShieldsEnabledForUrls` greys (`panel_new/components/advanced_settings.tsx:306-310`) |
| DefaultBraveHttpsUpgradeSetting | ⚠️ unenforced where Griffin moves to upstream HTTPS-First (25% of Release) | cr142 | int enum | same | 1 = allow HTTP, 2 = strict, 3 = standard. Every enforcing reader needs `kBraveHttpsByDefault` (`HttpsByDefault`, on in code, `chromium_src/net/base/features.cc:31-33`). With it on, 2 upgrades every navigation and turns a failed upgrade into a warning (Chromium's Ask-before-HTTP dialog on desktop; `components/brave_shields/core/browser/brave_shields_utils.cc:683-719`), 3 upgrades unless the host is on Brave's exceptions list, 1 turns upgrading off; all only where Shields are up. **Griffin switches that path off:** brave-variations `TransitionToUpstreamHttpsUpgrade` (#1891, #1939) disables `HttpsByDefault` and enables `TransitionToUpstreamHttpsUpgrades` and `HttpsFirstBalancedMode` for all of desktop Beta and Nightly and 25% of desktop Release (from 1.97.41). There the key is read once per profile: `MigrateHttpsUpgradeSettings` (`browser/profiles/brave_profile_manager.cc:88-143`) copies it into upstream HTTPS-First as **user** prefs (1 → off, 2 → strict, 3 → Balanced); the Shields HTTPS controls are hidden and the upstream setting shows in `brave://settings/security`, where the user can lower it. The study sets no `policy_restriction`, so either `ChromeVariations` row (Maximum Privacy carries 1) keeps Brave's path and this key enforced. **Trigger:** the Release share rising, or brave-core removing `kBraveHttpsByDefault` (brave-core#39916 calls the transition code a step "before removing Brave's implementation"); then re-verify. Chromium's `HttpsOnlyMode` is the lock on the upstream path (see What's next) |
| DefaultBraveReferrersSetting | ✅ | cr142 | int enum | same | 1 = permissive, 2 = cap to strict origin; both exposed as mutually exclusive rows (issue #9); never put 1 in a preset. 2 is Brave's own default, so the key locks it and voids per-site `ALLOW` exceptions, including those Brave's webcompat list adds. The cap acts only on cross-origin requests from a page with Shields up (`components/brave_shields/content/browser/brave_shields_util.cc:38-64`); 1 lifts it, so a page's own `unsafe-url` policy sends the full URL cross-origin |
| DefaultBraveRemember1PStorageSetting | ✅ | cr142 | int enum | same | 1 = remember, 2 = forget when the site's last tab closes. Cleanup is skipped for any eTLD+1 where a visited host had Shields off or cookies on Allow (`browser/ephemeral_storage/ephemeral_storage_tab_helper.cc:231-243`). Inert whenever `kBraveShredFeature` is on: Auto Shred then decides (default `NEVER`, `components/ephemeral_storage/ephemeral_storage_service.cc:385-389`), and its migration copies user rules, not the policy (no Auto Shred policy exists). Off by default on desktop (`components/brave_shields/core/common/features.cc:70-75`) with no desktop study, but `brave://flags/#brave-shred` lets a user escape a forced 2. **Trigger:** the feature turning on for desktop, in code or by a study (brave-browser#49999); then re-label the row ⚠️ |

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
| MetricsReportingEnabled | ✅ | cr8 | bool | false | restart; browser-wide. Chromium marks it `sensitive: true`, which blocks it from a platform source on a Windows/Mac machine that is not domain-joined or MDM-managed (156.0.8078.48 `components/policy/core/common/async_policy_loader.cc:110-119`; Linux never filters); brave-core patches that flag out of the YAML, the only reason an HKLM write works on a home PC. Brave sends no UMA/UKM (`chromium_src/components/metrics/enabled_state_provider.cc:13-15`), so in practice the key governs crash-report upload to `cr.brave.com`: upstream `ApplyMetricsReportingPolicy()` copies the pref into the crash-upload consent (`chrome/browser/metrics/metrics_reporting_state.cc:203-209`), honoured because brave-core forces `GOOGLE_CHROME_BRANDING` there (`chromium_src/components/metrics/metrics_service_accessor.cc:16-19`). Brave defaults the pref to false on Release and in Brave Origin but **true on Beta and Nightly** (`browser/metrics/metrics_reporting_util.cc:21-39`). Any managed value also suppresses Brave's post-crash "send crash reports?" dialog (`:41-60`) |
| SafeBrowsingProtectionLevel | ✅ | cr83 | int enum | 0 (no protection) | 0/1/2 valid. Brave proxies Safe Browsing through its own hosts: `components/static_redirect_helper/static_redirect_helper.cc:85-105` (`v1.98.60`) rewrites `safebrowsing.googleapis.com`, `sb-ssl.google.com` and `safebrowsing.google.com` to `*.brave.com`, so Google receives the proxied lookups but never learns which client made them, not even its IP. Upstream's hash-prefix real-time lookups, whose OHTTP relay the rewrite does not cover, never run in Brave: they require `HasGoogleChromeBranding()` (`components/safe_browsing/core/common/hashprefix_realtime/hash_realtime_utils.cc:25-31,107-110` at 156.0.8078.48). Value 2 behaves as 1: brave-core makes `IsEnhancedProtectionEnabled()` false (`chromium_src/components/safe_browsing/core/common/safe_browsing_prefs.cc:8`). Turning it off buys almost no privacy and costs the phishing/malware interstitials; in no preset |
| UrlKeyedAnonymizedDataCollectionEnabled | ✅ | cr69 | bool | false | belt and braces — the pref defaults to false upstream (156.0.8078.48 `components/unified_consent/unified_consent_service.cc:198-199`) and brave-core compiles its Settings toggle out (`patches/chrome-browser-resources-settings-privacy_page-personalization_options.html.patch:34-41`); the key locks it off. Legacy half of a `SimpleDeprecatingPolicyHandler` (factory `:2680-2687`) whose successor `UrlKeyedMetricsAllowed` is still `future_on` only, so this key is the one that applies — see Considered and rejected |
| AutofillAddressEnabled | ⚠️ deprecated, still applied | cr69 | bool | false | `deprecated: true` at 156.0.8078.48 ("deprecated in M156, please use AutofillSettings", `34ae451dfc`) but uncapped and still applied, also at 157.0.8103.21 and main: `AutofillSettingsPolicyHandler` (factory `:2656-2657`) sets `autofill.profile_enabled` false (`components/autofill/core/browser/permissions/autofill_policy_handler.cc:101-105`), read with no feature gate by `ChromeAutofillClient::IsAutofillProfileEnabled` (`chrome/browser/ui/autofill/chrome_autofill_client.cc:1042-1045`). Deprecation is a label: handlers run on a deprecated policy like any other (`components/policy/core/browser/configuration_policy_handler_list.cc:83-97`) and `brave://policy` shows its status as `Deprecated`. Kept, with that caveat in the description, because the successor `AutofillSettings` is inert in Brave (see Considered and rejected): writing it instead would leave address Autofill on |
| AutofillCreditCardEnabled | ⚠️ deprecated, still applied | cr63 | bool | false | `deprecated: true` at 156.0.8078.48 by the same change, uncapped and still applied: the same handler sets `autofill.credit_card_enabled` false (`autofill_policy_handler.cc:107-111`), read with no feature gate by `ChromePaymentsAutofillClient::IsAutofillPaymentMethodsEnabled` (`chrome/browser/ui/autofill/payments/chrome_payments_autofill_client.cc:868-874`). Same `Deprecated` status and the same reason to keep it as AutofillAddressEnabled |
| PasswordManagerEnabled | ✅ | cr8 | bool | false | pref `credentials_enable_service`; false stops offer-to-save and password generation (both gated by `IsSavingAndFillingEnabled()`, 156.0.8078.48 `chrome/browser/password_manager/chrome_password_manager_client.cc:302-317`), but passwords already saved still autofill — `IsFillingEnabled()` does not read the pref (YAML: "previously saved passwords will still work") |
| BrowserSignin | ✅ | cr70 | int enum | 0 (disable) | restart; browser-wide. Off ChromeOS, `BrowserSigninPolicyHandler` maps 0 to `signin.allowed_on_next_startup` false (156.0.8078.48 `chrome/browser/policy/browser_signin_policy_handler.cc:64-75`), copied into `signin.allowed` at the next start. Brave has no Chrome account sign-in; that pref backs the `brave://settings/extensions` "Allow Google login for extensions" toggle, which brave-core already defaults off (`chromium_src/chrome/browser/profiles/pref_service_builder_utils.cc:31-32`), so 0 locks it off. It does not touch Brave Account, Brave's own sign-in, offered on Release desktop through Email Aliases (`components/brave_account/features.cc:17-29`) |
| WebRtcIPHandling | ✅ | cr91 | string enum | disable_non_proxied_udp | Brave keeps the upstream default and exposes the same pref as the "WebRTC IP handling policy" dropdown in `brave://settings/privacy`; the managed value outranks it. `disable_non_proxied_udp` turns off network-adapter enumeration, UDP, STUN and TURN over UDP (156.0.8078.48 `third_party/blink/renderer/platform/p2p/port_allocator.cc:36-45`), so ICE runs over TCP only — through the configured proxy if there is one — and a call needs a TCP path. Tor windows already force this value |
| QuicAllowed | ✅ | cr43 | bool | false | restart; browser-wide. A managed false that arrives at runtime applies live: `ProfileNetworkContextService` watches the pref and calls `SystemNetworkContextManager::DisableQuic()` for every context (156.0.8078.48 `chrome/browser/net/profile_network_context_service.cc:681-692`); lifting it needs a restart. It covers HTTP(S) loads, not WebTransport, which opens its own QUIC connection without checking `IsQuicEnabled()` (`net/quic/dedicated_web_transport_http3_client.cc:636-674`; source-read); WebRTC media is UDP either way. No brave-core override and no Griffin study |
| BlockThirdPartyCookies | ✅ | cr10 | bool | true | belt and braces — brave-core already defaults `profile.cookie_controls_mode` to block third-party (`browser/profiles/profile_util.cc:31-36`); the key locks it through `CookieSettingsPolicyHandler` (156.0.8078.48 `components/content_settings/core/browser/cookie_settings_policy_handler.cc:25-33`), so the Shields global "allow all cookies" choice stops applying while per-site Shields exceptions still do (they are explicit `COOKIES` rules, `components/content_settings/core/browser/brave_content_settings_pref_provider.cc:877-880`). Ad Block Only Mode injects `false` at lower priority (see Cross-cutting) |
| ForceGoogleSafeSearch | ✅ | cr41 | bool | true | simple map → `settings.force_google_safesearch` (factory `:959-961`); `GoogleURLLoaderThrottle` adds `safe=active&ssui=on` to Google Search URLs (156.0.8078.48 `chrome/common/google_url_loader_throttle.cc:177-183`). No brave-core override of that path |
| IncognitoModeAvailability | ✅ | cr14 | int enum | 1 or 2 | 0 = enabled, 1 = disabled, 2 = forced, as two mutually exclusive rows; restart per YAML, but open windows pick a change up (156.0.8078.48 `chrome/browser/ui/browser_command_controller.cc:2058-2070`). In Brave `tor::IsIncognitoDisabledOrForced` treats 1 and 2 alike (`browser/tor/util.cc:17-34`), so either row also removes Tor windows |
| SyncDisabled | ✅ | cr8 | bool | true | governs Brave Sync: `syncer::SyncPolicyHandler` sets `sync.managed`, and brave-core's `BraveSyncServiceImpl` (`chromium_src/chrome/browser/sync/sync_service_factory.cc:11-18`) keeps upstream's `GetDisableReasons()`, so `brave://settings/braveSync` shows Sync disabled by the administrator. Side effect: the resulting `StopAndClear(kEnterprisePolicy)` runs Brave's override, which clears the sync code (`components/sync/service/brave_sync_service_impl.cc:207-227`), so the device leaves its sync chain and must rejoin with a code once the policy is removed |
| BackgroundModeEnabled | ⚠️ Win/Linux only | cr19 | bool | false | **Windows and Linux only** (`chrome.win:19-`, `chrome.linux:19-`; the factory entry sits under a Windows/Linux guard, 156.0.8078.48 `:2008-2012`); browser-wide (local state `background_mode.enabled`). Background mode starts only while an installed extension or app holds the `background` permission. `slimbrave-mac.py` also runs on Linux, so it builds the row only under `sys.platform.startswith("linux")`; on macOS a preset naming the key has it silently ignored |
| ShoppingListEnabled | ⚠️ no-op in Brave | cr107 | bool | false | dispatched (pref `shopping_list_enabled`), but its only functional reader, `commerce::IsShoppingListEligible` (156.0.8078.48 `components/commerce/core/feature_utils.cc:19-41`), fails its first gate: brave-core re-declares `kShoppingList` (off upstream too) `BASE_OVERRIDDEN_FEATURE` (`rewrite/components/commerce/core/commerce_feature_list.cc.yaml:27-30`), so it stays off without reaching the `us`/`en-us` launch map. Forced on by flag, it still needs a Chrome sync account, which Brave never creates. Defensive lock only |
| AlwaysOpenPdfExternally | ✅ | cr55 | bool | true | pref `plugins.always_open_pdf_externally` (desktop only); true turns the PDF viewer off (156.0.8078.48 `chrome/browser/plugins/plugin_prefs.cc:52-54`), so a PDF downloads and opening it hands it to the OS handler. No brave-core override |
| TranslateEnabled | ✅ | cr12 | bool | false | Brave translates through its own `translate.brave.com`, not Google: `kUseBraveTranslateGo` is on by default (`components/translate/core/common/brave_translate_features.cc:13-14`) and brave-core's overrides of `translate_script.cc` and `translate_util.cc` point the script and requests there; Google is reached only under a test switch. Auto-translate is off (`kBraveEnableAutoTranslate`). A managed false also refuses manual translation (156.0.8078.48 `components/translate/core/browser/translate_prefs.cc:193-200`). The key removes the feature, not a Google data flow |
| SpellcheckEnabled | ✅ | cr65 | bool | false | desktop only; mutually exclusive with SpellCheckServiceEnabled |
| SearchSuggestEnabled | ✅ | cr8 | bool | false | Brave registers the default false (`browser/brave_profile_prefs.cc:249-251`) but flips it to true for every regular profile when the desktop first run found an OS-locale region of AR, AT, BR, CA, DE, ES, FR, GB, IN, IT, MX or US; a locale with no region counts as US (`browser/search_engines/search_engine_provider_util.cc:35-38,140-164`). On those installs the key is what turns suggestions off, and it locks the toggle |
| PrintingEnabled | ✅ | cr8 | bool | false | |
| DefaultBrowserSettingEnabled | ✅ | cr11 | bool | false | desktop only; browser-wide. Any managed value stops the startup default-browser prompt (156.0.8078.48 `chrome/browser/ui/startup/default_browser_prompt/default_browser_prompt.cc:85-90`). But Brave's first-run `brave://welcome` offers *Set as default* without reading `isDisabledByPolicy` (`components/brave_welcome_ui/components/welcome/index.tsx:37-38,95`), and with this key false the click hits the `CHECK(!DefaultBrowserIsDisabledByPolicy())` in `DefaultBrowserHandler::SetAsDefaultBrowser` (`chrome/browser/ui/webui/settings/settings_default_browser_handler.cc:126`) and crashes the browser — click *Skip*. brave-browser#60038 (open) reports the crash at runtime on 1.97.59 for Linux |
| DeveloperToolsAvailability | ✅ | cr68 | int enum | 2 (disallowed) | 2 = `DeveloperToolsDisallowed`. Does **not** stop the CDP port or pipe opening — see RemoteDebuggingAllowed: 2 refuses CDP attach to profile targets (`chrome/browser/devtools/chrome_devtools_manager_delegate.cc:412-421` at 156.0.8078.48), but the browser target has no profile and passes, and its `Storage.getCookies` still returns every cookie of the last-used profile. Applies live. Also forces `extensions.ui.developer_mode` false, locking Developer mode off on `brave://extensions` and refusing *Load unpacked* (`chrome/browser/policy/developer_tools_policy_handler.cc:283-288`). No brave-core override |
| DnsOverHttpsMode | ✅ | cr78 | string enum | off / automatic / secure | browser-wide. Stock Chromium forces DoH **off** whenever this key is unmanaged on a machine that is domain-joined or carries *any* machine-level policy (156.0.8078.48 `chrome/browser/net/stub_resolver_config_reader.cc:245-271`) — every SlimBrave machine once it writes its first key. brave-core overrides that (`chromium_src/chrome/browser/net/stub_resolver_config_reader.cc:166-168`), so **Not managed** keeps Brave's own automatic DoH; the companion YAML patch only drops ChromeOS metadata. On Windows with Brave VPN connected over IKEv2 and its DNS helper not live, Brave forces secure DoH to `chrome.cloudflare-dns.com` unless this key is managed or already `secure`; managed and not `secure`, it shows a policy-warning dialog instead (`browser/brave_vpn/dns/brave_vpn_dns_observer_service_win.cc:175-198`). WireGuard skips this path; Brave Origin has no VPN |
| DnsOverHttpsTemplates | ✅ | cr80 | string | URL template | browser-wide. **Required** for `secure` and `custom`, optional for `automatic` (unset = Chromium's upgrade of the system resolver; Brave's fallback provider hook, off on Release, appends `https://brave.cloudflare-dns.com/dns-query` on Beta and Nightly via the Griffin study `BraveFallbackDoHStudy`, which `ChromeVariations` 1 or 2 filters out), ignored for `off`. `secure` with an empty or unparseable template destroys name resolution: no secure transaction is possible and the system-resolver fallback is gated on `secure_dns_mode != kSecure` (156.0.8078.48 `net/dns/host_resolver_manager.cc:1366-1370`). All three scripts refuse an empty template for `custom`/`secure`; only `SlimBrave.ps1` also refuses a non-https or unparseable one (`Test-DohTemplate`), and the Python scripts also write a template with `automatic` (see What the project does) |
| PasswordLeakDetectionEnabled | ✅ | cr79 | bool | false | belt and braces: Brave defaults `profile.password_manager_leak_detection` to false (`browser/brave_profile_prefs.cc:268-271`) and hides the settings switch (`browser/resources/settings/br/security_page.ts:50-58`); the copy on upstream's bundled security page would show if the off-by-default `kBundledSecuritySettings` turned on, locked when the key is set. The key locks off the online breach-list check Chromium runs on credentials after a successful sign-in and on saved logins edited in the Password Manager (`leak_detection/leak_detection_check_impl.cc:225-237` at 156.0.8078.48) |
| NetworkPredictionOptions | ✅ | cr38 | int enum | 2 (never predict) | 0 = always, 2 = never (1 deprecated, read as 0). Belt and braces: Brave defaults `net.network_prediction_options` to 2 (`browser/brave_profile_prefs.cc:253-257`) and clears any user value on every profile load (`chromium_src/chrome/browser/prefs/browser_prefs.cc:154`), so only Brave Sync restoring a value or a policy of 0 turns prediction on. Brave never runs the loading predictor whatever the value (`rewrite/chrome/browser/predictors/loading_predictor_config.cc.yaml`: no learned preconnects, `dns-prefetch`/`preconnect` hints or pointer-down preconnects) and never prerenders (`Prerender2` shipped off, `rewrite/third_party/blink/renderer/platform/runtime_enabled_features.json5.yaml:133-136`). What the pref still gates: speculation-rules prefetch, `<link rel=prerender>` NoStatePrefetch, the address bar's search-result prefetch and the default-search-engine preconnector (156.0.8078.48 `chrome/browser/navigation_predictor/search_engine_preconnector.cc:319-340`), which also needs search suggestions on (see SearchSuggestEnabled). The key adds the in-session lock and outranks Sync |
| PaymentMethodQueryEnabled | ✅ | cr80 | bool | false | with the pref off Chromium stops consulting payment apps: `canMakePayment()` always resolves **true** (a deliberate lie, so a site must call `show()`) and `hasEnrolledInstrument()` false, so neither reveals saved methods; Secure Payment Confirmation exempt (156.0.8078.48 `components/payments/content/payment_request.cc:717-733,754-767`). The YAML's "no payment methods are available" does not match the code |
| AlternateErrorPagesEnabled | ⚠️ inert in Brave | cr8 | bool | false | no live reader in Brave. Upstream the pref gates only `NetErrorTabHelper`'s DNS-error probe to 8.8.8.8 and the captive-portal check; brave-core never attaches `NetErrorTabHelper` (`chromium_src/chrome/browser/ui/tab_helpers.cc:26`, `#define NetErrorTabHelper NoTabHelper`) and patches the pref out of the captive-portal check (`rewrite/components/captive_portal/content/captive_portal_service.cc.yaml`), so captive-portal detection runs whatever the value. No settings page binds the pref and Brave defaults it to false; locking it only pins `chrome.privacy.services.alternateErrorPagesEnabled` for extensions. Kept as belt and braces (see What's next for Chromium 157) |
| DefaultNotificationsSetting | ✅ | cr10 | int enum | 1, 2 or 3, user-selected; key omitted when Not managed | full legal enum **1 = allow, 2 = block, 3 = ask**, all exposed as a choice row |
| DefaultGeolocationSetting | ✅ | cr10 | int enum | 1, 2 or 3; omitted when Not managed | full legal enum 1 = allow, 2 = block, 3 = ask; choice row |
| DefaultSensorsSetting | ✅ | cr88 | int enum | 1, 2 or 3; omitted when Not managed | motion/orientation sensors, a fingerprinting vector; full legal enum 1 = allow, 2 = block, 3 = ask. "3 = ask" holds in Brave only because brave-core force-enables `kSensorsAllowAskBlockPermissionModel` (`rewrite/services/device/public/cpp/device_features.cc.yaml:18-21`): the dedicated `DefaultSensorsSettingPolicyHandler` rewrites 3 to **Allow** when that flag is off (156.0.8078.48 `chrome/browser/policy/default_sensors_setting_policy_handler.cc:30-41`), which is Chromium's code default; Brave compiles out the field-trial testing config that turns it on upstream. Brave also re-registers SENSORS with default **Block** (brave/brave-browser#4789), so Not managed in Brave is block-by-default-but-user-changeable. A policy file with 3 taken to a Chromium where the flag is off means Allow |
| ExtensionInstallBlocklist | ✅ | cr86 | list | `["*"]` | blocks all installs and disables (does not uninstall) already-installed extensions, themes and apps included; component extensions (Brave's and Chromium's built-ins) and shared modules are exempt (`StandardManagementPolicyProvider::UserMayLoad`, 156.0.8078.48 `chrome/browser/extensions/standard_management_policy_provider.cc:111-119`) |
| BrowserGuestModeEnabled | ✅ | cr38 | bool | false | guest windows are an off-the-record session with no saved history and none of the main profile's extensions, which `IncognitoModeAvailability` = 1 does not close (156.0.8078.48 `chrome/browser/prefs/incognito_mode_prefs.cc:95-97`); machine policies still apply inside them (`chrome/browser/policy/profile_policy_connector.cc:521-525`). Dedicated `GuestModePolicyHandler`, Win/Mac/Linux only; Brave's menu honours it (`browser/ui/brave_browser_command_controller.cc:355-365`); browser-wide |
| HighEfficiencyModeEnabled | ✅ | cr108 | bool | true | forces Memory Saver tab discarding on; browser-wide, applied live. `MemorySaverPolicyHandler` sets `performance_tuning.high_efficiency_mode.state` (156.0.8078.48 `chrome/browser/performance_manager/user_tuning/memory_saver_policy_handler.cc:32-36`), applied with no feature gate; no brave-core override of the policy and no Griffin study |
| HardwareAccelerationModeEnabled | ✅ | cr46 | bool | true / false | both states as a mutually exclusive pair (`Group = "hwaccel"`) because unset is not off: Chromium's default is on, absent means user-controlled, `false` means forced off (read once at startup, 156.0.8078.48 `chrome/browser/gpu/gpu_mode_manager.cc:47-52`); `true` only stops the user turning acceleration off — the GPU blocklist still applies. The off state is a troubleshooting lever for a faulty GPU driver, a VM or RDP session, or screen-sharing corruption, not a privacy posture — in no preset. Restart; browser-wide |
| EnableMediaRouter | ✅ | cr52 | bool | false | disables Cast and its LAN device discovery; restart. Brave gives the policy precedence over the `brave://settings/extensions` Media Router toggle (`chromium_src/chrome/browser/media/router/media_router_feature.cc:35-37`). Sticky: a profile created under the policy gets the managed `false` copied into `brave.enable_media_router_on_restart` (`browser/profiles/brave_profile_manager.cc:199-209`), so once the policy is removed Cast stays off until that toggle is turned back on and Brave restarted |
| ChromeVariations | ✅ | cr83 | int enum | 1 or 2 | 0 = all variations, 1 = critical fixes only, 2 = none; browser-wide. Closes the last remote-configuration channel: the Griffin seed from `variations.brave.com` that flips features in an installed browser. Maps to `kVariationsRestrictionsByPolicy`, with no brave-core override. Despite `dynamic_refresh: true` a change takes effect at the next start: studies are applied once per run (156.0.8078.48 `components/variations/service/variations_field_trial_creator.cc:717-720`). The seed is still downloaded; no fetch path reads the pref. 2 refuses every study; 1 admits only studies whose filter sets a `policy_restriction` (`components/variations/study_filtering.cc:222-227`), and in brave-variations `165f9af46` (the live seed) only `V8IgnitionElideRedundantTdzChecksKillSwitch`, capped at `139.*`, carries one, so on 1.98.60 values 1 and 2 both apply zero studies. Two mutually exclusive rows; 2 is in no preset only because it would also refuse a kill switch Brave tags critical later |
| SpellCheckServiceEnabled | ✅ | cr22 | bool | false | belt and braces — already off in Brave with no UI to turn it on: Chromium registers `spellcheck.use_spelling_service` false, Brave re-asserts it (`chromium_src/chrome/browser/profiles/pref_service_builder_utils.cc:27-29`), both settings controls are `_google_chrome`-only, and Brave stubs out the context-menu opt-in. The key locks the Google spelling web service off, even against a stored `true`, while offline dictionaries keep working; it has no effect once `SpellcheckEnabled` is false, hence the mutual exclusion |
| RemoteDebuggingAllowed | ✅ | cr93 | bool | false | blocks `--remote-debugging-port` / `--remote-debugging-pipe`, the CDP cookie-theft vector `DeveloperToolsAvailability` leaves open, and the listener the `brave://inspect` remote-debugging toggle starts: `RemoteDebuggingServer::GetInstance` returns `kDisabledByPolicy` before any of them starts (156.0.8078.48 `chrome/browser/devtools/remote_debugging_server.cc:337-340`). Google Chrome also refuses both switches on the default profile, but only under `GOOGLE_CHROME_BRANDING` (`:169-180`), which Brave never sets, so this key is Brave's only lock. Breaks Puppeteer, Playwright and that toggle; local-tab inspection keeps working. Browser-wide; no restart: set false at runtime, the server and pipe stop (`chrome/browser/browser_process_impl.cc:1107-1124`). Lifting it starts nothing until the toggle is turned back on or the browser relaunched |
| DNSInterceptionChecksEnabled | ⚠️ inert | cr80 | bool | false | no effect by default: the probes it stops never run. `IntranetRedirectDetector` would resolve three random 7–15 character hostnames after launch and every network change (156.0.8078.48 `chrome/browser/intranet_redirect_detector.cc:150-155,235-244`), but `IsEnabledByPolicy()` (`:264-285`) first requires `IntranetRedirectBehavior` set to 3, a policy-only pref; unset it is `DISABLE_FEATURE`, the default since M97 (`components/omnibox/browser/intranet_redirector_state.h:14-16`), so this key's pref is never reached. The YAML's "When this policy is not set … the checks are performed" does not match the code. Kept as a lock in case `IntranetRedirectBehavior` is ever set to 3; browser-wide |
| BasicAuthOverHttpEnabled | ✅ | cr88 | bool | false | refuses HTTP Basic auth over cleartext: `HttpAuthHandlerBasic::Factory` returns `ERR_UNSUPPORTED_AUTH_SCHEME` for a challenge from any `http` origin (156.0.8078.48 `net/http/http_auth_handler_basic.cc:128-132`), including a plain-HTTP proxy, so Basic-authenticated `http://` proxies stop working too; HTTPS proxies and the other auth schemes are untouched. Breaks legacy plain-HTTP appliance logins; browser-wide |
| DefaultWebUsbGuardSetting | ✅ | cr67 | int enum | 2 or 3; omitted when Not managed | **2 = block, 3 = ask — no value 1** in the schema, so the row offers Not managed / Ask / Block. Ships enabled in Brave. Breaks Ledger/Trezor web wallets and in-browser firmware flashers |
| DefaultSerialGuardSetting | ✅ | cr86 | int enum | 2 or 3; omitted when Not managed | 2 = block, 3 = ask, no 1; breaks in-browser microcontroller tooling |
| DefaultWebHidGuardSetting | ✅ | cr100 | int enum | 2 or 3; omitted when Not managed | 2 = block, 3 = ask, no 1; may break security keys and gamepad configurators that use WebHID rather than WebAuthn. Block also cuts Brave Wallet's own Ledger connection (source-read): the wallet's ledger bridge uses `TransportWebHID`, `HidService` checks the guard against the wallet's `chrome://` origin (156.0.8078.48 `content/browser/hid/hid_service.cc:439-443`) and Brave's HID overrides run only after that check (`browser/hid/brave_hid_delegate.cc:22-53`), so `requestDevice` and `getDevices` come back empty. The device-API set is USB+Serial+HID because WebBluetooth and File System Access are already feature-disabled in Brave (see Considered and rejected) |
| DefaultLocalFontsSetting | ✅ | cr103 | int enum | 2 or 3; omitted when Not managed | 2 = block, 3 = ask, no 1; `queryLocalFonts()` returns the installed font list, a top-tier fingerprint that Shields' farbling does not cover |
| DefaultWindowManagementSetting | ✅ | cr111 | int enum | 2 or 3; omitted when Not managed | 2 = block, 3 = ask, no 1; stops sites reading the multi-monitor topology. Complementary to `kBraveBlockScreenFingerprinting` (on by default on desktop), which gives `window.screen` one synthetic screen but leaves `getScreenDetails()` listing every real display (156.0.8078.48 `third_party/blink/renderer/modules/screen_details/screen_details.cc:22`) |
| BlockExternalExtensions | ✅ | cr80 | bool | true | closes the sideload channel bundleware uses: with the pref set, none of the registry or drop-in providers is registered (156.0.8078.48 `chrome/browser/extensions/external_provider_impl.cc:876-916`). On Windows that is Chromium's hard-coded `Software\Google\Chrome\Extensions` key (HKLM 32-bit view and HKCU), which brave-core does not repoint, so a sideload registered for Chrome also reaches Brave; on macOS and Linux the `external_extensions.json` / `<id>.json` drop-ins. Unmanaged, such extensions arrive disabled behind an approval prompt on Windows and macOS and install silently on Linux; with the policy they never load, and any already installed that way, approved or not, is uninstalled at the next launch (`chrome/browser/extensions/external_provider_manager.cc:160-167,174-203`). User-chosen extensions keep working, unlike `ExtensionInstallBlocklist: ["*"]`; restart |

Every key above fetches 200 at Chromium 156.0.8078.48 and at main
`7b96745f7dfb` (158.0.8123.0), and all 48 YAML files are byte-identical
between the two; none is upper-bounded or `future_on:`-only on desktop at
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
master (`1e6f00267`). Every Chromium-inherited key is cr111 or older, and
every Brave key cr142 or older except the three branch-probed rows
(`EmailAliasesEnabled` and `PsstEnabled` cr147, `BraveLocalAIEnabled` cr149),
so all are present in any Brave still receiving updates.

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
  key once Brave has run under it. `…\BraveSoftware\Update` is the updater's
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
  overrides.
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
  other five permission keys list only 2 / 3 in their schema, but Chromium
  does not enforce the enum: their handlers only type-check, so a 1 reaches
  the managed pref with no error on `brave://policy`; `PolicyProvider` then
  ignores it for WebUSB, Serial and WebHID (Ask/Block only) and applies it as
  a managed Allow for `DefaultLocalFontsSetting` and
  `DefaultWindowManagementSetting`
  (`content_settings_registry.cc:374,384,403,534-535,544-545` at
  156.0.8078.48). This tool offers only the schema's values: a value outside
  a key's legal set is left unmanaged on import and named in the message, and
  a quoted `"1"` or a `true` is rejected in all three implementations. A
  fraction or exponent is not always rejected: the Python scripts accept only
  a JSON integer, but `SlimBrave.ps1` also accepts a `[double]` and rounds it
  — under PowerShell 7 `2.0`, `2e0` and `2.5`; under Windows PowerShell 5.1,
  its elevated host, only exponent forms such as `2e0`, since `2.0` and `2.5`
  arrive as `[decimal]` and are rejected (What's next).
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
  cr121 or older. The highest Chromium-inherited milestone is
  `DefaultWindowManagementSetting` at cr111.

## Considered and rejected — do not add

The source is the tiebreaker in every case: the YAML, the handler registration (Chromium's or brave-core's) and the `pref_mapping` file.

| Key(s) | Status | Why not |
|---|---|---|
| `EnableDoNotTrack` | ❌ | does not exist in Chromium's policy index; DNT has no enterprise policy and nothing reads the name (no YAML and no `policies.yaml` id at 156.0.8078.48 or main, no reference in brave-core `v1.98.60`). The Windows and Linux loaders pass unknown names through, so `brave://policy` lists it with the error `Unknown policy.` (`IDS_POLICY_UNKNOWN`, `policy_conversions_client.cc:496-500`); the macOS loader reads only schema keys (`policy_loader_mac.mm:118-123` at 156.0.8078.48), so there it is not listed. GPC (`BraveGlobalPrivacyControlEnabled`) is the working equivalent |
| `MediaRecommendationsEnabled` | 💀 | **dead key.** The YAML is open (`chrome.*:87-`, no cap, not deprecated) but Chromium removed the handler and the pref with Kaleidoscope in `3e5b1be4a` (2021); `pref_mapping/MediaRecommendationsEnabled.json:3` says `Policy was removed` at 156.0.8078.48 and main, and brave-core never references it. `brave://policy` validates and lists it, but it has done nothing since Chromium 89. No script or preset writes it; `SlimBrave.ps1` Apply and Reset delete a leftover `0` it wrote. The pref-mapping file is the tiebreaker |
| `SafeBrowsingExtendedReportingEnabled` | ❌ removed | removed after cr144: `deprecated: true`, capped `chrome.*:66-144` ("no effect starting with M145") at 156.0.8078.48; Chromium `63b1c79f13` deleted its factory entry and `pref_mapping` file, and brave-core re-adds none. Outside the cr156 schema (see Version gating), so a written value shows in `brave://policy` as `Unknown policy.` on Windows and Linux and is not listed on macOS. Moot anyway: `IsExtendedReportingEnabled()` returns `IsEnhancedProtectionEnabled()` (156.0.8078.48 `components/safe_browsing/core/common/safe_browsing_prefs.cc:193-196`), which brave-core forces false (`chromium_src/components/safe_browsing/core/common/safe_browsing_prefs.cc:8`). Dropped from the three scripts and the Balanced Privacy, Maximum Privacy and Developer presets in v2.3.3; `SlimBrave.ps1` Apply and Reset delete a leftover `0` it wrote. The YAML cap and the missing pref-mapping file are the tiebreaker |
| `SafeSitesFilterBehavior` | ⚠️ dispatched, inert | **filters nothing in Brave and still sends every URL to Google.** Dispatched (factory `:1146-1148`): with 1, every http(s) navigation, iframes and redirects included, is POSTed to `safesearch.googleapis.com/v1:classify` with `key=<google_apis::GetAPIKey()>` (156.0.8078.48 `components/safe_search_api/safe_search/safe_search_url_checker_client.cc:30-39`), query, fragment and credentials stripped. Brave ships no Google API key (no `google_api_key` GN arg, `build/commands/lib/buildArgs.ts:12-36` at `v1.98.60`; the 1.98.60 Linux and Windows binaries hold no `AIza` key), so the request carries Chromium's placeholder `dummytoken` and the API answers HTTP 400; the verdict is `kUnknown`, which loads and is never cached (`components/safe_search_api/url_checker.cc:111-123`): every navigation is looked up again and nothing is blocked. Only a key supplied at run time (`GOOGLE_API_KEY`, `--gaia-config`) would change that. brave-core neither overrides the path nor proxies the host. Dropped from the three scripts and the Strict Parental Controls preset in v2.3.3 (the value does not mean what the label said, and sending every URL to Google is no product reason); the preset's DNS filter does the blocking. `SlimBrave.ps1` Apply and Reset delete a leftover `1` it wrote |
| `PromotionalTabsEnabled` | ⛔ | `deprecated: true`; still dispatched with its live successor `PromotionsEnabled` (`chrome.*:128-`), both into `prefs::kPromotionsEnabled` (factory `:2829-2835` at 156.0.8078.48). Not exposed either: nearly every surface that pref gates is a Chrome/Google promo Brave suppresses or never shows. Its one Brave-visible effect: `false` also hides the post-update brave.com/whats-new tab (upstream `DetermineStartupTabs` adds it only `if (promotions_enabled)`, `startup_browser_creator_impl.cc:663-682`) |
| `IPFSEnabled` | ⛔ | see the Brave table: deprecated, feature gone since 1.69.153. On desktop the `DEPRECATE_IPFS` tombstone (`!is_android && !is_ios`) still maps it to `brave.ipfs.enabled` (`brave_simple_policy_map.h:152-155` at `v1.98.60`), a pref registered only in `RegisterProfilePrefsForMigration` so `ClearDeprecatedIpfsPrefs` can clear it at startup; nothing reads it, so a written value is accepted, flagged deprecated in `brave://policy`, and inert. Same on `1.97.x` and master |
| `PrivacySandboxAdMeasurementEnabled`, `PrivacySandboxAdTopicsEnabled`, `PrivacySandboxSiteEnabledAdsEnabled` | ⛔ dispatched, inert | `deprecated: true` (cr144), uncapped `111-`; still dispatched at 156.0.8078.48 by `PrivacySandboxPolicyHandler` (factory `:3551`) into `privacy_sandbox.m1.*` prefs nothing reads any more (the Topics and Protected Audience implementations are deleted upstream). Brave ships the APIs off regardless: `rewrite/` disables `kBrowsingTopics`, `kConversionMeasurement`, `kFencedFrames` and the Blink `Fledge` / `AdInterestGroupAPI` features, asserted in `app/feature_defaults_unittest.cc` (`v1.98.60`) |
| `PrivacySandboxFingerprintingProtectionEnabled`, `PrivacySandboxIpProtectionEnabled` | ❌ removed | removed after cr145 / cr143: `deprecated: true`, capped `140-145` / `138-143`; no handler and no pref-mapping file at 156.0.8078.48; YAMLs unchanged on main |
| `PrivacySandboxPromptEnabled` | 💀 | `deprecated: true` (prompt configuration no longer supported), uncapped `111-`, but no handler reads it and `pref_mapping/PrivacySandboxPromptEnabled.json:3` says `Policy was removed` at 156.0.8078.48 and main |
| `ComponentUpdatesEnabled` | ✅ live, harmful | **actively harmful.** Dispatched (factory `:333-335` at 156.0.8078.48); for an installer that opts in (`supports_group_policy_enable_component_updates`), update_client refuses with `UPDATE_DISABLED`, so the component freezes or never installs (`components/component_updater/component_updater_service.cc:339-347`). Brave's `AdBlockComponentInstallerPolicy` opts in (`components/brave_shields/core/browser/ad_block_component_installer.cc:84-87`), so the Shields resources and filter lists would freeze, as would the user-agent list, NTP images, Chromium's CT log list and Root Store, and Widevine. Brave's own `BraveComponentInstallerPolicy` (Tor, ads resources, the Local Data Files bundle) opts out (`components/brave_component_updater/browser/brave_component_installer.cc:93-96`), so the key would freeze the protective parts and leave the rest |
| `FeedbackSurveysEnabled`, `SafeBrowsingSurveysEnabled` | ⚠️ no-op in Brave | dispatched (`configuration_policy_handler_list_factory.cc:369-371,1037-1039` at 156.0.8078.48), but brave-core's `rewrite/chrome/browser/ui/hats/hats_service_desktop.cc.yaml:15-18` makes `HatsServiceDesktop::RunCommonLaunchChecks` always return an error (`v1.98.60`; same on `1.99.x` and master), and both `CanShowSurvey` and every launch path (`ShowSurvey` → `RunLaunchChecks`) go through it (`chrome/browser/ui/hats/hats_service_desktop.cc:433-434,644-647,712` at 156.0.8078.48); no survey ever launches |
| `BrowserNetworkTimeQueriesEnabled` | ⚠️ no-op in Brave | dispatched on desktop (`configuration_policy_handler_list_factory.cc:2093-2095` at 156.0.8078.48), but `kNetworkTimeServiceQuerying` is force-disabled in Brave on every platform (`rewrite/components/network_time/network_time_tracker.cc.yaml:6-15` and its generated `patches/components-network_time-network_time_tracker.cc.patch:9-13` at `v1.98.60`; same on `1.99.x` and master), and `ShouldIssueTimeQuery` returns on that feature (`AreTimeFetchesEnabled`) before it reads the policy pref (`components/network_time/network_time_tracker.cc:453-456,740-749` at 156.0.8078.48) |
| `DomainReliabilityAllowed` | ⚠️ no-op in Brave | `app/brave_main_delegate.cc:121` (`v1.98.60`; same on `1.99.x` and master) appends `--disable-domain-reliability` unconditionally (from `BasicStartupComplete`, `:136-137`), and `ShouldCreateService` returns false on that switch before it reaches the policy check (`IsDomainReliabilityAllowed`, which reads `domain_reliability.allowed_by_policy`; `chrome/browser/domain_reliability/service_factory.cc:28-34`, `chrome/browser/net/profile_network_context_service.cc:181-184` at 156.0.8078.48) |
| `BuiltInAIAPIsEnabled` | ⚠️ no-op in Brave | Brave ships the base features behind every API the key gates disabled (`AIPromptAPI`, `AISummarizationAPI`, `AIWriterAPI`, `AIRewriterAPI`, `AIProofreadingAPI`; `rewrite/third_party/blink/renderer/platform/runtime_enabled_features.json5.yaml:73-101` at `v1.98.60`), and each `AIManager::CanCreate*` returns `kUnavailableFeatureNotEnabled` before reading the policy pref (156.0.8078.48 `chrome/browser/ai/ai_manager.cc:737-753`), so the policy is never consulted; no on-device model backs them either |
| `DefaultWebBluetoothGuardSetting`, `DefaultFileSystemReadGuardSetting`, `DefaultFileSystemWriteGuardSetting` | ⚠️ redundant | already feature-disabled in Brave, which is why the device-API set is USB+Serial+HID. The keys are live upstream, but both APIs sit behind Brave-owned `FEATURE_DISABLED_BY_DEFAULT` features (`chromium_src/third_party/blink/common/features.cc:10,12` at `v1.98.60`; no Griffin study): `kFileSystemAccessAPI` (`chrome://flags#file-system-access-api`) and `kBraveWebBluetoothAPI` (`chrome://flags#brave-web-bluetooth-api`, checked in `browser/bluetooth/brave_bluetooth_delegate.cc:19-20`). The keys bite only if a user turns those flags on |
| `DefaultThirdPartyStoragePartitioningSetting` | ❌ removed | removed after cr145: `deprecated: true`, capped `chrome.*:113-145`; no handler in `configuration_policy_handler_list_factory.cc` and `pref_mapping/DefaultThirdPartyStoragePartitioningSetting.json:3` says `Policy was removed` at 156.0.8078.48 and main (`7b96745f7dfb`) |
| `FirstPartySetsEnabled`, `RelatedWebsiteSetsEnabled`, `FirstPartySetsOverrides`, `RelatedWebsiteSetsOverrides` | ❌ removed | removed after cr152: all four `deprecated: true` and capped (`113-152` / `120-152`, Chromium `6925f9c991`), with their handlers and pref-mapping files deleted, so none is dispatched at 156.0.8078.48; brave-core re-adds none. Moot anyway: Brave's `AreRelatedWebsiteSetsEnabled()` returns false (`components/privacy_sandbox/brave_privacy_sandbox_settings.cc:29-52` at `v1.98.60`) |
| `InsecurePrivateNetworkRequestsAllowed`, `LocalNetworkAccessRestrictionsEnabled` | ❌ removed | removed after cr137 and cr144: `deprecated: true`, capped (`chrome.*:92-137`, `chrome.*:138-144`), no handler and no `pref_mapping` file at 156.0.8078.48. The successors are no posture switch: `LocalNetworkAccess{Blocked,Allowed}ForUrls` and the `LocalNetwork*` / `LoopbackNetwork*ForUrls` lists are URL-pattern lists, and `["*"]` in a `*BlockedForUrls` list would cut every site off from routers, NAS and local dev servers; the remaining LNA booleans only loosen it |
| `UrlKeyedMetricsAllowed` | 🕓 future_on only | `future_on:` only at 156.0.8078.48 and main, never shipped. Its handler is registered, the new half of a `SimpleDeprecatingPolicyHandler` pair with `UrlKeyedAnonymizedDataCollectionEnabled` (factory `:2680-2687`). A `future_on` key is dropped on the Stable and Beta channels unless `EnableExperimentalPolicies` lists it and honoured on others (`components/policy/core/browser/configuration_policy_handler_list.cc:62-66`), so Brave Release and Beta ignore it and Nightly applies it. Where applied, `false` writes only what `UrlKeyedAnonymizedDataCollectionEnabled = false` already writes, while `true` writes nothing yet still shadows that key, leaving the pref unmanaged |
| `AutofillSettings` | ⚠️ feature off | `supported_on: chrome.*:154-` and dispatched at 156.0.8078.48 (`AutofillSettingsPolicyHandler` → `autofill.types_blocked`), but every reader is gated on `kAutofillEnableAutofillSettingsEnterprisePolicy`, `FEATURE_DISABLED_BY_DEFAULT` at 156.0.8078.48 (`components/autofill/core/common/autofill_features.cc:714-715`), 157.0.8103.21 and main; no brave-core override, no Griffin study. Written today it only fills that pref. Beside the legacy keys it is a hazard: one handler checks all three and applies none if any check fails (`autofill_policy_handler.cc:76-93`, `configuration_policy_handler_list.cc:84-87`), so an `AutofillSettings` value that fails the schema cancels both legacy keys. Redundant even with the feature on: the two legacy keys already block `contact_info`, `identity_docs`, `travel` and `payments` (`autofill_policy_service.cc:28-77`), and `shopping` is Autofill AI, which Brave ships off. It is the successor the legacy keys' `deprecated: true` names — see What's next |
| `AutofillGenAiSettings` | ⚠️ no-op in Brave | `chrome.*:156-` int-enum (`google-sharing`), dispatched at 156.0.8078.48 (factory `:3598-3606`) into the Find-and-Fill-with-Gemini and Autofill-prediction prefs. Both features it governs are shipped off in Brave: Autofill AI needs `kAutofillAiWithDataSchema` and Find and Fill needs `kPersonalContext`, both on upstream and pinned off by brave-core (`rewrite/components/autofill/core/common/autofill_features.cc.yaml:7-23`, `rewrite/components/personal_context/core/personal_context_features.cc.yaml:7-10` at `v1.98.60`); no Griffin study. `2` (Disabled) would change nothing |
| `TryOnYouSettings` | ⚠️ no-op in Brave | `chrome.*:155-` int-enum (unset falls back to `GenAiDefaultSettings`), dispatched on desktop at 156.0.8078.48 into `indigo.policy` (`configuration_policy_handler_list_factory.cc:501-503`, `!IS_ANDROID`; fallback entry `:3685-3686`). Its one reader is `IndigoService`, which `CHECK`s `kIndigo` in its constructor (`chrome/browser/indigo/indigo_service.cc:214`); `kIndigo` is `FEATURE_DISABLED_BY_DEFAULT` (`chrome/common/chrome_features.cc:1285`) with no `brave://flags` entry, and brave-core pins it off (`rewrite/chrome/common/chrome_features.cc.yaml:34-37`, asserted in `app/feature_defaults_unittest.cc:220`, `v1.98.60`; same on `1.99.x` and master); no Griffin study. Try on You never runs, so `2` (Disabled) changes nothing |
| `LaunchOnStartupEnabled` | ⚠️ no-op in Brave | `chrome.win:156-`, browser-wide; dispatched on Windows (factory `:1977-1979` at 156.0.8078.48). Brave never registers itself to open at Windows sign-in or shows the prompts the key suppresses: both need `kLaunchOnStartup` (`chrome/browser/startup/startup_features.cc:12,30-43`), off upstream and pinned off by brave-core (`rewrite/chrome/browser/startup/startup_features.cc.yaml:6-10`); no Griffin study. It bites only if a user turns on `brave://flags#startup-launch` |
| `DefaultMediaStreamSetting` | ⛔ | `deprecated: true` (uncapped `chrome.*:22-`, same on main) yet still dispatched at 156.0.8078.48 (`configuration_policy_handler_list_factory.cc:671-673` into `profile.managed_default_content_settings.media_stream`, which the content-settings policy provider applies to both camera and microphone, `components/content_settings/core/browser/content_settings_policy_provider.cc:388-391`); a microphone/camera switch would use `AudioCaptureAllowed` / `VideoCaptureAllowed` (`chrome.*:25-`, `configuration_policy_handler_list_factory.cc:610-611,910-911`) |
| `BraveSearchResultAdsEnabled` | ❌ removed after 1.94.x | exists in no shipping Brave. A one-release key: merged to master 2026-07-20 (brave-core#37955) and reverted by `cf025361c` before `1.95.x` branched, so only 1.94.x and Nightly `v1.95.1`–`v1.95.47` dispatched it; the YAML is absent at `v1.98.60`, `1.99.x` and master. Its replacement, the universal pref `brave.brave_ads.sponsored.enabled` (first in 1.96), gates NTP sponsored images and tiles and the browser side of search result ads, and has no policy key: brave-browser#57204 closed on `1.96.x` with only a Settings toggle, and brave-browser#54917 (ads policy independent of Rewards, open, unmilestoned) plans a `SponsoredAdsEnabled` key with no PR yet. Until a key ships, `BraveRewardsDisabled` keeps the ads service off (see its row). A switch that does nothing is worse than none |

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
- Brave Sponsored Ads (`brave.brave_ads.sponsored.enabled`) — no policy key;
  `BraveRewardsDisabled` keeps the ads service off for now (see its row).
  Trigger: a new ads YAML under `policy_definitions/BraveSoftware` (watch the
  file list; a YAML never names its pref), or brave-browser#54917 gaining a
  milestone. Then a checkbox writing the off value, in every preset that
  carries `BraveRewardsDisabled`; required once #54917 lands, since it would
  decouple ads startup from Rewards. Until then, runtime-check what the
  Rewards row states from source; if it does not hold, correct the row and
  the scripts' Rewards description.
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
- `AlternateErrorPagesEnabled` on Chromium 157 — the row's proof of inertness
  is brave-core's `#define NetErrorTabHelper NoTabHelper`, which stops
  applying once Chromium creates the helper through `TabFeatures` (main);
  Brave's Chromium 157 upgrade (brave-core#40363) replaces the class with a
  no-op instead. Trigger: the first shipping Brave on 157; re-cite the row on
  the no-op class, or re-audit if it does not ship.
- `kSensorsAllowAskBlockPermissionModel` — off upstream, force-enabled by a
  brave-core plaster, which is what makes `DefaultSensorsSetting` = 3 mean
  Ask. Triggers: Chromium enabling it by default (the plaster turns
  redundant; correct the row), or brave-core dropping the plaster or a
  Release study disabling it while the default is off (3 then means Allow:
  drop or relabel the Ask choice in the three scripts).
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
  (`MediaRecommendationsEnabled`, `SafeBrowsingExtendedReportingEnabled`,
  `SafeSitesFilterBehavior`, or `BackgroundModeEnabled` on macOS) is dropped
  without a word. (5) `SlimBrave.ps1` import accepts a float for a choice
  key and rounds it: under PowerShell 7 `2.0`, `2e0` and `2.5`; under Windows
  PowerShell 5.1, the elevated relaunch host, only exponent forms such as
  `2e0`, since `2.0` and `2.5` arrive as `[decimal]` and are rejected and
  named (see Cross-cutting, Content-setting enums); the Python scripts reject
  all of them.
  `MAC_CHANNELS` needs no Dev entry: Brave dropped Dev (brave-browser#25248)
  and its macOS Dev appcast stopped at 1.61.87 (2023-11).
- Runtime checks owed on a shipping Brave: `DefaultBrowserSettingEnabled` =
  false with *Set as default* on the first-run welcome page
  (brave-browser#60038 confirms the crash on 1.97.59 for Linux; Windows,
  macOS and 1.98.60 still to run); `BraveRewardsDisabled` = true with no
  `ChromeVariations`: does Brave still fetch
  `static.ads.brave.com/v1/ohttp/hpkekeyconfig` (`brave://net-export`, on a
  fresh profile's second launch, since a desktop applies a Griffin seed only
  from then)? Source says yes; and the Sponsored Ads items above.
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
  class (16 of the 47 Chromium keys written at 156.0.8078.48, through 14
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
   from there). **The YAML is not enough:** a policy can be removed from the
   code and left in the templates for years. For every Chromium key confirm
   dispatch at the tag in `configuration_policy_handler_list_factory.cc` (or its
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
