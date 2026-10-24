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
| BraveStatsPingEnabled | ✅ | cr138 | bool | map, unguarded | unset = enabled; restart per YAML, but each reader checks the pref when it acts, so a change applies live (the pinger on every 5-minute timer tick before its once-a-day ping, `browser/brave_stats/brave_stats_updater.cc:77,283-295`; SERP collection per navigation; referral finalization on its own timer, `components/brave_referrals/browser/brave_referrals_service.cc:209-214`); browser-wide. The pref (`brave.stats.reporting_enabled`) also stops SERP-metrics collection (`SerpMetricsTabHelper::DidFinishNavigation` returns early, `browser/serp_metrics/serp_metrics_tab_helper.cc:115-117`; `kSerpMetricsFeature` on by default, `components/serp_metrics/serp_metrics_feature.cc:10`), whose `braveSearch`/`googleSearch`/`otherSearch`/`staleSearch` counts the ping carries (`browser/brave_stats/brave_stats_updater_params.cc:194-224`), and both referral initialization and finalization (`BraveReferralsService`: `InitReferral` skips the promo-code request, `components/brave_referrals/browser/brave_referrals_service.cc:535-543`; `MaybeCheckForReferralFinalization` clears the download ID, `:471-480`). P3A reports the same counts, bucketed, as the `Brave.Search.SERPBrave`/`SERPGoogle`/`SERPOther`/`SERPStale` express metrics, sent once a day (`components/p3a/metric_log_type.h:22`; `browser/serp_metrics/serp_metrics_p3a.cc:83-103,127-150`; `kSerpMetricsP3A` param, default true, `components/serp_metrics/serp_metrics_feature.h:23-24`); with collection off that copy still sends `Brave.Search.SERPBrave` = 0 every day (`serp_metrics_p3a.cc:142-143`; the other three are suppressed at zero, `:62-66`) until `BraveP3AEnabled` stops P3A |
| BraveGlobalPrivacyControlEnabled | ✅ | cr142 | bool | map, unguarded | dynamic refresh; unset = enabled, no Settings toggle: `IsGlobalPrivacyControlEnabled` returns true unless the pref is managed (`components/global_privacy_control/global_privacy_control_utils.cc:16-22`), so `true` matches the default and only outranks Ad Block Only Mode's injected `false` (`components/brave_policy/ad_block_only_mode/ad_block_only_mode_policy_manager.cc:131-133`; see Cross-cutting) and pins against a default flip. `Sec-GPC` and `navigator.globalPrivacyControl` sit behind `kBraveGlobalPrivacyControl`, on by default (`chromium_src/third_party/blink/common/features.cc:40`; checked at `browser/net/brave_request_handler_impl.cc:99-104` and `third_party/blink/renderer/modules/global_privacy_control/global_privacy_control.cc:15-16`); `brave://flags/#brave-global-privacy-control-enabled` (`browser/about_flags.cc:1541-1546`) turns the feature off and the policy cannot override it |
| BraveDeAmpEnabled | ✅ | cr140 | bool | map, unguarded | dynamic refresh; unset = the user's Settings toggle, default on: `kBraveDeAMP` is on by default with no Griffin study (`components/de_amp/common/features.cc:15`) and `brave.de_amp.enabled` defaults `true` (`components/de_amp/common/pref_names.cc:13`; toggle at `browser/resources/settings/brave_privacy_page/brave_personalization_options.html:70`), so the key locks it and outranks Ad Block Only Mode's injected `false` (see Cross-cutting). No Shields check: `DeAmpBodyHandler::Create` tests only the feature and the pref (`components/de_amp/browser/de_amp_body_handler.cc:102-105`) and is attached to every main-frame request (`browser/brave_content_browser_client.cc:1246-1251`), so it also works where Shields are off. `brave://flags/#brave-de-amp` turns the feature off and the policy cannot override it |
| BraveDebouncingEnabled | ✅ | cr140 | bool | map, unguarded | dynamic refresh; unset = the user's Settings toggle, default on: `kBraveDebounce` is on by default (`components/debounce/core/common/features.cc:16`; brave-variations' `BraveDebounceStudy` only enables it and ends at `max_version` 151.*) and `brave.debounce.enabled` defaults `true` (`components/debounce/core/browser/debounce_service.cc:55`; toggle at `brave_personalization_options.html:75-78`), so the key locks it and outranks Ad Block Only Mode's injected `false` (see Cross-cutting). No Shields check: the throttle checks every main-frame navigation while the pref is true (`components/debounce/content/browser/debounce_navigation_throttle.cc:99-101`, `browser/brave_content_browser_client.cc:1552-1555`), so it also works where Shields are off; the redirect rules come from the debounce component. `brave://flags/#brave-debounce` turns the feature off and the policy cannot override it: no `DebounceService` is built (`browser/debounce/debounce_service_factory.cc:46-47`) and the Settings toggle is hidden (`browser/ui/webui/settings/brave_privacy_handler.cc:128-130`) |
| BraveTrackingQueryParametersFilteringEnabled | ✅ | cr142 | bool | map, unguarded | dynamic refresh; only effective while Shields is enabled (`ctx->allow_brave_shields()`, `browser/net/brave_site_hacks_network_delegate_helper.cc:77-78`); unset = enabled, no user toggle (the pref is read only when managed, `browser/net/brave_site_hacks_network_delegate_helper.cc:58-67`), so `true` matches the default and only keeps filtering on against Ad Block Only Mode's injected `false` (see Cross-cutting). The parameter list is the Query Filter component (brave/adblock-lists `brave-lists/query-filter.json`; fbclid, gclid and mc_eid are among its `*://*/*` parameters), applied only while `kQueryFilterComponent` is on, which it is by default, with no brave://flags entry and no Griffin study (`components/query_filter/common/features.cc:13`; `components/query_filter/browser/utils.cc:183-186`) |
| BraveReduceLanguageEnabled | ✅ | cr140 | bool | map, unguarded | dynamic refresh; the pref (`brave.reduce_language`) defaults on (`components/brave_shields/core/browser/brave_shields_settings_service.cc:403-404`) with a Settings toggle (`brave_personalization_options.html:86`), so the key locks it and outranks Ad Block Only Mode's injected `false` (see Cross-cutting); `kBraveReduceLanguage` is on by default (`components/brave_shields/core/common/features.cc:68`; brave-variations' `DisableReduceLanguage`, despite its name, only enables it and ends at `max_version` 151.*), but `brave://flags/#brave-reduce-language` turns it off and the policy cannot override it. It governs two things, both only where Shields are up and fingerprinting is not off. The `Accept-Language` header, cut to the first language (plus its base code) with a per-site random q-value: `ShouldDoReduceLanguage` (`components/brave_shields/core/browser/brave_shields_utils.cc:374-390`, called from `browser/net/brave_reduce_language_network_delegate_helper.cc:110-113`) bails when Shields are down, when fingerprinting is `ALLOW` for the site (e.g. `DefaultBraveFingerprintingV2Setting` = 1) or on a `BRAVE_WEBCOMPAT_LANGUAGE` exception. The local-font allowlist (`BraveSessionCache::AllowFontFamily`, `third_party/blink/renderer/core/farbling/brave_session_cache.cc:443-451`), lifted wherever farbling is off or on a `BRAVE_WEBCOMPAT_FONT` exception. `navigator.languages` is not this key's: farbling trims it whenever it is on for the site, whatever the pref or the flag (`chromium_src/third_party/blink/renderer/core/frame/navigator_language.cc:19-38`) |
| BraveRewardsDisabled | ✅ | cr105 | bool | map, `ENABLE_BRAVE_REWARDS` | true = disable; restart. **Also stops Sponsored Ads, except Brave Search's.** It keeps the ads service from starting (`AdsServiceImpl::CanStartBatAdsService` returns false when `brave_rewards::IsSupported` fails, `ads_service_impl.cc:307-312`; the first start waits on `PolicyInitializationWaiter`, 213-218), so no notification ads, no NTP sponsored wallpapers (New Tab Takeover, served only via `AdsServiceImpl::MaybeServeNewTabPageAd`, which returns no ad while bat-ads is unbound, 1295-1299; the NTP falls back to a regular background, `view_counter_service.cc:240-257,427-432`) and no ad event or conversion reporting. Brave Search's own result ads are server-side and still show; the `Brave-Search-Ads` opt-out header goes only to a joined, wallet-connected Rewards profile (`search_ads_header_network_delegate_helper.cc:25-36`; brave-browser#51040, wontfix). The policy hides Settings → Privacy and security → Data collection → "Enable Sponsored Ads" (`isSponsoredAdsAllowed`, `brave_settings_ui.cc:281-283`; brave-core#39810, uplifted as #39857) and, on the default refreshed NTP, the customize panel's sponsored-images and sponsored-sites toggles (both need `rewardsFeatureEnabled`, which is `brave_rewards::IsSupportedForProfile`, `new_tab_page_initializer.cc:215-216`; `background_panel.tsx:188`, `top_sites_panel.tsx:64`); the "Show background images" switch remains. Edge, until restart: the sponsored-images component is registered if the policy lands while Brave runs (the ads service observes the pref and shuts down at once, `ads_service_impl.cc:739-743,820-826`, but a component it registered stays: `ViewCounterService` observes only ads init and data clear, `view_counter_service.h:131-132`) or once that switch is turned off and on again: `ViewCounterService::OnPreferenceChanged` calls `UpdateSponsoredImagesComponentRegistration`, which checks only `brave.brave_ads.sponsored.enabled` (default true, left alone by the policy), the ads region and the switch, not whether the ads service runs (`view_counter_service.cc:339-343,403-425`; brave-core#40173). Wallpapers still cannot be served, but refreshed-NTP sponsored-site tiles need no ads service (`sponsored_sites_facade.cc:123-139`) and can appear for an advertiser already among the user's visited top sites (`top_sites_grid_items.ts:82-98`). Clear browsing data → "Clear Brave Ads data" does not register it (`OnDidClearAdsServiceData` returns while the component is unregistered, `view_counter_service.cc:146-156`). brave-browser#54917 (open, unmilestoned; the issue names `SponsoredAdsEnabled`, draft brave-core#35873 `BraveAdsEnabled`) would decouple ads startup from Rewards; when it lands this row stops covering ads and a new key is needed. Not all ads traffic stops: every regular profile still builds its ads service at profile init with no Rewards check (`browser/profiles/brave_profile_manager.cc:249-251`), and its `HttpClient` fetches the OHTTP key config from `static.ads.brave.com/v1/ohttp/hpkekeyconfig`, without credentials, at startup when the stored config has expired or was never fetched and otherwise when it expires (3 days by default; `components/brave_ads/core/browser/network/http_client.cc:132-135`, `oblivious_http_key_config.cc:46-53`), whenever `kShouldSupportOhttp` is set. The flag is off in code (`oblivious_http_feature.cc:10`) and set only by Griffin's `BraveAdsObliviousHttpStudy` (100% on Nightly, Beta and Release, no `policy_restriction`), so either `ChromeVariations` row stops the fetch; on `1.99.x` and master it also needs `brave.brave_ads.sponsored.enabled` (default true) or Rewards with notification ads (brave-browser#59687), so this key alone still does not stop it there. Source-read at `v1.98.60` (gate and edge the same on `1.99.x` and master, where startup sits in `AdsServiceImpl::Init()`), not runtime-tested |
| BraveWalletDisabled | ✅ | cr106 | bool | map, `ENABLE_BRAVE_WALLET` | true = disable. Entry `brave_simple_policy_map.h:98-101` into `brave.wallet.disabled_by_policy`, guard `enable_brave_wallet = !is_brave_origin_branded` (`components/brave_wallet/common/buildflags/buildflags.gni:9`), so every regular desktop build; no feature gate: `IsAllowedForContext` checks only the managed pref, Tor and the profile type (`browser/brave_wallet/brave_wallet_context_utils.cc:17-36`, `IsAllowed` at `components/brave_wallet/browser/brave_wallet_utils.cc:52-56,217-219`). Removes the wallet service (`brave_wallet_service_factory.cc:36-38`), toolbar button, side panel and settings page, and also disables web3 and decentralized DNS: Brave's own dapp providers (`window.ethereum`, `window.solana`, Cardano) are neither bound nor injected (`browser/brave_content_browser_client.cc:1056-1066`, `renderer/brave_content_renderer_client.cc:205-210`), and ENS/SNS/Unstoppable Domains resolution and its opt-in interstitial bail (`browser/net/decentralized_dns_network_delegate_helper.cc:46-51`, `components/decentralized_dns/content/decentralized_dns_navigation_throttle.cc:45-48`); same on `1.99.x` and master. Restart |
| BraveVPNDisabled | ⚠️ no-op on Linux | cr112 | bool | map, `ENABLE_BRAVE_VPN` | **Windows, macOS, Android, iOS only.** `enable_brave_vpn = enable_brave_vpn_v1 \|\| enable_brave_vpn_v2`, both `(is_win \|\| is_android \|\| is_mac \|\| is_ios) && !is_brave_origin_branded` (`components/brave_vpn/common/buildflags/buildflags.gni:11-22` at `v1.98.60`, unchanged on `1.97.x`, `1.99.x` and master) — no `is_linux`, so the `brave_simple_policy_map.h:112-115` entry is compiled out of Linux builds and the key is a silent no-op there while `brave://policy` still shows it applied: the 1.98.60 Linux `brave` binary carries the key name but not the target pref `brave.brave_vpn.disabled_by_policy`, which the Windows `chrome.dll` does. Linux also keeps `kBraveVPN` `FEATURE_DISABLED_BY_DEFAULT` (`components/brave_vpn/common/features.cc:15-21`). On Windows and macOS the key is effective: `IsBraveVPNEnabled` = not disabled by policy **and** `kBraveVPN` and `kSkusFeature`, both on by default there (`components/brave_vpn/common/brave_vpn_utils.cc:207-228`), which hides the toolbar button (it watches the pref, `brave_toolbar_view.cc:440-443`), the NTP card, the settings section and the welcome-page offer. The Linux row is labelled rather than removed (`enable_brave_vpn_v2_apps` already names `is_linux`, `buildflags.gni:34`); `slimbrave-mac.py` gives it the same label and note when run on Linux. **Trigger:** `is_linux` joining `enable_brave_vpn_v1` or `_v2` with `kBraveVPN` on for Linux, in `features.cc` or by a Griffin study (brave-browser#15817 "Implement Brave VPN on Linux" and #56726 "Add VPN app binaries to the Linux installer", both open and unmilestoned); then drop the Linux label and note from both Python scripts. Restart |
| BraveAIChatEnabled | ✅ | cr121 | bool | map, `ENABLE_AI_CHAT` | false = disable Leo. Entry `brave_simple_policy_map.h:116-119` into `brave.ai_chat.enabled_by_policy` (default `true`), guard `enable_ai_chat = !is_brave_origin_branded` (`components/ai_chat/core/common/buildflags/buildflags.gni:9`), so every regular build, Linux included. `IsAIChatEnabled(prefs)` = `kAIChat` (on by default, `components/ai_chat/core/common/features.cc:22`; no Griffin study turns it off) **and** not managed `false` (`components/ai_chat/core/browser/utils.cc:102-106,131-134`); `false` makes `AIChatServiceFactory` return null (`browser/ai_chat/ai_chat_service_factory.cc:51`) and removes the sidebar item, the toolbar button, the omnibox Leo provider (`chromium_src/components/omnibox/browser/autocomplete_controller.cc:82`), the selection context menu, the NTP Leo input, `brave://leo-ai` (`browser/ui/webui/ai_chat/ai_chat_ui.cc:238-241`) and Tab Focus, which needs the service; same on `1.99.x` and master. Does not cover on-device models (see BraveLocalAIEnabled: own buildflag, pref and code; `components/local_ai/` has no AI Chat dependency); restart |
| BraveLocalAIEnabled | ⚠️ feature off on Release | cr149 — **Brave 1.94**, branch-probed | bool | map, `ENABLE_LOCAL_AI` | false = unregister and uninstall the on-device model components: EmbeddingGemma (`ejhejjmaoaohpghnblcdcjilndkangfe`, `components/local_ai/core/local_models_updater.cc:88-101,128-137`) and the on-device speech models (`nhkekccefdppopbldokibkoegppanbba`; allowed only with feature **and** switch, `components/local_ai/core/utils.cc:19-22`, applied by `on_device_speech_models_component_installer.cc:134-140,207-226`); and `IsHistoryEmbeddingsFeatureEnabled()` returns false (`rewrite/chrome/browser/history_embeddings/history_embeddings_utils.cc.yaml:42-45`), so history is not vector-indexed, the brave://settings/privacy "Semantic history search" toggle is hidden (`isSemanticHistorySearchAvailable`, `brave_settings_localized_strings_provider.cc:1230-1232`), Leo is not given its history-search tool (`browser/ai_chat/browser_tool_provider.cc:63-66`), and Leo's tab search and Tab Search's search-by-content get no index (`ai_chat_untrusted_conversation_ui.cc:150`, `chromium_src/…/tab_search_page_handler.cc:449`). **Feature off on Release:** EmbeddingGemma and history search need `kHistoryEmbeddings`, `FEATURE_DISABLED_BY_DEFAULT` at 156.0.8078.48 (`components/history_embeddings/core/history_embeddings_features.cc:26`) and pinned off by brave-core (`rewrite/components/history_embeddings/core/history_embeddings_features.cc.yaml:7-13`), which also pins off `kLaunchedHistoryEmbeddings` (`…history_embeddings_utils.cc.yaml:27-30`), the upstream switch that otherwise turns history search on for us/en-US when the feature is not overridden (`chrome/browser/history_embeddings/history_embeddings_utils.cc:180-186` at 156.0.8078.48); the speech models need `kBraveOnDeviceSpeechRecognition`, off with no Griffin study and no brave://flags entry on `v1.98.60` or `1.99.x` (`components/local_ai/core/features.cc:10-11`; master adds `brave-on-device-speech-recognition`). Griffin enables `HistoryEmbeddings` on desktop (Windows/macOS/Linux) Nightly at 100% (`HistoryEmbeddingsStudy`, brave-variations `3502e2473b`) and Beta at 50% (`HistoryEmbeddingsStudy_Beta`, brave-variations#1936, `86c21c7cb7`), both from `152.1.96.13` and in the live seed; no Release study. There EmbeddingGemma downloads at launch whether or not a profile opts in, while indexing stays a per-profile opt-in: the "Semantic history search" toggle, `brave.history_embeddings_enabled`, default false (`components/local_ai/core/pref_names.cc:13`). Neither study sets `policy_restriction`, so either `ChromeVariations` row (1 or 2) filters both out (`components/variations/study_filtering.cc:213-229` at 156.0.8078.48). On Release, and on the Beta installs outside the study, the key only blocks a `brave://flags#brave-history-embeddings` opt-in. It is the only policy lever: Chromium's `HistorySearchSettings` and `GenAiDefaultSettings` never reach Brave, which replaces `IsHistoryEmbeddingsEnabledForProfile` with the feature plus that per-profile pref (`…history_embeddings_utils.cc.yaml:53-56`). Separate buildflag (`ENABLE_LOCAL_AI`) and prefs from AI Chat. Restart for history search (the switch takes effect on relaunch, `brave_history_embeddings_status.cc:48-49`); the two model registrars observe the pref and unregister on a change (`local_models_updater.cc:66-70`, `on_device_speech_models_component_installer.cc:85-89`); browser-wide. In five presets, all but Strict Parental Controls; Brave Origin's matches Origin's own `false` default (`brave_origin_service_factory.cc:144`) |
| BraveShieldsDisabledForUrls | ✅ | cr107 | list | map, unguarded | scheme-wide patterns, see Cross-cutting; browser-wide; restart per YAML (`brave://policy` flags a change "restart required": `components/policy/core/browser/policy_conversions_client.cc:339-360`), but applies live: Chromium's content-settings `PolicyProvider` watches the pref and re-reads the list on change (`components/content_settings/core/browser/content_settings_policy_provider.cc:451-455,758-765`, both at 156.0.8078.48), as for its own `*ForUrls` lists. Where Shields are off, all five `DefaultBrave*` rows, `BraveTrackingQueryParametersFilteringEnabled` and `BraveReduceLanguageEnabled` do nothing; with `https://*` and `http://*` that is every web page. De-AMP, Debouncing and GPC have no Shields check and keep working |
| BraveShieldsEnabledForUrls | ✅ | cr107 | list | map, unguarded | counterpart of the row above; browser-wide; restart per YAML but applies live, as above. Pins Shields on for matched sites: the new panel (the default: `kShowUpdatedShieldsPanel` on, `components/brave_shields/core/common/features.cc:160`) keeps its main toggle clickable, but it only writes a user rule that the policy rule outranks (`components/brave_shields/resources/panel_new/components/main_card.tsx:84-87` at `v1.98.60`); `isBraveShieldsManaged` (reads only `BRAVE_SHIELDS`, `brave_shields_settings_service.cc:107-112`) greys the ad-block, scripts, fingerprinting, cookie and forget-first-party-storage controls (`panel_new/components/advanced_settings.tsx:85,213,272,292,338,383`) but not the HTTPS-upgrade dropdown (`HttpsUpgradeControls`, 129-167; hidden only while `HttpsByDefault` is off or in a Tor window, 141), whose per-site choice writes a user `BRAVE_HTTPS_UPGRADE` rule with no managed check (`SetHttpsUpgradeMode`, `browser/brave_shields/brave_shields_tab_helper.cc:425-441`), so a per-site HTTPS mode stays settable unless `DefaultBraveHttpsUpgradeSetting` is set too. `HttpsByDefault` is on in code (`chromium_src/net/base/features.cc:31-33`), but brave-variations `TransitionToUpstreamHttpsUpgrade` (brave-variations#1939) turns it off, and with it the dropdown, for 25% of desktop Release and all of desktop Beta and Nightly; it sets no `policy_restriction`, so `ChromeVariations` 1 or 2 keeps it out. It is the only key that stops a user dropping Shields per site, which would void every `DefaultBrave*` enforcer there. If the identical pattern is in both lists this one wins and Shields stay on: Brave's patch inserts it after `DisabledForUrls` and Chromium's provider lets the last entry for an origin win (`content_settings_policy_provider.cc:47-48` at 156.0.8078.48); a narrower `DisabledForUrls` pattern still beats a broad one here. The scripts keep the two rows mutually exclusive, so only foreign files hit this |
| BraveNewsDisabled | ✅ | cr138 | bool | map, `ENABLE_BRAVE_NEWS` | true = disable; restart. Unset, News stays off until the user opts in on the new tab page (`brave.today.opted_in`, default `false`, `components/brave_news/common/pref_names.cc:21`). `true` makes `brave_news::IsEnabled` false whatever the user chose (`components/brave_news/common/pref_names.cc:34-41`), so the feed is never fetched: `BraveNewsController`'s feed, publisher, channel, signal and locale getters return empty (e.g. `GetFeedV2`, `components/brave_news/browser/brave_news_controller.cc:346-351`) and the refresh timers never start, the start waiting on `PolicyInitializationWaiter` (189-195). It hides News on the new tab page (`newsFeatureEnabled`, `browser/ui/webui/brave_new_tab_page_refresh/new_tab_page_initializer.cc:233-236`), the RSS page action (`browser/brave_news/brave_news_tab_helper.cc:294-299`) and its customize-toolbar entry (`browser/ui/webui/side_panel/customize_chrome/customize_toolbar/list_action_modifiers.cc:69-72`), and disables `IDC_CONFIGURE_BRAVE_NEWS` and `IDC_TOGGLE_BRAVE_NEWS_SIDE_PANEL` (`browser/ui/brave_browser_command_controller.cc:388-391,502-505`). Edge: the sidebar News item, a default item (`browser/ui/sidebar/sidebar_service_factory.h:60-62`), checks only `kBraveNewsSidebar` (on by default, `components/brave_news/common/features.cc:18`) and `brave.today.opted_in` (`components/sidebar/browser/sidebar_service.cc:770-783`), and its panel is registered on the feature alone (`chromium_src/chrome/browser/ui/views/side_panel/side_panel_helper.cc:67-73`), so a profile that opted in before the policy keeps the button, which opens a panel with no feed; the YAML's "all related UI elements will be hidden" overstates. `kBraveNewsNewUserOptIn`, which on first run sets `brave.today.opted_in` whatever the policy and reverts it after 30 days unless News was used (`brave_news_controller.cc:84-118`, called from the constructor at 177), is `FEATURE_DISABLED_BY_DEFAULT` (`components/brave_news/common/features.cc:29`, same on `1.98.61`, `1.99.x` and master) with no Griffin study; if it turns on, the policy still wins wherever `IsEnabled` gates, but every new profile gets the sidebar edge above (see What's next). The sidebar and `IsEnabled` code is the same on `1.99.x` and master. Source-read, not runtime-tested |
| BraveTalkDisabled | ✅ | cr138 | bool | map, `ENABLE_BRAVE_TALK` | true = disable; restart. Removes Brave Talk's browser entry points: the new tab page widget (`talkFeatureEnabled`, `browser/ui/webui/brave_new_tab_page_refresh/new_tab_page_initializer.cc:242-244`), the sidebar item (`components/sidebar/browser/sidebar_service.cc:680-689`, which watches the pref, 160-162) and the `IDC_SHOW_BRAVE_TALK` command and its shortcut (`browser/ui/brave_browser_command_controller.cc:398-402`, `browser/ui/commands/accelerator_service.cc:476-478`). No navigation check reads the pref: `talk.brave.com` is a website and still opens when typed or linked; the `braveTalk` extension API is exposed only to `chrome://newtab` (`common/extensions/api/_brave_talk_api_features.json:11`). Same on `1.99.x` and master |
| BravePlaylistEnabled | ⚠️ feature off on Release/Beta | cr139 | bool | map, `ENABLE_PLAYLIST` | **Key live, feature off outside Nightly.** `playlist::features::kPlaylist` is `FEATURE_DISABLED_BY_DEFAULT` on every non-iOS build (`components/playlist/core/common/features.cc:13-19` at `v1.98.60`; same on `1.99.x` and master), `IsPlaylistAllowed()` requires feature **and** no policy `false` (`components/playlist/core/browser/utils.cc:18-29`), and the only Griffin study enabling it, brave-variations `DefaultPlaylistStudy`, is Nightly-only in the source and the live seed (Windows/macOS/Linux; no `policy_restriction`, so `ChromeVariations` 1 or 2 filters it out). `false` bites on Nightly and wherever the user turns on `brave://flags/#playlist` (`browser/about_flags.cc:374-381`); on Release and Beta it is a pre-emptive guard. The YAML's "enabled by default" is wrong for desktop. Restart |
| BraveWebDiscoveryEnabled | ✅ | cr138 | bool | map, `ENABLE_WEB_DISCOVERY` | unset = **disabled** by default (`brave.web_discovery_enabled` registered `false`, `browser/brave_profile_prefs.cc:551`); writing `false` locks it off and, the pref being managed, suppresses both opt-in prompts: the search.brave.com infobar shown when Brave Search is the default engine (`WebDiscoveryTabHelper::DidFinishLoad` asks `ShouldShowWebDiscoveryInfoBar`, which bails on a managed pref, `browser/web_discovery/web_discovery_cta_util.cc:85-92` at `v1.98.60`) and the first-run `chrome://welcome` flow's Web Discovery step (skipped when `isWebDiscoveryEnabledManaged`, `components/brave_welcome_ui/state/hooks.ts:89-93`, set by `browser/ui/webui/welcome_page/brave_welcome_ui.cc:174-178`; the unlinked `chrome://welcome-new` page drops it too, `browser/resources/brave_welcome_page/components/use_available_metrics.ts:25`). On desktop the collector is the Brave extension's background page, attached only while the pref is true (`browser/extensions/brave_component_loader.cc:57-68`), because `kBraveWebDiscoveryNative` is off outside Android (`components/web_discovery/common/features.cc:12-18`) and its only Griffin study, `WebDiscoveryNativeStudy`, is Android-only and capped at `153.1.96.42`; the native service, where enabled, stops on `false` too (`components/web_discovery/browser/web_discovery_service.cc:114-120`). Same on `1.99.x` and master. Restart per YAML, but both paths watch the pref and apply a change live (`brave_component_loader.cc:42-45`, `web_discovery_service.cc:44-47`) |
| BraveSpeedreaderEnabled | ✅ | cr138 | bool | map, `ENABLE_SPEEDREADER` | desktop only (`enable_speedreader = !is_ios && !is_android && !is_brave_origin_branded`, `components/speedreader/common/buildflags/buildflags.gni:9`); restart. Maps to the top-level `brave.speedreader.feature_enabled` (default `true`, `components/speedreader/speedreader_service.cc:65`), not the all-sites pref: `false` makes `IsAllowedForSite` and `IsAllowedForAllReadableSites` return false (`speedreader_service.cc:98-103,124-127`) and hides the page action (`browser/ui/views/page_action/speedreader_page_action_controller.cc:113-118`), taking the reader view's read-aloud (`kSpeedreaderTTS`, default `true`, `components/speedreader/common/features.cc:17-18`) with it. `kSpeedreaderFeature` is on by default (`features.cc:10-12`, same on `1.99.x` and master) and no Griffin study turns it off |
| BraveWaybackMachineEnabled | ✅ | cr138 | bool | map, `ENABLE_BRAVE_WAYBACK_MACHINE` | desktop only; unset = enabled (`brave.wayback_machine_enabled` defaults `true`, `browser/brave_profile_prefs.cc:480-483` at `v1.98.60`). `false` stops the archive.org offer after a 404, 408, 410, 451 or most 5xx responses (`ShouldCheckWaybackMachine`, `components/brave_wayback_machine/brave_wayback_machine_utils.cc:52-72`) and hides the URL-bar icon (`browser/ui/views/page_action/wayback_machine_page_action_controller.cc:240-243`) and the Settings toggle (`browser/resources/settings/brave_content_page/content.html:51-66`). The two opt-ins on top of it, `kWaybackMachineAutoShowBubble` (pops the bubble on a missing page) and `kWaybackMachineAutoCheck` (a Settings toggle shown only while the pref is on), are `FEATURE_DISABLED_BY_DEFAULT` (`components/brave_wayback_machine/features.cc:10-11`; same on `1.99.x` and master) with no Griffin study, and `false` covers both. Restart per YAML, but applies live: the tab helper watches the pref and re-reads it on every navigation (`components/brave_wayback_machine/brave_wayback_machine_tab_helper.cc:49-53,73-76`) |
| TorDisabled | ✅ | cr78 (Win) / cr93 (mac, Linux) | bool | map, `ENABLE_TOR` | desktop only; browser-wide (Local State `tor.tor_disabled`). `true` drops "New private window with Tor" from the app menu (inserted only while its command is enabled, `browser/ui/toolbar/brave_app_menu_model.cc:172-176`) and, when each profile starts and whenever the pref turns on, closes every Tor window and deletes the downloaded Tor client, its data and the pluggable-transport component (`BraveExtensionManagement::OnTorDisabledChanged`, `browser/extensions/brave_extension_management.cc:55-65,80-87` at `v1.98.60`; `components/tor/brave_tor_client_updater.cc:110-120`). Restart per YAML, but applies live: the Tor commands follow the pref too (`browser/brave_browser_process_impl.cc:195-198,486-495`) |
| EmailAliasesEnabled | ✅ | cr147 — **Brave 1.92**, branch-probed | bool | map, `ENABLE_EMAIL_ALIASES` | **Feature on via Griffin, off in code.** Dispatched (`brave_simple_policy_map.h:156-159` under `ENABLE_EMAIL_ALIASES` = `!is_ios && !is_android && !is_brave_origin_branded`, desktop only, `components/email_aliases/buildflags/buildflags.gni:8`). `components/email_aliases/features.cc:13` keeps `kEmailAliases` `FEATURE_DISABLED_BY_DEFAULT` on `1.92.x` through `1.99.x` and master, but brave-variations `EmailAliasesStudy_Release` (brave-variations#1835, `83e246fcc`, 2026-08-27) enables `EmailAliases` at 100% on Release Windows/macOS/Linux from `152.1.94.113`, and `EmailAliasesStudy` on Nightly and Beta from `149.1.93.23`; both are in the live seed. `IsEmailAliasesEnabledForProfile()` requires feature **and** pref (`brave.email_aliases.enabled`, default `true`, `components/email_aliases/email_aliases_service.cc:125`), so on shipping `v1.98.60` `false` removes the service (`browser/email_aliases/email_aliases_service_factory.cc:56-59`) and with it the settings page, context-menu entry, autofill suggestions, promo and command. With `kBraveAccount` off (`components/brave_account/features.cc:17`; same on `1.99.x` and master, no Griffin study) it also hides the Settings → Get started Brave Account row (`IsBraveAccountEnabledForProfile` = `kBraveAccount` **or** Email Aliases for the profile, `features.cc:35-41`, read by `brave_settings_ui.cc:336-339`); `brave://account` and the per-profile `BraveAccountService` stay, since they follow the process-wide `IsBraveAccountEnabled()`, which reads the features and no pref (`features.cc:23-29`). Neither study sets `policy_restriction`, so either `ChromeVariations` row (1 or 2) filters both out (`components/variations/study_filtering.cc:213-228` at 156.0.8078.48) and `false` is then a guard, which also outranks a `brave://flags/#brave-email-aliases` opt-in. Restart |
| DefaultBraveAdblockSetting | ✅ | cr142 | int enum | own `IntRangePolicyHandlerBase` handler, unguarded (`chromium_src/chrome/browser/policy/configuration_policy_handler_list_factory.cc:32-36`) → `brave.profile.managed_default_content_settings.*` pref → content-settings policy provider (brave-core patch + `rewrite/` twin) | 1 = allow ads, 2 = block. Locks only `BRAVE_ADS` (`GetAdControlType`): standard network ad/tracker blocking (`allow_ads`, `browser/net/url_context.cc:535-537` at `v1.98.60`; same on `1.99.x` and master). Cosmetic filtering (element hiding, scriptlets: `IsCosmeticFilteringEnabled`, `components/content_settings/renderer/brave_content_settings_agent_impl.cc:333-352`), the domain-block interstitial (`GetDomainBlockingType`, `brave_shields_utils.cc:395-431`) and Aggressive mode (`url_context.cc:540-542`) key off the unmanaged `BRAVE_COSMETIC_FILTERING`, which "Allow all trackers & ads" in the Shields panel (per site) or "Disabled" in `brave://settings/shields` (global) still sets to `ALLOW` (`SetAdBlockMode`, `components/brave_shields/core/browser/brave_shields_settings_service.cc:123-148` / `onAdControlChange_`, `default_brave_shields_page.ts:329-334`); the UI then reads back Standard (`GetAdBlockMode`, `brave_shields_settings_service.cc:150-168`). This key greys neither control. `BraveShieldsEnabledForUrls` greys the panel dropdown (`disabled={isManaged}`, `panel_new/components/advanced_settings.tsx:78-85`) but not the settings select, which only Ad Block Only Mode greys (`default_brave_shields_page.html:69-71`), so the global route stays open under it. At 1 the converse holds: network blocking and the domain block stop (`GetDomainBlockingType` needs `BRAVE_ADS` at `BLOCK`, `brave_shields_utils.cc:409-412`) while cosmetic filtering keeps its `BLOCK_THIRD_PARTY` default (`brave_shields_settings_values.h:123-126`) and the UI shows Disabled (brave-browser#59662, open, unmilestoned). **All five `DefaultBrave*`** lock the type's default and void per-site exceptions for it (Chromium `kManagedDefaultPrefs`, `components/content_settings/core/browser/content_settings_policy_provider.cc:274-276` at 156.0.8078.48), but every consumer checks Shields first, so a site with Shields off escapes them. **Trigger:** a fix for brave-browser#59662 that makes this handler also write a managed `BRAVE_COSMETIC_FILTERING` default; for 2 that locks cosmetic filtering too, and this row and the scripts' "Cosmetic filtering … is not locked" description change |
| DefaultBraveFingerprintingV2Setting | ✅ | cr141 | int enum | same | 1 = off, 3 = standard (no value 2: retired Strict, outside the schema enum `[1, 3]` (`BraveSoftware/DefaultBraveFingerprintingV2Setting.yaml:30-32`) and ignored by the handler, `browser/policy/handlers/brave_fingerprinting_v2_policy_handler.h:15-18`, `.cc:57-62`). Pins only the site-level `BRAVE_FINGERPRINTING_V2` mode, over the user's per-site mode and the remote list's `all-fingerprinting` (`components/webcompat/content/browser/webcompat_exceptions_service.cc:48`): `GetFingerprintingControlType` (`components/brave_shields/core/browser/brave_shields_utils.cc:591-608` at `v1.98.60`) takes the first matching rule (`GetBraveFPContentSettingFromRules`, `components/brave_shields/core/common/brave_shield_utils.cc:24-40`), and the policy provider ranks above the pref provider and Brave's `kRemoteListProvider`, which Brave's enum patch places after `kPrefProvider` (`patches/components-content_settings-core-common-content_settings_enums.mojom.patch`; `content_settings_enums.mojom:72,78` at 156.0.8078.48). Per-API `BRAVE_WEBCOMPAT_*` `ALLOW` rules are unmanaged and still switch farbling off for one API on one site (`brave_content_settings_agent_impl.cc:396-406`): Brave's remote list (`RemoteListProvider`) and the user's toggles in the Shields panel's fingerprinting details (`SetWebcompatEnabled`, not greyed by this key or by `BraveShieldsEnabledForUrls`: the details button's `isDisabled` has no managed check, `panel_new/components/advanced_settings.tsx:306-310`, and neither do the toggles, `fingerprinting_details.tsx:190-196`). Both need `kBraveWebcompatExceptionsService` (`brave_shield_utils.cc:47-49`), which is on by default (`components/webcompat/core/common/features.cc:15-16`; same on `1.99.x` and master); its two Griffin studies stop at `151.1.95.71` |
| DefaultBraveHttpsUpgradeSetting | ⚠️ unenforced where Griffin moves to upstream HTTPS-First (25% of Release) | cr142 | int enum | same | 1 = allow HTTP, 2 = strict, 3 = standard (`CONTENT_SETTING_ALLOW` / `BLOCK` / `ASK`, `browser/policy/handlers/brave_https_upgrade_policy_handler.cc:23-28`). Every enforcing reader (navigations, Brave News direct feeds) needs `kBraveHttpsByDefault` (`"HttpsByDefault"`, `FEATURE_ENABLED_BY_DEFAULT`, `chromium_src/net/base/features.cc:31-33`). With it on, 2 upgrades every navigation and turns a failed upgrade into an HTTP warning: `ShouldUpgradeToHttps` / `ShouldForceHttps` (`components/brave_shields/core/browser/brave_shields_utils.cc:683-719`) and `NormalWindowHttpsOnly` (`chromium_src/chrome/browser/ssl/https_upgrades_util.cc:18-27`, OR-ed into `kHttpsOnlyModeEnabled` by brave-core's patch and its `rewrite/chrome/browser/ssl/https_upgrades_util.cc.yaml:12-16` twin). On desktop the warning is Chromium's Ask-before-HTTP dialog over a blank page (`kHttpsFirstDialogUi`, `chrome/browser/ssl/https_upgrades_navigation_throttle.cc:139-145` at 156.0.8078.48, kept on outside Android by `rewrite/components/security_interstitials/core/features.cc.yaml:15-23`). 3 upgrades unless the host is on Brave's exceptions list and, in normal windows, falls back without the warning; 1 turns upgrading off; all three act only where Shields are up. **Griffin switches that path off:** brave-variations `TransitionToUpstreamHttpsUpgrade` (#1891, #1939, `165f9af46`; in the live seed) disables `HttpsByDefault` and enables `TransitionToUpstreamHttpsUpgrades` and `HttpsFirstBalancedMode` (both off in code: `components/brave_shields/core/common/features.cc:128-130`, `rewrite/chrome/common/chrome_features.cc.yaml:29-32`) for 100% of desktop Beta and Nightly and 25% of desktop Release (Windows/macOS/Linux, from `154.1.97.41`, permanent consistency). There the readers above bail and the key is read once per profile: `MigrateHttpsUpgradeSettings` (`browser/profiles/brave_profile_manager.cc:88-143`, run at profile load from `DoFinalInitForServices`, 227-238) copies the effective default, policy included, into upstream HTTPS-First as **user** prefs — 1 → off (no upgrading at all: Brave substitutes `HttpsByDefault` for upstream `kHttpsUpgrades`, `chromium_src/chrome/browser/ssl/https_upgrades_interceptor.cc:36-39`), 2 → strict (`kHttpsOnlyModeEnabled`), 3 → Balanced (`HttpsFirstModeService::UpdatePrefs`, `chrome/browser/ssl/https_first_mode_settings_tracker.cc:746-800` at 156.0.8078.48) — then sets `kHttpsUpgradeSettingsMigrated` and stops reading it while the profile stays on that arm (a load with `HttpsByDefault` on resets the flag, 104-105). Brave's Shields HTTPS controls are hidden (`panel_new/components/advanced_settings.tsx:141`, `default_brave_shields_page.html:80`) and the upstream setting shows in `brave://settings/security` (Brave hides it only while `HttpsByDefault` is on, `browser/resources/settings/br/security_page.ts:59`), so the user can lower it, and a policy first written after the migration changes nothing. The study sets no `policy_restriction`, so `ChromeVariations` 1 or 2 (Maximum Privacy carries 1) keeps Brave's path and this key enforced (`components/variations/study_filtering.cc:213-228` at 156.0.8078.48). A user who disables `brave://flags/#https-by-default` (`browser/about_flags.cc:1548-1555`) also leaves Brave's path (2 is then re-copied to upstream strict as a user pref at each start, `brave_profile_manager.cc:133-141`). Same on `v1.98.61`, `1.99.x` and master. **Trigger:** the Release share rising, or brave-core removing `kBraveHttpsByDefault` (brave-core#39916 calls `TransitionToUpstreamHttpsUpgrades` the transition code "before removing Brave's implementation"); then re-verify this row. Chromium's `HttpsOnlyMode` (`force_enabled`, `HttpsOnlyModePolicyHandler`, `chrome/browser/policy/configuration_policy_handler_list_factory.cc:3022-3024` at 156.0.8078.48) is the lock on the upstream path (see What's next) |
| DefaultBraveReferrersSetting | ✅ | cr142 | int enum | same | 1 = permissive, 2 = cap to strict origin; both exposed as mutually exclusive rows (issue #9); never put 1 in a preset. 2 is Brave's own default (`BRAVE_REFERRERS` registers `CONTENT_SETTING_BLOCK`, `chromium_src/components/content_settings/core/browser/content_settings_registry.cc:98-99`), so the key locks it and voids per-site `ALLOW` exceptions, including those Brave's webcompat list adds through `RemoteListProvider` (`"referrer"` → `BRAVE_REFERRERS`, `components/webcompat/content/browser/webcompat_exceptions_service.cc:59`), which ranks below the policy provider. The cap acts only on cross-origin requests from a page with Shields up: `MaybeChangeReferrer` rewrites the referrer to its origin under `strict-origin-when-cross-origin` (`components/brave_shields/content/browser/brave_shields_util.cc:38-64`), for navigations in `BraveContentBrowserClient::MaybeHideReferrer` (`browser/brave_content_browser_client.cc:1417-1447`) and for subresources in `browser/net/brave_site_hacks_network_delegate_helper.cc:41-47`. 1 lifts the cap everywhere, so a page's own `unsafe-url` policy sends the full URL cross-origin |
| DefaultBraveRemember1PStorageSetting | ✅ | cr142 | int enum | same | 1 = remember, 2 = forget when the site's last tab closes. Cleanup is skipped for any eTLD+1 where a visited host had Shields off or cookies on Allow (`EphemeralStorageTabHelper::UpdateShieldsState`, `browser/ephemeral_storage/ephemeral_storage_tab_helper.cc:231-243`). Inert whenever `kBraveShredFeature` is on: `FirstPartyStorageAreaNotInUse` honours this setting only while `GetAutoShredMode` is empty (`components/ephemeral_storage/ephemeral_storage_service.cc:385-389`; with Shred on, and `kBraveForgetFirstPartyStorage` on as it is by default, it returns the Auto Shred value, default `NEVER`: `browser/ephemeral_storage/brave_ephemeral_storage_service_delegate.cc:326-336`, `components/brave_shields/core/common/brave_shields_settings_values.h:128-131`), and the Auto Shred migration copies user rules, not the policy (`MigrateBraveRemember1PStorageToAutoShred` reads the user default pref and the pref provider's own rules, `components/content_settings/core/browser/brave_content_settings_pref_provider.cc:628-669`; no Auto Shred policy exists). Off by default on desktop at `v1.98.60` (`components/brave_shields/core/common/features.cc:70-75`), same on `1.99.x` and master, with no desktop Griffin study (`BraveShredFeatureStudy` targets iOS and Android only, capped at `151.*`), but `brave://flags/#brave-shred` (`browser/about_flags.cc:1647-1655`) lets a user turn it on and escape a forced 2. **Trigger:** `components/brave_shields/core/common/features.cc` or a Griffin study enabling it on desktop (brave-browser#49999, open, unmilestoned); then re-label the row ⚠️ |

Brave keys that exist and are **not exposed**:

| Key | Status | Why not |
|---|---|---|
| BraveSyncUrl | ✅ exists, unexposed | a custom sync-server URL (unguarded `brave_simple_policy_map.h:106-107` entry into `brave_sync.sync_service_url`, honoured only when managed and `https`, ahead of `--sync-url`: `chromium_src/components/sync/service/sync_service_impl.cc:23-32` at `v1.98.60`), not a debloat toggle; self-hosters write it by hand |
| PsstEnabled | ⚠️ feature off on Release/Beta | `chrome.*:147-` — **Brave 1.95**, branch-probed (YAML absent from `1.94.x` and `v1.94.122`, present in every 1.95 release; added by `13a8fd8cc`). At `v1.98.60`, same on `v1.98.61`, `1.99.x` and master: YAML (restart), a `brave_simple_policy_map.h:160-163` entry into `brave.psst.settings.enable_psst` (default `true`) under `ENABLE_PSST` (`enable_psst = !is_android && !is_ios && !is_brave_origin_branded`: Windows, macOS, Linux; compiled out of the Origin-branded build, whose 1.98.60 Linux binary carries the key name but not the pref, feature or flag), and for regular Brave with Origin purchased an Origin default of `false`, `user_settable=false` (`brave_origin_service_factory.cc:240-246`, same guard). Inert on Release and Beta: `kEnablePsst` is `FEATURE_DISABLED_BY_DEFAULT` (`components/psst/core/common/features.cc:10`) at `v1.98.60`, `v1.98.61`, `1.99.x` and master, and the only study enabling `EnablePsst`, brave-variations `EnablePsstStudy` (#1906, `d3513a7d6`, in the live seed), targets Nightly only: 100% on Windows/macOS/Linux from `154.1.98.30`. It sets no `policy_restriction`, so either `ChromeVariations` row (1 or 2) filters it out (`components/variations/study_filtering.cc:213-228` at 156.0.8078.48). `PsstTabWebContentsObserver::MaybeCreateForWebContents` and `RegisterPsstComponent` bail on the feature (`browser/psst/psst_tab_web_contents_observer.cc:123-126`, `components/psst/core/browser/psst_component_installer.cc:136-138`), so on Release and Beta nothing downloads or injects; `chrome://flags#enable-psst` turns it on locally. Where the feature is on (desktop Nightly, or the flag) the rules component is registered and installed at launch whatever the policy says (`psst_component_installer.cc:136-146`), and `false` stops only page processing (`IsPsstEnabled()` in `DidFinishNavigation`, `psst_tab_web_contents_observer.cc:217-220`). PSST downloads per-site scripts, injects them into logged-in origins to detect sign-in, then drives the account through settings URLs flipping switches. **Trigger:** `kEnablePsst` turning on for Release — `features.cc` flipping on a shipping branch, or a brave-variations study enabling `EnablePsst` on the Release channel (how `EmailAliases` went live, `83e246fcc`); `EnablePsstStudy` gaining Beta would be the next leading indicator, not the trigger. Then add a checkbox writing `false`, label Brave 1.95+ (branch-probed), restart note, no promise that `false` stops the rules download; the key joins `ORIGIN_BUILTIN_KEYS` |
| IPFSEnabled | ⛔ | `deprecated: true`; the feature (local node, `ipfs://` scheme) left Brave in 1.69.153 (Aug 2024), only a `DEPRECATE_IPFS` tombstone remains (`brave_simple_policy_map.h:152-155` at `v1.98.60`, into the migration-only `brave.ipfs.enabled`, which nothing reads). Decentralized DNS still rewrites ENS contenthash records to the public IPFS gateway `https://inbrowser.link` (`browser/net/decentralized_dns_network_delegate_helper.cc:119-124`, `components/ipfs/ipfs_utils.h:16`) without reading the key; `BraveWalletDisabled` stops that (`brave_wallet::IsAllowed`, same helper `:49-51`). **Do not re-add**; the YAML is the tiebreaker |

## Chromium-inherited keys

Dispatch for every row is `factory` unless the Notes say otherwise.

| Key | Status | Min | Type | Written | Notes |
|---|---|---|---|---|---|
| MetricsReportingEnabled | ✅ | cr8 | bool | false | restart; browser-wide. Chromium marks it `sensitive: true`, which makes `FilterSensitivePolicies` block it from a platform source on a Windows/Mac machine that is not domain-joined or MDM-managed (156.0.8078.48 `components/policy/core/common/async_policy_loader.cc:110-119`, applied at `policy_loader_win.cc:380-381` and `policy_loader_mac.mm:155-160`; Linux never filters); brave-core patches `sensitive: true` out of the YAML (one of its two policy-definition patches at `v1.98.60`, the other being DnsOverHttpsMode; its base blob `522bce22` is the 156.0.8078.48 file), which is the only reason an HKLM write works on a home PC. Brave sends no UMA/UKM — it registers no providers (`chromium_src/chrome/browser/metrics/chrome_metrics_service_client.cc:18-24`) and its `EnabledStateProvider::IsReportingEnabled()` always returns false (`chromium_src/components/metrics/enabled_state_provider.cc:13-15`) — so in practice the key governs crash-report upload to `cr.brave.com` (`chromium_src/components/crash/core/app/crash_reporter_client.cc:6-8`): upstream `ApplyMetricsReportingPolicy()` copies the pref into the crash-upload consent (`chrome/browser/metrics/metrics_reporting_state.cc:203-209`) at startup and on every change (`chrome/browser/browser_process_impl.cc:499-501,1684`), honoured because brave-core forces `GOOGLE_CHROME_BRANDING` in `chromium_src/components/metrics/metrics_service_accessor.cc:16-19` (unbranded, upstream returns false: `components/metrics/metrics_service_accessor.cc:41-47`); on Linux and macOS the crash handler reads that consent because `patches/chrome-app-chrome_crash_reporter_client.cc.patch` widens the branding test in `GetCollectStatsConsent` to `OFFICIAL_BUILD` (Windows: see Platform policy locations). Brave defaults the pref to false on Release and in Brave Origin but **true on Beta and Nightly** (`browser/metrics/metrics_reporting_util.cc:21-39`, registered at `browser/brave_local_state_prefs.cc:198-200`). The key locks the Settings toggle bound to the pref, "Help improve Brave's features and performance" (`browser/resources/settings/brave_data_collection_page/brave_data_collection_page.html:21-26`). Any managed value also suppresses Brave's post-crash "send crash reports?" dialog (`metrics_reporting_util.cc:41-60`, official desktop builds only). Same on `1.99.x` and master |
| SafeBrowsingProtectionLevel | ✅ | cr83 | int enum | 0 (no protection) | 0/1/2 valid; dedicated `SafeBrowsingPolicyHandler` (factory `:2672-2673`) into `safebrowsing.enabled` / `safebrowsing.enhanced`. Brave proxies Safe Browsing through its own hosts — `safebrowsing_api_endpoint = "safebrowsing.brave.com"` in `components/safebrowsing/BUILD.gn:10`, and `components/static_redirect_helper/static_redirect_helper.cc` (`v1.98.60` lines 85-105, reached for the Safe Browsing network context's requests through `browser/net/brave_system_request_handler.cc:33-49`) rewrites the host `safebrowsing.googleapis.com` → `safebrowsing.brave.com`, `sb-ssl.google.com` (download checks) → `sb-ssl.brave.com`, `safebrowsing.google.com` (the crx list) → `safebrowsing2.brave.com` — so with Safe Browsing on, Google receives the proxied lookups but never learns which client made them, not even its IP; the download ping also leaves without its URL, file name, resources and referrer chain (`chromium_src/chrome/browser/safe_browsing/download_protection/check_client_download_request_base.cc:13-18`). Upstream's hash-prefix real-time lookups, which go over an OHTTP relay (`ohttp-relay-safebrowsing-chrome.google.fastly-edge.com`, keys from `www.gstatic.com`) the rewrite does not cover, never run in Brave: `kHashPrefixRealTimeLookups` is on by default (156.0.8078.48 `components/safe_browsing/core/common/features.cc:360-372`) but `IsHashRealTimeLookupEligibleInSession()` also requires `HasGoogleChromeBranding()` (`components/safe_browsing/core/common/hashprefix_realtime/hash_realtime_utils.cc:25-31,107-110`), false in Brave, and the same check gates the OHTTP key fetch (`OhttpKeyService`'s `IsEnabled` goes through `DetermineHashRealTimeSelection`, `components/safe_browsing/core/browser/hashprefix_realtime/ohttp_key_service.cc:124-140`, `hash_realtime_utils.cc:146-148`). Value 2 behaves as 1: the `safe_browsing_prefs.cc` patch makes `IsEnhancedProtectionEnabled()` false before it reads the pref (`chromium_src/components/safe_browsing/core/common/safe_browsing_prefs.cc:8` at `v1.98.60`). Turning it off buys almost no privacy and costs the phishing/malware interstitials; in no preset. Same on `1.99.x` and master |
| UrlKeyedAnonymizedDataCollectionEnabled | ✅ | cr69 | bool | false | belt and braces — the pref defaults to false upstream (156.0.8078.48 `components/unified_consent/unified_consent_service.cc:198-199`) and brave-core compiles its Settings toggle out (`<if expr="_google_chrome">` around `urlCollectionToggle`, `patches/chrome-browser-resources-settings-privacy_page-personalization_options.html.patch:34-41` at `v1.98.60`, same on `1.99.x` and master); the key locks it off. Legacy half of a `SimpleDeprecatingPolicyHandler` (factory `:2680-2687`) whose successor `UrlKeyedMetricsAllowed` is still `future_on` only (156.0.8078.48 and main), so this key is the one that applies; it carries no `deprecated:` flag — see Considered and rejected |
| AutofillAddressEnabled | ⚠️ deprecated, still applied | cr69 | bool | false | `deprecated: true` at 156.0.8078.48 ("deprecated in M156, please use AutofillSettings", `34ae451dfc`; `AutofillAddressEnabled.yaml:2-4`) but uncapped (`chrome.*:69-`, `:30`) and still applied, same at 157.0.8103.21 and main: `AutofillSettingsPolicyHandler`, the only handler that maps it (factory `:2656-2657`), sets `autofill.profile_enabled` false (`components/autofill/core/browser/permissions/autofill_policy_handler.cc:101-105`), read with no feature gate by `ChromeAutofillClient::IsAutofillProfileEnabled` (`chrome/browser/ui/autofill/chrome_autofill_client.cc:1042-1045`), which brave-core leaves `final` (`patches/chrome-browser-ui-autofill-chrome_autofill_client.h.patch:21` at `v1.98.60`, same on `1.99.x` and master); brave-core's `BraveChromeAutofillClient` overrides only `IsAutofillEnabled`, calling upstream first and narrowing it for off-the-record profiles (`chromium_src/chrome/browser/ui/autofill/chrome_autofill_client.cc:100-111`). Deprecation is a label: handlers run on a deprecated policy like any other (`components/policy/core/browser/configuration_policy_handler_list.cc:83-97`), `brave://policy` shows its status as `Deprecated` instead of `OK` (`policy_conversions_client.cc:327-328`, `components/policy/resources/webui/policy_row.ts:177`; source-read), and Brave 1.98.60's `policy_templates.zip` files it under the ADMX category `DeprecatedPolicies` (`windows/admx/brave.admx:1676-1677`). Kept, with that caveat in the label, because the successor `AutofillSettings` is inert in Brave (`kAutofillEnableAutofillSettingsEnterprisePolicy` off; see Considered and rejected): writing it instead would leave address Autofill on |
| AutofillCreditCardEnabled | ⚠️ deprecated, still applied | cr63 | bool | false | `deprecated: true` at 156.0.8078.48 by the same change (`AutofillCreditCardEnabled.yaml:2-4`), uncapped (`chrome.*:63-`, `:30`), same at 157.0.8103.21 and main; the same handler sets `autofill.credit_card_enabled` false (`autofill_policy_handler.cc:107-111`), read with no feature gate by `ChromePaymentsAutofillClient::IsAutofillPaymentMethodsEnabled` (`chrome/browser/ui/autofill/payments/chrome_payments_autofill_client.cc:868-874`). Same `Deprecated` status in `brave://policy`, same `DeprecatedPolicies` ADMX category (`brave.admx:1686-1687`) and the same inert-successor reason to keep it as AutofillAddressEnabled |
| PasswordManagerEnabled | ✅ | cr8 | bool | false | pref `credentials_enable_service`; false stops offer-to-save and password generation (both gated by `IsSavingAndFillingEnabled()`, which reads the pref through `PasswordManagerSettingsServiceImpl::IsSettingEnabled(kOfferToSavePasswords)`; 156.0.8078.48 `chrome/browser/password_manager/chrome_password_manager_client.cc:302-317`, `components/password_manager/core/browser/password_manager_settings_service_impl.cc:19-21`, `components/password_manager/core/browser/password_generation_frame_helper.cc:127`), but passwords already saved still autofill — `IsFillingEnabled()` does not read the pref (YAML: "previously saved passwords will still work"). brave-core's override of that client only widens `IsFillingEnabled()`'s guest-session refusal to private and Tor windows unless autofill in private windows is on (`chromium_src/chrome/browser/password_manager/chrome_password_manager_client.cc:9-13` at `v1.98.60`, same on `1.99.x` and master) |
| BrowserSignin | ✅ | cr70 | int enum | 0 (disable) | restart; browser-wide. Off ChromeOS, `BrowserSigninPolicyHandler` maps 0 to `signin.allowed_on_next_startup` false (156.0.8078.48 `chrome/browser/policy/browser_signin_policy_handler.cc:64-75`; factory `:3167-3169`, under the `#else` of `BUILDFLAG(IS_CHROMEOS)`), which `AccountConsistencyModeManager` copies into `signin.allowed` at the next start (`chrome/browser/signin/account_consistency_mode_manager.cc:123-134`; brave-core's override of that file changes only Android, `chromium_src/chrome/browser/signin/account_consistency_mode_manager.cc:10-15` at `v1.98.60`). Brave has no Chrome account sign-in; that pref backs the `brave://settings/extensions` "Allow Google login for extensions" toggle (`browser/resources/settings/brave_default_extensions_page/brave_default_extensions_page.html:64-66`), which brave-core already defaults off (`chromium_src/chrome/browser/profiles/pref_service_builder_utils.cc:31-32`; all three same on `1.99.x` and master), so 0 locks it off. It does not touch Brave Account, Brave's own sign-in, which reads neither pref and is offered whenever `kBraveAccount` (off by default) or Email Aliases is on (`components/brave_account/features.cc:17-29`) — on Release desktop through the Griffin study `EmailAliasesStudy_Release` (100%), which `ChromeVariations` 1 or 2 filters out |
| WebRtcIPHandling | ✅ | cr91 | string enum | disable_non_proxied_udp | Brave keeps the upstream default `default` and exposes the same pref, `webrtc.ip_handling_policy`, as the "WebRTC IP handling policy" dropdown in `brave://settings/privacy` (`browser/resources/settings/brave_privacy_page/brave_personalization_options.html:53` at `v1.98.60`); the managed value outranks it. `disable_non_proxied_udp` turns off network-adapter enumeration, UDP, STUN and TURN over UDP (156.0.8078.48 `third_party/blink/renderer/modules/peerconnection/peer_connection_dependency_factory.cc:1098-1101`, `third_party/blink/renderer/platform/p2p/port_allocator.cc:36-45`), so ICE runs over TCP only — through the configured proxy if there is one (`services/network/p2p/socket_tcp.cc:115`), else the default route — and a call needs a TCP path (TURN over TCP/TLS or an ICE-TCP candidate). Tor windows already force this value and refuse `RTCPeerConnection` outright (`browser/tor/tor_profile_manager.cc:280-281`, `chromium_src/third_party/blink/renderer/modules/peerconnection/rtc_peer_connection.cc:36-43`); same on `1.99.x` and master |
| QuicAllowed | ✅ | cr43 | bool | false | restart; browser-wide. On launch the value comes straight from the policy service and is applied when the network service starts (156.0.8078.48 `chrome/browser/net/system_network_context_manager.cc:623-633,825-828`), but a managed false that arrives later applies live: `ProfileNetworkContextService` watches `net.quic_allowed` and `DisableQuicIfNotAllowed()` calls `SystemNetworkContextManager::DisableQuic()`, which turns QUIC off in the network service for every context, system and Safe Browsing included (`chrome/browser/net/profile_network_context_service.cc:524-527,681-692`, `system_network_context_manager.cc:941-948`; upstream `QuicAllowedPolicyDynamicTest`, `chrome/browser/policy/test/quic_allowed_browsertest.cc:440-468`). Lifting it needs a restart: re-enabling QUIC is not supported. It covers HTTP(S) loads (`HttpNetworkSession::DisableQuic`, `net/http/http_network_session.cc:385-387`), not WebTransport, which always asks for HTTP/3 (`services/network/web_transport.cc:64`) and opens its own QUIC connection over UDP without checking `IsQuicEnabled()` (`net/quic/dedicated_web_transport_http3_client.cc:636-674,738-770`, with upstream's "TODO(vasilvv): check if QUIC is disabled by policy." at `:653`; source-read, not runtime-tested); brave-core blocks WebTransport only to onion URLs (`browser/brave_content_browser_client.cc:1314-1336` at `v1.98.60`). WebRTC media is UDP either way. No brave-core override of QUIC (`chromium_src/services/network/network_service.h:11-14` uses `DisableQuic` only as a macro anchor) and no Griffin study; same on `1.99.x` and master |
| BlockThirdPartyCookies | ✅ | cr10 | bool | true | belt and braces — brave-core already defaults `profile.cookie_controls_mode` to block third-party (`browser/profiles/profile_util.cc:31-36`, called from `BraveProfileManager::InitProfileUserPrefs`, `browser/profiles/brave_profile_manager.cc:216` at `v1.98.60`); the key locks it through `CookieSettingsPolicyHandler` (factory `:2980-2981`; true → `kBlockThirdParty`, 156.0.8078.48 `components/content_settings/core/browser/cookie_settings_policy_handler.cc:25-33`), so the Shields global "allow all cookies" choice, which writes that pref (`components/brave_shields/core/browser/brave_shields_utils.cc:445-488` at `v1.98.60`), stops applying while per-site Shields exceptions still do: `BravePrefProvider` serves them as explicit `COOKIES` rules (`components/content_settings/core/browser/brave_content_settings_pref_provider.cc:877-880,1049-1060`), which the third-party block skips (`chromium_src/components/content_settings/core/common/cookie_settings_base.cc:266-271`). Ad Block Only Mode injects `false` at lower priority (see Cross-cutting) |
| ForceGoogleSafeSearch | ✅ | cr41 | bool | true | simple map → `settings.force_google_safesearch` (factory `:959-961`); `GoogleURLLoaderThrottle` adds `safe=active&ssui=on` to Google Search, Google home-page and SafeSearch-settings URLs (156.0.8078.48 `chrome/common/google_url_loader_throttle.cc:177-183`, `components/safe_search_api/safe_search_util.cc:82-86`; the browser hands it the pref in `chrome/browser/chrome_content_browser_client.cc:6081-6082`). brave-core does not override that path; its renderer override only adds throttles (`chromium_src/chrome/renderer/url_loader_throttle_provider_impl.cc` at `v1.98.60`) |
| IncognitoModeAvailability | ✅ | cr14 | int enum | 1 or 2 | 0 = enabled, 1 = disabled, 2 = forced, as two mutually exclusive rows; restart per YAML, but open windows pick a change up: upstream's `BrowserCommandController` watches the pref and updates New Window and New Incognito Window at once (156.0.8078.48 `chrome/browser/ui/browser_command_controller.cc:372-376,2058-2070`). In Brave `tor::IsIncognitoDisabledOrForced` reads the pref and treats 1 and 2 alike (`browser/tor/util.cc:17-34` at `v1.98.60`), so either row also removes Tor windows: `TorProfileServiceFactory::IsTorDisabled` returns true (`browser/tor/tor_profile_service_factory.cc:72-77`), which greys the Tor-window command (`browser/ui/brave_browser_command_controller.cc:477-484`) and makes `TorProfileManager::GetTorProfile` return null (`browser/tor/tor_profile_manager.cc:232-235`) |
| SyncDisabled | ✅ | cr8 | bool | true | governs Brave Sync: `syncer::SyncPolicyHandler` (factory `:2674`) sets `sync.managed`, and brave-core's factory builds `syncer::BraveSyncServiceImpl`, a `SyncServiceImpl` subclass (`chromium_src/chrome/browser/sync/sync_service_factory.cc:11-18` at `v1.98.60`) that does not override `GetDisableReasons()`, so `sync.managed` gives `DISABLE_REASON_ENTERPRISE_POLICY` (156.0.8078.48 `components/sync/service/sync_service_impl.cc:834-836`) and `brave://settings/braveSync` shows it disabled by the administrator (`browser/resources/settings/brave_sync_page/brave_sync_subpage.html:32-35`, from upstream's `syncStatus.managed`). Side effect: the resulting `StopAndClear(kEnterprisePolicy)` (`sync_service_impl.cc:353-354` at startup, `:1962-1963` on a live change) runs Brave's override, which clears the sync code (`kSyncV2Seed`; `components/sync/service/brave_sync_service_impl.cc:207-227`, `components/brave_sync/brave_sync_prefs.cc:198-201` at `v1.98.60`; same on `1.99.x` and master), so the device leaves its sync chain and must rejoin with the chain's sync code once the policy is removed |
| BackgroundModeEnabled | ⚠️ Win/Linux only | cr19 | bool | false | **Windows and Linux only** (`chrome.win:19-`, `chrome.linux:19-`); no macOS support in Chromium: the factory entry sits under a Windows/Linux buildflag guard (156.0.8078.48 `:2008-2012`), although the background-mode code also builds on macOS (`chrome/common/features.gni:47`); browser-wide (pref `background_mode.enabled` in local state). The pref defaults true (`chrome/browser/background/extensions/background_mode_manager.cc:351`), but background mode starts only while an installed extension or app holds the `background` permission (`:172-174`, `:825-828`); no brave-core override. `slimbrave-mac.py` also runs on Linux, so it builds the row only under `sys.platform.startswith("linux")`, at index 0 of Performance & Bloat; on macOS a config or preset naming the key (Performance Focused, Maximum Privacy, Balanced Privacy, Developer) has it silently ignored — `import_settings` walks only built rows and names only keys whose value is off-enum |
| ShoppingListEnabled | ⚠️ no-op in Brave | cr107 | bool | false | dispatched (pref `shopping_list_enabled`, factory `:2350-2352`), but its only functional reader, `commerce::IsShoppingListEligible` (156.0.8078.48 `components/commerce/core/feature_utils.cc:19-41`), fails its first gate: brave-core re-declares `kShoppingList` (off upstream too, `components/commerce/core/commerce_feature_list.cc:214`) `BASE_OVERRIDDEN_FEATURE` (`rewrite/components/commerce/core/commerce_feature_list.cc.yaml:27-30` at `v1.98.60`, listed in `base/compile_overridden_features.inc:164`), so the patched `FeatureList::IsFeatureOverridden` (`patches/base-feature_list.cc.patch:8-11`) makes `IsRegionLockedFeatureEnabled` return the off flag (`commerce_feature_list.cc:306-308`) without reaching the `us`/`en-us` launch map (`:59`). Forced on by flag, it still needs a `ConsentLevel::kSync` IdentityManager primary account (`components/commerce/core/account_checker.cc:72-83`; brave-core forces `IsReplaceSyncPromosWithSignInPromosEnabled()` false, `rewrite/components/sync/base/features.cc.yaml:18-31`, so the `kSignin` branch never applies), which Brave never creates (Brave Sync's account lives in `BraveSyncAuthManager`). Defensive lock only; same on `1.99.x` and master |
| AlwaysOpenPdfExternally | ✅ | cr55 | bool | true | pref `plugins.always_open_pdf_externally` (factory `:2111-2113`, desktop only); true turns the PDF viewer plugin off (156.0.8078.48 `chrome/browser/plugins/plugin_prefs.cc:52-54`) and bars every extension from the PDF MIME types (`chrome/browser/plugins/plugin_utils.cc:47-50`), so a PDF downloads; opening the finished download hands it to the OS handler (`chrome/browser/download/download_item_model.cc:1194-1207`, `chrome/browser/download/chrome_download_manager_delegate.cc:1422-1425`). Nothing opens it automatically unless the user picks always-open for PDFs in the download menu (`download.open_pdf_in_system_reader`, `download_item_model.cc:777-786`, `chrome/browser/download/download_prefs.cc:492-502`). No brave-core override |
| TranslateEnabled | ✅ | cr12 | bool | false | Brave translates through its own `translate.brave.com`, not Google: `kUseBraveTranslateGo` is on by default (`components/translate/core/common/brave_translate_features.cc:13-14` at `v1.98.60`) and the `chromium_src` overrides of `translate_script.cc` and `translate_util.cc` point the script and requests there (`chromium_src/components/translate/core/browser/translate_script.cc:31-43`, `chromium_src/components/translate/core/common/translate_util.cc:19-29`); Google is reached only under the test switch `--use-google-translate-endpoint` (`components/translate/core/common/brave_translate_switches.h:12-15`). Auto-translate is off behind `kBraveEnableAutoTranslate` (`brave_translate_features.cc:19-20`); neither Griffin translate study reaches 156 (`BraveTranslateStudy` ends at 106, `BraveAutoTranslateStudy` at 152). A managed false also refuses manual translation (`TranslatePrefs::IsTranslateAllowedByPolicy`, 156.0.8078.48 `components/translate/core/browser/translate_prefs.cc:193-200`, checked in `TranslateManager::CanManuallyTranslate`, `translate_manager.cc:266`). The key removes the feature, not a Google data flow |
| SpellcheckEnabled | ✅ | cr65 | bool | false | desktop only; mutually exclusive with SpellCheckServiceEnabled |
| SearchSuggestEnabled | ✅ | cr8 | bool | false | Brave registers the default false (`browser/brave_profile_prefs.cc:249-251` at `v1.98.60`) but flips it to true for every regular profile when the desktop first run found an OS-locale region of AR, AT, BR, CA, DE, ES, FR, GB, IN, IT, MX or US; a locale with no region counts as US (`browser/search_engines/search_engine_provider_util.cc:35-38,140-164`, called from `browser/brave_browser_process_impl.cc:215-216` and `browser/search_engines/normal_window_search_engine_provider_service.cc:29-30`; `components/l10n/common/locale_util.cc:40-51`). On those installs the key is what turns suggestions off, and it locks the toggle |
| PrintingEnabled | ✅ | cr8 | bool | false | |
| DefaultBrowserSettingEnabled | ✅ | cr11 | bool | false | desktop only; browser-wide. Any managed value stops the startup default-browser prompt (`chrome/browser/ui/startup/default_browser_prompt/default_browser_prompt.cc:85-90` at 156.0.8078.48; Brave adds no prompt of its own). From source, and reported at runtime on 1.97.59 for Linux by brave-browser#60038 (open, unmilestoned; a fresh profile still shows the prompt and every click aborts the browser): Brave's first-run `brave://welcome` (`browser/ui/startup/brave_startup_tab_provider_impl.cc:24-25` at `v1.98.60`) offers *Set as default* without reading `isDisabledByPolicy` (`components/brave_welcome_ui/components/welcome/index.tsx:37-38,95`); with this key false the click reaches Chromium's stock `DefaultBrowserHandler::SetAsDefaultBrowser` (registered unmodified by `browser/ui/webui/welcome_page/brave_welcome_ui.cc:130-131`), whose opening `CHECK(!DefaultBrowserIsDisabledByPolicy())` (`chrome/browser/ui/webui/settings/settings_default_browser_handler.cc:126` at 156.0.8078.48) crashes the browser — click *Skip*. `brave://welcome-new`, which first run does not open, has the same gap (`browser/resources/brave_welcome_page/components/welcome_step.tsx:27`; *Maybe later* there); same on `1.99.x` and master |
| DeveloperToolsAvailability | ✅ | cr68 | int enum | 2 (disallowed) | 2 = `DeveloperToolsDisallowed`. Does **not** stop the CDP port or pipe opening — see RemoteDebuggingAllowed: 2 refuses CDP attach to profile targets (pages, frames, workers, extensions, and `chrome.debugger`; `AllowInspectingTarget` → `IsInspectionAllowed`, `chrome/browser/devtools/chrome_devtools_manager_delegate.cc:412-421` at 156.0.8078.48), but the browser target has no profile and passes, and its `Storage.getCookies` still returns every cookie of the last-used profile (`content/browser/devtools/protocol/storage_handler.cc:435-448`, context from `chrome/browser/devtools/devtools_browser_context_manager.cc:103-107`). The YAML documents the split — this key limits which targets can be inspected, `RemoteDebuggingAllowed` whether debugging starts (`89ae2af617`, since cr155) — but not the browser-target pass. Applies live: a change force-detaches open sessions on profile targets (`chrome/browser/devtools/chrome_devtools_session_base.cc:60-68`), never the browser-target one. Also forces `extensions.ui.developer_mode` false unless `ExtensionDeveloperModeSettings` is set (never written here), locking Developer mode off on `brave://extensions` and refusing *Load unpacked* (`chrome/browser/policy/developer_tools_policy_handler.cc:283-288`; `chrome/browser/extensions/api/developer_private/developer_private_functions.cc:902-904`). No brave-core override; same on `1.99.x` and master |
| DnsOverHttpsMode | ✅ | cr78 | string enum | off / automatic / secure | browser-wide. `SecureDnsPolicyHandler` (factory `:2992`) maps it to the `dns_over_https.mode` local-state pref. Stock Chromium forces DoH **off** whenever this key is unmanaged on a machine that is domain-joined (Windows) or carries *any* machine-level policy (`StubResolverConfigReader::ShouldDisableDohForManaged`, `chrome/browser/net/stub_resolver_config_reader.cc:245-271`, applied at `:349-351`, 156.0.8078.48) — which every SlimBrave machine satisfies the moment it writes its first key. brave-core `chromium_src/chrome/browser/net/stub_resolver_config_reader.cc:166-168` overrides that to false, so **Not managed** keeps Brave's own automatic DoH (the pref default, `chrome/browser/net/default_dns_over_https_config_source.cc:30-32`); the companion YAML patch drops `default_for_enterprise_users: 'off'` (it only feeds `SetEnterpriseUsersDefaults`, generated under `BUILDFLAG(IS_CHROMEOS)`) and the matching "If this policy is unset, for managed devices…" desc paragraph — metadata. On Windows with Brave VPN connected over IKEv2 and its DNS helper service not live, Brave forces secure DoH to `chrome.cloudflare-dns.com` unless this key is managed or the mode is already `secure` (`ShouldOverride`, that `chromium_src` file `:32-47` at `v1.98.60`, behind `kBraveVPNDnsProtection`, on by default); managed and not `secure`, it shows a policy-warning dialog instead, which a "don't show again" checkbox silences (`browser/brave_vpn/dns/brave_vpn_dns_observer_service_win.cc:175-198`). WireGuard, switched on once the VPN system services install (`kBraveVPNUseWireguardService` on by default), skips this path (`:203-205`); Brave Origin has no VPN |
| DnsOverHttpsTemplates | ✅ | cr80 | string | URL template | browser-wide. **required** for `secure` and `custom`, optional for `automatic` (unset = Chromium's upgrade of the system resolver; brave-core's `kBraveFallbackDoHProvider` hook (`chromium_src/net/dns/dns_client.cc:50-51` at `v1.98.60`) appends the endpoint its `BraveFallbackDoHProviderEndpoint` param names there — default `none`, `https://brave.cloudflare-dns.com/dns-query` under the Griffin study `BraveFallbackDoHStudy`; the feature is `FEATURE_DISABLED_BY_DEFAULT` (`chromium_src/net/base/features.cc:37-50`), so off on Release, but on for 100% of Beta and Nightly via that study, which `ChromeVariations` 1 or 2 filters out), ignored for `off`. `secure` with an empty or unparseable template destroys name resolution — an empty one blanks the templates pref; a non-https one is stored with only a policy error, then dropped by `DnsOverHttpsConfig::FromStringLax`; either way `CanUseSecureDnsTransactions()` is false, and the system-resolver fallback is gated on `secure_dns_mode != kSecure` (crbug.com/1326526; 156.0.8078.48 `chrome/browser/net/secure_dns_policy_handler.cc:91-107`, `:207-211`, `net/dns/host_resolver_manager.cc:1366-1370`, `:1476-1479`). All three scripts refuse an empty template for `custom`/`secure`; only `SlimBrave.ps1` also refuses a non-https or unparseable one (`Test-DohTemplate`), and the Python scripts also write a template with `automatic` (see What the project does) |
| PasswordLeakDetectionEnabled | ✅ | cr79 | bool | false | belt and braces: Brave defaults `profile.password_manager_leak_detection` to false (`browser/brave_profile_prefs.cc:268-271` at `v1.98.60`) and hides the settings switch (`browser/resources/settings/br/security_page.ts:50-58`, upstream's `passwordsLeakToggle` at 156.0.8078.48 `chrome/browser/resources/settings/privacy_page/security/security_page.html:244`). Brave's override modifies only `settings-security-page` (`br/security_page.ts:9-10`), so the copy on upstream's bundled page (`settings-security-page-v2`, `privacy_page/security/security_page_v2.html:522`) is not hidden. That page shows only under `kBundledSecuritySettings` (`privacy_page/privacy_page_index.html:71-77`), which is `FEATURE_DISABLED_BY_DEFAULT` at 156.0.8078.48 and on main (`components/safe_browsing/core/common/features.cc:62`), with no brave-core override and no Griffin study. If it turns on, the switch reappears, locked when the key is set (`chrome/browser/password_manager/generated_password_leak_detection_pref.cc:99-102`). The key locks off the online breach-list check Chromium runs on credentials after a successful sign-in (`PasswordManager::OnLoginSuccessful`, `components/password_manager/core/browser/password_manager.cc:1713-1718`) and on saved logins edited in the Password Manager (`components/password_manager/core/browser/ui/bulk_leak_check_service_adapter.cc:84-95`), both through `LeakDetectionCheck::CanStartLeakCheck` (`leak_detection/leak_detection_check_impl.cc:225-237`). The edit check is a bulk check that needs a signed-in Google account (`leak_detection/leak_detection_check_factory_impl.cc:58-61`), which Brave's default of sign-in off (`chromium_src/chrome/browser/profiles/pref_service_builder_utils.cc:31-32`) rules out |
| NetworkPredictionOptions | ✅ | cr38 | int enum | 2 (never predict) | 0 = always, 2 = never (1 deprecated, read as 0: 156.0.8078.48 `chrome/browser/preloading/preloading_prefs.cc:23-39`). Belt and braces: Brave defaults `net.network_prediction_options` to 2 (`browser/brave_profile_prefs.cc:253-257` at `v1.98.60`) and clears any user value on every profile load (`chromium_src/chrome/browser/prefs/browser_prefs.cc:154`, run after the upstream body of `MigrateObsoleteProfilePrefs`). So an unmanaged Brave keeps prediction off unless Brave Sync restores a value (the pref is a `SYNCABLE_PREF`), and only a policy value of 0 (or the deprecated 1) turns it on reliably. Whatever the value, Brave never runs the loading predictor: `rewrite/chrome/browser/predictors/loading_predictor_config.cc.yaml` makes `IsLoadingPredictorEnabled()` return false, so `LoadingPredictorFactory` builds nothing (`chrome/browser/predictors/loading_predictor_factory.cc:49-50`). That rules out learned preconnects, pages' `dns-prefetch`/`preconnect` hints (there is no `PreconnectManager`: `chrome/browser/predictors/network_hints_handler_impl.cc:51-52,75-76,109-112`) and pointer-down link preconnects (`chrome/browser/navigation_predictor/anchor_element_preloader.cc:90-96`). Brave never prerenders either. brave-core ships Blink's `Prerender2` base feature disabled (`rewrite/third_party/blink/renderer/platform/runtime_enabled_features.json5.yaml:133-136`), so `PrerenderHostRegistry::CreateAndStartHost` rejects every prerender (`content/browser/preloading/prerender/prerender_host_registry.cc:587-592`), and it replaces the browser-triggered `PrerenderManager` with a stub (`chromium_src/chrome/browser/preloading/prerender/prerender_manager.h:14-15`). What the pref still gates in Brave: speculation-rules prefetch (`content/browser/preloading/prefetch/prefetch_service.cc:834-840`; Brave answers `HTMLScriptElement.supports('speculationrules')` false, `chromium_src/third_party/blink/renderer/core/html/html_script_element.cc:22-24`, but the script loader still parses the rules, `third_party/blink/renderer/core/script/script_loader.cc:474-475`), `<link rel=prerender>` NoStatePrefetch (`chrome/browser/preloading/prefetch/no_state_prefetch/chrome_no_state_prefetch_manager_delegate.cc:58-62`), the address bar's search-result prefetch (`chrome/browser/preloading/prefetch/search_prefetch/search_prefetch_service.cc:330-332`) and the default-search-engine preconnector (`chrome/browser/navigation_predictor/search_engine_preconnector.cc:319-340`; `kPreconnectFromKeyedService` and `kPreconnectToSearch` are on by default, `:93-94`). The preconnector also needs search suggestions on: Brave registers them off (`browser/brave_profile_prefs.cc:249-251`) but turns them on at first run in 12 OS-locale regions, including the US (see SearchSuggestEnabled). A page's `<link rel=prefetch>` never checks the pref (`third_party/blink/renderer/core/loader/preload_helper.cc:796`). brave-core does not override these readers, and no Griffin study applies. The key adds the in-session lock and outranks Sync |
| PaymentMethodQueryEnabled | ✅ | cr80 | bool | false | with the pref off Chromium stops consulting payment apps: `canMakePayment()` always resolves **true** (a deliberate lie, so a site must call `show()`) and `hasEnrolledInstrument()` false, so neither reveals saved methods, and installed service-worker payment apps are not sent the `canmakepayment` event; Secure Payment Confirmation exempt (156.0.8078.48 `components/payments/content/payment_request.cc:717-733,754-767`, `components/payments/content/service_worker_payment_app.cc:136-142`). The YAML's "no payment methods are available" does not match the code for `canMakePayment()` |
| AlternateErrorPagesEnabled | ⚠️ inert in Brave | cr8 | bool | false | no live reader in Brave. Upstream the pref gates only `NetErrorTabHelper`'s DNS-error probe to 8.8.8.8/8.8.4.4 (156.0.8078.48 `chrome/browser/net/net_error_tab_helper.cc:270-276`, `chrome/browser/net/dns_probe_service_factory.cc:47-48`) and `CaptivePortalService::UpdateEnabledState` (`components/captive_portal/content/captive_portal_service.cc:238-242`); brave-core never attaches `NetErrorTabHelper` (`chromium_src/chrome/browser/ui/tab_helpers.cc:26` at `v1.98.60`, `#define NetErrorTabHelper NoTabHelper`, against upstream's `chrome/browser/ui/tab_helpers.cc:310`) and patches the pref out of the captive-portal check (`rewrite/components/captive_portal/content/captive_portal_service.cc.yaml` → `patches/components-captive_portal-content-captive_portal_service.cc.patch`), so captive-portal detection runs whatever the value. No web-service error page exists at 156.0.8078.48 and no settings page binds the pref; Brave defaults it to false (`browser/brave_profile_prefs.cc:225-227`). Locking it only pins `chrome.privacy.services.alternateErrorPagesEnabled` for extensions (`chrome/browser/extensions/pref_mapping.cc:43-45`); kept as belt and braces |
| DefaultNotificationsSetting | ✅ | cr10 | int enum | 1, 2 or 3, user-selected; key omitted when Not managed | full legal enum **1 = allow, 2 = block, 3 = ask**, all exposed as a choice row |
| DefaultGeolocationSetting | ✅ | cr10 | int enum | 1, 2 or 3; omitted when Not managed | full legal enum 1 = allow, 2 = block, 3 = ask; choice row |
| DefaultSensorsSetting | ✅ | cr88 | int enum | 1, 2 or 3; omitted when Not managed | motion/orientation sensors, a fingerprinting vector; full legal enum 1 = allow, 2 = block, 3 = ask. "3 = ask" holds in Brave only because brave-core force-enables `features::kSensorsAllowAskBlockPermissionModel` (`rewrite/services/device/public/cpp/device_features.cc.yaml:18-21` → `patches/services-device-public-cpp-device_features.cc.patch:9-12` at `v1.98.60`, same on `1.99.x` and master; no Griffin study names it) — the dedicated `DefaultSensorsSettingPolicyHandler` (in M152 since `8a50daa`; 156.0.8078.48 factory `:2649`) rewrites 3 to **Allow** when that flag is off (`chrome/browser/policy/default_sensors_setting_policy_handler.cc:30-41`). Chromium's code default is off (`services/device/public/cpp/device_features.cc:21-22`, also on main). Its field-trial testing config turns it on (`testing/variations/fieldtrial_testing_config.json:16821-16839`, which the `pref_mapping` test for 3 assumes), but that config is applied by default only in non-Chrome-branded builds; a Chrome-branded build applies it only with `--enable-field-trial-config` (`components/variations/service/variations_field_trial_creator.cc:143-155`). Brave compiles it out with `disable_fieldtrial_testing_config = true` (`build/args/brave_defaults.gni:11`, imported by `build/commands/lib/buildArgs.ts:40`, same on `1.99.x` and master; `components/variations/service/BUILD.gn:25-27`), so the plaster alone enables it. Brave also re-registers SENSORS with default **Block** (brave/brave-browser#4789, `chromium_src/components/content_settings/core/browser/content_settings_registry.cc:286-298`), so Not managed in Brave is block-by-default-but-user-changeable. A policy file with 3 taken to a Chromium-based browser where the flag is off (its code default, with no testing config or field trial enabling it) means Allow |
| ExtensionInstallBlocklist | ✅ | cr86 | list | `["*"]` | blocks all installs and disables (does not uninstall) already-installed extensions, themes and apps included; component extensions (Brave's and Chromium's built-ins) and shared modules are exempt (`StandardManagementPolicyProvider::UserMayLoad`, `chrome/browser/extensions/standard_management_policy_provider.cc:111-119` at 156.0.8078.48). `ExtensionInstallBlockListPolicyHandler` (factory `:3504-3505`) writes `extensions.install.denylist`; `*` makes the default installation mode `kBlocked` (`chrome/browser/extensions/extension_management.cc:746-749`), and only `kRemoved` force-uninstalls (`standard_management_policy_provider.cc:315-325`) |
| BrowserGuestModeEnabled | ✅ | cr38 | bool | false | guest windows are an off-the-record session with no saved history and none of the main profile's extensions, which `IncognitoModeAvailability` = 1 does not close (`IncognitoModePrefs::CanOpenBrowser` blocks only incognito-typed and enterprise-isolated profiles, `chrome/browser/prefs/incognito_mode_prefs.cc:95-97` at 156.0.8078.48, and a guest profile is typed `kGuest`, `chrome/browser/profiles/profile.cc:422-425,436-439`); machine policies still apply inside them (`ProfilePolicyConnector::Init` appends the platform provider for every profile, `chrome/browser/policy/profile_policy_connector.cc:521-525`). Dedicated `GuestModePolicyHandler` (factory `:3044-3045`), Win/Mac/Linux only, sets local-state `profile.browser_guest_enabled`, which `profiles::IsGuestModeEnabled` reads (`chrome/browser/profiles/profiles_state.cc:222-231`); Brave's menu honours it (`browser/ui/brave_browser_command_controller.cc:355-365` at `v1.98.60`); browser-wide |
| HighEfficiencyModeEnabled | ✅ | cr108 | bool | true | forces Memory Saver tab discarding on; browser-wide, applied live. `MemorySaverPolicyHandler` (factory `:2767-2768`, Windows/macOS/Linux/ChromeOS) sets local-state `performance_tuning.high_efficiency_mode.state` to `kEnabled` (156.0.8078.48 `chrome/browser/performance_manager/user_tuning/memory_saver_policy_handler.cc:32-36`), which `UserPerformanceTuningManager` observes and hands to `MemorySaverModePolicy` with no feature gate (`chrome/browser/performance_manager/user_tuning/user_performance_tuning_manager.cc:238-242,263-280`; the policy is on every desktop graph, `chrome/browser/performance_manager/chrome_browser_main_extra_parts_performance_manager.cc:237-238`); brave-core's override of that file stubs only metrics (`PageResourceMonitor`, `MetricsProviderDesktop`), and no Griffin study touches Memory Saver |
| HardwareAccelerationModeEnabled | ✅ | cr46 | bool | true / false | both states as a mutually exclusive pair (`Group = "hwaccel"`) because unset is not off: Chromium's default is on, absent means user-controlled, `false` means forced off. Factory `:2087-2089` (Windows/macOS/Linux) → local-state `hardware_acceleration_mode.enabled`, read once at startup by `GpuModeManager`, which calls `DisableHardwareAcceleration()` when it is false (156.0.8078.48 `chrome/browser/gpu/gpu_mode_manager.cc:47-52,63-67`); `true` only stops the user turning acceleration off — the GPU blocklist still applies (YAML: "if available"). No brave-core override. The off state is a troubleshooting lever for a faulty GPU driver, a VM or RDP session, or screen-sharing corruption, not a privacy posture — in no preset. Restart; browser-wide |
| EnableMediaRouter | ✅ | cr52 | bool | false | disables Cast and its LAN device discovery; restart. Brave's `media_router_feature.cc` gives the policy precedence over the `brave://settings/extensions` Media Router toggle (`chromium_src/chrome/browser/media/router/media_router_feature.cc:35-37` at `v1.98.60`); Tor windows are always off (`:19-22`). Sticky: a profile whose toggle pref is still at its default when Brave starts under the policy (in practice, one created under it) gets the managed `false` copied into `brave.enable_media_router_on_restart` (`browser/profiles/brave_profile_manager.cc:199-209` at `v1.98.60`, same on `1.99.x` and master), so once the policy is removed Cast stays off until that toggle is turned back on and Brave restarted; older profiles return to their own setting |
| ChromeVariations | ✅ | cr83 | int enum | 1 or 2 | 0 = all variations, 1 = critical fixes only, 2 = none; browser-wide. Closes the last remote-configuration channel: Brave fetches a Griffin seed from `variations.brave.com` (`components/variations/buildflags.gni:7` at `v1.98.60`) that flips features in an installed browser. Maps to `variations::prefs::kVariationsRestrictionsByPolicy` (factory `:1160-1162`); brave-core does not override the restriction path (nor on `1.99.x` or master). Studies are applied once per run, at startup: `GetVariationPolicyRestriction` reads the pref into the client state that `CreateTrialsFromSeed` uses, and that CHECKs it runs once (156.0.8078.48 `components/variations/service/variations_field_trial_creator.cc:89-98,354,456,717-720`); mid-session the pref is read again only to simulate a newly fetched seed for the kill-switch restart badge (`components/variations/service/variations_service.cc:871-873,1281-1294`) and on the runtime-mutable path, which the off-by-default `kVariationsRuntimeMutability` keeps shut (`:350,880`; no brave-core override, and no Brave study enables it or is `runtime_mutable`). So despite `dynamic_refresh: true` a change takes effect at the next start. The seed is still downloaded: `IsFetchingEnabled()` checks only the `--variations-server-url` switch (`variations_service.cc:275-291`) that Brave appends at startup (`components/variations/command_line_utils.cc:29,46-47`, `app/brave_main_delegate.cc:133` at `v1.98.60`), and no fetch path reads the pref. 2 refuses every study, filterless ones included (`components/variations/study_filtering.cc:226-227,363-370`); 1 admits only studies whose filter sets a non-`NONE` `policy_restriction` (`CheckStudyPolicyRestriction`, `:222-223`), and Brave almost never tags one: in brave-variations `165f9af46` (the live seed; its `version` field is `main@165f9af46…`, 174 studies) only `V8IgnitionElideRedundantTdzChecksKillSwitch` (`CRITICAL`, both copies capped at `139.*`) carries it and none of the other kill-switch or `Disable*` studies does, so on 1.98.60 (and on 1.99.x and master, also on 156) values 1 and 2 both apply zero studies. Two mutually exclusive rows; 2 is in no preset only because it would also refuse a kill switch Brave tags critical later |
| SpellCheckServiceEnabled | ✅ | cr22 | bool | false | belt and braces — already off in Brave with no UI to turn it on: Chromium registers `spellcheck.use_spelling_service` false (`chrome/browser/spellchecker/spellcheck_factory.cc:68-69` at 156.0.8078.48), Brave re-asserts it (`chromium_src/chrome/browser/profiles/pref_service_builder_utils.cc:27-29` at `v1.98.60`), both settings controls are `_google_chrome`-only (`chrome/browser/resources/settings/languages_page/spell_check_page.html.ts:23-43`, `chrome/browser/resources/settings/privacy_page/personalization_options.html:97-120`, a block brave-core's patch of that file leaves alone), and Brave stubs out the context-menu opt-in (`chromium_src/chrome/browser/renderer_context_menu/render_view_context_menu.cc:718-731`). The key locks the Google spelling web service off, even against a stored `true`, while offline dictionaries keep working; upstream says it has no effect once `SpellcheckEnabled` is false (`Miscellaneous/SpellCheckServiceEnabled.yaml:8`), hence the mutual exclusion. Same on `1.99.x` and master (the context-menu stub sits at `:700-713` there) |
| RemoteDebuggingAllowed | ✅ | cr93 | bool | false | blocks `--remote-debugging-port` / `--remote-debugging-pipe`, the CDP cookie-theft vector `DeveloperToolsAvailability` leaves open, and the approval-mode listener the `brave://inspect` remote-debugging toggle starts (`kDevToolsAcceptDebuggingConnections`, on by default on desktop, `chrome/browser/devtools/features.cc:208-209` at 156.0.8078.48, untouched by brave-core and Griffin): `RemoteDebuggingServer::GetInstance` returns `kDisabledByPolicy` before any of them starts (`chrome/browser/devtools/remote_debugging_server.cc:337-340`); inherited unchanged by Brave. Google Chrome also refuses both switches on the default user-data-dir, but only under `GOOGLE_CHROME_BRANDING` (`remote_debugging_server.cc:169-180`); Brave never sets `is_chrome_branded` (its branding is `branding_path_component = "brave"`, `build/args/branding_defaults.gni:6` at `v1.98.60`), so the port opens on the real profile and this key is the only lock. Breaks Puppeteer, Playwright and that toggle; local-tab inspection (`DeveloperToolsAvailability`) and device discovery in `brave://inspect` keep working — the page reads the pref only to grey out and no-op the toggle (`chrome/browser/ui/webui/inspect/inspect_ui.cc:694-697,892-894`). Browser-wide; no restart: `dynamic_refresh: true` since 154.0.8029.0 (`80ad0b9`); set false at runtime, `BrowserProcessImpl::OnDevToolsRemoteDebuggingAllowedChanged` stops the server and pipe and clears the toggle (`chrome/browser/browser_process_impl.cc:1107-1124`). Lifting it starts nothing: the toggle must be turned back on and the switches need a relaunch, as does everything if the policy was in force at launch (`GetInstance` returned `kDisabledByPolicy`). Same on `1.99.x` and master |
| DNSInterceptionChecksEnabled | ⚠️ inert | cr80 | bool | false | no effect by default: the probes it stops never run. `IntranetRedirectDetector`, created at startup (156.0.8078.48 `chrome/browser/chrome_browser_main.cc:2038`), would fetch three random 7–15 character hostnames 7 s after launch and after every network or DNS-config change (`chrome/browser/intranet_redirect_detector.cc:52,150-155,235-244`), but `IsEnabledByPolicy()` (`:264-285`) first requires `IntranetRedirectBehavior` set to 3, a policy-only pref with no settings UI (factory `:526-527`): unset, `GetInterceptionChecksBehavior` returns `DISABLE_FEATURE` (`components/omnibox/browser/intranet_redirector_state.cc:41-42`; `intranet_redirector_state.h:14-16` marks it the default for M97 and above), so `Restart` and `FinishSleep` return before any lookup (`intranet_redirect_detector.cc:82-88,107-113`) and this key's pref (`:280-282`) is never reached. The YAML's "When this policy is not set, or is enabled, the DNS interception checks are performed" (`Miscellaneous/DNSInterceptionChecksEnabled.yaml:8`) does not match the code. No brave-core override or Griffin study touches either; same on `1.99.x`, master and Chromium main. Kept as a lock in case `IntranetRedirectBehavior` is ever set to 3; browser-wide |
| BasicAuthOverHttpEnabled | ✅ | cr88 | bool | false | refuses HTTP Basic auth over cleartext: the local-state pref feeds `HttpAuthDynamicParams` (156.0.8078.48 `chrome/browser/net/system_network_context_manager.cc:196-197`, re-sent on change `:649-650`), which the network service pushes to every network context (`services/network/network_service.cc:604-607,810-813` → `network_context.cc:2827-2828`), and `HttpAuthHandlerBasic::Factory` returns `ERR_UNSUPPORTED_AUTH_SCHEME` for a challenge from any `http` origin (`net/http/http_auth_handler_basic.cc:128-132`). A plain-HTTP proxy's auth origin is `http` too, on both the CONNECT-tunnel and the forwarded-request path (`net/http/http_proxy_connect_job.cc:135-139,264-268`, `net/http/http_network_transaction.cc:2508-2511`), so Basic-authenticated `http://` proxies stop working as well; HTTPS proxies and the other auth schemes are untouched. Breaks legacy plain-HTTP appliance logins; brave-core does not touch the chain at `v1.98.60`, `1.99.x` or master; browser-wide |
| DefaultWebUsbGuardSetting | ✅ | cr67 | int enum | 2 or 3; omitted when Not managed | **2 = block, 3 = ask — no value 1** in the schema, so the row offers Not managed / Ask / Block. Ships enabled in Brave. Breaks Ledger/Trezor web wallets and in-browser firmware flashers |
| DefaultSerialGuardSetting | ✅ | cr86 | int enum | 2 or 3; omitted when Not managed | 2 = block, 3 = ask, no 1; breaks in-browser microcontroller tooling |
| DefaultWebHidGuardSetting | ✅ | cr100 | int enum | 2 or 3; omitted when Not managed | 2 = block, 3 = ask, no 1; may break security keys and gamepad configurators that use WebHID rather than WebAuthn. Block also cuts Brave Wallet's own Ledger connection (source-read, not runtime-tested): the `chrome-untrusted://ledger-bridge` frame uses `TransportWebHID` (`components/brave_wallet_ui/ledger/ledger_bridge.ts:37` at `v1.98.60`), `HidService` checks the guard against the wallet's `chrome://` main-frame origin (`content/browser/hid/hid_service.cc:126,439-443` at 156.0.8078.48; `getDevices` is filtered by the same guard at `chrome/browser/hid/hid_chooser_context.cc:518-519`), `HID_GUARD` allowlists no scheme (`components/content_settings/core/browser/content_settings_registry.cc:401-403`), and Brave's HID overrides only waive the user-gesture requirement and swap in the wallet's own chooser, both after that check (`browser/hid/brave_hid_delegate.cc:22-53` at `v1.98.60`; `patches/content-browser-hid-hid_service.cc.patch` splices the waiver into the activation check at `hid_service.cc:448-456`, and the chooser runs at `:462`), so `requestDevice` and `getDevices` come back empty. The device-API set is USB+Serial+HID because WebBluetooth and File System Access are already feature-disabled in Brave (see Considered and rejected) |
| DefaultLocalFontsSetting | ✅ | cr103 | int enum | 2 or 3; omitted when Not managed | 2 = block, 3 = ask, no 1; `queryLocalFonts()` returns the installed font list, a top-tier fingerprint that Shields' farbling does not cover |
| DefaultWindowManagementSetting | ✅ | cr111 | int enum | 2 or 3; omitted when Not managed | 2 = block, 3 = ask, no 1; stops sites reading the multi-monitor topology. Complementary to `kBraveBlockScreenFingerprinting` (on by default on Windows, macOS and Linux, `chromium_src/third_party/blink/common/features.cc:23-29` at `v1.98.60`), which is about screen size: it gives `window.screen` one synthetic common-size screen with `isExtended` false (`chromium_src/third_party/blink/renderer/core/page/chrome_client_impl.cc:35-61`) but leaves `getScreenDetails()` listing every real display (156.0.8078.48 `third_party/blink/renderer/modules/screen_details/screen_details.cc:22`) |
| BlockExternalExtensions | ✅ | cr80 | bool | true | closes the sideload channel bundleware uses: with the pref set, `ExternalProviderImpl::CreateExternalProviders` registers none of the registry or drop-in providers (156.0.8078.48 `chrome/browser/extensions/external_provider_impl.cc:876-916`). On Windows that is Chromium's hard-coded `Software\Google\Chrome\Extensions` key, read from HKLM's 32-bit view (`WOW6432Node` on 64-bit Windows) and HKCU (`chrome/browser/extensions/external_registry_loader_win.cc:38,88-95`), which brave-core does not repoint, so a sideload registered for Chrome also reaches Brave; on macOS and Linux `external_extensions.json` / `<id>.json` drop-ins, also not repointed (`chrome/common/chrome_paths.cc:54-58,415-447`): macOS `/Library/Application Support/Google/Chrome/External Extensions`, shared with Chrome; Linux `/usr/share/chromium/extensions`, shared with Chromium, and `<install dir>/extensions`; on both a per-user `External Extensions` folder in the user-data directory. Unmanaged, such extensions arrive disabled behind an approval prompt on Windows and macOS (`prompt_for_external_extensions`, `extensions/common/feature_switch.cc:22-27`) and install silently on Linux; with the policy they never load, and any already installed that way, approved or not, is uninstalled as an orphan at the next launch (`chrome/browser/extensions/external_provider_manager.cc:160-167,174-203`; that uninstall reason bypasses the user-may-modify check, `extensions/browser/extension_registrar.cc:742-754`). It does not cover the first-run `initial_extensions` list of `initial_preferences` (Web Store-hosted only; `external_provider_impl.cc:948-961`, behind `kInitialExternalExtensions`, enabled by default at `chrome/browser/browser_features.cc:91` with no brave-core override). User-chosen extensions keep working, unlike `ExtensionInstallBlocklist: ["*"]`; restart |

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
Windows and macOS. Artifact facts are verified on the shipped 1.98.60
artifacts (brave-core `v1.98.60`, Chromium 156.0.8078.48), each equal to its
v1.98.60 GitHub release asset digest — `brave-origin_1.98.60_amd64.deb`
(136,205,664 B, sha256 `54a05b1c…e639`, the bytes the apt `Packages` index
lists) and `brave-origin-1.98.60-1.x86_64.rpm` (137,992,253 B, sha256
`0f8577b0…56f3`, as the rpm `primary.xml` lists), both unpacked, and
`brave-origin-1.98.60-linux-amd64.zip` (191,253,706 B, sha256
`39a69cf1…b6e8`, the AUR `brave-origin-bin` 1:1.98.60-1 `sha256sums_x86_64`),
read in place. The runtime facts — the inotify watches, the
`ExtensionInstallForcelist` install, `--import` in `chrome://policy`, the
`chrome://policy/test` injection — rest on a real 1.94.121 install of the AUR
zip on CachyOS. `SlimBrave.ps1` has no Origin-specific code.

- **Origin reads `/etc/brave/policies/managed`, like regular Brave.** Source:
  `app/brave_main_delegate.cc:166-170` (`v1.98.60`; same on `1.99.x` and
  master) overrides `chrome::DIR_POLICY_FILES` to `/etc/brave/policies` under
  `IS_POSIX && !IS_MAC` with no branding or channel guard; Chromium's
  `config_dir_policy_loader.cc:33-36` (156.0.8078.48), with no brave-core
  patch or `chromium_src/` override, appends `managed` and `recommended`.
  Binary: the 1.98.60 Origin ELF — byte-identical across zip, deb and rpm,
  311,754,048 B, sha256 `60f9b9ec…fb9e` — holds `/etc/brave/policies` and
  `BraveSoftware/Brave-Origin` and no `/etc/brave-origin` string, as do the
  beta 1.99.44 and nightly 1.100.7 ELFs. Runtime: a
  running Origin holds inotify watches on `/etc/brave`, `/etc/brave/policies`
  and `/etc/brave/policies/managed` themselves (and parks on `/etc`, never on
  the existing `/etc/chromium`, while they don't exist). End to end: a managed
  `ExtensionInstallForcelist` there installed its extensions into the
  `Brave-Origin` profile as `location = 7` (`kExternalPolicyDownload`) without
  a restart, and this tool's `--import` showed every key in `chrome://policy`
  as Platform / Machine / Mandatory / OK.
- **`/etc/brave-origin/policies/enrollment` is not a policy directory.** It is
  the installer's `ENROLLMENTDIR`
  (`chromium_src/chrome/installer/linux/common/brave-origin/chromium-browser.info:17-18`;
  one file for every channel, so the path takes no channel suffix); Chromium's
  `postinst.include:79-104` (156.0.8078.48), run by the deb `postinst` and the
  rpm `%post`, creates it only when `/etc/default/brave-origin[-beta|-nightly]`
  holds `install_device_trust_key_management_command=true`, and only to hold
  `DeviceTrustSigningKey` — the shipped 1.98.60 deb and rpm and the beta
  1.99.44 and nightly 1.100.7 debs each carry that check before
  `mkdir -p "/etc/brave-origin/policies/enrollment"`, each reading its own
  `/etc/default/` file. The browser reads nothing there. Chrome Browser
  Cloud Management is off in a non-Chrome-branded build unless the browser is
  launched with `--enable-chrome-browser-cloud-management`
  (`chrome_browser_cloud_management_controller.cc:102-116`, 156.0.8078.48; not
  overridden); only then does it read
  `/etc/brave/policies/enrollment/CloudManagementEnrollmentToken`
  (`DIR_POLICY_FILES`, `browser_dm_token_storage_linux.cc:45-46`), and the
  Device Trust key from `/etc/chromium/policies/enrollment` (`kPolicyPath`,
  `policy_paths.cc:21`, not overridden); the 1.98.60 ELF carries both
  strings. Never write policies there.
- **Where Origin lives**, every row read from the artifact (stable 1.98.60,
  beta 1.99.44, nightly 1.100.7; Nix from the derivation and the NAR listing
  of Hydra's 1.97.59 build). The one-command install Brave's Origin Linux
  page (`brave.com/origin/linux/`) leads with,
  `curl -fsS https://dl.brave.com/install.sh | FLAVOR=origin sh` (optional
  `CHANNEL=beta|nightly`), adds no layout of its own (`install.sh:59-118`):
  apt, dnf, zypper, yum and rpm-ostree get `brave-origin[-beta|-nightly]`
  from the repos in the deb, rpm and Beta/Nightly rows; pacman gets a repo
  package if `pacman -Ss` finds one (CachyOS carries `brave-origin-bin`),
  else the AUR `brave-origin[-beta|-nightly]-bin` through paru, pikaur or
  yay; eopkg is refused. Per packaging:

| Packaging | Install dir | Binary | Launcher | On `PATH` | Profile |
|---|---|---|---|---|---|
| Arch: AUR `brave-origin-bin` (Brave maintains the PKGBUILD; CachyOS mirrors it in its `cachyos` repo); unpacks the upstream zip | `/opt/brave-origin-bin/` | `brave` | `brave-origin`, Chromium's wrapper as brave-core's `chrome-installer-linux-common-wrapper.patch` leaves it (no `exec -a`, so bash stays the browser's parent), byte-identical to the deb/rpm launcher | `/usr/bin/brave-origin`, a bash script that reads `$XDG_CONFIG_HOME/brave-origin-flags.conf` (default `~/.config`) and execs the launcher | `~/.config/BraveSoftware/Brave-Origin` |
| deb: `brave-origin`, from the same `brave-browser-apt-release.s3.brave.com` repo as `brave-browser`; no Conflicts, Replaces or Breaks and no file in common, both co-install | `/opt/brave.com/brave-origin/` | `brave` | `brave-origin` | `/usr/bin/brave-origin-stable`, shipped symlink; bare `/usr/bin/brave-origin` via `update-alternatives` in postinst | same |
| rpm: `brave-origin`, from `brave-browser-rpm-release.s3.brave.com` through the `brave-browser.repo` Brave's Origin page gives (dnf, zypper, rpm-ostree); the CDN generates every `brave-browser*.repo` response, so `brave-browser-origin.repo`, `-origin-beta`, even `brave-browser-foo.repo` return that bucket's one `[brave-browser]` release file — aliases, not Origin repos (`brave-origin.repo` is a 404); `brave-origin-beta` and `-nightly` come only from the `brave-browser-rpm-beta` / `-nightly` buckets | `/opt/brave.com/brave-origin/` | `brave` | `brave-origin` | `/usr/bin/brave-origin-stable`, shipped; bare `/usr/bin/brave-origin` is a `%ghost` from `%post`'s `update-alternatives` | same |
| Beta, Nightly: `brave-origin-beta`, `brave-origin-nightly` (apt/rpm beta and nightly repos; Brave's AUR `*-bin` repackage the GitHub-release deb) | `/opt/brave.com/brave-origin-beta/`, `…-nightly/` | `brave` | `brave-origin-beta`, `-nightly`, with a `brave-origin` symlink to it in the same dir | deb/rpm: `/usr/bin/brave-origin-beta`, `-nightly`, direct symlinks; each also registers the bare `/usr/bin/brave-origin` alternative (the rpms `Provides: brave-origin` and `%ghost` it); priorities, deb/rpm: stable 201/200, beta 151/150, nightly 1/0 (brave-core's channel `nightly`, `build/linux/channels.gni:24-25`, falls to Chromium's `* ) PRIORITY=0`, `debian/postinst:44-45` and `rpm/chrome.spec.template:161-162` at 156.0.8078.48; only the deb postinst patch adds 1, `chrome-installer-linux-debian-postinst.patch:9`), so in auto mode without stable Origin a bare `brave-origin` is the beta if installed, else the nightly. AUR: a bash wrapper replaces `/usr/bin/brave-origin-<ch>`, exports `CHROME_USER_DATA_DIR=~/.config/BraveSoftware/Brave-Origin-<Ch>` when unset (Chromium reads it on Linux, `chrome/app/chrome_main_delegate.cc:669-682`) and registers no alternative | `Brave-Origin-Beta`, `Brave-Origin-Nightly` — the suffixes of `common/brave_channel_info_posix.cc:33-38` |
| Nix: nixpkgs `brave-origin` (`pkgs/applications/networking/browsers/brave/`, x86_64/aarch64-linux, plus aarch64-darwin from the dmg; 1.98.60 on master `658676ada4`, 1.97.59 on nixos-unstable `3ec636362e`, absent from nixos-26.05 `da6dc0e7b2`, which carries only `brave`); repackages the GitHub-release deb (amd64: the apt bytes, sha256 `54a05b1c…e639`) | `/nix/store/…-brave-origin-<ver>/opt/brave.com/brave-origin/` | `brave`; only interpreter and rpath patched (with `chrome_crashpad_handler`; `make-brave.nix:248-252`, the same file at both commits), strings untouched | `brave-origin`, the deb's launcher with `/bin/bash` and `CHROME_WRAPPER` rewritten (`make-brave.nix:242-246`); `bin/brave-origin` is a wrapGAppsHook3 wrapper around it | `bin/brave-origin` only (no `brave-origin-stable`), through whichever Nix profile installed it: `/run/current-system/sw/bin`, `/etc/profiles/per-user/<user>/bin`, `~/.nix-profile/bin` | `~/.config/BraveSoftware/Brave-Origin` |
| Flatpak | no official one. Flathub has only `com.brave.Browser`, and its search for "brave origin" returns only that; every Origin-shaped id 404s; `flathub/com.brave.Browser` has no Origin branch, issue or PR; brave/brave-browser #55196 asking for one is open, as is #59433, FlatPark's request that Brave approve its listing. Brave's RDN for Origin, `com.brave.Origin` (`chromium-browser.info:34`), names the deb/rpm's `NoDisplay` portal desktop file (next bullet) and two unofficial Flatpaks: FlatPark's (`flatpark/flatpark` `registry/com.brave.Origin`, a bot-refreshed extra-data pin of the official zip, at the 1.98.60 release asset, sha256 `39a69cf1…b6e8`, `com.brave.Origin.yml:72-73`; profile `~/.var/app/com.brave.Origin/config/BraveSoftware/Brave-Origin`) and a stale one-star bundle of the 1.93.134 deb (`jfrmorales/brave-origin-flatpak`). Neither reads host policy: neither grants `host-etc` nor links `/run/host/etc/brave/policies` into the sandbox's `/etc/brave/policies` as Flathub's `brave.sh:3-11` does, and Flatpak will not expose `/etc` paths, so no permission override helps (FlatPark's manifest calls host policy loading opt-in, `com.brave.Origin.yml:54-56`, but its launcher links nothing). A third, `io.github.shyvortex.BraveOrigin` (`ShyVortex/brave-origin-flatpak`, `.flatpak` release bundles of the official zip, 1.98.60), copies Flathub's `host-etc` grant and `brave.sh`, so it does read `/etc/brave/policies`. No official Flatpak to probe | | | | |
| Snap | none. The store has `brave` only (Brave Software, verified); `brave-origin`, `brave-origin-beta` and `brave-origin-nightly` are `resource-not-found`; the `brave` snap's channel map is `latest/{stable,candidate,beta,edge}`, all four on 1.98.60 (rev 698 amd64, 699 arm64), its squashfs holds `opt/brave.com/brave/` only and its binary says `BraveSoftware/Brave-Browser`, never `Brave-Origin`. Likely, not confirmed: snapd's `browser-support` interface grants `/etc/opt/chrome` and `/etc/chromium` and nothing under `/etc/brave` (`interfaces/builtin/browser_support.go:96-97`, snapd `8d4d073ab303`), and the `brave` snap (rev 698) adds nothing — no `system-files` or `personal-files` plug, a `layout` binding only `/usr` paths, no other plugged interface granting `/etc/brave`; that is the mechanism behind the tool's Snap warning | | | | |

- **Names the detector relies on.** Profile:
  `chromium_src/chrome/common/chrome_paths_linux.cc:26-27` —
  `BraveSoftware/Brave-Origin` plus the channel suffix under
  `IS_BRAVE_ORIGIN_BRANDED`. Package: `build/config.gni:72-80`
  (`brave_linux_package_name = "brave-origin"`), `installer/linux/sources.gni:8-9`.
  Desktop ids: `chromium_src/chrome/common/channel_info_posix.cc:64-74` —
  `brave-origin[-beta|-nightly|-dev].desktop`; the deb/rpm also ship a
  `NoDisplay=true` twin for the XDG-portal app id,
  `com.brave.Origin[.beta|.nightly].desktop` (`RDN`,
  `chromium-browser.info:34`; Chromium `installer.py:527-533,938-963`,
  156.0.8078.48). `StartupWMClass` is the package name after the channel
  suffix (`installer.py:529,535`, `desktop.template:110`): `brave-origin` on
  stable, `brave-origin-beta`, `-nightly` otherwise, as the 1.98.60, 1.99.44
  and 1.100.7 desktop files read. Processes: the browser's
  comm is `brave` on every packaging; the launcher's bash process stays alive
  around it (brave-core's `chrome-installer-linux-common-wrapper.patch:9-10`
  drops Chromium's `exec -a`) with the comm it was started by — `brave-origin`
  from the AUR wrapper, `brave-origin-st` (comm's 15-character cap) from the
  deb/rpm desktop file's `brave-origin-stable`; the profile's `SingletonLock`
  covers the truncated case. The shipped man page's `$HOME/.config/brave-origin`
  is Chromium template text (brave-core's copy,
  `chromium_src/chrome/app/resources/manpage.1.in:27`) and wrong.
- **What the tool does with it.** `LINUX_CHANNELS` carries `origin`,
  `origin-beta`, `origin-nightly` (no `origin-dev`: named in source, never
  published — the release, beta and nightly apt indexes carry only
  `brave-origin`, `brave-origin-beta` and `brave-origin-nightly`).
  `detect_brave()` probes `/opt/brave-origin-bin/brave`,
  `/opt/brave.com/brave-origin/brave-origin`, `/opt/brave.com/brave-origin/brave`
  (still the 1.98.60 layout: the zip's root holds `brave` and the
  `brave-origin` launcher, which AUR `brave-origin-bin` 1:1.98.60-1 copies to
  `/opt/brave-origin-bin/`; the deb and rpm install both in
  `/opt/brave.com/brave-origin/`) and, only when no Brave at all
  has turned up, `brave-origin-stable`, `brave-origin`, `brave-origin-beta` and
  `brave-origin-nightly` on `PATH`; reports `arch (Brave Origin)`,
  `deb/rpm (Brave Origin)`, `unknown (Brave Origin)`, or `arch: Stable, Origin`
  beside a regular Brave. Each Origin channel's record comes from its profile
  directory or its launcher on `PATH`, stable's also from the install-dir
  probe. Beta and Nightly have no install-dir probe, and their deb and rpm packages
  point the bare `brave-origin` alternative at their own launcher (see the
  table), so a Beta- or Nightly-only deb or rpm install reports
  `unknown (Brave Origin)` and also gets a stable `Origin` record. Origin's profiles join prefs repair and the running
  check; `--channels` accepts the three ids. A `notes` list beside `warnings`
  keeps the launch line in the success colour.
- **Regular Brave in "Origin mode" is still regular Brave.** On Linux the free
  tier is one click on the Origin onboarding card at `brave://settings/system`
  (`brave_origin_onboarding.html:45-49`, `is_linux` only; shown in
  non-Origin-branded builds while `kBraveOrigin`, on by default
  (`components/brave_origin/features.cc:12`; no brave-variations study names
  it), is enabled, hidden once purchased, `brave_system_page_index.ts:82-86,152-155`):
  `ProceedFree` → `BraveOriginService::AcceptFreeTier`
  (`brave_origin_settings_handler_impl.cc:95-102`, `brave_origin_service.cc:319-324`)
  sets `brave.origin.free_tier_accepted` and, through
  `BraveOriginPolicyManager::SetPurchased(true)`, `brave.origin.purchase_validated`
  in `Local State`. The page then loads `brave://settings/origin`
  (`brave_origin_onboarding.ts:57-61`; routed only once purchased and only in
  a non-branded build, `page_visibility.ts:129-130`, `brave_routes.ts:33-35`),
  whose purchase check counts the free tier as a purchase and sets
  `brave.origin.policies_were_enforced` (`brave_origin_service.cc:257-273`);
  toggles live in `brave.brave_origin.policies` (all four prefs in
  `Local State`, `brave_origin_prefs.cc:14-25`). Same binary, same
  `Brave-Browser` profile, every feature compiled in, the Flatpak included.
  Nothing for the detector to do; every row live.
- **A managed file outranks Origin's own layer; it cannot revive what Origin
  compiled out.** Origin enforces its debloat through `BraveBrowserPolicyProvider`
  and `BraveProfilePolicyProvider`, which emit mandatory `POLICY_SOURCE_BRAVE`
  entries at `kBravePriority` — inserted below `kEnterpriseDefault`, the lowest
  browser priority (brave-core `chromium_src/components/policy/core/common/policy_types.h:16-17`
  and `chromium_src/…/policy_map.cc:9-12`, over Chromium's `policy_types.h:83-85`),
  per brave-core's own `BravePolicySourceTest.BraveHasLowerPriority`
  (`brave_policy_source_unittest.cc:34`).
  Both load Origin's set only when `IsBraveOriginPurchased()`
  (`brave_browser_policy_provider.cc:65-67`, `brave_profile_policy_provider.cc:100-102`
  at `v1.98.60`): `kBraveOrigin`, on by default, plus an initialised
  `BraveOriginPolicyManager` reporting a purchase (`brave_origin_utils.cc:21-27`)
  — a validated purchase or, on Linux, the accepted free tier (`AcceptFreeTier`,
  `brave_origin_service.cc:319-324`; re-applied at startup, `:74-80`). Either
  sticks: `SetPurchased` persists only `true` into
  `brave.origin.purchase_validated` and `IsPurchased` falls back to it
  (`brave_origin_policy_manager.cc:178-205`), and no browser code clears it or
  the free-tier pref. Until then Origin's layer is empty and only Ad Block Only
  Mode writes `POLICY_SOURCE_BRAVE` (`brave_profile_policy_provider.cc:104`);
  the branded build's startup dialog stands before the first window until one
  of the two holds (`brave_origin_startup_view.cc:87-111`; on Linux,
  `--skip-origin-startup-dialog` records the free tier and skips it, `:97-106`;
  called only under `IS_BRAVE_ORIGIN_BRANDED`,
  `chromium_src/chrome/browser/ui/startup/startup_browser_creator.cc:166-167`).
  `PolicyMap::MergeFrom` settles each key in `MergePolicy` on (level, priority)
  (`policy_map.cc:468-491`, via `EntryHasHigherPriority` at `:684-706`, at
  156.0.8078.48), so a mandatory platform entry wins every conflict:
  `{"BraveP3AEnabled": true}` would switch P3A back on in Origin. Nothing this
  tool writes points that way.
- **Thirteen rows are dead on Origin, and the tool shows them inert.** Each
  key's `brave_simple_policy_map.h` entry sits under a buildflag whose `.gni`
  is `… && !is_brave_origin_branded`: `BraveRewardsDisabled` (`ENABLE_BRAVE_REWARDS`),
  `BraveWalletDisabled`, `TorDisabled`, `BraveVPNDisabled`, `BraveAIChatEnabled`,
  `BraveLocalAIEnabled`, `BravePlaylistEnabled`, `BraveWebDiscoveryEnabled`,
  `BraveNewsDisabled`, `BraveTalkDisabled`, `BraveSpeedreaderEnabled`,
  `BraveWaybackMachineEnabled`, `EmailAliasesEnabled` (at `v1.98.60`, same on
  `1.98.61`, `1.99.x` and master). A fourteenth, `PsstEnabled`
  (`ENABLE_PSST`, `enable_psst = !is_android && !is_ios && !is_brave_origin_branded`,
  `components/psst/buildflags/buildflags.gni:9`; `brave_simple_policy_map.h:160-163`
  at `v1.98.60`), is dead on Origin too;
  the tool does not write it, and exposing it would add it to
  `ORIGIN_BUILTIN_KEYS`. Confirmed on the 1.94.121 binary: nothing registered
  under `brave.wallet`, `brave.ai_chat`, `brave.playlist`, `brave.speedreader`,
  `brave.news`, `brave.talk`, `brave.email_aliases`, `brave.web_discovery`,
  `brave.wayback`, no `tor.*`, and injecting every Brave key as a mandatory
  machine policy through `chrome://policy/test` made none of the thirteen prefs
  managed — while `brave://policy` listed each as applied, the same blind spot
  the `BraveVPNDisabled` row documents. The 1.98.60 Origin ELF (from the deb)
  holds none of the target pref names of the Wallet, VPN, AI Chat, Local AI,
  Playlist, Web Discovery, News, Talk, Speedreader, Email Aliases or PSST keys;
  `tor.tor_disabled` survives only as the name the Snowflake settings handler
  probes with `IsManagedPreference` (`brave_tor_snowflake_extension_handler.cc:117-122`,
  built under `enable_extensions`) and `brave.wayback_machine_enabled` only as
  the unguarded key of Origin's own metadata table
  (`brave_origin_service_factory.cc:156`). At `v1.98.60` each target pref is
  registered only behind its key's own flag, `brave.local_ai_enabled` (Local
  State, `brave_local_state_prefs.cc:184-186`) and
  `brave.brave_vpn.disabled_by_policy` (built only `if (enable_brave_vpn)`,
  `browser/brave_vpn/sources.gni:11`, on no Linux build) included, except
  `brave.rewards.disabled_by_policy`: registered unguarded
  (`brave_profile_prefs.cc:628` → `components/brave_rewards/core/pref_registry.cc:62`;
  present in the 1.98.60 Origin ELF), reached by no policy once its map entry
  is compiled out. `BraveP3AEnabled` and `BraveStatsPingEnabled` are dispatched
  (unguarded, `brave_simple_policy_map.h:124-127`); once Origin counts as
  purchased its layer emits both at the lowest priority, default `false` and
  marked user-settable (`brave_origin_service_factory.cc:131-139`), but the
  branded build offers no toggle for either: `brave://settings/origin` is
  routed only in non-branded builds (`page_visibility.ts:129-130`,
  `brave_routes.ts:33-35`) and the privacy page hides its P3A and usage-ping
  toggles there unconditionally (`brave_privacy_handler.cc:165-170`,
  brave-browser#56166). A managed `false` equals what Origin already applies
  and pins it. Origin compiles out the usage
  pinger itself (`enable_brave_stats_updater = !is_brave_origin_branded`,
  `browser/brave_stats/buildflags.gni:11`), but `kStatsReportingEnabled` stays
  registered (`brave_local_state_prefs.cc:174-179`) and still gates referral
  initialisation and SERP-metrics recording, so the key stays live and out of
  `ORIGIN_BUILTIN_KEYS`. `MetricsReportingEnabled` is live (Chromium simple map,
  `configuration_policy_handler_list_factory.cc:1163-1165` at 156.0.8078.48,
  under `!BUILDFLAG(IS_CHROMEOS)`);
  Origin only registers its default as `false` on every channel
  (`metrics_reporting_util.cc:22-23`, applied at `brave_local_state_prefs.cc:198-200`;
  regular Brave only on Stable) and its layer never emits it, so the user can
  flip it and a managed `false` pins it. Everything else —
  the five unguarded Brave privacy toggles, both Shields lists, the
  `DefaultBrave*` content settings (handlers added unconditionally,
  `chromium_src/…/configuration_policy_handler_list_factory.cc:32-36`), every
  Chromium key — is live. In the
  tool: `ORIGIN_BUILTIN_KEYS` in both scripts carries the thirteen; when every
  detected Brave is Origin (`is_origin_only`), `build_rows` marks them inert —
  drawn `[-]`, dimmed, `(built into Origin)`, out of the counts, untoggleable,
  never written or exported, unticked on sync so the next Apply drops a stale
  key; an import that names them reports `13 keys built into Brave Origin left
  unmanaged`. "Only Brave" is judged on the whole machine: a regular Brave
  found by package, Flatpak, Snap or launcher but never started still gets its
  record, and every record carries the machine-wide `origin_only` verdict, so
  `--channels origin` cannot narrow a mixed machine. Under `--policy-file` the
  rows come from the override record and stay live.
- **Origin parity of the presets.** `browser/brave_origin/brave_origin_service_factory.cc`
  (`v1.98.60`; identical on `1.98.61`, `1.99.x` and master) builds Origin's
  debloat set by walking `kBraveSimplePolicyMap` (`:320-359`) and keeping each
  pref found in `kBraveOriginBrowserMetadata` (4, `:118-149`) or
  `kBraveOriginProfileMetadata` (12, `:152-247`) — sixteen prefs. Fifteen map to
  keys this project exposes, and for every one the value the project writes
  equals Origin's default (the Brave Origin preset). The sixteenth is
  `PsstEnabled`, dispatched but inert on Release and Beta while `kEnablePsst`
  is off (see its row); its Origin entry (`false`, `user_settable=false`,
  `:240-246`) shares the `ENABLE_PSST` guard, so it applies only in regular
  Brave's Origin mode; the project does not expose it. Each build gets the
  subset its buildflags compile: regular Brave in Origin mode gets sixteen on
  Windows and macOS and fifteen on Linux, where `enable_brave_vpn`
  (Windows/macOS/Android/iOS only,
  `components/brave_vpn/common/buildflags/buildflags.gni:11-22`) drops the VPN
  profile entry and its map entry; the branded build keeps only P3A and the
  stats ping (the Wayback table entry, `:156`, is unguarded, but the walk drops
  it with its guarded map entry), both `false` with no settings toggle in that
  build (see the bullet above). Regular Brave's Origin mode shows both as
  toggles on `brave://settings/origin` (`brave_origin_page.html:92-104`), and
  there a managed `false` is what locks them. De-AMP, Debouncing,
  query-parameter filtering, GPC and Reduce Language (each registered default
  `true`) and the two Shields lists are in `kBraveSimplePolicyMap` but in
  neither table: Origin leaves the five toggles at their enabled-by-default
  user setting, the direction the project forces, and the lists unset.

## Platform policy locations, from source

- **Windows** — `HKLM\SOFTWARE\Policies\BraveSoftware\Brave`. Chromium's
  `components/policy/tools/generate_policy_source.py` emits
  `kRegistryChromePolicyKey` from `CHROMIUM_POLICY_KEY` for non-Google branding
  (`:31`, `:1208-1218` at 156.0.8078.48); brave-core's
  `chromium_src/components/policy/tools/generate_policy_source.py:11` overrides
  the constant to `SOFTWARE\Policies\BraveSoftware\Brave`, inlined into the
  generator by `patches/components-policy-tools-generate_policy_source.py.patch`;
  `chrome_browser_policy_connector.cc:316-320` hands it to `PolicyLoaderWin`.
  brave-core's
  `chromium_src/chrome/browser/policy/chrome_browser_policy_connector.cc:17-37`
  (at `v1.98.60`) only renames `CreatePolicyProviders` to append its
  browser-level provider last; `CreatePlatformProvider`, which builds
  `PolicyLoaderWin`, `PolicyLoaderMac` and `ConfigDirPolicyLoader`, is
  Chromium's on every platform. No channel or Origin suffix: nothing in
  `install_static` feeds the constant (its install modes vary install suffix,
  app GUIDs and ProgIDs; Origin's product dir is `Brave-Origin`,
  `chromium_install_modes.h:30-37`), so one key serves stable, beta, nightly
  and Origin; the Brave and Origin 1.98.60 `chrome.dll` each hold exactly one
  `SOFTWARE\Policies\BraveSoftware\Brave`, NUL-terminated UTF-16LE (no ASCII
  copy, no `Policies\Chromium`). `BraveSoftware\Brave-Browser`
  (Origin: `Brave-Origin`) is the install and profile dir name, not the policy
  path, with one early reader: before the policy stack exists,
  `install_static::ReportingIsEnforcedByPolicy` reads `MetricsReportingEnabled`
  for crash-report consent from `SOFTWARE\Policies\BraveSoftware\Brave-Browser`
  (Origin: `…\Brave-Origin`), HKLM then HKCU (Chromium
  `chrome/install_static/install_util.cc:520-541` at 156.0.8078.48, from
  `chrome_crash_reporter_client_win.cc:114-122`; brave-core leaves it, and its
  `brave_install_util_unittest.cc:295-311` writes there; the 1.98.60
  `chrome_elf.dll` holds `SOFTWARE\Policies\`, `BraveSoftware` and
  `Brave-Browser` (Origin: `Brave-Origin`) only as separate strings). The
  browser copies the effective metrics pref into the updater's `usagestats` at
  every start and on every change of the pref or its policy (Chromium
  `chrome/browser/browser_process_impl.cc:1684`, `:499-501`), so crash consent
  follows this tool's key once Brave has run under it. The other early read,
  `UserDataDir`, is redirected to `…\BraveSoftware\Brave`
  (`chromium_src/chrome/install_static/user_data_dir.cc:28-42`).
  `…\BraveSoftware\Update` is the updater's policy key
  (`patches/chrome-installer-util-google_update_settings_win.cc.patch`).
  Matches Brave's own Group Policy documentation and the 1.98.60
  `policy_templates.zip`, whose ADMX puts every policy under
  `Software\Policies\BraveSoftware\Brave` or its `\Recommended` subkey.
- **Linux** — `/etc/brave/policies/managed`. Chromium's default is
  `/etc/chromium/policies` (`policy_paths.cc:21`), unpatched; brave-core
  `app/brave_main_delegate.cc:166-170` (at `v1.98.60`; same on `1.99.x` and
  master) overrides `chrome::DIR_POLICY_FILES` at startup
  (`PreSandboxStartup`) under `IS_POSIX && !IS_MAC`, unconditionally, and the
  platform loader is built only from `DIR_POLICY_FILES`
  (`chrome_browser_policy_connector.cc:346-350`), so no Brave reads
  `/etc/chromium/policies`; `config_dir_policy_loader.cc:33-36` appends
  `managed` / `recommended`. The 1.98.60 Brave and Origin `brave` binaries
  each hold one `/etc/brave/policies` beside Chromium's overridden default.
  Channel- and Origin-independent, confirmed at runtime on Origin. Flatpak:
  Flathub `com.brave.Browser` (1.98.60, Brave's own linux zip;
  `flathub/com.brave.Browser@0d2de46495af`) has `--filesystem=host-etc`,
  which mounts the host `/etc` at `/run/host/etc`, and its `brave.sh`
  symlinks `/run/host/etc/brave/policies/{managed,recommended,enrollment}/*.json`
  (and the same under `/run/host/etc/static/brave/policies`, NixOS's
  `/etc/static`) into the sandbox's own `/etc/brave/policies` before each
  launch; a file first created while Brave runs is seen only after a full
  quit and relaunch, and an edit to an already-linked file raises no event in
  the watched directory, so it lands on the loader's 15-minute reload
  (`async_policy_loader.cc:30`) or at restart. Snap: `brave` (1.98.60, rev 698
  amd64, `confinement: strict`) plugs no `system-files` or `personal-files`
  and its `layout` binds only `/usr` paths; `browser-support` grants
  `/etc/opt/chrome` and `/etc/chromium` and nothing under `/etc/brave`
  (`interfaces/builtin/browser_support.go:96-97`), nor does the default
  template or any other plugged interface (snapd `8d4d073ab303`), so where
  snapd enforces AppArmor the read should be denied; source only, not
  confirmed at runtime. The tool's Snap warning rests on this.
- **macOS** — `/Library/Managed Preferences/<bundle id>.plist`, bundle ids
  `com.brave.Browser`, `.beta`, `.nightly`, and for Brave Origin, a separate
  `Brave Origin.app`: `com.brave.Browser.origin`, `.origin.beta`,
  `.origin.nightly` (the shipped 1.98.60 `Brave Origin.app` carries
  `com.brave.Browser.origin`).
  Chromium's `chrome_browser_policy_connector.cc:332-341` (156.0.8078.48) keys
  the loader on the running app's own `BaseBundleID()` for non-Google branding,
  which `chrome/app/chrome_main_mac.mm:110-113` sets from the outer app's
  bundle identifier, so each app and channel reads only its own id.
  `policy_loader_mac.mm:108-135` reads every schema key through
  `CFPreferencesCopyAppValue` / `CFPreferencesAppValueIsForced` on that id: a
  forced value is Mandatory (machine scope when the any-user managed source
  also has it), any other value Recommended at user scope. Machine-scope
  values come from `/Library/Managed Preferences/<bundle id>.plist` or a
  System-scope Configuration Profile; an unforced `<bundle id>.plist` under
  `/Library/Preferences` loads as Recommended, not Mandatory.
  `GetManagedPolicyPath` (`:178-194`) builds only the per-user
  `/Library/Managed Preferences/<login>/<bundle id>.plist`, the only file the
  loader watches (`:77-78`), so a machine-plist change lands on the 15-minute
  periodic reload (`async_policy_loader.cc:30`), `brave://policy` "Reload
  policies", or a restart. The ids are `MAC_BUNDLE_ID` in brave-core
  `app/theme/{brave,brave_origin}/BRANDING[.<channel>]` (plain `BRANDING` for
  Release; for Origin builds `build/commands/lib/buildArgs.ts:65-70` imports
  `build/args/brave_origin/branding_defaults.gni`, which sets
  `branding_path_component = "brave_origin"`), copied over
  `chrome/app/theme/<branding>/BRANDING` by
  `build/commands/lib/branding.js:301-310,380-386` and read into
  `chrome_mac_bundle_id` by Chromium's `build/util/branding.gni:20,42`.
  `MAC_CHANNELS` lists only the three regular ids, so the tool neither
  detects nor writes Origin on macOS: each app reads only its own id, and when
  detection finds no listed app the tool falls back to
  `com.brave.Browser.plist`, which Origin never reads (What's next).
  `app/theme/brave/BRANDING.dev` still names `com.brave.Browser.dev`, but Brave
  dropped the Dev channel (brave-browser#25248) and publishes no Dev build, and
  Origin has no `BRANDING.dev`; `BRANDING.development` is for local builds. No
  Dev or development id belongs in `MAC_CHANNELS`.

## Cross-cutting facts

- **`ForUrls` patterns.** Brave's docs' "wildcards are not supported" means
  `*.example.com`, which the parser rejects: a host may be a bare `*` or start
  with `[*.]`, and any other `*` makes the pattern invalid
  (`components/content_settings/core/common/content_settings_pattern_parser.cc:126-153`
  at 156.0.8078.48), and `PolicyProvider` skips an invalid entry
  (`content_settings_policy_provider.cc:518-524`). The scheme-wide `https://*`
  and `http://*` this tool uses are valid `ContentSettingsPattern` syntax, any
  host on any port (127-134, 178-180; `content_settings_pattern_unittest.cc:646`),
  and apply. The policy path never writes them to the profile: `PolicyProvider`
  keeps policy content settings in an in-memory `OriginValueMap`
  (`content_settings_policy_provider.h:84`) and is read-only
  (`SetWebsiteSetting` returns false, `ClearAllContentSettingsRules` is empty,
  `content_settings_policy_provider.cc:728-738`). At `v1.98.60` (same on
  `1.99.x` and master) the Shields keys reach it through the
  `rewrite/components/content_settings/core/browser/content_settings_policy_provider.cc.yaml`
  plaster, which inserts `kManagedBraveShields{Disabled,Enabled}ForUrls` into
  `kPrefsForManagedContentSettingsMap` as `BRAVE_SHIELDS` Block and Allow
  (lines 12-18) and into `kManagedPrefs`, which registers both list prefs and
  puts them under the provider's change watcher (19-25), and registers the
  managed defaults of the five `DefaultBrave*Setting` keys, Adblock as
  `BRAVE_ADS` (26-50);
  `patches/components-content_settings-core-browser-content_settings_policy_provider.cc.patch`
  is its generated diff; a separate `chromium_src/` shim of the same file adds the
  `brave/components/constants/pref_names.h` include those names need. The
  `profile.content_settings.exceptions.braveShields` `http://*,*` /
  `https://*,*` entries the repair logic scrubs have no identified writer:
  SlimBrave-Neo#2 reported them after the Shields list was applied and
  removed, and no SlimBrave code but the repair has ever touched content
  settings (`git log --all -S content_settings` starts at the repair, `80d461f`,
  v1.4.1). The repair is a guard for profiles that carry them, not a fix for a
  known writer.
- **Ad Block Only Mode writes policies too.** brave-core ships
  `components/brave_policy/ad_block_only_mode/ad_block_only_mode_policy_manager.cc`:
  with `kAdblockOnlyMode` on and the local-state opt-in `kAdBlockOnlyModeEnabled`
  true (`:61-69`), `BraveProfilePolicyProvider` injects thirteen values at
  `MANDATORY / USER / POLICY_SOURCE_BRAVE` (`:83-135`;
  `brave_profile_policy_provider.cc:163-168` at `v1.98.60`) —
  `BlockThirdPartyCookies=false`, `DefaultCookiesSetting=1`,
  `DefaultJavaScriptSetting=1`, `DefaultBraveAdblockSetting=2`,
  `DefaultBraveFingerprintingV2Setting=1`, `DefaultBraveHttpsUpgradeSetting=3`,
  `DefaultBraveReferrersSetting=1`, `DefaultBraveRemember1PStorageSetting=1`,
  and `BraveReduceLanguageEnabled`, `BraveDeAmpEnabled`, `BraveDebouncingEnabled`,
  `BraveTrackingQueryParametersFilteringEnabled`, `BraveGlobalPrivacyControlEnabled`
  all `false` — eleven of them keys this project writes, mostly to the opposite
  value. The injection compiles under `ENABLE_AD_BLOCK_ONLY_MODE_POLICIES`
  (`!is_ios`), and `kAdblockOnlyMode` is `FEATURE_ENABLED_BY_DEFAULT` on desktop
  at `v1.98.60` (`components/brave_shields/core/common/features.cc:107-112`;
  brave-core#39428, first in `v1.96.26`; off on iOS and Android; same on
  `1.99.x` and master), whatever `ChromeVariations` says. Builds before
  `v1.96.26` have it off in source, but brave-variations' `AdblockOnlyModeStudy`
  turns it on for 100% of desktop Release from 1.88.96 (capped at `max_version`
  154.1.96.26); the study sets no `policy_restriction`, so `ChromeVariations` 1
  or 2 keeps it out there. The opt-in defaults to false — the Shields panel
  prompts for it once Shields has been switched off five times
  (`prompt_after_shields_disabled_count`, `features.h:67-68`) — and exists only
  in an English UI: the Shields panel and the Settings toggle require the
  locale's language in `kAdblockOnlyModeSupportedLanguageCodes` (`{"en"}`,
  `brave_shield_constants.h:160-161`), and `ManageAdBlockOnlyModeByLocale`
  switches the opt-in off as a profile loads in any other locale, back on after
  a return to English (`brave_shields_locale_utils.cc:30-58`). Precedence
  favours this tool at the mandatory level it writes: `kBravePriority` is the
  lowest, and Chromium compares level before priority (`policy_map.cc:706` at
  156.0.8078.48); a macOS `--policy-file` under `/Library/Preferences` with
  `--persist off` is read as recommended (`policy_loader_mac.mm:126-129`) and
  loses to the mode. The loser is kept as a conflict (`policy_map.cc:529-537`),
  so with the mode on `brave://policy` shows an
  `IDS_POLICY_CONFLICT_DIFF_VALUE` warning on each key this tool writes to a
  different value (ten of the eleven with Cap Referrers, nine with Allow
  Permissive Referrers) and an `IDS_POLICY_CONFLICT_SAME_VALUE` info note where
  they agree (`DefaultBraveAdblockSetting=2`; `DefaultBraveReferrersSetting=1`
  under Allow Permissive Referrers).
  Precedence covers only those thirteen values: the mode also limits the
  component filter lists to `kAdblockOnlyModeFilterListUUIDs` (default,
  first-party, ABOM supplemental) and ignores list toggles
  (`ad_block_component_service_manager.cc:344-347,408-411`), which no policy
  overrides; regional, cookie-notice and other optional component lists go
  dark, custom filters and subscriptions stay active.
- **Where brave-core overrides live.** `chromium_src/`, `patches/` **and**
  `rewrite/*.yaml` coexist, and overrides move between them across branches:
  the `device_features.cc` flip of `kSensorsAllowAskBlockPermissionModel` was a
  `chromium_src` `OVERRIDE_FEATURE_DEFAULT_STATES` at `v1.94.121`; at `v1.98.60`
  (and on `1.99.x`, master) it is the
  `rewrite/services/device/public/cpp/device_features.cc.yaml` plaster
  (`:18-21`, brave-core#39268), same effect; the same-named `chromium_src/`
  file now only redefines the geolocation `kLocationProviderManagerParam`. A
  `rewrite/` plaster is applied to the upstream file (Chromium `src`, or a
  submodule listed in `patches/.repositories.cfg`) and generates its
  `patches/` twin (`docs/plaster.md:40-41`), so the two are one override: read
  the plaster for intent and the patch for the exact result, whose `index` base
  blob should `git hash-object`-match the pinned Chromium file (both do at
  156.0.8078.48, on `v1.98.60`, `1.99.x` and master:
  `content_settings_policy_provider.cc` `1582879c`, `device_features.cc`
  `ee538fca`). A `chromium_src/` file at the same path is a separate override
  beside them. Searching one directory proves nothing.
- **Content-setting enums are not uniform.** `DefaultNotificationsSetting`,
  `DefaultGeolocationSetting`, `DefaultSensorsSetting` take 1 / 2 / 3, all
  three in their `valid_settings` (156.0.8078.48
  `content_settings_registry.cc:150-151,161-162,343-344`; brave-core's SENSORS
  re-registration keeps all three, `chromium_src/components/content_settings/core/browser/content_settings_registry.cc:292-293`
  at `v1.98.60`). The other five permission keys list only 2 / 3 in their
  schema, but Chromium does not enforce the enum: their handlers only
  type-check (`SimplePolicyHandler`,
  `configuration_policy_handler.cc:74-79,377-393`;
  `DefaultWindowManagementSetting` goes through a
  `SimpleDeprecatingPolicyHandler` wrapping two of them, factory
  `:2937-2945`), so a 1 reaches the managed pref with no error on
  `brave://policy`; `PolicyProvider` then sets a managed default only if the
  type's `valid_settings` contains it
  (`content_settings_policy_provider.cc:703-716`,
  `content_settings_info.cc:42-44,67-72`), so it ignores the 1 for WebUSB,
  Serial and WebHID (Ask/Block only, `content_settings_registry.cc:374,384,403`)
  and applies it as a managed Allow for `DefaultLocalFontsSetting` and
  `DefaultWindowManagementSetting` (Allow/Ask/Block, `:534-535,544-545`). This
  tool offers only the schema's values: the choice lists are per key for that
  reason; a value outside a key's legal set is left unmanaged on import and
  named in the message; a quoted `"1"` or a `true` is rejected by a
  type-strict test in all three implementations. A number written with a
  fraction or an exponent is not always rejected: the Python scripts accept
  only a JSON integer (`_choice_index_for_value` compares types), but
  `SlimBrave.ps1` also accepts a `[double]` and compares `[int]$want`
  (`Import-PresetIntoState`), so whatever its `ConvertFrom-Json` returns as a
  double imports rounded. Under PowerShell 7 (Newtonsoft.Json) that is any of
  them: `2.0`, `2e0`, and `2.5`, which `[int]` rounds to 2. Under Windows
  PowerShell 5.1, the host of its elevated relaunch, it is only exponent forms
  such as `2e0` or `25e-1`: that `ConvertFrom-Json` (`JavaScriptSerializer`)
  returns `[decimal]` for `2.0` and `2.5`, which the test rejects and names
  (source-read, not runtime-tested; What's next).
- **Version gating.** A key whose `supported_on` range excludes the running
  build's Chromium milestone does nothing, whether it is newer than that
  Brave or capped below it: the policy code generator skips every platform
  range that excludes `--chrome-version-major`
  (`components/policy/tools/generate_policy_source.py:129-134` at
  156.0.8078.48) and drops a policy left with no platform for the target
  (`is_supported`, `:145-146`; `_GetSupportedPolicies`, `:453-464`); the flag
  is passed at `generate_policy_source.gni:59` by the one action that also
  writes `policy_constants.cc`, and brave-core's `chromium_src/` override of
  the script only sets the Windows registry key to
  `SOFTWARE\Policies\BraveSoftware\Brave`. So that build's schema has no
  entry for such a key and no handler exists —
  `SafeBrowsingExtendedReportingEnabled` (`chrome.*:66-144`) is outside the
  cr156 schema of Brave 1.98, and the shipping 1.98.60 Linux `brave` binary
  carries no `SafeBrowsingExtendedReportingEnabled` string at all (it does
  carry `SafeBrowsingProtectionLevel`). On Windows and Linux the loaders keep
  every name they read
  (`components/policy/core/common/policy_loader_win.cc:85-93`,
  `config_dir_policy_loader.cc:161`), `SchemaMap::FilterBundle` leaves
  Chrome-domain policies unfiltered "so that typos appear in about:policy"
  (`components/policy/core/common/schema_map.cc:44-46`), and `brave://policy`
  lists such a key with the error `Unknown policy.`
  (`components/policy/core/browser/policy_conversions_client.cc:496-501`); the
  macOS loader reads only schema-known names
  (`components/policy/core/common/policy_loader_mac.mm:118-123`), so there it
  is not listed at all. By milestone (`supported_on` at `v1.98.60`, same on
  `1.99.x` and master): cr138 (News, Talk, Speedreader, Wayback, P3A, Stats
  Ping, Web Discovery) · cr139 (Playlist) · cr140 (De-AMP, Debouncing, Reduce
  Language) · cr141 (Fingerprinting V2) · cr142 (GPC, Tracking Query
  Parameters, the other four `DefaultBrave*` enforcers) · cr147 (Email
  Aliases — Brave 1.92) · cr149 (Local AI — Brave 1.94); every other Brave key
  the scripts write is cr121 or older. The highest Chromium-inherited
  milestone is `DefaultWindowManagementSetting` at cr111.

## Considered and rejected — do not add

The source is the tiebreaker in every case: the YAML, the handler registration (Chromium's or brave-core's) and the `pref_mapping` file.

| Key(s) | Status | Why not |
|---|---|---|
| `EnableDoNotTrack` | ❌ | does not exist in Chromium's policy index; DNT has no enterprise policy and nothing reads the name (no YAML and no `policies.yaml` id at 156.0.8078.48 or main, no reference in brave-core `v1.98.60`). The Windows and Linux loaders pass unknown names through, so `brave://policy` lists it with the error `Unknown policy.` (`IDS_POLICY_UNKNOWN`, `policy_conversions_client.cc:496-500`); the macOS loader reads only schema keys (`policy_loader_mac.mm:118-123` at 156.0.8078.48), so there it is not listed. GPC (`BraveGlobalPrivacyControlEnabled`) is the working equivalent |
| `MediaRecommendationsEnabled` | 💀 | **dead key.** The YAML is open (`chrome.*:87-`, no cap, not deprecated) but Chromium removed the handler and the pref with Kaleidoscope in `3e5b1be4a` (2021-01-06); `policy_test_cases.json` said "removed since Chrome 89" at M90, `configuration_policy_handler_list_factory.cc` has no handler for it, and `pref_mapping/MediaRecommendationsEnabled.json:3` says `Policy was removed` at 156.0.8078.48 and at main (`7b96745f7dfb`); zero references in brave-core `v1.98.60`, `1.99.x` or master. `brave://policy` validates and lists it, but it has done nothing since Chromium 89. No script or preset writes it; an old export naming it still imports and the key is dropped without mention (no script's import names keys that match no row). The pref-mapping file is the tiebreaker |
| `SafeBrowsingExtendedReportingEnabled` | ❌ removed | removed after cr144: `deprecated: true`, capped `chrome.*:66-144` ("no effect starting with M145"; `policy_definitions/SafeBrowsing/SafeBrowsingExtendedReportingEnabled.yaml:4-6,31-34` at 156.0.8078.48, identical on main); Chromium `63b1c79f13` deleted its `configuration_policy_handler_list_factory.cc` entry (into `safebrowsing.scout_reporting_enabled`) and `pref_mapping/SafeBrowsingExtendedReportingEnabled.json`, so nothing dispatches it at 156.0.8078.48; brave-core re-adds none. The policy generator skips a platform whose `supported_on` range ends below the build's milestone (`components/policy/tools/generate_policy_source.py:131-134`, given `--chrome-version-major` by `components/policy/tools/generate_policy_source.gni:59`), so the key is not in the 1.98.60 schema (the 1.98.60 Linux `brave` binary holds no copy of the name). The Windows and Linux loaders pass names outside the schema through (`components/policy/core/common/registry_dict.cc:43-46`; `SchemaMap::FilterBundle` leaves Chrome policies unfiltered, `schema_map.cc:44-46`), so `brave://policy` lists a written value with the error `Unknown policy.` (`components/policy/core/browser/policy_conversions_client.cc:496-500`); the macOS loader reads only schema keys (`policy_loader_mac.mm:118-123`), so there it is not listed. Brave's 1.98.60 ADMX files it under "Removed policies". Moot anyway: upstream `kExtendedReportingRemovePrefDependency` is `FEATURE_ENABLED_BY_DEFAULT` (`components/safe_browsing/core/common/features.cc:314-315`; no brave-core override, no Griffin study), so `IsExtendedReportingEnabled()` returns `IsEnhancedProtectionEnabled()` (`components/safe_browsing/core/common/safe_browsing_prefs.cc:193-196`), which brave-core forces false (`chromium_src/components/safe_browsing/core/common/safe_browsing_prefs.cc:8` at `v1.98.60`); Brave also defaults the pref and its opt-in off (`browser/brave_profile_prefs.cc:229-236`) and hides the reporting toggle and the Enhanced radio (`browser/resources/settings/br/security_page.ts:11-38`). Same on `1.99.x` and master. No script or preset writes it; an old export naming it still imports and the key is dropped without mention. Dropped from the three scripts and the Balanced Privacy, Maximum Privacy and Developer presets when 156 became the shipping pin; `SlimBrave.ps1` Apply and Reset delete a leftover `0` it wrote. The YAML cap and the missing pref-mapping file are the tiebreaker |
| `SafeSitesFilterBehavior` | ⚠️ dispatched, inert | **filters nothing in Brave and still sends every URL to Google.** Dispatched (`factory` `:1146-1148` → `policy.safe_sites_filter_behavior`, read by `PolicyBlocklistNavigationThrottle::CheckSafeSitesFilter`, 156.0.8078.48 `components/policy/content/policy_blocklist_navigation_throttle.cc:127-139`, a throttle added to every navigation, `chrome/browser/chrome_content_browser_client_navigation_throttles.cc:429-433`): with 1, every http(s) navigation, iframes and redirects included (`components/policy/content/safe_sites_navigation_throttle.cc:48-51,89-92`; captive-portal tabs excepted, `:53-67`), is POSTed to `safesearch.googleapis.com/v1:classify` as `key=<google_apis::GetAPIKey()>&urls=<url>` (`components/safe_search_api/safe_search/safe_search_url_checker_client.cc:30-39`, key defaulted in `safe_search_url_checker_client.h:32`), with query, fragment and URL credentials stripped (`components/url_matcher/url_util.cc:237-246`, called from `components/policy/content/safe_search_service.cc:73-75`) and cookies omitted (`tags: [filtering, google-sharing]`). Brave ships no Google API key: brave-core sets no `google_api_key` GN arg (`build/commands/lib/buildArgs.ts:12-36` at `v1.98.60`, same on `1.99.x` and master), and neither of its Google API-key args reaches `GetAPIKey()` (`brave_google_api_key` feeds only the `location.brave.com` geolocation proxy, `components/geolocation/BUILD.gn:8-17`; `brave_safebrowsing_api_key` is Android-only, `browser/android/safe_browsing/BUILD.gn:10-15`), so `GetAPIKey()` returns Chromium's placeholder `dummytoken` (`google_apis/default_api_keys-inc.cc:18-19`, `google_apis/default_api_keys.h:19`); the 1.98.60 Linux `brave` and Windows `chrome.dll` contain no `AIza` key, and the API answers `key=dummytoken` with HTTP 400 `API_KEY_INVALID`. A non-2xx reply is a failed load with no body (`services/network/public/cpp/simple_url_loader.cc:1855-1857,2023-2024`), so the verdict is `kUnknown` (`safe_search_url_checker_client.cc:137-140`), which loads (`components/safe_search_api/url_checker.cc:111-116`) and is never cached (`:121-123`): every navigation is looked up again and nothing is blocked. Only a valid key supplied at run time would change that: the `GOOGLE_API_KEY` environment variable (honoured because Brave is not Chrome-branded, `google_apis/default_api_keys-inc.cc:141`), a `--gaia-config` file, or the `api_key` parameter of the off-by-default `kOverrideAPIKeyFeature` (`google_apis/api_key_cache.cc:36-44,89-112,133`); no Griffin study sets one. brave-core neither overrides this path nor proxies the host (no `safesearch.googleapis.com` in `components/static_redirect_helper/static_redirect_helper.cc`). The DNS filter covers the parental-control use. Dropped from the three scripts and the Strict Parental Controls preset for that reason (it fails the third and fourth conditions: the value does not mean what the label said, and sending every URL to Google is no product reason); `SlimBrave.ps1` Apply and Reset delete a leftover `1` it wrote |
| `PromotionalTabsEnabled` | ⛔ | `deprecated: true`; still dispatched through `SimpleDeprecatingPolicyHandler` with its live successor `PromotionsEnabled` (`chrome.*:128-`), both into `prefs::kPromotionsEnabled` (`configuration_policy_handler_list_factory.cc:2829-2835` at 156.0.8078.48). Not exposed either: nearly every surface that pref gates is a Chrome/Google promo Brave suppresses or never shows (sign-in, avatar, desktop-to-iOS and extensions zero-state promos, the app-menu Find-extensions item behind off-by-default `kExtensionsCollapseMainMenu`, the Windows launch-on-startup infobar behind off-by-default `kLaunchOnStartup`, which Brave also ships off in `rewrite/chrome/browser/startup/startup_features.cc.yaml`, low-priority non-toast IPH; Brave's one IPH is a toast, exempt). Its one Brave-visible effect: `false` also hides the post-update brave.com/whats-new tab, because Brave's `chromium_src/…/whats_new_util.cc` drops the argument from `ShouldShowForState` but upstream `DetermineStartupTabs` adds `GetNewFeaturesTabs` only `if (promotions_enabled)` (`startup_browser_creator_impl.cc:663-682`) |
| `IPFSEnabled` | ⛔ | see the Brave table: deprecated, feature gone since 1.69.153. On desktop the `DEPRECATE_IPFS` tombstone (`!is_android && !is_ios`) still maps it to `brave.ipfs.enabled` (`brave_simple_policy_map.h:152-155` at `v1.98.60`), a pref registered only in `RegisterProfilePrefsForMigration` so `ClearDeprecatedIpfsPrefs` can clear it at startup; nothing reads it, so a written value is accepted, flagged deprecated in `brave://policy`, and inert. Same on `1.97.x` and master |
| `PrivacySandboxAdMeasurementEnabled`, `PrivacySandboxAdTopicsEnabled`, `PrivacySandboxSiteEnabledAdsEnabled` | ⛔ dispatched, inert | `deprecated: true` (cr144), uncapped `111-`; still dispatched at 156.0.8078.48 by `PrivacySandboxPolicyHandler` (`configuration_policy_handler_list_factory.cc:3551`), which applies only `false` (`privacy_sandbox_policy_handler.cc:39-49`), into `privacy_sandbox.m1.{topics,fledge,ad_measurement}_enabled`, prefs nothing gates on any more (`PrivacySandboxSettingsImpl` no longer reads them; the Topics (`components/browsing_topics`) and Protected Audience (`content/browser/interest_group`) implementations are deleted upstream). Brave ships the APIs off regardless: `rewrite/` (with its generated `patches/`) disables `kBrowsingTopics`, `kConversionMeasurement`, `kFencedFrames`, `kPrivacySandboxAdsAPIsM1Override` and the Blink `Fledge` / `AdInterestGroupAPI` / `Parakeet` features, all asserted in `app/feature_defaults_unittest.cc`, and no Griffin study enables any of them; `renderer/brave_content_renderer_client.cc:126-130` turns off Fledge, fenced frames and Topics (`v1.98.60`; same on `1.99.x` and master) |
| `PrivacySandboxFingerprintingProtectionEnabled`, `PrivacySandboxIpProtectionEnabled` | ❌ removed | removed after cr145 / cr143: `deprecated: true`, capped `140-145` / `138-143`; no handler and no pref-mapping file at 156.0.8078.48; YAMLs unchanged on main |
| `PrivacySandboxPromptEnabled` | 💀 | `deprecated: true` (prompt configuration no longer supported), uncapped `111-`, but no handler reads it and `pref_mapping/PrivacySandboxPromptEnabled.json:3` says `Policy was removed` at 156.0.8078.48 and main |
| `ComponentUpdatesEnabled` | ✅ live, harmful | **actively harmful.** Dispatched unguarded (`configuration_policy_handler_list_factory.cc:333-335` at 156.0.8078.48), and Chromium honours it per installer (`supports_group_policy_enable_component_updates`); for an installer that returns true, update_client refuses with `UPDATE_DISABLED`, so the component freezes, or never installs if not yet present (`components/component_updater/component_updater_service.cc:339-347`, `components/update_client/component.cc:436-443` at 156.0.8078.48). Brave's `AdBlockComponentInstallerPolicy` returns true (`components/brave_shields/core/browser/ad_block_component_installer.cc:84-87`), so the Shields resources, filter-list catalog and filter lists would freeze; so would the Brave user-agent list, NTP background/sponsored images and WebMCP scripts (with AI Chat; `kWebMCP` is on by default, `chromium_src/chrome/browser/component_updater/registration.cc:67-70`), and the PSST rules, Playlist scripts and extension malware blocklist once their off-by-default features are on. Chromium's PKI metadata (CT log list, Chrome Root Store; Brave already discards its key pins), SSL error assistant and file-type policies would freeze too, as would Widevine, which Brave registers only once the user opts in. The Tor client and pluggable transports, Brave Ads resources and the Local Data Files bundle (debounce, HTTPS-upgrade exceptions, URL sanitizer, request-OTR, webcompat exceptions) ride `BraveComponentInstallerPolicy`, which returns false (`components/brave_component_updater/browser/brave_component_installer.cc:93-96`); the query filter, wallet data, P3A and local-AI installers return false too, and CRLSets keep updating (`v1.98.60`; same on `1.99.x` and master) |
| `FeedbackSurveysEnabled`, `SafeBrowsingSurveysEnabled` | ⚠️ no-op in Brave | dispatched (`configuration_policy_handler_list_factory.cc:369-371,1037-1039` at 156.0.8078.48), but brave-core's `rewrite/chrome/browser/ui/hats/hats_service_desktop.cc.yaml:15-18` makes `HatsServiceDesktop::RunCommonLaunchChecks` always return an error (`v1.98.60`; same on `1.99.x` and master), and both `CanShowSurvey` and every launch path (`ShowSurvey` → `RunLaunchChecks`) go through it (`chrome/browser/ui/hats/hats_service_desktop.cc:433-434,644-647,712` at 156.0.8078.48); no survey ever launches |
| `BrowserNetworkTimeQueriesEnabled` | ⚠️ no-op in Brave | dispatched on desktop (`configuration_policy_handler_list_factory.cc:2093-2095` at 156.0.8078.48), but `kNetworkTimeServiceQuerying` is force-disabled in Brave on every platform (`rewrite/components/network_time/network_time_tracker.cc.yaml:6-15` and its generated `patches/components-network_time-network_time_tracker.cc.patch:9-13` at `v1.98.60`; same on `1.99.x` and master), and `ShouldIssueTimeQuery` returns on that feature (`AreTimeFetchesEnabled`) before it reads the policy pref (`components/network_time/network_time_tracker.cc:453-456,740-749` at 156.0.8078.48) |
| `DomainReliabilityAllowed` | ⚠️ no-op in Brave | `app/brave_main_delegate.cc:121` (`v1.98.60`; same on `1.99.x` and master) appends `--disable-domain-reliability` unconditionally (from `BasicStartupComplete`, `:136-137`), and `ShouldCreateService` returns false on that switch before it reaches the policy check (`IsDomainReliabilityAllowed`, which reads `domain_reliability.allowed_by_policy`; `chrome/browser/domain_reliability/service_factory.cc:28-34`, `chrome/browser/net/profile_network_context_service.cc:181-184` at 156.0.8078.48) |
| `BuiltInAIAPIsEnabled` | ⚠️ no-op in Brave | Brave ships the base features behind every API the key gates disabled (`AIPromptAPI`, `AIPromptAPIMultimodalInput`, `AISummarizationAPI`, `AIWriterAPI`, `AIRewriterAPI`, `AIProofreadingAPI`; `rewrite/third_party/blink/renderer/platform/runtime_enabled_features.json5.yaml:73-101` at `v1.98.60`, same on `1.99.x` and master, asserted in `app/feature_defaults_unittest.cc:369-378`; `AIEmbeddingsAPI` is `test`-only upstream, `runtime_enabled_features.json5:351-352` at 156.0.8078.48), and each `AIManager::CanCreate*` returns `kUnavailableFeatureNotEnabled` on that check before `GetPrefBlockedResult` reads the policy pref (`chrome/browser/ai/ai_manager.cc:737-753,1802-1819` at 156.0.8078.48), so the policy is never consulted; the interfaces may stay exposed but report unavailable. Backstop: `GetOptimizationTargetForFeature` returns UNKNOWN (`chromium_src/components/optimization_guide/core/model_execution/on_device_features.cc:18-21`), so no on-device model backs them |
| `DefaultWebBluetoothGuardSetting`, `DefaultFileSystemReadGuardSetting`, `DefaultFileSystemWriteGuardSetting` | ⚠️ redundant | already feature-disabled in Brave, which is why the device-API set is USB+Serial+HID. The keys themselves are live upstream (uncapped `chrome.*:50-` / `chrome.*:86-`, dispatched by `configuration_policy_handler_list_factory.cc:648-653,1080-1082` at 156.0.8078.48), but both APIs sit behind Brave-owned `FEATURE_DISABLED_BY_DEFAULT` features (`chromium_src/third_party/blink/common/features.cc:10,12` at `v1.98.60`, same on `1.99.x` and master; no Griffin study turns either on), gated in different places: with `kFileSystemAccessAPI` (`chrome://flags#file-system-access-api`) off, `renderer/brave_content_renderer_client.cc:150-154` disables the `FileSystemAccessLocal` / `FileSystemAccessAPIExperimental` runtime features; with `kBraveWebBluetoothAPI` (`chrome://flags#brave-web-bluetooth-api`) off, `BraveBluetoothDelegate::AllowWebBluetooth` returns `kBlockGloballyDisabled` before upstream `ChromeBluetoothDelegate::AllowWebBluetooth` runs (`browser/bluetooth/brave_bluetooth_delegate.cc:19-20`). The keys bite only if a user turns those flags on |
| `DefaultThirdPartyStoragePartitioningSetting` | ❌ removed | removed after cr145: `deprecated: true`, capped `chrome.*:113-145`; no handler in `configuration_policy_handler_list_factory.cc` and `pref_mapping/DefaultThirdPartyStoragePartitioningSetting.json:3` says `Policy was removed` at 156.0.8078.48 and main (`7b96745f7dfb`) |
| `FirstPartySetsEnabled`, `RelatedWebsiteSetsEnabled`, `FirstPartySetsOverrides`, `RelatedWebsiteSetsOverrides` | ❌ removed | removed after cr152: all four `deprecated: true`; Chromium `6925f9c991` capped them `113-152` (`FirstPartySets*`) / `120-152` (`RelatedWebsiteSets*`) and deleted both `SimpleDeprecatingPolicyHandler` pairs (the `Enabled` pair into `kPrivacySandboxRelatedWebsiteSetsEnabled`, the `Overrides` pair around `FirstPartySetsOverridesPolicyHandler`) and all four pref-mapping files, so none is dispatched at 156.0.8078.48 or main (`7b96745f7dfb`); brave-core re-adds none. Moot anyway: `BravePrivacySandboxSettings::AreRelatedWebsiteSetsEnabled()` returns false and its pref observer resets `kPrivacySandboxRelatedWebsiteSetsEnabled` to false (`components/privacy_sandbox/brave_privacy_sandbox_settings.cc:29-52` at `v1.98.60`, same on `1.99.x` and master) |
| `InsecurePrivateNetworkRequestsAllowed`, `LocalNetworkAccessRestrictionsEnabled` | ❌ removed | removed after cr137 and cr144: `deprecated: true`, capped (`chrome.*:92-137`, `chrome.*:138-144`), no handler in `configuration_policy_handler_list_factory.cc` and no `pref_mapping` file at 156.0.8078.48; same on main (`7b96745f7dfb`), which adds no LNA policy. The successors are no posture switch: `LocalNetworkAccess{Blocked,Allowed}ForUrls` and the `LocalNetwork*` / `LoopbackNetwork*ForUrls` lists are URL-pattern lists, and `["*"]` in a `*BlockedForUrls` list would cut every site off from routers, NAS and local dev servers; `LocalNetworkAccessIpAddressSpaceOverrides` (cr146, restart, browser-wide) only reclassifies `cidr=` / `ip:port=` entries as public\|local\|loopback (a bare `*` is dropped); the booleans `LocalNetworkAccessRestrictionsTemporaryOptOut` ("removed after M163") and `LocalNetworkAccessPermissionsPolicyDefaultEnabled` only loosen LNA. Brave pins `kLocalNetworkAccessChecksWebSockets` at upstream's enabled default (`services/network/public/cpp/features.cc:254-255` at 156.0.8078.48; `BASE_OVERRIDDEN_FEATURE`, `rewrite/services/network/public/cpp/features.cc.yaml:12-15` at `v1.98.60`, same on `1.99.x` and master) |
| `UrlKeyedMetricsAllowed` | 🕓 future_on only | `future_on:` only (`chrome.*`, `chrome_os`, `android`, `ios`, `fuchsia`; no `supported_on:`) at 156.0.8078.48 and main (`7b96745f7dfb`), never shipped. Its handler is registered unguarded, the new half of a `SimpleDeprecatingPolicyHandler` pair with `UrlKeyedAnonymizedDataCollectionEnabled`: a `BooleanDisablingPolicyHandler` into `url_keyed_anonymized_data_collection.enabled` (`configuration_policy_handler_list_factory.cc:2680-2687`; `pref_mapping/UrlKeyedMetricsAllowed.json:42`: "UrlKeyedMetricsAllowed overrides UrlKeyedAnonymizedDataCollectionEnabled"). A `future_on` key is dropped before dispatch on the Stable and Beta channels unless `EnableExperimentalPolicies` lists it, and honoured on every other channel (`configuration_policy_handler_list_factory.cc:2602-2611,2633`; `components/policy/core/browser/configuration_policy_handler_list.cc:62-66,159-163,230-235`; brave-core's override wraps that list unchanged, `chromium_src/chrome/browser/policy/configuration_policy_handler_list_factory.cc:22-25` at `v1.98.60`), so Brave Release and Beta ignore it and Nightly (`CANARY`) applies it. On Linux the channel comes from the launcher's `CHROME_VERSION_EXTRA` (the 1.98.60 deb and zip wrappers export `stable`); the bare `brave` binary started without it resolves `UNKNOWN` and applies it too (`common/brave_channel_info_posix.cc:16-40` at `v1.98.60`). Where applied, `false` writes only the `false` that `UrlKeyedAnonymizedDataCollectionEnabled = false` already writes, while `true` writes nothing (`components/policy/core/browser/boolean_disabling_policy_handler.cc:30-32`) yet still shadows that key, leaving the pref unmanaged (`components/policy/core/browser/configuration_policy_handler.cc:831-857`) |
| `AutofillSettings` | ⚠️ feature off | `supported_on: chrome.*:154-` (`06b1ad6`, 2026-08-31) and dispatched unguarded at 156.0.8078.48 (`configuration_policy_handler_list_factory.cc:2656-2657`, `AutofillSettingsPolicyHandler` → `autofill.types_blocked`, mandatory level only, `autofill_policy_handler.cc:71-72`), but every reader (`AutofillPolicyService`, the autofill and payments clients, the Settings page) is gated on `kAutofillEnableAutofillSettingsEnterprisePolicy`, `FEATURE_DISABLED_BY_DEFAULT` at 156.0.8078.48 (`components/autofill/core/common/autofill_features.cc:714-715`), 157.0.8103.21 and main; no brave-core override (`v1.98.60`, `1.99.x`, master), no Griffin study (brave-variations `165f9af46`), and Brave builds without the field-trial testing config (`build/args/brave_defaults.gni:11`). Written today it would only fill that pref: the handler merges its entries with the `"*"` rule it already builds from a false `AutofillAddressEnabled` / `AutofillCreditCardEnabled` (`contact_info`, `payments`; `autofill_policy_handler.cc:113-147`), and with the feature off nothing blocks on the pref (`autofill_policy_service.cc:194-202,224-227,250-253`). Beside the legacy keys it is a hazard: one handler checks all three (`autofill_policy_handler.cc:76-93`) and applies none if any check fails (`configuration_policy_handler_list.cc:84-87`), so an `AutofillSettings` value at the same level that fails the schema also cancels both legacy keys, with the error shown on `AutofillSettings` alone (at 156 one bad list entry fails all of it, `SCHEMA_ALLOW_UNKNOWN`, `:70`; 157.0.8103.21 and main drop bad entries instead, `e55660b6e8`). Each policy pref store applies one level (`configuration_policy_pref_store.cc:135-138`), so a recommended `AutofillSettings`, which is refused (`configuration_policy_handler.cc:576-583`), cancels only legacy keys that are also recommended, never mandatory ones. Redundant even with the feature on: a per-URL-pattern blocklist, not a toggle, and the two Autofill keys block outside that gate (`IsCategoryGloballyBlocked`, `autofill_policy_service.cc:28-77`): a managed `AutofillAddressEnabled=false` covers `contact_info`, `identity_docs` and `travel`; `AutofillCreditCardEnabled=false` covers `payments`; `shopping` is Autofill AI, which Brave ships off (`kAutofillAiWithDataSchema`, `rewrite/components/autofill/core/common/autofill_features.cc.yaml:14-23` at `v1.98.60`); so `[{"*", ["all"]}]` adds nothing. It is the successor the legacy keys' `deprecated: true` names (`34ae451dfc`, in 156.0.8078.48) — see What's next |
| `AutofillGenAiSettings` | ⚠️ no-op in Brave | `chrome.*:156-` int-enum (`google-sharing`; unset falls back to `GenAiDefaultSettings`), dispatched unguarded at 156.0.8078.48 (`configuration_policy_handler_list_factory.cc:3598-3606,3705-3707`): `AutofillGenAiSettingsPolicyHandler` writes `autofill.personal_context.find_and_fill_with_gemini_settings` (forced to 2 while `GeminiSettings` is disabled) and, superseding `AutofillPredictionSettings`, `optimization_guide.model_execution.autofill_prediction_improvements_enterprise_policy_allowed`. Both features it governs are shipped off in Brave: smarter form understanding is Autofill AI, every action of which needs `kAutofillAiWithDataSchema` (`components/autofill/core/browser/permissions/autofill_ai/autofill_ai_permission_util.cc:220-221`; the server model also needs `kAutofillAiServerModel`, `:246-247`), and Find and Fill with Gemini needs personal-context eligibility (`components/autofill/core/browser/at_memory/at_memory_enablement_util.cc:83-90`), whose service is never built without `kPersonalContext` (`chrome/browser/personal_context/personal_context_eligibility_service_factory.cc:65-67`). Upstream ships all three on for desktop (`components/autofill/core/common/autofill_features.cc:34-35,278,418`, `components/personal_context/core/personal_context_features.cc:11`); brave-core ships them off (`rewrite/components/autofill/core/common/autofill_features.cc.yaml:7-23`, `rewrite/components/personal_context/core/personal_context_features.cc.yaml:7-10`, asserted in `app/feature_defaults_unittest.cc:148-149,302`, `v1.98.60`; same on `1.99.x` and master); no Griffin study. `2` (Disabled) would change nothing |
| `TryOnYouSettings` | ⚠️ no-op in Brave | `chrome.*:155-` int-enum (unset falls back to `GenAiDefaultSettings`), dispatched on desktop at 156.0.8078.48 into `indigo.policy` (`configuration_policy_handler_list_factory.cc:501-503`, `!IS_ANDROID`; fallback entry `:3685-3686`). Its one reader is `IndigoService`, which `CHECK`s `kIndigo` in its constructor (`chrome/browser/indigo/indigo_service.cc:214`); `kIndigo` is `FEATURE_DISABLED_BY_DEFAULT` (`chrome/common/chrome_features.cc:1285`) with no `brave://flags` entry, and brave-core pins it off (`rewrite/chrome/common/chrome_features.cc.yaml:34-37`, asserted in `app/feature_defaults_unittest.cc:220`, `v1.98.60`; same on `1.99.x` and master); no Griffin study. Try on You never runs, so `2` (Disabled) changes nothing |
| `LaunchOnStartupEnabled` | ⚠️ no-op in Brave | `chrome.win:156-`, browser-wide, recommendable; dispatched on Windows at 156.0.8078.48 into local-state `launch_on_login.foreground.enabled` (`configuration_policy_handler_list_factory.cc:1977-1979`). Brave never registers itself to open at Windows sign-in, nor shows the prompts the key suppresses: `StartupLaunchManager` reads the pref only when `IsForegroundLaunchEnabled()` and otherwise unregisters the foreground launch (`chrome/browser/startup/startup_launch_manager.cc:153-172`); that needs `kLaunchOnStartup` (`chrome/browser/startup/startup_features.cc:30-39`, the infobar too, `:41-43`), `FEATURE_DISABLED_BY_DEFAULT` upstream (`:12`) and pinned off by brave-core (`rewrite/chrome/browser/startup/startup_features.cc.yaml:6-10`, asserted on Windows in `app/feature_defaults_unittest.cc:222`, `v1.98.60`; same on `1.99.x` and master); no Griffin study. It bites only if a user turns on `brave://flags#startup-launch` (`chrome/browser/about_flags.cc:11873-11877`), which brave-core does not remove |
| `DefaultMediaStreamSetting` | ⛔ | `deprecated: true` (uncapped `chrome.*:22-`, same on main) yet still dispatched at 156.0.8078.48 (`configuration_policy_handler_list_factory.cc:671-673` into `profile.managed_default_content_settings.media_stream`, which the content-settings policy provider applies to both camera and microphone, `components/content_settings/core/browser/content_settings_policy_provider.cc:388-391`); a microphone/camera switch would use `AudioCaptureAllowed` / `VideoCaptureAllowed` (`chrome.*:25-`, `configuration_policy_handler_list_factory.cc:610-611,910-911`) |
| `BraveSearchResultAdsEnabled` | ❌ removed after 1.94.x | exists in no shipping Brave. A one-release key: merged to master 2026-07-20 (brave-core#37955) and reverted there by `cf025361c` (brave-core#38829, 2026-08-06) before `1.95.x` branched; `1.94.x`, cut in between, kept it (the revert was never uplifted), so only 1.94.x (through `v1.94.122`) and Nightly `v1.95.1`–`v1.95.47` dispatched it (`BooleanDisablingPolicyHandler` into `kOptedInToSearchResultAds`). The YAML is 404 from `v1.95.48` on and absent at `v1.98.60`, `1.99.x` and master. Its replacement, the universal pref `brave.brave_ads.sponsored.enabled` (`kSponsoredEnabled`, default true, `a723c7b00` / brave-core#39135, first in 1.96), gates NTP sponsored images and sponsored-site tiles, whether the ads service starts for a profile outside Rewards (`ads_service_impl.cc:321-323` at `v1.98.60`), and the browser side of search result ads (event and conversion reporting, `components/brave_ads/core/internal/ad_units/search_result_ad/search_result_ad_handler.cc:89` at `v1.98.60`; Brave Search serves the ads server-side, brave-browser#51040), and has no policy key: brave-browser#57204 closed 2026-09-08 on `1.96.x` shipping only a Settings toggle (brave-core#39330); neither `brave_simple_policy_map.h` nor Brave's `chromium_src` override of `configuration_policy_handler_list_factory.cc` registers one at `v1.98.60`, `1.99.x` or master; the per-unit PRs (brave-core#37956 NTP, #37957 notification) closed unmerged and brave-browser#57452 (`BraveNewTabPageAdsEnabled`) closed wontfix. brave-browser#54917 (ads policy independent of Rewards) is open, unmilestoned, and plans a `SponsoredAdsEnabled` key on that pref with no PR yet; its orphaned draft brave-core#35873 (`BraveAdsEnabled`, dropped from the issue's checklist 2026-07-15) is merge-conflicting and writes three prefs gone at `v1.98.60`. Until a key ships, `BraveRewardsDisabled` keeps the ads service off (see its row). A switch that does nothing is worse than none |

## What's next

Watch list, each with the trigger that turns it into work:

- `PsstEnabled` — dispatched in every Release since 1.95 (`ENABLE_PSST` map
  entry, `browser/policy/brave_simple_policy_map.h:160-163` at `v1.98.60`) but
  inert on Release and Beta: `kEnablePsst` is `FEATURE_DISABLED_BY_DEFAULT`
  (`components/psst/core/common/features.cc:10`) at `v1.98.60`, `v1.98.61`,
  `1.99.x` and master, and the only study enabling `EnablePsst`,
  brave-variations `EnablePsstStudy` (#1906, `d3513a7d6`, in the live seed), is
  Nightly-only (100%, Windows/macOS/Linux, from `154.1.98.30`). Trigger:
  `features.cc` flipping it on a shipping branch, or a `brave/brave-variations`
  study enabling `EnablePsst` on Release (none at `165f9af46`; `EnablePsstStudy`
  gaining Beta is the next leading indicator). Then a checkbox writing `false`,
  labelled Brave 1.95+, restart note, with no promise that `false` stops the
  rules download (the component installs whenever the feature is on); it joins
  `ORIGIN_BUILTIN_KEYS` too (`enable_psst = … && !is_brave_origin_branded`).
- Brave's HTTPS transition — brave-core added `kTransitionToUpstreamHttpsUpgrades`
  (`components/brave_shields/core/common/features.cc:128-130` at `v1.98.60`, off
  in code) and brave-variations `TransitionToUpstreamHttpsUpgrade` (#1891,
  #1939, `165f9af46`, in the live seed) turns off `HttpsByDefault` for all
  desktop Beta and Nightly and 25% of desktop Release, which leaves
  `DefaultBraveHttpsUpgradeSetting` unenforced there (see its row). Chromium's
  `HttpsOnlyMode` (`chrome.*:94-`, per-profile, dynamic refresh;
  `force_enabled` / `force_balanced_enabled` set `kHttpsOnlyModeEnabled` /
  `kHttpsFirstBalancedMode`, and either sets `kHttpsFirstModeIncognito`, as
  managed prefs through `HttpsOnlyModePolicyHandler`,
  `chrome/browser/policy/configuration_policy_handler_list_factory.cc:3022-3024`
  and `components/security_interstitials/core/https_only_mode_policy_handler.cc:46-50`
  at 156.0.8078.48; no brave-core override) is the lock on the upstream path;
  not written. Before it ships, check what `force_enabled` does on the
  `HttpsByDefault`-on arm, where Brave's interceptor pre-check
  (`chromium_src/chrome/browser/ssl/https_upgrades_interceptor.cc:18-39`) and
  `MigrateHttpsUpgradeSettings` (`browser/profiles/brave_profile_manager.cc:97-105`)
  still run; brave-browser#30950 (open since 2023-06) reports that there it
  does not lock Brave's Shields HTTPS setting. Trigger: the Release share
  rising above 25%, or brave-core dropping `kBraveHttpsByDefault`; then add an
  `HttpsOnlyMode` = `force_enabled` row beside the Brave one, or replace it.
- Brave Sponsored Ads (the 1.96 "Enable Sponsored Ads" toggle,
  `brave.brave_ads.sponsored.enabled`) — no policy key at `v1.98.60`, `1.99.x`
  or master, and none in the `v1.98.60` `policy_templates.zip`;
  `BraveRewardsDisabled` covers the in-browser ads for now by keeping the ads
  service from starting (see its row). Trigger: any new ads YAML under
  `policy_definitions/BraveSoftware` (a YAML never names its pref: watch the
  file list, not `kSponsoredEnabled`), or brave-browser#54917 gaining a
  milestone (open, unmilestoned; the issue names `SponsoredAdsEnabled`, draft
  brave-core#35873 `BraveAdsEnabled`). Then a checkbox writing the off value,
  in every preset that carries `BraveRewardsDisabled`; required once #54917
  lands, since it would decouple ads startup from Rewards and the Rewards row
  would stop covering ads. Until then: runtime-check on `v1.98.60` what the
  Rewards row states from source (with `BraveRewardsDisabled` set before
  launch: no notification ads, no NTP sponsored wallpapers, and the
  sponsored-images component registered only once the "Show background
  images" switch is turned off and on); if it does not hold, correct the row
  and the scripts' Rewards description.
- `BackgroundTabFreezingEnabled` (`686333cc22`, `chrome.*:155-`,
  `per_profile: false`, `dynamic_refresh: true`; local_state
  `performance_tuning.tab_freezing.enabled`, default on,
  `components/performance_manager/user_tuning/prefs.cc:44`) and
  `ExtensionReviewPromptsEnabled` (`23e107eaa3`, `chrome.*:154-` but landed
  after the M154 branch point; `per_profile: true`, `dynamic_refresh: true`;
  `extensions.review_prompts_allowed`, default on,
  `chrome/browser/extensions/extension_util.cc:353`) — both in the shipping
  pin, 156.0.8078.48 (`v1.98.60`; `1.99.x` and master pin the same), and both
  dispatched: `configuration_policy_handler_list_factory.cc:2338-2340` (under
  `IS_WIN || IS_MAC || IS_LINUX || IS_CHROMEOS`) and `:2267-2269` (under
  `ENABLE_EXTENSIONS_CORE`, on in every desktop build,
  `extensions/buildflags/buildflags.gni:48,72-73`); the 1.98.60
  `policy_templates.zip` lists both in `brave.admx`. Not candidates: both are
  inert by default. The tab-freezing pref feeds only
  `FreezingPolicy::SetFreezingEnabledByUser`
  (`chrome/browser/performance_manager/user_tuning/user_performance_tuning_manager.cc:288-292`),
  whose flag gates only the infinite-tabs paths, which also need
  `kInfiniteTabsFreezing` or `kInfiniteTabsFreezingOnMemoryPressure`
  (`components/performance_manager/freezing/freezing_policy.cc:507-521,1292-1307`);
  vote-based and Battery Saver freezing (`:500-506`) ignore it. Every reader
  of `extensions.review_prompts_allowed` (the extension context menus,
  `extension_context_menu_model.cc:888,962`, and `chrome://extensions`,
  `extension_info_generator.cc:921`, `developer_private_functions.cc:638`)
  goes through `ShouldShowReviewPrompt`
  (`chrome/browser/extensions/extension_ui_util.cc:160-170`) or the page's
  `cwsReviewPromptingEnabled` flag
  (`chrome/browser/ui/webui/extensions/extensions_ui.cc:487-492`), and both
  bail unless `kCWSReviewPromptingNativeUI` is on. All three features are
  `FEATURE_DISABLED_BY_DEFAULT` (`components/performance_manager/features.cc:215,235-236`,
  `extensions/common/extension_features.cc:117-119` at 156.0.8078.48; also off
  on main `7b96745f7dfb`) with no brave-core override at `v1.98.60`, `1.99.x`
  or master and no Griffin study at `165f9af46`; Brave builds with
  `disable_fieldtrial_testing_config = true`
  (`build/args/brave_defaults.gni:11`). Trigger: one of the three features on
  for desktop Release — a Chromium default flip, a brave-core `chromium_src/`,
  `patches/` or `rewrite/` override, or a Griffin study; the pin already
  carries both YAMLs, so a pin bump alone is not one. Then
  `ExtensionReviewPromptsEnabled` becomes a checkbox writing `false` in
  Performance & Bloat, in the presets that carry `DefaultBrowserSettingEnabled`:
  it hides the native "Rate it" links, which open the extension's Chrome Web
  Store review page (`chrome/browser/extensions/extension_util.cc:409-429`).
  `BackgroundTabFreezingEnabled` stays out even then: unset already means on,
  so `true` adds nothing, and `false` only keeps background tabs running.
- `AutofillSettings` and the deprecated Autofill keys — `AutofillAddressEnabled`
  and `AutofillCreditCardEnabled` are `deprecated: true` at 156.0.8078.48
  (Brave 1.98.60; `v1.98.61`, `1.99.x` and master pin the same Chromium):
  "deprecated in M156, please use AutofillSettings" (`34ae451dfc`), uncapped,
  and still applied — `AutofillSettingsPolicyHandler` maps them to their prefs
  (`autofill_policy_handler.cc:101-111`), whose readers have no feature gate;
  `brave://policy` lists them as `Deprecated`. Their successor
  `AutofillSettings` is dispatched (→ `autofill.types_blocked`) but inert: its
  readers are gated on `kAutofillEnableAutofillSettingsEnterprisePolicy`,
  `FEATURE_DISABLED_BY_DEFAULT` at 156.0.8078.48 (`autofill_features.cc:714-715`),
  157.0.8103.21 and main, no brave-core override, no Griffin study. So both
  legacy keys stay, ⚠️ with the deprecation in their descriptions: migrating now
  would leave Autofill on, and dropping them would leave SlimBrave no Autofill
  switch that works. Writing `AutofillSettings` beside them duplicates the
  `"*"` rule the handler already builds from them
  (`autofill_policy_handler.cc:113-147`), and a value at the same level that
  fails the schema cancels them (see Considered and rejected).
  Triggers: (1) the feature on at a shipping pin (Chromium default, brave-core
  or a Griffin study) — replace both keys with one `{"url_pattern": "*",
  "blocked_types": [...]}` entry as the deprecation notes prescribe
  (`contact_info`, `identity_docs`, `travel` for addresses; `payments` for
  cards) in the three scripts (on Windows a JSON `REG_SZ`, the ADMX `text`
  element), Maximum Privacy (all four types), Balanced Privacy (`payments`) and
  the preset copies embedded in `SlimBrave.ps1`; move the key from Considered
  and rejected into the Chromium table and the two legacy rows into Considered
  and rejected (`test_nothing_rejected_is_written`). (2) The legacy keys capped
  in `supported_on`, their `pref_mapping` files saying `Policy was removed`, or
  the legacy branch of `AutofillSettingsPolicyHandler::ApplyPolicySettings`
  deleted, at a shipping pin — they turn ❌ or 💀 and must go: migrate as in
  (1) if the feature is on, otherwise drop them and say in the README that
  Brave has no working Autofill policy. Neither has fired: the feature is off
  and there is no cap and no removal at 157.0.8103.21 or main
  (`7b96745f7dfb`); the YAMLs name no removal milestone.
- `BraveGlobalPrivacyControlEnabled` on Chromium's GPC — a migration plan
  posted on brave-browser#57532 (open, unmilestoned; the issue is the
  removal of `BraveProxyingURLLoaderFactory`, and the plan calls itself a
  proposal, not built) would replace Brave's own `Sec-GPC` header callback
  and `navigator.globalPrivacyControl` getter with Chromium's GPC
  implementation, whose pref is `universal_optout.enabled`
  (`components/universal_optout`), keeping Brave's WebSocket handshake
  header until a replacement exists. At 156.0.8078.48 `kUniversalOptOut` is
  `FEATURE_DISABLED_BY_DEFAULT` (`features.cc:22-24`) and
  `universal_optout.enabled` defaults to false (`prefs.cc:15`). The plan
  keeps this key's name, maps it onto that pref's managed layer and migrates
  each profile's effective setting (unset stays on). No brave-core PR
  implements it. At `v1.98.60` the key maps to
  `brave.global_privacy_control_enabled`
  (`browser/policy/brave_simple_policy_map.h:173-174`); same on `1.99.x` and
  master. Chromium has no GPC policy of its own at 156.0.8078.48 or main.
  Trigger: a brave-core change that moves that map entry or removes
  `kBraveGlobalPrivacyControl`. Then re-read the row (dispatch, the
  managed-only default, Ad Block Only Mode's injected `false`, the flag note)
  and the scripts' description.
- `kBraveNewsNewUserOptIn` (`BraveNewsDisabled`) — on first run it sets
  `brave.today.opted_in` and `brave.news.opt_in_trial`, whatever the policy,
  and reverts the opt-in after 30 days unless News was used
  (`components/brave_news/browser/brave_news_controller.cc:84-118` at
  `v1.98.60`). `FEATURE_DISABLED_BY_DEFAULT`
  (`components/brave_news/common/features.cc:29`) at `v1.98.60`, `v1.98.61`,
  `1.99.x` and master; no study on brave-variations `main` (`165f9af46`)
  enables `BraveNewsNewUserOptIn`. Trigger: the default flipping on a shipping
  branch, or a study enabling it on desktop Release. Then News is on for new
  installs wherever `brave.new_tab_page.show_brave_news` defaults on
  (`IsUserInDefaultEnabledLocale()`, `pref_names.cc:19-20`): say so in the
  News label/desc. `BraveNewsDisabled` still wins wherever
  `brave_news::IsEnabled` gates, but the sidebar News item, gated only on
  `kBraveNewsSidebar` and the opt-in (`components/sidebar/browser/sidebar_service.cc:770-783`),
  would then appear for every new profile under the policy; re-check that edge
  in the row.
- `AlternateErrorPagesEnabled` on Chromium 157. The row proves the key inert
  through brave-core's `#define NetErrorTabHelper NoTabHelper` in its
  `chromium_src/` copy of `chrome/browser/ui/tab_helpers.cc` (`:26` at
  `v1.98.60`; the same `#define` is on `1.99.x` and master). Chromium main
  now creates `NetErrorTabHelper` through `TabFeatures` (`771fe024274f`;
  `chrome/browser/ui/tabs/tab_features.cc:1295` at `7b96745f7dfb`) and has
  deleted `chrome/browser/ui/tab_helpers.{h,cc}` (`33087c269427`), so the
  `#define` stops applying. Brave's open Chromium 157 upgrade
  (brave-core#40363, branch `cr157`, pin 157.0.8103.3) drops the `#define`
  and replaces the class with one that does nothing
  (`chromium_src/chrome/browser/net/net_error_tab_helper.cc`, "Overrides the
  upstream class to be a no-op"). Its
  `browser/net/brave_net_error_tab_helper_browsertest.cc` turns the pref on
  and expects zero DNS probes. Trigger: the first shipping Brave on Chromium
  157 or later. Re-cite the row on the no-op class: it stays ⚠️ if that class
  ships. Otherwise re-audit `NetErrorTabHelper::ProbesAllowed`. No script
  change either way.
- `kSensorsAllowAskBlockPermissionModel` — still `FEATURE_DISABLED_BY_DEFAULT`
  upstream (`services/device/public/cpp/device_features.cc:21-22` at
  156.0.8078.48 and main); 156 adds a field-trial testing-config entry for it,
  which its commit calls "a prerequisite for running the feature on
  Dev/Beta/Stable" (`3160583fd8`). Brave force-enables it with a plaster
  (`rewrite/services/device/public/cpp/device_features.cc.yaml:18-21` at
  `v1.98.60`, same on `1.99.x` and master; no Griffin study names it), which
  is what makes `DefaultSensorsSetting` = 3 mean Ask (see its row). Triggers:
  (1) Chromium enabling it by default, or removing the flag together with the
  handler's 3 → Allow fallback (`default_sensors_setting_policy_handler.cc:30-41`)
  — the plaster turns redundant or stops applying; correct the row, no script
  change. (2) brave-core dropping the plaster, or a Griffin study disabling the
  feature on desktop Release, while the code default is off — 3 then means
  Allow in Brave: drop or relabel the Ask choice for this key in the three
  scripts.
- Brave Origin — real-machine runs of the deb on Debian/Ubuntu, the rpm on
  Fedora/openSUSE, Origin beta and nightly, and mixed machines with regular
  Brave beside Origin. The checklist with exact commands and expected output is
  `TESTING-brave-origin.md` on the `brave-origin-detection` branch.
- nixpkgs `brave-origin` from source — draft NixOS/nixpkgs#551523 ("brave,
  brave-origin: build from source code"; open, labelled `2.status: merge
  conflict`) replaces the deb repackage with a source build installed under
  `$out/libexec/<package>` (`browser.nix:615` at its head `6ef1f9210d58`).
  Trigger: it merges. Then re-read the whole Nix row of Where Origin lives —
  install dir, binary strings, launcher, `bin/` names — from the new
  derivation and a Hydra NAR listing.
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
- Runtime checks owed on a shipping Brave: `DefaultBrowserSettingEnabled` = false with
  *Set as default* on the first-run welcome page: source says it hits a
  `CHECK` (see its row), and brave-browser#60038 (open, unmilestoned)
  reports that crash on Brave 1.97.59 for Linux (AUR `brave-bin`): a fresh
  profile still shows the prompt and every click aborts the browser (3 of
  3); Windows, macOS and 1.98.60 are still to run; `BraveRewardsDisabled` =
  true with no `ChromeVariations`: does Brave still fetch
  `static.ads.brave.com/v1/ohttp/hpkekeyconfig` (`brave://net-export`)?
  Source says yes at `v1.98.60`. Every regular profile's ads service is
  built at profile init with no Rewards check
  (`browser/profiles/brave_profile_manager.cc:249-251`). Its `HttpClient`
  makes that credentialless GET whenever `kShouldSupportOhttp` is set: at
  startup if the stored key config has expired or was never fetched, else
  when it expires (3 days by default)
  (`components/brave_ads/core/browser/network/http_client.cc:132-135`,
  `oblivious_http_key_config.cc:46-53`, `oblivious_http_feature.h:33-35`).
  The flag is off in code (`oblivious_http_feature.cc:10`, `.h:22-23`) and
  set only by Griffin's `BraveAdsObliviousHttpStudy` (100% on Nightly, Beta
  and Release, no `policy_restriction`, so either `ChromeVariations` row
  stops the fetch). A desktop applies a Griffin seed only from its second
  launch (the first-run seed is Android/iOS only,
  `components/variations/variations_seed_store.cc:289-292` at
  156.0.8078.48), so watch a fresh profile's second launch. On `1.99.x` and
  master the fetch also needs `brave.brave_ads.sponsored.enabled` (default
  true) or Rewards with notification ads (`http_client.cc:123-136` there;
  brave-browser#59687), so the key alone still does not stop it; and the
  Sponsored Ads items above.
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
