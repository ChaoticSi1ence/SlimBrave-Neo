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
⚠️ dispatched but inert or platform-limited, caveat in the label · ⛔
deprecated upstream, not exposed · ❌ does not exist · 💀 dead: YAML present,
handler gone · 🕓 not yet in a shipping Brave, watch. `Min` is the Chromium
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
| Brave-specific keys | 2026-09-28 | brave-core `v1.96.59` (`08e68f356`), `1.97.x` (`949a7fed5`), master (`25fd2970b`); brave-variations `main` (`ac7b120e6`) | YAML + `brave_simple_policy_map.h` guards resolved through `.gni` + feature defaults and Griffin studies; one auditor and one critic per key group, two refuters (tiebreaker on a split) per finding |
| Chromium-inherited keys | 2026-09-28 | Chromium 154.0.8037.58 (tree `3eb0347`), 155.0.8059.16, `chromium/main` `a5891bb458f3`; brave-core `v1.96.59` | YAML + `configuration_policy_handler_list_factory.cc` + `pref_mapping/<Key>.json` at the tag, brave-core `chromium_src/`, `patches/`, `rewrite/`; same auditor, critic and refuter scheme |
| Content-setting enums | 2026-09-28 | Chromium 154.0.8037.58, `chromium/main` `a5891bb458f3` | schema `items:` of each `Default*Setting` key; `content_settings_registry.cc` `valid_settings`; the three scripts' import tests |
| `HardwareAccelerationModeEnabled` off state | 2026-09-28 | Chromium 154.0.8037.58, `chromium/main` `a5891bb458f3` | YAML `items:` |
| Platform policy locations | 2026-09-28 (source); Linux at runtime 2026-09-11 | brave-core `v1.96.59`, Chromium 154.0.8037.58; the 1.96.59 Brave and Origin binaries; Brave Origin 1.94.121 live | source chains; binary strings; inotify watches and a policy seen taking effect |
| Brave Origin on Linux | 2026-09-28 (source and artifacts); runtime 2026-09-11 | brave-core `v1.96.59`, `1.97.x`, master; the 1.96.59 zip, deb and rpm, beta 1.97.47 and nightly 1.98.28 debs; Flathub, Snap store and nixpkgs; a CachyOS install of 1.94.121 | artifacts checked against the apt, rpm and AUR indexes and unpacked; runtime facts from 2026-09-11 not re-run |
| Considered and rejected | 2026-09-28 | as the two key tables | as the two key tables |
| Sponsored Ads coverage | 2026-09-28 | brave-core `v1.96.59`, `1.97.x`, master; brave-browser#51040, #54917, #57204; brave-core#35873, #39810 | `ads_service_impl.cc`, `view_counter_service.cc`, `brave_settings_ui.cc`, the refreshed NTP panels; source-read, not runtime-tested |
| Ad Block Only Mode provider | 2026-09-28 | brave-core `v1.96.59`, `1.97.x`, master; brave-variations `AdblockOnlyModeStudy` | `ad_block_only_mode_policy_manager.cc`, `features.cc`, `ad_block_component_service_manager.cc`, `policy_map.cc` |

## What the project does

- Writes Chromium and Brave managed policies and, apart from the prefs
  repair below, nothing else: no binary edits, no hosts-file entries, no
  service or flag changes. The rest is delivery plumbing. `SlimBrave.ps1`
  also deletes the user-scope copy
  (`HKU\<SID>` of the invoking user after its elevated relaunch, else `HKCU`)
  of every key it manages, on Apply and Reset; an unticked or reset list
  policy that is not exactly SlimBrave's is left alone in both scopes. On
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
- **Inventory: 78 rows over 74 distinct keys** (`ChromeVariations`,
  `IncognitoModeAvailability`, `DefaultBraveReferrersSetting` and
  `HardwareAccelerationModeEnabled` have two rows each), plus
  `DnsOverHttpsMode` and `DnsOverHttpsTemplates` from the DNS section — 76
  keys written, 27 Brave and 49 Chromium. Fewer reach some machines:
  `slimbrave-mac.py` on macOS has 77 rows over 73 keys (75 written), since
  `BackgroundModeEnabled` is `chrome.win` / `chrome.linux` only; on a Linux
  machine where every Brave found is Origin (and no `--policy-file`), the
  Python scripts mark the 13 `ORIGIN_BUILTIN_KEYS` rows inert and write at
  most 63. Seven categories: Telemetry & Reporting, Privacy & Security, Site
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
  Origin on Linux). Nothing dead ships — a switch that silently does nothing
  is worse than no switch.
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

- **Shipping Brave:** 1.96.59 (Release, 2026-09-24) on Chromium
  **154.0.8037.58** (the tag brave-core `v1.96.59`, `08e68f356`, pins in
  `package.json:82`). Chromium policy definitions at that tag: tree `3eb0347`,
  1,419 policies (the named ids in `policies.yaml`; a file count must skip
  `.group.details.yaml` and the 36 `policy_atomic_groups.yaml`). `chromium/main` last read at `a5891bb458f3` (156.0.8076.0,
  tree `456167e`): 1,420 policies, +6/−5 against 154, none written by the
  scripts.
- **Brave policies:** 30 at `v1.96.59`, on `1.97.x` (`949a7fed5`) and on master
  (`25fd2970b`) — the `BraveSoftware/*.yaml` files `brave_policies.gni` lists,
  `.group.details.yaml` not counted. At the tag each has a handler, subject to
  its row's buildflag: 25 `kBraveSimplePolicyMap` entries (10 unguarded, 15
  under a buildflag; `IPFSEnabled`'s is a tombstone) plus the five
  `DefaultBrave*Setting` handlers. 30 on every release branch since `1.94.x`:
  master reverted
  `BraveSearchResultAdsEnabled` (`cf025361c`) and added `PsstEnabled`
  (`13a8fd8cc`) before `1.95.x` branched, so no branch carries both.
- **Branch pins** (`package.json:82`): `v1.94.121` → 152.0.7977.83; `1.95.x`
  (last tag `v1.95.104`) → 153.0.8010.53; `v1.96.59`, `1.96.x` and `1.97.x`
  (`949a7fed5`, 3 commits past tag `v1.97.48`) → 154.0.8037.58; master
  (`25fd2970b`) → 155.0.8059.16, first tagged as nightly `v1.98.34` (earlier
  1.98 nightlies are on 154). Recent branches were cut a milestone low and
  upgraded before their first Release: `1.94.x` 151→152 (`5d053cbbf`),
  `1.95.x` 152→153 (`13fb96678`), `1.96.x` 153→154 (`ca54d24da`).
- **Milestones, not versions.** `supported_on` counts Chromium milestones
  (`cr138`), and the mapping to Brave releases drifts by whole versions:
  `EmailAliasesEnabled` is `chrome.*:147-` yet first ships in Brave 1.92;
  `BraveLocalAIEnabled` is `chrome.*:149-` yet first ships in 1.94;
  `PsstEnabled` is `chrome.*:147-` yet first ships in 1.95. Any Brave
  version in a row label comes from probing the release branches —
  `raw.githubusercontent.com/brave/brave-core/<1.9N.x>/components/policy/resources/templates/policy_definitions/BraveSoftware/<Key>.yaml`,
  walking until it stops 404ing — never from milestone arithmetic. Rough
  alignment for orientation only: cr138 ≈ 1.80 … cr154 ≈ 1.96, the milestone
  each minor ships on at Release (minor + 58 for every Release from 1.76 to
  1.96); pre-release pins read low until the branch's upgrade, so beta
  `1.97.x` (154) and master (155) may still move.
- **Authorities:** Chromium's `policy_definitions/` YAML and brave-core's
  `BraveSoftware/` YAML for existence and schema, a Chromium YAML as amended by
  brave-core's `patches/components-policy-resources-templates-policy_definitions-*.yaml.patch`
  (two at `v1.96.59`, both on written keys: `MetricsReportingEnabled` drops
  `sensitive: true`, `DnsOverHttpsMode` drops
  `default_for_enterprise_users: 'off'`); `configuration_policy_handler_list_factory.cc`
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
| BraveP3AEnabled | ✅ | cr138 | bool | map, unguarded | unset = enabled; restart; browser-wide |
| BraveStatsPingEnabled | ✅ | cr138 | bool | map, unguarded | unset = enabled; restart; browser-wide. The pref (`brave.stats.reporting_enabled`) also stops SERP-metrics collection (`SerpMetricsTabHelper::DidFinishNavigation` returns early, `browser/serp_metrics/serp_metrics_tab_helper.cc:115-117`; `kSerpMetricsFeature` on by default), whose Brave/Google/other search counts the ping carries, and both referral initialization and finalization (`BraveReferralsService`: `InitReferral` skips the promo-code request, `MaybeCheckForReferralFinalization` clears the download ID) |
| BraveGlobalPrivacyControlEnabled | ✅ | cr142 | bool | map, unguarded | dynamic refresh; unset = enabled, no Settings toggle: `IsGlobalPrivacyControlEnabled` returns true unless the pref is managed (`components/global_privacy_control/global_privacy_control_utils.cc:16-22`), so `true` matches the default and only outranks Ad Block Only Mode's injected `false` (see Cross-cutting) and pins against a default flip. `Sec-GPC` and `navigator.globalPrivacyControl` sit behind `kBraveGlobalPrivacyControl`, on by default; `brave://flags/#brave-global-privacy-control-enabled` turns the feature off and the policy cannot override it |
| BraveDeAmpEnabled | ✅ | cr140 | bool | map, unguarded | dynamic refresh |
| BraveDebouncingEnabled | ✅ | cr140 | bool | map, unguarded | dynamic refresh |
| BraveTrackingQueryParametersFilteringEnabled | ✅ | cr142 | bool | map, unguarded | dynamic refresh; only effective while Shields is enabled (`ctx->allow_brave_shields()`); unset = enabled, no user toggle (the pref is read only when managed, `browser/net/brave_site_hacks_network_delegate_helper.cc:58-67`), so `true` matches the default and only keeps filtering on against Ad Block Only Mode's injected `false` (see Cross-cutting) |
| BraveReduceLanguageEnabled | ✅ | cr140 | bool | map, unguarded | dynamic refresh; the pref defaults on with a Settings toggle, so the key locks it. Acts only where Shields are up and fingerprinting is not off: `ShouldDoReduceLanguage` (`components/brave_shields/core/browser/brave_shields_utils.cc:374-390`) bails when Shields are down, when fingerprinting is `ALLOW` for the site (e.g. `DefaultBraveFingerprintingV2Setting` = 1) or on a `BRAVE_WEBCOMPAT_LANGUAGE` exception; `navigator.languages` and the font restriction are gated the same way through farbling OFF |
| BraveRewardsDisabled | ✅ | cr105 | bool | map, `ENABLE_BRAVE_REWARDS` | true = disable; restart. **Also stops Sponsored Ads, except Brave Search's.** It keeps the ads service from starting (`AdsServiceImpl::CanStartBatAdsService` returns false when `brave_rewards::IsSupported` fails, `ads_service_impl.cc:285-290`; the first start waits on `PolicyInitializationWaiter`, 214-219), so no notification ads, no NTP sponsored wallpapers (New Tab Takeover, served only via `AdsServiceImpl::MaybeServeNewTabPageAd`, which returns no ad while bat-ads is unbound, 1232-1236; the NTP falls back to a regular background, `view_counter_service.cc:218-235,390-395`) and no ad event or conversion reporting. Brave Search's own result ads are server-side and still show; the `Brave-Search-Ads` opt-out header goes only to a joined, wallet-connected Rewards profile (`search_ads_header_network_delegate_helper.cc:25-36`; brave-browser#51040, wontfix). The policy hides Settings → Privacy and security → Data collection → "Enable Sponsored Ads" (`isSponsoredAdsAllowed`, `brave_settings_ui.cc:284-286`; brave-core#39810, uplifted as #39857) and, on the default refreshed NTP, the customize panel's sponsored-images and sponsored-sites toggles (both need `rewardsFeatureEnabled` = `brave_rewards::IsSupportedForProfile`: `background_panel.tsx:188`, `top_sites_panel.tsx:64`); the "Show background images" switch remains. Edge, until restart: Clear browsing data → "Clear Brave Ads data" (shown while Rewards is not joined) runs `AdsService::ClearData`, after which `ViewCounterService::OnDidClearAdsServiceData` registers the sponsored component (`view_counter_service.cc:132-134`); wallpapers still cannot be served, but refreshed-NTP sponsored-site tiles need no ads service (`sponsored_sites_facade.cc:123-139`) and can appear for an advertiser already among the user's visited top sites. brave-browser#54917 (open, unmilestoned; the issue names `SponsoredAdsEnabled`, draft brave-core#35873 `BraveAdsEnabled`) would decouple ads startup from Rewards; when it lands this row stops covering ads and a new key is needed. Source-read at `v1.96.59`, not runtime-tested |
| BraveWalletDisabled | ✅ | cr106 | bool | map, `ENABLE_BRAVE_WALLET` | also disables web3 and decentralized DNS; restart |
| BraveVPNDisabled | ⚠️ no-op on Linux | cr112 | bool | map, `ENABLE_BRAVE_VPN` | **Windows, macOS, Android, iOS only.** `enable_brave_vpn = enable_brave_vpn_v1 \|\| enable_brave_vpn_v2`, both `(is_win \|\| is_android \|\| is_mac \|\| is_ios) && !is_brave_origin_branded` — no `is_linux`, so the `brave_simple_policy_map.h` entry is compiled out of Linux builds and the key is a silent no-op there while `brave://policy` still shows it applied. The Linux row is labelled rather than removed (`enable_brave_vpn_v2_apps` already names `is_linux`); `slimbrave-mac.py` gives it the same label and note when run on Linux. Restart |
| BraveAIChatEnabled | ✅ | cr121 | bool | map, `ENABLE_AI_CHAT` | false = disable Leo; does not cover on-device models (see BraveLocalAIEnabled); restart |
| BraveLocalAIEnabled | ⚠️ feature off on Release/Beta | cr149 — **Brave 1.94**, branch-probed | bool | map, `ENABLE_LOCAL_AI` | false = unregister and uninstall the on-device model components: EmbeddingGemma (`ejhejjmaoaohpghnblcdcjilndkangfe`, `components/local_ai/core/local_models_updater.cc:88-101,128-137`) and the on-device speech models (`nhkekccefdppopbldokibkoegppanbba`, `on_device_speech_models_component_installer.cc:60-63`); and `IsHistoryEmbeddingsFeatureEnabled()` returns false, so history is not vector-indexed (`rewrite/chrome/browser/history_embeddings/history_embeddings_utils.cc.yaml:42-45`). **Feature off on Release/Beta:** EmbeddingGemma and history search need `kHistoryEmbeddings`, `FEATURE_DISABLED_BY_DEFAULT` at 154.0.8037.58 and pinned off by brave-core (`rewrite/components/history_embeddings/core/history_embeddings_features.cc.yaml:7-13`); the speech models need `kBraveOnDeviceSpeechRecognition`, off with no brave://flags entry (`components/local_ai/core/features.cc:10-11`). Griffin turns `HistoryEmbeddings` on for 100% of desktop Nightly only (brave-variations `3502e2473b`); there EmbeddingGemma downloads at launch whether or not a profile opts in, while indexing stays a per-profile opt-in (`brave.history_embeddings_enabled`, default false). On Release and Beta the key only blocks a `brave://flags#brave-history-embeddings` opt-in. It is the only policy lever: Chromium's `HistorySearchSettings` and `GenAiDefaultSettings` never reach Brave, which replaces `IsHistoryEmbeddingsEnabledForProfile` with the feature plus that per-profile pref (`…history_embeddings_utils.cc.yaml:54-57`). Separate buildflag (`ENABLE_LOCAL_AI`) and prefs from AI Chat. Restart; browser-wide. In five presets, all but Strict Parental Controls; Brave Origin's matches Origin's own `false` default (`brave_origin_service_factory.cc:144`) |
| BraveShieldsDisabledForUrls | ✅ | cr107 | list | map, unguarded | scheme-wide patterns, see Cross-cutting; browser-wide; restart per YAML (`brave://policy` flags a change "restart required"), but applies live: Chromium's content-settings `PolicyProvider` watches the pref and re-reads the list on change (`components/content_settings/core/browser/content_settings_policy_provider.cc:462-466,769-776` at 154.0.8037.58), as for its own `*ForUrls` lists. Where Shields are off, all five `DefaultBrave*` rows, `BraveTrackingQueryParametersFilteringEnabled` and `BraveReduceLanguageEnabled` do nothing; with `https://*` and `http://*` that is every web page. De-AMP, Debouncing and GPC have no Shields check and keep working |
| BraveShieldsEnabledForUrls | ✅ | cr107 | list | map, unguarded | counterpart of the row above; browser-wide; restart per YAML but applies live, as above. Pins Shields on for matched sites: the new panel's main toggle stays clickable, but it only writes a user rule that the policy rule outranks (`components/brave_shields/resources/panel_new/components/main_card.tsx:84-87` at `v1.96.59`); `isBraveShieldsManaged` (reads only `BRAVE_SHIELDS`) greys the advanced controls. It is the only key that stops a user dropping Shields per site, which would void every `DefaultBrave*` enforcer there. If the identical pattern is in both lists this one wins and Shields stay on: Brave's patch inserts it after `DisabledForUrls` and Chromium's provider lets the last entry for an origin win (`content_settings_policy_provider.cc:47-48` at 154.0.8037.58); a narrower `DisabledForUrls` pattern still beats a broad one here. The scripts keep the two rows mutually exclusive, so only foreign files hit this |
| BraveNewsDisabled | ✅ | cr138 | bool | map, `ENABLE_BRAVE_NEWS` | restart |
| BraveTalkDisabled | ✅ | cr138 | bool | map, `ENABLE_BRAVE_TALK` | restart |
| BravePlaylistEnabled | ⚠️ feature off on Release/Beta | cr139 | bool | map, `ENABLE_PLAYLIST` | **Key live, feature off outside Nightly.** `playlist::features::kPlaylist` is `FEATURE_DISABLED_BY_DEFAULT` on every non-iOS build (`components/playlist/core/common/features.cc:13-19` at `v1.96.59`; same on `1.97.x` and master), `IsPlaylistAllowed()` requires feature **and** no policy `false`, and the only Griffin study enabling it, brave-variations `DefaultPlaylistStudy`, is Nightly-only (Windows/macOS/Linux). `false` bites on Nightly and wherever the user turns on `brave://flags/#playlist`; on Release and Beta it is a pre-emptive guard. The YAML's "enabled by default" is wrong for desktop. Restart |
| BraveWebDiscoveryEnabled | ✅ | cr138 | bool | map, `ENABLE_WEB_DISCOVERY` | unset = **disabled** by default; writing `false` locks it off and, the pref being managed, suppresses both opt-in prompts: the search.brave.com infobar shown when Brave Search is the default engine (`ShouldShowWebDiscoveryInfoBar` bails on a managed pref, `browser/web_discovery/web_discovery_cta_util.cc:85-92` at `v1.96.59`) and the welcome flow's Web Discovery step (skipped when the pref is managed); restart |
| BraveSpeedreaderEnabled | ✅ | cr138 | bool | map, `ENABLE_SPEEDREADER` | desktop only; restart |
| BraveWaybackMachineEnabled | ✅ | cr138 | bool | map, `ENABLE_BRAVE_WAYBACK_MACHINE` | desktop only; restart |
| TorDisabled | ✅ | cr78 (Win) / cr93 (mac, Linux) | bool | map, `ENABLE_TOR` | desktop only; restart; browser-wide |
| EmailAliasesEnabled | ✅ | cr147 — **Brave 1.92**, branch-probed | bool | map, `ENABLE_EMAIL_ALIASES` | **Feature on via Griffin, off in code.** Dispatched (`brave_simple_policy_map.h:156-159` under `ENABLE_EMAIL_ALIASES` = `!is_ios && !is_android && !is_brave_origin_branded`, desktop only). `components/email_aliases/features.cc:13` keeps `kEmailAliases` `FEATURE_DISABLED_BY_DEFAULT` on `1.92.x` through `1.97.x` and master, but brave-variations `EmailAliasesStudy_Release` (brave-variations#1835, `83e246fcc`, 2026-08-27) enables `EmailAliases` at 100% on Release Windows/macOS/Linux from `152.1.94.113`, and `EmailAliasesStudy` on Nightly and Beta from `149.1.93.23`; both are in the live seed. `IsEmailAliasesEnabledForProfile()` requires feature **and** pref (default `true`), so on shipping `v1.96.59` `false` removes the service and with it the settings page, context-menu entry and command; with `kBraveAccount` still off it also hides the Settings → Get started Brave Account row (`IsBraveAccountEnabledForProfile` = `kBraveAccount` **or** Email Aliases for the profile). Neither study sets `policy_restriction`, so either `ChromeVariations` row (1 or 2) filters both out (`components/variations/study_filtering.cc:213-228` at 154.0.8037.58) and `false` is then a guard. Restart |
| DefaultBraveAdblockSetting | ✅ | cr142 | int enum | own `IntRangePolicyHandlerBase` handler, unguarded (`chromium_src/chrome/browser/policy/configuration_policy_handler_list_factory.cc:32-36`) → `brave.profile.managed_default_content_settings.*` pref → content-settings policy provider (brave-core patch + `rewrite/` twin) | 1 = allow ads, 2 = block. Locks only `BRAVE_ADS` (`GetAdControlType`): standard network ad/tracker blocking. Cosmetic filtering (element hiding, scriptlets), the domain-block interstitial and Aggressive mode key off the unmanaged `BRAVE_COSMETIC_FILTERING`, which "Allow all trackers & ads" in the Shields panel (per site) or "Disabled" in `brave://settings/shields` (global) still sets to `ALLOW` (`SetAdBlockMode` / `onAdControlChange_`); the UI then reads back Standard. This key greys neither control. `BraveShieldsEnabledForUrls` greys the panel dropdown but not the settings select, which only Ad Block Only Mode greys, so the global route stays open under it. **All five `DefaultBrave*`** lock the type's default and void per-site exceptions for it (Chromium `kManagedDefaultPrefs`), but every consumer checks Shields first, so a site with Shields off escapes them |
| DefaultBraveFingerprintingV2Setting | ✅ | cr141 | int enum | same | 1 = off, 3 = standard (no value 2: retired Strict, the handler ignores it). Pins only the site-level `BRAVE_FINGERPRINTING_V2` mode, over the user's per-site mode and the remote list's `all-fingerprinting`. Per-API `BRAVE_WEBCOMPAT_*` `ALLOW` rules are unmanaged and still switch farbling off for one API on one site: Brave's remote list (`RemoteListProvider`) and the user's toggles in the Shields panel's fingerprinting details (`SetWebcompatEnabled`, not greyed by this key or by `BraveShieldsEnabledForUrls`: the details button's `isDisabled` has no managed check, `panel_new/components/advanced_settings.tsx:305-309`); both need `kBraveWebcompatExceptionsService`, on by default |
| DefaultBraveHttpsUpgradeSetting | ✅ | cr142 | int enum | same | 1 = allow HTTP, 2 = strict, 3 = standard |
| DefaultBraveReferrersSetting | ✅ | cr142 | int enum | same | 1 = permissive, 2 = cap to strict origin; both exposed as mutually exclusive rows (issue #9); never put 1 in a preset |
| DefaultBraveRemember1PStorageSetting | ✅ | cr142 | int enum | same | 1 = remember, 2 = forget when the site's last tab closes. Cleanup is skipped for any eTLD+1 where a visited host had Shields off or cookies on Allow (`EphemeralStorageTabHelper::UpdateShieldsState`). Inert whenever `kBraveShredFeature` is on: `FirstPartyStorageAreaNotInUse` honours this setting only while `GetAutoShredMode` is empty (with Shred on it returns the Auto Shred value, default `NEVER`), and the Auto Shred migration copies user rules, not the policy (no Auto Shred policy exists). Off by default on desktop at `v1.96.59`, `1.97.x` and master with no desktop Griffin study, but `brave://flags/#brave-shred` lets a user turn it on and escape a forced 2. **Trigger:** `components/brave_shields/core/common/features.cc` or a Griffin study enabling it on desktop (brave-browser#49999); then re-label the row ⚠️ |

Brave keys that exist and are **not exposed**:

| Key | Status | Why not |
|---|---|---|
| BraveSyncUrl | ✅ exists, unexposed | a custom sync-server URL, not a debloat toggle; self-hosters write it by hand |
| PsstEnabled | ⚠️ feature off | `chrome.*:147-` — **Brave 1.95**, branch-probed (YAML absent from `1.94.x` and `v1.94.122`, present in every 1.95 release; added by `13a8fd8cc`). At `v1.96.59`, same on `1.97.x` and master: YAML (restart), a `brave_simple_policy_map.h:160-163` entry into `brave.psst.settings.enable_psst` (default `true`) under `ENABLE_PSST` (`enable_psst = !is_android && !is_ios && !is_brave_origin_branded`: Windows, macOS, Linux; compiled out of the Origin-branded build), and for regular Brave with Origin purchased an Origin default of `false`, `user_settable=false` (`brave_origin_service_factory.cc:240-246`, same guard). Inert on Release and Beta: `kEnablePsst` is `FEATURE_DISABLED_BY_DEFAULT` (`components/psst/core/common/features.cc:10`) at `v1.96.59`, `1.97.x` and master, and no study on brave-variations `main` enables `EnablePsst`; `PsstTabWebContentsObserver::MaybeCreateForWebContents` and `RegisterPsstComponent` bail on it, so nothing downloads or injects; `chrome://flags#enable-psst` turns it on locally. PSST downloads per-site scripts, injects them into logged-in origins to detect sign-in, then drives the account through settings URLs flipping switches. **Trigger:** `kEnablePsst` turning on for Release — `features.cc` flipping on a shipping branch, or a brave-variations study enabling `EnablePsst` on the Release channel (how `EmailAliases` went live, `83e246fcc`); brave-variations#1906 (open since 2026-09-25, 100% on Nightly desktop ≥ `154.1.98.30`) is a leading indicator, not the trigger. Then add a checkbox writing `false`, label Brave 1.95+ (branch-probed), restart note; the key joins `ORIGIN_BUILTIN_KEYS` |
| IPFSEnabled | ⛔ | `deprecated: true`; the feature left Brave in 1.69.153 (Aug 2024), only a `DEPRECATE_IPFS` tombstone remains. **Do not re-add**; the YAML is the tiebreaker |

## Chromium-inherited keys

Dispatch for every row is `factory` unless the Notes say otherwise.

| Key | Status | Min | Type | Written | Notes |
|---|---|---|---|---|---|
| MetricsReportingEnabled | ✅ | cr8 | bool | false | restart; browser-wide. Chromium marks it `sensitive: true`, which makes `FilterSensitivePolicies` block it from a platform source on a Windows/Mac machine that is not domain-joined or MDM-managed (154.0.8037.58 `components/policy/core/common/async_policy_loader.cc:110-119`; Linux never filters); brave-core patches `sensitive: true` out of the YAML (one of its two policy-definition patches at `v1.96.59`, the other being DnsOverHttpsMode), which is the only reason an HKLM write works on a home PC. Brave registers no UMA/UKM providers (`chromium_src/chrome/browser/metrics/chrome_metrics_service_client.cc:18-24`), so in practice the key governs crash-report upload: upstream `ApplyMetricsReportingPolicy()` copies the pref into the crash-upload consent at startup and on every change (`chrome/browser/metrics/metrics_reporting_state.cc:203-209`), honoured because brave-core forces `GOOGLE_CHROME_BRANDING` in `chromium_src/components/metrics/metrics_service_accessor.cc:16-19`. Brave defaults the pref to false on Release and in Brave Origin but **true on Beta and Nightly** (`browser/metrics/metrics_reporting_util.cc:21-39`). Any managed value also suppresses Brave's post-crash "send crash reports?" dialog (`metrics_reporting_util.cc:41-60`, official desktop builds only) |
| SafeBrowsingProtectionLevel | ✅ | cr83 | int enum | 0 (no protection) | 0/1/2 valid. Brave proxies Safe Browsing through its own hosts — `safebrowsing_api_endpoint = "safebrowsing.brave.com"` in `components/safebrowsing/BUILD.gn`, and `components/static_redirect_helper/static_redirect_helper.cc` (`v1.96.59` lines 85-105) rewrites the host `safebrowsing.googleapis.com` → `safebrowsing.brave.com`, `sb-ssl.google.com` → `sb-ssl.brave.com`, `safebrowsing.google.com` (the crx list) → `safebrowsing2.brave.com` — so with Safe Browsing on, Google receives the proxied lookups but never learns which client made them, not even its IP. Upstream's hash-prefix real-time lookups, which go over an OHTTP relay (`ohttp-relay-safebrowsing-chrome.google.fastly-edge.com`, keys from `www.gstatic.com`) the rewrite does not cover, never run in Brave: `kHashPrefixRealTimeLookups` is on by default (154.0.8037.58 `components/safe_browsing/core/common/features.cc:355-367`) but `IsHashRealTimeLookupEligibleInSession()` also requires `HasGoogleChromeBranding()` (`components/safe_browsing/core/common/hashprefix_realtime/hash_realtime_utils.cc:25-31,107-110`), false in Brave, and the same check gates the OHTTP key fetch. Value 2 behaves as 1: the `safe_browsing_prefs.cc` patch makes `IsEnhancedProtectionEnabled()` false before it reads the pref. Turning it off buys almost no privacy and costs the phishing/malware interstitials; in no preset |
| SafeBrowsingExtendedReportingEnabled | ⚠️ inert | cr66 | bool | false | dispatched (`factory` → `safebrowsing.scout_reporting_enabled`) but no reporting path reads the pref: upstream `kExtendedReportingRemovePrefDependency` is `FEATURE_ENABLED_BY_DEFAULT` (154.0.8037.58 `components/safe_browsing/core/common/features.cc:305-306`, still on main; no brave-core override), so `IsExtendedReportingEnabled()` returns `IsEnhancedProtectionEnabled()` (`safe_browsing_prefs.cc:193-196`), which brave-core forces false (`chromium_src/components/safe_browsing/core/common/safe_browsing_prefs.cc:8` at `v1.96.59`). Extended reporting is off in Brave with or without the key; Brave also defaults the pref and its opt-in off (`browser/brave_profile_prefs.cc:228-235`) and hides the reporting toggle and the Enhanced radio (`browser/resources/settings/br/security_page.ts:11-38`). An enforced false only marks the Safe Browsing radio group policy-controlled and refuses Enhanced (`chrome/browser/safe_browsing/generated_safe_browsing_pref.cc:48-58,182-193`), a radio Brave already hides |
| UrlKeyedAnonymizedDataCollectionEnabled | ✅ | cr69 | bool | false | belt and braces — the pref defaults to false upstream (154.0.8037.58 `components/unified_consent/unified_consent_service.cc:198-199`) and brave-core compiles its Settings toggle out (`<if expr="_google_chrome">` around `urlCollectionToggle`, `patches/chrome-browser-resources-settings-privacy_page-personalization_options.html.patch:34-41` at `v1.96.59`); the key locks it off. Legacy half of a `SimpleDeprecatingPolicyHandler` (factory `:2682-2689`) whose successor `UrlKeyedMetricsAllowed` is still `future_on` only, so this key is the one that applies — see Considered and rejected |
| AutofillAddressEnabled | ✅ | cr69 | bool | false | `AutofillSettingsPolicyHandler` (factory `:2658-2659`) sets `autofill.profile_enabled` false (154.0.8037.58 `components/autofill/core/browser/permissions/autofill_policy_handler.cc:101-111`), read with no feature gate by `ChromeAutofillClient::IsAutofillProfileEnabled` (`chrome/browser/ui/autofill/chrome_autofill_client.cc:1059-1062`). `deprecated: true` on Chromium main only (`34ae451dfc`: "deprecated in M156, please use AutofillSettings"), not at 154.0.8037.58 or 155.0.8059.16. The successor `AutofillSettings` is dispatched at 154.0.8037.58 but feature-off (see Considered and rejected) — do not migrate until it is on |
| AutofillCreditCardEnabled | ✅ | cr63 | bool | false | the same handler sets `autofill.credit_card_enabled` false, read with no feature gate by `ChromePaymentsAutofillClient::IsAutofillPaymentMethodsEnabled` (154.0.8037.58 `chrome/browser/ui/autofill/payments/chrome_payments_autofill_client.cc:872-878`); deprecated on main by the same commit, with the same inert-successor caveat as AutofillAddressEnabled |
| PasswordManagerEnabled | ✅ | cr8 | bool | false | pref `credentials_enable_service`; false stops offer-to-save and password generation (both gated by `IsSavingAndFillingEnabled()`, 154.0.8037.58 `chrome/browser/password_manager/chrome_password_manager_client.cc:277-292`, `components/password_manager/core/browser/password_generation_frame_helper.cc:127`), but passwords already saved still autofill — `IsFillingEnabled()` does not read the pref (YAML: "previously saved passwords will still work") |
| BrowserSignin | ✅ | cr70 | int enum | 0 (disable) | restart; browser-wide. Off ChromeOS, `BrowserSigninPolicyHandler` maps 0 to `signin.allowed_on_next_startup` false. Brave has no Chrome account sign-in; that pref backs the `brave://settings/extensions` "Allow Google login for extensions" toggle, which brave-core already defaults off (`chromium_src/chrome/browser/profiles/pref_service_builder_utils.cc:31-32` at `v1.96.59`), so 0 locks it off |
| WebRtcIPHandling | ✅ | cr91 | string enum | disable_non_proxied_udp | |
| QuicAllowed | ✅ | cr43 | bool | false | restart; browser-wide |
| BlockThirdPartyCookies | ✅ | cr10 | bool | true | belt and braces — brave-core already defaults `profile.cookie_controls_mode` to block third-party (`browser/profiles/profile_util.cc:31-36`, called from `browser/profiles/brave_profile_manager.cc:183` at `v1.96.59`); the key locks it through `CookieSettingsPolicyHandler`, so the Shields global "allow all cookies" choice stops applying while per-site Shields exceptions still do. Ad Block Only Mode injects `false` at lower priority (see Cross-cutting) |
| ForceGoogleSafeSearch | ✅ | cr41 | bool | true | |
| IncognitoModeAvailability | ✅ | cr14 | int enum | 1 or 2 | 0 = enabled, 1 = disabled, 2 = forced, as two mutually exclusive rows; restart. In Brave `tor::IsIncognitoDisabledOrForced` treats 1 and 2 alike, so either row also removes Tor windows |
| SyncDisabled | ✅ | cr8 | bool | true | governs Brave Sync: brave-core's factory builds `syncer::BraveSyncServiceImpl`, a `SyncServiceImpl` subclass (`chromium_src/chrome/browser/sync/sync_service_factory.cc`) that does not override `GetDisableReasons()`, so `sync.managed` gives `DISABLE_REASON_ENTERPRISE_POLICY` and `brave://settings/braveSync` shows it disabled by the administrator. Side effect: the resulting `StopAndClear(kEnterprisePolicy)` runs Brave's override, which clears the sync code (`kSyncV2Seed`; `components/sync/service/brave_sync_service_impl.cc:207-227` at `v1.96.59`), so the device leaves its sync chain and must rejoin with a code once the policy is removed |
| BackgroundModeEnabled | ⚠️ Win/Linux only | cr19 | bool | false | **Windows and Linux only** (`chrome.win:19-`, `chrome.linux:19-`); no macOS support in Chromium; browser-wide (pref `background_mode.enabled` in local state). `slimbrave-mac.py` also runs on Linux, so it builds the row only under `sys.platform.startswith("linux")`, at index 0 of Performance & Bloat; on macOS a config or preset naming the key (Performance Focused, Maximum Privacy, Balanced Privacy, Developer) has it silently ignored — `import_settings` walks only built rows and names only keys whose value is off-enum |
| ShoppingListEnabled | ⚠️ no-op in Brave | cr107 | bool | false | dispatched (pref `shopping_list_enabled`), but its only functional reader, `commerce::IsShoppingListEligible`, fails its first gate: brave-core re-declares `kShoppingList` (off upstream too) `BASE_OVERRIDDEN_FEATURE` (`rewrite/components/commerce/core/commerce_feature_list.cc.yaml` at `v1.96.59`, listed in `base/compile_overridden_features.inc`), so the patched `FeatureList::IsFeatureOverridden` makes `IsRegionLockedFeatureEnabled` return the off flag without reaching the `us`/`en-us` launch map. Forced on by flag, it still needs a `ConsentLevel::kSync` IdentityManager primary account, which Brave never creates (Brave Sync's account lives in `BraveSyncAuthManager`). Defensive lock only; same on `1.97.x` and master |
| AlwaysOpenPdfExternally | ✅ | cr55 | bool | true | |
| TranslateEnabled | ✅ | cr12 | bool | false | Brave translates through its own `translate.brave.com`, not Google: `kUseBraveTranslateGo` is on by default (`components/translate/core/common/brave_translate_features.cc:14-15` at `v1.96.59`) and the `chromium_src` overrides of `translate_script.cc` and `translate_util.cc` point the script and requests there; Google is reached only under the test switch `--use-google-translate-endpoint`. Auto-translate is off behind `kBraveEnableAutoTranslate`. The key removes the feature, not a Google data flow |
| SpellcheckEnabled | ✅ | cr65 | bool | false | desktop only; mutually exclusive with SpellCheckServiceEnabled |
| SearchSuggestEnabled | ✅ | cr8 | bool | false | Brave registers the default false (`browser/brave_profile_prefs.cc:248-250` at `v1.96.59`) but flips it to true for every regular profile when the desktop first run found an OS-locale region of AR, AT, BR, CA, DE, ES, FR, GB, IN, IT, MX or US; a locale with no region counts as US (`browser/search_engines/search_engine_provider_util.cc:35-38,140-164`; `components/l10n/common/locale_util.cc:40-51`). On those installs the key is what turns suggestions off, and it locks the toggle |
| PrintingEnabled | ✅ | cr8 | bool | false | |
| DefaultBrowserSettingEnabled | ✅ | cr11 | bool | false | desktop only; browser-wide. From source, not runtime-tested: Brave's first-run `brave://welcome` offers *Set as default* without reading `isDisabledByPolicy` (`components/brave_welcome_ui/components/welcome/index.tsx:37-38,95` at `v1.96.59`); with this key false the click reaches Chromium's stock `DefaultBrowserHandler::SetAsDefaultBrowser`, whose opening `CHECK(!DefaultBrowserIsDisabledByPolicy())` (`chrome/browser/ui/webui/settings/settings_default_browser_handler.cc:126` at 154.0.8037.58) crashes the browser — click *Skip*. `brave://welcome-new` has the same gap (`browser/resources/brave_welcome_page/components/welcome_step.tsx:27`); same on `1.97.x` and master |
| DeveloperToolsAvailability | ✅ | cr68 | int enum | 2 (disallowed) | 2 = `DeveloperToolsDisallowed`. Does **not** stop the CDP port or pipe opening — see RemoteDebuggingAllowed: 2 refuses CDP attach to profile targets (pages, frames, workers, extensions; `AllowInspectingTarget` → `IsInspectionAllowed`, `chrome/browser/devtools/chrome_devtools_manager_delegate.cc:409-418` at 154.0.8037.58), but the browser target has no profile and passes, and its `Storage.getCookies` still returns every cookie of the last-used profile; upstream documents the split from cr155 (`89ae2af617`). Also forces `extensions.ui.developer_mode` false unless `ExtensionDeveloperModeSettings` is set (never written here), locking Developer mode off on `brave://extensions` and refusing *Load unpacked* (`chrome/browser/policy/developer_tools_policy_handler.cc:282-287`) |
| DnsOverHttpsMode | ✅ | cr78 | string enum | off / automatic / secure | browser-wide. Stock Chromium forces DoH **off** whenever this key is unmanaged on a machine that is domain-joined (Windows) or carries *any* machine-level policy (`StubResolverConfigReader::ShouldDisableDohForManaged`, `chrome/browser/net/stub_resolver_config_reader.cc:245-271`, applied at `:349-351`, 154.0.8037.58) — which every SlimBrave machine satisfies the moment it writes its first key. brave-core `chromium_src/chrome/browser/net/stub_resolver_config_reader.cc` overrides that to false, so **Not managed** keeps Brave's own automatic DoH; the companion YAML patch drops `default_for_enterprise_users: 'off'` (it only feeds `SetEnterpriseUsersDefaults`, generated under `BUILDFLAG(IS_CHROMEOS)`) and the matching "If this policy is unset, for managed devices…" desc paragraph — metadata. On Windows with Brave VPN connected over IKEv2 and its DNS helper service not live, Brave forces secure DoH to `chrome.cloudflare-dns.com` unless this key is managed or the mode is already `secure` (`ShouldOverride`, that `chromium_src` file `:32-47` at `v1.96.59`); managed and not `secure`, it shows a policy-warning dialog instead, which a "don't show again" checkbox silences (`browser/brave_vpn/dns/brave_vpn_dns_observer_service_win.cc:175-198`). WireGuard, switched on once the VPN system services install (`kBraveVPNUseWireguardService` on by default), skips this path (`:203-205`); Brave Origin has no VPN |
| DnsOverHttpsTemplates | ✅ | cr80 | string | URL template | browser-wide. **required** for `secure` and `custom`, optional for `automatic` (unset = Chromium's upgrade of the system resolver; brave-core's `kBraveFallbackDoHProvider` hook (`chromium_src/net/dns/dns_client.cc:50-51` at `v1.96.59`) appends `https://brave.cloudflare-dns.com/dns-query` there — `FEATURE_DISABLED_BY_DEFAULT`, so off on Release, but on for 100% of Beta and Nightly via the Griffin study `BraveFallbackDoHStudy`, which `ChromeVariations` 1 or 2 filters out), ignored for `off`. `secure` with an empty or unparseable template destroys name resolution — an empty one blanks the templates pref; a non-https one is stored with only a policy error, then dropped by `DnsOverHttpsConfig::FromStringLax`; either way `CanUseSecureDnsTransactions()` is false, and the system-resolver fallback is gated on `secure_dns_mode != kSecure` (crbug.com/1326526). All three scripts refuse an empty template for `custom`/`secure`; only `SlimBrave.ps1` also refuses a non-https or unparseable one (`Test-DohTemplate`), and the Python scripts also write a template with `automatic` (see What the project does) |
| PasswordLeakDetectionEnabled | ✅ | cr79 | bool | false | belt and braces: Brave defaults `profile.password_manager_leak_detection` to false (`browser/brave_profile_prefs.cc:267-270` at `v1.96.59`) and hides the settings switch (`browser/resources/settings/br/security_page.ts:50-58`); the key locks off the online breach-list check Chromium runs on credentials after a successful sign-in (`PasswordManager::OnLoginSuccessful`) and on saved logins edited in the Password Manager |
| NetworkPredictionOptions | ✅ | cr38 | int enum | 2 (never predict) | 0 = always, 2 = never (1 deprecated, read as 0). Belt and braces: Brave defaults `net.network_prediction_options` to 2 (`browser/brave_profile_prefs.cc:252-256` at `v1.96.59`) and clears any user value on every profile load (`chromium_src/chrome/browser/prefs/browser_prefs.cc:153`, run after `MigrateObsoleteProfilePrefs`), so an unmanaged Brave keeps prediction off unless Brave Sync restores a value (the pref is a `SYNCABLE_PREF`), and only a policy value of 0 turns it on reliably. The key adds the in-session lock and outranks Sync |
| PaymentMethodQueryEnabled | ✅ | cr80 | bool | false | with the pref off Chromium stops consulting payment apps: `canMakePayment()` always resolves **true** (a deliberate lie, so a site must call `show()`) and `hasEnrolledInstrument()` false, so neither reveals saved methods; Secure Payment Confirmation exempt (`components/payments/content/payment_request.cc:762-778,799-812` at 154.0.8037.58). The YAML's "no payment methods are available" is stale |
| AlternateErrorPagesEnabled | ⚠️ inert in Brave | cr8 | bool | false | no live reader in Brave. Upstream the pref gates only `NetErrorTabHelper`'s DNS-error probe to 8.8.8.8/8.8.4.4 and `CaptivePortalService::UpdateEnabledState`; brave-core never attaches `NetErrorTabHelper` (`chromium_src/chrome/browser/ui/tab_helpers.cc:28` at `v1.96.59`, `#define NetErrorTabHelper NoTabHelper`) and patches the pref out of the captive-portal check (`rewrite/components/captive_portal/content/captive_portal_service.cc.yaml` → `patches/components-captive_portal-content-captive_portal_service.cc.patch`), so captive-portal detection runs whatever the value. No web-service error page exists at 154.0.8037.58 and no settings page binds the pref; Brave defaults it to false (`browser/brave_profile_prefs.cc:224-226`). Locking it only pins `chrome.privacy.services.alternateErrorPagesEnabled` for extensions; kept as belt and braces |
| DefaultNotificationsSetting | ✅ | cr10 | int enum | 1, 2 or 3, user-selected; key omitted when Not managed | full legal enum **1 = allow, 2 = block, 3 = ask**, all exposed as a choice row |
| DefaultGeolocationSetting | ✅ | cr10 | int enum | 1, 2 or 3; omitted when Not managed | full legal enum 1 = allow, 2 = block, 3 = ask; choice row |
| DefaultSensorsSetting | ✅ | cr88 | int enum | 1, 2 or 3; omitted when Not managed | motion/orientation sensors, a fingerprinting vector; full legal enum 1 = allow, 2 = block, 3 = ask. "3 = ask" holds in Brave only because brave-core force-enables `features::kSensorsAllowAskBlockPermissionModel` (`rewrite/services/device/public/cpp/device_features.cc.yaml` → `patches/services-device-public-cpp-device_features.cc.patch` at `v1.96.59`, same on `1.97.x` and master) — the dedicated `DefaultSensorsSettingPolicyHandler` (in M152 since `8a50daa`) rewrites 3 to **Allow** when that flag is off, and stock Chromium ships it off. Brave also re-registers SENSORS with default **Block** (brave/brave-browser#4789), so Not managed in Brave is block-by-default-but-user-changeable. A policy file taken to stock Chromium with 3 means Allow |
| ExtensionInstallBlocklist | ✅ | cr86 | list | `["*"]` | blocks all installs and disables (does not uninstall) already-installed extensions, themes and apps included; component extensions (Brave's and Chromium's built-ins) and shared modules are exempt (`StandardManagementPolicyProvider::UserMayLoad`, `chrome/browser/extensions/standard_management_policy_provider.cc:107-115` at 154.0.8037.58) |
| SafeSitesFilterBehavior | ✅ | cr69 | int enum | 1 (filter) | not a local filter — every http(s) navigation, iframes and redirects included, is POSTed to Google's Safe Search API (`safesearch.googleapis.com/v1:classify`) with query, fragment and credentials stripped (`tags: [filtering, google-sharing]`); definitive verdicts are cached 1 h, failed lookups are re-sent. Fails open: a failed or non-2xx lookup is `kUnknown` (`components/safe_search_api/safe_search/safe_search_url_checker_client.cc:137-140` at 154.0.8037.58) and anything not `kRestricted` loads (`components/safe_search_api/url_checker.cc:111-116`). The request carries `google_apis::GetAPIKey()` and brave-core sets no Chromium `google_api_key` (only `brave_google_api_key`, for geolocation), so whether shipping Brave blocks anything or only sends the URLs is unverified; runtime check pending. Disclosed in the tooltip and README because the same tool ships `SafeBrowsingProtectionLevel = 0` |
| BrowserGuestModeEnabled | ✅ | cr38 | bool | false | guest windows are an off-the-record session with no saved history and none of the main profile's extensions, which `IncognitoModeAvailability` = 1 does not close (`IncognitoModePrefs::CanOpenBrowser` blocks only incognito-typed profiles, `chrome/browser/prefs/incognito_mode_prefs.cc:95-96` at 154.0.8037.58); machine policies still apply inside them (`ProfilePolicyConnector::Init` appends the platform provider for every profile, `chrome/browser/policy/profile_policy_connector.cc:521-525`). Dedicated `GuestModePolicyHandler`, Win/Mac/Linux only; Brave's menu honours it (`browser/ui/brave_browser_command_controller.cc:324-334` at `v1.96.59`); browser-wide |
| HighEfficiencyModeEnabled | ✅ | cr108 | bool | true | forces Memory Saver tab discarding on; browser-wide |
| HardwareAccelerationModeEnabled | ✅ | cr46 | bool | true / false | both states as a mutually exclusive pair (`Group = "hwaccel"`) because unset is not off: Chromium's default is on, absent means user-controlled, `false` means forced off. The off state is a troubleshooting lever for a faulty GPU driver, a VM or RDP session, or screen-sharing corruption, not a privacy posture — in no preset. Restart; browser-wide |
| EnableMediaRouter | ✅ | cr52 | bool | false | disables Cast and its LAN device discovery; restart. Brave's `media_router_feature.cc` gives the policy precedence over the `brave://settings/extensions` Media Router toggle; Tor windows are always off. Sticky: a profile whose toggle pref is still at its default when Brave starts under the policy (in practice, one created under it) gets the managed `false` copied into `brave.enable_media_router_on_restart` (`browser/profiles/brave_profile_manager.cc:166-176` at `v1.96.59`), so once the policy is removed Cast stays off until that toggle is turned back on and Brave restarted; older profiles return to their own setting |
| ChromeVariations | ✅ | cr83 | int enum | 1 or 2 | 0 = all variations, 1 = critical fixes only, 2 = none; browser-wide. Closes the last remote-configuration channel: Brave fetches a Griffin seed from `variations.brave.com` that flips features in an installed browser. Maps to `variations::prefs::kVariationsRestrictionsByPolicy`; brave-core does not override the restriction path. 1 admits only studies whose filter sets a non-`NONE` `policy_restriction` (`CheckStudyPolicyRestriction`, `components/variations/study_filtering.cc:222-223` at 154.0.8037.58), and Brave almost never tags one: in brave-variations `ac7b120` (the live seed) only `V8IgnitionElideRedundantTdzChecksKillSwitch`, capped at `139.*`, carries it and none of the other kill-switch or `Disable*` studies does, so on 1.96.59 values 1 and 2 both apply zero studies. Two mutually exclusive rows; 2 is in no preset only because it would also refuse a kill switch Brave tags critical later |
| SpellCheckServiceEnabled | ✅ | cr22 | bool | false | belt and braces — already off in Brave with no UI to turn it on: Chromium registers `spellcheck.use_spelling_service` false (`chrome/browser/spellchecker/spellcheck_factory.cc:68-69` at 154.0.8037.58), Brave re-asserts it (`chromium_src/chrome/browser/profiles/pref_service_builder_utils.cc:27-29` at `v1.96.59`), both settings controls are `_google_chrome`-only, and Brave stubs out the context-menu opt-in (`chromium_src/chrome/browser/renderer_context_menu/render_view_context_menu.cc:718-731`). The key locks the Google spelling web service off, even against a stored `true`, while offline dictionaries keep working; upstream says it has no effect once `SpellcheckEnabled` is false, hence the mutual exclusion |
| RemoteDebuggingAllowed | ✅ | cr93 | bool | false | blocks `--remote-debugging-port` / `--remote-debugging-pipe`, the CDP cookie-theft vector `DeveloperToolsAvailability` leaves open, and the approval-mode listener the `brave://inspect` remote-debugging toggle starts (`kDevToolsAcceptDebuggingConnections`, on by default on desktop, untouched by brave-core); inherited unchanged by Brave. Google Chrome also refuses both switches on the default user-data-dir, but only under `GOOGLE_CHROME_BRANDING` (`chrome/browser/devtools/remote_debugging_server.cc:169-180` at 154.0.8037.58); Brave is not `is_chrome_branded`, so the port opens on the real profile and this key is the only lock. Breaks Puppeteer, Playwright and that toggle; local-tab inspection (`DeveloperToolsAvailability`) and device discovery in `brave://inspect` keep working. Browser-wide; no restart: `dynamic_refresh: true` since 154.0.8029.0 (`80ad0b9`); set false at runtime, `BrowserProcessImpl::OnDevToolsRemoteDebuggingAllowedChanged` stops the server and pipe and clears the toggle. Lifting it starts nothing: the toggle must be turned back on and the switches need a relaunch, as does everything if the policy was in force at launch (`GetInstance` returned `kDisabledByPolicy`) |
| DNSInterceptionChecksEnabled | ✅ | cr80 | bool | false | stops the three random 7–15 character hostname lookups at startup and on every network change, a per-launch beacon to the ISP or DoH resolver; browser-wide |
| BasicAuthOverHttpEnabled | ✅ | cr88 | bool | false | refuses HTTP Basic auth over cleartext; breaks legacy plain-HTTP appliance logins; browser-wide |
| DefaultWebUsbGuardSetting | ✅ | cr67 | int enum | 2 or 3; omitted when Not managed | **2 = block, 3 = ask — no value 1** in the schema, so the row offers Not managed / Ask / Block. Ships enabled in Brave. Breaks Ledger/Trezor web wallets and in-browser firmware flashers |
| DefaultSerialGuardSetting | ✅ | cr86 | int enum | 2 or 3; omitted when Not managed | 2 = block, 3 = ask, no 1; breaks in-browser microcontroller tooling |
| DefaultWebHidGuardSetting | ✅ | cr100 | int enum | 2 or 3; omitted when Not managed | 2 = block, 3 = ask, no 1; may break security keys and gamepad configurators that use WebHID rather than WebAuthn. Block also cuts Brave Wallet's own Ledger connection (source-read, not runtime-tested): the `chrome-untrusted://ledger-bridge` frame uses `TransportWebHID`, `HidService` checks the guard against the wallet's `chrome://` main-frame origin (`content/browser/hid/hid_service.cc:438-442` at 154.0.8037.58), `HID_GUARD` allowlists no scheme, and Brave's HID overrides only waive the user-gesture requirement and swap in the wallet's own chooser, both after that check (`browser/hid/brave_hid_delegate.cc:22-53` at `v1.96.59`), so `requestDevice` and `getDevices` come back empty. The device-API set is USB+Serial+HID because WebBluetooth and File System Access are already feature-disabled in Brave |
| DefaultLocalFontsSetting | ✅ | cr103 | int enum | 2 or 3; omitted when Not managed | 2 = block, 3 = ask, no 1; `queryLocalFonts()` returns the installed font list, a top-tier fingerprint that Shields' farbling does not cover |
| DefaultWindowManagementSetting | ✅ | cr111 | int enum | 2 or 3; omitted when Not managed | 2 = block, 3 = ask, no 1; stops sites reading the multi-monitor topology; complementary to `kBraveBlockScreenFingerprinting`, which is about screen size |
| BlockExternalExtensions | ✅ | cr80 | bool | true | closes the sideload channel bundleware uses: on Windows Chromium's hard-coded `Software\Google\Chrome\Extensions` key, read from HKLM's 32-bit view (`WOW6432Node` on 64-bit Windows) and HKCU (`chrome/browser/extensions/external_registry_loader_win.cc:38,88-95` at 154.0.8037.58), which brave-core does not repoint, so a sideload registered for Chrome also reaches Brave; on macOS and Linux `external_extensions.json` / `<id>.json` drop-ins. Unmanaged, such extensions arrive disabled behind an approval prompt on Windows and macOS (`prompt_for_external_extensions`) and install silently on Linux; with the policy they never load. User-chosen extensions keep working, unlike `ExtensionInstallBlocklist: ["*"]`; restart |

Every key above fetches 200 at Chromium 154.0.8037.58 and at main
`a5891bb458f3` (156.0.8076.0); none is upper-bounded or `future_on:`-only on
desktop at either ref, none is `deprecated:` at the tag, and no
`pref_mapping/<Key>.json` says `Policy was removed` at either. 44 of the 49
YAML files are byte-identical between tag and main. Of the five that differ,
`AutofillAddressEnabled` and `AutofillCreditCardEnabled` are `deprecated: true`
on main ("deprecated in M156, please use AutofillSettings", `34ae451dfc`; not
in 155.0.8059.16, so in no Brave channel yet); both are still mapped to their
prefs there by `autofill::AutofillSettingsPolicyHandler`
(`components/autofill/core/browser/permissions/autofill_policy_handler.cc:95-111` at the
tag, identical on main), and `AutofillSettings` is already `chrome.*:154-` and
dispatched at the tag but feature-off (see AutofillAddressEnabled). The other three change nothing on desktop:
`DefaultWebHidGuardSetting` moves `android` from `future_on:` to
`android:155-`; `RemoteDebuggingAllowed` adds `android:155-` and Android
wording; `DeveloperToolsAvailability` changes text only (`8641e99e05`,
`89ae2af617`), the new text documenting the per-target CDP inspection gate
that 154 already enforces (see its row). The 27 Brave YAMLs the scripts write
are byte-identical between `v1.96.59` and `1.97.x`, and against master
`25fd2970b` all but `BraveLocalAIEnabled` (description wording,
`3900f295f9`). Every Chromium-inherited key is cr111 or older, and every Brave
key cr142 or older except the two branch-probed rows (cr147, cr149), so all
are present in any Brave still receiving updates.

## Brave Origin on Linux

Origin is Brave with Rewards, Wallet, VPN, Leo, News and friends removed at
build time (`is_brave_origin_branded`); free on Linux, a paid upgrade on
Windows and macOS. Artifact facts are verified on the shipped 1.96.59
artifacts (brave-core `v1.96.59`, Chromium 154.0.8037.58), each equal to its
v1.96.59 GitHub release asset digest — `brave-origin_1.96.59_amd64.deb`
(132,484,356 B, sha256 `447bc5ac…5613`, the bytes the apt `Packages` index
lists) and `brave-origin-1.96.59-1.x86_64.rpm` (134,303,141 B, sha256
`3de65c3f…8400`, as the rpm `primary.xml` lists), both unpacked, and
`brave-origin-1.96.59-linux-amd64.zip` (186,384,117 B, sha256
`ad71abea…3797`, the AUR `brave-origin-bin` 1:1.96.59-1 `sha256sums_x86_64`),
read in place. The runtime facts — the inotify watches, the
`ExtensionInstallForcelist` install, `--import` in `chrome://policy`, the
`chrome://policy/test` injection — rest on a real 1.94.121 install of the AUR
zip on CachyOS. `SlimBrave.ps1` has no Origin-specific code.

- **Origin reads `/etc/brave/policies/managed`, like regular Brave.** Source:
  `app/brave_main_delegate.cc:166-170` overrides `chrome::DIR_POLICY_FILES` to
  `/etc/brave/policies` under `IS_POSIX && !IS_MAC` with no branding or channel
  guard; Chromium's `config_dir_policy_loader.cc`, unpatched, appends
  `managed` and `recommended`. Binary: the 1.96.59 Origin ELF — byte-identical
  across zip, deb and rpm, 304,713,024 B, sha256 `03587912…5fbf` — holds
  `/etc/brave/policies` and `BraveSoftware/Brave-Origin` and no
  `/etc/brave-origin` string, as do the beta 1.97.47 and nightly 1.98.28 ELFs.
  Runtime: a
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
  one file for every channel, so the path takes no channel suffix); Chromium's `postinst.include:79-104`,
  run by the deb `postinst` and the rpm `%post`, creates it only when
  `/etc/default/brave-origin[-beta|-nightly]` holds
  `install_device_trust_key_management_command=true`, and only to hold
  `DeviceTrustSigningKey`. The browser reads nothing there. Chrome Browser
  Cloud Management is off in a non-Chrome-branded build unless the browser is
  launched with `--enable-chrome-browser-cloud-management`
  (`chrome_browser_cloud_management_controller.cc:102-116`, 154.0.8037.58; not
  overridden); only then does it read
  `/etc/brave/policies/enrollment/CloudManagementEnrollmentToken`
  (`DIR_POLICY_FILES`), and the Device Trust key from
  `/etc/chromium/policies/enrollment` (`kPolicyPath`, not overridden). Never
  write policies there.
- **Where Origin lives**, every row read from the artifact (stable 1.96.59,
  beta 1.97.47, nightly 1.98.28; Nix from the derivation and the NAR listing
  of Hydra's 1.95.104 build):

| Packaging | Install dir | Binary | Launcher | On `PATH` | Profile |
|---|---|---|---|---|---|
| Arch: AUR `brave-origin-bin` (CachyOS mirrors it); unpacks the upstream zip | `/opt/brave-origin-bin/` | `brave` | `brave-origin`, Chromium's wrapper as brave-core's `chrome-installer-linux-common-wrapper.patch` leaves it (no `exec -a`, so bash stays the browser's parent), byte-identical to the deb/rpm launcher | `/usr/bin/brave-origin`, a bash script that reads `~/.config/brave-origin-flags.conf` and execs the launcher | `~/.config/BraveSoftware/Brave-Origin` |
| deb: `brave-origin`, from the same `brave-browser-apt-release.s3.brave.com` repo as `brave-browser`; no Conflicts, both co-install | `/opt/brave.com/brave-origin/` | `brave` | `brave-origin` | `/usr/bin/brave-origin-stable`, shipped symlink; bare `/usr/bin/brave-origin` via `update-alternatives` in postinst | same |
| rpm: `brave-origin`, from `brave-browser-rpm-release.s3.brave.com` through the `brave-browser.repo` Brave's Origin page gives (dnf, zypper, rpm-ostree); the CDN generates every `brave-browser*.repo` response, so `brave-browser-origin.repo`, `-origin-beta`, even `brave-browser-foo.repo` return that bucket's one `[brave-browser]` release file — aliases, not Origin repos; `brave-origin-beta` and `-nightly` come only from the `brave-browser-rpm-beta` / `-nightly` buckets | `/opt/brave.com/brave-origin/` | `brave` | `brave-origin` | `/usr/bin/brave-origin-stable`, shipped; bare `/usr/bin/brave-origin` is a `%ghost` from `%post`'s `update-alternatives` | same |
| Beta, Nightly: `brave-origin-beta`, `brave-origin-nightly` (apt/rpm beta and nightly repos; Brave's AUR `*-bin` repackage the GitHub-release deb) | `/opt/brave.com/brave-origin-beta/`, `…-nightly/` | `brave` | `brave-origin-beta`, `-nightly`, with a `brave-origin` symlink to it in the same dir | deb/rpm: `/usr/bin/brave-origin-beta`, `-nightly`, direct symlinks; each also registers the bare `/usr/bin/brave-origin` alternative (the rpms `Provides: brave-origin` and `%ghost` it); priorities, deb/rpm: stable 201/200, beta 151/150, nightly 1/0 (brave-core's channel `nightly`, `build/linux/channels.gni:24-25`, falls to Chromium's `* ) PRIORITY=0`; only the deb postinst patch adds 1), so in auto mode without stable Origin a bare `brave-origin` is the beta if installed, else the nightly. AUR: a bash wrapper replaces `/usr/bin/brave-origin-<ch>` and registers no alternative | `Brave-Origin-Beta`, `Brave-Origin-Nightly` — the suffixes of `common/brave_channel_info_posix.cc:33-38` |
| Nix: nixpkgs `brave-origin` (`pkgs/applications/networking/browsers/brave/`, x86_64/aarch64-linux; 1.96.59 on master `e9227ddbcc`, 1.95.104 on nixos-unstable, absent from nixos-26.05); repackages the GitHub-release deb (amd64: the apt bytes, sha256 `447bc5ac…5613`) | `/nix/store/…-brave-origin-<ver>/opt/brave.com/brave-origin/` | `brave`; only interpreter and rpath patched (with `chrome_crashpad_handler`), strings untouched | `brave-origin`, the deb's launcher with `/bin/bash` and `CHROME_WRAPPER` rewritten; `bin/brave-origin` is a wrapGAppsHook3 wrapper around it | `bin/brave-origin` only (no `brave-origin-stable`), through whichever Nix profile installed it: `/run/current-system/sw/bin`, `/etc/profiles/per-user/<user>/bin`, `~/.nix-profile/bin` | `~/.config/BraveSoftware/Brave-Origin` |
| Flatpak | no official one. Flathub has only `com.brave.Browser`; every Origin-shaped id 404s; `flathub/com.brave.Browser` has no Origin branch, issue or PR; brave/brave-browser #55196 asking for one is open. Brave's RDN for Origin, `com.brave.Origin` (`chromium-browser.info:34`), names the deb/rpm's `NoDisplay` portal desktop file (next bullet) and two unofficial Flatpaks: FlatPark's (`flatpark/flatpark` `registry/com.brave.Origin`, a bot-refreshed extra-data pin of the official zip; profile `~/.var/app/com.brave.Origin/config/BraveSoftware/Brave-Origin`) and a stale one-star bundle of the 1.93.134 deb (`jfrmorales/brave-origin-flatpak`). Neither reads host policy: neither grants `host-etc` nor links `/run/host/etc/brave/policies` into the sandbox's `/etc/brave/policies` as Flathub's `brave.sh:3-11` does, and Flatpak will not expose `/etc` paths, so no permission override helps. A third, `io.github.shyvortex.BraveOrigin` (`ShyVortex/brave-origin-flatpak`, `.flatpak` release bundles of the official zip), copies Flathub's `host-etc` grant and `brave.sh`, so it does read `/etc/brave/policies`. No official Flatpak to probe | | | | |
| Snap | none. The store has `brave` only (Brave Software, verified); `brave-origin` is `resource-not-found`; the `brave` snap's channel map is `latest/{stable,candidate,beta,edge}`, its squashfs holds `opt/brave.com/brave/` only and its binary says `Brave-Browser`. Likely, not confirmed: snapd's `browser-support` interface grants `/etc/opt/chrome` and `/etc/chromium` and nothing under `/etc/brave`, and the `brave` snap (stable rev 686, 1.96.59) adds nothing — no `system-files` or `personal-files` plug, a `layout` binding only `/usr` paths, no other plugged interface granting `/etc/brave`; that is the mechanism behind the tool's Snap warning | | | | |

- **Names the detector relies on.** Profile:
  `chromium_src/chrome/common/chrome_paths_linux.cc:26-27` —
  `BraveSoftware/Brave-Origin` plus the channel suffix under
  `IS_BRAVE_ORIGIN_BRANDED`. Package: `build/config.gni:71-79`
  (`brave_linux_package_name = "brave-origin"`), `installer/linux/sources.gni:8-9`.
  Desktop ids: `chromium_src/chrome/common/channel_info_posix.cc:64-74` —
  `brave-origin[-beta|-nightly|-dev].desktop`; the deb/rpm also ship a
  `NoDisplay=true` twin for the XDG-portal app id,
  `com.brave.Origin[.beta|.nightly].desktop` (`RDN`,
  `chromium-browser.info:34`; Chromium `installer.py:527-533,959-984`,
  154.0.8037.58). `StartupWMClass` is the package name after the channel
  suffix (`installer.py:529,535`, `desktop.template:110`): `brave-origin` on
  stable, `brave-origin-beta`, `-nightly` otherwise. Processes: the browser's
  comm is `brave` on every packaging; the launcher's bash process stays alive
  around it (brave-core's `chrome-installer-linux-common-wrapper.patch` drops
  Chromium's `exec -a`) with the comm it was started by — `brave-origin` from
  the AUR wrapper, `brave-origin-st` (comm's 15-character cap) from the deb/rpm
  desktop file's `brave-origin-stable`; the profile's `SingletonLock` covers
  the truncated case. The shipped man page's `$HOME/.config/brave-origin` is
  Chromium template text and wrong.
- **What the tool does with it.** `LINUX_CHANNELS` carries `origin`,
  `origin-beta`, `origin-nightly` (no `origin-dev`: named in source, never
  published). `detect_brave()` probes `/opt/brave-origin-bin/brave`,
  `/opt/brave.com/brave-origin/brave-origin`, `/opt/brave.com/brave-origin/brave`
  (still the 1.96.59 zip, deb and rpm layout) and, only when no Brave at all
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
  non-Origin-branded builds while `kBraveOrigin`, on by default, is enabled,
  hidden once purchased): `ProceedFree` → `BraveOriginService::AcceptFreeTier`
  (`brave_origin_settings_handler_impl.cc:95-102`, `brave_origin_service.cc:319-324`)
  sets `brave.origin.free_tier_accepted` and, through
  `BraveOriginPolicyManager::SetPurchased(true)`, `brave.origin.purchase_validated`
  in `Local State`. The page then loads `brave://settings/origin` (routed only
  once purchased, `page_visibility.ts:132-133`), whose purchase check counts
  the free tier as a purchase and sets `brave.origin.policies_were_enforced`
  (`brave_origin_service.cc:257-273`); toggles live in
  `brave.brave_origin.policies`. Same binary, same `Brave-Browser` profile,
  every feature compiled in, the Flatpak included. Nothing for the detector to
  do; every row live.
- **A managed file outranks Origin's own layer; it cannot revive what Origin
  compiled out.** Origin enforces its debloat through `BraveBrowserPolicyProvider`
  and `BraveProfilePolicyProvider`, which emit `POLICY_SOURCE_BRAVE` at
  `kBravePriority` — inserted below `kEnterpriseDefault`, the lowest browser
  priority, per brave-core's own `BravePolicySourceTest.BraveHasLowerPriority`.
  Both load Origin's set only when `IsBraveOriginPurchased()`
  (`brave_browser_policy_provider.cc:65-67`, `brave_profile_policy_provider.cc:100-102`
  at `v1.96.59`): `kBraveOrigin`, on by default, plus a validated purchase or,
  on Linux, the accepted free tier (`AcceptFreeTier`,
  `brave_origin_service.cc:319-324`; re-applied at startup, `:74-80`). Until
  then Origin's layer is empty and only Ad Block Only Mode writes
  `POLICY_SOURCE_BRAVE`; the branded build's startup dialog stands before the
  first window until one of the two holds (`brave_origin_startup_view.cc:87-111`).
  `PolicyMap::MergeFrom` resolves on (level, priority), so a mandatory platform
  entry wins every conflict: `{"BraveP3AEnabled": true}` would switch P3A back
  on in Origin. Nothing this tool writes points that way.
- **Thirteen rows are dead on Origin, and the tool shows them inert.** Each
  key's `brave_simple_policy_map.h` entry sits under a buildflag whose `.gni`
  is `… && !is_brave_origin_branded`: `BraveRewardsDisabled` (`ENABLE_BRAVE_REWARDS`),
  `BraveWalletDisabled`, `TorDisabled`, `BraveVPNDisabled`, `BraveAIChatEnabled`,
  `BraveLocalAIEnabled`, `BravePlaylistEnabled`, `BraveWebDiscoveryEnabled`,
  `BraveNewsDisabled`, `BraveTalkDisabled`, `BraveSpeedreaderEnabled`,
  `BraveWaybackMachineEnabled`, `EmailAliasesEnabled`. A fourteenth, `PsstEnabled`
  (`ENABLE_PSST`, `enable_psst = !is_android && !is_ios && !is_brave_origin_branded`;
  `brave_simple_policy_map.h:160-163` at `v1.96.59`), is dead on Origin too;
  the tool does not write it, and exposing it would add it to
  `ORIGIN_BUILTIN_KEYS`. Confirmed on the 1.94.121 binary: nothing registered
  under `brave.wallet`, `brave.ai_chat`, `brave.playlist`, `brave.speedreader`,
  `brave.news`, `brave.talk`, `brave.email_aliases`, `brave.web_discovery`,
  `brave.wayback`, no `tor.*`, and injecting every Brave key as a mandatory
  machine policy through `chrome://policy/test` made none of the thirteen prefs
  managed — while `brave://policy` listed each as applied, the same blind spot
  the `BraveVPNDisabled` row documents. At `v1.96.59` each target pref is registered only behind its key's own
  flag, `brave.local_ai_enabled` (Local State, `brave_local_state_prefs.cc:184-186`)
  and `brave.brave_vpn.disabled_by_policy` (built only `if (enable_brave_vpn)`,
  on no Linux build) included, except `brave.rewards.disabled_by_policy`:
  registered unguarded (`brave_profile_prefs.cc:620`), reached by no policy
  once its map entry is compiled out. `BraveP3AEnabled` and `BraveStatsPingEnabled` are dispatched
  (unguarded, `brave_simple_policy_map.h:124-127`); once Origin counts as
  purchased its layer emits both at the lowest priority with the user's
  `brave://settings/origin` toggles, default `false`
  (`brave_origin_service_factory.cc:131-139`), so a managed `false` equals the
  default and pins them against those toggles. Origin compiles out the usage
  pinger itself (`enable_brave_stats_updater = !is_brave_origin_branded`,
  `browser/brave_stats/buildflags.gni:11`), but `kStatsReportingEnabled` stays
  registered (`brave_local_state_prefs.cc:174-179`) and still gates referral
  initialisation and SERP-metrics recording, so the key stays live and out of
  `ORIGIN_BUILTIN_KEYS`. `MetricsReportingEnabled` is live (Chromium simple map,
  `configuration_policy_handler_list_factory.cc:1177-1179` at 154.0.8037.58);
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
  (`v1.96.59`; identical on `1.97.x` and master) builds Origin's debloat set by
  walking `kBraveSimplePolicyMap` and keeping each pref found in
  `kBraveOriginBrowserMetadata` (4) or `kBraveOriginProfileMetadata` (12) —
  sixteen prefs, fifteen at `v1.94.121` before `PsstEnabled`. Fifteen map to
  keys this project exposes, and for every one the value the project writes
  equals Origin's default (the Brave Origin preset). The sixteenth is
  `PsstEnabled`, dispatched but inert while `kEnablePsst` is off (see its row);
  its Origin entry (`false`, `user_settable=false`, `:240-246`) shares the
  `ENABLE_PSST` guard, so it applies only in regular Brave's Origin mode; the
  project does not expose it. Each build gets the subset its buildflags
  compile: regular Brave in Origin mode gets sixteen on Windows and macOS and
  fifteen on Linux, where `enable_brave_vpn` (Windows/macOS/Android/iOS only)
  drops the VPN profile entry and its map entry; the branded build keeps only
  P3A and the stats ping, both user-toggleable in Origin's settings, so a
  managed `false` is what locks them. De-AMP, Debouncing, query-parameter
  filtering, GPC and Reduce Language (each registered default `true`) and the
  two Shields lists are in `kBraveSimplePolicyMap` but in neither table: Origin
  leaves the five toggles at their enabled-by-default user setting, the
  direction the project forces, and the lists unset.

## Platform policy locations, from source

- **Windows** — `HKLM\SOFTWARE\Policies\BraveSoftware\Brave`. Chromium's
  `components/policy/tools/generate_policy_source.py` emits
  `kRegistryChromePolicyKey` from `CHROMIUM_POLICY_KEY` for non-Google branding;
  brave-core's `chromium_src/…/generate_policy_source.py` overrides the constant
  to `SOFTWARE\Policies\BraveSoftware\Brave`; `chrome_browser_policy_connector.cc`
  hands it to `PolicyLoaderWin`. brave-core's
  `chromium_src/chrome/browser/policy/chrome_browser_policy_connector.cc:17-37`
  (at `v1.96.59`) only renames `CreatePolicyProviders` to append its
  browser-level provider last; `CreatePlatformProvider`, which builds
  `PolicyLoaderWin`, `PolicyLoaderMac` and `ConfigDirPolicyLoader`, is
  Chromium's on every platform. No channel or Origin suffix: nothing in
  `install_static` feeds the constant (its install modes vary install suffix,
  app GUIDs and ProgIDs; Origin's product dir is `Brave-Origin`,
  `chromium_install_modes.h`), so one key serves stable, beta, nightly and
  Origin; the Brave and Origin 1.96.59 `chrome.dll` each hold exactly one
  `SOFTWARE\Policies\BraveSoftware\Brave`. `BraveSoftware\Brave-Browser`
  (Origin: `Brave-Origin`) is the install and profile dir name, not the policy
  path, with one early reader: before the policy stack exists,
  `install_static::ReportingIsEnforcedByPolicy` reads `MetricsReportingEnabled`
  for crash-report consent from `SOFTWARE\Policies\BraveSoftware\Brave-Browser`
  (Origin: `…\Brave-Origin`), HKLM then HKCU (Chromium
  `chrome/install_static/install_util.cc:524-545` at 154.0.8037.58, from
  `chrome_crash_reporter_client_win.cc:109-117`; brave-core leaves it, and its
  `brave_install_util_unittest.cc:295-311` writes there). The browser copies
  the effective metrics pref into the updater's `usagestats` at every start
  (`browser_process_impl.cc:1697`), so crash consent follows this tool's key
  once Brave has run under it. The other early read, `UserDataDir`, is
  redirected to `…\BraveSoftware\Brave`
  (`chromium_src/chrome/install_static/user_data_dir.cc:28-42`).
  `…\BraveSoftware\Update` is the updater's policy key
  (`patches/chrome-installer-util-google_update_settings_win.cc.patch`).
  Matches Brave's own Group Policy documentation.
- **Linux** — `/etc/brave/policies/managed`. Chromium's default is
  `/etc/chromium/policies` (`policy_paths.cc:21`), unpatched; brave-core
  `app/brave_main_delegate.cc:166-170` (at `v1.96.59`) overrides
  `chrome::DIR_POLICY_FILES` at startup under `IS_POSIX && !IS_MAC`,
  unconditionally, and the platform loader is built only from
  `DIR_POLICY_FILES` (`chrome_browser_policy_connector.cc:346-350`), so no
  Brave reads `/etc/chromium/policies`; `config_dir_policy_loader.cc` appends
  `managed` / `recommended`. Channel- and Origin-independent, confirmed at
  runtime on Origin. Flatpak: Flathub `com.brave.Browser` (1.96.59, Brave's
  own linux zip; `flathub/com.brave.Browser@1116209a57aa`) has
  `--filesystem=host-etc`, which mounts the host `/etc` at `/run/host/etc`,
  and its `brave.sh` symlinks
  `/run/host/etc/brave/policies/{managed,recommended,enrollment}/*.json` into
  the sandbox's own `/etc/brave/policies` before each launch; a file first
  created while Brave runs is seen only after a full quit and relaunch, and an
  edit to an already-linked file raises no event in the watched directory, so
  it lands on the loader's 15-minute reload (`async_policy_loader.cc:30`) or at
  restart. Snap: `brave` (1.96.59, rev 686 amd64, `confinement: strict`) plugs
  no `system-files`; `browser-support` grants `/etc/opt/chrome` and
  `/etc/chromium` and nothing under `/etc/brave`, nor does the default
  template or any other plugged interface (snapd `834c95bd85df`), so where
  snapd enforces AppArmor the read should be denied; source only, not
  confirmed at runtime. The tool's Snap warning rests on this.
- **macOS** — `/Library/Managed Preferences/<bundle id>.plist`, bundle ids
  `com.brave.Browser`, `.beta`, `.nightly`, and for Brave Origin, a separate
  `Brave Origin.app`: `com.brave.Browser.origin`, `.origin.beta`,
  `.origin.nightly` (the shipped 1.96.59 `Brave Origin.app` carries
  `com.brave.Browser.origin`).
  Chromium's `chrome_browser_policy_connector.cc:332-341` keys the loader on
  the running app's own `BaseBundleID()` for non-Google branding, so each app
  and channel reads only its own id. `policy_loader_mac.mm:108-135` reads every
  schema key through `CFPreferencesCopyAppValue` /
  `CFPreferencesAppValueIsForced` on that id: a forced value is Mandatory
  (machine scope when the any-user managed source also has it), any other
  value Recommended at user scope. Machine-scope values come from
  `/Library/Managed Preferences/<bundle id>.plist` or a System-scope
  Configuration Profile; an unforced `<bundle id>.plist` under
  `/Library/Preferences` loads as Recommended, not Mandatory.
  `GetManagedPolicyPath` (`:178-194`) builds only the per-user
  `/Library/Managed Preferences/<login>/<bundle id>.plist`, the only file the
  loader watches, so
  a machine-plist change lands on the 15-minute periodic reload,
  `brave://policy` "Reload policies", or a restart. The ids are
  `MAC_BUNDLE_ID` in brave-core `app/theme/{brave,brave_origin}/BRANDING[.<channel>]`
  (plain `BRANDING` for Release; `build/commands/lib/buildArgs.ts:67-72` selects
  `brave_origin` for Origin builds), copied over
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
  `*.example.com`. The scheme-wide `https://*` and `http://*` this tool uses
  are valid `ContentSettingsPattern` syntax and apply. The policy path never
  writes them to the profile: `PolicyProvider` keeps policy content settings in
  an in-memory `OriginValueMap` and is read-only (`SetWebsiteSetting` returns
  false, `ClearAllContentSettingsRules` is empty). At `v1.96.59` the
  Shields keys reach it through the
  `rewrite/components/content_settings/core/browser/content_settings_policy_provider.cc.yaml`
  plaster, which inserts `kManagedBraveShields{Disabled,Enabled}ForUrls` into
  `kPrefsForManagedContentSettingsMap` (and registers the managed defaults of
  the five `DefaultBrave*Setting` keys, Adblock as `BRAVE_ADS`);
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
  true, `BraveProfilePolicyProvider` injects thirteen values at
  `MANDATORY / USER / POLICY_SOURCE_BRAVE` — `BlockThirdPartyCookies=false`,
  `DefaultCookiesSetting=1`, `DefaultJavaScriptSetting=1`, `DefaultBraveAdblockSetting=2`,
  `DefaultBraveFingerprintingV2Setting=1`, `DefaultBraveHttpsUpgradeSetting=3`,
  `DefaultBraveReferrersSetting=1`, `DefaultBraveRemember1PStorageSetting=1`,
  and `BraveReduceLanguageEnabled`, `BraveDeAmpEnabled`, `BraveDebouncingEnabled`,
  `BraveTrackingQueryParametersFilteringEnabled`, `BraveGlobalPrivacyControlEnabled`
  all `false` — eleven of them keys this project writes, mostly to the opposite
  value. The injection compiles under `ENABLE_AD_BLOCK_ONLY_MODE_POLICIES`
  (`!is_ios`), and `kAdblockOnlyMode` is `FEATURE_ENABLED_BY_DEFAULT` on desktop
  at `v1.96.59` (`components/brave_shields/core/common/features.cc:107-112`;
  brave-core#39428, first in `v1.96.26`; off on iOS and Android; same on
  `1.97.x` and master), whatever `ChromeVariations` says. Builds before
  `v1.96.26` have it off in source, but brave-variations' `AdblockOnlyModeStudy`
  turns it on for 100% of desktop Release from 1.88.96 (capped at `max_version`
  154.1.96.26); the study sets no `policy_restriction`, so `ChromeVariations` 1
  or 2 keeps it out there. The opt-in defaults to false and exists only in an
  English UI: the Shields panel and the Settings toggle require the locale's
  language in `kAdblockOnlyModeSupportedLanguageCodes` (`{"en"}`), and
  `ManageAdBlockOnlyModeByLocale` switches the opt-in off as a profile loads in
  any other locale, back on after a return to English. Precedence favours this
  tool at the mandatory level it writes: `kBravePriority` is the lowest, and
  Chromium compares level before priority (`policy_map.cc:706` at
  154.0.8037.58); a macOS `--policy-file` under `/Library/Preferences` with
  `--persist off` is read as recommended and loses to the mode. The loser is
  kept as a conflict, so with the mode on `brave://policy` shows an
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
  `chromium_src` `OVERRIDE_FEATURE_DEFAULT_STATES` at `v1.94.121`; at `v1.96.59`
  (and on `1.97.x`, master) it is the
  `rewrite/services/device/public/cpp/device_features.cc.yaml` plaster
  (brave-core#39268), same effect; the same-named `chromium_src/` file now only
  redefines the geolocation `kLocationProviderManagerParam`. A
  `rewrite/` plaster is applied to the Chromium file and generates its
  `patches/` twin (`docs/plaster.md:44-45`), so the two are one override: read
  the plaster for intent and the patch for the exact result, whose `index` base
  blob should `git hash-object`-match the pinned Chromium file (both do at
  154.0.8037.58: `content_settings_policy_provider.cc` `637e76ba`,
  `device_features.cc` `4fa3c767`). A `chromium_src/` file at the
  same path is a separate override beside them. Searching one directory proves
  nothing.
- **Content-setting enums are not uniform.** `DefaultNotificationsSetting`,
  `DefaultGeolocationSetting`, `DefaultSensorsSetting` take 1 / 2 / 3. The
  other five permission keys list only 2 / 3 in their schema, but Chromium does
  not enforce the enum: their handlers only type-check, so a 1 reaches the
  managed pref with no error on `brave://policy`; `PolicyProvider` then ignores
  it for WebUSB, Serial and WebHID (`valid_settings` Ask/Block only in
  `content_settings_registry.cc`) and applies it as a managed Allow for
  `DefaultLocalFontsSetting` and `DefaultWindowManagementSetting` (Allow/Ask/Block). This tool
  offers only the schema's values: the choice lists are per key for that
  reason; a value outside a key's legal set is left unmanaged on import and
  named in the message; a quoted `"1"` or a `true` is rejected by a
  type-strict test in all three implementations. A float is not: the Python
  scripts accept only a JSON integer, but `SlimBrave.ps1` also accepts a
  double and compares `[int]$want` (`Import-PresetIntoState`), so `2.0` —
  and `2.5`, which `[int]` rounds to 2 — imports as 2 (What's next).
- **Version gating.** A key newer than the running Brave does nothing: that
  build's schema has no entry for it, so no handler exists. On Windows and
  Linux `brave://policy` still lists it with the error `Unknown policy.`; the
  macOS loader reads only schema-known names, so there it is not listed at all.
  By milestone: cr138 (News, Talk, Speedreader, Wayback, P3A, Stats
  Ping, Web Discovery) · cr139 (Playlist) · cr140 (De-AMP, Debouncing, Reduce
  Language) · cr141 (Fingerprinting V2) · cr142 (GPC, Tracking Query Parameters,
  the other four `DefaultBrave*` enforcers) · cr147 (Email Aliases — Brave 1.92) · cr149
  (Local AI — Brave 1.94). The highest Chromium-inherited milestone is
  `DefaultWindowManagementSetting` at cr111.

## Considered and rejected — do not add

The source is the tiebreaker in every case: the YAML, the handler registration (Chromium's or brave-core's) and the `pref_mapping` file.

| Key(s) | Status | Why not |
|---|---|---|
| `EnableDoNotTrack` | ❌ | does not exist in Chromium's policy index; DNT has no enterprise policy and nothing reads the name. The Windows and Linux loaders pass unknown names through, so `brave://policy` lists it with the error `Unknown policy.`; the macOS loader reads only schema keys (`policy_loader_mac.mm:118-123` at 154.0.8037.58), so there it is not listed. GPC (`BraveGlobalPrivacyControlEnabled`) is the working equivalent |
| `MediaRecommendationsEnabled` | 💀 | **dead key.** The YAML is open (`chrome.*:87-`, no cap, not deprecated) but Chromium removed the handler and the pref with Kaleidoscope in `3e5b1be4a` (2021-01-06); `policy_test_cases.json` said "removed since Chrome 89" at M90 and `pref_mapping/MediaRecommendationsEnabled.json:3` says `Policy was removed` at 154.0.8037.58 and at main (`a5891bb458f3`); zero references in brave-core `v1.96.59`. `brave://policy` validates and lists it, but it has done nothing since Chromium 89. No script or preset writes it; an old export naming it still imports and the key is dropped without mention (no script's import names keys that match no row). The pref-mapping file is the tiebreaker |
| `PromotionalTabsEnabled` | ⛔ | `deprecated: true`; still dispatched through `SimpleDeprecatingPolicyHandler` with its live successor `PromotionsEnabled` (`chrome.*:128-`), both into `prefs::kPromotionsEnabled` (`configuration_policy_handler_list_factory.cc:2824-2830` at 154.0.8037.58). Not exposed either: nearly every surface that pref gates is a Chrome/Google promo Brave suppresses or never shows (sign-in, avatar, desktop-to-iOS and extensions zero-state promos, the app-menu Find-extensions item behind off-by-default `kExtensionsCollapseMainMenu`, low-priority non-toast IPH; Brave's one IPH is a toast, exempt). Its one Brave-visible effect: `false` also hides the post-update brave.com/whats-new tab, because Brave's `chromium_src/…/whats_new_util.cc` drops the argument from `ShouldShowForState` but upstream `DetermineStartupTabs` adds `GetNewFeaturesTabs` only `if (promotions_enabled)` (`startup_browser_creator_impl.cc:669-688`) |
| `IPFSEnabled` | ⛔ | see the Brave table: deprecated, feature gone since 1.69.153. On desktop the `DEPRECATE_IPFS` tombstone (`!is_android && !is_ios`) still maps it to `brave.ipfs.enabled` (`brave_simple_policy_map.h:152-155` at `v1.96.59`), a pref registered only in `RegisterProfilePrefsForMigration` so `ClearDeprecatedIpfsPrefs` can clear it at startup; nothing reads it, so a written value is accepted, flagged deprecated in `brave://policy`, and inert. Same on `1.97.x` and master |
| `PrivacySandboxAdMeasurementEnabled`, `PrivacySandboxAdTopicsEnabled`, `PrivacySandboxSiteEnabledAdsEnabled` | ⛔ dispatched, inert | `deprecated: true` (cr144), uncapped `111-`; still dispatched at 154.0.8037.58 by `PrivacySandboxPolicyHandler` (`configuration_policy_handler_list_factory.cc:3549`), which applies only `false`, into `privacy_sandbox.m1.{topics,fledge,ad_measurement}_enabled`, prefs nothing gates on any more (`PrivacySandboxSettingsImpl` no longer reads them; the Topics (`components/browsing_topics`) and Protected Audience (`content/browser/interest_group`) implementations are deleted upstream). Brave ships the APIs off regardless: `rewrite/` (with its generated `patches/`) disables `kBrowsingTopics`, `kConversionMeasurement`, `kFencedFrames`, `kPrivacySandboxAdsAPIsM1Override` and the Blink `Fledge` / `AdInterestGroupAPI` / `Parakeet` features, all asserted in `app/feature_defaults_unittest.cc`; `renderer/brave_content_renderer_client.cc:126-130` turns off Fledge, fenced frames and Topics (`v1.96.59`) |
| `PrivacySandboxFingerprintingProtectionEnabled`, `PrivacySandboxIpProtectionEnabled` | ❌ removed | removed after cr145 / cr143: `deprecated: true`, capped `140-145` / `138-143`; no handler and no pref-mapping file at 154.0.8037.58 |
| `PrivacySandboxPromptEnabled` | 💀 | `deprecated: true` (prompt configuration no longer supported), uncapped `111-`, but no handler reads it and `pref_mapping/PrivacySandboxPromptEnabled.json` says `Policy was removed` at 154.0.8037.58 |
| `ComponentUpdatesEnabled` | ✅ live, harmful | **actively harmful.** Chromium honours it per installer (`supports_group_policy_enable_component_updates`); for an installer that returns true, update_client refuses with `UPDATE_DISABLED`, so the component freezes, or never installs if not yet present (`components/component_updater/component_updater_service.cc:337-345`, `components/update_client/component.cc:434-441` at 154.0.8037.58). Brave's `AdBlockComponentInstallerPolicy` returns true, so the Shields resources, filter-list catalog and filter lists would freeze; so would the Brave user-agent list, NTP background/sponsored images and WebMCP scripts (with AI Chat), and the PSST rules, Playlist scripts and extension malware blocklist once their off-by-default features are on. Chromium's PKI metadata (CT log list, Chrome Root Store; Brave already discards its key pins), SSL error assistant and file-type policies would freeze too, as would Widevine, which Brave registers only once the user opts in. The Tor client and pluggable transports, Brave Ads resources and the Local Data Files bundle (debounce, HTTPS-upgrade exceptions, URL sanitizer, request-OTR, webcompat exceptions) ride `BraveComponentInstallerPolicy`, which returns false; the query filter, wallet data, P3A and local-AI installers return false too, and CRLSets keep updating (v1.96.59) |
| `FeedbackSurveysEnabled`, `SafeBrowsingSurveysEnabled` | ⚠️ no-op in Brave | brave-core's `rewrite/chrome/browser/ui/hats/hats_service_desktop.cc.yaml` makes `HatsServiceDesktop::RunCommonLaunchChecks` always return an error (`v1.96.59`); no survey ever launches |
| `BrowserNetworkTimeQueriesEnabled` | ⚠️ no-op in Brave | `kNetworkTimeServiceQuerying` is force-disabled in Brave on every platform (`rewrite/components/network_time/network_time_tracker.cc.yaml:6-15` and its generated `patches/components-network_time-network_time_tracker.cc.patch:9-13` at v1.96.59) |
| `DomainReliabilityAllowed` | ⚠️ no-op in Brave | `app/brave_main_delegate.cc:121` (`v1.96.59`) appends `--disable-domain-reliability` unconditionally |
| `BuiltInAIAPIsEnabled` | ⚠️ no-op in Brave | Brave ships the base features behind every API the key gates disabled (`AIPromptAPI`, `AIPromptAPIMultimodalInput`, `AISummarizationAPI`, `AIWriterAPI`, `AIRewriterAPI`, `AIProofreadingAPI`; `rewrite/third_party/blink/renderer/platform/runtime_enabled_features.json5.yaml:73-101` at `v1.96.59`, asserted in `app/feature_defaults_unittest.cc`; `AIEmbeddingsAPI` is `test`-only upstream), and each `AIManager::CanCreate*` returns `kUnavailableFeatureNotEnabled` on that check before `GetPrefBlockedResult` reads the policy pref (`chrome/browser/ai/ai_manager.cc:749-765,1784-1801` at 154.0.8037.58), so the policy is never consulted; the interfaces may stay exposed but report unavailable. Backstop: `GetOptimizationTargetForFeature` returns UNKNOWN (`chromium_src/components/optimization_guide/core/model_execution/on_device_features.cc:18-21`), so no on-device model backs them |
| `DefaultWebBluetoothGuardSetting`, `DefaultFileSystemReadGuardSetting`, `DefaultFileSystemWriteGuardSetting` | ⚠️ redundant | already feature-disabled in Brave, which is why the device-API set is USB+Serial+HID. Both are Brave-owned `FEATURE_DISABLED_BY_DEFAULT` features (`chromium_src/third_party/blink/common/features.cc:10,12` at `v1.96.59`), gated in different places: with `kFileSystemAccessAPI` (`chrome://flags#file-system-access-api`) off, `renderer/brave_content_renderer_client.cc:150-154` disables the `FileSystemAccessLocal` / `FileSystemAccessAPIExperimental` runtime features; with `kBraveWebBluetoothAPI` (`chrome://flags#brave-web-bluetooth-api`) off, `BraveBluetoothDelegate::AllowWebBluetooth` returns `kBlockGloballyDisabled` before upstream `ChromeBluetoothDelegate::AllowWebBluetooth` runs (`browser/bluetooth/brave_bluetooth_delegate.cc:19-20`). The keys bite only if a user turns those flags on |
| `DefaultThirdPartyStoragePartitioningSetting` | ❌ removed | removed after cr145 |
| `FirstPartySetsEnabled`, `RelatedWebsiteSetsEnabled`, `FirstPartySetsOverrides`, `RelatedWebsiteSetsOverrides` | ❌ removed | removed after cr152: all four `deprecated: true`; Chromium `6925f9c991` capped them `113-152` (`FirstPartySets*`) / `120-152` (`RelatedWebsiteSets*`) and deleted both `SimpleDeprecatingPolicyHandler` pairs (the `Enabled` pair into `kPrivacySandboxRelatedWebsiteSetsEnabled`, the `Overrides` pair around `FirstPartySetsOverridesPolicyHandler`) and all four pref-mapping files, so none is dispatched at 154.0.8037.58; brave-core re-adds none. Moot anyway: `BravePrivacySandboxSettings::AreRelatedWebsiteSetsEnabled()` returns false and its pref observer resets `kPrivacySandboxRelatedWebsiteSetsEnabled` to false (`components/privacy_sandbox/brave_privacy_sandbox_settings.cc:29-52` at `v1.96.59`) |
| `InsecurePrivateNetworkRequestsAllowed`, `LocalNetworkAccessRestrictionsEnabled` | ❌ removed | removed after cr137 and cr144: `deprecated: true`, capped (`chrome.*:92-137`, `chrome.*:138-144`), no handler in `configuration_policy_handler_list_factory.cc` and no `pref_mapping` file at 154.0.8037.58; YAMLs unchanged on main. The successors are no posture switch: `LocalNetworkAccess{Blocked,Allowed}ForUrls` and the `LocalNetwork*` / `LoopbackNetwork*ForUrls` lists are URL-pattern lists, and `["*"]` in a `*BlockedForUrls` list would cut every site off from routers, NAS and local dev servers; `LocalNetworkAccessIpAddressSpaceOverrides` (cr146, restart, browser-wide) only reclassifies `cidr=` / `ip:port=` entries as public\|local\|loopback (a bare `*` is dropped); the booleans `LocalNetworkAccessRestrictionsTemporaryOptOut` ("removed after M163") and `LocalNetworkAccessPermissionsPolicyDefaultEnabled` only loosen LNA. Brave pins `kLocalNetworkAccessChecksWebSockets` at upstream's enabled default (`BASE_OVERRIDDEN_FEATURE`, `rewrite/services/network/public/cpp/features.cc.yaml:12-15` at `v1.96.59`) |
| `UrlKeyedMetricsAllowed` | 🕓 future_on only | `future_on:` only, never shipped; its handler would write the pref `UrlKeyedAnonymizedDataCollectionEnabled = false` already writes |
| `AutofillSettings` | ⚠️ feature off | `supported_on: chrome.*:154-` from 154.0.8037.58 (`06b1ad6`, 2026-08-31) and dispatched unguarded (`configuration_policy_handler_list_factory.cc:2658-2659`, `AutofillSettingsPolicyHandler` → `autofill.types_blocked`), but every reader (`AutofillPolicyService`, the autofill and payments clients, the Settings page) is gated on `kAutofillEnableAutofillSettingsEnterprisePolicy`, `FEATURE_DISABLED_BY_DEFAULT` at 154.0.8037.58 (`components/autofill/core/common/autofill_features.cc:720-721`), 155.0.8059.16 and main; no brave-core override, no Griffin study. Redundant even with the feature on: a per-URL-pattern blocklist, not a toggle, and the two Autofill keys block outside that gate (`IsCategoryGloballyBlocked`, `autofill_policy_service.cc:24-65`): a managed `AutofillAddressEnabled=false` covers `contact_info`, `identity_docs` and `travel`; `AutofillCreditCardEnabled=false` covers `payments`; `shopping` is Autofill AI, which Brave ships off (`kAutofillAiWithDataSchema`, `rewrite/components/autofill/core/common/autofill_features.cc.yaml:14-23` at `v1.96.59`); so `[{"*", ["all"]}]` adds nothing. Main marks those two keys `deprecated: true` "in M156" in its favour (`34ae451dfc`, 2026-09-18; uncapped, not in 155.0.8059.16) |
| `DefaultMediaStreamSetting` | ⛔ | `deprecated: true`; a microphone/camera switch would use `AudioCaptureAllowed` / `VideoCaptureAllowed` |
| `BraveSearchResultAdsEnabled` | ❌ removed after 1.94.x | exists in no shipping Brave. A one-release key: merged to master 2026-07-20 (brave-core#37955) and reverted there by `cf025361c` (brave-core#38829, 2026-08-06) before `1.95.x` branched; `1.94.x`, cut in between, kept it (the revert was never uplifted), so only 1.94.x (through `v1.94.122`) and Nightly `v1.95.1`–`v1.95.47` dispatched it (`BooleanDisablingPolicyHandler` into `kOptedInToSearchResultAds`). The YAML is 404 from `v1.95.48` on and absent at `v1.96.59`, `1.97.x` and master. Its replacement, the universal pref `brave.brave_ads.sponsored.enabled` (`kSponsoredEnabled`, `a723c7b00` / brave-core#39135, first in 1.96), gates NTP sponsored images and the browser side of search result ads (event and conversion reporting, `components/brave_ads/…/search_result_ad_handler.cc:89` at `v1.96.59`; Brave Search serves the ads server-side, brave-browser#51040), and has no policy key: brave-browser#57204 closed 2026-09-08 on `1.96.x` shipping only a Settings toggle (brave-core#39330); neither `brave_simple_policy_map.h` nor Brave's `chromium_src` override of `configuration_policy_handler_list_factory.cc` registers one at `v1.96.59`, `1.97.x` or master; the per-unit PRs (brave-core#37956 NTP, #37957 notification) closed unmerged and brave-browser#57452 (`BraveNewTabPageAdsEnabled`) closed wontfix. brave-browser#54917 (ads policy independent of Rewards) is open, unmilestoned, and plans a `SponsoredAdsEnabled` key on that pref with no PR yet; its orphaned draft brave-core#35873 (`BraveAdsEnabled`, dropped from the issue's checklist 2026-07-15) is merge-conflicting and writes three prefs gone at `v1.96.59`. Until a key ships, `BraveRewardsDisabled` keeps the ads service off (see its row). A switch that does nothing is worse than none |

## What's next

Watch list, each with the trigger that turns it into work:

- `PsstEnabled` — dispatched in every Release since 1.95 (`ENABLE_PSST` map
  entry, `browser/policy/brave_simple_policy_map.h:160-163` at `v1.96.59`) but
  inert: `kEnablePsst` is `FEATURE_DISABLED_BY_DEFAULT`
  (`components/psst/core/common/features.cc:10`) at `v1.96.59`, `1.97.x` and
  master. Trigger: `features.cc` flipping it on a shipping branch, or a
  `brave/brave-variations` study enabling `EnablePsst` on Release (none at
  `ac7b120e6`). Then a checkbox writing `false`, labelled Brave 1.95+, restart note;
  it joins `ORIGIN_BUILTIN_KEYS` too
  (`enable_psst = … && !is_brave_origin_branded`).
- Brave Sponsored Ads (the 1.96 "Enable Sponsored Ads" toggle,
  `brave.brave_ads.sponsored.enabled`) — no policy key at `v1.96.59`, `1.97.x`
  or master; `BraveRewardsDisabled` covers the in-browser ads for now by
  keeping the ads service from starting (see its row). Trigger: any new ads
  YAML under `policy_definitions/BraveSoftware` (a YAML never names its pref:
  watch the file list, not `kSponsoredEnabled`), or brave-browser#54917 gaining
  a milestone (open, unmilestoned; the issue names `SponsoredAdsEnabled`, draft
  brave-core#35873 `BraveAdsEnabled`). Then a checkbox writing the off value,
  in every preset that carries `BraveRewardsDisabled`; required once #54917
  lands, since it would decouple ads startup from Rewards and the Rewards row
  would stop covering ads. Until then: runtime-check on `v1.96.59` what the
  Rewards row states from source (with `BraveRewardsDisabled` set, no
  notification ads and no NTP sponsored wallpapers); if it does not hold,
  correct the row and the scripts' Rewards description.
- `BackgroundTabFreezingEnabled` (`686333c`, `chrome.*:155-`, `per_profile: false`,
  local_state `performance_tuning.tab_freezing.enabled`, default on) and
  `ExtensionReviewPromptsEnabled` (`23e107e`, `chrome.*:154-` but landed after
  the M154 branch point) — 404 at 154.0.8037.58 (`v1.96.59`, `1.97.x`); present
  and dispatched at 155.0.8059.16 (master). Not candidates even there: both are
  inert by default. The tab-freezing pref gates only `FreezingPolicy`'s
  infinite-tabs paths, which also need `kInfiniteTabsFreezing` or
  `kInfiniteTabsFreezingOnMemoryPressure` (`freezing_policy.cc:485-497` at
  155.0.8059.16); vote-based and Battery Saver freezing ignore it. Every reader
  of `extensions.review_prompts_allowed` bails unless
  `kCWSReviewPromptingNativeUI` is on. All three features are
  `FEATURE_DISABLED_BY_DEFAULT` with no brave-core override. Trigger: a shipping
  Brave whose Chromium carries the YAML (cr155 today) with one of them on
  (Chromium default, brave-core or a Griffin study); a pin bump alone is not
  one.
- `AutofillSettings` — dispatched at 154.0.8037.58 (`AutofillSettingsPolicyHandler`
  → `autofill.types_blocked`) but inert: its readers are gated on
  `kAutofillEnableAutofillSettingsEnterprisePolicy`, `FEATURE_DISABLED_BY_DEFAULT`
  at 154.0.8037.58, 155.0.8059.16 and main, no brave-core override. The same
  handler already turns `AutofillAddressEnabled` / `AutofillCreditCardEnabled`
  = false into one `"*"` rule (`contact_info`, `payments`), so while those
  dispatch it would duplicate them (`autofill_policy_handler.cc:113-147` at
  154.0.8037.58, identical at main). Main (`34ae451dfc`, 2026-09-18; not in
  155.0.8059.16) marks both legacy keys `deprecated: true`, "deprecated in
  M156, please use AutofillSettings"; `supported_on` stays uncapped and they
  still dispatch. Triggers: (1) the feature on at a shipping pin (Chromium default,
  brave-core or a Griffin study) — re-mark the rejected row; no script change,
  the legacy keys still apply. (2) The legacy YAMLs `deprecated` at a shipping
  pin (cr156 at the earliest) — they turn ⛔ and may not be written. With (1)
  in place, replace them with one `{"url_pattern": "*", "blocked_types":
  [...]}` entry as the deprecation notes prescribe (`contact_info`,
  `identity_docs`, `travel` for addresses; `payments` for cards) in the three
  scripts, Maximum Privacy (all four types), Balanced Privacy (`payments`) and
  the preset copies embedded in `SlimBrave.ps1`, and move the key from
  Considered and rejected into the Chromium table
  (`test_nothing_rejected_is_written`). Without (1) the replacement is inert
  while the legacy keys still work: decide then.
- Brave Origin — real-machine runs of the deb on Debian/Ubuntu, the rpm on
  Fedora/openSUSE, Origin beta and nightly, and mixed machines with regular
  Brave beside Origin. The checklist with exact commands and expected output is
  `TESTING-brave-origin.md` on the `brave-origin-detection` branch.
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
  Python scripts, Origin built-ins, so a key that matches no row (`MediaRecommendationsEnabled`, or
  `BackgroundModeEnabled` on macOS) is dropped without a word. (5)
  `SlimBrave.ps1` import accepts a float for a choice key and rounds it
  (see Cross-cutting, Content-setting enums); the Python scripts reject it.
  `MAC_CHANNELS` needs no Dev entry: Brave dropped Dev (brave-browser#25248)
  and its macOS Dev appcast stopped at 1.61.87 (2023-11).
- Runtime checks owed on a shipping Brave: `SafeSitesFilterBehavior` (does
  the Safe Search lookup succeed, i.e. does it block anything, or only send
  the URLs; see its row); `DefaultBrowserSettingEnabled` = false with
  *Set as default* on `brave://welcome` (source says it hits a `CHECK`); and
  the Sponsored Ads items above.
- Under consideration, not decided: a Preview (dry-run diff of what Apply will
  change) and a Verify (read the policy location back and compare) — the two
  usability features the Windows-only Brave-Free-Origin project has and this
  one lacks.

## Done log

One line per change to what the tool writes or how this document judges it,
with the reference that carries the detail. Newest first.

| When | What | Reference |
|---|---|---|
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
  `find rewrite -path '*policy/resources/templates*'`. At `v1.96.59` there are
  two patches and nothing in `rewrite/`:
  `…Miscellaneous-MetricsReportingEnabled.yaml.patch` drops `sensitive: true`
  (why an HKLM write works on a home PC; see its row) and
  `…Miscellaneous-DnsOverHttpsMode.yaml.patch` drops
  `default_for_enterprise_users: 'off'`. For those keys read the tag's YAML with
  the patch applied; `chromium_src/components/policy/resources/policy_templates.py`
  only adds the `BraveSoftware` group.
- **Dispatch of a Chromium key:** `chrome/browser/policy/configuration_policy_handler_list_factory.cc`
  at the tag: a `key::k<Key>` entry or, for a key with a dedicated handler
  class (14 of the 49 Chromium keys written at 154.0.8037.58, e.g.
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
  (24 files at `v1.96.59`); `components/` alone misses
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
  `components/headless/command_handler/headless_command.js:222-229` at
  154.0.8037.58); `--headless=new --dump-dom chrome://policy` also hung on
  Brave Origin 1.94.121 (not re-tried on 1.96.59). Always pass a scratch
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
