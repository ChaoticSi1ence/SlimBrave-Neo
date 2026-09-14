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
`brave_simple_policy_map.h` entry with its buildflag guard, or the Chromium
handler list (`factory` = `configuration_policy_handler_list_factory.cc` plus
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
| Brave-specific keys | 2026-09-07 | brave-core `v1.94.121` (`e894693`), master `20512a1`; branches `1.95.x`, `1.96.x` | YAML + `brave_simple_policy_map.h` guards resolved through `.gni`; 18 agents, every citation re-fetched by a refuter |
| Chromium-inherited keys | 2026-09-07 | Chromium 152.0.7977.83 (tree `04b4c4f`), `chromium/main` `34e8449` | YAML + `configuration_policy_handler_list_factory.cc` + `pref_mapping/<Key>.json` at the tag |
| Content-setting enums | 2026-08-28 | `chromium/main` | schema `items:` of each `Default*Setting` key |
| `HardwareAccelerationModeEnabled` off state | 2026-09-03 | `chromium/main` | YAML `items:` |
| Platform policy locations | 2026-09-07 (source); Linux at runtime 2026-09-11 | brave-core `v1.94.121`, Chromium 152.0.7977.83; Brave Origin 1.94.121 live | source chains; inotify watches and a policy seen taking effect |
| Brave Origin on Linux | 2026-09-11 | brave-core `v1.94.121`; the v1.94.121 zip, deb and rpm artifacts; Flathub and Snap store APIs; a CachyOS install | artifacts unpacked; 7 readers, 2 refuters each; binary injection test |
| Considered and rejected | 2026-09-07 | as the two key tables | as the two key tables |
| Ad Block Only Mode provider | 2026-09-07 | brave-core `v1.94.121`, `1.95.x`, `1.96.x` | `ad_block_only_mode_policy_manager.cc`, `policy_types.h`, `policy_map.cc` |

## What the project does

- Writes Chromium managed policies and nothing else: no binary edits, no
  hosts-file entries, no service changes, no flags. The one write outside the
  policy location is the repair of Shields exceptions that pre-1.x SlimBrave
  leaked into profiles (see Cross-cutting).
- Three implementations kept in lockstep by tests: `SlimBrave.ps1` (Windows,
  Fluent GUI), `slimbrave-linux.py` (curses TUI), `slimbrave-mac.py` (curses
  TUI; macOS and Linux). Same rows, same descriptions, same presets,
  import/export files that round-trip between all three.
- **Inventory: 78 rows over 74 distinct keys**, plus `DnsOverHttpsMode` and
  `DnsOverHttpsTemplates` from the DNS section — 76 keys written. Seven
  categories: Telemetry & Reporting, Privacy & Security, Site Permissions,
  Access Controls, Brave Features, Shields & Content Protection, Performance
  & Bloat. Six presets, all derived from the same tables.
- **A key ships only when all four hold:** its YAML exists at the Chromium tag
  Brave pins; the browser dispatches it (a handler at that tag, or a
  `brave_simple_policy_map.h` entry whose buildflag is on for the platform);
  the value written is a legal schema member meaning what the label says; and
  there is a product reason. A key that is dispatched but inert (behind an
  off-by-default feature, or compiled out on one platform) stays only with the
  caveat in its label. Nothing dead ships — a switch that does nothing is worse
  than no switch.
- **This document is enforced.** `tests/test_audit.py` parses the tables here
  and asserts: every key the scripts write appears in a key table with ✅ or
  ⚠️; nothing in Considered and rejected, and nothing marked ⛔ ❌ 💀 🕓, is
  written by any script; `ORIGIN_BUILTIN_KEYS` in the scripts equals the set of
  written Brave keys whose Dispatch is a guarded map entry; the inventory
  counts in this section match `build_rows()`; every Status cell uses the
  vocabulary; the ledger names the key sections. When it fails, the document or
  the code is wrong — fix whichever disagrees with the source.
- Where the policies land:

| Platform | Location | Scope |
|---|---|---|
| Windows | `HKLM\SOFTWARE\Policies\BraveSoftware\Brave` | one key for stable, beta, nightly and Origin — no channel suffix |
| Linux | `/etc/brave/policies/managed/slimbrave.json` | one file for every channel and for Brave Origin |
| macOS | `/Library/Managed Preferences/com.brave.Browser{,.beta,.nightly}.plist`, or a Configuration Profile | one plist per selected channel |

## Sources and pins

- **Shipping Brave:** 1.94.121 on Chromium **152.0.7977.83** (the tag brave-core
  `v1.94.121` pins in `package.json`). Chromium policy definitions at that tag:
  tree `04b4c4f`, 1,452 policies. `chromium/main` last read at `34e8449`
  (1,458 policies). brave-core `v1.94.121` (`e894693`) and master (`20512a1`):
  30 Brave policies at the tag, 31 on `1.95.x`+ with `PsstEnabled`.
- **Branch pins:** `v1.94.121` and `1.95.x` → 152.0.7977.83; `1.96.x` and
  master → 153.0.8010.28.
- **Milestones, not versions.** `supported_on` counts Chromium milestones
  (`cr138`), and the mapping to Brave releases drifts by whole versions:
  `EmailAliasesEnabled` is `chrome.*:147-` yet first ships in Brave 1.92;
  `BraveLocalAIEnabled` is `chrome.*:149-` yet first ships in 1.94. Any Brave
  version in a row label comes from probing the release branches —
  `raw.githubusercontent.com/brave/brave-core/<1.9N.x>/components/policy/resources/templates/policy_definitions/BraveSoftware/<Key>.yaml`,
  walking until it stops 404ing — never from milestone arithmetic. Rough
  alignment for orientation only: cr138 ≈ 1.80 … cr152 ≈ 1.94.
- **Authorities:** Chromium's `policy_definitions/` YAML and brave-core's
  `BraveSoftware/` YAML for existence and schema; `configuration_policy_handler_list_factory.cc`,
  `pref_mapping/<Key>.json` and `brave_simple_policy_map.h` for dispatch;
  brave-core `chromium_src/`, `patches/` and `rewrite/` for overrides. Source
  outranks support articles and third-party guides, which lag it.

Legend for the tables: **restart** = `dynamic_refresh: false`, the browser must
restart to pick the value up; **browser-wide** = `per_profile: false`; a `Min`
of `—` means the milestone was not recorded here — read it from the YAML.

## Brave-specific keys

| Key | Status | Min | Type | Dispatch | Notes |
|---|---|---|---|---|---|
| BraveP3AEnabled | ✅ | cr138 | bool | map, unguarded | unset = enabled; restart; browser-wide |
| BraveStatsPingEnabled | ✅ | cr138 | bool | map, unguarded | unset = enabled; restart; browser-wide |
| BraveGlobalPrivacyControlEnabled | ✅ | cr142 | bool | map, unguarded | dynamic refresh |
| BraveDeAmpEnabled | ✅ | cr140 | bool | map, unguarded | dynamic refresh |
| BraveDebouncingEnabled | ✅ | cr140 | bool | map, unguarded | dynamic refresh |
| BraveTrackingQueryParametersFilteringEnabled | ✅ | cr142 | bool | map, unguarded | only effective while Shields is enabled |
| BraveReduceLanguageEnabled | ✅ | cr140 | bool | map, unguarded | dynamic refresh |
| BraveRewardsDisabled | ✅ | cr105 | bool | map, `ENABLE_BRAVE_REWARDS` | true = disable; restart |
| BraveWalletDisabled | ✅ | cr106 | bool | map, `ENABLE_BRAVE_WALLET` | also disables web3 and decentralized DNS; restart |
| BraveVPNDisabled | ⚠️ no-op on Linux | cr112 | bool | map, `ENABLE_BRAVE_VPN` | **Windows, macOS, Android, iOS only.** `enable_brave_vpn = enable_brave_vpn_v1 \|\| enable_brave_vpn_v2`, both `(is_win \|\| is_android \|\| is_mac \|\| is_ios) && !is_brave_origin_branded` — no `is_linux`, so the `brave_simple_policy_map.h` entry is compiled out of Linux builds and the key is a silent no-op there while `brave://policy` still shows it applied. The Linux row is labelled rather than removed (`enable_brave_vpn_v2_apps` already names `is_linux`); `slimbrave-mac.py` labels it plainly, cosmetic. Restart |
| BraveAIChatEnabled | ✅ | cr121 | bool | map, `ENABLE_AI_CHAT` | false = disable Leo; does not cover on-device models (see BraveLocalAIEnabled); restart |
| BraveLocalAIEnabled | ✅ | cr149 — **Brave 1.94**, branch-probed | bool | map, `ENABLE_LOCAL_AI` | false = skip registering the on-device model component (EmbeddingGemma, `ejhejjmaoaohpghnblcdcjilndkangfe`), delete its directory, stop history vector-indexing. Separate buildflag (`ENABLE_LOCAL_AI`) and prefs from AI Chat. Restart; browser-wide. Deliberately in no preset |
| BraveShieldsDisabledForUrls | ✅ | cr107 | list | map, unguarded | scheme-wide patterns, see Cross-cutting; restart; browser-wide |
| BraveShieldsEnabledForUrls | ✅ | cr107 | list | map, unguarded | counterpart of the row above; restart; browser-wide |
| BraveNewsDisabled | ✅ | cr138 | bool | map, `ENABLE_BRAVE_NEWS` | restart |
| BraveTalkDisabled | ✅ | cr138 | bool | map, `ENABLE_BRAVE_TALK` | restart |
| BravePlaylistEnabled | ✅ | cr139 | bool | map, `ENABLE_PLAYLIST` | restart |
| BraveWebDiscoveryEnabled | ✅ | cr138 | bool | map, `ENABLE_WEB_DISCOVERY` | unset = **disabled** by default; restart |
| BraveSpeedreaderEnabled | ✅ | cr138 | bool | map, `ENABLE_SPEEDREADER` | desktop only; restart |
| BraveWaybackMachineEnabled | ✅ | cr138 | bool | map, `ENABLE_BRAVE_WAYBACK_MACHINE` | desktop only; restart |
| TorDisabled | ✅ | cr78 (Win) / cr93 (mac, Linux) | bool | map, `ENABLE_TOR` | desktop only; restart; browser-wide |
| EmailAliasesEnabled | ⚠️ feature off | cr147 — **Brave 1.92**, branch-probed | bool | map, `ENABLE_EMAIL_ALIASES` | **key live, feature off.** Dispatched (`brave_simple_policy_map.h` under `ENABLE_EMAIL_ALIASES`, desktop only) and the pref is written, but `components/email_aliases/features.cc` has `kEmailAliases` `FEATURE_DISABLED_BY_DEFAULT` on 1.92.x through 1.96.x and master, and `IsEmailAliasesEnabledForProfile()` requires feature **and** pref — no observable effect until Brave flips the feature (default or Griffin seed). `false` stays as a pre-emptive guard; the `ChromeVariations` rows are what would stop the flip. Restart |
| DefaultBraveAdblockSetting | ✅ | cr142 | int enum | content-settings policy provider (brave-core patch) | 1 = allow ads, 2 = block |
| DefaultBraveFingerprintingV2Setting | ✅ | cr141 | int enum | same | 1 = off, 3 = standard (no value 2) |
| DefaultBraveHttpsUpgradeSetting | ✅ | cr142 | int enum | same | 1 = allow HTTP, 2 = strict, 3 = standard |
| DefaultBraveReferrersSetting | ✅ | cr142 | int enum | same | 1 = permissive, 2 = cap to strict origin; both exposed as mutually exclusive rows (issue #9); never put 1 in a preset |
| DefaultBraveRemember1PStorageSetting | ✅ | cr142 | int enum | same | 1 = remember, 2 = forget on close |

Brave keys that exist and are **not exposed**:

| Key | Status | Why not |
|---|---|---|
| BraveSyncUrl | ✅ exists, unexposed | a custom sync-server URL, not a debloat toggle; self-hosters write it by hand |
| PsstEnabled | 🕓 1.95.x+, feature off | On `1.95.x`, `1.96.x` and master (commit `13a8fd8cc`), absent from `v1.94.121`: YAML, a `brave_simple_policy_map.h` entry under `ENABLE_PSST` (`enable_psst = !is_android && !is_ios && !is_brave_origin_branded`) and a Brave Origin default of `false`, `user_settable=false`. Still a no-op: `kEnablePsst` is `FEATURE_DISABLED_BY_DEFAULT` on every ref and both the tab observer and the component installer bail on it; `chrome://flags#enable-psst` turns it on locally. PSST downloads per-site scripts, injects them into logged-in origins to detect sign-in, then drives the account through settings URLs flipping switches. **Trigger:** `components/psst/core/common/features.cc` flipping on a shipping branch — then add as a checkbox writing 0, label Brave 1.95+ (branch-probed), restart note |
| IPFSEnabled | ⛔ | `deprecated: true`; the feature left Brave in 1.69.153 (Aug 2024), only a `DEPRECATE_IPFS` tombstone remains. Has bounced in and out of this project before — **do not re-add**; the YAML is the tiebreaker |

## Chromium-inherited keys

Dispatch for every row is `factory` unless the Notes say otherwise.

| Key | Status | Min | Type | Written | Notes |
|---|---|---|---|---|---|
| MetricsReportingEnabled | ✅ | — | bool | false | restart. Chromium marks it `sensitive: true`, which makes `FilterSensitivePolicies` drop it from a platform source on a Windows/Mac machine that is not domain-joined or MDM-managed; brave-core patches `sensitive: true` out of the YAML (one of its two policy-definition patches, the other being DnsOverHttpsMode), which is the only reason an HKLM write works on a home PC. Brave defaults the pref to false and registers no UMA/UKM providers, so in practice the key governs crash reporting |
| SafeBrowsingProtectionLevel | ✅ | — | int enum | 0 (no protection) | 0/1/2 valid. Brave proxies Safe Browsing through its own hosts — `safebrowsing_api_endpoint = "safebrowsing.brave.com"` in `components/safebrowsing/BUILD.gn`, and `components/static_redirect_helper/static_redirect_helper.cc` (`v1.94.121` lines 85-102) rewrites `safebrowsing.googleapis.com` → `safebrowsing.brave.com`, `sb-ssl.google.com` → `sb-ssl.brave.com`, the `safebrowsing.google.com` crx list → `safebrowsing2.brave.com` — so Google never sees a lookup even with Safe Browsing on. Value 2 behaves as 1: the `safe_browsing_prefs.cc` patch makes `IsEnhancedProtectionEnabled()` false before it reads the pref. Turning it off buys almost no privacy and costs the phishing/malware interstitials; in no preset |
| SafeBrowsingExtendedReportingEnabled | ✅ | — | bool | false | |
| UrlKeyedAnonymizedDataCollectionEnabled | ✅ | — | bool | false | |
| AutofillAddressEnabled | ✅ | — | bool | false | |
| AutofillCreditCardEnabled | ✅ | — | bool | false | |
| PasswordManagerEnabled | ✅ | — | bool | false | |
| BrowserSignin | ✅ | — | int enum | 0 (disable) | restart |
| WebRtcIPHandling | ✅ | — | string enum | disable_non_proxied_udp | |
| QuicAllowed | ✅ | — | bool | false | restart |
| BlockThirdPartyCookies | ✅ | — | bool | true | |
| ForceGoogleSafeSearch | ✅ | — | bool | true | |
| IncognitoModeAvailability | ✅ | — | int enum | 1 or 2 | 0 = enabled, 1 = disabled, 2 = forced, as two mutually exclusive rows; restart. In Brave `tor::IsIncognitoDisabledOrForced` treats 1 and 2 alike, so either row also removes Tor windows |
| SyncDisabled | ✅ | — | bool | true | |
| BackgroundModeEnabled | ⚠️ Win/Linux only | cr19 | bool | false | **Windows and Linux only** (`chrome.win:19-`, `chrome.linux:19-`); no macOS support in Chromium. `slimbrave-mac.py` also runs on Linux, so it gates the row on `sys.platform.startswith("linux")` at index 0 of Performance & Bloat; on macOS the key is dropped and the import message names it as not applicable |
| ShoppingListEnabled | ✅ | — | bool | false | |
| AlwaysOpenPdfExternally | ✅ | — | bool | true | |
| TranslateEnabled | ✅ | — | bool | false | |
| SpellcheckEnabled | ✅ | — | bool | false | desktop only; mutually exclusive with SpellCheckServiceEnabled |
| SearchSuggestEnabled | ✅ | — | bool | false | |
| PrintingEnabled | ✅ | — | bool | false | |
| DefaultBrowserSettingEnabled | ✅ | — | bool | false | desktop only |
| DeveloperToolsAvailability | ✅ | — | int enum | 2 (disallowed) | does **not** cover the CDP port — see RemoteDebuggingAllowed |
| DnsOverHttpsMode | ✅ | — | string enum | off / automatic / secure | Stock Chromium forces DoH **off** whenever this key is unmanaged on a machine that is domain-joined or carries *any* machine-level policy (`StubResolverConfigReader::ShouldDisableDohForManaged`, 152.0.7977.83 lines 240-266 and 344-346) — which every SlimBrave machine satisfies the moment it writes its first key. brave-core `chromium_src/chrome/browser/net/stub_resolver_config_reader.cc` overrides that to false, so **Not managed** keeps Brave's own automatic DoH; the companion YAML patch dropping `default_for_enterprise_users: 'off'` is metadata that only reaches ChromeOS code. On Windows with Brave VPN connected, Brave skips its forced-secure-DoH override when this key is managed and shows a policy-warning dialog |
| DnsOverHttpsTemplates | ✅ | — | string | URL template | **required** for `secure` and `custom`, optional for `automatic`, ignored for `off`. `secure` with an empty template destroys name resolution — the templates pref is blanked, `CanUseSecureDnsTransactions()` is false, and the system-resolver fallback is gated on `secure_dns_mode != kSecure` (crbug.com/1326526). All three scripts refuse that combination |
| PasswordLeakDetectionEnabled | ✅ | cr79 | bool | false | stops the online breach-list credential check |
| NetworkPredictionOptions | ✅ | cr38 | int enum | 2 (never predict) | 0 = always, 2 = never (1 deprecated in-source) |
| PaymentMethodQueryEnabled | ✅ | cr80 | bool | false | sites' `canMakePayment` always answers "none saved" |
| AlternateErrorPagesEnabled | ✅ | cr8 | bool | false | belt and braces — Brave ships the web-service error page off |
| DefaultNotificationsSetting | ✅ | cr10 | int enum | 1, 2 or 3, user-selected; key omitted when Not managed | full legal enum **1 = allow, 2 = block, 3 = ask**, all exposed as a choice row |
| DefaultGeolocationSetting | ✅ | cr10 | int enum | 1, 2 or 3; omitted when Not managed | full legal enum 1 = allow, 2 = block, 3 = ask; choice row |
| DefaultSensorsSetting | ✅ | cr88 | int enum | 1, 2 or 3; omitted when Not managed | motion/orientation sensors, a fingerprinting vector; full legal enum 1 = allow, 2 = block, 3 = ask. "3 = ask" holds in Brave only because brave-core force-enables `features::kSensorsAllowAskBlockPermissionModel` (`chromium_src/services/device/public/cpp/device_features.cc` at the tag; `rewrite/` + `patches/` on 1.96.x, same effect) — the dedicated `DefaultSensorsSettingPolicyHandler` (in M152 since `8a50daa`) rewrites 3 to **Allow** when that flag is off, and stock Chromium ships it off. Brave also re-registers SENSORS with default **Block** (brave/brave-browser#4789), so Not managed in Brave is block-by-default-but-user-changeable. A policy file taken to stock Chromium with 3 means Allow |
| ExtensionInstallBlocklist | ✅ | cr86 | list | `["*"]` | blocks all installs and disables already-installed extensions |
| SafeSitesFilterBehavior | ✅ | cr69 | int enum | 1 (filter) | not a local filter — sends every navigation URL, iframes included, to Google's Safe Search API (`tags: [filtering, google-sharing]`); disclosed in the tooltip and README because the same tool ships `SafeBrowsingProtectionLevel = 0` |
| BrowserGuestModeEnabled | ✅ | cr38 | bool | false | guest windows bypass profile restrictions |
| HighEfficiencyModeEnabled | ✅ | cr108 | bool | true | forces Memory Saver tab discarding on |
| HardwareAccelerationModeEnabled | ✅ | cr46 | bool | true / false | both states as a mutually exclusive pair (`Group = "hwaccel"`) because unset is not off: Chromium's default is on, absent means user-controlled, `false` means forced off. The off state is a troubleshooting lever for a faulty GPU driver, a VM or RDP session, or screen-sharing corruption, not a privacy posture — in no preset. Restart |
| EnableMediaRouter | ✅ | cr52 | bool | false | disables Cast and its LAN device discovery; restart. Brave's `media_router_feature.cc` gives the policy precedence over the `brave://settings/extensions` Media Router toggle; Tor windows are always off |
| ChromeVariations | ✅ | cr83 | int enum | 1 or 2 | 0 = all variations, 1 = critical fixes only, 2 = none. Closes the last remote-configuration channel: Brave fetches a Griffin seed from `variations.brave.com` that flips features in an installed browser. Maps to `variations::prefs::kVariationsRestrictionsByPolicy`; brave-core does not override the restriction path. Two mutually exclusive rows; value 2 also blocks the emergency killswitches, so it is in no preset |
| SpellCheckServiceEnabled | ✅ | cr22 | bool | false | removes the Google spelling web service while offline dictionaries keep working; upstream says it has no effect once `SpellcheckEnabled` is false, hence the mutual exclusion |
| RemoteDebuggingAllowed | ✅ | cr93 | bool | false | blocks `--remote-debugging-port` / `--remote-debugging-pipe`, the CDP cookie-theft vector `DeveloperToolsAvailability` leaves open; inherited unchanged by Brave. Breaks Puppeteer, Playwright and `brave://inspect`. Restart: `dynamic_refresh` flipped to true only in 154.0.8029.0 (`80ad0b9`), so the note holds through the cr153 line |
| DNSInterceptionChecksEnabled | ✅ | cr80 | bool | false | stops the three random 7–15 character hostname lookups at startup and on every network change, a per-launch beacon to the ISP or DoH resolver |
| BasicAuthOverHttpEnabled | ✅ | cr88 | bool | false | refuses HTTP Basic auth over cleartext; breaks legacy plain-HTTP appliance logins |
| DefaultWebUsbGuardSetting | ✅ | cr67 | int enum | 2 or 3; omitted when Not managed | **2 = block, 3 = ask — no value 1** in the schema, so the row offers Not managed / Ask / Block. Ships enabled in Brave. Breaks Ledger/Trezor web wallets and in-browser firmware flashers |
| DefaultSerialGuardSetting | ✅ | cr86 | int enum | 2 or 3; omitted when Not managed | 2 = block, 3 = ask, no 1; breaks in-browser microcontroller tooling |
| DefaultWebHidGuardSetting | ✅ | cr100 | int enum | 2 or 3; omitted when Not managed | 2 = block, 3 = ask, no 1; may break security keys and gamepad configurators that use WebHID rather than WebAuthn. The device-API set is USB+Serial+HID because WebBluetooth and File System Access are already feature-disabled in Brave |
| DefaultLocalFontsSetting | ✅ | cr103 | int enum | 2 or 3; omitted when Not managed | 2 = block, 3 = ask, no 1; `queryLocalFonts()` returns the installed font list, a top-tier fingerprint that Shields' farbling does not cover |
| DefaultWindowManagementSetting | ✅ | cr111 | int enum | 2 or 3; omitted when Not managed | 2 = block, 3 = ask, no 1; stops sites reading the multi-monitor topology; complementary to `kBraveBlockScreenFingerprinting`, which is about screen size |
| BlockExternalExtensions | ✅ | cr80 | bool | true | closes the silent install channel (registry `…\Extensions` keys, `external_extensions.json` drop-ins) that bundleware uses while user-chosen extensions keep working, unlike `ExtensionInstallBlocklist: ["*"]`; restart |

Every key above fetches 200 at the Chromium tag and at main; none is
`deprecated:`, upper-bounded, or `future_on:`-only. 73 of the YAML files are
byte-identical between tag and main; the four that differ
(`RemoteDebuggingAllowed` dynamic_refresh, `BrowserSignin` +`android:153-`,
`DeveloperToolsAvailability` android, `SafeBrowsingExtendedReportingEnabled`
quoting) change nothing on desktop. Every Chromium-inherited key is cr111 or
older, and every Brave key cr142 or older except the two branch-probed rows
(cr147, cr149), so all are present in any Brave still receiving updates.

## Brave Origin on Linux

Origin is Brave with Rewards, Wallet, VPN, Leo, News and friends removed at
build time (`is_brave_origin_branded`); free on Linux, a paid upgrade on
Windows and macOS. Everything here is verified on the shipped 1.94.121
artifacts — `brave-origin_1.94.121_amd64.deb` (130,821,188 B, sha256
`0f76ec5f…1495`, the bytes the apt `Packages` index lists) and
`brave-origin-1.94.121-1.x86_64.rpm` (132,609,317 B, sha256 `9844f1b9…6b3e`,
as the rpm `primary.xml` lists), both unpacked with bsdtar, and the AUR
install of the zip — and on a real install; the Windows script is untouched.

- **Origin reads `/etc/brave/policies/managed`, like regular Brave.** Source:
  `app/brave_main_delegate.cc:166-170` overrides `chrome::DIR_POLICY_FILES` to
  `/etc/brave/policies` under `IS_POSIX && !IS_MAC` with no branding or channel
  guard; Chromium's `config_dir_policy_loader.cc`, unpatched, appends
  `managed` and `recommended`. Binary: the Origin ELF — byte-identical across
  zip, deb and rpm, sha256 `e2061ff6…05c5` — holds `/etc/brave/policies` and
  `BraveSoftware/Brave-Origin` and no `/etc/brave-origin` string. Runtime: a
  running Origin holds inotify watches on `/etc/brave`, `/etc/brave/policies`
  and `/etc/brave/policies/managed` themselves (and parks on `/etc`, never on
  the existing `/etc/chromium`, while they don't exist). End to end: a managed
  `ExtensionInstallForcelist` there installed its extensions into the
  `Brave-Origin` profile as `location = 7` (`kExternalPolicyDownload`) without
  a restart, and this tool's `--import` showed every key in `chrome://policy`
  as Platform / Machine / Mandatory / OK.
- **`/etc/brave-origin/policies/enrollment` is not a policy directory.** It is
  Chrome Browser Cloud Management's enrollment-token directory from
  `chromium_src/chrome/installer/linux/common/brave-origin/chromium-browser.info`,
  touched only by the deb/rpm post-install scripts when `/etc/default/brave-origin`
  opts into the device-trust key. Never write policies there.
- **Where Origin lives**, every row read from the artifact:

| Packaging | Install dir | Binary | Launcher | On `PATH` | Profile |
|---|---|---|---|---|---|
| Arch: AUR `brave-origin-bin` (CachyOS mirrors it); unpacks the upstream zip | `/opt/brave-origin-bin/` | `brave` | `brave-origin`, Chromium's stock wrapper | `/usr/bin/brave-origin`, a bash script that reads `~/.config/brave-origin-flags.conf` and execs the launcher | `~/.config/BraveSoftware/Brave-Origin` |
| deb: `brave-origin`, from the same `brave-browser-apt-release.s3.brave.com` repo as `brave-browser`; no Conflicts, both co-install | `/opt/brave.com/brave-origin/` | `brave` | `brave-origin` | `/usr/bin/brave-origin-stable`, shipped symlink; bare `/usr/bin/brave-origin` via `update-alternatives` in postinst | same |
| rpm: `brave-origin`, from `brave-browser-rpm-release.s3.brave.com` (dnf, zypper, rpm-ostree; the bucket also serves `brave-browser-origin.repo` plus `-beta` and `-nightly` variants, byte-identical to `brave-browser.repo`) | `/opt/brave.com/brave-origin/` | `brave` | `brave-origin` | `/usr/bin/brave-origin-stable`, shipped; bare `/usr/bin/brave-origin` is a `%ghost` from `%post`'s `update-alternatives` | same |
| Beta, Nightly: `brave-origin-beta`, `brave-origin-nightly` (apt/rpm beta and nightly repos; AUR `*-bin` repackage the deb) | `/opt/brave.com/brave-origin-beta/`, `…-nightly/` | `brave` | `brave-origin-beta`, `-nightly` | `/usr/bin/brave-origin-beta`, `-nightly`, direct symlinks | `Brave-Origin-Beta`, `Brave-Origin-Nightly` — the suffixes of `brave_channel_info_posix.cc:27-38` |
| Flatpak | none. Flathub has only `com.brave.Browser`; every Origin-shaped id 404s; `flathub/com.brave.Browser` has no Origin branch, issue or PR; brave/brave-browser #55196 asking for one is open. Brave's RDN for Origin, `com.brave.Origin`, is used only by a one-star unofficial bundle. Nothing to probe | | | | |
| Snap | none. The store has `brave` only (Brave Software, verified); `brave-origin` is `resource-not-found`; the `brave` snap's channel map is `latest/{stable,candidate,beta,edge}`, its squashfs holds `opt/brave.com/brave/` only and its binary says `Brave-Browser`. Likely, not confirmed: snapd's `browser-support` interface grants `/etc/opt/chrome` and `/etc/chromium` and nothing under `/etc/brave`, which is the mechanism behind the tool's Snap warning | | | | |

- **Names the detector relies on.** Profile:
  `chromium_src/chrome/common/chrome_paths_linux.cc:26-27` —
  `BraveSoftware/Brave-Origin` plus the channel suffix under
  `IS_BRAVE_ORIGIN_BRANDED`. Package: `build/config.gni:71-79`
  (`brave_linux_package_name = "brave-origin"`), `installer/linux/sources.gni:8-9`.
  Desktop ids: `channel_info_posix.cc:64-74` — `brave-origin[-beta|-nightly|-dev].desktop`,
  `StartupWMClass=brave-origin`. Processes: the browser's comm is `brave` on
  every packaging; the launcher's bash process stays alive around it
  (brave-core's `chrome-installer-linux-common-wrapper.patch` drops Chromium's
  `exec -a`) with the comm it was started by — `brave-origin` from the AUR
  wrapper, `brave-origin-st` (comm's 15-character cap) from the deb/rpm desktop
  file's `brave-origin-stable`; the profile's `SingletonLock` covers the
  truncated case. The shipped man page's `$HOME/.config/brave-origin` is
  Chromium template text and wrong.
- **What the tool does with it.** `LINUX_CHANNELS` carries `origin`,
  `origin-beta`, `origin-nightly` (no `origin-dev`: named in source, never
  published). `detect_brave()` probes `/opt/brave-origin-bin/brave`,
  `/opt/brave.com/brave-origin/brave-origin`, `/opt/brave.com/brave-origin/brave`,
  then `brave-origin-stable`, `brave-origin`, `brave-origin-beta` and
  `brave-origin-nightly` on `PATH`; reports `arch (Brave Origin)`,
  `deb/rpm (Brave Origin)`, `unknown (Brave Origin)`, or `arch: Stable, Origin`
  beside a regular Brave. Origin's profiles join prefs repair and the running
  check; `--channels` accepts the three ids. A `notes` list beside `warnings`
  keeps the launch line in the success colour.
- **Regular Brave in "Origin mode" is still regular Brave.** On Linux the free
  tier is a click at `brave://settings/origin` (`brave_origin_settings_handler_impl.cc`
  `ProceedFree` → `BraveOriginService::AcceptFreeTier`); it sets
  `brave.origin.free_tier_accepted` and `policies_were_enforced` in `Local State`
  and keeps toggles in `brave.brave_origin.policies`. Same binary, same
  `Brave-Browser` profile, every feature compiled in, the Flatpak included.
  Nothing for the detector to do; every row live.
- **A managed file outranks Origin's own layer; it cannot revive what Origin
  compiled out.** Origin enforces its debloat through `BraveBrowserPolicyProvider`
  and `BraveProfilePolicyProvider`, which emit `POLICY_SOURCE_BRAVE` at
  `kBravePriority` — inserted below `kEnterpriseDefault`, the lowest browser
  priority, per brave-core's own `BravePolicySourceTest.BraveHasLowerPriority`.
  `PolicyMap::MergeFrom` resolves on (level, priority), so a mandatory platform
  entry wins every conflict: `{"BraveP3AEnabled": true}` would switch P3A back
  on in Origin. Nothing this tool writes points that way.
- **Thirteen rows are dead on Origin, and the tool shows them inert.** Each
  key's `brave_simple_policy_map.h` entry sits under a buildflag whose `.gni`
  is `… && !is_brave_origin_branded`: `BraveRewardsDisabled` (`ENABLE_BRAVE_REWARDS`),
  `BraveWalletDisabled`, `TorDisabled`, `BraveVPNDisabled`, `BraveAIChatEnabled`,
  `BraveLocalAIEnabled`, `BravePlaylistEnabled`, `BraveWebDiscoveryEnabled`,
  `BraveNewsDisabled`, `BraveTalkDisabled`, `BraveSpeedreaderEnabled`,
  `BraveWaybackMachineEnabled`, `EmailAliasesEnabled`. Confirmed on the binary:
  the target prefs are not registered (nothing under `brave.wallet`,
  `brave.ai_chat`, `brave.playlist`, `brave.speedreader`, `brave.news`,
  `brave.talk`, `brave.email_aliases`, `brave.web_discovery`, `brave.wayback`,
  no `tor.*`), and injecting every Brave key as a mandatory machine policy
  through `chrome://policy/test` made none of the thirteen prefs managed —
  while `brave://policy` listed each as applied, the same blind spot the
  `BraveVPNDisabled` row documents. `BraveP3AEnabled` and `BraveStatsPingEnabled`
  are dispatched and Origin sets them `false` at the lowest priority, so a
  managed `false` is redundant but pins them; `MetricsReportingEnabled` is
  live against a default Origin already forces to `false`. Everything else —
  the five unguarded Brave privacy toggles, both Shields lists, the
  `DefaultBrave*` content settings, every Chromium key — is live. In the
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
  builds Origin's debloat set from `kBraveSimplePolicyMap` and two metadata
  tables — sixteen prefs on master. Fifteen map to keys this project exposes,
  and for every one the value the project writes equals Origin's default (the
  Brave Origin preset). The sixteenth is `PsstEnabled`. On the branded build
  only P3A and the stats ping of those fifteen are enforced by Origin itself;
  the rest are compiled out. De-AMP, Debouncing, GPC, Reduce Language and the
  Shields lists are not in Origin's tables: it leaves those at their
  enabled-by-default user setting, the direction the project forces.

## Platform policy locations, from source

- **Windows** — `HKLM\SOFTWARE\Policies\BraveSoftware\Brave`. Chromium's
  `components/policy/tools/generate_policy_source.py` emits
  `kRegistryChromePolicyKey` from `CHROMIUM_POLICY_KEY` for non-Google branding;
  brave-core's `chromium_src/…/generate_policy_source.py` overrides the constant
  to `SOFTWARE\Policies\BraveSoftware\Brave`; `chrome_browser_policy_connector.cc`
  hands it to `PolicyLoaderWin`, which brave-core does not touch. No channel or
  Origin suffix (`install_static` varies only install-dir names), so one key
  serves stable, beta, nightly and Origin. `BraveSoftware\Brave-Browser` is the
  install dir name, not the policy path. Matches Brave's own Group Policy
  documentation.
- **Linux** — `/etc/brave/policies/managed`. Chromium's default is
  `/etc/chromium/policies` (`policy_paths.cc`), unpatched; `app/brave_main_delegate.cc:166-170`
  overrides `chrome::DIR_POLICY_FILES` at startup under `IS_POSIX && !IS_MAC`,
  unconditionally; `config_dir_policy_loader.cc` appends `managed` / `recommended`.
  Channel- and Origin-independent, confirmed at runtime on Origin.
- **macOS** — `/Library/Managed Preferences/<bundle id>.plist`, bundle ids
  `com.brave.Browser`, `.beta`, `.nightly`. Chromium's `chrome_browser_policy_connector.cc`
  uses the running app's own bundle id for non-Google branding and
  `policy_loader_mac.mm` builds the path from it; the ids come from brave-core
  `app/theme/brave/BRANDING*` via `branding.gni`. `MAC_CHANNELS` matches them.
  A Dev channel (`com.brave.Browser.dev`) exists and is not listed.

## Cross-cutting facts

- **`ForUrls` patterns.** Brave's docs' "wildcards are not supported" means
  `*.example.com`. The scheme-wide `https://*` and `http://*` this tool uses
  are valid `ContentSettingsPattern` syntax and apply. They are never written to
  the profile: `PolicyProvider` keeps policy content settings in an in-memory
  `OriginValueMap` and is read-only (`SetWebsiteSetting` returns false,
  `ClearAllContentSettingsRules` is empty); the Shields keys take the same path
  via brave-core's `patches/components-content_settings-core-browser-content_settings_policy_provider.cc.patch`
  and its `rewrite/` twin. The `profile.content_settings.exceptions.braveShields`
  entries the repair logic scrubs were written by pre-1.x SlimBrave as ordinary
  user settings; the repair undoes that, not anything current Brave does.
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
  value. Off at `v1.94.121` and `1.95.x`, **on by default on desktop from
  `1.96.x`**; the opt-in defaults to false. Precedence favours this tool
  (`kBravePriority` is the lowest); the loser is kept as a conflict, so from
  1.96 a user with the mode on sees `IDS_POLICY_CONFLICT_DIFF_VALUE` warnings on
  `brave://policy` for those keys.
- **Where brave-core overrides live.** `chromium_src/`, `patches/` **and**
  `rewrite/*.yaml` coexist, and overrides move between them across branches
  (`device_features.cc` is `chromium_src` on 1.95.x, `rewrite/` + `patches/` on
  1.96.x, same effect). Searching one directory proves nothing.
- **Content-setting enums are not uniform.** `DefaultNotificationsSetting`,
  `DefaultGeolocationSetting`, `DefaultSensorsSetting` take 1 / 2 / 3. The
  other five permission keys are ask-or-block only: 1 is not in their schema
  and a file naming it is rejected. The choice lists are per key for that
  reason; a value outside a key's legal set is left unmanaged on import and
  named in the message; a quoted `"1"` is rejected by the same type-strict test
  in all three implementations.
- **Version gating.** A key that predates the running Brave is silently
  ignored. By milestone: cr138 (News, Talk, Speedreader, Wayback, P3A, Stats
  Ping, Web Discovery) · cr139 (Playlist) · cr140 (De-AMP, Debouncing, Reduce
  Language) · cr141 (Fingerprinting V2) · cr142 (GPC, Tracking Query Parameters,
  the `DefaultBrave*` enforcers) · cr147 (Email Aliases — Brave 1.92) · cr149
  (Local AI — Brave 1.94). The highest Chromium-inherited milestone is
  `DefaultWindowManagementSetting` at cr111.

## Considered and rejected — do not add

The YAML or the brave-core source is the tiebreaker in every case.

| Key(s) | Status | Why not |
|---|---|---|
| `EnableDoNotTrack` | ❌ | does not exist in Chromium's policy index; DNT has no enterprise policy. Was written and silently ignored until removed. GPC (`BraveGlobalPrivacyControlEnabled`) is the working equivalent |
| `MediaRecommendationsEnabled` | 💀 | **dead key.** The YAML is open (`chrome.*:87-`, no cap, not deprecated) but Chromium removed the handler and the pref with Kaleidoscope in `3e5b1be4a` (2021-01-06); `policy_test_cases.json` said "removed since Chrome 89" at M90 and `pref_mapping/MediaRecommendationsEnabled.json` says `Policy was removed` at the tag and at main; zero references in brave-core. Validated, rendered in `brave://policy`, did nothing since Chromium 89. Removed from all three scripts and four presets; an old export naming it is reported as ignored on import. The pref-mapping file is the tiebreaker |
| `PromotionalTabsEnabled` | ⛔ | `deprecated: true`. Its live successor `PromotionsEnabled` (`chrome.*:128-`) writes the same `prefs::kPromotionsEnabled`; not exposed either, because the surfaces it gates are Chrome-branded ones Brave replaces |
| `IPFSEnabled` | ⛔ | see the Brave table: deprecated, feature gone since 1.69.153 |
| all `PrivacySandbox*` | ⛔ / neutralised | `PrivacySandboxFingerprintingProtectionEnabled` capped at cr145, `PrivacySandboxIpProtectionEnabled` at cr143; `AdMeasurement`, `AdTopics`, `SiteEnabledAds`, `Prompt` are `deprecated: true`, uncapped, three still dispatched at the tag. What neutralises them in Brave is `BravePrivacySandboxSettings` (every `Is*Allowed` false, `IsPrivacySandboxRestricted` true), the feature overrides in `feature_defaults_unittest.cc` and the renderer client disabling Fledge/Topics |
| `ComponentUpdatesEnabled` | ✅ live, harmful | **actively harmful.** Chromium honours it per installer (`supports_group_policy_enable_component_updates`): Brave's `AdBlockComponentInstallerPolicy` returns true, so the Shields resources, filter-list catalog and filter lists would freeze; Widevine and the SSL error assistant too. The Tor client, debounce rules and HTTPS-upgrade exceptions ride `BraveComponentInstallerPolicy`, which returns false, and CRLSets keep updating |
| `FeedbackSurveysEnabled`, `SafeBrowsingSurveysEnabled` | ⚠️ no-op in Brave | brave-core patches `RunCommonLaunchChecks` to always error; no survey ever launches |
| `BrowserNetworkTimeQueriesEnabled` | ⚠️ no-op in Brave | `kNetworkTimeServiceQuerying` is force-disabled in Brave (`chromium_src/components/network_time/network_time_tracker.cc` at the tag; `rewrite/…network_time_tracker.cc.yaml` + `patches/` on master) |
| `DomainReliabilityAllowed` | ⚠️ no-op in Brave | `brave_main_delegate.cc` appends `--disable-domain-reliability` unconditionally |
| `BuiltInAIAPIsEnabled` | ⚠️ no-op in Brave | `GetOptimizationTargetForFeature` returns UNKNOWN in Brave; the APIs never initialise |
| `DefaultWebBluetoothGuardSetting`, `DefaultFileSystemReadGuardSetting`, `DefaultFileSystemWriteGuardSetting` | ⚠️ redundant | already feature-disabled in Brave, which is why the device-API set is USB+Serial+HID. File System Access is `kFileSystemAccessAPI` `FEATURE_DISABLED_BY_DEFAULT` in `chromium_src/third_party/blink/common/features.cc`; Web Bluetooth is not in the feature-defaults list at all — `BraveBluetoothDelegate::AllowWebBluetooth` returns `kBlockGloballyDisabled` unless `kBraveWebBluetoothAPI` (off, `chrome://flags#brave-web-bluetooth-api`) is on |
| `DefaultThirdPartyStoragePartitioningSetting` | ❌ removed | removed after cr145 |
| `FirstPartySetsEnabled`, `RelatedWebsiteSetsEnabled` | ⛔ / neutralised | `deprecated: true`, capped `113-152` / `120-152` on main (bites when Brave rebases to cr153); at the tag still dispatched through `SimpleDeprecatingPolicyHandler` into `kPrivacySandboxRelatedWebsiteSetsEnabled`. Moot: `BravePrivacySandboxSettings` forces that pref back to false whenever it becomes true |
| `InsecurePrivateNetworkRequestsAllowed`, `LocalNetworkAccessRestrictionsEnabled` | ❌ removed | removed after cr137 and cr144; `deprecated: true`, capped, undispatched at the tag. The successors (`LocalNetworkAccess{Blocked,Allowed}ForUrls`, `LocalNetworkAccessRestrictionsTemporaryOptOut`, `LocalNetworkAccessPermissionsPolicyDefaultEnabled`, the `LocalNetwork*` / `LoopbackNetwork*ForUrls` lists) are URL-pattern lists, not a posture; `["*"]` would cut every site off from routers, NAS and local dev servers. Brave force-enables `kLocalNetworkAccessChecksWebSockets` itself |
| `UrlKeyedMetricsAllowed` | 🕓 future_on only | `future_on:` only, never shipped; its handler would write the pref `UrlKeyedAnonymizedDataCollectionEnabled = false` already writes |
| `Miscellaneous/AutofillSettings` | 🕓 cr154 | `supported_on: chrome.*:154-` on main (`06b1ad6`, 2026-08-31), still `future_on:` at every Chromium tag a Brave branch pins. A per-URL-pattern blocklist, not a toggle; `[{"*", ["all"]}]` would duplicate the two Autofill keys with a heavier schema |
| `DefaultMediaStreamSetting` | ⛔ | `deprecated: true`; a microphone/camera switch would use `AudioCaptureAllowed` / `VideoCaptureAllowed` |
| `BraveSearchResultAdsEnabled` | 💀 from 1.95 | a one-release key: merged 2026-07-20, reverted (`cf025361c`) on master and `1.95.x` but never uplifted to `1.94.x`, so the shipping 1.94.121 dispatches it (`BooleanDisablingPolicyHandler` into `kOptedInToSearchResultAds`; `false` disables, `true` ignored) and it is 404 from 1.95.x on. The replacement universal pref `brave.brave_ads.sponsored.enabled` (`a723c7b00`, `1.96.x`) has no policy key; brave-browser#57204 is open and demilestoned. A toggle that dies on the next update is worse than none |

## What's next

Watch list, each with the trigger that turns it into work:

- `PsstEnabled` — `components/psst/core/common/features.cc` flipping
  `kEnablePsst` on a shipping branch. Then a checkbox writing 0, labelled
  Brave 1.95+, restart note; it joins `ORIGIN_BUILTIN_KEYS` too
  (`enable_psst = … && !is_brave_origin_branded`).
- `BraveSearchResultAdsEnabled`'s successor — a commit under
  `policy_definitions/BraveSoftware` that references `kSponsoredEnabled`.
- `BackgroundTabFreezingEnabled` (`686333c`, `chrome.*:155-`, `per_profile: false`,
  default on — a Performance & Bloat lever beside Memory Saver) and
  `ExtensionReviewPromptsEnabled` (`23e107e`, `chrome.*:154-` — a promo
  surface, low value) — only once a shipping Brave pins a Chromium ≥
  the gate *and* the YAML fetches 200 at that exact tag. `1.96.x` pins
  153.0.8010.28, so not yet.
- `AutofillSettings` — re-check once the shipping Brave is on cr154 or later.
- `RemoteDebuggingAllowed` — drop the restart note only when the shipping
  Brave pins ≥ 154.0.8029.0.
- Ad Block Only Mode — a README sentence about the `brave://policy` conflict
  warnings when 1.96 ships.
- Brave Origin — real-machine runs of the deb on Debian/Ubuntu, the rpm on
  Fedora/openSUSE, Origin beta and nightly, and mixed machines with regular
  Brave beside Origin. The checklist with exact commands and expected output is
  `TESTING-brave-origin.md` on the `brave-origin-detection` branch.
- Cosmetic: `slimbrave-mac.py` should label the `BraveVPNDisabled` row as the
  Linux script does; a macOS Dev channel (`com.brave.Browser.dev`) could join
  `MAC_CHANNELS`.
- Under consideration, not decided: a Preview (dry-run diff of what Apply will
  change) and a Verify (read the policy location back and compare) — the two
  usability features the Windows-only Brave-Free-Origin project has and this
  one lacks.

## Done log

One line per change to what the tool writes or how this document judges it,
with the reference that carries the detail. Newest first.

| When | What | Reference |
|---|---|---|
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
  tag with `?ref=<tag>`.
- **One Chromium YAML at the pinned tag:**
  `https://raw.githubusercontent.com/chromium/chromium/<tag>/components/policy/resources/templates/policy_definitions/<Group>/<Key>.yaml`
  — read `deprecated`, `supported_on`, `future_on`, `features`, `schema`.
- **Dispatch of a Chromium key:** `chrome/browser/policy/configuration_policy_handler_list_factory.cc`
  at the tag, and `components/policy/test/data/pref_mapping/<Key>.json`
  (`Policy was removed` = dead).
- **Brave YAML at a release branch:**
  `https://raw.githubusercontent.com/brave/brave-core/<1.9N.x>/components/policy/resources/templates/policy_definitions/BraveSoftware/<Key>.yaml`;
  walk branches to find where a key first ships.
- **Brave dispatch and guards:** clone brave-core at the tag
  (`git clone --depth 1 --branch v<ver>`), then `browser/policy/brave_simple_policy_map.h`
  for the `#if BUILDFLAG(...)` around each entry and
  `grep -rn "is_brave_origin_branded" --include='*.gni' components/` for what
  Origin compiles out. Search `chromium_src/`, `patches/` and `rewrite/` before
  saying an override lapsed.
- **Origin's own set:** `browser/brave_origin/brave_origin_service_factory.cc`.
- **Runtime proof of the Linux policy dir:** with Brave running, the inotify
  watches in `/proc/<pid>/fdinfo/<fd>` of the browser process map (by inode)
  to `/etc/brave/policies/managed`. To read `chrome://policy` headlessly, drive
  `--remote-debugging-pipe` and walk the shadow DOM; `--dump-dom` hangs on this
  build, and `innerText` does not traverse shadow roots, so the policy rows are
  missing from it. Always pass a scratch `--user-data-dir`, or the run
  creates `~/.config/BraveSoftware/Brave-Origin-<Channel>` profiles that make
  the detector report channels that are not installed.

## Re-verification procedure

0. Start in the source, not the templates: `browser/policy/brave_simple_policy_map.h`
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
