# Policy Audit — August 2026

Verification of every policy key SlimBrave Neo manages, against the two
authoritative sources:

- **Brave-specific keys:** [brave-core policy definitions](https://github.com/brave/brave-core/tree/master/components/policy/resources/templates/policy_definitions/BraveSoftware) (per-policy YAML: `deprecated`, `supported_on`, `features`, schema) — read at master tree `5f1127a` on 2026-08-29; 30 policies
- **Chromium-inherited keys:** [Chromium policy definitions](https://chromium.googlesource.com/chromium/src/+/main/components/policy/resources/templates/policy_definitions/) (same YAML format) — read at `chromium/main` `3477903` (policy_definitions tree `f4b77f4`) on 2026-08-29; the index holds 1,522 YAML files, 67 of them `.group.details.yaml` group metadata, so **1,455 policies**

`supported_on` counts Chromium milestones, so this document records milestones
(`cr138`) and not Brave versions. Rough alignment at the time of writing:
cr138 ≈ 1.80, cr139 ≈ 1.81, cr140 ≈ 1.82, cr141 ≈ 1.83, cr142 ≈ 1.84,
cr147 ≈ 1.89, cr148 ≈ 1.90, cr149 ≈ 1.91, cr150 ≈ 1.92, cr151 ≈ 1.93,
cr152 ≈ 1.94.
Current stable is Brave 1.94.117 on Chromium 152.0.7977.64, released
2026-08-27.

**Do not turn `supported_on` into a Brave version.** The milestone says where
the policy landed in the tree, not where Brave shipped it, and the two drift by
whole releases: `EmailAliasesEnabled` is `chrome.*:147-` (≈1.89 by the line
above) but its YAML is 404 on the 1.89.x, 1.90.x and 1.91.x release branches
and first appears on **1.92.x**; `BraveLocalAIEnabled` is `chrome.*:149-`
(≈1.91) and first appears on **1.94.x**. The reliable method is to probe the
release branches directly —
`raw.githubusercontent.com/brave/brave-core/<branch>/components/policy/resources/templates/policy_definitions/BraveSoftware/<Key>.yaml`,
walking `1.9N.x` branches until it stops 404ing. Any version number in a toggle
label comes from that probe, never from the mapping above.

## Re-audit log

Every pass records the upstream revisions it read, so the next one can diff
against them instead of re-verifying every key from scratch. A row marked
**stale as of `<date>`** below has been superseded by a later pass: the
original wording is kept because the *reasoning* is the audit trail, and
knowing why a decision was made — and what changed under it — is the point.

### 2026-09-03 — targeted: `HardwareAccelerationModeEnabled` second value

**Not a full pass.** One key re-read to answer a user report that the tool could
pin GPU acceleration on but not off.

- **Read at:** `chromium/main`,
  `components/policy/resources/templates/policy_definitions/Miscellaneous/HardwareAccelerationModeEnabled.yaml`
  (HTTP 200). `schema: type boolean`, `default: true`, `supported_on: chrome.*:46-`,
  `dynamic_refresh: false`, `per_profile: false`. Both members named in `items:`
  — `true` "Enable graphics acceleration", `false` "Disable graphics acceleration".
- **Verdict:** no new key and no new policy surface. The `false` state of a key
  already audited and already written by this project is now reachable, as a
  mutually exclusive pair beside the force-on row, matching the three existing
  same-key pairs (`IncognitoModeAvailability`, `ChromeVariations`,
  `DefaultBraveReferrersSetting`). Inventory 78 → **79 rows** over an unchanged **75 distinct keys** — the pair
  shares one, as the three existing same-key pairs do. All three implementations updated together; PS1↔Python parity green.
- **Deliberately in no preset.** Chromium's default is on, so forcing it off
  costs rendering performance and battery; it is a troubleshooting lever for a
  faulty GPU driver, a VM or RDP session, or screen-sharing corruption — not a
  privacy posture. Same reasoning that keeps the device-permission guards out of
  every preset.
- **No point release.** Nothing shipped in v2.2.0 changed behaviour; this exposes
  a third state of an existing key and rides the next release.
- **Not re-verified in this pass:** every other key, and the upstream revisions
  the 2026-08-29 entry pinned. Those still stand as that pass left them.

### 2026-08-29 — all 75 keys re-verified, no change required

- **Read at:** `chromium/main` `3477903` (policy_definitions tree `f4b77f4`; 1,522 YAML, 67 group metadata, **1,455 policies**) and `brave-core` master `5f1127a` (**30 policies**, name-for-name unchanged).
- **Verdict:** every key fetched 200. Zero `deprecated:`, zero `deprecated_in_favor_of:`, zero upper-bounded `supported_on:`. Every value still a legal schema member meaning what its label claims. All three implementations still in lockstep. No script, preset or test changed.
- **Chromium moved 1,456 → 1,455**, fully accounted for, and none of it a key this project writes: `6a766cf` created the `Relaunch/` group and moved 6 policies out of `Miscellaneous/` (+1 group file, 0 policies); `7809ff5` reverted three ChromeOS device-level LNA policies (−3); `1b1aa2f` added `RendererAccessibilityEnabled` (+1); `a98c395` added `DeviceOsMigrationTargetDate` (+1).
- **Only in-inventory change across all 59 commits in the window:** `RemoteDebuggingAllowed` flipped `dynamic_refresh` false → true on 2026-08-27 (`80ad0b9`). That landed in M154 territory and Brave stable is on cr152, so the restart note stays correct until Brave rebases past it. Do not drop the note early.
- **Brave stable advanced** 1.93.134 / cr151 → **1.94.117 / cr152** (2026-08-27). Nothing SlimBrave manages was removed or sunset between 1.92.134 and 1.94.117; the diff on `brave_simple_policy_map.h` across master / 1.94.x / 1.93.x is additions only.
- **Superseded by this pass:** the `BraveVPNDisabled`, `BraveLocalAIEnabled` and `PsstEnabled` rows, each marked inline below.

### 2026-08-13 — initial full audit

- Read at `brave-core` master tree `855ca5b` (30 policies) and `chromium/main` (1,522 YAML, 66 group metadata, 1,456 policies).
- Established the tables below: every key verified against source, `EnableDoNotTrack` removed as non-existent, the branch-probing method adopted over `supported_on` arithmetic, and the Brave-version column dropped because one milestone had been mapped to three different Brave releases.

## Brave-specific keys

| Key | Status | Min milestone | Type | Notes |
|---|---|---|---|---|
| BraveP3AEnabled | ✅ active | cr138 | bool | unset = enabled; `dynamic_refresh: false` — needs browser restart; browser-wide (`per_profile: false`) |
| BraveStatsPingEnabled | ✅ active | cr138 | bool | unset = enabled; `dynamic_refresh: false` — needs browser restart; browser-wide (`per_profile: false`) |
| BraveGlobalPrivacyControlEnabled | ✅ active | cr142 | bool | dynamic refresh |
| BraveDeAmpEnabled | ✅ active | cr140 | bool | dynamic refresh |
| BraveDebouncingEnabled | ✅ active | cr140 | bool | dynamic refresh |
| BraveTrackingQueryParametersFilteringEnabled | ✅ active | cr142 | bool | only effective while Shields enabled |
| BraveReduceLanguageEnabled | ✅ active | cr140 | bool | dynamic refresh |
| BraveRewardsDisabled | ✅ active | cr105 | bool | true = disable |
| BraveWalletDisabled | ✅ active | cr106 | bool | also disables web3 + decentralized DNS |
| BraveVPNDisabled | ✅ active | cr112 | bool | Windows/macOS/Android/iOS only — `enable_brave_vpn` omits `is_linux`, so the `brave_simple_policy_map.h` entry is compiled out of Linux builds and the key is a silent no-op there; `brave://policy` still renders it as cleanly applied. The Linux row is labelled accordingly rather than removed — `enable_brave_vpn_v2_apps` already names `is_linux` for a future rollout. **Stale as of 2026-08-29:** only `slimbrave-linux.py` carries the caveat; `slimbrave-mac.py` also runs on Linux and labels the row plainly. Cosmetic — the written value is correct on every platform |
| BraveAIChatEnabled | ✅ active | cr121 | bool | false = disable Leo; does **not** cover on-device models — see BraveLocalAIEnabled |
| BraveLocalAIEnabled | ✅ active | cr149 | bool | **added August 2026**; false = skip registering the on-device model component (EmbeddingGemma, `ejhejjmaoaohpghnblcdcjilndkangfe`), delete its directory, and stop history vector-indexing. Separate buildflag (`ENABLE_LOCAL_AI`) and prefs from AI Chat. ~~Forward-looking: first release branch carrying the YAML is **1.94.x**, older Brave ignores it.~~ **Stale as of 2026-08-29:** 1.94 went stable on 2026-08-27, so this is live in the shipping browser. Its absence from every preset now needs a product reason, not a version one. `dynamic_refresh: false` — needs browser restart; browser-wide (`per_profile: false`). Deliberately in no preset |
| BraveShieldsDisabledForUrls | ✅ active | cr107 | list | see pattern note below; `dynamic_refresh: false` / `per_profile: false` — needs browser restart |
| BraveShieldsEnabledForUrls | ✅ active | cr107 | list | **added June 2026**; counterpart to the row above; `dynamic_refresh: false` / `per_profile: false` — needs browser restart |
| BraveNewsDisabled | ✅ active | cr138 | bool | |
| BraveTalkDisabled | ✅ active | cr138 | bool | |
| BravePlaylistEnabled | ✅ active | cr139 | bool | |
| BraveWebDiscoveryEnabled | ✅ active | cr138 | bool | unset = **disabled** by default; `dynamic_refresh: false` — needs browser restart |
| BraveSpeedreaderEnabled | ✅ active | cr138 | bool | desktop only |
| BraveWaybackMachineEnabled | ✅ active | cr138 | bool | desktop only |
| TorDisabled | ✅ active | cr78 (Win) / cr93 (mac, Linux) | bool | desktop only |
| EmailAliasesEnabled | ✅ active | cr147 | bool | **added June 2026**; ships in **Brave 1.92** — branch-probed, not derived from `supported_on` (see the warning above); older Brave ignores it |
| DefaultBraveAdblockSetting | ✅ active | cr142 | int enum | **added June 2026**; 1 = allow ads, 2 = block |
| DefaultBraveFingerprintingV2Setting | ✅ active | cr141 | int enum | **added June 2026**; 1 = off, 3 = standard (no value 2) |
| DefaultBraveHttpsUpgradeSetting | ✅ active | cr142 | int enum | **added June 2026**; 1 = allow HTTP, 2 = strict, 3 = standard |
| DefaultBraveReferrersSetting | ✅ active | cr142 | int enum | 1 = permissive, 2 = cap to strict origin; both values exposed as mutually exclusive toggles (issue #9); never put value 1 in a preset |
| DefaultBraveRemember1PStorageSetting | ✅ active | cr142 | int enum | **added June 2026**; 1 = remember, 2 = forget on close |
| BraveSyncUrl | ✅ active | cr129 (+ `android:142-`) | string | **deliberately not exposed** — it's a custom-sync-server URL, not a debloat toggle; use a hand-written policy file if you self-host sync |
| PsstEnabled | 🕓 master only | — | bool | **deliberately not exposed** — a no-op twice over today: `kEnablePsst` is `FEATURE_DISABLED_BY_DEFAULT`, ~~and the YAML is on **no** release branch (1.92.x / 1.93.x / 1.94.x all 404)~~, so nothing dispatches the key. **Stale as of 2026-08-29:** the YAML now ships on **1.95.x**, so the branch half of this rationale has lapsed — it is a no-op once over, not twice. Still correctly unexposed: `kEnablePsst` remains `FEATURE_DISABLED_BY_DEFAULT` on master, and that flag — not the branch — is now the trigger to re-check. Worth re-checking: PSST downloads per-site scripts, injects them into logged-in origins to detect sign-in, then drives your authenticated account through settings URLs flipping switches (`enable_psst = !is_android && !is_ios`). Revisit once it reaches a release branch |
| IPFSEnabled | ⛔ `deprecated: true` | — | bool | IPFS feature removed from Brave 1.69.153 (Aug 2024); not exposed by SlimBrave Neo. **Do not re-add** — this key has bounced in/out of this project before; the brave-core YAML is the tiebreaker |

## Chromium-inherited keys

| Key | Status | Type | Project value | Notes |
|---|---|---|---|---|
| MetricsReportingEnabled | ✅ active | bool | false | `dynamic_refresh: false` — needs browser restart |
| SafeBrowsingProtectionLevel | ✅ active | int enum | 0 (= no protection) | 0/1/2 valid. Brave proxies Safe Browsing through its own hosts — `safebrowsing_api_endpoint = "safebrowsing.brave.com"` in `components/safebrowsing/BUILD.gn`, and `static_redirect_helper.cc` rewrites all three Google SB hosts to `sb-ssl.brave.com` / `safebrowsing2.brave.com` — so Google never sees a lookup even with Safe Browsing **on**. Turning it off buys almost no privacy and costs the phishing/malware interstitials; excluded from every preset for that reason |
| SafeBrowsingExtendedReportingEnabled | ✅ active | bool | false | |
| UrlKeyedAnonymizedDataCollectionEnabled | ✅ active | bool | false | |
| AutofillAddressEnabled | ✅ active | bool | false | |
| AutofillCreditCardEnabled | ✅ active | bool | false | |
| PasswordManagerEnabled | ✅ active | bool | false | |
| BrowserSignin | ✅ active | int enum | 0 (= disable) | `dynamic_refresh: false` — needs browser restart |
| EnableDoNotTrack | ❌ **does not exist** | — | — | not in Chromium's policy index (checked all 1,456). DNT has no enterprise policy in Chromium; the key was silently ignored. Removed June 2026. GPC (`BraveGlobalPrivacyControlEnabled`) is the working equivalent |
| WebRtcIPHandling | ✅ active | string enum | disable_non_proxied_udp | valid enum member |
| QuicAllowed | ✅ active | bool | false | `dynamic_refresh: false` — needs browser restart |
| BlockThirdPartyCookies | ✅ active | bool | true | |
| ForceGoogleSafeSearch | ✅ active | bool | true | |
| IncognitoModeAvailability | ✅ active | int enum | 1 or 2 | 0 = enabled, 1 = disabled, 2 = forced; `dynamic_refresh: false` — needs browser restart |
| SyncDisabled | ✅ active | bool | true | |
| BackgroundModeEnabled | ✅ active (Win/Linux **only**) | bool | false | `chrome.win:19-` + `chrome.linux:19-`; no macOS support in Chromium. `slimbrave-mac.py` also runs on Linux, so the row is gated there on `sys.platform.startswith("linux")` and inserted at index 0 of Performance & Bloat to match the other two scripts — on macOS the key is dropped and the import message names it as not applicable |
| ShoppingListEnabled | ✅ active | bool | false | re-verified — not deprecated |
| AlwaysOpenPdfExternally | ✅ active | bool | true | |
| TranslateEnabled | ✅ active | bool | false | |
| SpellcheckEnabled | ✅ active | bool | false | desktop only; mutually exclusive with SpellCheckServiceEnabled below |
| SearchSuggestEnabled | ✅ active | bool | false | |
| PrintingEnabled | ✅ active | bool | false | |
| DefaultBrowserSettingEnabled | ✅ active | bool | false | desktop only |
| DeveloperToolsAvailability | ✅ active | int enum | 2 (= disallowed) | does **not** cover the CDP port — see RemoteDebuggingAllowed below |
| DnsOverHttpsMode | ✅ active | string enum | off/automatic/secure | |
| DnsOverHttpsTemplates | ✅ active | string | URL template | **required** for `secure` and `custom`, optional for `automatic`, ignored for `off`. Mode `secure` with an empty template destroys all name resolution — the templates pref is blanked, `CanUseSecureDnsTransactions()` returns false, and the system-resolver fallback is gated on `secure_dns_mode != kSecure` (crbug.com/1326526). All three scripts refuse that combination |
| PasswordLeakDetectionEnabled | ✅ active (cr79+) | bool | false | **added July 2026**; stops the online breach-list credential check |
| NetworkPredictionOptions | ✅ active (cr38+) | int enum | 2 (= never predict) | **added July 2026**; 0 = always, 2 = never (value 1 deprecated in-source) |
| PaymentMethodQueryEnabled | ✅ active (cr80+) | bool | false | **added July 2026**; sites' canMakePayment always answers "none saved" |
| AlternateErrorPagesEnabled | ✅ active (cr8+) | bool | false | **added July 2026**; belt-and-braces — Brave ships the web-service error page off by default |
| DefaultNotificationsSetting | ✅ active (cr10+) | int enum | 1, 2 or 3 — user-selected; key omitted entirely when the row is left unmanaged | **added July 2026**; full legal enum **1 = allow, 2 = block, 3 = ask** — all three members valid, all three exposed. Re-verified against `chromium/main` **2026-08-28**, when the row became a choice row (Not managed / Allow / Ask / Block) instead of a checkbox that only ever wrote 2 |
| DefaultGeolocationSetting | ✅ active (cr10+) | int enum | 1, 2 or 3 — user-selected; key omitted entirely when the row is left unmanaged | **added July 2026**; full legal enum **1 = allow, 2 = block, 3 = ask** — all three members valid, all three exposed. Re-verified against `chromium/main` **2026-08-28**; choice row (Not managed / Allow / Ask / Block) |
| DefaultSensorsSetting | ✅ active (cr88+) | int enum | 1, 2 or 3 — user-selected; key omitted entirely when the row is left unmanaged | **added July 2026**; motion/orientation sensors — fingerprinting vector. Full legal enum **1 = allow, 2 = block, 3 = ask** — all three members valid, all three exposed. Re-verified against `chromium/main` **2026-08-28**; choice row (Not managed / Allow / Ask / Block) |
| ExtensionInstallBlocklist | ✅ active (cr86+) | list | `["*"]` | **added July 2026**; `*` blocks all installs and disables already-installed extensions |
| SafeSitesFilterBehavior | ✅ active (cr69+) | int enum | 1 (= filter) | **added July 2026**; not a local filter — it sends every navigation URL, iframes included, to Google's Safe Search API for classification (`tags: [filtering, google-sharing]`). Disclosed in the tooltip and the README because the same tool ships `SafeBrowsingProtectionLevel = 0` |
| BrowserGuestModeEnabled | ✅ active (cr38+) | bool | false | **added July 2026**; guest windows bypass profile restrictions — parental hole |
| HighEfficiencyModeEnabled | ✅ active (cr108+) | bool | true | **added July 2026**; forces Memory Saver tab discarding on |
| HardwareAccelerationModeEnabled | ✅ active (cr46+) | bool | true / false | **added July 2026**, opposite value **September 2026**; both states exposed as a mutually exclusive pair (`Group = "hwaccel"`) because unset is not the same as off — Chromium's default is on, so absent means user-controlled and `false` means forced off. `dynamic_refresh: false` — needs browser restart |
| EnableMediaRouter | ✅ active (cr52+) | bool | false | **added July 2026**; disables Cast + its LAN device discovery; `dynamic_refresh: false` — needs browser restart |
| MediaRecommendationsEnabled | ✅ active (cr87+) | bool | false | **added July 2026** |
| ChromeVariations | ✅ active (cr83+) | int enum | 1 or 2 | **added August 2026**; 0 = all variations, 1 = critical fixes only, 2 = none. Closes the last remote-configuration channel: Brave fetches a Griffin seed from `variations.brave.com` that flips features in an installed browser. Maps to `variations::prefs::kVariationsRestrictionsByPolicy`; brave-core does not override the restriction path. Exposed as two mutually exclusive rows — value 2 also blocks the emergency killswitches used to turn off a broken or unsafe feature, so it is kept out of every preset |
| SpellCheckServiceEnabled | ✅ active (cr22+) | bool | false | **added August 2026**; removes the Google spelling web service while offline dictionaries keep working. Upstream states it "will have no effect" once `SpellcheckEnabled` is false, which is why the two rows are mutually exclusive |
| RemoteDebuggingAllowed | ✅ active (cr93+) | bool | false | **added August 2026**; blocks `--remote-debugging-port` / `--remote-debugging-pipe`, the CDP cookie-theft vector `DeveloperToolsAvailability` leaves open. Inherited unchanged by Brave. `dynamic_refresh: false` — needs browser restart. Breaks Puppeteer/Playwright and `brave://inspect` |
| DNSInterceptionChecksEnabled | ✅ active (cr80+) | bool | false | **added August 2026**; stops the three random 7–15 char hostname lookups at startup and on every network change — a per-launch beacon visible to the ISP or DoH resolver |
| BasicAuthOverHttpEnabled | ✅ active (cr88+) | bool | false | **added August 2026**; refuses HTTP Basic auth over cleartext so base64 credentials are never sent in the clear. Breaks legacy plain-HTTP appliance logins |
| DefaultWebUsbGuardSetting | ✅ active (cr67+) | int enum | 2 or 3 — user-selected; key omitted entirely when the row is left unmanaged | **added August 2026**; full legal enum **2 = block, 3 = ask — there is no value 1**. Unlike the three settings above, this key has no allow member, so the row offers Not managed / Ask / Block and never an Allow. Asymmetry confirmed against `chromium/main` **2026-08-28**. Ships enabled in Brave (no feature override). Breaks Ledger/Trezor web wallets and in-browser firmware flashers |
| DefaultSerialGuardSetting | ✅ active (cr86+) | int enum | 2 or 3 — user-selected; key omitted entirely when the row is left unmanaged | **added August 2026**; full legal enum **2 = block, 3 = ask — no value 1**, same Ask-or-Block-only shape as WebUSB, confirmed against `chromium/main` **2026-08-28**. Same class as WebUSB — breaks in-browser microcontroller tooling |
| DefaultWebHidGuardSetting | ✅ active (cr100+) | int enum | 2 or 3 — user-selected; key omitted entirely when the row is left unmanaged | **added August 2026**; full legal enum **2 = block, 3 = ask — no value 1**, confirmed against `chromium/main` **2026-08-28**. Completes the device-API trio. May break security keys and gamepad configurators that use WebHID rather than WebAuthn. The trio is USB+Serial+HID and not all six because WebBluetooth and File System Access are already feature-disabled in Brave |
| DefaultLocalFontsSetting | ✅ active (cr103+) | int enum | 2 or 3 — user-selected; key omitted entirely when the row is left unmanaged | **added August 2026**; full legal enum **2 = block, 3 = ask — no value 1**, confirmed against `chromium/main` **2026-08-28**. `queryLocalFonts()` returns the installed font list, a top-tier fingerprint that Shields' farbling does not cover — farbling handles CSS/canvas measurement, not the explicit enumeration permission |
| DefaultWindowManagementSetting | ✅ active (cr111+) | int enum | 2 or 3 — user-selected; key omitted entirely when the row is left unmanaged | **added August 2026**; full legal enum **2 = block, 3 = ask — no value 1**, confirmed against `chromium/main` **2026-08-28**. Stops sites reading the full multi-monitor topology. Complementary to `kBraveBlockScreenFingerprinting`, which is about screen size rather than the permission |
| BlockExternalExtensions | ✅ active (cr80+) | bool | true | **added August 2026**; closes the *silent* install channel (registry `…\Extensions` keys, `external_extensions.json` drop-ins) that bundleware uses while user-chosen extensions keep working — unlike the all-or-nothing `ExtensionInstallBlocklist: ["*"]`. `dynamic_refresh: false` — needs browser restart |
| PromotionalTabsEnabled | ⛔ `deprecated: true` | — | — | considered July 2026, rejected — Chromium YAML marks it deprecated. **Do not add.** Its live successor is `PromotionsEnabled` (`chrome.*:128-`, not deprecated), which writes the same `prefs::kPromotionsEnabled` through `SimpleDeprecatingPolicyHandler`. Also not exposed: several surfaces it gates are Chrome-branded ones Brave replaces, so the real-world effect is small |

## Considered and rejected — do not add

Checked this pass and deliberately left out. Recorded so future sweeps do not
re-litigate them; the YAML or the brave-core source is the tiebreaker in every
case.

| Key(s) | Why not |
|---|---|
| `IPFSEnabled` | `deprecated: true`; feature removed in 1.69.153, only a `DEPRECATE_IPFS` tombstone remains. See the Brave-specific table above |
| all `PrivacySandbox*` | deprecated at cr144 — `PrivacySandboxFingerprintingProtectionEnabled` capped at 145, `PrivacySandboxIpProtectionEnabled` at 143; also build-disabled in Brave |
| `ComponentUpdatesEnabled` | **actively harmful** — would freeze Shields filter lists, HTTPS-upgrade and debounce rules, and the Tor client |
| `FeedbackSurveysEnabled`, `SafeBrowsingSurveysEnabled` | brave-core patches `RunCommonLaunchChecks` to always return an error, so no survey ever launches |
| `BrowserNetworkTimeQueriesEnabled` | `kNetworkTimeServiceQuerying` is force-disabled in Brave |
| `DomainReliabilityAllowed` | `brave_main_delegate.cc` appends `--disable-domain-reliability` unconditionally |
| `BuiltInAIAPIsEnabled` | `GetOptimizationTargetForFeature` returns UNKNOWN in Brave; the APIs never initialize |
| `DefaultWebBluetoothGuardSetting`, `DefaultFileSystemReadGuardSetting`, `DefaultFileSystemWriteGuardSetting` | already feature-disabled in Brave — this is why the device-API block is USB+Serial+HID only |
| `DefaultThirdPartyStoragePartitioningSetting` | removed after cr145 |
| `FirstPartySetsEnabled`, `RelatedWebsiteSetsEnabled` | removed after cr152 |
| `InsecurePrivateNetworkRequestsAllowed`, `LocalNetworkAccessRestrictionsEnabled` | removed after cr137 and cr144 respectively |
| `UrlKeyedMetricsAllowed`, `Miscellaneous/AutofillSettings` | `future_on:` only, no `supported_on:` — never shipped |
| `DefaultMediaStreamSetting` | `deprecated: true`; if a microphone/camera switch is ever wanted, use `AudioCaptureAllowed` / `VideoCaptureAllowed` |
| `BraveSearchResultAdsEnabled` | merged 2026-07-20, **reverted 2026-08-06**; absent from master. The replacement is a universal opt-out pref (brave-browser#57204, milestone 1.95.x) with no policy key yet — re-check after 1.95 rather than guessing a name |

## Cross-cutting checks

- **Windows registry path** — `HKLM:\SOFTWARE\Policies\BraveSoftware\Brave` confirmed correct against Brave's official Group Policy documentation (`BraveSoftware\Brave-Browser` is the *install* dir name, not the policy path).
- **`ForUrls` wildcard patterns** — Brave's docs say "wildcards are not supported", meaning patterns like `*.example.com`. The scheme-wide patterns SlimBrave uses (`https://*`, `http://*`) are valid ContentSettingsPattern syntax and are applied correctly. They are **not** written to your profile: `PolicyProvider` keeps policy content settings in an in-memory `OriginValueMap` (`content_settings_policy_provider.h`) and never writes them back to `Preferences`. The `profile.content_settings.exceptions.braveShields` entries the repair logic in all three scripts scrubs were written by **pre-1.x SlimBrave**, which set them as ordinary user content settings; the repair undoes that old damage rather than anything current Brave does.
- **Content-setting enums are not uniform** — re-verified key by key against `chromium/main` on **2026-08-28**, when the eight `Default*Setting` permission rows stopped being block-only checkboxes and started exposing the enum. `DefaultNotificationsSetting`, `DefaultGeolocationSetting` and `DefaultSensorsSetting` take **1 = allow, 2 = block, 3 = ask**. The other five — `DefaultWebUsbGuardSetting`, `DefaultSerialGuardSetting`, `DefaultWebHidGuardSetting`, `DefaultLocalFontsSetting`, `DefaultWindowManagementSetting` — are **ask-or-block only: 1 is not a member of their schema at all** and a policy file naming it is rejected. That asymmetry is the reason the choice lists are per-key rather than shared; do not "tidy" them into one list, and re-check the schema rather than pattern-matching off a neighbouring key. A value outside a key's legal set is left unmanaged on import and named in the import message instead of being written through; the same type-strict test rejects a quoted `"1"` in all three implementations.
- **Version gating** — a key that predates the running Brave is silently ignored: harmless, but the toggle does nothing until the browser updates. By milestone: cr138 (News, Talk, Speedreader, Wayback, P3A, Stats Ping, Web Discovery) · cr139 (Playlist) · cr140 (De-AMP, Debouncing, Reduce Language) · cr141 (Fingerprinting V2) · cr142 (GPC, Tracking Query Parameter filtering, and the `DefaultBrave*` enforcers — Adblock, HTTPS Upgrade, Referrers, Remember 1P Storage) · cr147 (Email Aliases — **Brave 1.92**, branch-probed) · cr149 (Local AI — **Brave 1.94**, branch-probed). Every other Brave key is cr129 or older, and every Chromium-inherited key is cr111 or older, so both are present in any Brave still receiving updates.

## Re-audit procedure

0. Start in the source, not the templates: `browser/policy/brave_simple_policy_map.h` proves the browser actually dispatches a key and shows the `#if BUILDFLAG(...)` guards that make one a no-op on a platform (this is how `BraveVPNDisabled` on Linux was caught), and `browser/brave_origin/brave_origin_service_factory.cc` tells you which value Brave itself considers debloated. Both of this pass's new Brave candidates came from those two files.
1. Diff the key list in each script against the two YAML directories above.
2. For any key, fetch `<dir>/<Key>.yaml` and check `deprecated:`, `supported_on:` and `features:` (`dynamic_refresh`, `per_profile` — the restart and browser-wide notes in the tables come from there).
3. Never derive a shipping Brave version from `supported_on`; probe the release branches as described at the top of this document.
4. Treat brave-core/Chromium source as the tiebreaker over support articles and third-party guides — the docs lag the source.
