# Policy Audit — August 2026

Verification of every policy key SlimBrave Neo manages, against the two
authoritative sources:

- **Brave-specific keys:** [brave-core policy definitions](https://github.com/brave/brave-core/tree/master/components/policy/resources/templates/policy_definitions/BraveSoftware) (per-policy YAML: `deprecated`, `supported_on`, `features`, schema) — read at master tree `855ca5b` on 2026-08-13; 30 policies
- **Chromium-inherited keys:** [Chromium policy definitions](https://chromium.googlesource.com/chromium/src/+/main/components/policy/resources/templates/policy_definitions/) (same YAML format) — read at `chromium/main` on 2026-08-13; the index holds 1,522 YAML files, 66 of them `.group.details.yaml` group metadata, so **1,456 policies**

`supported_on` counts Chromium milestones, so this document records milestones
(`cr138`) and not Brave versions. Rough alignment at the time of writing:
cr138 ≈ 1.80, cr139 ≈ 1.81, cr140 ≈ 1.82, cr141 ≈ 1.83, cr142 ≈ 1.84,
cr147 ≈ 1.89, cr148 ≈ 1.90, cr149 ≈ 1.91, cr150 ≈ 1.92, cr151 ≈ 1.93.
Current stable is Brave 1.93.134 on Chromium 151.0.7922.108, released
2026-08-07.

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
| BraveVPNDisabled | ✅ active | cr112 | bool | Windows/macOS/Android/iOS only — `enable_brave_vpn` omits `is_linux`, so the `brave_simple_policy_map.h` entry is compiled out of Linux builds and the key is a silent no-op there; `brave://policy` still renders it as cleanly applied. The Linux row is labelled accordingly rather than removed — `enable_brave_vpn_v2_apps` already names `is_linux` for a future rollout |
| BraveAIChatEnabled | ✅ active | cr121 | bool | false = disable Leo; does **not** cover on-device models — see BraveLocalAIEnabled |
| BraveLocalAIEnabled | ✅ active | cr149 | bool | **added August 2026**; false = skip registering the on-device model component (EmbeddingGemma, `ejhejjmaoaohpghnblcdcjilndkangfe`), delete its directory, and stop history vector-indexing. Separate buildflag (`ENABLE_LOCAL_AI`) and prefs from AI Chat. Forward-looking: first release branch carrying the YAML is **1.94.x**, older Brave ignores it. `dynamic_refresh: false` — needs browser restart; browser-wide (`per_profile: false`). Deliberately in no preset |
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
| PsstEnabled | 🕓 master only | — | bool | **deliberately not exposed** — a no-op twice over today: `kEnablePsst` is `FEATURE_DISABLED_BY_DEFAULT`, and the YAML is on **no** release branch (1.92.x / 1.93.x / 1.94.x all 404), so nothing dispatches the key. Worth re-checking: PSST downloads per-site scripts, injects them into logged-in origins to detect sign-in, then drives your authenticated account through settings URLs flipping switches (`enable_psst = !is_android && !is_ios`). Revisit once it reaches a release branch |
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
| DefaultNotificationsSetting | ✅ active (cr10+) | int enum | 2 (= block all) | **added July 2026**; 1 = allow, 2 = block, 3 = ask |
| DefaultGeolocationSetting | ✅ active (cr10+) | int enum | 2 (= block all) | **added July 2026**; 1 = allow, 2 = block, 3 = ask |
| DefaultSensorsSetting | ✅ active (cr88+) | int enum | 2 (= block all) | **added July 2026**; motion/orientation sensors — fingerprinting vector |
| ExtensionInstallBlocklist | ✅ active (cr86+) | list | `["*"]` | **added July 2026**; `*` blocks all installs and disables already-installed extensions |
| SafeSitesFilterBehavior | ✅ active (cr69+) | int enum | 1 (= filter) | **added July 2026**; not a local filter — it sends every navigation URL, iframes included, to Google's Safe Search API for classification (`tags: [filtering, google-sharing]`). Disclosed in the tooltip and the README because the same tool ships `SafeBrowsingProtectionLevel = 0` |
| BrowserGuestModeEnabled | ✅ active (cr38+) | bool | false | **added July 2026**; guest windows bypass profile restrictions — parental hole |
| HighEfficiencyModeEnabled | ✅ active (cr108+) | bool | true | **added July 2026**; forces Memory Saver tab discarding on |
| HardwareAccelerationModeEnabled | ✅ active (cr46+) | bool | true | **added July 2026**; `dynamic_refresh: false` — needs browser restart |
| EnableMediaRouter | ✅ active (cr52+) | bool | false | **added July 2026**; disables Cast + its LAN device discovery; `dynamic_refresh: false` — needs browser restart |
| MediaRecommendationsEnabled | ✅ active (cr87+) | bool | false | **added July 2026** |
| ChromeVariations | ✅ active (cr83+) | int enum | 1 or 2 | **added August 2026**; 0 = all variations, 1 = critical fixes only, 2 = none. Closes the last remote-configuration channel: Brave fetches a Griffin seed from `variations.brave.com` that flips features in an installed browser. Maps to `variations::prefs::kVariationsRestrictionsByPolicy`; brave-core does not override the restriction path. Exposed as two mutually exclusive rows — value 2 also blocks the emergency killswitches used to turn off a broken or unsafe feature, so it is kept out of every preset |
| SpellCheckServiceEnabled | ✅ active (cr22+) | bool | false | **added August 2026**; removes the Google spelling web service while offline dictionaries keep working. Upstream states it "will have no effect" once `SpellcheckEnabled` is false, which is why the two rows are mutually exclusive |
| RemoteDebuggingAllowed | ✅ active (cr93+) | bool | false | **added August 2026**; blocks `--remote-debugging-port` / `--remote-debugging-pipe`, the CDP cookie-theft vector `DeveloperToolsAvailability` leaves open. Inherited unchanged by Brave. `dynamic_refresh: false` — needs browser restart. Breaks Puppeteer/Playwright and `brave://inspect` |
| DNSInterceptionChecksEnabled | ✅ active (cr80+) | bool | false | **added August 2026**; stops the three random 7–15 char hostname lookups at startup and on every network change — a per-launch beacon visible to the ISP or DoH resolver |
| BasicAuthOverHttpEnabled | ✅ active (cr88+) | bool | false | **added August 2026**; refuses HTTP Basic auth over cleartext so base64 credentials are never sent in the clear. Breaks legacy plain-HTTP appliance logins |
| DefaultWebUsbGuardSetting | ✅ active (cr67+) | int enum | 2 (= block all) | **added August 2026**; 2 = block, 3 = ask. Ships enabled in Brave (no feature override). Breaks Ledger/Trezor web wallets and in-browser firmware flashers |
| DefaultSerialGuardSetting | ✅ active (cr86+) | int enum | 2 (= block all) | **added August 2026**; same class as WebUSB — breaks in-browser microcontroller tooling |
| DefaultWebHidGuardSetting | ✅ active (cr100+) | int enum | 2 (= block all) | **added August 2026**; completes the device-API trio. May break security keys and gamepad configurators that use WebHID rather than WebAuthn. The trio is USB+Serial+HID and not all six because WebBluetooth and File System Access are already feature-disabled in Brave |
| DefaultLocalFontsSetting | ✅ active (cr103+) | int enum | 2 (= block all) | **added August 2026**; `queryLocalFonts()` returns the installed font list, a top-tier fingerprint that Shields' farbling does not cover — farbling handles CSS/canvas measurement, not the explicit enumeration permission |
| DefaultWindowManagementSetting | ✅ active (cr111+) | int enum | 2 (= block all) | **added August 2026**; stops sites reading the full multi-monitor topology. Complementary to `kBraveBlockScreenFingerprinting`, which is about screen size rather than the permission |
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
- **Version gating** — a key that predates the running Brave is silently ignored: harmless, but the toggle does nothing until the browser updates. By milestone: cr138 (News, Talk, Speedreader, Wayback, P3A, Stats Ping, Web Discovery) · cr139 (Playlist) · cr140 (De-AMP, Debouncing, Reduce Language) · cr141 (Fingerprinting V2) · cr142 (GPC, Tracking Query Parameter filtering, and the `DefaultBrave*` enforcers — Adblock, HTTPS Upgrade, Referrers, Remember 1P Storage) · cr147 (Email Aliases — **Brave 1.92**, branch-probed) · cr149 (Local AI — **Brave 1.94**, branch-probed). Every other Brave key is cr129 or older, and every Chromium-inherited key is cr111 or older, so both are present in any Brave still receiving updates.

## Re-audit procedure

0. Start in the source, not the templates: `browser/policy/brave_simple_policy_map.h` proves the browser actually dispatches a key and shows the `#if BUILDFLAG(...)` guards that make one a no-op on a platform (this is how `BraveVPNDisabled` on Linux was caught), and `browser/brave_origin/brave_origin_service_factory.cc` tells you which value Brave itself considers debloated. Both of this pass's new Brave candidates came from those two files.
1. Diff the key list in each script against the two YAML directories above.
2. For any key, fetch `<dir>/<Key>.yaml` and check `deprecated:`, `supported_on:` and `features:` (`dynamic_refresh`, `per_profile` — the restart and browser-wide notes in the tables come from there).
3. Never derive a shipping Brave version from `supported_on`; probe the release branches as described at the top of this document.
4. Treat brave-core/Chromium source as the tiebreaker over support articles and third-party guides — the docs lag the source.
