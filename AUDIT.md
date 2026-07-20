# Policy Audit — June 2026

Verification of every policy key SlimBrave Neo manages, against the two
authoritative sources:

- **Brave-specific keys:** [brave-core policy definitions](https://github.com/brave/brave-core/tree/master/components/policy/resources/templates/policy_definitions/BraveSoftware) (per-policy YAML: `deprecated`, `supported_on`, schema)
- **Chromium-inherited keys:** [Chromium policy definitions](https://chromium.googlesource.com/chromium/src/+/main/components/policy/resources/templates/policy_definitions/) (same YAML format; the master index lists 1,457 policies)

`supported_on` uses Chromium milestones. Rough Brave mapping: Chromium 138 ≈ Brave 1.80, 140 ≈ 1.82, 141–142 ≈ 1.83–1.84, 147 ≈ 1.89.

## Brave-specific keys

| Key | Status | Min version | Type | Notes |
|---|---|---|---|---|
| BraveP3AEnabled | ✅ active | cr138 / Brave 1.83 | bool | unset = enabled |
| BraveStatsPingEnabled | ✅ active | cr138 / Brave 1.83 | bool | unset = enabled |
| BraveGlobalPrivacyControlEnabled | ✅ active | cr142 | bool | dynamic refresh |
| BraveDeAmpEnabled | ✅ active | cr140 | bool | dynamic refresh |
| BraveDebouncingEnabled | ✅ active | cr140 | bool | dynamic refresh |
| BraveTrackingQueryParametersFilteringEnabled | ✅ active | cr142 | bool | only effective while Shields enabled |
| BraveReduceLanguageEnabled | ✅ active | cr140 | bool | dynamic refresh |
| BraveRewardsDisabled | ✅ active | cr105 | bool | true = disable |
| BraveWalletDisabled | ✅ active | cr106 | bool | also disables web3 + decentralized DNS |
| BraveVPNDisabled | ✅ active | cr112 | bool | |
| BraveAIChatEnabled | ✅ active | cr121 | bool | false = disable Leo |
| BraveShieldsDisabledForUrls | ✅ active | cr107 | list | see pattern note below |
| BraveShieldsEnabledForUrls | ✅ active | cr107 | list | counterpart; **newly exposed** |
| BraveNewsDisabled | ✅ active | cr138 / Brave 1.82 | bool | |
| BraveTalkDisabled | ✅ active | cr138 / Brave 1.82 | bool | |
| BravePlaylistEnabled | ✅ active | cr139 / Brave 1.84 | bool | |
| BraveWebDiscoveryEnabled | ✅ active | cr138 / Brave 1.83 | bool | unset = **disabled** by default |
| BraveSpeedreaderEnabled | ✅ active | cr138 / Brave 1.82 | bool | desktop only |
| BraveWaybackMachineEnabled | ✅ active | cr138 / Brave 1.82 | bool | desktop only |
| TorDisabled | ✅ active | cr78 (Win) / cr93 (mac, Linux) | bool | desktop only |
| EmailAliasesEnabled | ✅ active | cr147 / Brave ~1.89 | bool | **newly exposed**; very recent — older Brave ignores it |
| DefaultBraveAdblockSetting | ✅ active | cr142 | int enum | 1 = allow ads, 2 = block; **newly exposed** |
| DefaultBraveFingerprintingV2Setting | ✅ active | cr141 | int enum | 1 = off, 3 = standard (no value 2); **newly exposed** |
| DefaultBraveHttpsUpgradeSetting | ✅ active | cr142 | int enum | 1 = allow HTTP, 2 = strict, 3 = standard; **newly exposed** |
| DefaultBraveReferrersSetting | ✅ active | cr142 | int enum | 1 = permissive, 2 = cap to strict origin; both values exposed as mutually exclusive toggles (issue #9); never put value 1 in a preset |
| DefaultBraveRemember1PStorageSetting | ✅ active | cr142 | int enum | 1 = remember, 2 = forget on close; **newly exposed** |
| BraveSyncUrl | ✅ active | cr129 | string | **deliberately not exposed** — it's a custom-sync-server URL, not a debloat toggle; use a hand-written policy file if you self-host sync |
| IPFSEnabled | ⛔ `deprecated: true` | — | bool | IPFS feature removed from Brave 1.69.153 (Aug 2024); not exposed by SlimBrave Neo. **Do not re-add** — this key has bounced in/out of this project before; the brave-core YAML is the tiebreaker |

## Chromium-inherited keys

| Key | Status | Type | Project value | Notes |
|---|---|---|---|---|
| MetricsReportingEnabled | ✅ active | bool | false | |
| SafeBrowsingProtectionLevel | ✅ active | int enum | 0 (= no protection) | 0/1/2 valid |
| SafeBrowsingExtendedReportingEnabled | ✅ active | bool | false | |
| UrlKeyedAnonymizedDataCollectionEnabled | ✅ active | bool | false | |
| AutofillAddressEnabled | ✅ active | bool | false | |
| AutofillCreditCardEnabled | ✅ active | bool | false | |
| PasswordManagerEnabled | ✅ active | bool | false | |
| BrowserSignin | ✅ active | int enum | 0 (= disable) | |
| EnableDoNotTrack | ❌ **does not exist** | — | — | not in Chromium's policy index (checked all 1,457). DNT has no enterprise policy in Chromium; the key was silently ignored. Removed June 2026. GPC (`BraveGlobalPrivacyControlEnabled`) is the working equivalent |
| WebRtcIPHandling | ✅ active | string enum | disable_non_proxied_udp | valid enum member |
| QuicAllowed | ✅ active | bool | false | |
| BlockThirdPartyCookies | ✅ active | bool | true | |
| ForceGoogleSafeSearch | ✅ active | bool | true | |
| IncognitoModeAvailability | ✅ active | int enum | 1 or 2 | 0 = enabled, 1 = disabled, 2 = forced |
| SyncDisabled | ✅ active | bool | true | |
| BackgroundModeEnabled | ✅ active (Win/Linux **only**) | bool | false | no macOS support in Chromium — removed from the mac script, kept on Windows/Linux |
| ShoppingListEnabled | ✅ active | bool | false | re-verified — not deprecated |
| AlwaysOpenPdfExternally | ✅ active | bool | true | |
| TranslateEnabled | ✅ active | bool | false | |
| SpellcheckEnabled | ✅ active | bool | false | desktop only |
| SearchSuggestEnabled | ✅ active | bool | false | |
| PrintingEnabled | ✅ active | bool | false | |
| DefaultBrowserSettingEnabled | ✅ active | bool | false | desktop only |
| DeveloperToolsAvailability | ✅ active | int enum | 2 (= disallowed) | |
| DnsOverHttpsMode | ✅ active | string enum | off/automatic/secure | |
| DnsOverHttpsTemplates | ✅ active | string | URL template | only effective with mode secure/automatic |
| PasswordLeakDetectionEnabled | ✅ active (cr79+) | bool | false | **added July 2026**; stops the online breach-list credential check |
| NetworkPredictionOptions | ✅ active (cr38+) | int enum | 2 (= never predict) | **added July 2026**; 0 = always, 2 = never (value 1 deprecated in-source) |
| PaymentMethodQueryEnabled | ✅ active (cr80+) | bool | false | **added July 2026**; sites' canMakePayment always answers "none saved" |
| AlternateErrorPagesEnabled | ✅ active (cr8+) | bool | false | **added July 2026**; belt-and-braces — Brave ships the web-service error page off by default |
| DefaultNotificationsSetting | ✅ active (cr10+) | int enum | 2 (= block all) | **added July 2026**; 1 = allow, 2 = block, 3 = ask |
| DefaultGeolocationSetting | ✅ active (cr10+) | int enum | 2 (= block all) | **added July 2026**; 1 = allow, 2 = block, 3 = ask |
| DefaultSensorsSetting | ✅ active (cr88+) | int enum | 2 (= block all) | **added July 2026**; motion/orientation sensors — fingerprinting vector |
| ExtensionInstallBlocklist | ✅ active (cr86+) | list | `["*"]` | **added July 2026**; `*` blocks all installs and disables already-installed extensions |
| SafeSitesFilterBehavior | ✅ active (cr69+) | int enum | 1 (= filter) | **added July 2026**; built-in adult-content URL filter |
| BrowserGuestModeEnabled | ✅ active (cr38+) | bool | false | **added July 2026**; guest windows bypass profile restrictions — parental hole |
| HighEfficiencyModeEnabled | ✅ active (cr108+) | bool | true | **added July 2026**; forces Memory Saver tab discarding on |
| HardwareAccelerationModeEnabled | ✅ active (cr46+) | bool | true | **added July 2026**; `dynamic_refresh: false` — needs browser restart |
| EnableMediaRouter | ✅ active (cr52+) | bool | false | **added July 2026**; disables Cast + its LAN device discovery; `dynamic_refresh: false` — needs browser restart |
| MediaRecommendationsEnabled | ✅ active (cr87+) | bool | false | **added July 2026** |
| PromotionalTabsEnabled | ⛔ `deprecated: true` | — | — | considered July 2026, rejected — Chromium YAML marks it deprecated. **Do not add** |

## Chrome-specific keys (July 2026 — multi-browser support)

Source: same Chromium policy_definitions YAML as above. These appear only in the "Chrome Features" category.

| Key | Status | Type | Project value | Notes |
|---|---|---|---|---|
| UserFeedbackAllowed | ✅ active (cr77+) | bool | false | also valid on Edge (documented separately by Microsoft) |
| BrowserLabsEnabled | ✅ active (cr89+) | bool | false | |
| GoogleSearchSidePanelEnabled | ✅ active (cr115+) | bool | false | |
| GeminiSettings | ✅ active (cr137+) | int enum | 1 (= disable) | `supported_on: chrome.win, chrome.mac` only — **absent from the Linux catalog** |
| ChromeVariations | ✅ active (cr83+) | int enum | 1 (= critical fixes only) | 2 (= disable all) deliberately not used: it also drops security-critical variation killswitches |
| PrivacySandboxPromptEnabled / AdTopics / SiteEnabledAds / AdMeasurement | ⛔ all `deprecated: true` | — | — | considered and rejected — Google sunset Privacy Sandbox; **do not add** |
| LensOverlaySettings | ⛔ `deprecated: true` | — | — | considered and rejected |

## Edge keys (July 2026 — multi-browser support)

Source: Microsoft's per-policy Edge documentation (`learn.microsoft.com/deployedge/microsoft-edge-policies/<key>`). Chromium YAML does not cover Edge — Microsoft maintains a separate policy set that renames several Chromium keys. **Edge is Windows + macOS only:** the docs list no Linux support per policy, so no Linux Edge catalog exists to audit.

Renamed equivalents (the Chromium originals are excluded from the Edge catalog):

| Chromium key (excluded) | Edge key (used) | Project value |
|---|---|---|
| MetricsReportingEnabled (obsolete in Edge 89) | DiagnosticData | 0 (= off) |
| IncognitoModeAvailability | InPrivateModeAvailability | 1 / 2 (grouped) |
| WebRtcIPHandling | WebRtcLocalhostIpHandling | disable_non_proxied_udp |
| PasswordLeakDetectionEnabled | PasswordMonitorAllowed | false |
| SafeBrowsingProtectionLevel / SafeBrowsingExtendedReportingEnabled | SmartScreenEnabled | false (opt-in toggle, like Disable Safe Browsing) |
| HighEfficiencyModeEnabled | EfficiencyModeEnabled (≥106) | true |
| ShoppingListEnabled | EdgeShoppingAssistantEnabled | false |

Also excluded from Edge (no equivalent): UrlKeyedAnonymizedDataCollectionEnabled, SafeSitesFilterBehavior, MediaRecommendationsEnabled (all 404 in Microsoft's policy reference).

Edge-only keys, all ✅ active: PersonalizationReportingEnabled (false), UserFeedbackAllowed (false), HubsSidebarEnabled (false; the *recommended* variant is obsolete, the mandatory policy is not), EdgeCollectionsEnabled (false), ShowMicrosoftRewards (false), EdgeWalletCheckoutEnabled (false), NewTabPageContentEnabled (false), EdgeAssetDeliveryServiceEnabled (false), SleepingTabsEnabled (true), ForceBingSafeSearch (2 = strict), StartupBoostEnabled (false, **Windows only**), SpotlightExperiencesAndRecommendationsEnabled (false, **Windows only**).

Rejected as obsolete/deprecated by Microsoft: PromotionalTabsEnabled (Edge's own copy — "will become obsolete"), EdgeFollowEnabled (obsolete after 126), EdgeWalletEtreeEnabled (deprecated). **Do not add.**

## Cross-cutting checks

- **Windows registry path** — `HKLM:\SOFTWARE\Policies\BraveSoftware\Brave` confirmed correct against Brave's official Group Policy documentation (`BraveSoftware\Brave-Browser` is the *install* dir name, not the policy path).
- **`ForUrls` wildcard patterns** — Brave's docs say "wildcards are not supported", meaning patterns like `*.example.com`. The scheme-wide patterns SlimBrave uses (`https://*`, `http://*`) are valid ContentSettingsPattern syntax and demonstrably work: Brave materializes them into profile `braveShields` exceptions (which is exactly the pref leak the repair logic in all three scripts scrubs).
- **Version gating** — several keys only act on newer Brave: 1.82 (News/Talk/Speedreader/Wayback), 1.83 (P3A/StatsPing/WebDiscovery, FingerprintingV2), 1.84 (Playlist, the other `DefaultBrave*` enforcers), ~1.89 (EmailAliases). Older Brave silently ignores unknown keys — harmless, but the toggle won't do anything until the browser updates.

## Re-audit procedure

1. Diff the key list in each script against the two YAML directories above (Brave/Chromium keys) and Microsoft's per-policy pages (Edge keys).
2. For any Chromium key, fetch `<dir>/<Key>.yaml` and check `deprecated:` and `supported_on:`. For any Edge key, fetch `learn.microsoft.com/deployedge/microsoft-edge-policies/<key>` and check the obsolete banner and "Supported versions".
3. Treat brave-core/Chromium source (and, for Edge, Microsoft's policy reference) as the tiebreaker over support articles and third-party guides — the docs lag the source.
