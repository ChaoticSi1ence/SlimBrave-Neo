
# Forwarded by the elevation relaunch below, never passed by hand. After
# elevation $env:LOCALAPPDATA and HKCU belong to whichever account approved
# UAC, which under over-the-shoulder UAC is the admin and not the user whose
# Brave profile holds the leaked prefs. These carry the invoking user's path
# and SID across. $OriginalSid is read further down; dropping it from this
# block does not fail loudly, it silently scrubs the wrong hive.
# Must stay the literal first statement of the file.
param (
    [string] $OriginalLocalAppData,
    [string] $OriginalSid
)

# SlimBrave Neo - debloat and harden Brave Browser on Windows.
# https://github.com/ChaoticSi1ence/SlimBrave-Neo
#
# One self-contained script. Writes Chromium enterprise managed policy to
# HKLM\SOFTWARE\Policies\BraveSoftware\Brave; Brave reads it at startup.
#
# Relaunches itself elevated so Apply and
# Reset can write machine policy. Capture the path BEFORE anything else: under
# `iex (irm ...)` or an unsaved buffer $MyInvocation.MyCommand.Path is empty,
# and -File "" dies instantly with no diagnostic.
$script:selfPath = $MyInvocation.MyCommand.Path
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$isAdmin = (New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    if ([string]::IsNullOrWhiteSpace($script:selfPath)) {
        [void][System.Windows.Forms.MessageBox]::Show(
            "Run this from a saved .ps1 file so it can relaunch itself as Administrator.",
            "Cannot determine script path",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error)
        exit 1
    }
    try {
        # ONE quoted string, not an array: Start-Process joins an array with
        # spaces and quotes nothing, so any path containing a space (OneDrive,
        # "John Smith") silently launches the wrong thing. -NoProfile keeps the
        # elevating admin's PowerShell profile out of this process.
        $currentSid = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
        $relaunchArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$($script:selfPath)`"" +
            " -OriginalLocalAppData `"$env:LOCALAPPDATA`" -OriginalSid `"$currentSid`""
        Start-Process -FilePath "powershell.exe" -Verb RunAs -ErrorAction Stop `
            -ArgumentList $relaunchArgs
    } catch {
        # A declined UAC prompt is non-terminating without -ErrorAction Stop,
        # so without this the original would exit silently and look broken.
        [void][System.Windows.Forms.MessageBox]::Show(
            "Administrator access was declined. Apply and Reset need it to write machine policy.",
            "Not elevated",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning)
    }
    exit
}
[System.Windows.Forms.Application]::EnableVisualStyles()
# ---------------------------------------------------------------------------
# High DPI & Visual Styles Support
# Fixes blurry window / text rendering on displays with >100% DPI scaling
# ---------------------------------------------------------------------------

try {
    [System.Windows.Forms.Application]::EnableVisualStyles()
} catch {}

try {
    Add-Type -Namespace SlimBrave -Name DpiHelper -MemberDefinition @'
[DllImport("user32.dll")]
public static extern bool SetProcessDpiAwarenessContext(IntPtr dpiContext);

[DllImport("shcore.dll")]
public static extern int SetProcessDpiAwareness(int awareness);

[DllImport("user32.dll")]
public static extern bool SetProcessDPIAware();

public static void EnableDpiAwareness() {
    try {
        // -4 = DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 (Windows 10 1703+)
        if (!SetProcessDpiAwarenessContext((IntPtr)(-4))) {
            // Fallback: 2 = PROCESS_PER_MONITOR_DPI_AWARE (Windows 8.1 / earlier Win10)
            if (SetProcessDpiAwareness(2) != 0) {
                // Fallback: Windows Vista / 7
                SetProcessDPIAware();
            }
        }
    } catch {
        try { SetProcessDPIAware(); } catch {}
    }
}

[DllImport("dwmapi.dll")]
public static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);
'@
    [SlimBrave.DpiHelper]::EnableDpiAwareness()
} catch {}

$machineRegistryPath = "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave"
# HKCU inside the elevated process is the admin's hive, which is the wrong
# one under over-the-shoulder UAC. The invoking user is interactively logged
# on, so their hive is already mounted under HKEY_USERS - address it by SID
# rather than loading it. Falls back to HKCU when the script was already
# elevated (then we ARE the invoking user).
if ([string]::IsNullOrWhiteSpace($OriginalSid)) {
    $userRegistryPath = "HKCU:\SOFTWARE\Policies\BraveSoftware\Brave"
} else {
    $userRegistryPath = "Registry::HKEY_USERS\$OriginalSid\SOFTWARE\Policies\BraveSoftware\Brave"
}
$registryPath       = $machineRegistryPath

Clear-Host
# ---------------------------------------------------------------------------
# DNS helper - handles both DnsOverHttpsMode and DnsOverHttpsTemplates
# ---------------------------------------------------------------------------

function Set-DnsSettings {
    param (
        [string] $dnsMode,
        [string] $dnsTemplates,
        [string] $MachinePath,
        [string] $UserPath
    )
    # "secure" (and "custom", which resolves to it) with no template breaks
    # every hostname lookup: Chromium applies the mode anyway, blanks the
    # template pref, and secure mode has no plaintext fallback. The user
    # can't undo it in brave://settings either, because the policy is
    # machine-managed. "off"/"automatic" are fine without a template.
    if ($dnsMode -in @("custom", "secure") -and [string]::IsNullOrWhiteSpace($dnsTemplates)) {
        [System.Windows.Forms.MessageBox]::Show(
            "'secure' and 'custom' DoH require a template URL (e.g. https://cloudflare-dns.com/dns-query).",
            "Missing DoH Template",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        return $false
    }

    $resolvedMode = $dnsMode

    if ($dnsMode -eq "custom" -or $dnsMode -eq "secure") {
        # Chromium has no "custom" mode - a pinned resolver IS "secure" plus
        # a template. Writing the template for a plain "secure" selection too
        # keeps parity with the Linux/macOS scripts, so cross-platform
        # configs with DnsMode=secure + DnsTemplates don't lose their
        # resolver here.
        $resolvedMode = "secure"
        Set-ItemProperty -Path $MachinePath -Name "DnsOverHttpsTemplates" -Value $dnsTemplates -Type String -Force
    } else {
        # Remove the templates key when no template applies
        if (Get-ItemProperty -Path $MachinePath -Name "DnsOverHttpsTemplates" -ErrorAction SilentlyContinue) {
            Remove-ItemProperty -Path $MachinePath -Name "DnsOverHttpsTemplates" -ErrorAction SilentlyContinue
        }
    }

    Set-ItemProperty -Path $MachinePath -Name "DnsOverHttpsMode" -Value $resolvedMode -Type String -Force

    # Scrub the user-scope twin whichever branch ran, so Brave never merges a
    # stale HKCU DNS policy with the machine one. Per-branch placement would
    # miss the template path.
    if (Test-Path -Path $UserPath) {
        Remove-ItemProperty -Path $UserPath -Name "DnsOverHttpsMode"      -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $UserPath -Name "DnsOverHttpsTemplates" -ErrorAction SilentlyContinue
    }

    return $true
}

# ---------------------------------------------------------------------------
# List-policy helpers
#
# Chromium list policies on Windows live in a subkey with numbered REG_SZ
# values (e.g. ...\BraveShieldsDisabledForUrls\1 = "https://*"). Writing the
# list as a single REG_SZ holding a JSON array has no effect — Chromium
# won't parse it, and the corresponding policy silently stays at its
# default.
# ---------------------------------------------------------------------------

function Set-ListPolicy {
    param (
        [string]   $RegistryPath,
        [string]   $Name,
        [string[]] $Values
    )
    $listKey = Join-Path $RegistryPath $Name
    # Drop any stale subkey and any legacy REG_SZ that used to live at the
    # parent with the same name, so old broken SlimBrave writes are cleaned.
    if (Test-Path $listKey) {
        Remove-Item -Path $listKey -Recurse -Force
    }
    if (Get-ItemProperty -Path $RegistryPath -Name $Name -ErrorAction SilentlyContinue) {
        Remove-ItemProperty -Path $RegistryPath -Name $Name -ErrorAction SilentlyContinue
    }
    New-Item -Path $listKey -Force | Out-Null
    for ($i = 0; $i -lt $Values.Count; $i++) {
        Set-ItemProperty -Path $listKey -Name ($i + 1) -Value $Values[$i] -Type String -Force
    }
}

function Remove-ListPolicy {
    param (
        [string] $RegistryPath,
        [string] $Name
    )
    $listKey = Join-Path $RegistryPath $Name
    if (Test-Path $listKey) {
        Remove-Item -Path $listKey -Recurse -Force
    }
    if (Get-ItemProperty -Path $RegistryPath -Name $Name -ErrorAction SilentlyContinue) {
        Remove-ItemProperty -Path $RegistryPath -Name $Name -ErrorAction SilentlyContinue
    }
}

function Repair-OneBravePrefs {
    param ([string] $pref)
    # Scrub one profile's Preferences file; returns the number of leaked
    # Shields exceptions removed. Safe when the file or keys do not exist.
    if (-not (Test-Path $pref)) { return 0 }

    try {
        $j = Get-Content $pref -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        return 0
    }

    $bs = $null
    if ($j.profile -and $j.profile.content_settings -and $j.profile.content_settings.exceptions) {
        $bs = $j.profile.content_settings.exceptions.braveShields
    }
    if (-not $bs) { return 0 }

    $removed = 0
    foreach ($pattern in @('http://*,*', 'https://*,*')) {
        if ($bs.PSObject.Properties.Name -contains $pattern) {
            $bs.PSObject.Properties.Remove($pattern)
            $removed++
        }
    }

    if ($removed -eq 0) { return 0 }

    # Brave reads Preferences as compact UTF-8 JSON without BOM. Out-File
    # default would write UTF-16/BOM and break Brave on next launch.
    $json = $j | ConvertTo-Json -Depth 100 -Compress
    $tmp = "$pref.slimbrave-tmp"
    try {
        [System.IO.File]::WriteAllText($tmp, $json, (New-Object System.Text.UTF8Encoding $false))
        Move-Item -Force $tmp $pref
    } catch {
        if (Test-Path $tmp) { Remove-Item -Force $tmp -ErrorAction SilentlyContinue }
        return 0
    }

    return $removed
}

function Repair-BravePrefs {
    <#
    .SYNOPSIS
    Scrubs SlimBrave-leaked Shields exceptions from the user's Brave profiles.

    .DESCRIPTION
    Brave/Chromium writes managed *ForUrls content-setting policies through
    to each profile's Preferences file. Removing the policy from the
    registry does NOT roll those entries back — the profile keeps the
    per-URL exceptions, so unchecking "Disable Brave Shields" leaves
    shields stuck off. The exceptions land in every profile that was used
    while the policy was active (Default, Profile 1, Profile 2, ...) and
    in every installed channel (Stable, Beta, Nightly, Dev — the registry
    policy applies to all of them), so every profile directory of every
    channel is scrubbed, not just Stable's Default.

    Returns a hashtable @{ Removed = N; Running = $true/$false; Skipped = $true/$false }.
    Safe to call when files or keys do not exist.
    #>
    # Every Brave channel runs as brave.exe on Windows.
    $running = ($null -ne (Get-Process brave -ErrorAction SilentlyContinue))
    # Chromium serves prefs from an in-memory PrefService and rewrites the
    # file on shutdown, so a scrub done now is thrown away the moment the
    # user closes Brave - which is exactly what we tell them to do next.
    # Skip the write and report it rather than claiming a clean that won't
    # survive.
    if ($running) {
        return @{ Removed = 0; Running = $true; Skipped = $true }
    }

    # Prefer the invoking user's profile root over the elevated process's
    # own, which under over-the-shoulder UAC belongs to the admin account.
    $localAppData = $env:LOCALAPPDATA
    if (-not [string]::IsNullOrWhiteSpace($script:OriginalLocalAppData)) {
        $localAppData = $script:OriginalLocalAppData
    }

    $removed = 0
    foreach ($channelDir in @('Brave-Browser', 'Brave-Browser-Beta', 'Brave-Browser-Nightly', 'Brave-Browser-Dev')) {
        $userData = Join-Path $localAppData "BraveSoftware\$channelDir\User Data"
        if (-not (Test-Path $userData)) { continue }
        $profileDirs = Get-ChildItem -Path $userData -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' }
        foreach ($dir in $profileDirs) {
            $removed += Repair-OneBravePrefs (Join-Path $dir.FullName 'Preferences')
        }
    }

    return @{ Removed = $removed; Running = $false; Skipped = $false }
}

function Test-FeatureValueMatches {
    param($feature, $expected)
    # List-typed features write a fixed canonical value (the Shields URL
    # pattern list), so an imported list has to match it exactly. Accepting
    # any list for the key would tick the row and then apply OUR wildcards -
    # turning an imported single-site exception into Shields-off for the
    # whole web, reported as a successful import.
    if ($feature.Type -eq "List") {
        $exp = @($expected      | ForEach-Object { [string]$_ })
        $own = @($feature.Value | ForEach-Object { [string]$_ })
        return (($exp.Count -eq $own.Count) -and -not (Compare-Object $exp $own))
    }
    if ($feature.Type -eq "DWord") {
        try { return ([int]$feature.Value -eq [int]$expected) }
        catch { return $false }
    }
    return ($feature.Value.ToString() -eq $expected.ToString())
}

function Test-ListPolicyMatches {
    param (
        [string]   $RegistryPath,
        [string]   $Name,
        [string[]] $Expected
    )
    $listKey = Join-Path $RegistryPath $Name
    if (-not (Test-Path $listKey)) { return $false }
    $props = Get-ItemProperty -Path $listKey -ErrorAction SilentlyContinue
    if (-not $props) { return $false }
    $actual = @()
    foreach ($p in $props.PSObject.Properties) {
        if ($p.Name -match '^\d+$') { $actual += [string]$p.Value }
    }
    foreach ($e in $Expected) {
        if ($actual -notcontains $e) { return $false }
    }
    return $true
}

function Test-ListPolicyIsExactly {
    param (
        [string]   $RegistryPath,
        [string]   $Name,
        [string[]] $Expected
    )
    # Ownership test, as opposed to the subset test above: is the list on
    # disk exactly the one SlimBrave writes? An admin's own blocklist is a
    # superset (or a different set entirely) and must not be deleted just
    # because the matching box is unchecked. Absent means nothing to
    # protect, so removal is safe.
    $listKey = Join-Path $RegistryPath $Name
    if (-not (Test-Path $listKey)) { return $true }
    $props = Get-ItemProperty -Path $listKey -ErrorAction SilentlyContinue
    if (-not $props) { return $true }
    $actual = @()
    foreach ($p in $props.PSObject.Properties) {
        if ($p.Name -match '^\d+$') { $actual += [string]$p.Value }
    }
    # An empty subkey holds no third-party list, so let it be cleaned up.
    if ($actual.Count -eq 0) { return $true }
    return (($actual.Count -eq $Expected.Count) -and -not (Compare-Object $actual $Expected))
}

# ---------------------------------------------------------------------------
# Feature row state
#
# A row is either a CheckBox (binary: write Tag.Value or nothing) or, when
# its feature carries `Choices`, a ComboBox (write the selected choice's
# value, or nothing when "Not managed" is selected). Everything that reads
# or writes row state - Apply, Reset, Import, Export, Initialize - goes
# through these three helpers so neither control type is special-cased at
# the call sites.
# ---------------------------------------------------------------------------

function Get-RowValue {
    <#
    .SYNOPSIS
    The policy value this row currently manages, or $null when it manages
    nothing (unchecked box / "Not managed").
    #>
    param ($Control)
    $feature = $Control.Tag
    if ($null -ne $feature.Choices) {
        $index = $Control.SelectedIndex
        if ($index -lt 0) { return $null }
        return $feature.Choices[$index].Value
    }
    if ($Control.Checked) {
        # The unary comma keeps a List row's value a list: returning a
        # one-element array unrolls it to a bare string, which would export
        # ExtensionInstallBlocklist as "*" instead of ["*"].
        if ($feature.Value -is [array]) { return ,$feature.Value }
        return $feature.Value
    }
    return $null
}

function Reset-FeatureRow {
    # Back to "manages nothing": unchecked, or the first choice, which is
    # always ("Not managed", $null).
    param ($Control)
    if ($null -ne $Control.Tag.Choices) {
        $Control.SelectedIndex = 0
    } else {
        $Control.Checked = $false
    }
}

function Select-ChoiceValue {
    <#
    .SYNOPSIS
    Select the entry of a choice row whose value is $Value. Returns $false
    when the row cannot represent that value (including $null) and leaves it
    on "Not managed", so callers can report the value they had to drop.
    #>
    param ($Control, $Value)
    $choices = $Control.Tag.Choices
    # Only a genuine integer can name an enum member. This has to be a type
    # test, not a cast: [int]$true is 1, so a JSON `true` would otherwise
    # select "Allow" on the three keys that have one and silently grant every
    # site the permission the user never asked to grant. A quoted "1" is not
    # a member either. Both drop to "Not managed" and are reported, matching
    # the type-strict check in the two Python scripts.
    $isInteger = ($Value -is [int]) -or ($Value -is [long]) -or
                 ($Value -is [int16]) -or ($Value -is [byte]) -or ($Value -is [uint32])
    if ($isInteger) {
        for ($i = 0; $i -lt $choices.Count; $i++) {
            $choiceValue = $choices[$i].Value
            if ($null -eq $choiceValue) { continue }
            # The registry hands us Int32, imported JSON Int32/Int64, so
            # compare numerically once both sides are known to be integers.
            $isMatch = $false
            try { $isMatch = ([int]$choiceValue -eq [int]$Value) } catch { $isMatch = $false }
            if ($isMatch) {
                $Control.SelectedIndex = $i
                return $true
            }
        }
    }
    $Control.SelectedIndex = 0
    return $false
}

$telemetryFeatures = @(
    @{ Name = "Disable Metrics Reporting"; Key = "MetricsReportingEnabled"; Value = 0; Type = "DWord"
       Tip = "Stops Brave from sending anonymous usage statistics and crash reports to Brave's servers." },
    @{ Name = "Disable Safe Browsing Reporting"; Key = "SafeBrowsingExtendedReportingEnabled"; Value = 0; Type = "DWord"
       Tip = "Stops extended Safe Browsing reports (details about suspicious pages and downloads) from being sent to Google. Safe Browsing protection itself stays on." },
    @{ Name = "Disable URL Data Collection"; Key = "UrlKeyedAnonymizedDataCollectionEnabled"; Value = 0; Type = "DWord"
       Tip = "Stops URL-keyed anonymized data collection, which reports the URLs you visit to improve suggestion and safety features." },
    @{ Name = "Disable P3A Analytics"; Key = "BraveP3AEnabled"; Value = 0; Type = "DWord"
       Tip = "Disables P3A (Privacy-Preserving Product Analytics), Brave's anonymized product usage telemetry." },
    @{ Name = "Disable Stats Ping"; Key = "BraveStatsPingEnabled"; Value = 0; Type = "DWord"
       Tip = "Stops the daily usage ping that counts this install in Brave's active-user statistics." },
    @{ Name = "Limit Variations to Critical Fixes"; Key = "ChromeVariations"; Value = 1; Type = "DWord"; Group = "variations"
       Tip = "Restricts Brave's remote experiment seed (Griffin) to critical security and stability fixes, instead of the full set of A/B experiments. The safe choice of the two. Mutually exclusive with Disable Variations." },
    @{ Name = "Disable Variations / Griffin Experiments"; Key = "ChromeVariations"; Value = 2; Type = "DWord"; Group = "variations"
       Tip = "Blocks the remote experiment seed entirely, so Brave can no longer flip features in your installed browser from its servers. This also blocks the emergency killswitches Brave uses to turn off a broken or unsafe feature - pick Limit Variations to Critical Fixes unless you accept that. Mutually exclusive with Limit Variations to Critical Fixes." },
    @{ Name = "Disable Enhanced Spell Check"; Key = "SpellCheckServiceEnabled"; Value = 0; Type = "DWord"; Group = "spellcheck"
       Tip = "Stops enhanced spell check, which sends the text you type in web forms to Google's servers to be checked. Offline spell checking keeps working. Mutually exclusive with Disable Spellcheck, which turns spell checking off altogether and makes this row do nothing." }
)

$privacyFeatures = @(
    @{ Name = "Disable Safe Browsing (security downgrade)"; Key = "SafeBrowsingProtectionLevel"; Value = 0; Type = "DWord"
       Tip = "Turns Safe Browsing fully off. Brave already routes these lookups through its own servers, so Google never sees the sites you visit even with Safe Browsing on - turning it off buys almost no privacy and costs you the phishing and malware warning pages. Excluded from every preset for that reason." },
    @{ Name = "Disable Autofill (Addresses)"; Key = "AutofillAddressEnabled"; Value = 0; Type = "DWord"
       Tip = "Stops Brave from saving and auto-filling street addresses in web forms." },
    @{ Name = "Disable Autofill (Credit Cards)"; Key = "AutofillCreditCardEnabled"; Value = 0; Type = "DWord"
       Tip = "Stops Brave from saving and auto-filling credit card numbers in web forms." },
    @{ Name = "Disable Password Manager"; Key = "PasswordManagerEnabled"; Value = 0; Type = "DWord"
       Tip = "Disables the built-in password manager (no save prompts, no autofill). Recommended if you use a dedicated password manager." },
    @{ Name = "Disable Password Leak Detection"; Key = "PasswordLeakDetectionEnabled"; Value = 0; Type = "DWord"
       Tip = "Stops the online check that compares your saved credentials against known breach lists. Defense in depth if you audit passwords with your own manager instead." },
    @{ Name = "Disable Browser Sign-in"; Key = "BrowserSignin"; Value = 0; Type = "DWord"
       Tip = "Prevents signing in to the browser itself with an account." },
    @{ Name = "Enable Global Privacy Control"; Key = "BraveGlobalPrivacyControlEnabled"; Value = 1; Type = "DWord"
       Tip = "Sends the GPC signal with every request, telling sites not to sell or share your data. Legally binding in some regions (e.g. under CCPA)." },
    @{ Name = "Enable De-AMP"; Key = "BraveDeAmpEnabled"; Value = 1; Type = "DWord"
       Tip = "Skips Google AMP pages and loads the publisher's original page instead." },
    @{ Name = "Enable Debouncing"; Key = "BraveDebouncingEnabled"; Value = 1; Type = "DWord"
       Tip = "Skips known tracking redirects and navigates straight to the final destination URL." },
    @{ Name = "Strip Tracking URL Parameters"; Key = "BraveTrackingQueryParametersFilteringEnabled"; Value = 1; Type = "DWord"
       Tip = "Removes known tracking parameters (fbclid, gclid, mc_eid, ...) from URLs before they load." },
    @{ Name = "Reduce Language Fingerprinting"; Key = "BraveReduceLanguageEnabled"; Value = 1; Type = "DWord"
       Tip = "Reports a generic language configuration to sites, making your browser harder to fingerprint." },
    @{ Name = "Disable WebRTC IP Leak"; Key = "WebRtcIPHandling"; Value = "disable_non_proxied_udp"; Type = "String"
       Tip = "Restricts WebRTC to proxied connections so video/voice calls can't expose your real IP address behind a VPN or proxy." },
    @{ Name = "Disable QUIC Protocol"; Key = "QuicAllowed"; Value = 0; Type = "DWord"
       Tip = "Disables the QUIC (HTTP/3) transport so all traffic uses TCP. Useful when a firewall or filter can't inspect QUIC; may slightly slow some Google sites." },
    @{ Name = "Disable Network Prediction (Prefetch)"; Key = "NetworkPredictionOptions"; Value = 2; Type = "DWord"
       Tip = "Stops Brave from pre-resolving DNS and pre-connecting to links it guesses you might click, so no network requests are made for pages you never visit." },
    @{ Name = "Block Third Party Cookies"; Key = "BlockThirdPartyCookies"; Value = 1; Type = "DWord"
       Tip = "Blocks cookies set by domains other than the site you are visiting. Can break some embedded logins." },
    @{ Name = "Block Payment Method Probing"; Key = "PaymentMethodQueryEnabled"; Value = 0; Type = "DWord"
       Tip = "Stops sites from querying whether you have payment methods saved (canMakePayment) - they are always told none are available." },
    @{ Name = "Disable Alternate Error Pages"; Key = "AlternateErrorPagesEnabled"; Value = 0; Type = "DWord"
       Tip = "Uses plain local error pages for navigation errors instead of a web-service-assisted suggestion page. Belt-and-braces: Brave already ships this off." },
    @{ Name = "Block Remote Debugging"; Key = "RemoteDebuggingAllowed"; Value = 0; Type = "DWord"
       Tip = "Blocks the remote debugging port and pipe, the interface automation tools use to drive the browser and read your cookies and logged-in sessions. Disable Developer Tools does not cover this. Breaks Puppeteer, Playwright and brave://inspect." },
    @{ Name = "Disable DNS Interception Probes"; Key = "DNSInterceptionChecksEnabled"; Value = 0; Type = "DWord"
       Tip = "Stops Brave from resolving three random hostnames at startup and again on every network change to detect a hijacking DNS provider. Those lookups are visible to your ISP or DoH resolver and mark each launch." },
    @{ Name = "Require HTTPS for Basic Auth"; Key = "BasicAuthOverHttpEnabled"; Value = 0; Type = "DWord"
       Tip = "Refuses HTTP Basic authentication over plain HTTP so your username and password are never sent in the clear. Breaks logins on legacy routers, printers and other appliances that only serve HTTP." }
)

# Site permissions and access lockdowns: content-setting defaults plus the
# escape hatches (guest, incognito, extensions) that would otherwise bypass
# the rest of the policy set.
#
# The first eight rows are tri-state content settings: a row carrying
# `Choices` is drawn as a dropdown instead of a checkbox, because Chromium
# accepts more than "block or leave alone" for these keys. Choices is an
# ordered list of Label/Value pairs; Value $null means "not managed", i.e.
# write nothing and remove any value we previously wrote. That entry is
# always first and is the default selection, so an untouched row behaves
# exactly like the old unchecked checkbox.
#
# The legal values differ per key and are NOT uniform - Allow (1) is not a
# member of the *GuardSetting / LocalFonts / WindowManagement enums, so
# those rows only offer Ask (3) and Block (2). Do not "tidy" them into a
# shared list.
#
# `Value` stays on a choice row as the value its pre-tri-state checkbox
# wrote (always Block). It is never written directly; it is what a bare key
# in a legacy array-format export means on import.
$sitePermissionFeatures = @(
    @{ Name = "Web Notifications"; Key = "DefaultNotificationsSetting"; Value = 2; Type = "DWord"
       Choices = @(
           @{ Label = "Not managed"; Value = $null },
           @{ Label = "Allow"; Value = 1 },
           @{ Label = "Ask";   Value = 3 },
           @{ Label = "Block"; Value = 2 })
       Tip = "Sets the default for desktop notifications. Block stops every site from asking or showing them, Ask keeps the permission prompt, Allow grants it to every site." },
    @{ Name = "Location Access"; Key = "DefaultGeolocationSetting"; Value = 2; Type = "DWord"
       Choices = @(
           @{ Label = "Not managed"; Value = $null },
           @{ Label = "Allow"; Value = 1 },
           @{ Label = "Ask";   Value = 3 },
           @{ Label = "Block"; Value = 2 })
       Tip = "Sets the default for reading your physical location. Block removes the prompt entirely, so maps and delivery sites will need the location typed manually; Ask keeps the prompt." },
    @{ Name = "Motion Sensors"; Key = "DefaultSensorsSetting"; Value = 2; Type = "DWord"
       Choices = @(
           @{ Label = "Not managed"; Value = $null },
           @{ Label = "Allow"; Value = 1 },
           @{ Label = "Ask";   Value = 3 },
           @{ Label = "Block"; Value = 2 })
       Tip = "Sets the default for motion and orientation sensors, a known fingerprinting vector. Blocking rarely breaks anything on desktop." },
    @{ Name = "WebUSB Access"; Key = "DefaultWebUsbGuardSetting"; Value = 2; Type = "DWord"
       Choices = @(
           @{ Label = "Not managed"; Value = $null },
           @{ Label = "Ask";   Value = 3 },
           @{ Label = "Block"; Value = 2 })
       Tip = "Sets the default for sites talking to USB devices. Block removes the prompt and breaks web-based hardware wallets (Ledger, Trezor) and in-browser firmware flashers; Ask keeps the prompt. Chromium has no Allow state for this key." },
    @{ Name = "Web Serial Access"; Key = "DefaultSerialGuardSetting"; Value = 2; Type = "DWord"
       Choices = @(
           @{ Label = "Not managed"; Value = $null },
           @{ Label = "Ask";   Value = 3 },
           @{ Label = "Block"; Value = 2 })
       Tip = "Sets the default for sites opening serial ports. Block removes the prompt and breaks in-browser microcontroller and device programming tools; Ask keeps the prompt. Chromium has no Allow state for this key." },
    @{ Name = "WebHID Access"; Key = "DefaultWebHidGuardSetting"; Value = 2; Type = "DWord"
       Choices = @(
           @{ Label = "Not managed"; Value = $null },
           @{ Label = "Ask";   Value = 3 },
           @{ Label = "Block"; Value = 2 })
       Tip = "Sets the default for sites talking to human interface devices. Block removes the prompt and may break security keys and gamepad configurators that use WebHID rather than WebAuthn. Chromium has no Allow state for this key." },
    @{ Name = "Local Font Enumeration"; Key = "DefaultLocalFontsSetting"; Value = 2; Type = "DWord"
       Choices = @(
           @{ Label = "Not managed"; Value = $null },
           @{ Label = "Ask";   Value = 3 },
           @{ Label = "Block"; Value = 2 })
       Tip = "Sets the default for sites asking which fonts are installed on your machine - a strong fingerprinting signal that Shields' font protections don't cover. Blocking rarely breaks anything outside web design tools. Chromium has no Allow state for this key." },
    @{ Name = "Multi-Screen Access"; Key = "DefaultWindowManagementSetting"; Value = 2; Type = "DWord"
       Choices = @(
           @{ Label = "Not managed"; Value = $null },
           @{ Label = "Ask";   Value = 3 },
           @{ Label = "Block"; Value = 2 })
       Tip = "Sets the default for sites reading your monitor layout and placing windows on a chosen screen. Blocking breaks the full-screen presentation mode in some web apps. Chromium has no Allow state for this key." }
)

# Lockdowns and the escape hatches (guest, incognito, extensions) that
# would otherwise bypass the rest of the policy set.
$accessControlFeatures = @(
    @{ Name = "Force Google SafeSearch"; Key = "ForceGoogleSafeSearch"; Value = 1; Type = "DWord"
       Tip = "Forces SafeSearch on for all Google searches. Mainly useful for parental controls." },
    @{ Name = "Filter Adult Content (SafeSites)"; Key = "SafeSitesFilterBehavior"; Value = 1; Type = "DWord"
       Tip = "Sends every URL you navigate to - including URLs loaded inside frames - to Google's Safe Search API to be classified, and blocks anything rated adult. This is a remote lookup, not a local filter. Mainly useful for parental controls." },
    @{ Name = "Disable Guest Mode"; Key = "BrowserGuestModeEnabled"; Value = 0; Type = "DWord"
       Tip = "Removes guest browsing sessions. Closes the loophole where a guest window bypasses profile-level restrictions and history." },
    @{ Name = "Block All Extensions"; Key = "ExtensionInstallBlocklist"; Value = @("*"); Type = "List"
       Tip = "Blocks installation of every extension and disables ones already installed. For lockdown/parental setups - a proxy or VPN extension would bypass DNS filtering." },
    @{ Name = "Block Sideloaded (External) Extensions"; Key = "BlockExternalExtensions"; Value = 1; Type = "DWord"
       Tip = "Blocks extensions that other programs install for you through the registry or a drop-in file, which is how bundleware gets in. Extensions you install yourself keep working, so this rarely breaks anything." },
    @{ Name = "Disable Incognito Mode"; Key = "IncognitoModeAvailability"; Value = 1; Type = "DWord"; Group = "incognito"
       Tip = "Removes private browsing entirely - no incognito windows can be opened. Mutually exclusive with Force Incognito Mode." },
    @{ Name = "Force Incognito Mode"; Key = "IncognitoModeAvailability"; Value = 2; Type = "DWord"; Group = "incognito"
       Tip = "Every window opens in incognito: no history, and logins and most extensions stop persisting. Mutually exclusive with Disable Incognito Mode." }
)

# Brave 1.84+ content-protection enforcers (fingerprinting protection also
# works on 1.83). These pin Brave's own privacy defaults as managed policy so
# neither the user nor a malicious page/extension can quietly weaken them.
$shieldsContentFeatures = @(
    @{ Name = "Enforce Ad Blocking"; Key = "DefaultBraveAdblockSetting"; Value = 2; Type = "DWord"
       Tip = "Pins Brave's ad and tracker blocking on as managed policy, so it can't be lowered in settings or per-site." },
    @{ Name = "Enforce Fingerprinting Protection"; Key = "DefaultBraveFingerprintingV2Setting"; Value = 3; Type = "DWord"
       Tip = "Pins Shields fingerprinting protection on as managed policy, so sites can't be exempted from it." },
    @{ Name = "Force HTTPS Upgrades (Strict)"; Key = "DefaultBraveHttpsUpgradeSetting"; Value = 2; Type = "DWord"
       Tip = "Always upgrades connections to HTTPS. Sites that can't serve HTTPS show a warning page instead of silently falling back to HTTP." },
    @{ Name = "Cap Referrers (Strict Origin)"; Key = "DefaultBraveReferrersSetting"; Value = 2; Type = "DWord"; Group = "referrers"
       Tip = "Caps the Referer header at the origin for cross-site requests, locked as managed policy. Mutually exclusive with Allow Permissive Referrers." },
    @{ Name = "Allow Permissive Referrers (unsafe-url)"; Key = "DefaultBraveReferrersSetting"; Value = 1; Type = "DWord"; Group = "referrers"
       Tip = "Sends your full referring URL cross-origin when a site requests it. Compatibility escape hatch only - this weakens privacy and is excluded from every preset. Mutually exclusive with Cap Referrers." },
    @{ Name = "Forget First-Party Storage on Close"; Key = "DefaultBraveRemember1PStorageSetting"; Value = 2; Type = "DWord"
       Tip = "Clears a site's cookies and storage when you close its last tab - sites forget you (and your logins) between visits." }
)

$braveFeatures = @(
    @{ Name = "Disable Brave Rewards"; Key = "BraveRewardsDisabled"; Value = 1; Type = "DWord"
       Tip = "Removes Brave Rewards and BAT ads from the browser UI." },
    @{ Name = "Disable Brave Wallet"; Key = "BraveWalletDisabled"; Value = 1; Type = "DWord"
       Tip = "Disables the built-in cryptocurrency wallet and hides its UI." },
    @{ Name = "Disable Brave VPN"; Key = "BraveVPNDisabled"; Value = 1; Type = "DWord"
       Tip = "Removes the Brave VPN feature and its upsell prompts." },
    @{ Name = "Disable Brave AI Chat"; Key = "BraveAIChatEnabled"; Value = 0; Type = "DWord"
       Tip = "Disables Leo, Brave's built-in AI assistant, and removes it from the sidebar and address bar." },
    @{ Name = "Disable Local AI (On-Device Models, Brave 1.94+)"; Key = "BraveLocalAIEnabled"; Value = 0; Type = "DWord"
       Tip = "Stops Brave from downloading and running on-device AI models and from building an AI index of your browsing history. Separate from Brave AI Chat - disabling Leo does not cover this. Needs Brave 1.94 or newer - that is current stable, so most installs already have it; older versions ignore the key. Takes effect after a browser restart." },
    @{ Name = "Disable Brave Shields"; Key = "BraveShieldsDisabledForUrls"; Value = @("https://*", "http://*"); Type = "List"; Group = "shields"
       Tip = "Turns Shields OFF for every site: no ad blocking, no tracker blocking. Also makes Enforce Ad Blocking, Enforce Fingerprinting Protection, Force HTTPS Upgrades and Cap Referrers do nothing, because Brave skips all four wherever Shields are off. Almost nobody wants this - it exists for kiosk/testing setups. Mutually exclusive with Force Shields On." },
    @{ Name = "Force Shields On (All Sites)"; Key = "BraveShieldsEnabledForUrls"; Value = @("https://*", "http://*"); Type = "List"; Group = "shields"
       Tip = "Locks Shields ON for every site; the per-site Shields toggle stops working. Mutually exclusive with Disable Brave Shields." },
    @{ Name = "Disable Brave News"; Key = "BraveNewsDisabled"; Value = 1; Type = "DWord"
       Tip = "Removes the Brave News feed from the new tab page." },
    @{ Name = "Disable Brave Talk"; Key = "BraveTalkDisabled"; Value = 1; Type = "DWord"
       Tip = "Disables Brave Talk video calls." },
    @{ Name = "Disable Brave Playlist"; Key = "BravePlaylistEnabled"; Value = 0; Type = "DWord"
       Tip = "Disables the Playlist feature for saving and playing media in the sidebar." },
    @{ Name = "Disable Web Discovery"; Key = "BraveWebDiscoveryEnabled"; Value = 0; Type = "DWord"
       Tip = "Stops Brave from anonymously contributing pages you visit to the Brave Search index (Web Discovery Project)." },
    @{ Name = "Disable Speedreader"; Key = "BraveSpeedreaderEnabled"; Value = 0; Type = "DWord"
       Tip = "Disables Speedreader, the distraction-free article reading mode." },
    @{ Name = "Disable Tor"; Key = "TorDisabled"; Value = 1; Type = "DWord"
       Tip = "Removes the 'New private window with Tor' option." },
    @{ Name = "Disable Sync"; Key = "SyncDisabled"; Value = 1; Type = "DWord"
       Tip = "Disables Brave Sync, which shares bookmarks, history, and settings across devices via a sync chain." },
    @{ Name = "Disable Email Aliases"; Key = "EmailAliasesEnabled"; Value = 0; Type = "DWord"
       Tip = "Disables the Email Aliases feature for generating throwaway email addresses." }
)

$perfFeatures = @(
    @{ Name = "Disable Background Mode"; Key = "BackgroundModeEnabled"; Value = 0; Type = "DWord"
       Tip = "Stops Brave from keeping background processes running after the last window is closed." },
    @{ Name = "Enable Memory Saver"; Key = "HighEfficiencyModeEnabled"; Value = 1; Type = "DWord"
       Tip = "Forces Memory Saver on: inactive tabs are discarded to free RAM and reload when you return to them." },
    @{ Name = "Force Hardware Acceleration"; Key = "HardwareAccelerationModeEnabled"; Value = 1; Type = "DWord"
       Tip = "Pins GPU hardware acceleration on so rendering and video decode stay off the CPU. Takes effect after a browser restart." },
    @{ Name = "Disable Media Router (Cast)"; Key = "EnableMediaRouter"; Value = 0; Type = "DWord"
       Tip = "Disables the Google Cast media router and its background device discovery on the local network. Takes effect after a browser restart." },
    @{ Name = "Disable Media Recommendations"; Key = "MediaRecommendationsEnabled"; Value = 0; Type = "DWord"
       Tip = "Disables the media history and recommendation surfaces built from what you watch." },
    @{ Name = "Disable Shopping List"; Key = "ShoppingListEnabled"; Value = 0; Type = "DWord"
       Tip = "Disables the price-tracking shopping list feature." },
    @{ Name = "Always Open PDF Externally"; Key = "AlwaysOpenPdfExternally"; Value = 1; Type = "DWord"
       Tip = "Downloads PDF files and opens them in your system PDF viewer instead of the built-in viewer." },
    @{ Name = "Disable Translate"; Key = "TranslateEnabled"; Value = 0; Type = "DWord"
       Tip = "Disables the built-in page translation feature and its popup prompts." },
    @{ Name = "Disable Spellcheck"; Key = "SpellcheckEnabled"; Value = 0; Type = "DWord"; Group = "spellcheck"
       Tip = "Turns off spell checking in text fields entirely. Mutually exclusive with Disable Enhanced Spell Check, which keeps offline checking and only removes the Google lookup." },
    @{ Name = "Disable Search Suggestions"; Key = "SearchSuggestEnabled"; Value = 0; Type = "DWord"
       Tip = "Stops sending what you type in the address bar to your search engine for live suggestions." },
    @{ Name = "Disable Printing"; Key = "PrintingEnabled"; Value = 0; Type = "DWord"
       Tip = "Disables printing from the browser entirely (including Ctrl+P)." },
    @{ Name = "Disable Default Browser Prompt"; Key = "DefaultBrowserSettingEnabled"; Value = 0; Type = "DWord"
       Tip = "Stops Brave from asking to become your default browser." },
    @{ Name = "Disable Developer Tools"; Key = "DeveloperToolsAvailability"; Value = 2; Type = "DWord"
       Tip = "Blocks DevTools (F12) and extension debugging everywhere. Don't enable this if you do web development." },
    @{ Name = "Disable Wayback Machine"; Key = "BraveWaybackMachineEnabled"; Value = 0; Type = "DWord"
       Tip = "Stops Brave from offering an archive.org snapshot when a page returns 404." }
)

# ---------------------------------------------------------------------------
# Embedded presets
#
# The Windows quick start downloads SlimBrave.ps1 on its own, so there is no
# Presets/ directory on disk for the Quick Presets row to read. The five
# preset files are embedded here verbatim instead, and parsed with the same
# ConvertFrom-Json the Import button uses, so a preset button and an imported
# file reach the controls by exactly the same route.
#
# These blocks are copies of Presets/*.json - regenerate them from those
# files rather than editing them here, because a typo is a silently wrong
# policy. Import still loads a preset (or any other config) from an arbitrary
# path, so this is additive.
#
# A here-string's closing '@ has to sit at column 0, which is why the JSON
# below is flush left.
# ---------------------------------------------------------------------------

$script:embeddedPresets = [ordered]@{
    "Maximum Privacy Preset" = @'
{
    "Features": {
        "MetricsReportingEnabled": false,
        "SafeBrowsingExtendedReportingEnabled": false,
        "UrlKeyedAnonymizedDataCollectionEnabled": false,
        "BraveP3AEnabled": false,
        "BraveStatsPingEnabled": false,
        "AutofillAddressEnabled": false,
        "AutofillCreditCardEnabled": false,
        "PasswordManagerEnabled": false,
        "PasswordLeakDetectionEnabled": false,
        "BrowserSignin": 0,
        "BraveGlobalPrivacyControlEnabled": true,
        "BraveDeAmpEnabled": true,
        "BraveDebouncingEnabled": true,
        "BraveTrackingQueryParametersFilteringEnabled": true,
        "BraveReduceLanguageEnabled": true,
        "WebRtcIPHandling": "disable_non_proxied_udp",
        "QuicAllowed": false,
        "NetworkPredictionOptions": 2,
        "BlockThirdPartyCookies": true,
        "PaymentMethodQueryEnabled": false,
        "AlternateErrorPagesEnabled": false,
        "DefaultNotificationsSetting": 2,
        "DefaultGeolocationSetting": 2,
        "DefaultSensorsSetting": 2,
        "BraveRewardsDisabled": true,
        "BraveWalletDisabled": true,
        "BraveVPNDisabled": true,
        "BraveAIChatEnabled": false,
        "BraveNewsDisabled": true,
        "BraveTalkDisabled": true,
        "BravePlaylistEnabled": false,
        "BraveWebDiscoveryEnabled": false,
        "BraveSpeedreaderEnabled": false,
        "TorDisabled": true,
        "SyncDisabled": true,
        "EmailAliasesEnabled": false,
        "DefaultBraveAdblockSetting": 2,
        "DefaultBraveFingerprintingV2Setting": 3,
        "DefaultBraveHttpsUpgradeSetting": 2,
        "DefaultBraveReferrersSetting": 2,
        "DefaultBraveRemember1PStorageSetting": 2,
        "BackgroundModeEnabled": false,
        "EnableMediaRouter": false,
        "MediaRecommendationsEnabled": false,
        "ShoppingListEnabled": false,
        "AlwaysOpenPdfExternally": true,
        "TranslateEnabled": false,
        "SpellcheckEnabled": false,
        "SearchSuggestEnabled": false,
        "PrintingEnabled": false,
        "DefaultBrowserSettingEnabled": false,
        "DeveloperToolsAvailability": 2,
        "BraveWaybackMachineEnabled": false,
        "BraveLocalAIEnabled": false,
        "DNSInterceptionChecksEnabled": false,
        "RemoteDebuggingAllowed": false,
        "BasicAuthOverHttpEnabled": false,
        "BlockExternalExtensions": true,
        "ChromeVariations": 1
    }
}
'@
    "Balanced Privacy Preset" = @'
{
    "Features": {
        "MetricsReportingEnabled": false,
        "SafeBrowsingExtendedReportingEnabled": false,
        "UrlKeyedAnonymizedDataCollectionEnabled": false,
        "BraveP3AEnabled": false,
        "BraveStatsPingEnabled": false,
        "AutofillCreditCardEnabled": false,
        "BrowserSignin": 0,
        "BraveGlobalPrivacyControlEnabled": true,
        "BraveDeAmpEnabled": true,
        "BraveDebouncingEnabled": true,
        "BraveTrackingQueryParametersFilteringEnabled": true,
        "BraveReduceLanguageEnabled": true,
        "WebRtcIPHandling": "disable_non_proxied_udp",
        "QuicAllowed": false,
        "NetworkPredictionOptions": 2,
        "BlockThirdPartyCookies": true,
        "PaymentMethodQueryEnabled": false,
        "AlternateErrorPagesEnabled": false,
        "BraveRewardsDisabled": true,
        "BraveWalletDisabled": true,
        "BraveVPNDisabled": true,
        "BraveAIChatEnabled": false,
        "BraveNewsDisabled": true,
        "BraveTalkDisabled": true,
        "BraveWebDiscoveryEnabled": false,
        "TorDisabled": true,
        "SyncDisabled": true,
        "BackgroundModeEnabled": false,
        "MediaRecommendationsEnabled": false,
        "ShoppingListEnabled": false,
        "DefaultBrowserSettingEnabled": false,
        "BraveLocalAIEnabled": false,
        "DNSInterceptionChecksEnabled": false,
        "RemoteDebuggingAllowed": false,
        "BasicAuthOverHttpEnabled": false,
        "BlockExternalExtensions": true,
        "ChromeVariations": 1,
        "SpellCheckServiceEnabled": false
    },
    "DnsMode": "automatic"
}
'@
    "Performance Focused Preset" = @'
{
    "Features": {
        "MetricsReportingEnabled": false,
        "BraveP3AEnabled": false,
        "BraveStatsPingEnabled": false,
        "BraveDeAmpEnabled": true,
        "BraveDebouncingEnabled": true,
        "BraveTrackingQueryParametersFilteringEnabled": true,
        "BraveRewardsDisabled": true,
        "BraveWalletDisabled": true,
        "BraveVPNDisabled": true,
        "BraveAIChatEnabled": false,
        "BraveNewsDisabled": true,
        "BraveTalkDisabled": true,
        "BravePlaylistEnabled": false,
        "BraveWebDiscoveryEnabled": false,
        "BraveSpeedreaderEnabled": false,
        "BackgroundModeEnabled": false,
        "HighEfficiencyModeEnabled": true,
        "HardwareAccelerationModeEnabled": true,
        "EnableMediaRouter": false,
        "MediaRecommendationsEnabled": false,
        "ShoppingListEnabled": false,
        "DefaultBrowserSettingEnabled": false,
        "BraveWaybackMachineEnabled": false,
        "BraveLocalAIEnabled": false
    },
    "DnsMode": "automatic"
}
'@
    "Developer Preset" = @'
{
    "Features": {
        "MetricsReportingEnabled": false,
        "SafeBrowsingExtendedReportingEnabled": false,
        "UrlKeyedAnonymizedDataCollectionEnabled": false,
        "BraveP3AEnabled": false,
        "BraveStatsPingEnabled": false,
        "AlternateErrorPagesEnabled": false,
        "BraveRewardsDisabled": true,
        "BraveWalletDisabled": true,
        "BraveVPNDisabled": true,
        "BraveAIChatEnabled": false,
        "BraveNewsDisabled": true,
        "BraveTalkDisabled": true,
        "BackgroundModeEnabled": false,
        "MediaRecommendationsEnabled": false,
        "ShoppingListEnabled": false,
        "DefaultBrowserSettingEnabled": false,
        "BraveLocalAIEnabled": false,
        "DNSInterceptionChecksEnabled": false,
        "ChromeVariations": 1,
        "SpellCheckServiceEnabled": false
    },
    "DnsMode": "automatic"
}
'@
    "Strict Parental Controls Preset" = @'
{
    "Features": {
        "BraveP3AEnabled": false,
        "BraveStatsPingEnabled": false,
        "IncognitoModeAvailability": 1,
        "BrowserGuestModeEnabled": false,
        "ExtensionInstallBlocklist": [
            "*"
        ],
        "ForceGoogleSafeSearch": true,
        "SafeSitesFilterBehavior": 1,
        "BrowserSignin": 0,
        "BraveDeAmpEnabled": true,
        "BraveDebouncingEnabled": true,
        "BraveTrackingQueryParametersFilteringEnabled": true,
        "BraveReduceLanguageEnabled": true,
        "SyncDisabled": true,
        "BraveRewardsDisabled": true,
        "BraveWalletDisabled": true,
        "BraveVPNDisabled": true,
        "BraveAIChatEnabled": false,
        "BraveNewsDisabled": true,
        "BraveTalkDisabled": true,
        "BraveWebDiscoveryEnabled": false,
        "TorDisabled": true,
        "DeveloperToolsAvailability": 2,
        "RemoteDebuggingAllowed": false
    },
    "DnsMode": "custom",
    "DnsTemplates": "https://family.cloudflare-dns.com/dns-query"
}
'@
    "Brave Origin Preset" = @'
{
    "Features": {
        "BraveP3AEnabled": false,
        "BraveStatsPingEnabled": false,
        "BraveRewardsDisabled": true,
        "BraveWalletDisabled": true,
        "BraveVPNDisabled": true,
        "BraveAIChatEnabled": false,
        "BraveLocalAIEnabled": false,
        "BraveNewsDisabled": true,
        "BraveTalkDisabled": true,
        "BravePlaylistEnabled": false,
        "BraveWebDiscoveryEnabled": false,
        "BraveSpeedreaderEnabled": false,
        "BraveWaybackMachineEnabled": false,
        "TorDisabled": true,
        "EmailAliasesEnabled": false
    }
}
'@
}

# ---------------------------------------------------------------------------
# Column layout
#
# Three fixed columns, always. The window is a fixed size that fits on a
# 1366x768 display; each column is its own AutoScroll panel, so a column
# whose categories are taller than the panel scrolls on its own and the DNS
# row and the button row below never move.
#
# This deliberately replaces the old height heuristic (measure the natural
# two-column window, compare it against the working area, reflow to three
# columns if it doesn't fit, and cap the form height as a last resort). That
# constant was wrong by a few pixels in both directions across DPI scales,
# and its safety net then produced the whole-window scrollbar it existed to
# prevent. Nothing measures the screen any more, so there is no constant to
# drift: adding rows makes a column scroll instead of resizing the window.
# ---------------------------------------------------------------------------

$categories = @(
    @{ Name = "Telemetry & Reporting";        Features = $telemetryFeatures },
    @{ Name = "Privacy & Security";           Features = $privacyFeatures },
    @{ Name = "Site Permissions";             Features = $sitePermissionFeatures },
    @{ Name = "Access Controls";              Features = $accessControlFeatures },
    @{ Name = "Shields & Content Protection"; Features = $shieldsContentFeatures },
    @{ Name = "Brave Features";               Features = $braveFeatures },
    @{ Name = "Performance & Bloat";          Features = $perfFeatures }
)
$categoryByName = @{}
foreach ($cat in $categories) { $categoryByName[$cat.Name] = $cat }

# ---------------------------------------------------------------------------
# ADAPTER - native feature tables to the shape the interface reads
#
# The interface wants a lowercase row shape with a description and an ordered
# choices list. The tables above are the single source of truth and stay in the
# form the test suite parses, so the translation happens here at startup rather
# than by maintaining a second copy of all 78 policies.
#
# Ids are index-based because a few policy keys legitimately appear on two rows
# (incognito, referrers). State is keyed by id, never by key.
# ---------------------------------------------------------------------------
$script:state = @{}
$script:cats = @()
$script:dnsModes = @("unmanaged", "automatic", "off", "secure", "custom")

$ci = 0
foreach ($cat in $categories) {
    $rows = @()
    $ri = 0
    foreach ($f in $cat.Features) {
        $tip = [string]$f.Tip
        $short = $tip
        $dot = $tip.IndexOf(". ")
        if ($dot -gt 0) { $short = $tip.Substring(0, $dot) }
        $choices = $null
        if ($null -ne $f.Choices) {
            $choices = @()
            foreach ($c in $f.Choices) { $choices += ,@($c.Label, $c.Value) }
        }
        $group = ""
        if ($f.ContainsKey("Group")) { $group = [string]$f.Group }
        $row = [pscustomobject]@{
            Id      = "$ci.$ri"
            name    = [string]$f.Name
            key     = [string]$f.Key
            value   = $f.Value
            type    = [string]$f.Type
            full    = $tip
            short   = $short
            group   = $group
            choices = $choices
        }
        if ($null -eq $choices) { $row.PSObject.Properties.Remove('choices') }
        $rows += $row
        $script:state["$ci.$ri"] = @{ On = $false; Sel = 0 }
        $ri++
    }
    $script:cats += [pscustomobject]@{ name = [string]$cat.Name; rows = $rows }
    $ci++
}

# Preset cards read the embedded presets, so there is no second copy of those
# either. Blurbs are presentation, not data.
$script:presetBlurbs = @{
    "Maximum Privacy Preset"          = "Everything privacy-related, at the cost of convenience."
    "Balanced Privacy Preset"         = "Strong privacy that keeps the conveniences most people want."
    "Performance Focused Preset"      = "Speed and clutter, not privacy extremes."
    "Developer Preset"                = "Telemetry off, dev tools and the network stack untouched."
    "Strict Parental Controls Preset" = "Lockdown: filtered, no incognito, no extensions."
    "Brave Origin Preset"             = "Clones Brave Origin's enforced policy set."
}
$script:presets = @()
foreach ($name in $script:embeddedPresets.Keys) {
    $obj = $script:embeddedPresets[$name] | ConvertFrom-Json
    $count = @($obj.Features.PSObject.Properties).Count
    $blurb = ""
    if ($script:presetBlurbs.ContainsKey($name)) { $blurb = $script:presetBlurbs[$name] }
    $script:presets += [pscustomobject]@{
        name     = ($name -replace ' Preset$', '')
        blurb    = $blurb
        count    = $count
        features = $obj.Features
        dns      = [string]$obj.DnsMode
        tmpl     = [string]$obj.DnsTemplates
    }
}
# SlimBrave Fluent - policy engine. Dot-sourced by fluent3.ps1.
# Ported from SlimBrave.ps1 with the same semantics, including the fixes that
# shipped in v2.0.x: scoped Reset, and DNS "secure" requiring a template.

$script:dnsState = @{ Mode = 0; Tmpl = "" }

# ---------------------------------------------------------------------------
# REGISTRY
# ---------------------------------------------------------------------------
$script:machineReg = "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave"
$script:userReg    = "HKCU:\SOFTWARE\Policies\BraveSoftware\Brave"

function Test-Elevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-AllRows {
    $out = @()
    foreach ($cat in $script:cats) { foreach ($row in $cat.rows) { $out += $row } }
    return $out
}

function Test-IsChoiceRow($row) {
    return ($null -ne $row.PSObject.Properties['choices'])
}

function Get-RowPolicyValue($row) {
    # $null means "this row manages nothing" - unticked, or a choice row left
    # on "Not managed". Those fall into Apply's removal branch.
    $st = $script:state[$row.Id]
    if (Test-IsChoiceRow $row) {
        if ($st.Sel -le 0) { return $null }
        return $row.choices[$st.Sel][1]
    }
    if (-not $st.On) { return $null }
    # Unary comma: PowerShell unrolls a one-element array on return, which turns
    # ExtensionInstallBlocklist = @("*") into a bare string, so Get-RowRegType
    # calls it String and it is written as REG_SZ instead of a policy list.
    # Chromium then ignores it while the UI reports success.
    if ($row.value -is [array]) { return ,$row.value }
    return $row.value
}

function Get-DeclaredListValues {
    # Every List row's declared value, keyed by policy key. Used as the
    # ownership baseline when deciding whether a list on disk is ours.
    $map = @{}
    foreach ($row in Get-AllRows) {
        if ($row.value -is [array]) { $map[$row.key] = [string[]]$row.value }
    }
    return $map
}

function Remove-OwnedListPolicy([string]$Scope, [string]$Key, $DeclaredLists) {
    # An unticked List row does NOT mean "no list is set". Re-sync only ticks
    # the box on a match, so an admin's own - or a GPO's, or Intune's -
    # ExtensionInstallBlocklist leaves it unticked, and removing the subkey
    # would destroy a policy SlimBrave never wrote. Only remove a list that is
    # exactly ours. Non-list keys are unaffected.
    if (-not (Test-Path $Scope)) { return $false }
    if ($DeclaredLists.ContainsKey($Key) -and
        -not (Test-ListPolicyIsExactly -RegistryPath $Scope -Name $Key `
                                       -Expected $DeclaredLists[$Key])) {
        return $false
    }
    Remove-ListPolicy $Scope $Key
    return $true
}

function Get-RowRegType($value) {
    if ($value -is [array])  { return "List" }
    if ($value -is [string]) { return "String" }
    return "DWord"
}

function ConvertTo-RegValue($value) {
    if ($value -is [bool]) { if ($value) { return 1 } else { return 0 } }
    return $value
}

function Set-ListPolicy([string]$RegistryPath, [string]$Name, [string[]]$Values) {
    $listKey = Join-Path $RegistryPath $Name
    if (Test-Path $listKey) { Remove-Item -Path $listKey -Recurse -Force }
    if (Get-ItemProperty -Path $RegistryPath -Name $Name -ErrorAction SilentlyContinue) {
        Remove-ItemProperty -Path $RegistryPath -Name $Name -ErrorAction SilentlyContinue
    }
    New-Item -Path $listKey -Force | Out-Null
    for ($i = 0; $i -lt $Values.Count; $i++) {
        Set-ItemProperty -Path $listKey -Name ($i + 1) -Value $Values[$i] -Type String -Force
    }
}

function Remove-ListPolicy([string]$RegistryPath, [string]$Name) {
    $listKey = Join-Path $RegistryPath $Name
    if (Test-Path $listKey) { Remove-Item -Path $listKey -Recurse -Force }
    if (Get-ItemProperty -Path $RegistryPath -Name $Name -ErrorAction SilentlyContinue) {
        Remove-ItemProperty -Path $RegistryPath -Name $Name -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------
# DoH TEMPLATE VALIDATION
# The only free-text input in the tool, and the only place a keystroke reaches
# a policy value. A malformed template with mode "secure" leaves Brave unable
# to resolve any hostname, and the user cannot undo it from brave://settings
# because the policy is machine-managed. Validate before writing, never after.
# ---------------------------------------------------------------------------
function Test-DohTemplate([string]$Raw) {
    $v = [string]$Raw
    # Control characters in a registry string are a corrupted policy, not a
    # validation error, so strip rather than reject.
    $v = ($v -replace '[\x00-\x1F\x7F]', '').Trim()
    if ([string]::IsNullOrWhiteSpace($v)) {
        return @{ Ok = $false; Value = ""; Reason = "The template is empty." }
    }
    if ($v.Length -gt 2048) {
        return @{ Ok = $false; Value = $v; Reason = "The template is unreasonably long (over 2048 characters)." }
    }
    $uri = $null
    if (-not [System.Uri]::TryCreate($v, [System.UriKind]::Absolute, [ref]$uri)) {
        return @{ Ok = $false; Value = $v; Reason = "That is not a complete URL. A DoH template looks like https://cloudflare-dns.com/dns-query." }
    }
    if ($uri.Scheme -ne "https") {
        return @{ Ok = $false; Value = $v; Reason = "DoH templates must use https. Chromium rejects '$($uri.Scheme)', which would leave secure DNS with no working resolver." }
    }
    if ([string]::IsNullOrWhiteSpace($uri.Host)) {
        return @{ Ok = $false; Value = $v; Reason = "The URL has no hostname." }
    }
    return @{ Ok = $true; Value = $v; Reason = "" }
}

# ---------------------------------------------------------------------------
# LEAKED SHIELDS EXCEPTIONS
# Brave writes managed *ForUrls content-setting policies through to each
# profile's Preferences file. Removing the policy from the registry does NOT
# roll those entries back, so unticking "Disable Brave Shields" leaves shields
# stuck off. They land in every profile of every installed channel, because the
# registry policy applies to all of them.
# ---------------------------------------------------------------------------
function Repair-OneBravePrefs([string]$pref) {
    if (-not (Test-Path $pref)) { return 0 }
    try { $j = Get-Content $pref -Raw -Encoding UTF8 | ConvertFrom-Json } catch { return 0 }
    $bs = $null
    if ($j.profile -and $j.profile.content_settings -and $j.profile.content_settings.exceptions) {
        $bs = $j.profile.content_settings.exceptions.braveShields
    }
    if (-not $bs) { return 0 }
    $removed = 0
    foreach ($pattern in @('http://*,*', 'https://*,*')) {
        if ($bs.PSObject.Properties.Name -contains $pattern) {
            $bs.PSObject.Properties.Remove($pattern)
            $removed++
        }
    }
    if ($removed -eq 0) { return 0 }
    # Brave reads Preferences as compact UTF-8 without BOM. Out-File would
    # write UTF-16 with a BOM and break Brave on next launch.
    $json = $j | ConvertTo-Json -Depth 100 -Compress
    $tmp = "$pref.slimbrave-tmp"
    try {
        [System.IO.File]::WriteAllText($tmp, $json, (New-Object System.Text.UTF8Encoding $false))
        Move-Item -Force $tmp $pref
    } catch {
        if (Test-Path $tmp) { Remove-Item -Force $tmp -ErrorAction SilentlyContinue }
        return 0
    }
    return $removed
}

function Get-UserAppDataRoots {
    <#
      Which LOCALAPPDATA roots hold a Brave profile worth scrubbing.

      The single-user case is the fast path and comes first: the invoking
      user's own root. But the policy this tool writes lives in HKLM and
      applies to every account on the machine, so on a shared PC the leaked
      Shields exceptions land in every profile that opened Brave while it was
      active - not just the one running this.

      Other users' roots come from the ProfileList registry key rather than by
      globbing C:\Users, because that key is the authoritative mapping and it
      lets us filter to real interactive accounts (S-1-5-21-*), skipping
      SYSTEM, service accounts, Default and Public.
    #>
    $roots = New-Object System.Collections.ArrayList
    $primary = $env:LOCALAPPDATA
    if (-not [string]::IsNullOrWhiteSpace($script:OriginalLocalAppData)) {
        $primary = $script:OriginalLocalAppData
    }
    if (-not [string]::IsNullOrWhiteSpace($primary)) {
        [void]$roots.Add(@{ Path = $primary; Label = "this user" })
    }

    $profileList = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
    if (Test-Path $profileList) {
        foreach ($sk in (Get-ChildItem $profileList -ErrorAction SilentlyContinue)) {
            $sid = $sk.PSChildName
            if ($sid -notlike "S-1-5-21-*") { continue }
            $img = (Get-ItemProperty $sk.PSPath -ErrorAction SilentlyContinue).ProfileImagePath
            if ([string]::IsNullOrWhiteSpace($img)) { continue }
            $local = Join-Path $img "AppData\Local"
            # Another user's profile is unreadable when this is running
            # unelevated, and Test-Path surfaces that as a visible error even
            # though the miss is handled. Silence it: an unreadable root is
            # simply one we cannot repair.
            if (-not (Test-Path $local -ErrorAction SilentlyContinue)) { continue }
            $already = $false
            foreach ($r in $roots) {
                if ($r.Path -and ($r.Path.TrimEnd('\') -ieq $local.TrimEnd('\'))) { $already = $true; break }
            }
            if ($already) { continue }
            # only bother with accounts that actually have Brave data
            if (-not (Test-Path (Join-Path $local "BraveSoftware") -ErrorAction SilentlyContinue)) { continue }
            [void]$roots.Add(@{ Path = $local; Label = (Split-Path $img -Leaf) })
        }
    }
    return $roots
}

function Repair-OneUserRoot([string]$localAppData) {
    # One unreadable or locked profile must not abort the sweep - the other
    # users on the machine still deserve their repair.
    $removed = 0
    foreach ($channelDir in @('Brave-Browser', 'Brave-Browser-Beta', 'Brave-Browser-Nightly', 'Brave-Browser-Dev')) {
        $userData = Join-Path $localAppData "BraveSoftware\$channelDir\User Data"
        if (-not (Test-Path $userData)) { continue }
        $profileDirs = Get-ChildItem -Path $userData -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' }
        foreach ($dir in $profileDirs) {
            try { $removed += Repair-OneBravePrefs (Join-Path $dir.FullName 'Preferences') } catch { }
        }
    }
    return $removed
}

function Repair-BravePrefs {
    # Every Brave channel runs as brave.exe on Windows.
    $running = ($null -ne (Get-Process brave -ErrorAction SilentlyContinue))
    # Chromium serves prefs from an in-memory PrefService and rewrites the file
    # on shutdown, so a scrub done now is discarded the moment the user closes
    # Brave - which is exactly what we tell them to do next. Report it instead
    # of claiming a clean that will not survive.
    if ($running) { return @{ Removed = 0; Running = $true; Skipped = $true; Users = 0 } }

    $removed = 0
    $users = 0
    foreach ($root in Get-UserAppDataRoots) {
        $n = Repair-OneUserRoot $root.Path
        if ($n -gt 0) { $users++ }
        $removed += $n
    }
    return @{ Removed = $removed; Running = $false; Skipped = $false; Users = $users }
}

function Get-RepairNote($repair) {
    if ($repair.Skipped) {
        return " Brave is running, so leaked profile prefs were left alone - it would overwrite the fix on its next save. Close Brave fully and run this again to clear them."
    }
    if ($repair.Removed -gt 0) {
        $plural = ""
        if ($repair.Removed -ne 1) { $plural = "s" }
        # Machine policy applies to every account, so say when the repair
        # reached beyond the person sitting here.
        if ($repair.Users -gt 1) {
            return " Also cleaned $($repair.Removed) leaked profile pref$plural across $($repair.Users) user profiles on this PC."
        }
        return " Also cleaned $($repair.Removed) leaked profile pref$plural that earlier SlimBrave versions wrote into your Brave profile."
    }
    return ""
}

function Invoke-ApplyPolicy {
    # DNS is validated first. Writing features and then bailing out would
    # leave the store half-applied, which is what the v1.9.5 critical bug
    # looked like in practice - "secure" with no template is as fatal as
    # "custom" with none.
    $mode = $script:dnsModes[$script:dnsState.Mode]
    $needsTemplate = ($mode -eq "custom" -or $mode -eq "secure")
    if ($needsTemplate) {
        $check = Test-DohTemplate $script:dnsState.Tmpl
        if (-not $check.Ok) {
            [void][System.Windows.Forms.MessageBox]::Show(
                "$($check.Reason)`n`nMode '$mode' sends DNS over HTTPS only - with no working resolver, nothing resolves at all, and the setting cannot be changed from brave://settings because it is machine policy.",
                "Check the DoH template",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning)
            return $false
        }
        # write the sanitised value, not the raw keystrokes
        $script:dnsState.Tmpl = $check.Value
    } elseif (-not [string]::IsNullOrWhiteSpace($script:dnsState.Tmpl)) {
        # a template kept for "automatic" still has to be well-formed
        $check = Test-DohTemplate $script:dnsState.Tmpl
        if (-not $check.Ok) {
            [void][System.Windows.Forms.MessageBox]::Show(
                "$($check.Reason)`n`nClear the template or correct it before applying.",
                "Check the DoH template",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning)
            return $false
        }
        $script:dnsState.Tmpl = $check.Value
    }
    if (-not (Test-Elevated)) {
        [void][System.Windows.Forms.MessageBox]::Show(
            "Writing machine policy needs Administrator. Relaunch elevated to apply.",
            "Not elevated",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning)
        return $false
    }
    if (-not (Test-Path $script:machineReg)) {
        New-Item -Path $script:machineReg -Force | Out-Null
    }

    $selected = @{}
    foreach ($row in Get-AllRows) {
        $v = Get-RowPolicyValue $row
        if ($null -eq $v) { continue }
        $selected[$row.key] = @{ Key = $row.key; Value = $v; Type = (Get-RowRegType $v) }
    }
    $declaredLists = Get-DeclaredListValues
    $skippedLists = @{}
    $uniqueKeys = (Get-AllRows | ForEach-Object { $_.key } | Select-Object -Unique)
    $written = 0
    foreach ($key in $uniqueKeys) {
        if ($selected.ContainsKey($key)) {
            $f = $selected[$key]
            try {
                if ($f.Type -eq "List") {
                    Set-ListPolicy $script:machineReg $f.Key ([string[]]$f.Value)
                    Remove-ListPolicy $script:userReg $f.Key
                } else {
                    Set-ItemProperty -Path $script:machineReg -Name $f.Key `
                        -Value (ConvertTo-RegValue $f.Value) -Type $f.Type -Force
                    if ((Test-Path $script:userReg) -and
                        (Get-ItemProperty -Path $script:userReg -Name $key -ErrorAction SilentlyContinue)) {
                        Remove-ItemProperty -Path $script:userReg -Name $key -ErrorAction SilentlyContinue
                    }
                }
                $written++
            } catch { }
        } else {
            foreach ($scope in @($script:machineReg, $script:userReg)) {
                if (-not (Remove-OwnedListPolicy $scope $key $declaredLists)) {
                    if ($declaredLists.ContainsKey($key)) { $skippedLists[$key] = $true }
                }
            }
        }
    }

    # Clear BOTH scopes first, unconditionally. The managed branch below used
    # to write HKLM only and never touch the user-scope twin, unlike every other
    # key here - so a leftover HKCU DnsOverHttpsTemplates from an older tool
    # survived, stayed invisible to Read-LivePolicy (machine scope only), and
    # could still be the template Chromium honoured.
    foreach ($scope in @($script:machineReg, $script:userReg)) {
        if (Test-Path $scope) {
            Remove-ItemProperty -Path $scope -Name "DnsOverHttpsMode" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $scope -Name "DnsOverHttpsTemplates" -ErrorAction SilentlyContinue
        }
    }
    if ($mode -eq "unmanaged") {
        # nothing further: the scrub above is the whole action
    } else {
        # "custom" is Chromium's "secure" plus a template; the UI keeps them
        # apart so the template field can be required for one and not the other.
        $writeMode = $mode
        if ($mode -eq "custom") { $writeMode = "secure" }
        Set-ItemProperty -Path $script:machineReg -Name "DnsOverHttpsMode" -Value $writeMode -Type String -Force
        # Chromium does honour a template in "automatic" mode, but this UI
        # greys the template box out there and captions it "Only used by the
        # custom and secure modes". Writing it anyway pinned a resolver the
        # interface said was inactive, with the box disabled so it could not be
        # cleared. Match what the user is shown; "custom" is the way to pair a
        # template with a mode here.
        $wantsTemplate = ($mode -eq "custom" -or $mode -eq "secure")
        if ($wantsTemplate -and -not [string]::IsNullOrWhiteSpace($script:dnsState.Tmpl)) {
            Set-ItemProperty -Path $script:machineReg -Name "DnsOverHttpsTemplates" `
                -Value $script:dnsState.Tmpl -Type String -Force
        } else {
            Remove-ItemProperty -Path $script:machineReg -Name "DnsOverHttpsTemplates" -ErrorAction SilentlyContinue
        }
        $written++
    }
    $repair = Repair-BravePrefs
    Set-Status ("Applied $written policies. Restart Brave, then check brave://policy." + (Get-RepairNote $repair))
    return $true
}

function Invoke-ResetPolicy {
    # Scoped to keys this tool manages. A recursive delete of the hive would
    # take out GPO-set policies SlimBrave never wrote - the v2.0.0 bug.
    if (-not (Test-Elevated)) {
        [void][System.Windows.Forms.MessageBox]::Show(
            "Removing machine policy needs Administrator. Relaunch elevated to reset.",
            "Not elevated",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning)
        return $false
    }
    $uniqueKeys = (Get-AllRows | ForEach-Object { $_.key } | Select-Object -Unique)
    $declaredLists = Get-DeclaredListValues
    $skippedLists = @{}
    foreach ($scope in @($script:machineReg, $script:userReg)) {
        if (-not (Test-Path $scope)) { continue }
        foreach ($key in $uniqueKeys) {
            if (-not (Remove-OwnedListPolicy $scope $key $declaredLists)) {
                if ($declaredLists.ContainsKey($key)) { $skippedLists[$key] = $true }
            }
        }
        Remove-ItemProperty -Path $scope -Name "DnsOverHttpsMode" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $scope -Name "DnsOverHttpsTemplates" -ErrorAction SilentlyContinue
    }
    foreach ($id in @($script:state.Keys)) { $script:state[$id].On = $false; $script:state[$id].Sel = 0 }
    $script:dnsState.Mode = 0
    $script:dnsState.Tmpl = ""
    $repair = Repair-BravePrefs
    $note = "Reset. Only keys SlimBrave Neo manages were removed."
    if ($skippedLists.Count -gt 0) {
        $note += " Left $($skippedLists.Count) externally-managed list policy" +
                 $(if ($skippedLists.Count -eq 1) { "" } else { "s" }) + " alone."
    }
    Set-Status ($note + (Get-RepairNote $repair))
    return $true
}

function Read-LivePolicy {
    $live = @{}
    if (Test-Path $script:machineReg) {
        foreach ($pr in (Get-ItemProperty $script:machineReg).PSObject.Properties) {
            if ($pr.Name -notlike "PS*") { $live[$pr.Name] = $pr.Value }
        }
        foreach ($sk in (Get-ChildItem $script:machineReg -ErrorAction SilentlyContinue)) {
            $vals = @()
            foreach ($pr in (Get-ItemProperty $sk.PSPath).PSObject.Properties) {
                if ($pr.Name -match '^[0-9]+$') { $vals += [string]$pr.Value }
            }
            if ($vals.Count -gt 0) { $live[$sk.PSChildName] = $vals }
        }
    }
    return $live
}

function Sync-FromRegistry {
    $live = Read-LivePolicy
    foreach ($id in @($script:state.Keys)) { $script:state[$id].On = $false; $script:state[$id].Sel = 0 }
    foreach ($row in Get-AllRows) {
        if (-not $live.ContainsKey($row.key)) { continue }
        $lv = $live[$row.key]
        if (Test-IsChoiceRow $row) {
            for ($i = 1; $i -lt $row.choices.Count; $i++) {
                if ([string]$row.choices[$i][1] -eq [string]$lv) { $script:state[$row.Id].Sel = $i; break }
            }
        } elseif ($row.value -is [array]) {
            if (($lv -is [array]) -and ((($lv) -join ",") -eq (($row.value) -join ","))) {
                $script:state[$row.Id].On = $true
            }
        } else {
            if ([string]$lv -eq [string](ConvertTo-RegValue $row.value)) { $script:state[$row.Id].On = $true }
        }
    }
    $script:dnsState.Mode = 0
    $script:dnsState.Tmpl = ""
    if ($live.ContainsKey("DnsOverHttpsMode")) {
        $m = [string]$live["DnsOverHttpsMode"]
        $tm = ""
        if ($live.ContainsKey("DnsOverHttpsTemplates")) { $tm = [string]$live["DnsOverHttpsTemplates"] }
        # A stored "secure" with a template is what this UI calls "custom".
        if ($m -eq "secure" -and $tm) { $m = "custom" }
        $idx = [Array]::IndexOf($script:dnsModes, $m)
        if ($idx -ge 0) { $script:dnsState.Mode = $idx }
        $script:dnsState.Tmpl = $tm
    }
    Set-Status "Policy read from registry - $($live.Count) values found"
}

function Import-PresetIntoState($preset) {
    foreach ($id in @($script:state.Keys)) { $script:state[$id].On = $false; $script:state[$id].Sel = 0 }
    $feat = $preset.features
    if ($feat -is [array]) {
        # Legacy pre-2026 export: Features was a bare ARRAY of policy key names,
        # not an object of key/value pairs. main carried an explicit branch for
        # this; without one, PSObject.Properties[$key] is $null for every row,
        # so the import staged nothing and still reported success - after having
        # already cleared the user's selections above.
        $names = @()
        foreach ($n in $feat) { $names += [string]$n }
        foreach ($row in Get-AllRows) {
            if ($names -notcontains $row.key) { continue }
            if ($script:state[$row.Id].On -or $script:state[$row.Id].Sel -gt 0) { continue }
            if (Test-IsChoiceRow $row) {
                for ($i = 1; $i -lt $row.choices.Count; $i++) {
                    if ([string]$row.choices[$i][1] -eq [string]$row.value) {
                        $script:state[$row.Id].Sel = $i; break
                    }
                }
            } else {
                # A bare key in the legacy format means "apply this row's own
                # declared value", which is what the row is ticked to write.
                $script:state[$row.Id].On = $true
            }
        }
        $feat = $null
    }
    foreach ($row in Get-AllRows) {
        if ($null -eq $feat) { continue }
        if ($null -eq $feat.PSObject.Properties[$row.key]) { continue }
        $want = $feat.$($row.key)
        if (Test-IsChoiceRow $row) {
            for ($i = 1; $i -lt $row.choices.Count; $i++) {
                if ([string]$row.choices[$i][1] -eq [string]$want) { $script:state[$row.Id].Sel = $i; break }
            }
        } elseif ($row.value -is [array]) {
            # Match the VALUE, not merely the key. Ticking on key presence alone
            # means an imported single-site exception such as
            # BraveShieldsDisabledForUrls = ["https://intranet.example"] stages
            # this row, and Apply then writes SlimBrave's own wildcard - turning
            # one site into the whole web.
            $wantList = @(); foreach ($x in @($want)) { $wantList += [string]$x }
            $mine = @();     foreach ($x in $row.value) { $mine += [string]$x }
            if ($wantList.Count -eq $mine.Count -and
                -not (Compare-Object $wantList $mine)) {
                $script:state[$row.Id].On = $true
            }
        } else {
            if ([string](ConvertTo-RegValue $want) -eq [string](ConvertTo-RegValue $row.value)) {
                $script:state[$row.Id].On = $true
            }
        }
    }
    $script:dnsState.Mode = 0
    $script:dnsState.Tmpl = ""
    if ($preset.dns) {
        $idx = [Array]::IndexOf($script:dnsModes, [string]$preset.dns)
        if ($idx -ge 0) { $script:dnsState.Mode = $idx }
    }
    if ($preset.tmpl) { $script:dnsState.Tmpl = [string]$preset.tmpl }
}
[System.Windows.Forms.Application]::EnableVisualStyles()

$F = @{
    Bg=[System.Drawing.Color]::FromArgb(32,32,32);      Rail=[System.Drawing.Color]::FromArgb(27,27,27)
    Row=[System.Drawing.Color]::FromArgb(45,45,45);     RowHot=[System.Drawing.Color]::FromArgb(51,51,51)
    RowEdge=[System.Drawing.Color]::FromArgb(56,56,56); RowTopHi=[System.Drawing.Color]::FromArgb(64,64,64)
    Text=[System.Drawing.Color]::FromArgb(255,255,255); TextSub=[System.Drawing.Color]::FromArgb(160,160,160)
    Accent=[System.Drawing.Color]::FromArgb(76,194,255);AccentDim=[System.Drawing.Color]::FromArgb(40,76,194,255)
    ThumbOn=[System.Drawing.Color]::FromArgb(27,27,27); ThumbOff=[System.Drawing.Color]::FromArgb(206,206,206)
    OutlineOff=[System.Drawing.Color]::FromArgb(154,154,154)
    NavHot=[System.Drawing.Color]::FromArgb(41,41,41);  NavSel=[System.Drawing.Color]::FromArgb(48,48,48)
    Bar=[System.Drawing.Color]::FromArgb(39,39,39)
}


# Segoe MDL2 Assets glyphs, one per nav page
$script:navGlyphs = @([char]0xE9D9, [char]0xE72E, [char]0xE71D, [char]0xE8D7,
                      [char]0xE734, [char]0xE83D, [char]0xE9D2)

# StringFormat that renders "&" literally instead of eating it as a mnemonic
$script:SF = New-Object System.Drawing.StringFormat
$script:SF.HotkeyPrefix = [System.Drawing.Text.HotkeyPrefix]::None
$script:SFw = New-Object System.Drawing.StringFormat
$script:SFw.HotkeyPrefix = [System.Drawing.Text.HotkeyPrefix]::None
$script:SFw.Trimming = [System.Drawing.StringTrimming]::Word

function Add-RoundedPath([System.Drawing.Drawing2D.GraphicsPath]$path,[System.Drawing.RectangleF]$r,[float]$rad){
    $d=$rad*2
    $path.AddArc($r.X,$r.Y,$d,$d,180,90); $path.AddArc($r.Right-$d,$r.Y,$d,$d,270,90)
    $path.AddArc($r.Right-$d,$r.Bottom-$d,$d,$d,0,90); $path.AddArc($r.X,$r.Bottom-$d,$d,$d,90,90)
    $path.CloseFigure()
}
function Enable-DoubleBuffer($c){
    $c.GetType().GetProperty("DoubleBuffered",[System.Reflection.BindingFlags]"Instance,NonPublic").SetValue($c,$true)
}
function Fill-Round([System.Drawing.Graphics]$g,[System.Drawing.RectangleF]$r,[float]$rad,[System.Drawing.Color]$c){
    $p=New-Object System.Drawing.Drawing2D.GraphicsPath; Add-RoundedPath $p $r $rad
    $b=New-Object System.Drawing.SolidBrush $c; $g.FillPath($b,$p); $b.Dispose(); $p.Dispose()
}
function Stroke-Round([System.Drawing.Graphics]$g,[System.Drawing.RectangleF]$r,[float]$rad,[System.Drawing.Color]$c){
    $p=New-Object System.Drawing.Drawing2D.GraphicsPath; Add-RoundedPath $p $r $rad
    $pen=New-Object System.Drawing.Pen $c; $g.DrawPath($pen,$p); $pen.Dispose(); $p.Dispose()
}

Add-Type -TypeDefinition @"
using System.Drawing;
using System.Windows.Forms;
public class DarkMenuColors : ProfessionalColorTable {
    public override Color ToolStripDropDownBackground { get { return Color.FromArgb(51,51,51); } }
    public override Color MenuBorder { get { return Color.FromArgb(70,70,70); } }
    public override Color MenuItemBorder { get { return Color.FromArgb(76,194,255); } }
    public override Color MenuItemSelected { get { return Color.FromArgb(62,62,62); } }
    public override Color MenuItemSelectedGradientBegin { get { return Color.FromArgb(62,62,62); } }
    public override Color MenuItemSelectedGradientEnd { get { return Color.FromArgb(62,62,62); } }
    public override Color ImageMarginGradientBegin { get { return Color.FromArgb(51,51,51); } }
    public override Color ImageMarginGradientMiddle { get { return Color.FromArgb(51,51,51); } }
    public override Color ImageMarginGradientEnd { get { return Color.FromArgb(51,51,51); } }
}
"@ -ReferencedAssemblies System.Drawing, System.Windows.Forms

$form = New-Object System.Windows.Forms.Form
$form.Text = "SlimBrave Neo - Fluent GUI (beta)"
$form.ClientSize = New-Object System.Drawing.Size 1180, 760
$form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedSingle
$form.MaximizeBox = $false
$form.BackColor = $F.Bg
Enable-DoubleBuffer $form

$script:titleFont=New-Object System.Drawing.Font "Segoe UI Semibold",16
$script:crumbFont=New-Object System.Drawing.Font "Segoe UI",9
$script:navFont  =New-Object System.Drawing.Font "Segoe UI",10
$script:rowFont  =New-Object System.Drawing.Font "Segoe UI",10
$script:capFont  =New-Object System.Drawing.Font "Segoe UI",8.5
$script:btnFont  =New-Object System.Drawing.Font "Segoe UI",9.5
$script:pTitle   =New-Object System.Drawing.Font "Segoe UI Semibold",11
try { $script:iconFont = New-Object System.Drawing.Font "Segoe MDL2 Assets",11 }
catch { $script:iconFont = New-Object System.Drawing.Font "Segoe UI",10 }
$script:chevFont = New-Object System.Drawing.Font "Segoe UI",9

# --------------------------------------------------------------- nav rail
$rail=New-Object System.Windows.Forms.Panel
$rail.Location=New-Object System.Drawing.Point 0,0
$rail.Size=New-Object System.Drawing.Size 250,760
$rail.BackColor=$F.Rail; Enable-DoubleBuffer $rail; $form.Controls.Add($rail)

$script:railTitleFont=New-Object System.Drawing.Font "Segoe UI Semibold",15
$script:railSubFont=New-Object System.Drawing.Font "Segoe UI",9

$railHead=New-Object System.Windows.Forms.Panel
$railHead.Location=New-Object System.Drawing.Point 0,14
$railHead.Size=New-Object System.Drawing.Size 250,60
$railHead.BackColor=$F.Rail
Enable-DoubleBuffer $railHead
$railHead.Add_Paint({
    param($s,$e); $g=$e.Graphics
    $g.SmoothingMode=[System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint=[System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit
    $g.Clear($script:F.Rail)
    # accent-tinted app tile with the shield glyph, the same language the nav
    # items use, so the header reads as part of the list rather than a banner
    $tile=New-Object System.Drawing.RectangleF 16,8,32,32
    Fill-Round $g $tile 8 $script:F.AccentDim
    $ib=New-Object System.Drawing.SolidBrush $script:F.Accent
    $glyphFont=New-Object System.Drawing.Font $script:iconFont.FontFamily,14
    $gl=[char]0xE72E
    $sz=$g.MeasureString($gl,$glyphFont,1000,$script:SF)
    $g.DrawString($gl,$glyphFont,$ib,(16+(32-$sz.Width)/2),(8+(32-$sz.Height)/2),$script:SF)
    $glyphFont.Dispose(); $ib.Dispose()
    $tb=New-Object System.Drawing.SolidBrush $script:F.Text
    $g.DrawString("SlimBrave Neo",$script:railTitleFont,$tb,58,6,$script:SF); $tb.Dispose()
    $sb=New-Object System.Drawing.SolidBrush $script:F.TextSub
    $g.DrawString("Policy manager",$script:railSubFont,$sb,60,31,$script:SF); $sb.Dispose()
})
$rail.Controls.Add($railHead)

# page 0 = Presets, 1..7 = categories, 8 = DNS
$script:pages=@("Quick Presets","All Options")
foreach($c in $script:cats){ $script:pages+=$c.name }
$script:pages+="DNS Over HTTPS"
$script:navItems=@(); $script:sel=0

function New-NavItem([int]$idx,[string]$name,[int]$y){
    $it=New-Object System.Windows.Forms.Panel
    $it.Location=New-Object System.Drawing.Point 8,$y
    $it.Size=New-Object System.Drawing.Size 234,36
    $it.BackColor=$F.Rail; $it.Tag=@{Idx=$idx;Name=$name;Hot=$false}
    Enable-DoubleBuffer $it
    $it.Add_Paint({
        param($s,$e); $g=$e.Graphics
        $g.SmoothingMode=[System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $st=$s.Tag; $g.Clear($script:F.Rail)
        $isSel=($st.Idx -eq $script:sel)
        if($isSel -or $st.Hot){
            $c=$script:F.NavHot; if($isSel){$c=$script:F.NavSel}
            Fill-Round $g (New-Object System.Drawing.RectangleF 0,0,($s.Width-1),($s.Height-1)) 5 $c
        }
        if($isSel){ $b=New-Object System.Drawing.SolidBrush $script:F.Accent
                    $g.FillRectangle($b,0,10,3,16); $b.Dispose() }
        $glyph=[char]0xE713
        if($st.Idx -eq 0){ $glyph=[char]0xE7BE }
        elseif($st.Idx -eq 1){ $glyph=[char]0xE8FD }
        elseif(($st.Idx-2) -lt $script:navGlyphs.Count){ $glyph=$script:navGlyphs[$st.Idx-2] }
        else { $glyph=[char]0xE968 }
        $ib=New-Object System.Drawing.SolidBrush $script:F.Accent
        $g.DrawString($glyph,$script:iconFont,$ib,14,8,$script:SF); $ib.Dispose()
        $ink=$script:F.TextSub; if($isSel){$ink=$script:F.Text}
        $nb=New-Object System.Drawing.SolidBrush $ink
        $g.DrawString($st.Name,$script:navFont,$nb,44,9,$script:SF); $nb.Dispose()
    })
    $it.Add_MouseEnter({$this.Tag.Hot=$true;$this.Invalidate()})
    $it.Add_MouseLeave({$this.Tag.Hot=$false;$this.Invalidate()})
    $it.Add_Click({
        if($script:searchBox -and $script:searchBox.Text){ $script:searchBox.Text="" }
        Select-Page $this.Tag.Idx
    })
    $it.Cursor=[System.Windows.Forms.Cursors]::Hand
    $rail.Controls.Add($it); return $it
}
$yy=88
for($i=0;$i -lt $script:pages.Count;$i++){
    $script:navItems+=(New-NavItem $i $script:pages[$i] $yy); $yy+=40
}

# --------------------------------------------------------------- header
$crumb=New-Object System.Windows.Forms.Label
$crumb.Font=$script:crumbFont; $crumb.ForeColor=$F.TextSub; $crumb.BackColor=$F.Bg
$crumb.Location=New-Object System.Drawing.Point 282,18; $crumb.AutoSize=$true
$crumb.UseMnemonic=$false; $form.Controls.Add($crumb)

$pageTitle=New-Object System.Windows.Forms.Label
$pageTitle.Font=$script:titleFont; $pageTitle.ForeColor=$F.Text; $pageTitle.BackColor=$F.Bg
$pageTitle.Location=New-Object System.Drawing.Point 280,38; $pageTitle.AutoSize=$true
$pageTitle.UseMnemonic=$false; $form.Controls.Add($pageTitle)

# Search box. Sits in the header so it is reachable from any page, not just
# All Options - a policy you cannot name is exactly the one you need to find.
$searchHost=New-Object System.Windows.Forms.Panel
$searchHost.Location=New-Object System.Drawing.Point 880,34
$searchHost.Size=New-Object System.Drawing.Size 272,32
$searchHost.BackColor=$F.Bg
Enable-DoubleBuffer $searchHost
$searchHost.Add_Paint({
    param($s,$e); $g=$e.Graphics
    $g.SmoothingMode=[System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.Clear($script:F.Bg)
    $r=New-Object System.Drawing.RectangleF 0,0,($s.Width-1),($s.Height-1)
    Fill-Round $g $r 4 $script:F.Row
    $edge=$script:F.RowEdge
    if($script:searchBox -and $script:searchBox.Focused){ $edge=$script:F.Accent }
    Stroke-Round $g $r 4 $edge
    $ib=New-Object System.Drawing.SolidBrush $script:F.TextSub
    $gl=[char]0xE721
    $g.DrawString($gl,$script:iconFont,$ib,9,7,$script:SF); $ib.Dispose()
    if(-not $script:searchBox -or [string]::IsNullOrEmpty($script:searchBox.Text)){
        $pb=New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(110,110,110))
        $g.DrawString("Search policies and descriptions",$script:capFont,$pb,34,9,$script:SF)
        $pb.Dispose()
    }
})
$form.Controls.Add($searchHost)

$script:searchBox=New-Object System.Windows.Forms.TextBox
$script:searchBox.BorderStyle=[System.Windows.Forms.BorderStyle]::None
$script:searchBox.Font=$script:rowFont
$script:searchBox.BackColor=$F.Row
$script:searchBox.ForeColor=$F.Text
$script:searchBox.Location=New-Object System.Drawing.Point 34,8
$script:searchBox.Size=New-Object System.Drawing.Size 228,20
$searchHost.Controls.Add($script:searchBox)
$script:searchBox.Add_GotFocus({ $searchHost.Invalidate() })
$script:searchBox.Add_LostFocus({ $searchHost.Invalidate() })

$page=New-Object System.Windows.Forms.Panel
$page.Location=New-Object System.Drawing.Point 270,80
$page.Size=New-Object System.Drawing.Size 900,608
$page.BackColor=$F.Bg; $page.AutoScroll=$true
Enable-DoubleBuffer $page; $form.Controls.Add($page)

# --------------------------------------------------------------- action bar
$bar=New-Object System.Windows.Forms.Panel
$bar.Location=New-Object System.Drawing.Point 250,692
$bar.Size=New-Object System.Drawing.Size 930,68
$bar.BackColor=$F.Bar; Enable-DoubleBuffer $bar; $form.Controls.Add($bar)
$script:statusText="Ready"
$bar.Add_Paint({
    param($s,$e); $g=$e.Graphics
    $p=New-Object System.Drawing.Pen $script:F.RowEdge
    $g.DrawLine($p,0,0,$s.Width,0); $p.Dispose()
    $b=New-Object System.Drawing.SolidBrush $script:F.TextSub
    $g.DrawString($script:statusText,$script:capFont,$b,20,26,$script:SF); $b.Dispose()
})
function Set-Status([string]$t){ $script:statusText=$t; $bar.Invalidate() }

function New-BarButton([string]$label,[bool]$accent,[int]$x){
    $b=New-Object System.Windows.Forms.Panel
    $w=[int]([System.Windows.Forms.TextRenderer]::MeasureText($label,$script:btnFont).Width+34)
    $b.Location=New-Object System.Drawing.Point $x,18
    $b.Size=New-Object System.Drawing.Size $w,32
    $b.BackColor=$F.Bar; $b.Tag=@{L=$label;A=$accent;Hot=$false}
    Enable-DoubleBuffer $b
    $b.Add_Paint({
        param($s,$e); $g=$e.Graphics
        $g.SmoothingMode=[System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $g.Clear($script:F.Bar)
        $r=New-Object System.Drawing.RectangleF 0,0,($s.Width-1),($s.Height-1)
        if($s.Tag.A){
            $c=$script:F.Accent; if($s.Tag.Hot){$c=[System.Drawing.Color]::FromArgb(96,205,255)}
            Fill-Round $g $r 4 $c; $ink=[System.Drawing.Color]::FromArgb(27,27,27)
        } else {
            $c=$script:F.Row; if($s.Tag.Hot){$c=$script:F.RowHot}
            Fill-Round $g $r 4 $c; Stroke-Round $g $r 4 $script:F.RowEdge; $ink=$script:F.Text
        }
        $tb=New-Object System.Drawing.SolidBrush $ink
        $sz=$g.MeasureString($s.Tag.L,$script:btnFont,1000,$script:SF)
        $g.DrawString($s.Tag.L,$script:btnFont,$tb,(($s.Width-$sz.Width)/2),(($s.Height-$sz.Height)/2),$script:SF)
        $tb.Dispose()
    })
    $b.Add_MouseEnter({$this.Tag.Hot=$true;$this.Invalidate()})
    $b.Add_MouseLeave({$this.Tag.Hot=$false;$this.Invalidate()})
    $b.Add_Click({
        switch($this.Tag.L){
            "Apply Settings" { if(Invoke-ApplyPolicy){ Select-Page $script:sel } }
            "Reset" {
                $ans=[System.Windows.Forms.MessageBox]::Show(
                    "Remove every policy SlimBrave Neo manages? Policies set by group policy or another tool are left alone.",
                    "Confirm reset",[System.Windows.Forms.MessageBoxButtons]::YesNo,
                    [System.Windows.Forms.MessageBoxIcon]::Warning)
                if($ans -eq "Yes"){ if(Invoke-ResetPolicy){ Select-Page $script:sel } }
            }
            "Re-sync" { Sync-FromRegistry; Select-Page $script:sel }
            "Export" {
                $dlg=New-Object System.Windows.Forms.SaveFileDialog
                $dlg.Filter="JSON files (*.json)|*.json"
                $dlg.FileName="SlimBraveNeoSettings.json"
                if($dlg.ShowDialog() -eq "OK"){
                    $feat=@{}
                    foreach($row in Get-AllRows){
                        $v=Get-RowPolicyValue $row
                        if($null -ne $v){ $feat[$row.key]=$v }
                    }
                    $out=@{Features=$feat}
                    $m=$script:dnsModes[$script:dnsState.Mode]
                    if($m -ne "unmanaged"){
                        $out.DnsMode=$m
                        if($script:dnsState.Tmpl){ $out.DnsTemplates=$script:dnsState.Tmpl }
                    }
                    # Set-Content failure is NON-terminating, so without this
                    # the success status ran even when nothing was written -
                    # a locked, read-only or full target reported "Exported".
                    try{
                        [System.IO.File]::WriteAllText($dlg.FileName,
                            ($out | ConvertTo-Json -Depth 5),
                            (New-Object System.Text.UTF8Encoding $false))
                        Set-Status "Exported $($feat.Count) policies"
                    } catch {
                        Set-Status "Export failed - $($_.Exception.Message)"
                    }
                }
            }
            "Import" {
                $dlg=New-Object System.Windows.Forms.OpenFileDialog
                $dlg.Filter="JSON files (*.json)|*.json"
                if($dlg.ShowDialog() -eq "OK"){
                    try{
                        $cfg=Get-Content $dlg.FileName -Raw | ConvertFrom-Json
                        Import-PresetIntoState @{features=$cfg.Features;dns=$cfg.DnsMode;tmpl=$cfg.DnsTemplates}
                        Select-Page $script:sel
                        Set-Status "Imported from $([System.IO.Path]::GetFileName($dlg.FileName))"
                    } catch { Set-Status "Import failed - not a SlimBrave config" }
                }
            }
        }
    })
    $b.Cursor=[System.Windows.Forms.Cursors]::Hand
    $bar.Controls.Add($b); return $b
}
$bx=430
foreach($spec in @(@("Export",$false),@("Import",$false),@("Re-sync",$false),@("Reset",$false),@("Apply Settings",$true))){
    $btn=New-BarButton $spec[0] $spec[1] $bx; $bx+=$btn.Width+8
}

# --------------------------------------------------------------- rows
$script:rowPanels=@()
$script:COLLAPSED=64
$script:EXP_X=690        # chevron column on toggle rows
$script:EXP_X_CHOICE=596 # chevron column on dropdown rows
$script:DD_X=640         # dropdown control left edge
$script:DD_W=180         # dropdown control width
$script:TG_X=768         # toggle pill left edge
$script:TG_Y=22          # toggle pill top
$script:TG_W=44
$script:TG_H=20
$script:TG_PAD=10        # generous hit padding around the pill

function Get-CapWidth($isChoice){
    # room a caption has before it reaches that row type's chevron column.
    # Choice rows lose ~100px to the dropdown, so a fixed character count
    # cannot serve both - it either wastes space on toggles or overruns
    # into the dropdown on permissions rows.
    if($isChoice){ return ($script:EXP_X_CHOICE-34) }
    return ($script:EXP_X-34)
}

function Fit-Text([System.Drawing.Graphics]$g,[string]$text,[System.Drawing.Font]$font,[int]$w){
    if($g.MeasureString($text,$font,10000,$script:SF).Width -le $w){ return $text }
    $lo=0; $hi=$text.Length
    while($lo -lt $hi){
        $mid=[int](($lo+$hi+1)/2)
        $try=$text.Substring(0,$mid)+"..."
        if($g.MeasureString($try,$font,10000,$script:SF).Width -le $w){ $lo=$mid } else { $hi=$mid-1 }
    }
    return $text.Substring(0,$lo)+"..."
}

function Zone-Of($panel,[int]$x,[int]$y){
    $st=$panel.Tag
    $ecol=$script:EXP_X; if($st.IsChoice){ $ecol=$script:EXP_X_CHOICE }
    $g2=$panel.CreateGraphics()
    $hasExp = ($st.Row.full -and ($st.Row.full -ne $st.Row.short -or
        $g2.MeasureString($st.Row.short,$script:capFont,10000,$script:SF).Width -gt (Get-CapWidth $st.IsChoice)))
    $g2.Dispose()
    if($hasExp -and $x -ge $ecol -and $x -le ($ecol+26) -and $y -ge 14 -and $y -le 50){ return "exp" }
    if($st.IsChoice){
        # bounded exactly like the toggle: clicking a label or empty space
        # must do nothing on BOTH row types. Only the control is live.
        $dl=$script:DD_X-$script:TG_PAD; $dr2=$script:DD_X+$script:DD_W+$script:TG_PAD
        if($x -ge $dl -and $x -le $dr2 -and $y -ge (17-$script:TG_PAD) -and $y -le (47+$script:TG_PAD)){ return "ctl" }
        return ""
    }
    $l=$script:TG_X-$script:TG_PAD; $r=$script:TG_X+$script:TG_W+$script:TG_PAD
    $tp=$script:TG_Y-$script:TG_PAD;  $b=$script:TG_Y+$script:TG_H+$script:TG_PAD
    if($x -ge $l -and $x -le $r -and $y -ge $tp -and $y -le $b){ return "ctl" }
    return ""
}

function New-FluentRow($row,[int]$y){
    $p=New-Object System.Windows.Forms.Panel
    $p.Location=New-Object System.Drawing.Point 2,$y
    $p.Size=New-Object System.Drawing.Size 840,$script:COLLAPSED
    $p.BackColor=$F.Bg
    $isChoice=($null -ne $row.PSObject.Properties['choices'])
    $p.Tag=@{Row=$row;Hot=$false;IsChoice=$isChoice;Open=$false;Zone=''}
    Enable-DoubleBuffer $p
    $p.Add_Paint({
        param($s,$e); $g=$e.Graphics
        $g.SmoothingMode=[System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $g.TextRenderingHint=[System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit
        $st=$s.Tag; $g.Clear($script:F.Bg)
        $r=New-Object System.Drawing.RectangleF 0,0,($s.Width-1),($s.Height-2)
        $c=$script:F.Row; if($st.Hot){$c=$script:F.RowHot}
        Fill-Round $g $r 6 $c; Stroke-Round $g $r 6 $script:F.RowEdge
        $hi=New-Object System.Drawing.Pen $script:F.RowTopHi
        $g.DrawLine($hi,7,1,($s.Width-8),1); $hi.Dispose()
        $tb=New-Object System.Drawing.SolidBrush $script:F.Text
        $g.DrawString($st.Row.name,$script:rowFont,$tb,18,11,$script:SF); $tb.Dispose()
        $cb=New-Object System.Drawing.SolidBrush $script:F.TextSub
        if($st.Open){
            $wcol=$script:EXP_X; if($st.IsChoice){ $wcol=$script:EXP_X_CHOICE }
            $rect=New-Object System.Drawing.RectangleF 18,33,($wcol-30),($s.Height-42)
            $g.DrawString($st.Row.full,$script:capFont,$cb,$rect,$script:SFw)
        } else {
            $avail=Get-CapWidth $st.IsChoice
            $short=Fit-Text $g $st.Row.short $script:capFont $avail
            $g.DrawString($short,$script:capFont,$cb,18,34,$script:SF)
        }
        $cb.Dispose()
        # expander chevron, only when there is more to show
        $avail2=Get-CapWidth $st.IsChoice
        $truncated=($g.MeasureString($st.Row.short,$script:capFont,10000,$script:SF).Width -gt $avail2)
        if($st.Row.full -and ($st.Row.full -ne $st.Row.short -or $truncated)){
            $ecol=$script:EXP_X; if($st.IsChoice){ $ecol=$script:EXP_X_CHOICE }
            $ex=New-Object System.Drawing.RectangleF $ecol,18,26,26
            if($st.Zone -eq "exp"){ Fill-Round $g $ex 4 $script:F.RowTopHi }
            $cp=New-Object System.Drawing.Pen $script:F.TextSub,1.7
            $cx=($ecol+6); $cy=29
            if($st.Open){
                $g.DrawLines($cp,[System.Drawing.PointF[]]@(
                    [System.Drawing.PointF]::new($cx,($cy+4)),
                    [System.Drawing.PointF]::new(($cx+7),($cy-2)),
                    [System.Drawing.PointF]::new(($cx+14),($cy+4))))
            } else {
                $g.DrawLines($cp,[System.Drawing.PointF[]]@(
                    [System.Drawing.PointF]::new($cx,($cy-2)),
                    [System.Drawing.PointF]::new(($cx+7),($cy+4)),
                    [System.Drawing.PointF]::new(($cx+14),($cy-2))))
            }
            $cp.Dispose()
        }
        if($st.IsChoice){
            # owner-drawn dropdown: a stock ComboBox paints a light arrow
            # button that no dark theme can reach, so draw the whole control
            # and open a themed menu on click.
            $dr=New-Object System.Drawing.RectangleF $script:DD_X,17,$script:DD_W,30
            $managed=($script:state[$st.Row.Id].Sel -gt 0)
            $bg=$script:F.RowHot; if($managed){ $bg=$script:F.AccentDim }
            if($st.Zone -eq "ctl"){ $bg=$script:F.RowTopHi; if($managed){ $bg=[System.Drawing.Color]::FromArgb(70,76,194,255) } }
            Fill-Round $g $dr 4 $bg
            $edge=$script:F.RowEdge; if($managed){ $edge=$script:F.Accent }
            Stroke-Round $g $dr 4 $edge
            $ink=$script:F.Text; if($managed){ $ink=$script:F.Accent }
            $vb=New-Object System.Drawing.SolidBrush $ink
            $g.DrawString($st.Row.choices[$script:state[$st.Row.Id].Sel][0],$script:rowFont,$vb,($dr.X+12),($dr.Y+6),$script:SF)
            $vb.Dispose()
            $ch=New-Object System.Drawing.Pen $ink,1.6
            $cx2=$dr.Right-24; $cy2=$dr.Y+13
            $g.DrawLines($ch,[System.Drawing.PointF[]]@(
                [System.Drawing.PointF]::new($cx2,$cy2),
                [System.Drawing.PointF]::new(($cx2+5),($cy2+5)),
                [System.Drawing.PointF]::new(($cx2+10),$cy2)))
            $ch.Dispose()
        } else {
            $word="Off"; if($script:state[$st.Row.Id].On){$word="On"}
            $wb=New-Object System.Drawing.SolidBrush $script:F.TextSub
            $g.DrawString($word,$script:rowFont,$wb,726,21,$script:SF); $wb.Dispose()
            $tx=$script:TG_X;$ty=$script:TG_Y
            if($st.Zone -eq "ctl"){
                $halo=New-Object System.Drawing.RectangleF ($tx-6),($ty-6),($script:TG_W+12),($script:TG_H+12)
                Fill-Round $g $halo 15 $script:F.RowTopHi
            }
            $track=New-Object System.Drawing.RectangleF $tx,$ty,$script:TG_W,$script:TG_H
            if($script:state[$st.Row.Id].On){
                Fill-Round $g $track 10 $script:F.Accent
                $th=New-Object System.Drawing.SolidBrush $script:F.ThumbOn
                $g.FillEllipse($th,($tx+26),($ty+3),14,14); $th.Dispose()
            } else {
                Stroke-Round $g $track 10 $script:F.OutlineOff
                $th=New-Object System.Drawing.SolidBrush $script:F.ThumbOff
                $g.FillEllipse($th,($tx+4),($ty+3),14,14); $th.Dispose()
            }
        }
    })
    $p.Add_MouseDown({
        param($s,$ev)
        $st=$s.Tag
        $ecol=$script:EXP_X; if($st.IsChoice){ $ecol=$script:EXP_X_CHOICE }
        if($ev.X -ge $ecol -and $ev.X -le ($ecol+26) -and $ev.Y -le 50){
            $st.Open=-not $st.Open
            if($st.Open){
                $g=$s.CreateGraphics()
                $wc=$script:EXP_X; if($st.IsChoice){ $wc=$script:EXP_X_CHOICE }
                $sz=$g.MeasureString($st.Row.full,$script:capFont,($wc-30),$script:SFw)
                $g.Dispose()
                $s.Height=[Math]::Max($script:COLLAPSED,[int]($sz.Height+46))
            } else { $s.Height=$script:COLLAPSED }
            Reflow-Page
            $s.Invalidate(); return
        }
        if($st.IsChoice){
            if((Zone-Of $s $ev.X $ev.Y) -eq "ctl"){
                $menu=New-Object System.Windows.Forms.ContextMenuStrip
                $menu.BackColor=$script:F.RowHot
                $menu.ForeColor=$script:F.Text
                $menu.Font=$script:rowFont
                $menu.ShowImageMargin=$false
                $menu.Renderer=New-Object System.Windows.Forms.ToolStripProfessionalRenderer(
                    (New-Object DarkMenuColors))
                $i=0
                foreach($c in $st.Row.choices){
                    $mi=$menu.Items.Add($c[0])
                    $mi.Tag=@{Row=$s;Idx=$i}
                    if($i -eq $script:state[$st.Row.Id].Sel){ $mi.ForeColor=$script:F.Accent }
                    $mi.Add_Click({
                        $d=$this.Tag
                        $script:state[$d.Row.Tag.Row.Id].Sel=$d.Idx
                        $d.Row.Invalidate()
                    })
                    $i++
                }
                $menu.Show($s,(New-Object System.Drawing.Point $script:DD_X,47))
            }
            return
        }
        else {
            # toggles fire ONLY inside the pill (plus padding). Clicking a
            # label should never silently flip a machine-wide policy.
            if((Zone-Of $s $ev.X $ev.Y) -ne "ctl"){ return }
            $script:state[$st.Row.Id].On = -not $script:state[$st.Row.Id].On
            if($script:state[$st.Row.Id].On -and $st.Row.group){
                # exclusivity applies to the MODEL, so it holds for group
                # members that are not currently rendered on this page
                foreach($other in Get-AllRows){
                    if($other.Id -ne $st.Row.Id -and $other.group -eq $st.Row.group){
                        $script:state[$other.Id].On=$false
                    }
                }
                foreach($o in $script:rowPanels){ $o.Invalidate() }
            }
        }
        $s.Invalidate()
    })
    $p.Add_MouseEnter({$this.Tag.Hot=$true;$this.Invalidate()})
    $p.Add_MouseLeave({
        $this.Tag.Hot=$false; $this.Tag.Zone=""
        $this.Cursor=[System.Windows.Forms.Cursors]::Default
        $this.Invalidate()
    })
    $p.Add_MouseMove({
        param($s,$ev)
        $z=Zone-Of $s $ev.X $ev.Y
        if($z -ne $s.Tag.Zone){
            $s.Tag.Zone=$z
            if($z -eq ""){ $s.Cursor=[System.Windows.Forms.Cursors]::Default }
            else { $s.Cursor=[System.Windows.Forms.Cursors]::Hand }
            $s.Invalidate()
        }
    })

    return $p
}

function Reflow-Page {
    # AutoScroll makes child Location live in SCROLLED coordinates, and the
    # AutoScrollPosition getter returns negatives while the setter takes
    # positives. Repositioning with raw offsets while scrolled throws every
    # row out of place and leaves dead space above. So: park the scroll at
    # zero, lay out in unscrolled space, then put the scroll back.
    $keep=[Math]::Abs($page.AutoScrollPosition.Y)
    $page.SuspendLayout()
    $page.AutoScrollPosition=New-Object System.Drawing.Point 0,0
    $y=4
    foreach($p in $script:rowPanels){
        $p.Location=New-Object System.Drawing.Point 2,$y
        $y+=$p.Height+4
        if($null -ne $p.Tag.T){ $y+=6 }   # extra air under a section header
    }
    $page.ResumeLayout()
    $page.AutoScrollPosition=New-Object System.Drawing.Point 0,$keep
    # Setting AutoScrollPosition scrolls by blitting, so the region the moved
    # children used to occupy is never invalidated and their old pixels stay
    # on screen as ghosts. Repaint the whole page, children included.
    $page.Invalidate($true)
    $page.Update()
}

function New-SectionHeader([string]$text,[int]$y,[int]$count){
    $h=New-Object System.Windows.Forms.Panel
    $h.Location=New-Object System.Drawing.Point 2,$y
    $h.Size=New-Object System.Drawing.Size 840,38
    $h.BackColor=$F.Bg; $h.Tag=@{T=$text;N=$count}
    Enable-DoubleBuffer $h
    $h.Add_Paint({
        param($s,$e); $g=$e.Graphics
        $g.SmoothingMode=[System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $g.Clear($script:F.Bg)
        $tb=New-Object System.Drawing.SolidBrush $script:F.Text
        $g.DrawString($s.Tag.T,$script:pTitle,$tb,4,12,$script:SF); $tb.Dispose()
        $w=[int]($g.MeasureString($s.Tag.T,$script:pTitle,1000,$script:SF).Width)
        $cb=New-Object System.Drawing.SolidBrush $script:F.TextSub
        if($s.Tag.N -gt 0){ $g.DrawString("$($s.Tag.N)",$script:capFont,$cb,($w+12),16,$script:SF) }
        $cb.Dispose()
        $p=New-Object System.Drawing.Pen $script:F.RowEdge
        $g.DrawLine($p,($w+34),24,835,24); $p.Dispose()
    })
    return $h
}

# --------------------------------------------------------------- preset cards
function New-PresetCard($preset,[int]$y){
    $p=New-Object System.Windows.Forms.Panel
    $p.Location=New-Object System.Drawing.Point 2,$y
    $p.Size=New-Object System.Drawing.Size 840,78
    $p.BackColor=$F.Bg; $p.Tag=@{P=$preset;Hot=$false}
    Enable-DoubleBuffer $p
    $p.Add_Paint({
        param($s,$e); $g=$e.Graphics
        $g.SmoothingMode=[System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $st=$s.Tag; $g.Clear($script:F.Bg)
        $r=New-Object System.Drawing.RectangleF 0,0,($s.Width-1),($s.Height-2)
        $c=$script:F.Row; if($st.Hot){$c=$script:F.RowHot}
        Fill-Round $g $r 6 $c; Stroke-Round $g $r 6 $script:F.RowEdge
        $hi=New-Object System.Drawing.Pen $script:F.RowTopHi
        $g.DrawLine($hi,7,1,($s.Width-8),1); $hi.Dispose()
        $tb=New-Object System.Drawing.SolidBrush $script:F.Text
        $g.DrawString($st.P.name,$script:pTitle,$tb,18,14,$script:SF); $tb.Dispose()
        $cb=New-Object System.Drawing.SolidBrush $script:F.TextSub
        $g.DrawString($st.P.blurb,$script:capFont,$cb,18,40,$script:SF)
        $g.DrawString("$($st.P.count) policies",$script:capFont,$cb,18,56,$script:SF); $cb.Dispose()
        $bw=$script:PC_BW
        $br=New-Object System.Drawing.RectangleF $script:PC_BX,$script:PC_BY,$bw,$script:PC_BH
        $bg=$script:F.RowHot; if($st.Hot){$bg=$script:F.Accent}
        Fill-Round $g $br 4 $bg
        if(-not $st.Hot){ Stroke-Round $g $br 4 $script:F.RowEdge }
        $ink=$script:F.Text; if($st.Hot){$ink=[System.Drawing.Color]::FromArgb(27,27,27)}
        $lb=New-Object System.Drawing.SolidBrush $ink
        $sz=$g.MeasureString("Load",$script:btnFont,1000,$script:SF)
        $g.DrawString("Load",$script:btnFont,$lb,($br.X+($bw-$sz.Width)/2),($br.Y+7),$script:SF); $lb.Dispose()
    })
    # Same zone discipline as the setting rows: loading a preset DISCARDS every
    # staged selection, so a stray click on the blurb the user is reading must
    # not do it. Only the drawn Load button responds, and only it lights up.
    $p.Add_MouseMove({
        param($s,$ev)
        $over=(Test-InPresetButton $ev.X $ev.Y)
        if($s.Tag.Hot -ne $over){ $s.Tag.Hot=$over; $s.Invalidate() }
        if($over){ $s.Cursor=[System.Windows.Forms.Cursors]::Hand }
        else     { $s.Cursor=[System.Windows.Forms.Cursors]::Default }
    })
    $p.Add_MouseLeave({$this.Tag.Hot=$false;$this.Invalidate()})
    $p.Add_MouseDown({
        param($s,$ev)
        if(-not (Test-InPresetButton $ev.X $ev.Y)){ return }
        Import-PresetIntoState $s.Tag.P
        Select-Page $script:sel
        Set-Status "$($s.Tag.P.name) loaded - $($s.Tag.P.count) policies staged. Nothing is written until Apply."
    })
    return $p
}

# Shared by New-PresetCard's Paint and its hit-testing. Kept as constants for
# the same reason the row control columns are: when the drawn rect and the
# clickable rect were computed separately, they drifted apart.
$script:PC_BX = 705
$script:PC_BY = 24
$script:PC_BW = 110
$script:PC_BH = 32
function Test-InPresetButton($x, $y) {
    return ($x -ge $script:PC_BX -and $x -le ($script:PC_BX + $script:PC_BW) -and
            $y -ge $script:PC_BY -and $y -le ($script:PC_BY + $script:PC_BH))
}

# --------------------------------------------------------------- DNS page
# Script scope on purpose: the Leave handler fires long after Build-DnsPage
# has returned, and a nested function is out of scope by then - every blur of
# the template box threw CommandNotFoundException.
$script:tmplHint = "https://dns.example/dns-query"
function Sync-TmplHint($box){
    if($box.Focused){ return }
    if([string]::IsNullOrEmpty($box.Tag)){
        $box.ForeColor=[System.Drawing.Color]::FromArgb(96,96,96)
        $box.Text=$script:tmplHint
    }
}

function Build-DnsPage {
    $card=New-Object System.Windows.Forms.Panel
    $card.Location=New-Object System.Drawing.Point 2,4
    $card.Size=New-Object System.Drawing.Size 840,150
    $card.BackColor=$F.Bg
    $card.Tag=@{Zone=""}
    Enable-DoubleBuffer $card
    $card.Add_Paint({
        param($s,$e); $g=$e.Graphics
        $g.SmoothingMode=[System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $g.TextRenderingHint=[System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit
        $st=$s.Tag
        $g.Clear($script:F.Bg)
        $r=New-Object System.Drawing.RectangleF 0,0,($s.Width-1),($s.Height-2)
        Fill-Round $g $r 6 $script:F.Row; Stroke-Round $g $r 6 $script:F.RowEdge
        $hi=New-Object System.Drawing.Pen $script:F.RowTopHi
        $g.DrawLine($hi,7,1,($s.Width-8),1); $hi.Dispose()
        $tb=New-Object System.Drawing.SolidBrush $script:F.Text
        $g.DrawString("DNS over HTTPS mode",$script:rowFont,$tb,18,18,$script:SF)
        $g.DrawString("Custom template URL",$script:rowFont,$tb,18,92,$script:SF); $tb.Dispose()
        $cb=New-Object System.Drawing.SolidBrush $script:F.TextSub
        $g.DrawString("unmanaged writes no DNS policy, leaving Brave's own setting alone",$script:capFont,$cb,18,40,$script:SF)
        $needs=($script:dnsModes[$script:dnsState.Mode] -eq "custom" -or $script:dnsModes[$script:dnsState.Mode] -eq "secure")
        $note="Only used by the custom and secure modes"
        if($needs){ $note="Required - secure DNS with no template resolves nothing" }
        $g.DrawString($note,$script:capFont,$cb,18,114,$script:SF); $cb.Dispose()

        # mode dropdown, same column and bounds rule as every other row
        $dr=New-Object System.Drawing.RectangleF $script:DD_X,16,$script:DD_W,30
        $managed=($script:dnsState.Mode -gt 0)
        $bg=$script:F.RowHot; if($managed){ $bg=$script:F.AccentDim }
        if($st.Zone -eq "ctl"){ $bg=$script:F.RowTopHi; if($managed){ $bg=[System.Drawing.Color]::FromArgb(70,76,194,255) } }
        Fill-Round $g $dr 4 $bg
        $edge=$script:F.RowEdge; if($managed){ $edge=$script:F.Accent }
        Stroke-Round $g $dr 4 $edge
        $ink=$script:F.Text; if($managed){ $ink=$script:F.Accent }
        $vb=New-Object System.Drawing.SolidBrush $ink
        $g.DrawString($script:dnsModes[$script:dnsState.Mode],$script:rowFont,$vb,($dr.X+12),($dr.Y+6),$script:SF); $vb.Dispose()
        $ch=New-Object System.Drawing.Pen $ink,1.6
        $cx=$dr.Right-24; $cy=$dr.Y+13
        $g.DrawLines($ch,[System.Drawing.PointF[]]@(
            [System.Drawing.PointF]::new($cx,$cy),
            [System.Drawing.PointF]::new(($cx+5),($cy+5)),
            [System.Drawing.PointF]::new(($cx+10),$cy)))
        $ch.Dispose()

        # the template field is a real TextBox child; just draw its frame
        $well=New-Object System.Drawing.RectangleF ($script:DD_X-1),89,($script:DD_W+2),28
        $wedge=$script:F.RowEdge; if($needs){ $wedge=$script:F.Accent }
        Stroke-Round $g $well 4 $wedge
    })
    $tmpl=New-Object System.Windows.Forms.TextBox
    $tmpl.BorderStyle=[System.Windows.Forms.BorderStyle]::None
    $tmpl.Font=$script:rowFont
    $tmpl.BackColor=[System.Drawing.Color]::FromArgb(38,38,38)
    $tmpl.ForeColor=$F.Text
    $tmpl.Location=New-Object System.Drawing.Point ($script:DD_X+8),96
    $tmpl.Size=New-Object System.Drawing.Size ($script:DD_W-16),20
    $tmpl.Text=""
    $card.Controls.Add($tmpl)
    $card.Tag.Tmpl=$tmpl

    # .NET Framework has no PlaceholderText, so fake one: grey hint while the
    # box is empty and unfocused, cleared the moment the user types.
    $tmpl.Tag=""
    $tmpl.Add_Enter({
        if([string]::IsNullOrEmpty($this.Tag)){ $this.Text="" }
        $this.ForeColor=$script:F.Text
    })
    $tmpl.Add_Leave({
        $this.Tag=$this.Text
        Sync-TmplHint $this
    })
    $tmpl.Add_TextChanged({
        if($this.Focused){ $this.Tag=$this.Text }
    })
    Sync-TmplHint $tmpl

    $card.Add_MouseMove({
        param($s,$ev)
        $z=""
        $dl=$script:DD_X-$script:TG_PAD; $dr2=$script:DD_X+$script:DD_W+$script:TG_PAD
        if($ev.X -ge $dl -and $ev.X -le $dr2 -and $ev.Y -ge 6 -and $ev.Y -le 56){ $z="ctl" }
        if($z -ne $s.Tag.Zone){
            $s.Tag.Zone=$z
            if($z -eq ""){ $s.Cursor=[System.Windows.Forms.Cursors]::Default }
            else { $s.Cursor=[System.Windows.Forms.Cursors]::Hand }
            $s.Invalidate()
        }
    })
    $card.Add_MouseLeave({
        $this.Tag.Zone=""; $this.Cursor=[System.Windows.Forms.Cursors]::Default; $this.Invalidate()
    })
    $card.Add_MouseDown({
        param($s,$ev)
        # bounded exactly like every other control: label clicks do nothing
        if($s.Tag.Zone -ne "ctl"){ return }
        $menu=New-Object System.Windows.Forms.ContextMenuStrip
        $menu.BackColor=$script:F.RowHot
        $menu.ForeColor=$script:F.Text
        $menu.Font=$script:rowFont
        $menu.ShowImageMargin=$false
        $menu.Renderer=New-Object System.Windows.Forms.ToolStripProfessionalRenderer((New-Object DarkMenuColors))
        $i=0
        foreach($m in $script:dnsModes){
            $mi=$menu.Items.Add($m)
            $mi.Tag=@{Card=$s;Idx=$i}
            if($i -eq $script:dnsState.Mode){ $mi.ForeColor=$script:F.Accent }
            $mi.Add_Click({
                $d=$this.Tag
                $script:dnsState.Mode=$d.Idx
                $m=$script:dnsModes[$d.Idx]
                $box=$d.Card.Tag.Tmpl
                $box.Enabled=($m -eq "custom" -or $m -eq "secure")
                if(-not $box.Enabled){ $box.ForeColor=[System.Drawing.Color]::FromArgb(96,96,96) }
                elseif(-not [string]::IsNullOrEmpty($box.Tag)){ $box.ForeColor=$script:F.Text }
                Set-Status "DNS mode: $m (prototype)"
                $d.Card.Invalidate()
            })
            $i++
        }
        $menu.Show($s,(New-Object System.Drawing.Point $script:DD_X,46))
    })
    $m0=$script:dnsModes[$script:dnsState.Mode]
    $tmpl.Enabled=($m0 -eq "custom" -or $m0 -eq "secure")
    if($script:dnsState.Tmpl){ $tmpl.Tag=$script:dnsState.Tmpl; $tmpl.Text=$script:dnsState.Tmpl; $tmpl.ForeColor=$F.Text }
    $tmpl.Add_TextChanged({ if($this.Focused){ $this.Tag=$this.Text; $script:dnsState.Tmpl=$this.Text } })
    $tmpl.Add_Leave({
        # normalise on the way out so the stored value is what Apply writes
        if(-not [string]::IsNullOrWhiteSpace($this.Tag)){
            $chk=Test-DohTemplate $this.Tag
            if($chk.Ok){ $this.Tag=$chk.Value; $this.Text=$chk.Value; $script:dnsState.Tmpl=$chk.Value }
            else { Set-Status "DoH template: $($chk.Reason)" }
        }
    })
    $page.Controls.Add($card)
}

# --------------------------------------------------------------- page switch
function Get-SearchMatches([string]$query){
    # Token matching over name + key + full description, so a word that only
    # appears in the prose still finds the row. Each token must hit somewhere
    # (AND), which makes "password leak" narrower than either word alone.
    # Trailing "s" is trimmed on both sides so "passwords" finds "password".
    $tokens=@($query.ToLower() -split '\s+' | Where-Object { $_ })
    if(-not $tokens){ return @() }
    $hits=@()
    for($ci=0;$ci -lt $script:cats.Count;$ci++){
        $cat=$script:cats[$ci]
        foreach($row in $cat.rows){
            $name=[string]$row.name
            $desc=[string]$row.full
            $key=[string]$row.key
            $hay=("$name $key $desc $($cat.name)").ToLower()
            $stemHay=($hay -replace 's\b','')
            $titleHay=("$name $key").ToLower()
            $titleStem=($titleHay -replace 's\b','')
            $all=$true; $score=0
            foreach($tok in $tokens){
                $stem=$tok -replace 's$',''
                if($hay.Contains($tok) -or $stemHay.Contains($stem)){
                    # a title or key hit ranks above a description-only hit
                    if($titleHay.Contains($tok) -or $titleStem.Contains($stem)){ $score+=10 }
                    else { $score+=3 }
                } else { $all=$false; break }
            }
            if($all){ $hits+=@{Row=$row;Cat=$cat.name;Score=$score} }
        }
    }
    return ($hits | Sort-Object -Property @{Expression={$_.Score};Descending=$true},
                                          @{Expression={$_.Row.name}})
}

function Show-SearchResults([string]$query){
    $hits=Get-SearchMatches $query
    $pageTitle.Text="Search"
    $n=@($hits).Count
    $word="matches"; if($n -eq 1){ $word="match" }
    $crumb.Text="SlimBrave Neo  >  Search  -  $n $word for `"$query`""
    foreach($n2 in $script:navItems){ $n2.Invalidate() }
    $page.SuspendLayout()
    $page.AutoScrollPosition=New-Object System.Drawing.Point 0,0
    $page.AutoScrollMinSize=New-Object System.Drawing.Size 0,0
    $page.Controls.Clear(); $script:rowPanels=@()
    $y=4
    if($n -eq 0){
        $empty=New-Object System.Windows.Forms.Label
        $empty.Text="Nothing matches `"$query`"."
        $empty.Font=$script:rowFont; $empty.ForeColor=$F.TextSub
        $empty.BackColor=$F.Bg; $empty.AutoSize=$true
        $empty.Location=New-Object System.Drawing.Point 6,12
        $page.Controls.Add($empty)
    } else {
        $lastCat=""
        foreach($h in $hits){
            if($h.Cat -ne $lastCat){
                $hd=New-SectionHeader $h.Cat $y 0
                $page.Controls.Add($hd); $script:rowPanels+=$hd; $y+=42
                $lastCat=$h.Cat
            }
            $rp=New-FluentRow $h.Row $y
            $page.Controls.Add($rp); $script:rowPanels+=$rp; $y+=68
        }
    }
    $page.ResumeLayout()
    $page.AutoScrollPosition=New-Object System.Drawing.Point 0,0
    $page.Invalidate($true); $page.Update()
}

function Select-Page([int]$idx){
    $script:sel=$idx
    foreach($n in $script:navItems){$n.Invalidate()}
    $name=$script:pages[$idx]
    $crumb.Text="SlimBrave Neo  >  $name"
    $pageTitle.Text=$name
    $page.SuspendLayout()
    # Zero the scroll BEFORE clearing and refilling. Child Location is in
    # scrolled coordinates, so rows added while the previous page's offset is
    # still applied land that far down, and AutoScrollMinSize grows to cover
    # the emptiness above them - the "ghost scroll" you have to travel through
    # before reaching the content.
    $page.AutoScrollPosition=New-Object System.Drawing.Point 0,0
    $page.AutoScrollMinSize=New-Object System.Drawing.Size 0,0
    $page.Controls.Clear(); $script:rowPanels=@()
    if($idx -eq 0){
        $y=4
        foreach($pr in $script:presets){
            $c=New-PresetCard $pr $y; $page.Controls.Add($c); $y+=82
        }
    } elseif($idx -eq 1){
        # every row, every category, one scroll - no menuing
        $y=4; $total=0
        foreach($cat in $script:cats){
            $hd=New-SectionHeader $cat.name $y $cat.rows.Count
            $page.Controls.Add($hd); $script:rowPanels+=$hd; $y+=42
            foreach($row in $cat.rows){
                $rp=New-FluentRow $row $y; $page.Controls.Add($rp)
                $script:rowPanels+=$rp; $y+=68; $total++
            }
            $y+=10
        }
        $pageTitle.Text="All Options"
        $crumb.Text="SlimBrave Neo  >  All Options  -  $total policies in one list"
    } elseif($idx -eq ($script:pages.Count-1)){
        Build-DnsPage
    } else {
        $cat=$script:cats[$idx-2]; $y=4
        foreach($row in $cat.rows){
            $rp=New-FluentRow $row $y; $page.Controls.Add($rp)
            $script:rowPanels+=$rp; $y+=68
        }
    }
    $page.ResumeLayout()
    $page.AutoScrollPosition=New-Object System.Drawing.Point 0,0
    $page.Invalidate($true); $page.Update()
}

$script:searchBox.Add_TextChanged({
    $q=$this.Text.Trim()
    $searchHost.Invalidate()
    if([string]::IsNullOrWhiteSpace($q)){ Select-Page $script:sel } else { Show-SearchResults $q }
})
$script:searchBox.Add_KeyDown({
    param($s,$ev)
    if($ev.KeyCode -eq [System.Windows.Forms.Keys]::Escape){ $s.Text="" }
})

if(Test-Path $script:machineReg){ Sync-FromRegistry } else { Set-Status "No Brave policy set on this machine" }
Select-Page 0
[void] $form.ShowDialog()
