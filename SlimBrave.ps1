# Which browser to manage. All three speak the Chromium managed-policy
# dialect; only the registry path and vendor-specific keys differ.
param(
    [ValidateSet("brave", "chrome", "edge")]
    [string] $Browser = "brave"
)

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    # Carry -ExecutionPolicy Bypass and -Browser into the elevated
    # instance: the user often launches via "powershell -ExecutionPolicy
    # Bypass -File ..." and the relaunch would otherwise revert to the
    # machine default policy (and default browser) and silently fail.
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`" -Browser $Browser" -Verb RunAs
    exit
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$browserDefs = @{
    brave = @{
        Label = "Brave"
        RegistryPath = "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave"
        ProcessName = "brave"
        VendorCategory = "Brave Features"
        PrefsRepair = $true
    }
    chrome = @{
        Label = "Google Chrome"
        RegistryPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
        ProcessName = "chrome"
        VendorCategory = "Chrome Features"
        PrefsRepair = $false
    }
    edge = @{
        Label = "Microsoft Edge"
        RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
        ProcessName = "msedge"
        VendorCategory = "Edge Features"
        PrefsRepair = $false
    }
}
$browserDef = $browserDefs[$Browser]
$browserLabel = $browserDef.Label

$machineRegistryPath = $browserDef.RegistryPath
$userRegistryPath   = $browserDef.RegistryPath -replace "^HKLM:", "HKCU:"
$registryPath       = $machineRegistryPath

Clear-Host

# ---------------------------------------------------------------------------
# DNS helper - handles both DnsOverHttpsMode and DnsOverHttpsTemplates
# ---------------------------------------------------------------------------

function Set-DnsSettings {
    param (
        [string] $dnsMode,
        [string] $dnsTemplates
    )
    $regKey = $script:machineRegistryPath
    $resolvedMode = $dnsMode

    if ($dnsMode -eq "custom") {
        if ([string]::IsNullOrWhiteSpace($dnsTemplates)) {
            [System.Windows.Forms.MessageBox]::Show(
                "Custom DoH requires a template URL (e.g. https://cloudflare-dns.com/dns-query).",
                "Missing DoH Template",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
            return $false
        }
        $resolvedMode = "secure"
        Set-ItemProperty -Path $regKey -Name "DnsOverHttpsTemplates" -Value $dnsTemplates -Type String -Force
    } elseif ($dnsMode -eq "secure" -and -not [string]::IsNullOrWhiteSpace($dnsTemplates)) {
        # "secure" keeps an explicit template when one is provided — parity
        # with the Linux/macOS scripts, so cross-platform configs with
        # DnsMode=secure + DnsTemplates don't lose their resolver here.
        Set-ItemProperty -Path $regKey -Name "DnsOverHttpsTemplates" -Value $dnsTemplates -Type String -Force
    } else {
        # Remove the templates key when no template applies
        if (Get-ItemProperty -Path $regKey -Name "DnsOverHttpsTemplates" -ErrorAction SilentlyContinue) {
            Remove-ItemProperty -Path $regKey -Name "DnsOverHttpsTemplates" -ErrorAction SilentlyContinue
        }
    }

    Set-ItemProperty -Path $regKey -Name "DnsOverHttpsMode" -Value $resolvedMode -Type String -Force
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

    Returns a hashtable @{ Removed = N; Running = $true/$false }.
    Safe to call when files or keys do not exist.
    #>
    # Every channel of a browser shares one process name on Windows.
    $running = ($null -ne (Get-Process $script:browserDef.ProcessName -ErrorAction SilentlyContinue))

    if (-not $script:browserDef.PrefsRepair) {
        return @{ Removed = 0; Running = $running }
    }

    $removed = 0
    foreach ($channelDir in @('Brave-Browser', 'Brave-Browser-Beta', 'Brave-Browser-Nightly', 'Brave-Browser-Dev')) {
        $userData = Join-Path $env:LOCALAPPDATA "BraveSoftware\$channelDir\User Data"
        if (-not (Test-Path $userData)) { continue }
        $profileDirs = Get-ChildItem -Path $userData -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' }
        foreach ($dir in $profileDirs) {
            $removed += Repair-OneBravePrefs (Join-Path $dir.FullName 'Preferences')
        }
    }

    return @{ Removed = $removed; Running = $running }
}

function Test-FeatureValueMatches {
    param($feature, $expected)
    # List-typed features use a fixed canonical value (the Shields URL
    # pattern list). In dict-format imports we treat the key's presence as
    # "apply our list", since encoding alternative list values in a
    # round-trippable way is out of scope.
    if ($feature.Type -eq "List") { return $true }
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

# ---------------------------------------------------------------------------
# Theme palette
#
# The app follows the Windows "apps" light/dark setting. All colors live in
# this one table so the two modes stay in sync — controls read from $theme
# instead of hard-coding colors. Checkbox glyphs are custom-painted in
# Add-FeatureCheckboxes because the stock flat glyph is nearly invisible on
# dark backgrounds and follows the system theme on light ones.
# ---------------------------------------------------------------------------

$appsUseLightTheme = $true   # Windows defaults to light when the value is missing
try {
    $personalize = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -ErrorAction Stop
    $appsUseLightTheme = ([int]$personalize.AppsUseLightTheme -ne 0)
} catch {}

if ($appsUseLightTheme) {
    $theme = @{
        FormBack     = [System.Drawing.Color]::FromArgb(255, 243, 243, 243)
        PanelBack    = [System.Drawing.Color]::FromArgb(255, 252, 252, 252)
        Text         = [System.Drawing.Color]::FromArgb(255, 30, 30, 30)
        Accent       = [System.Drawing.Color]::FromArgb(255, 186, 70, 30)
        HintText     = [System.Drawing.Color]::FromArgb(255, 120, 120, 120)
        InputBack    = [System.Drawing.Color]::White
        InputText    = [System.Drawing.Color]::FromArgb(255, 30, 30, 30)
        BoxFill      = [System.Drawing.Color]::White
        BoxBorder    = [System.Drawing.Color]::FromArgb(255, 120, 120, 125)
        CheckFill    = [System.Drawing.Color]::FromArgb(255, 196, 80, 35)
        CheckMark    = [System.Drawing.Color]::White
        ButtonBack   = [System.Drawing.Color]::FromArgb(255, 230, 230, 232)
        ButtonHover  = [System.Drawing.Color]::FromArgb(255, 218, 218, 222)
        ButtonBorder = [System.Drawing.Color]::FromArgb(255, 165, 165, 170)
        TipBack      = [System.Drawing.Color]::FromArgb(255, 250, 250, 250)
        TipBorder    = [System.Drawing.Color]::FromArgb(255, 150, 150, 155)
        TipText      = [System.Drawing.Color]::FromArgb(255, 35, 35, 35)
        ExportText   = [System.Drawing.Color]::FromArgb(255, 186, 70, 30)
        ImportText   = [System.Drawing.Color]::FromArgb(255, 40, 100, 160)
        ApplyText    = [System.Drawing.Color]::FromArgb(255, 35, 120, 60)
        ResetText    = [System.Drawing.Color]::FromArgb(255, 178, 45, 45)
    }
} else {
    $theme = @{
        FormBack     = [System.Drawing.Color]::FromArgb(255, 25, 25, 25)
        PanelBack    = [System.Drawing.Color]::FromArgb(255, 35, 35, 35)
        Text         = [System.Drawing.Color]::FromArgb(255, 230, 230, 230)
        Accent       = [System.Drawing.Color]::LightSalmon
        HintText     = [System.Drawing.Color]::FromArgb(255, 140, 140, 140)
        InputBack    = [System.Drawing.Color]::FromArgb(255, 25, 25, 25)
        InputText    = [System.Drawing.Color]::FromArgb(255, 230, 230, 230)
        BoxFill      = [System.Drawing.Color]::FromArgb(255, 45, 45, 48)
        BoxBorder    = [System.Drawing.Color]::FromArgb(255, 130, 130, 135)
        CheckFill    = [System.Drawing.Color]::FromArgb(255, 225, 95, 50)
        CheckMark    = [System.Drawing.Color]::White
        ButtonBack   = [System.Drawing.Color]::FromArgb(255, 45, 45, 48)
        ButtonHover  = [System.Drawing.Color]::FromArgb(255, 62, 62, 66)
        ButtonBorder = [System.Drawing.Color]::FromArgb(255, 90, 90, 95)
        TipBack      = [System.Drawing.Color]::FromArgb(255, 45, 45, 48)
        TipBorder    = [System.Drawing.Color]::FromArgb(255, 110, 110, 115)
        TipText      = [System.Drawing.Color]::Gainsboro
        ExportText   = [System.Drawing.Color]::LightSalmon
        ImportText   = [System.Drawing.Color]::LightSkyBlue
        ApplyText    = [System.Drawing.Color]::LightGreen
        ResetText    = [System.Drawing.Color]::LightCoral
    }
}

# ---------------------------------------------------------------------------
# Form setup
# ---------------------------------------------------------------------------

$form = New-Object System.Windows.Forms.Form
$form.Text = "SlimBrave Neo - $browserLabel"
# Segoe UI replaces the WinForms default (8.25pt Microsoft Sans Serif) and
# is inherited by every control that doesn't set its own font.
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$form.ForeColor = $theme.Text
# Form size (ClientSize) is set by the responsive column builder below, once
# the column count and the tallest column height are known.
$form.StartPosition = "CenterScreen"
$form.BackColor = $theme.FormBack
$form.MaximizeBox = $false
$form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog

# Ask DWM for a dark title bar to match the dark theme; without this the
# window chrome stays system-light. Best-effort: silently skipped on
# Windows builds that don't support the attribute.
if (-not $appsUseLightTheme) {
    try {
        Add-Type -Namespace SlimBrave -Name Native -MemberDefinition @'
[DllImport("dwmapi.dll")]
public static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);
'@
        $form.Add_HandleCreated({
            $darkMode = 1
            # 20 = DWMWA_USE_IMMERSIVE_DARK_MODE; pre-20H1 Windows 10 used 19
            if ([SlimBrave.Native]::DwmSetWindowAttribute($this.Handle, 20, [ref]$darkMode, 4) -ne 0) {
                [void] [SlimBrave.Native]::DwmSetWindowAttribute($this.Handle, 19, [ref]$darkMode, 4)
            }
        })
    } catch {}
}

$allFeatures = @()

# ---------------------------------------------------------------------------
# Theme + hover tooltips
#
# One shared ToolTip serves every control. The stock WinForms tooltip is a
# black-on-cream system balloon that clashes with the dark theme, so it is
# owner-drawn: dark background, subtle border, word-wrapped Segoe UI text.
# Popup measures the wrapped text so the bubble fits multi-line tips.
# ---------------------------------------------------------------------------

$sectionFont = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$tipFont     = New-Object System.Drawing.Font("Segoe UI", 9)
$tipFlags    = [System.Windows.Forms.TextFormatFlags]::WordBreak

$tooltip = New-Object System.Windows.Forms.ToolTip
$tooltip.OwnerDraw    = $true
$tooltip.InitialDelay = 350
$tooltip.ReshowDelay  = 100
$tooltip.AutoPopDelay = 30000   # the 5s default cuts off the longer descriptions

$tooltip.Add_Popup({
    param($s, $e)
    $text = $s.GetToolTip($e.AssociatedControl)
    $proposed = New-Object System.Drawing.Size(340, 0)
    $size = [System.Windows.Forms.TextRenderer]::MeasureText($text, $tipFont, $proposed, $tipFlags)
    $e.ToolTipSize = New-Object System.Drawing.Size(($size.Width + 14), ($size.Height + 12))
})

$tooltip.Add_Draw({
    param($s, $e)
    $backBrush = New-Object System.Drawing.SolidBrush $script:theme.TipBack
    $borderPen = New-Object System.Drawing.Pen $script:theme.TipBorder
    try {
        $e.Graphics.FillRectangle($backBrush, $e.Bounds)
        $e.Graphics.DrawRectangle($borderPen, $e.Bounds.X, $e.Bounds.Y, ($e.Bounds.Width - 1), ($e.Bounds.Height - 1))
        $textRect = New-Object System.Drawing.Rectangle(($e.Bounds.X + 7), ($e.Bounds.Y + 6), ($e.Bounds.Width - 14), ($e.Bounds.Height - 12))
        [System.Windows.Forms.TextRenderer]::DrawText($e.Graphics, $e.ToolTipText, $tipFont, $textRect, $script:theme.TipText, $tipFlags)
    } finally {
        $backBrush.Dispose()
        $borderPen.Dispose()
    }
})

function Add-SectionLabel {
    param ($Panel, [string] $Text, [int] $Y)
    $label = New-Object System.Windows.Forms.Label
    $label.Text = $Text
    $label.UseMnemonic = $false   # render the & in "Telemetry & Reporting" literally
    $label.Font = $sectionFont
    $label.Location = New-Object System.Drawing.Point(25, $Y)
    $label.Size = New-Object System.Drawing.Size(300, 20)
    $label.ForeColor = $theme.Accent
    $Panel.Controls.Add($label)
}

function Add-FeatureCheckboxes {
    # Lays out one checkbox per feature starting at $Y and returns the next
    # free Y. Each feature's Tip becomes a hover tooltip, suffixed with the
    # exact policy it writes so power users can cross-check brave://policy.
    # $Step is the per-row vertical advance (tightened in three-column mode).
    param ($Panel, [array] $Features, [int] $Y, [int] $Step = 25)
    foreach ($feature in $Features) {
        $checkbox = New-Object System.Windows.Forms.CheckBox
        $checkbox.Text = $feature.Name
        $checkbox.Tag = $feature
        $checkbox.Location = New-Object System.Drawing.Point(28, $Y)
        $checkbox.Size = New-Object System.Drawing.Size(305, 20)
        $checkbox.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
        # The stock flat glyph is a thin system-colored check that is nearly
        # invisible on the dark theme, so paint over it: checked = accent
        # box with a white checkmark, unchecked = themed box and border.
        $checkbox.Add_Paint({
            param($s, $e)
            $g = $e.Graphics
            $boxY = [int](($s.ClientSize.Height - 12) / 2)
            $clearBrush = New-Object System.Drawing.SolidBrush $s.BackColor
            $g.FillRectangle($clearBrush, 0, 0, 16, $s.ClientSize.Height)
            $clearBrush.Dispose()
            if ($s.Checked) {
                $fillBrush = New-Object System.Drawing.SolidBrush $script:theme.CheckFill
                $g.FillRectangle($fillBrush, 1, $boxY, 12, 12)
                $fillBrush.Dispose()
                $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
                $checkPen = New-Object System.Drawing.Pen($script:theme.CheckMark, 2)
                $checkPen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
                $checkPen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
                $points = [System.Drawing.PointF[]]@(
                    [System.Drawing.PointF]::new(3.6, ($boxY + 6.2)),
                    [System.Drawing.PointF]::new(6.0, ($boxY + 8.6)),
                    [System.Drawing.PointF]::new(10.4, ($boxY + 3.4))
                )
                $g.DrawLines($checkPen, $points)
                $checkPen.Dispose()
                $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::Default
            } else {
                $fillBrush = New-Object System.Drawing.SolidBrush $script:theme.BoxFill
                $g.FillRectangle($fillBrush, 1, $boxY, 12, 12)
                $fillBrush.Dispose()
                $borderPen = New-Object System.Drawing.Pen $script:theme.BoxBorder
                $g.DrawRectangle($borderPen, 1, $boxY, 12, 12)
                $borderPen.Dispose()
            }
        })
        if ($feature.Tip) {
            $valueText = if ($feature.Type -eq "List") { $feature.Value -join ", " } else { $feature.Value }
            $tooltip.SetToolTip($checkbox, "$($feature.Tip)`n`nPolicy: $($feature.Key) = $valueText")
        }
        $Panel.Controls.Add($checkbox)
        $script:allFeatures += $checkbox
        $Y += $Step
    }
    return $Y
}

# ---------------------------------------------------------------------------
# Feature definitions
#
# Each category is a section header plus its feature checkboxes. The
# categories are arranged into columns further below; the column count adapts
# to the screen height so the window never runs off the bottom of the display.
# ---------------------------------------------------------------------------

$telemetryFeatures = @(
    @{ Name = "Disable Metrics Reporting"; Key = "MetricsReportingEnabled"; Browsers = @("brave", "chrome"); Value = 0; Type = "DWord"
       Tip = "Stops Brave from sending anonymous usage statistics and crash reports to Brave's servers." },
    @{ Name = "Disable Safe Browsing Reporting"; Key = "SafeBrowsingExtendedReportingEnabled"; Browsers = @("brave", "chrome"); Value = 0; Type = "DWord"
       Tip = "Stops extended Safe Browsing reports (details about suspicious pages and downloads) from being sent to Google. Safe Browsing protection itself stays on." },
    @{ Name = "Disable URL Data Collection"; Key = "UrlKeyedAnonymizedDataCollectionEnabled"; Browsers = @("brave", "chrome"); Value = 0; Type = "DWord"
       Tip = "Stops URL-keyed anonymized data collection, which reports the URLs you visit to improve suggestion and safety features." },
    @{ Name = "Disable P3A Analytics"; Key = "BraveP3AEnabled"; Browsers = @("brave"); Value = 0; Type = "DWord"
       Tip = "Disables P3A (Privacy-Preserving Product Analytics), Brave's anonymized product usage telemetry." },
    @{ Name = "Disable Stats Ping"; Key = "BraveStatsPingEnabled"; Browsers = @("brave"); Value = 0; Type = "DWord"
       Tip = "Stops the daily usage ping that counts this install in Brave's active-user statistics." }
)

$privacyFeatures = @(
    @{ Name = "Disable Safe Browsing"; Key = "SafeBrowsingProtectionLevel"; Browsers = @("brave", "chrome"); Value = 0; Type = "DWord"
       Tip = "Turns Google Safe Browsing fully off: nothing is checked against Google, but you also lose the phishing/malware warning pages. Only for users who understand the trade-off." },
    @{ Name = "Disable Autofill (Addresses)"; Key = "AutofillAddressEnabled"; Value = 0; Type = "DWord"
       Tip = "Stops Brave from saving and auto-filling street addresses in web forms." },
    @{ Name = "Disable Autofill (Credit Cards)"; Key = "AutofillCreditCardEnabled"; Value = 0; Type = "DWord"
       Tip = "Stops Brave from saving and auto-filling credit card numbers in web forms." },
    @{ Name = "Disable Password Manager"; Key = "PasswordManagerEnabled"; Value = 0; Type = "DWord"
       Tip = "Disables the built-in password manager (no save prompts, no autofill). Recommended if you use a dedicated password manager." },
    @{ Name = "Disable Password Leak Detection"; Key = "PasswordLeakDetectionEnabled"; Browsers = @("brave", "chrome"); Value = 0; Type = "DWord"
       Tip = "Stops the online check that compares your saved credentials against known breach lists. Defense in depth if you audit passwords with your own manager instead." },
    @{ Name = "Disable Browser Sign-in"; Key = "BrowserSignin"; Value = 0; Type = "DWord"
       Tip = "Prevents signing in to the browser itself with an account." },
    @{ Name = "Disable Sync"; Key = "SyncDisabled"; Value = 1; Type = "DWord"
       Tip = "Disables browser sync, which shares bookmarks, history, and settings across devices." },
    @{ Name = "Enable Global Privacy Control"; Key = "BraveGlobalPrivacyControlEnabled"; Browsers = @("brave"); Value = 1; Type = "DWord"
       Tip = "Sends the GPC signal with every request, telling sites not to sell or share your data. Legally binding in some regions (e.g. under CCPA)." },
    @{ Name = "Enable De-AMP"; Key = "BraveDeAmpEnabled"; Browsers = @("brave"); Value = 1; Type = "DWord"
       Tip = "Skips Google AMP pages and loads the publisher's original page instead." },
    @{ Name = "Enable Debouncing"; Key = "BraveDebouncingEnabled"; Browsers = @("brave"); Value = 1; Type = "DWord"
       Tip = "Skips known tracking redirects and navigates straight to the final destination URL." },
    @{ Name = "Strip Tracking URL Parameters"; Key = "BraveTrackingQueryParametersFilteringEnabled"; Browsers = @("brave"); Value = 1; Type = "DWord"
       Tip = "Removes known tracking parameters (fbclid, gclid, mc_eid, ...) from URLs before they load." },
    @{ Name = "Reduce Language Fingerprinting"; Key = "BraveReduceLanguageEnabled"; Browsers = @("brave"); Value = 1; Type = "DWord"
       Tip = "Reports a generic language configuration to sites, making your browser harder to fingerprint." },
    @{ Name = "Disable WebRTC IP Leak"; Key = "WebRtcIPHandling"; Browsers = @("brave", "chrome"); Value = "disable_non_proxied_udp"; Type = "String"
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
       Tip = "Uses plain local error pages for navigation errors instead of a web-service-assisted suggestion page. Belt-and-braces: Brave already ships this off." }
)

# Site permissions and access lockdowns: content-setting defaults plus the
# escape hatches (guest, incognito, extensions) that would otherwise bypass
# the rest of the policy set.
$accessFeatures = @(
    @{ Name = "Block Web Notifications"; Key = "DefaultNotificationsSetting"; Value = 2; Type = "DWord"
       Tip = "Blocks all sites from showing desktop notifications and removes the permission prompt entirely." },
    @{ Name = "Block Location Access"; Key = "DefaultGeolocationSetting"; Value = 2; Type = "DWord"
       Tip = "Blocks all sites from reading your physical location and removes the permission prompt. Maps and delivery sites will need the location typed manually." },
    @{ Name = "Block Motion Sensors"; Key = "DefaultSensorsSetting"; Value = 2; Type = "DWord"
       Tip = "Blocks all sites from reading motion and orientation sensors, a known fingerprinting vector. Rarely breaks anything on desktop." },
    @{ Name = "Force Google SafeSearch"; Key = "ForceGoogleSafeSearch"; Value = 1; Type = "DWord"
       Tip = "Forces SafeSearch on for all Google searches. Mainly useful for parental controls." },
    @{ Name = "Filter Adult Content (SafeSites)"; Key = "SafeSitesFilterBehavior"; Browsers = @("brave", "chrome"); Value = 1; Type = "DWord"
       Tip = "Enables the built-in SafeSites URL filter, which blocks sites classified as adult content. Mainly useful for parental controls." },
    @{ Name = "Disable Guest Mode"; Key = "BrowserGuestModeEnabled"; Value = 0; Type = "DWord"
       Tip = "Removes guest browsing sessions. Closes the loophole where a guest window bypasses profile-level restrictions and history." },
    @{ Name = "Block All Extensions"; Key = "ExtensionInstallBlocklist"; Value = @("*"); Type = "List"
       Tip = "Blocks installation of every extension and disables ones already installed. For lockdown/parental setups - a proxy or VPN extension would bypass DNS filtering." },
    @{ Name = "Disable Incognito Mode"; Key = "IncognitoModeAvailability"; Browsers = @("brave", "chrome"); Value = 1; Type = "DWord"; Group = "incognito"
       Tip = "Removes private browsing entirely - no incognito windows can be opened. Mutually exclusive with Force Incognito Mode." },
    @{ Name = "Force Incognito Mode"; Key = "IncognitoModeAvailability"; Browsers = @("brave", "chrome"); Value = 2; Type = "DWord"; Group = "incognito"
       Tip = "Every window opens in incognito: no history, and logins and most extensions stop persisting. Mutually exclusive with Disable Incognito Mode." }
)

# Brave 1.83+ content-protection enforcers. These pin Brave's own privacy
# defaults as managed policy so neither the user nor a malicious
# page/extension can quietly weaken them.
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
    @{ Name = "Disable Brave Shields"; Key = "BraveShieldsDisabledForUrls"; Value = @("https://*", "http://*"); Type = "List"; Group = "shields"
       Tip = "Turns Shields OFF for every site: no ad blocking, no tracker blocking. Almost nobody wants this - it exists for kiosk/testing setups. Mutually exclusive with Force Shields On." },
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
    @{ Name = "Disable Email Aliases"; Key = "EmailAliasesEnabled"; Value = 0; Type = "DWord"
       Tip = "Disables the Email Aliases feature for generating throwaway email addresses." }
)

# Chrome-only keys, verified against Chromium policy_definitions YAML
# (see AUDIT.md). The four Privacy Sandbox policies were considered and
# rejected: Chromium marks them deprecated.
$chromeFeatures = @(
    @{ Name = "Disable Feedback Collection"; Key = "UserFeedbackAllowed"; Value = 0; Type = "DWord"
       Tip = "Blocks the built-in 'Report an issue' feedback uploads to Google." },
    @{ Name = "Disable Chrome Labs"; Key = "BrowserLabsEnabled"; Value = 0; Type = "DWord"
       Tip = "Removes the Chrome Labs beaker icon and its experimental-feature promos from the toolbar." },
    @{ Name = "Disable Search Side Panel"; Key = "GoogleSearchSidePanelEnabled"; Value = 0; Type = "DWord"
       Tip = "Disables the Google Search side panel companion on all web pages." },
    @{ Name = "Disable Gemini Integrations"; Key = "GeminiSettings"; Value = 1; Type = "DWord"
       Tip = "Turns off Gemini AI integrations in Chrome (requires Chrome 137+)." },
    @{ Name = "Restrict Field Trials (Critical Only)"; Key = "ChromeVariations"; Value = 1; Type = "DWord"
       Tip = "Stops Google from A/B-testing experimental behavior changes on this browser; only variations carrying critical security fixes still apply." }
)

# Edge-only keys, verified against Microsoft's per-policy Edge
# documentation (see AUDIT.md). Includes Edge's renamed equivalents of
# Chromium policies (InPrivate, WebRTC, SmartScreen, Password Monitor,
# Efficiency Mode). MetricsReportingEnabled, PromotionalTabsEnabled,
# EdgeFollowEnabled, and EdgeWalletEtreeEnabled were considered and
# rejected: Microsoft marks them obsolete or deprecated.
$edgeFeatures = @(
    @{ Name = "Minimize Diagnostic Data"; Key = "DiagnosticData"; Value = 0; Type = "DWord"
       Tip = "Sets diagnostic data collection about browser usage to Off, the minimum Edge allows via policy." },
    @{ Name = "Disable Personalization Reporting"; Key = "PersonalizationReportingEnabled"; Value = 0; Type = "DWord"
       Tip = "Stops Microsoft from using your browsing history to personalize ads, search, and news." },
    @{ Name = "Disable Feedback Collection"; Key = "UserFeedbackAllowed"; Value = 0; Type = "DWord"
       Tip = "Blocks the built-in 'Send feedback' uploads to Microsoft." },
    @{ Name = "Disable Sidebar & Copilot Hub"; Key = "HubsSidebarEnabled"; Value = 0; Type = "DWord"
       Tip = "Removes the sidebar rail, including the Copilot hub and its app panels." },
    @{ Name = "Disable Collections"; Key = "EdgeCollectionsEnabled"; Value = 0; Type = "DWord"
       Tip = "Removes the Collections feature from the toolbar and menus." },
    @{ Name = "Disable Shopping Assistant"; Key = "EdgeShoppingAssistantEnabled"; Value = 0; Type = "DWord"
       Tip = "Disables coupons, price comparison, and cashback prompts while shopping." },
    @{ Name = "Disable Microsoft Rewards"; Key = "ShowMicrosoftRewards"; Value = 0; Type = "DWord"
       Tip = "Hides Microsoft Rewards experiences and stops related tracking." },
    @{ Name = "Disable Wallet Checkout"; Key = "EdgeWalletCheckoutEnabled"; Value = 0; Type = "DWord"
       Tip = "Disables the Microsoft Wallet express-checkout overlay on shopping sites." },
    @{ Name = "Disable New Tab MSN Feed"; Key = "NewTabPageContentEnabled"; Value = 0; Type = "DWord"
       Tip = "Removes the MSN news feed and sponsored content from the new tab page." },
    @{ Name = "Disable Asset Delivery Service"; Key = "EdgeAssetDeliveryServiceEnabled"; Value = 0; Type = "DWord"
       Tip = "Stops Edge from downloading extra feature payloads and experiments from Microsoft's asset delivery service." },
    @{ Name = "Enable Sleeping Tabs"; Key = "SleepingTabsEnabled"; Value = 1; Type = "DWord"
       Tip = "Forces sleeping tabs on: background tabs release memory and CPU after inactivity." },
    @{ Name = "Enable Efficiency Mode"; Key = "EfficiencyModeEnabled"; Value = 1; Type = "DWord"
       Tip = "Forces efficiency mode on to reduce CPU and battery use." },
    @{ Name = "Disable Startup Boost"; Key = "StartupBoostEnabled"; Value = 0; Type = "DWord"
       Tip = "Stops Edge processes from pre-launching at Windows sign-in and staying resident after close." },
    @{ Name = "Disable Spotlight Recommendations"; Key = "SpotlightExperiencesAndRecommendationsEnabled"; Value = 0; Type = "DWord"
       Tip = "Turns off Windows Spotlight tips and Microsoft feature recommendations inside Edge." },
    @{ Name = "Disable SmartScreen"; Key = "SmartScreenEnabled"; Value = 0; Type = "DWord"
       Tip = "Turns Microsoft Defender SmartScreen fully off: no URL or download reputation checks are sent to Microsoft, but you also lose the phishing/malware warnings. Only for users who understand the trade-off." },
    @{ Name = "Disable Password Monitor"; Key = "PasswordMonitorAllowed"; Value = 0; Type = "DWord"
       Tip = "Stops the online check that compares your saved credentials against known breach lists." },
    @{ Name = "Disable WebRTC IP Leak (Edge)"; Key = "WebRtcLocalhostIpHandling"; Value = "disable_non_proxied_udp"; Type = "String"
       Tip = "Restricts WebRTC to proxied connections so video/voice calls can't expose your real IP address behind a VPN or proxy." },
    @{ Name = "Force Bing SafeSearch (Strict)"; Key = "ForceBingSafeSearch"; Value = 2; Type = "DWord"
       Tip = "Forces strict SafeSearch for all Bing searches. Mainly useful for parental controls." },
    @{ Name = "Disable InPrivate Mode"; Key = "InPrivateModeAvailability"; Value = 1; Type = "DWord"; Group = "incognito"
       Tip = "Removes InPrivate browsing entirely. Mutually exclusive with Force InPrivate Mode." },
    @{ Name = "Force InPrivate Mode"; Key = "InPrivateModeAvailability"; Value = 2; Type = "DWord"; Group = "incognito"
       Tip = "Every window opens InPrivate: no history, and logins stop persisting. Mutually exclusive with Disable InPrivate Mode." }
)

$perfFeatures = @(
    @{ Name = "Disable Background Mode"; Key = "BackgroundModeEnabled"; Value = 0; Type = "DWord"
       Tip = "Stops Brave from keeping background processes running after the last window is closed." },
    @{ Name = "Enable Memory Saver"; Key = "HighEfficiencyModeEnabled"; Browsers = @("brave", "chrome"); Value = 1; Type = "DWord"
       Tip = "Forces Memory Saver on: inactive tabs are discarded to free RAM and reload when you return to them." },
    @{ Name = "Force Hardware Acceleration"; Key = "HardwareAccelerationModeEnabled"; Value = 1; Type = "DWord"
       Tip = "Pins GPU hardware acceleration on so rendering and video decode stay off the CPU. Takes effect after a browser restart." },
    @{ Name = "Disable Media Router (Cast)"; Key = "EnableMediaRouter"; Value = 0; Type = "DWord"
       Tip = "Disables the Google Cast media router and its background device discovery on the local network. Takes effect after a browser restart." },
    @{ Name = "Disable Media Recommendations"; Key = "MediaRecommendationsEnabled"; Browsers = @("brave", "chrome"); Value = 0; Type = "DWord"
       Tip = "Disables the media history and recommendation surfaces built from what you watch." },
    @{ Name = "Disable Shopping List"; Key = "ShoppingListEnabled"; Browsers = @("brave", "chrome"); Value = 0; Type = "DWord"
       Tip = "Disables the price-tracking shopping list feature." },
    @{ Name = "Always Open PDF Externally"; Key = "AlwaysOpenPdfExternally"; Value = 1; Type = "DWord"
       Tip = "Downloads PDF files and opens them in your system PDF viewer instead of the built-in viewer." },
    @{ Name = "Disable Translate"; Key = "TranslateEnabled"; Value = 0; Type = "DWord"
       Tip = "Disables the built-in page translation feature and its popup prompts." },
    @{ Name = "Disable Spellcheck"; Key = "SpellcheckEnabled"; Value = 0; Type = "DWord"
       Tip = "Turns off spell checking in text fields." },
    @{ Name = "Disable Search Suggestions"; Key = "SearchSuggestEnabled"; Value = 0; Type = "DWord"
       Tip = "Stops sending what you type in the address bar to your search engine for live suggestions." },
    @{ Name = "Disable Printing"; Key = "PrintingEnabled"; Value = 0; Type = "DWord"
       Tip = "Disables printing from the browser entirely (including Ctrl+P)." },
    @{ Name = "Disable Default Browser Prompt"; Key = "DefaultBrowserSettingEnabled"; Value = 0; Type = "DWord"
       Tip = "Stops Brave from asking to become your default browser." },
    @{ Name = "Disable Developer Tools"; Key = "DeveloperToolsAvailability"; Value = 2; Type = "DWord"
       Tip = "Blocks DevTools (F12) and extension debugging everywhere. Don't enable this if you do web development." },
    @{ Name = "Disable Wayback Machine"; Key = "BraveWaybackMachineEnabled"; Browsers = @("brave"); Value = 0; Type = "DWord"
       Tip = "Stops Brave from offering an archive.org snapshot when a page returns 404." }
)

# ---------------------------------------------------------------------------
# Responsive column layout
#
# In a single column the feature set is ~1750px tall, so it is split across
# columns. On a display whose usable (working-area) height is less than the
# natural two-column window, the categories reflow into THREE shorter columns
# so the lower options and the Apply/Reset buttons stay on-screen — the
# 720p / 768p / 1080p cutoff fix. Taller displays keep the two-column layout.
#
# Force a column count for testing on a normal monitor by setting
# $env:SLIMBRAVE_COLUMNS to "2" or "3" before launching.
# ---------------------------------------------------------------------------

$vendorFeatureSets = @{
    brave  = $braveFeatures
    chrome = $chromeFeatures
    edge   = $edgeFeatures
}

# Feature rows carry an optional Browsers list restricting them to a
# subset; untagged rows apply to every browser. Categories that filter
# down to zero rows (e.g. Telemetry & Reporting on Edge, which replaces
# every Chromium telemetry key with its own) are dropped entirely.
$allCategories = @(
    @{ Name = "Telemetry & Reporting";        Features = $telemetryFeatures },
    @{ Name = "Privacy & Security";           Features = $privacyFeatures },
    @{ Name = "Permissions & Access";         Features = $accessFeatures },
    @{ Name = "Shields & Content Protection"; Features = $shieldsContentFeatures; Browsers = @("brave") },
    @{ Name = $browserDef.VendorCategory;     Features = $vendorFeatureSets[$Browser] },
    @{ Name = "Performance & Bloat";          Features = $perfFeatures }
)
$categories = @()
foreach ($cat in $allCategories) {
    if ($cat.Browsers -and $cat.Browsers -notcontains $Browser) { continue }
    $feats = @($cat.Features | Where-Object {
        -not $_.Browsers -or $_.Browsers -contains $Browser
    })
    if ($feats.Count -eq 0) { continue }
    $categories += @{ Name = $cat.Name; Features = $feats }
}
$categoryByName = @{}
foreach ($cat in $categories) { $categoryByName[$cat.Name] = $cat }

# Natural height of the two-column window. If the screen's usable height is
# below this, switch to three columns. Set a little above the actual ~1130px
# form so a display that only just fits two columns is not left a few px short.
$twoColumnWindowHeight = 1140

$columnCount = 2
if ($env:SLIMBRAVE_COLUMNS -eq "2" -or $env:SLIMBRAVE_COLUMNS -eq "3") {
    $columnCount = [int]$env:SLIMBRAVE_COLUMNS
} elseif ([System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea.Height -lt $twoColumnWindowHeight) {
    $columnCount = 3
}

# Which categories go in each column. Three-column mode pairs the six
# categories so no column runs much past ~545px of content (vs. ~970px in
# the two-column layout).
if ($columnCount -eq 3) {
    $columnLayout = @(
        @("Privacy & Security", "Telemetry & Reporting"),
        @("Permissions & Access", $browserDef.VendorCategory),
        @("Shields & Content Protection", "Performance & Bloat")
    )
} else {
    $columnLayout = @(
        @("Privacy & Security", "Permissions & Access", "Shields & Content Protection"),
        @("Telemetry & Reporting", $browserDef.VendorCategory, "Performance & Bloat")
    )
}

# Three columns use tighter row spacing so the window fits on the short
# displays that trigger it; 21px is the floor (the checkbox controls are
# 20px tall). Two columns keep the original metrics.
if ($columnCount -eq 3) {
    $rowHeight = 21; $rowGap = 6;  $colStartY = 6
} else {
    $rowHeight = 25; $rowGap = 10; $colStartY = 10
}

# ---------------------------------------------------------------------------
# Build the columns
# ---------------------------------------------------------------------------

$layoutMargin   = 20
$layoutPanelW   = 340
$layoutPanelGap = 20
$layoutPanelTop = 20

$panels = @()
$maxColumnBottom = 0
for ($col = 0; $col -lt $columnLayout.Count; $col++) {
    $panelX = $layoutMargin + $col * ($layoutPanelW + $layoutPanelGap)

    $panel = New-Object System.Windows.Forms.Panel
    $panel.Location = New-Object System.Drawing.Point($panelX, $layoutPanelTop)
    $panel.BackColor = $theme.PanelBack
    $panel.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    $form.Controls.Add($panel)
    $panels += $panel

    $y = $colStartY
    foreach ($catName in $columnLayout[$col]) {
        # Categories can be absent for the selected browser (dropped as
        # empty after browser filtering, e.g. Shields on Chrome/Edge).
        if (-not $categoryByName.ContainsKey($catName)) { continue }
        $category = $categoryByName[$catName]
        Add-SectionLabel $panel $category.Name $y
        $y += $rowHeight
        $y = Add-FeatureCheckboxes $panel $category.Features $y $rowHeight
        $y += $rowGap
    }
    if ($y -gt $maxColumnBottom) { $maxColumnBottom = $y }
}

# Give every column the same height so the boxes line up, then expose the
# geometry the DNS row, the buttons, and the form size are positioned from.
$panelHeight = $maxColumnBottom + 5
foreach ($panel in $panels) {
    $panel.Size = New-Object System.Drawing.Size($layoutPanelW, $panelHeight)
}

$layoutContentWidth = (2 * $layoutMargin) + ($columnLayout.Count * $layoutPanelW) + (($columnLayout.Count - 1) * $layoutPanelGap)
$layoutPanelBottom  = $layoutPanelTop + $panelHeight
# Two-column content is 740px wide; shift the DNS row and buttons right so they
# sit under the centre of the wider three-column form (0px when two-column).
$layoutContentOffsetX = [int](($layoutContentWidth - 740) / 2)
$dnsRowTop            = $layoutPanelBottom + 15
$buttonRowTop         = $dnsRowTop + 75

$form.ClientSize = New-Object System.Drawing.Size($layoutContentWidth, ($buttonRowTop + 32 + 18))

# ---------------------------------------------------------------------------
# Mutual-exclusion groups
#
# Features tagged with a `Group` share a single policy key that can only
# take one value at a time. The handler below mirrors the Python TUI's
# toggle_feature_row: checking one group member unchecks the others,
# preventing the silent force-incognito bug that happened when a preset
# enabled both IncognitoModeAvailability rows and the later one won.
# ---------------------------------------------------------------------------

$script:groupSuppress = $false
foreach ($cb in $allFeatures) {
    if ($null -ne $cb.Tag.Group) {
        $cb.Add_CheckedChanged({
            if ($script:groupSuppress) { return }
            $self = $this
            if (-not $self.Checked) { return }
            $group = $self.Tag.Group
            $script:groupSuppress = $true
            try {
                foreach ($other in $allFeatures) {
                    if ($other -eq $self) { continue }
                    if ($other.Tag.Group -eq $group -and $other.Checked) {
                        $other.Checked = $false
                    }
                }
            } finally {
                $script:groupSuppress = $false
            }
        })
    }
}

# ---------------------------------------------------------------------------
# DNS controls
# ---------------------------------------------------------------------------

$dnsLabel = New-Object System.Windows.Forms.Label
$dnsLabel.Text = "DNS Over HTTPS Mode:"
$dnsLabel.Location = New-Object System.Drawing.Point(($layoutContentOffsetX + 20), ($dnsRowTop + 5))
$dnsLabel.Size = New-Object System.Drawing.Size(150, 20)
$form.Controls.Add($dnsLabel)

$dnsDropdown = New-Object System.Windows.Forms.ComboBox
$dnsDropdown.Location = New-Object System.Drawing.Point(($layoutContentOffsetX + 180), $dnsRowTop)
$dnsDropdown.Size = New-Object System.Drawing.Size(150, 20)
# "unmanaged" (the default) writes no DNS policy at all, leaving Brave's
# DNS settings user-controlled. The other four are managed-policy values —
# including "off", which actively force-disables DoH as policy.
$dnsDropdown.Items.AddRange(@("unmanaged", "automatic", "off", "secure", "custom"))
$dnsDropdown.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$dnsDropdown.BackColor = $theme.InputBack
$dnsDropdown.ForeColor = $theme.InputText
$form.Controls.Add($dnsDropdown)
$tooltip.SetToolTip($dnsDropdown, "unmanaged - write no DNS policy; Brave's own DNS settings stay user-controlled.`noff - force-disable DNS over HTTPS as policy.`nautomatic - use DoH when the current resolver supports it, plain DNS otherwise.`nsecure - always resolve over DoH.`ncustom - always resolve over DoH using the template URL below.")

$hoverHint = New-Object System.Windows.Forms.Label
$hoverHint.Text = "Hover over any option for details"
$hoverHint.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Italic)
$hoverHint.ForeColor = $theme.HintText
$hoverHint.Location = New-Object System.Drawing.Point(($layoutContentWidth - 360), ($dnsRowTop + 5))
$hoverHint.Size = New-Object System.Drawing.Size(340, 20)
$hoverHint.TextAlign = [System.Drawing.ContentAlignment]::MiddleRight
$form.Controls.Add($hoverHint)

$dnsTemplateLabel = New-Object System.Windows.Forms.Label
$dnsTemplateLabel.Text = "Custom DoH template URL:"
$dnsTemplateLabel.Location = New-Object System.Drawing.Point(($layoutContentOffsetX + 20), ($dnsRowTop + 35))
$dnsTemplateLabel.Size = New-Object System.Drawing.Size(170, 20)
$form.Controls.Add($dnsTemplateLabel)

$dnsTemplateBox = New-Object System.Windows.Forms.TextBox
$dnsTemplateBox.Location = New-Object System.Drawing.Point(($layoutContentOffsetX + 210), ($dnsRowTop + 35))
$dnsTemplateBox.Size = New-Object System.Drawing.Size(510, 20)
$dnsTemplateBox.BackColor = $theme.InputBack
$dnsTemplateBox.ForeColor = $theme.InputText
$dnsTemplateBox.Enabled = $false
$form.Controls.Add($dnsTemplateBox)
$tooltip.SetToolTip($dnsTemplateBox, "DoH resolver template, e.g. https://cloudflare-dns.com/dns-query. Required for 'custom' mode, optional for 'secure'.")

$dnsDropdown.Add_SelectedIndexChanged({
    $dnsTemplateBox.Enabled = ($dnsDropdown.SelectedItem -in @("custom", "secure"))
})

# ---------------------------------------------------------------------------
# Buttons
# ---------------------------------------------------------------------------

function New-ActionButton {
    # Solid themed buttons replace the old semi-transparent ARGB(150,...)
    # backgrounds, which WinForms blends unpredictably against the form.
    param (
        [string] $Text,
        [int]    $X,
        [System.Drawing.Color] $TextColor,
        [string] $Tip
    )
    $button = New-Object System.Windows.Forms.Button
    $button.Text = $Text
    $button.Location = New-Object System.Drawing.Point(($script:layoutContentOffsetX + $X), $script:buttonRowTop)
    $button.Size = New-Object System.Drawing.Size(120, 32)
    $button.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $button.FlatAppearance.BorderSize = 1
    $button.FlatAppearance.BorderColor = $theme.ButtonBorder
    $button.FlatAppearance.MouseOverBackColor = $theme.ButtonHover
    $button.BackColor = $theme.ButtonBack
    $button.ForeColor = $TextColor
    $tooltip.SetToolTip($button, $Tip)
    $form.Controls.Add($button)
    return $button
}

$exportButton = New-ActionButton "Export Settings" 20 $theme.ExportText `
    "Save the current selections to a JSON file. The format is shared with the Linux and macOS versions."
$importButton = New-ActionButton "Import Settings" 213 $theme.ImportText `
    "Load selections from a JSON file or one of the bundled presets. Nothing is written until you click Apply Settings."
$saveButton = New-ActionButton "Apply Settings" 407 $theme.ApplyText `
    "Write every checked policy to the registry and remove unchecked ones. Restart $browserLabel (close all $($browserDef.ProcessName).exe processes) for changes to take effect."
$resetButton = New-ActionButton "Reset All Settings" 600 $theme.ResetText `
    "Delete ALL Brave policies from machine and user scope - including any set by other tools - and scrub leaked Shields entries from your Brave profiles."

# ---------------------------------------------------------------------------
# Apply - sets checked keys AND removes unchecked keys (fixes #25, #27, #19)
# ---------------------------------------------------------------------------

$saveButton.Add_Click({
    # Validate DNS settings up-front. Writing features first and then
    # bailing out on a bad DNS config would leave the policy store in a
    # half-applied state, which is what the original "custom with no
    # template" bug looked like in practice.
    if ($dnsDropdown.SelectedItem -eq "custom" -and
        [string]::IsNullOrWhiteSpace($dnsTemplateBox.Text)) {
        [System.Windows.Forms.MessageBox]::Show(
            "Custom DoH requires a template URL (e.g. https://cloudflare-dns.com/dns-query).",
            "Missing DoH Template",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        return
    }

    # Created lazily here rather than at launch, so merely opening the app
    # never writes to the registry.
    if (-not (Test-Path -Path $registryPath)) {
        New-Item -Path $registryPath -Force | Out-Null
    }

    # Build a hashtable of selected features keyed by policy key name.
    # Group exclusivity (above) ensures at most one entry per key, so this
    # is just a key lookup.
    $selectedFeatures = @{}
    foreach ($checkbox in $allFeatures) {
        if ($checkbox.Checked) {
            $feature = $checkbox.Tag
            $selectedFeatures[$feature.Key] = $feature
        }
    }

    # Get every unique policy key across all features
    $uniqueKeys = $allFeatures | ForEach-Object { $_.Tag.Key } | Select-Object -Unique

    foreach ($key in $uniqueKeys) {
        if ($selectedFeatures.ContainsKey($key)) {
            $feature = $selectedFeatures[$key]
            try {
                if ($feature.Type -eq "List") {
                    Set-ListPolicy -RegistryPath $registryPath -Name $feature.Key -Values $feature.Value
                    Write-Host "Set $($feature.Key) to [$(($feature.Value) -join ', ')]"
                    # Clear any conflicting user-scope value / subkey so Brave
                    # does not merge machine and user policies.
                    Remove-ListPolicy -RegistryPath $userRegistryPath -Name $feature.Key
                } else {
                    Set-ItemProperty -Path $registryPath -Name $feature.Key -Value $feature.Value -Type $feature.Type -Force
                    Write-Host "Set $($feature.Key) to $($feature.Value)"
                    # When enforcing a machine-level policy, clear any conflicting
                    # user-scope value so Brave does not merge the two.
                    if ((Test-Path -Path $userRegistryPath) -and
                        (Get-ItemProperty -Path $userRegistryPath -Name $key -ErrorAction SilentlyContinue)) {
                        Remove-ItemProperty -Path $userRegistryPath -Name $key -ErrorAction SilentlyContinue
                    }
                }
            } catch {
                Write-Host "Failed to set $($feature.Key): $_"
            }
        } else {
            # Remove the policy from both machine and user scopes so
            # Brave falls back to its built-in default. Remove-ListPolicy
            # handles both REG_SZ values and list subkeys, so it is safe to
            # call without knowing the feature's Type here.
            try {
                Remove-ListPolicy -RegistryPath $registryPath -Name $key
                Remove-ListPolicy -RegistryPath $userRegistryPath -Name $key
                Write-Host "Removed $key"
            } catch {
                Write-Host "Failed to remove ${key}: $_"
            }
        }
    }

    # DNS settings. "unmanaged" removes the DNS policies from both scopes
    # so Brave's own DNS settings stay user-controlled; every other mode is
    # written as managed policy.
    if ($dnsDropdown.SelectedItem -eq "unmanaged") {
        foreach ($scope in @($registryPath, $userRegistryPath)) {
            if (Test-Path -Path $scope) {
                Remove-ItemProperty -Path $scope -Name "DnsOverHttpsMode" -ErrorAction SilentlyContinue
                Remove-ItemProperty -Path $scope -Name "DnsOverHttpsTemplates" -ErrorAction SilentlyContinue
            }
        }
    } elseif ($dnsDropdown.SelectedItem) {
        $dnsUpdated = Set-DnsSettings -dnsMode $dnsDropdown.SelectedItem -dnsTemplates $dnsTemplateBox.Text
        if (-not $dnsUpdated) {
            return
        }
    }

    # Scrub Chromium's per-URL pref leak (BraveShieldsDisabledForUrls writes
    # exceptions into the user profile that survive policy removal).
    $repair = Repair-BravePrefs

    $procExe = "$($browserDef.ProcessName).exe"
    $msg = "Settings applied successfully! Restart $browserLabel to see changes."
    if ($repair.Removed -gt 0) {
        $plural = if ($repair.Removed -ne 1) { "s" } else { "" }
        $msg = "Settings applied. Cleaned $($repair.Removed) leaked profile pref$plural. Restart $browserLabel to see changes."
    }
    if ($repair.Running) {
        $msg += "`n`n$browserLabel is running. Fully close it (taskkill /IM $procExe /F or end all $procExe in Task Manager) before reopening, or the changes may not stick."
    }

    [System.Windows.Forms.MessageBox]::Show(
        $msg,
        "SlimBrave Neo",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information
    )
})

# ---------------------------------------------------------------------------
# Reset
# ---------------------------------------------------------------------------

function Reset-AllSettings {
    $confirm = [System.Windows.Forms.MessageBox]::Show(
        "Warning: This will erase ALL $browserLabel policy settings and restore them to their default state. Do you wish to continue?",
        "Confirm SlimBrave Neo Reset",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Warning
    )

    if ($confirm -eq "Yes") {
        try {
            if (Test-Path -Path $registryPath) {
                Remove-Item -Path $registryPath -Recurse -Force
            }
            if (Test-Path -Path $userRegistryPath) {
                Remove-Item -Path $userRegistryPath -Recurse -Force
            }
            New-Item -Path $registryPath -Force | Out-Null

            # Scrub the per-URL exceptions Brave caches in the user profile.
            # Without this, "Disable Brave Shields" leaves shields stuck off
            # even after the registry policy is gone.
            $repair = Repair-BravePrefs

            $msg = "All Brave policy settings have been successfully reset to their default values."
            if ($repair.Removed -gt 0) {
                $plural = if ($repair.Removed -ne 1) { "s" } else { "" }
                $msg += "`n`nAlso cleaned $($repair.Removed) leaked profile pref$plural that previous SlimBrave versions wrote to your Brave profile."
            }
            if ($repair.Running) {
                $msg += "`n`n$browserLabel is running. Fully close it (Task Manager: end all $($browserDef.ProcessName).exe) before reopening for the reset to take effect."
            }

            [System.Windows.Forms.MessageBox]::Show(
                $msg,
                "Reset Successful",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
            return $true
        } catch {
            [System.Windows.Forms.MessageBox]::Show(
                "An error occurred while resetting the settings: $_",
                "Reset Failed",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
            return $false
        }
    }

    return $false
}

$resetButton.Add_Click({
    if (Reset-AllSettings) {
        if (-not (Test-Path -Path $registryPath)) {
            New-Item -Path $registryPath -Force | Out-Null
        }
        # Uncheck all boxes and reset DNS controls
        foreach ($checkbox in $allFeatures) {
            $checkbox.Checked = $false
        }
        $dnsDropdown.SelectedItem = "unmanaged"
        $dnsTemplateBox.Text = ""
        $dnsTemplateBox.Enabled = $false
    }
})

# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

$exportButton.Add_Click({
    $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveFileDialog.Filter = "JSON files (*.json)|*.json|All files (*.*)|*.*"
    $saveFileDialog.Title = "Export SlimBrave Neo Settings"
    $saveFileDialog.InitialDirectory = [Environment]::GetFolderPath("MyDocuments")
    $saveFileDialog.FileName = "SlimBraveNeoSettings.json"

    if ($saveFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        # New key-value map format so multi-value policies (e.g.
        # IncognitoModeAvailability: 1 vs 2) survive a round-trip.
        $featureMap = [ordered]@{}
        foreach ($checkbox in $allFeatures) {
            if ($checkbox.Checked) {
                $featureMap[$checkbox.Tag.Key] = $checkbox.Tag.Value
            }
        }

        # DnsMode is omitted when DNS is unmanaged, so importing the file
        # (on any platform) lands back on "unmanaged" instead of forcing a
        # managed DNS policy. The template only matters for custom/secure.
        $settingsToExport = [ordered]@{
            Browser  = $Browser
            Features = $featureMap
        }
        $dnsMode = $dnsDropdown.SelectedItem
        if ($dnsMode -and $dnsMode -ne "unmanaged") {
            $settingsToExport["DnsMode"] = $dnsMode
            if (($dnsMode -eq "custom" -or $dnsMode -eq "secure") -and
                -not [string]::IsNullOrWhiteSpace($dnsTemplateBox.Text)) {
                $settingsToExport["DnsTemplates"] = $dnsTemplateBox.Text
            }
        }

        try {
            # -Depth 5 covers Features -> key -> list values (Shields).
            $settingsToExport | ConvertTo-Json -Depth 5 | Out-File -FilePath $saveFileDialog.FileName -Force
            [System.Windows.Forms.MessageBox]::Show(
                "Settings exported successfully to:`n$($saveFileDialog.FileName)",
                "Export Successful",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
        } catch {
            [System.Windows.Forms.MessageBox]::Show(
                "Failed to export settings: $_",
                "Export Failed",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
        }
    }
})

# ---------------------------------------------------------------------------
# Import
# ---------------------------------------------------------------------------

$importButton.Add_Click({
    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.Filter = "JSON files (*.json)|*.json|All files (*.*)|*.*"
    $openFileDialog.Title = "Import SlimBrave Neo Settings"
    $openFileDialog.InitialDirectory = [Environment]::GetFolderPath("MyDocuments")

    if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        try {
            $importedSettings = Get-Content -Path $openFileDialog.FileName -Raw | ConvertFrom-Json

            $declared = "$($importedSettings.Browser)".ToLower()
            if ($declared -and $declared -ne $Browser) {
                [System.Windows.Forms.MessageBox]::Show(
                    "This config targets '$declared' but SlimBrave Neo is managing '$Browser'.`nRelaunch with:  .\SlimBrave.ps1 -Browser $declared",
                    "Wrong Browser",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                )
                return
            }

            # Uncheck everything first
            foreach ($checkbox in $allFeatures) {
                $checkbox.Checked = $false
            }

            $features = $importedSettings.Features
            if ($features -is [array]) {
                # Legacy pre-2026 array format. Only the first row per key
                # wins to preserve intent for multi-value keys (avoids
                # silently force-incognitoing users whose old export
                # listed IncognitoModeAvailability).
                $handled = @{}
                foreach ($featureKey in $features) {
                    if ($handled.ContainsKey($featureKey)) { continue }
                    foreach ($checkbox in $allFeatures) {
                        if ($checkbox.Tag.Key -eq $featureKey) {
                            $checkbox.Checked = $true
                            $handled[$featureKey] = $true
                            break
                        }
                    }
                }
            } elseif ($null -ne $features) {
                # New dict format — PSCustomObject with key-value pairs.
                foreach ($prop in $features.PSObject.Properties) {
                    foreach ($checkbox in $allFeatures) {
                        if ($checkbox.Tag.Key -eq $prop.Name -and
                            (Test-FeatureValueMatches $checkbox.Tag $prop.Value)) {
                            $checkbox.Checked = $true
                        }
                    }
                }
            }

            # DNS: a file with no DnsMode means DNS is unmanaged (a bare
            # DnsTemplates is treated as custom for legacy exports).
            if ($importedSettings.DnsMode) {
                $dnsDropdown.SelectedItem = $importedSettings.DnsMode
            } elseif ($importedSettings.DnsTemplates) {
                $dnsDropdown.SelectedItem = "custom"
            } else {
                $dnsDropdown.SelectedItem = "unmanaged"
            }
            $dnsTemplateBox.Text = if ($importedSettings.DnsTemplates) {
                $importedSettings.DnsTemplates
            } else {
                ""
            }

            [System.Windows.Forms.MessageBox]::Show(
                "Settings imported successfully from:`n$($openFileDialog.FileName)",
                "Import Successful",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
        } catch {
            [System.Windows.Forms.MessageBox]::Show(
                "Failed to import settings: $_",
                "Import Failed",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
        }
    }
})

# ---------------------------------------------------------------------------
# Initialize - read current registry and pre-check matching features on startup
# ---------------------------------------------------------------------------

function Initialize-CurrentSettings {
    # Read from both machine (HKLM) and user (HKCU) policy scopes.
    # Machine scope takes precedence; user scope is a fallback.
    $machineSettings = Get-ItemProperty -Path $registryPath -ErrorAction SilentlyContinue
    $userSettings    = Get-ItemProperty -Path $userRegistryPath -ErrorAction SilentlyContinue

    foreach ($checkbox in $allFeatures) {
        $feature = $checkbox.Tag
        if ($feature.Type -eq "List") {
            $checkbox.Checked =
                (Test-ListPolicyMatches -RegistryPath $registryPath     -Name $feature.Key -Expected $feature.Value) -or
                (Test-ListPolicyMatches -RegistryPath $userRegistryPath -Name $feature.Key -Expected $feature.Value)
            continue
        }
        $currentValue = $null
        if ($machineSettings -and ($machineSettings.PSObject.Properties.Name -contains $feature.Key)) {
            $currentValue = $machineSettings.$($feature.Key)
        } elseif ($userSettings -and ($userSettings.PSObject.Properties.Name -contains $feature.Key)) {
            $currentValue = $userSettings.$($feature.Key)
        }

        if ($null -ne $currentValue) {
            if ($feature.Type -eq "DWord") {
                $checkbox.Checked = ([int]$currentValue -eq [int]$feature.Value)
            } else {
                $checkbox.Checked = ($currentValue.ToString() -eq $feature.Value.ToString())
            }
        } else {
            $checkbox.Checked = $false
        }
    }

    # DNS settings
    if ($machineSettings -or $userSettings) {
        $currentDnsMode = $null
        $currentDnsTemplates = $null
        if ($machineSettings -and ($machineSettings.PSObject.Properties.Name -contains "DnsOverHttpsMode")) {
            $currentDnsMode = $machineSettings.DnsOverHttpsMode
        } elseif ($userSettings -and ($userSettings.PSObject.Properties.Name -contains "DnsOverHttpsMode")) {
            $currentDnsMode = $userSettings.DnsOverHttpsMode
        }
        if ($machineSettings -and ($machineSettings.PSObject.Properties.Name -contains "DnsOverHttpsTemplates")) {
            $currentDnsTemplates = $machineSettings.DnsOverHttpsTemplates
        } elseif ($userSettings -and ($userSettings.PSObject.Properties.Name -contains "DnsOverHttpsTemplates")) {
            $currentDnsTemplates = $userSettings.DnsOverHttpsTemplates
        }

        if (-not [string]::IsNullOrWhiteSpace($currentDnsTemplates)) {
            $dnsDropdown.SelectedItem = "custom"
            $dnsTemplateBox.Text = $currentDnsTemplates
        } elseif (-not [string]::IsNullOrWhiteSpace($currentDnsMode)) {
            $dnsDropdown.SelectedItem = $currentDnsMode
        } else {
            $dnsDropdown.SelectedItem = "unmanaged"
        }
    } else {
        $dnsDropdown.SelectedItem = "unmanaged"
    }

    $dnsTemplateBox.Enabled = ($dnsDropdown.SelectedItem -in @("custom", "secure"))
}

Initialize-CurrentSettings

# Safety net: on a display so short that even the three-column layout is a
# little taller than the working area, cap the height and enable scrolling so
# the buttons stay reachable. A no-op whenever the form already fits (the
# common case), so normal displays never get a scrollbar.
$form.AutoScroll = $true
$workingAreaHeight = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea.Height
if ($form.Height -gt $workingAreaHeight) {
    $form.Height = $workingAreaHeight
    $form.Width  = $form.Width + [System.Windows.Forms.SystemInformation]::VerticalScrollBarWidth
}

[void] $form.ShowDialog()
