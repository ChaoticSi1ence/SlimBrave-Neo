if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    # Carry -ExecutionPolicy Bypass into the elevated instance: the user
    # often launches via "powershell -ExecutionPolicy Bypass -File ..." and
    # the relaunch would otherwise revert to the machine default policy and
    # silently fail to start.
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`"" -Verb RunAs
    exit
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$machineRegistryPath = "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave"
$userRegistryPath   = "HKCU:\SOFTWARE\Policies\BraveSoftware\Brave"
$registryPath       = $machineRegistryPath

if (-not (Test-Path -Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}

Clear-Host

# ---------------------------------------------------------------------------
# DNS helper - handles both DnsOverHttpsMode and DnsOverHttpsTemplates
# ---------------------------------------------------------------------------

function Set-DnsSettings {
    param (
        [string] $dnsMode,
        [string] $dnsTemplates
    )
    $regKey = "HKLM:\Software\Policies\BraveSoftware\Brave"
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
    } else {
        # Remove the templates key if not using custom
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
    while the policy was active (Default, Profile 1, Profile 2, ...), so
    every profile directory is scrubbed, not just Default.

    Returns a hashtable @{ Removed = N; Running = $true/$false }.
    Safe to call when files or keys do not exist.
    #>
    $running = ($null -ne (Get-Process brave -ErrorAction SilentlyContinue))
    $userData = Join-Path $env:LOCALAPPDATA "BraveSoftware\Brave-Browser\User Data"
    if (-not (Test-Path $userData)) { return @{ Removed = 0; Running = $running } }

    $removed = 0
    $profileDirs = Get-ChildItem -Path $userData -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' }
    foreach ($dir in $profileDirs) {
        $removed += Repair-OneBravePrefs (Join-Path $dir.FullName 'Preferences')
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
# Form setup
# ---------------------------------------------------------------------------

$form = New-Object System.Windows.Forms.Form
$form.Text = "SlimBrave Neo"
$form.ForeColor = [System.Drawing.Color]::White
$form.Size = New-Object System.Drawing.Size(755, 980)
$form.StartPosition = "CenterScreen"
$form.BackColor = [System.Drawing.Color]::FromArgb(255, 25, 25, 25)
$form.MaximizeBox = $false
$form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog

$allFeatures = @()

# ---------------------------------------------------------------------------
# Left panel - Telemetry & Privacy
# ---------------------------------------------------------------------------

$leftPanel = New-Object System.Windows.Forms.Panel
$leftPanel.Location = New-Object System.Drawing.Point(20, 20)
$leftPanel.Size = New-Object System.Drawing.Size(340, 785)
$leftPanel.BackColor = [System.Drawing.Color]::FromArgb(255, 35, 35, 35)
$leftPanel.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$form.Controls.Add($leftPanel)

$telemetryLabel = New-Object System.Windows.Forms.Label
$telemetryLabel.Text = "Telemetry & Reporting"
$telemetryLabel.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 10.5, [System.Drawing.FontStyle]::Bold)
$telemetryLabel.Location = New-Object System.Drawing.Point(28, 10)
$telemetryLabel.Size = New-Object System.Drawing.Size(300, 20)
$telemetryLabel.ForeColor = [System.Drawing.Color]::LightSalmon
$leftPanel.Controls.Add($telemetryLabel)

$telemetryFeatures = @(
    @{ Name = "Disable Metrics Reporting"; Key = "MetricsReportingEnabled"; Value = 0; Type = "DWord" },
    @{ Name = "Disable Safe Browsing Reporting"; Key = "SafeBrowsingExtendedReportingEnabled"; Value = 0; Type = "DWord" },
    @{ Name = "Disable URL Data Collection"; Key = "UrlKeyedAnonymizedDataCollectionEnabled"; Value = 0; Type = "DWord" },
    @{ Name = "Disable P3A Analytics"; Key = "BraveP3AEnabled"; Value = 0; Type = "DWord" },
    @{ Name = "Disable Stats Ping"; Key = "BraveStatsPingEnabled"; Value = 0; Type = "DWord" }
)

$y = 35
foreach ($feature in $telemetryFeatures) {
    $checkbox = New-Object System.Windows.Forms.CheckBox
    $checkbox.Text = $feature.Name
    $checkbox.Tag = $feature
    $checkbox.Location = New-Object System.Drawing.Point(30, $y)
    $checkbox.Size = New-Object System.Drawing.Size(300, 20)
    $checkbox.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $leftPanel.Controls.Add($checkbox)
    $allFeatures += $checkbox
    $y += 25
}

$y += 10

$privacyLabel = New-Object System.Windows.Forms.Label
$privacyLabel.Text = "Privacy & Security"
$privacyLabel.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 11, [System.Drawing.FontStyle]::Bold)
$privacyLabel.Location = New-Object System.Drawing.Point(28, $y)
$privacyLabel.Size = New-Object System.Drawing.Size(300, 20)
$privacyLabel.ForeColor = [System.Drawing.Color]::LightSalmon
$leftPanel.Controls.Add($privacyLabel)
$y += 25

$privacyFeatures = @(
    @{ Name = "Disable Safe Browsing"; Key = "SafeBrowsingProtectionLevel"; Value = 0; Type = "DWord" },
    @{ Name = "Disable Autofill (Addresses)"; Key = "AutofillAddressEnabled"; Value = 0; Type = "DWord" },
    @{ Name = "Disable Autofill (Credit Cards)"; Key = "AutofillCreditCardEnabled"; Value = 0; Type = "DWord" },
    @{ Name = "Disable Password Manager"; Key = "PasswordManagerEnabled"; Value = 0; Type = "DWord" },
    @{ Name = "Disable Browser Sign-in"; Key = "BrowserSignin"; Value = 0; Type = "DWord" },
    @{ Name = "Enable Global Privacy Control"; Key = "BraveGlobalPrivacyControlEnabled"; Value = 1; Type = "DWord" },
    @{ Name = "Enable De-AMP"; Key = "BraveDeAmpEnabled"; Value = 1; Type = "DWord" },
    @{ Name = "Enable Debouncing"; Key = "BraveDebouncingEnabled"; Value = 1; Type = "DWord" },
    @{ Name = "Strip Tracking URL Parameters"; Key = "BraveTrackingQueryParametersFilteringEnabled"; Value = 1; Type = "DWord" },
    @{ Name = "Reduce Language Fingerprinting"; Key = "BraveReduceLanguageEnabled"; Value = 1; Type = "DWord" },
    @{ Name = "Disable WebRTC IP Leak"; Key = "WebRtcIPHandling"; Value = "disable_non_proxied_udp"; Type = "String" },
    @{ Name = "Disable QUIC Protocol"; Key = "QuicAllowed"; Value = 0; Type = "DWord" },
    @{ Name = "Block Third Party Cookies"; Key = "BlockThirdPartyCookies"; Value = 1; Type = "DWord" },
    @{ Name = "Force Google SafeSearch"; Key = "ForceGoogleSafeSearch"; Value = 1; Type = "DWord" },
    @{ Name = "Disable Incognito Mode"; Key = "IncognitoModeAvailability"; Value = 1; Type = "DWord"; Group = "incognito" },
    @{ Name = "Force Incognito Mode"; Key = "IncognitoModeAvailability"; Value = 2; Type = "DWord"; Group = "incognito" }
)

foreach ($feature in $privacyFeatures) {
    $checkbox = New-Object System.Windows.Forms.CheckBox
    $checkbox.Text = $feature.Name
    $checkbox.Tag = $feature
    $checkbox.Location = New-Object System.Drawing.Point(30, $y)
    $checkbox.Size = New-Object System.Drawing.Size(300, 20)
    $checkbox.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $leftPanel.Controls.Add($checkbox)
    $allFeatures += $checkbox
    $y += 25
}

$y += 10

$shieldsLabel = New-Object System.Windows.Forms.Label
$shieldsLabel.Text = "Shields & Content Protection"
$shieldsLabel.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 11, [System.Drawing.FontStyle]::Bold)
$shieldsLabel.Location = New-Object System.Drawing.Point(28, $y)
$shieldsLabel.Size = New-Object System.Drawing.Size(300, 20)
$shieldsLabel.ForeColor = [System.Drawing.Color]::LightSalmon
$leftPanel.Controls.Add($shieldsLabel)
$y += 25

# Brave 1.83+ content-protection enforcers. These pin Brave's own privacy
# defaults as managed policy so neither the user nor a malicious
# page/extension can quietly weaken them.
$shieldsContentFeatures = @(
    @{ Name = "Enforce Ad Blocking"; Key = "DefaultBraveAdblockSetting"; Value = 2; Type = "DWord" },
    @{ Name = "Enforce Fingerprinting Protection"; Key = "DefaultBraveFingerprintingV2Setting"; Value = 3; Type = "DWord" },
    @{ Name = "Force HTTPS Upgrades (Strict)"; Key = "DefaultBraveHttpsUpgradeSetting"; Value = 2; Type = "DWord" },
    @{ Name = "Cap Referrers (Strict Origin)"; Key = "DefaultBraveReferrersSetting"; Value = 2; Type = "DWord"; Group = "referrers" },
    @{ Name = "Allow Permissive Referrers (unsafe-url)"; Key = "DefaultBraveReferrersSetting"; Value = 1; Type = "DWord"; Group = "referrers" },
    @{ Name = "Forget First-Party Storage on Close"; Key = "DefaultBraveRemember1PStorageSetting"; Value = 2; Type = "DWord" }
)

foreach ($feature in $shieldsContentFeatures) {
    $checkbox = New-Object System.Windows.Forms.CheckBox
    $checkbox.Text = $feature.Name
    $checkbox.Tag = $feature
    $checkbox.Location = New-Object System.Drawing.Point(30, $y)
    $checkbox.Size = New-Object System.Drawing.Size(300, 20)
    $checkbox.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $leftPanel.Controls.Add($checkbox)
    $allFeatures += $checkbox
    $y += 25
}

# ---------------------------------------------------------------------------
# Right panel - Brave Features & Performance
# ---------------------------------------------------------------------------

$rightPanel = New-Object System.Windows.Forms.Panel
$rightPanel.Location = New-Object System.Drawing.Point(380, 20)
$rightPanel.Size = New-Object System.Drawing.Size(340, 785)
$rightPanel.BackColor = [System.Drawing.Color]::FromArgb(255, 35, 35, 35)
$rightPanel.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$form.Controls.Add($rightPanel)

$y = 5

$braveLabel = New-Object System.Windows.Forms.Label
$braveLabel.Text = "Brave Features"
$braveLabel.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 11, [System.Drawing.FontStyle]::Bold)
$braveLabel.Location = New-Object System.Drawing.Point(28, $y)
$braveLabel.Size = New-Object System.Drawing.Size(300, 20)
$braveLabel.ForeColor = [System.Drawing.Color]::LightSalmon
$rightPanel.Controls.Add($braveLabel)
$y += 25

$braveFeatures = @(
    @{ Name = "Disable Brave Rewards"; Key = "BraveRewardsDisabled"; Value = 1; Type = "DWord" },
    @{ Name = "Disable Brave Wallet"; Key = "BraveWalletDisabled"; Value = 1; Type = "DWord" },
    @{ Name = "Disable Brave VPN"; Key = "BraveVPNDisabled"; Value = 1; Type = "DWord" },
    @{ Name = "Disable Brave AI Chat"; Key = "BraveAIChatEnabled"; Value = 0; Type = "DWord" },
    @{ Name = "Disable Brave Shields"; Key = "BraveShieldsDisabledForUrls"; Value = @("https://*", "http://*"); Type = "List"; Group = "shields" },
    @{ Name = "Force Shields On (All Sites)"; Key = "BraveShieldsEnabledForUrls"; Value = @("https://*", "http://*"); Type = "List"; Group = "shields" },
    @{ Name = "Disable Brave News"; Key = "BraveNewsDisabled"; Value = 1; Type = "DWord" },
    @{ Name = "Disable Brave Talk"; Key = "BraveTalkDisabled"; Value = 1; Type = "DWord" },
    @{ Name = "Disable Brave Playlist"; Key = "BravePlaylistEnabled"; Value = 0; Type = "DWord" },
    @{ Name = "Disable Web Discovery"; Key = "BraveWebDiscoveryEnabled"; Value = 0; Type = "DWord" },
    @{ Name = "Disable Speedreader"; Key = "BraveSpeedreaderEnabled"; Value = 0; Type = "DWord" },
    @{ Name = "Disable Tor"; Key = "TorDisabled"; Value = 1; Type = "DWord" },
    @{ Name = "Disable Sync"; Key = "SyncDisabled"; Value = 1; Type = "DWord" },
    @{ Name = "Disable Email Aliases"; Key = "EmailAliasesEnabled"; Value = 0; Type = "DWord" }
)

foreach ($feature in $braveFeatures) {
    $checkbox = New-Object System.Windows.Forms.CheckBox
    $checkbox.Text = $feature.Name
    $checkbox.Tag = $feature
    $checkbox.Location = New-Object System.Drawing.Point(30, $y)
    $checkbox.Size = New-Object System.Drawing.Size(300, 20)
    $checkbox.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $rightPanel.Controls.Add($checkbox)
    $allFeatures += $checkbox
    $y += 25
}

$y += 10

$perfLabel = New-Object System.Windows.Forms.Label
$perfLabel.Text = "Performance & Bloat"
$perfLabel.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 11, [System.Drawing.FontStyle]::Bold)
$perfLabel.Location = New-Object System.Drawing.Point(28, $y)
$perfLabel.Size = New-Object System.Drawing.Size(300, 20)
$perfLabel.ForeColor = [System.Drawing.Color]::LightSalmon
$rightPanel.Controls.Add($perfLabel)
$y += 25

$perfFeatures = @(
    @{ Name = "Disable Background Mode"; Key = "BackgroundModeEnabled"; Value = 0; Type = "DWord" },
    @{ Name = "Disable Shopping List"; Key = "ShoppingListEnabled"; Value = 0; Type = "DWord" },
    @{ Name = "Always Open PDF Externally"; Key = "AlwaysOpenPdfExternally"; Value = 1; Type = "DWord" },
    @{ Name = "Disable Translate"; Key = "TranslateEnabled"; Value = 0; Type = "DWord" },
    @{ Name = "Disable Spellcheck"; Key = "SpellcheckEnabled"; Value = 0; Type = "DWord" },
    @{ Name = "Disable Search Suggestions"; Key = "SearchSuggestEnabled"; Value = 0; Type = "DWord" },
    @{ Name = "Disable Printing"; Key = "PrintingEnabled"; Value = 0; Type = "DWord" },
    @{ Name = "Disable Default Browser Prompt"; Key = "DefaultBrowserSettingEnabled"; Value = 0; Type = "DWord" },
    @{ Name = "Disable Developer Tools"; Key = "DeveloperToolsAvailability"; Value = 2; Type = "DWord" },
    @{ Name = "Disable Wayback Machine"; Key = "BraveWaybackMachineEnabled"; Value = 0; Type = "DWord" }
)

foreach ($feature in $perfFeatures) {
    $checkbox = New-Object System.Windows.Forms.CheckBox
    $checkbox.Text = $feature.Name
    $checkbox.Tag = $feature
    $checkbox.Location = New-Object System.Drawing.Point(30, $y)
    $checkbox.Size = New-Object System.Drawing.Size(300, 20)
    $checkbox.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $rightPanel.Controls.Add($checkbox)
    $allFeatures += $checkbox
    $y += 25
}

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
$dnsLabel.Location = New-Object System.Drawing.Point(35, 825)
$dnsLabel.Size = New-Object System.Drawing.Size(140, 20)
$form.Controls.Add($dnsLabel)

$dnsDropdown = New-Object System.Windows.Forms.ComboBox
$dnsDropdown.Location = New-Object System.Drawing.Point(180, 820)
$dnsDropdown.Size = New-Object System.Drawing.Size(150, 20)
# "unmanaged" (the default) writes no DNS policy at all, leaving Brave's
# DNS settings user-controlled. The other four are managed-policy values —
# including "off", which actively force-disables DoH as policy.
$dnsDropdown.Items.AddRange(@("unmanaged", "off", "automatic", "secure", "custom"))
$dnsDropdown.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$dnsDropdown.BackColor = [System.Drawing.Color]::FromArgb(255, 25, 25, 25)
$dnsDropdown.ForeColor = [System.Drawing.Color]::White
$form.Controls.Add($dnsDropdown)

$dnsTemplateLabel = New-Object System.Windows.Forms.Label
$dnsTemplateLabel.Text = "Custom DoH template URL:"
$dnsTemplateLabel.Location = New-Object System.Drawing.Point(35, 855)
$dnsTemplateLabel.Size = New-Object System.Drawing.Size(170, 20)
$form.Controls.Add($dnsTemplateLabel)

$dnsTemplateBox = New-Object System.Windows.Forms.TextBox
$dnsTemplateBox.Location = New-Object System.Drawing.Point(210, 855)
$dnsTemplateBox.Size = New-Object System.Drawing.Size(510, 20)
$dnsTemplateBox.BackColor = [System.Drawing.Color]::FromArgb(255, 25, 25, 25)
$dnsTemplateBox.ForeColor = [System.Drawing.Color]::White
$dnsTemplateBox.Enabled = $false
$form.Controls.Add($dnsTemplateBox)

$dnsDropdown.Add_SelectedIndexChanged({
    $dnsTemplateBox.Enabled = ($dnsDropdown.SelectedItem -eq "custom")
})

# ---------------------------------------------------------------------------
# Buttons
# ---------------------------------------------------------------------------

$exportButton = New-Object System.Windows.Forms.Button
$exportButton.Text = "Export Settings"
$exportButton.Location = New-Object System.Drawing.Point(50, 895)
$exportButton.Size = New-Object System.Drawing.Size(120, 30)
$form.Controls.Add($exportButton)
$exportButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$exportButton.FlatAppearance.BorderSize = 1
$exportButton.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(120, 120, 120)
$exportButton.BackColor = [System.Drawing.Color]::FromArgb(150, 102, 102, 102)
$exportButton.ForeColor = [System.Drawing.Color]::LightSalmon

$importButton = New-Object System.Windows.Forms.Button
$importButton.Text = "Import Settings"
$importButton.Location = New-Object System.Drawing.Point(210, 895)
$importButton.Size = New-Object System.Drawing.Size(120, 30)
$form.Controls.Add($importButton)
$importButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$importButton.FlatAppearance.BorderSize = 1
$importButton.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(120, 120, 120)
$importButton.BackColor = [System.Drawing.Color]::FromArgb(150, 102, 102, 102)
$importButton.ForeColor = [System.Drawing.Color]::LightSkyBlue

$saveButton = New-Object System.Windows.Forms.Button
$saveButton.Text = "Apply Settings"
$saveButton.Location = New-Object System.Drawing.Point(410, 895)
$saveButton.Size = New-Object System.Drawing.Size(120, 30)
$form.Controls.Add($saveButton)
$saveButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$saveButton.FlatAppearance.BorderSize = 1
$saveButton.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(120, 120, 120)
$saveButton.BackColor = [System.Drawing.Color]::FromArgb(150, 102, 102, 102)
$saveButton.ForeColor = [System.Drawing.Color]::LightGreen

$resetButton = New-Object System.Windows.Forms.Button
$resetButton.Text = "Reset All Settings"
$resetButton.Location = New-Object System.Drawing.Point(570, 895)
$resetButton.Size = New-Object System.Drawing.Size(120, 30)
$form.Controls.Add($resetButton)
$resetButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$resetButton.FlatAppearance.BorderSize = 1
$resetButton.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(120, 120, 120)
$resetButton.BackColor = [System.Drawing.Color]::FromArgb(150, 102, 102, 102)
$resetButton.ForeColor = [System.Drawing.Color]::LightCoral

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

    $msg = "Settings applied successfully! Restart Brave to see changes."
    if ($repair.Removed -gt 0) {
        $plural = if ($repair.Removed -ne 1) { "s" } else { "" }
        $msg = "Settings applied. Cleaned $($repair.Removed) leaked profile pref$plural. Restart Brave to see changes."
    }
    if ($repair.Running) {
        $msg += "`n`nBrave is running. Fully close it (taskkill /IM brave.exe /F or end all brave.exe in Task Manager) before reopening, or the changes may not stick."
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
        "Warning: This will erase ALL Brave policy settings and restore them to their default state. Do you wish to continue?",
        "Confirm SlimBrave Neo Reset",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Warning
    )

    if ($confirm -eq "Yes") {
        try {
            Remove-Item -Path $registryPath -Recurse -Force
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
                $msg += "`n`nBrave is running. Fully close it (Task Manager: end all brave.exe) before reopening for the reset to take effect."
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

    $dnsTemplateBox.Enabled = ($dnsDropdown.SelectedItem -eq "custom")
}

Initialize-CurrentSettings

[void] $form.ShowDialog()
