if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell -ArgumentList "-File `"$($MyInvocation.MyCommand.Path)`"" -Verb RunAs
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
                "自定义 DoH 需要提供模板 URL（例如 https://cloudflare-dns.com/dns-query）。",
                "缺少 DoH 模板",
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
$form.Size = New-Object System.Drawing.Size(755, 900)
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
$leftPanel.Size = New-Object System.Drawing.Size(340, 650)
$leftPanel.BackColor = [System.Drawing.Color]::FromArgb(255, 35, 35, 35)
$leftPanel.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$form.Controls.Add($leftPanel)

$telemetryLabel = New-Object System.Windows.Forms.Label
$telemetryLabel.Text = "遥测与报告"
$telemetryLabel.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 10.5, [System.Drawing.FontStyle]::Bold)
$telemetryLabel.Location = New-Object System.Drawing.Point(28, 10)
$telemetryLabel.Size = New-Object System.Drawing.Size(300, 20)
$telemetryLabel.ForeColor = [System.Drawing.Color]::LightSalmon
$leftPanel.Controls.Add($telemetryLabel)

$telemetryFeatures = @(
    @{ Name = "禁用指标上报"; Key = "MetricsReportingEnabled"; Value = 0; Type = "DWord" },
    @{ Name = "禁用安全浏览报告上报"; Key = "SafeBrowsingExtendedReportingEnabled"; Value = 0; Type = "DWord" },
    @{ Name = "禁用 URL 匿名化数据收集"; Key = "UrlKeyedAnonymizedDataCollectionEnabled"; Value = 0; Type = "DWord" },
    @{ Name = "禁用 P3A 分析"; Key = "BraveP3AEnabled"; Value = 0; Type = "DWord" },
    @{ Name = "禁用统计心跳（Stats Ping）"; Key = "BraveStatsPingEnabled"; Value = 0; Type = "DWord" }
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
$privacyLabel.Text = "隐私与安全"
$privacyLabel.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 11, [System.Drawing.FontStyle]::Bold)
$privacyLabel.Location = New-Object System.Drawing.Point(28, $y)
$privacyLabel.Size = New-Object System.Drawing.Size(300, 20)
$privacyLabel.ForeColor = [System.Drawing.Color]::LightSalmon
$leftPanel.Controls.Add($privacyLabel)
$y += 25

$privacyFeatures = @(
    @{ Name = "禁用安全浏览"; Key = "SafeBrowsingProtectionLevel"; Value = 0; Type = "DWord" },
    @{ Name = "禁用自动填充（地址）"; Key = "AutofillAddressEnabled"; Value = 0; Type = "DWord" },
    @{ Name = "禁用自动填充（信用卡）"; Key = "AutofillCreditCardEnabled"; Value = 0; Type = "DWord" },
    @{ Name = "禁用密码管理器"; Key = "PasswordManagerEnabled"; Value = 0; Type = "DWord" },
    @{ Name = "禁用浏览器登录"; Key = "BrowserSignin"; Value = 0; Type = "DWord" },
    @{ Name = "启用“请勿跟踪”"; Key = "EnableDoNotTrack"; Value = 1; Type = "DWord" },
    @{ Name = "启用全局隐私控制（GPC）"; Key = "BraveGlobalPrivacyControlEnabled"; Value = 1; Type = "DWord" },
    @{ Name = "启用 De-AMP（移除 AMP 包装）"; Key = "BraveDeAmpEnabled"; Value = 1; Type = "DWord" },
    @{ Name = "启用去跳转追踪（Debouncing）"; Key = "BraveDebouncingEnabled"; Value = 1; Type = "DWord" },
    @{ Name = "移除跟踪型 URL 参数"; Key = "BraveTrackingQueryParametersFilteringEnabled"; Value = 1; Type = "DWord" },
    @{ Name = "降低语言指纹"; Key = "BraveReduceLanguageEnabled"; Value = 1; Type = "DWord" },
    @{ Name = "防止 WebRTC IP 泄漏"; Key = "WebRtcIPHandling"; Value = "disable_non_proxied_udp"; Type = "String" },
    @{ Name = "禁用 QUIC 协议"; Key = "QuicAllowed"; Value = 0; Type = "DWord" },
    @{ Name = "阻止第三方 Cookie"; Key = "BlockThirdPartyCookies"; Value = 1; Type = "DWord" },
    @{ Name = "强制 Google 安全搜索（SafeSearch）"; Key = "ForceGoogleSafeSearch"; Value = 1; Type = "DWord" },
    @{ Name = "禁用隐身模式"; Key = "IncognitoModeAvailability"; Value = 1; Type = "DWord"; Group = "incognito" },
    @{ Name = "强制隐身模式"; Key = "IncognitoModeAvailability"; Value = 2; Type = "DWord"; Group = "incognito" }
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

# ---------------------------------------------------------------------------
# Right panel - Brave Features & Performance
# ---------------------------------------------------------------------------

$rightPanel = New-Object System.Windows.Forms.Panel
$rightPanel.Location = New-Object System.Drawing.Point(380, 20)
$rightPanel.Size = New-Object System.Drawing.Size(340, 650)
$rightPanel.BackColor = [System.Drawing.Color]::FromArgb(255, 35, 35, 35)
$rightPanel.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$form.Controls.Add($rightPanel)

$y = 5

$braveLabel = New-Object System.Windows.Forms.Label
$braveLabel.Text = "Brave 功能"
$braveLabel.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 11, [System.Drawing.FontStyle]::Bold)
$braveLabel.Location = New-Object System.Drawing.Point(28, $y)
$braveLabel.Size = New-Object System.Drawing.Size(300, 20)
$braveLabel.ForeColor = [System.Drawing.Color]::LightSalmon
$rightPanel.Controls.Add($braveLabel)
$y += 25

$braveFeatures = @(
    @{ Name = "禁用 Brave Rewards"; Key = "BraveRewardsDisabled"; Value = 1; Type = "DWord" },
    @{ Name = "禁用 Brave Wallet"; Key = "BraveWalletDisabled"; Value = 1; Type = "DWord" },
    @{ Name = "禁用 Brave VPN"; Key = "BraveVPNDisabled"; Value = 1; Type = "DWord" },
    @{ Name = "禁用 Brave AI Chat"; Key = "BraveAIChatEnabled"; Value = 0; Type = "DWord" },
    @{ Name = "禁用 Brave Shields"; Key = "BraveShieldsDisabledForUrls"; Value = @("https://*", "http://*"); Type = "List" },
    @{ Name = "禁用 Brave News"; Key = "BraveNewsDisabled"; Value = 1; Type = "DWord" },
    @{ Name = "禁用 Brave Talk"; Key = "BraveTalkDisabled"; Value = 1; Type = "DWord" },
    @{ Name = "禁用 Brave Playlist"; Key = "BravePlaylistEnabled"; Value = 0; Type = "DWord" },
    @{ Name = "禁用 Web Discovery"; Key = "BraveWebDiscoveryEnabled"; Value = 0; Type = "DWord" },
    @{ Name = "禁用 Speedreader"; Key = "BraveSpeedreaderEnabled"; Value = 0; Type = "DWord" },
    @{ Name = "禁用 Tor"; Key = "TorDisabled"; Value = 1; Type = "DWord" },
    @{ Name = "禁用同步（Sync）"; Key = "SyncDisabled"; Value = 1; Type = "DWord" },
    @{ Name = "禁用 IPFS"; Key = "IPFSEnabled"; Value = 0; Type = "DWord" }
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
$perfLabel.Text = "性能与精简"
$perfLabel.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 11, [System.Drawing.FontStyle]::Bold)
$perfLabel.Location = New-Object System.Drawing.Point(28, $y)
$perfLabel.Size = New-Object System.Drawing.Size(300, 20)
$perfLabel.ForeColor = [System.Drawing.Color]::LightSalmon
$rightPanel.Controls.Add($perfLabel)
$y += 25

$perfFeatures = @(
    @{ Name = "禁用后台模式"; Key = "BackgroundModeEnabled"; Value = 0; Type = "DWord" },
    @{ Name = "禁用购物清单"; Key = "ShoppingListEnabled"; Value = 0; Type = "DWord" },
    @{ Name = "总是外部打开 PDF"; Key = "AlwaysOpenPdfExternally"; Value = 1; Type = "DWord" },
    @{ Name = "禁用翻译"; Key = "TranslateEnabled"; Value = 0; Type = "DWord" },
    @{ Name = "禁用拼写检查"; Key = "SpellcheckEnabled"; Value = 0; Type = "DWord" },
    @{ Name = "禁用搜索建议"; Key = "SearchSuggestEnabled"; Value = 0; Type = "DWord" },
    @{ Name = "禁用打印"; Key = "PrintingEnabled"; Value = 0; Type = "DWord" },
    @{ Name = "禁用默认浏览器提示"; Key = "DefaultBrowserSettingEnabled"; Value = 0; Type = "DWord" },
    @{ Name = "禁用开发者工具"; Key = "DeveloperToolsAvailability"; Value = 2; Type = "DWord" },
    @{ Name = "禁用 Wayback Machine"; Key = "BraveWaybackMachineEnabled"; Value = 0; Type = "DWord" }
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
$dnsLabel.Text = "DNS over HTTPS（DoH）模式："
$dnsLabel.Location = New-Object System.Drawing.Point(35, 735)
$dnsLabel.Size = New-Object System.Drawing.Size(140, 20)
$form.Controls.Add($dnsLabel)

$dnsDropdown = New-Object System.Windows.Forms.ComboBox
$dnsDropdown.Location = New-Object System.Drawing.Point(180, 730)
$dnsDropdown.Size = New-Object System.Drawing.Size(150, 20)
$dnsDropdown.Items.AddRange(@("off", "automatic", "secure", "custom"))
$dnsDropdown.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$dnsDropdown.BackColor = [System.Drawing.Color]::FromArgb(255, 25, 25, 25)
$dnsDropdown.ForeColor = [System.Drawing.Color]::White
$form.Controls.Add($dnsDropdown)

$dnsTemplateLabel = New-Object System.Windows.Forms.Label
$dnsTemplateLabel.Text = "自定义 DoH 模板 URL："
$dnsTemplateLabel.Location = New-Object System.Drawing.Point(35, 765)
$dnsTemplateLabel.Size = New-Object System.Drawing.Size(170, 20)
$form.Controls.Add($dnsTemplateLabel)

$dnsTemplateBox = New-Object System.Windows.Forms.TextBox
$dnsTemplateBox.Location = New-Object System.Drawing.Point(210, 765)
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
$exportButton.Text = "导出设置"
$exportButton.Location = New-Object System.Drawing.Point(50, 810)
$exportButton.Size = New-Object System.Drawing.Size(120, 30)
$form.Controls.Add($exportButton)
$exportButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$exportButton.FlatAppearance.BorderSize = 1
$exportButton.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(120, 120, 120)
$exportButton.BackColor = [System.Drawing.Color]::FromArgb(150, 102, 102, 102)
$exportButton.ForeColor = [System.Drawing.Color]::LightSalmon

$importButton = New-Object System.Windows.Forms.Button
$importButton.Text = "导入设置"
$importButton.Location = New-Object System.Drawing.Point(210, 810)
$importButton.Size = New-Object System.Drawing.Size(120, 30)
$form.Controls.Add($importButton)
$importButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$importButton.FlatAppearance.BorderSize = 1
$importButton.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(120, 120, 120)
$importButton.BackColor = [System.Drawing.Color]::FromArgb(150, 102, 102, 102)
$importButton.ForeColor = [System.Drawing.Color]::LightSkyBlue

$saveButton = New-Object System.Windows.Forms.Button
$saveButton.Text = "应用设置"
$saveButton.Location = New-Object System.Drawing.Point(410, 810)
$saveButton.Size = New-Object System.Drawing.Size(120, 30)
$form.Controls.Add($saveButton)
$saveButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$saveButton.FlatAppearance.BorderSize = 1
$saveButton.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(120, 120, 120)
$saveButton.BackColor = [System.Drawing.Color]::FromArgb(150, 102, 102, 102)
$saveButton.ForeColor = [System.Drawing.Color]::LightGreen

$resetButton = New-Object System.Windows.Forms.Button
$resetButton.Text = "重置所有设置"
$resetButton.Location = New-Object System.Drawing.Point(570, 810)
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
            "自定义 DoH 需要提供模板 URL（例如 https://cloudflare-dns.com/dns-query）。",
            "缺少 DoH 模板",
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
                    Write-Host "已设置 $($feature.Key) 为 [$(($feature.Value) -join ', ')]"
                    # Clear any conflicting user-scope value / subkey so Brave
                    # does not merge machine and user policies.
                    Remove-ListPolicy -RegistryPath $userRegistryPath -Name $feature.Key
                } else {
                    Set-ItemProperty -Path $registryPath -Name $feature.Key -Value $feature.Value -Type $feature.Type -Force
                    Write-Host "已设置 $($feature.Key) 为 $($feature.Value)"
                    # When enforcing a machine-level policy, clear any conflicting
                    # user-scope value so Brave does not merge the two.
                    if ((Test-Path -Path $userRegistryPath) -and
                        (Get-ItemProperty -Path $userRegistryPath -Name $key -ErrorAction SilentlyContinue)) {
                        Remove-ItemProperty -Path $userRegistryPath -Name $key -ErrorAction SilentlyContinue
                    }
                }
            } catch {
                Write-Host "设置 $($feature.Key) 失败：$_"
            }
        } else {
            # Remove the policy from both machine and user scopes so
            # Brave falls back to its built-in default. Remove-ListPolicy
            # handles both REG_SZ values and list subkeys, so it is safe to
            # call without knowing the feature's Type here.
            try {
                Remove-ListPolicy -RegistryPath $registryPath -Name $key
                Remove-ListPolicy -RegistryPath $userRegistryPath -Name $key
                Write-Host "已移除 $key"
            } catch {
                Write-Host "移除 ${key} 失败：$_"
            }
        }
    }

    # DNS settings
    if ($dnsDropdown.SelectedItem) {
        $dnsUpdated = Set-DnsSettings -dnsMode $dnsDropdown.SelectedItem -dnsTemplates $dnsTemplateBox.Text
        if (-not $dnsUpdated) {
            return
        }
    }

    [System.Windows.Forms.MessageBox]::Show(
        "设置已应用成功！请重启 Brave 以生效。",
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
        "警告：这将清除所有 Brave 策略设置并恢复为默认状态。是否继续？",
        "确认重置 SlimBrave Neo",
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

            [System.Windows.Forms.MessageBox]::Show(
                "已成功将所有 Brave 策略设置重置为默认值。",
                "重置成功",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
            return $true
        } catch {
            [System.Windows.Forms.MessageBox]::Show(
                "重置时发生错误：$_",
                "重置失败",
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
        $dnsDropdown.SelectedItem = "off"
        $dnsTemplateBox.Text = ""
        $dnsTemplateBox.Enabled = $false
    }
})

# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

$exportButton.Add_Click({
    $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveFileDialog.Filter = "JSON 文件 (*.json)|*.json|所有文件 (*.*)|*.*"
    $saveFileDialog.Title = "导出 SlimBrave Neo 设置"
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

        $settingsToExport = [ordered]@{
            Features     = $featureMap
            DnsMode      = $dnsDropdown.SelectedItem
            DnsTemplates = $dnsTemplateBox.Text
        }

        try {
            # -Depth 5 covers Features -> key -> list values (Shields).
            $settingsToExport | ConvertTo-Json -Depth 5 | Out-File -FilePath $saveFileDialog.FileName -Force
            [System.Windows.Forms.MessageBox]::Show(
                "已成功导出设置到：`n$($saveFileDialog.FileName)",
                "导出成功",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
        } catch {
            [System.Windows.Forms.MessageBox]::Show(
                "导出设置失败：$_",
                "导出失败",
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
    $openFileDialog.Filter = "JSON 文件 (*.json)|*.json|所有文件 (*.*)|*.*"
    $openFileDialog.Title = "导入 SlimBrave Neo 设置"
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

            # DNS mode
            if ($importedSettings.DnsMode) {
                $dnsDropdown.SelectedItem = $importedSettings.DnsMode
            }

            # DNS template
            if ($importedSettings.DnsTemplates) {
                $dnsTemplateBox.Text = $importedSettings.DnsTemplates
                if (-not $importedSettings.DnsMode) {
                    $dnsDropdown.SelectedItem = "custom"
                }
            }

            [System.Windows.Forms.MessageBox]::Show(
                "已成功从以下文件导入设置：`n$($openFileDialog.FileName)",
                "导入成功",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
        } catch {
            [System.Windows.Forms.MessageBox]::Show(
                "导入设置失败：$_",
                "导入失败",
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
            $dnsDropdown.SelectedItem = "off"
        }
    } else {
        $dnsDropdown.SelectedItem = "off"
    }

    $dnsTemplateBox.Enabled = ($dnsDropdown.SelectedItem -eq "custom")
}

Initialize-CurrentSettings

[void] $form.ShowDialog()
