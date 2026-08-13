# Forwarded by the elevation relaunch below, never passed by hand. Under
# over-the-shoulder UAC (standard user + separate admin credentials) the
# elevated process runs as the ADMIN, so $env:LOCALAPPDATA and HKCU point at
# the wrong account and the profile scrub silently cleans nothing. These
# carry the invoking user's identity across the relaunch. This param block
# must stay the literal first statement of the file.
param (
    [string] $OriginalLocalAppData,
    [string] $OriginalSid
)

# Loaded before the elevation check so the failure paths below can report
# through a MessageBox instead of exiting silently.
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# $MyInvocation.MyCommand.Path is empty when the script runs from a pipe
# (iex (irm ...)) or an unsaved editor buffer, so capture it before anything
# can shadow it and refuse to relaunch with -File "" — that starts a process
# which dies instantly with no diagnostic.
$scriptPath = $MyInvocation.MyCommand.Path

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    if ([string]::IsNullOrWhiteSpace($scriptPath)) {
        [System.Windows.Forms.MessageBox]::Show(
            "SlimBrave Neo needs to run from a saved .ps1 file so it can relaunch itself elevated.`n`nSave the script to disk and run it with:`n  powershell -ExecutionPolicy Bypass -File .\SlimBrave.ps1",
            "Cannot Elevate",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
        exit 1
    }

    # Carry -ExecutionPolicy Bypass into the elevated instance: the user
    # often launches via "powershell -ExecutionPolicy Bypass -File ..." and
    # the relaunch would otherwise revert to the machine default policy and
    # silently fail to start. The two -Original* arguments hand the elevated
    # instance the current (unelevated) user's profile path and SID.
    $currentSid = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
    $relaunchArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`"" +
        " -OriginalLocalAppData `"$env:LOCALAPPDATA`" -OriginalSid `"$currentSid`""
    try {
        # -ErrorAction Stop is required: a declined UAC prompt is a
        # non-terminating error, so without it the catch never runs and the
        # user gets no feedback at all.
        Start-Process powershell -ArgumentList $relaunchArgs -Verb RunAs -ErrorAction Stop
    } catch {
        [System.Windows.Forms.MessageBox]::Show(
            "SlimBrave Neo could not restart with administrator rights: $_`n`nIt writes machine-wide policy, so it cannot continue without elevation.",
            "Elevation Failed",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
        exit 1
    }
    exit
}

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
$form.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Dpi
$form.Text = "SlimBrave Neo"
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
    @{ Name = "Disable Enhanced Spell Check (Google Web Service)"; Key = "SpellCheckServiceEnabled"; Value = 0; Type = "DWord"; Group = "spellcheck"
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
$accessFeatures = @(
    @{ Name = "Block Web Notifications"; Key = "DefaultNotificationsSetting"; Value = 2; Type = "DWord"
       Tip = "Blocks all sites from showing desktop notifications and removes the permission prompt entirely." },
    @{ Name = "Block Location Access"; Key = "DefaultGeolocationSetting"; Value = 2; Type = "DWord"
       Tip = "Blocks all sites from reading your physical location and removes the permission prompt. Maps and delivery sites will need the location typed manually." },
    @{ Name = "Block Motion Sensors"; Key = "DefaultSensorsSetting"; Value = 2; Type = "DWord"
       Tip = "Blocks all sites from reading motion and orientation sensors, a known fingerprinting vector. Rarely breaks anything on desktop." },
    @{ Name = "Block WebUSB Access"; Key = "DefaultWebUsbGuardSetting"; Value = 2; Type = "DWord"
       Tip = "Blocks all sites from talking to USB devices and removes the permission prompt. Breaks web-based hardware wallets (Ledger, Trezor) and in-browser firmware flashers." },
    @{ Name = "Block Web Serial Access"; Key = "DefaultSerialGuardSetting"; Value = 2; Type = "DWord"
       Tip = "Blocks all sites from opening serial ports and removes the permission prompt. Breaks in-browser microcontroller and device programming tools." },
    @{ Name = "Block WebHID Access"; Key = "DefaultWebHidGuardSetting"; Value = 2; Type = "DWord"
       Tip = "Blocks all sites from talking to human interface devices and removes the permission prompt. May break security keys and gamepad configurators that use WebHID rather than WebAuthn." },
    @{ Name = "Block Local Font Enumeration"; Key = "DefaultLocalFontsSetting"; Value = 2; Type = "DWord"
       Tip = "Blocks all sites from asking for the list of fonts installed on your machine - a strong fingerprinting signal that Shields' font protections don't cover. Rarely breaks anything outside web design tools." },
    @{ Name = "Block Multi-Screen (Window Management) Access"; Key = "DefaultWindowManagementSetting"; Value = 2; Type = "DWord"
       Tip = "Blocks all sites from reading your monitor layout and placing windows on a chosen screen. Breaks the full-screen presentation mode in some web apps." },
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
       Tip = "Stops Brave from downloading and running on-device AI models and from building an AI index of your browsing history. Separate from Brave AI Chat - disabling Leo does not cover this. Forward-looking: the policy first ships in Brave 1.94 and older versions ignore it. Takes effect after a browser restart." },
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

$categories = @(
    @{ Name = "Telemetry & Reporting";        Features = $telemetryFeatures },
    @{ Name = "Privacy & Security";           Features = $privacyFeatures },
    @{ Name = "Permissions & Access";         Features = $accessFeatures },
    @{ Name = "Shields & Content Protection"; Features = $shieldsContentFeatures },
    @{ Name = "Brave Features";               Features = $braveFeatures },
    @{ Name = "Performance & Bloat";          Features = $perfFeatures }
)
$categoryByName = @{}
foreach ($cat in $categories) { $categoryByName[$cat.Name] = $cat }

# Which categories go in each column when there are two. Named here rather
# than below because the natural window height is derived from it.
$twoColumnLayout = @(
    @("Privacy & Security", "Permissions & Access", "Shields & Content Protection"),
    @("Telemetry & Reporting", "Brave Features", "Performance & Bloat")
)

# Natural height of the two-column window. If the screen's usable height is
# below this, switch to three columns. Derived from the same metrics the
# builder uses further down, and from the window chrome, so it can't drift as
# rows are added: the old hard-coded 1140 was meant to sit a little ABOVE the
# form but the form measures 1144 at 96 DPI and 1152 at 125%, so the margin
# was inverted and the safety net at the end of the file produced the very
# scrollbar this check exists to avoid.
$twoColumnBottom = 0
foreach ($column in $twoColumnLayout) {
    # Mirrors the build loop at two-column metrics: $colStartY, then per
    # category a section-label row, one row per feature, and $rowGap.
    $columnBottom = 10
    foreach ($catName in $column) {
        $columnBottom += (25 * (1 + $categoryByName[$catName].Features.Count)) + 10
    }
    if ($columnBottom -gt $twoColumnBottom) { $twoColumnBottom = $columnBottom }
}
# Panel padding (5) + panel top margin (20) + DNS row (15 + 75) + button row
# (32) + bottom margin (18) is the ClientSize the builder arrives at; the
# window is that plus the non-client chrome, which grows with the DPI scale.
$twoColumnWindowHeight = $twoColumnBottom + 5 + 20 + 15 + 75 + 32 + 18 +
    [System.Windows.Forms.SystemInformation]::CaptionHeight +
    (2 * [System.Windows.Forms.SystemInformation]::FixedFrameBorderSize.Height)

$columnCount = 2
if ($env:SLIMBRAVE_COLUMNS -eq "2" -or $env:SLIMBRAVE_COLUMNS -eq "3") {
    $columnCount = [int]$env:SLIMBRAVE_COLUMNS
} elseif ([System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea.Height -lt $twoColumnWindowHeight) {
    $columnCount = 3
}

# Three-column mode pairs the six categories so no column runs much past
# ~545px of content (vs. ~970px in the two-column layout).
if ($columnCount -eq 3) {
    $columnLayout = @(
        @("Privacy & Security", "Telemetry & Reporting"),
        @("Permissions & Access", "Brave Features"),
        @("Shields & Content Protection", "Performance & Bloat")
    )
} else {
    $columnLayout = $twoColumnLayout
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
# Features tagged with a `Group` are mutually exclusive: either they share a
# single policy key that can only take one value at a time
# (IncognitoModeAvailability, DefaultBraveReferrersSetting, ChromeVariations)
# or checking one makes the other inert (the Shields URL lists, and the two
# spellcheck rows). The handler below mirrors the Python TUI's
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
$tooltip.SetToolTip($dnsDropdown, "unmanaged - write no DNS policy; Brave's own DNS settings stay user-controlled.`noff - force-disable DNS over HTTPS as policy.`nautomatic - use DoH when the current resolver supports it, plain DNS otherwise.`nsecure - always resolve over DoH, with no plaintext fallback; needs the template URL below.`ncustom - same as secure, kept so configs from the Linux/macOS scripts round-trip.")

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
$tooltip.SetToolTip($dnsTemplateBox, "DoH resolver template, e.g. https://cloudflare-dns.com/dns-query. Required for 'custom' and 'secure'; optional for 'automatic'.")

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
    "Write every checked policy to the registry and remove unchecked ones. Restart Brave (close all brave.exe processes) for changes to take effect."
$resetButton = New-ActionButton "Reset All Settings" 600 $theme.ResetText `
    "Remove every policy SlimBrave Neo manages from machine and user scope - policies set by group policy or another tool are left alone - and scrub leaked Shields entries from your Brave profiles."

# ---------------------------------------------------------------------------
# Apply - sets checked keys AND removes unchecked keys (fixes #25, #27, #19)
# ---------------------------------------------------------------------------

$saveButton.Add_Click({
    # Validate DNS settings up-front. Writing features first and then
    # bailing out on a bad DNS config would leave the policy store in a
    # half-applied state, which is what the original "custom with no
    # template" bug looked like in practice. Mirrors the guard in
    # Set-DnsSettings - "secure" without a template is just as fatal.
    if ($dnsDropdown.SelectedItem -in @("custom", "secure") -and
        [string]::IsNullOrWhiteSpace($dnsTemplateBox.Text)) {
        [System.Windows.Forms.MessageBox]::Show(
            "'secure' and 'custom' DoH require a template URL (e.g. https://cloudflare-dns.com/dns-query).",
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

    # List-typed features by key, so the removal branch below can tell our
    # own list from one an admin or another tool wrote.
    $listFeatures = @{}
    foreach ($checkbox in $allFeatures) {
        if ($checkbox.Tag.Type -eq "List") { $listFeatures[$checkbox.Tag.Key] = $checkbox.Tag }
    }
    $skippedListKeys = @()

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
            #
            # Exception: an unchecked List row does not mean "no list is
            # set". Initialize-CurrentSettings only ticks the box on a
            # subset match, so an admin's own ExtensionInstallBlocklist
            # leaves it unchecked - and blowing the subkey away would delete
            # a policy SlimBrave never wrote. Only remove a list that is
            # exactly ours.
            $listFeature = $listFeatures[$key]
            try {
                foreach ($scope in @($registryPath, $userRegistryPath)) {
                    if ($listFeature -and
                        -not (Test-ListPolicyIsExactly -RegistryPath $scope -Name $key -Expected $listFeature.Value)) {
                        $skippedListKeys += $key
                        Write-Host "Skipped $key (externally managed list)"
                        continue
                    }
                    Remove-ListPolicy -RegistryPath $scope -Name $key
                }
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
        $dnsUpdated = Set-DnsSettings -dnsMode $dnsDropdown.SelectedItem -dnsTemplates $dnsTemplateBox.Text `
            -MachinePath $registryPath -UserPath $userRegistryPath
        if (-not $dnsUpdated) {
            return
        }
    }

    # Scrub Chromium's per-URL pref leak (BraveShieldsDisabledForUrls writes
    # exceptions into the user profile that survive policy removal).
    $repair = Repair-BravePrefs

    $msg = "Settings applied successfully! Restart Brave to see changes."
    if ($repair.Skipped) {
        $msg += "`n`nBrave is running, so leaked profile prefs were left alone - Brave keeps prefs in memory and would overwrite the fix the moment it next saves. Fully close it (taskkill /IM brave.exe /F or end all brave.exe in Task Manager), then click Apply Settings again."
    } elseif ($repair.Removed -gt 0) {
        $plural = if ($repair.Removed -ne 1) { "s" } else { "" }
        $msg = "Settings applied. Cleaned $($repair.Removed) leaked profile pref$plural. Restart Brave to see changes."
    }
    if ($skippedListKeys.Count -gt 0) {
        $msg += "`n`nLeft alone because the list on disk is not the one SlimBrave writes: $(($skippedListKeys | Select-Object -Unique) -join ', ')."
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
        "Warning: This will erase all settings SlimBrave Neo manages and restore them to their default state. Policies set by group policy or another tool are left alone. Do you wish to continue?",
        "Confirm SlimBrave Neo Reset",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Warning
    )

    if ($confirm -eq "Yes") {
        try {
            # Scoped to our own keys, exactly like Apply. The Brave policy
            # hive is shared: a Remove-Item -Recurse here would also destroy
            # a GPO's ExtensionInstallForcelist, URLBlocklist, ProxySettings
            # and anything else another tool put there.
            $uniqueKeys = $allFeatures | ForEach-Object { $_.Tag.Key } | Select-Object -Unique
            foreach ($scope in @($registryPath, $userRegistryPath)) {
                if (-not (Test-Path -Path $scope)) { continue }
                foreach ($key in $uniqueKeys) {
                    Remove-ListPolicy -RegistryPath $scope -Name $key
                }
                Remove-ItemProperty -Path $scope -Name "DnsOverHttpsMode"      -ErrorAction SilentlyContinue
                Remove-ItemProperty -Path $scope -Name "DnsOverHttpsTemplates" -ErrorAction SilentlyContinue
            }

            # Scrub the per-URL exceptions Brave caches in the user profile.
            # Without this, "Disable Brave Shields" leaves shields stuck off
            # even after the registry policy is gone.
            $repair = Repair-BravePrefs

            $msg = "Every policy SlimBrave Neo manages has been reset to its default value."
            if ($repair.Skipped) {
                $msg += "`n`nBrave is running, so leaked profile prefs were left alone - Brave would overwrite the fix the moment it next saves. Fully close it (Task Manager: end all brave.exe), then run Reset again to clear them."
            } elseif ($repair.Removed -gt 0) {
                $plural = if ($repair.Removed -ne 1) { "s" } else { "" }
                $msg += "`n`nAlso cleaned $($repair.Removed) leaked profile pref$plural that previous SlimBrave versions wrote to your Brave profile."
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
            # Written as UTF-8 without BOM rather than through Out-File,
            # whose default encoding is host-dependent: UTF-16LE+BOM on
            # Windows PowerShell 5.1, UTF-8 on pwsh 7. Same idiom as
            # Repair-OneBravePrefs.
            [System.IO.File]::WriteAllText(
                $saveFileDialog.FileName,
                ($settingsToExport | ConvertTo-Json -Depth 5),
                (New-Object System.Text.UTF8Encoding $false))
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
            # -Encoding UTF8 to match what Export now writes. The reader
            # still honors a byte-order mark, so UTF-16 files written by
            # older versions keep importing correctly.
            $importedSettings = Get-Content -Path $openFileDialog.FileName -Raw -Encoding UTF8 | ConvertFrom-Json

            # Uncheck everything first
            foreach ($checkbox in $allFeatures) {
                $checkbox.Checked = $false
            }

            $ignoredLists = @()
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
                        if ($checkbox.Tag.Key -ne $prop.Name) { continue }
                        if (Test-FeatureValueMatches $checkbox.Tag $prop.Value) {
                            $checkbox.Checked = $true
                        } elseif ($checkbox.Tag.Type -eq "List") {
                            # A list we can't reproduce: applying the row
                            # would substitute our own wildcards for it.
                            $ignoredLists += $prop.Name
                        }
                    }
                }
            }

            # DNS: a file with no DnsMode means DNS is unmanaged (a bare
            # DnsTemplates is treated as custom for legacy exports).
            # Assigning a value the ComboBox doesn't hold is a silent no-op
            # that leaves the previous mode selected, and -contains can't
            # pre-check it: it matches case-insensitively while SelectedItem
            # resolution is case-sensitive, so "Automatic" would pass the
            # guard and then no-op. Resolve to the canonical item instead.
            $unknownDns = $null
            if ($importedSettings.DnsMode) {
                $mode = [string]$importedSettings.DnsMode
                $canonical = @($dnsDropdown.Items) | Where-Object { $_ -eq $mode } | Select-Object -First 1
                if ($canonical) {
                    $dnsDropdown.SelectedItem = $canonical
                } else {
                    $dnsDropdown.SelectedItem = "unmanaged"
                    $unknownDns = $mode
                }
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

            $importMsg = "Settings imported successfully from:`n$($openFileDialog.FileName)"
            if ($unknownDns) {
                $importMsg += "`n`nDNS mode '$unknownDns' is not recognised; DNS was left unmanaged."
            }
            if ($ignoredLists.Count -gt 0) {
                $importMsg += "`n`nIgnored, because the imported list is not the one SlimBrave writes: $(($ignoredLists | Select-Object -Unique) -join ', ')."
            }

            [System.Windows.Forms.MessageBox]::Show(
                $importMsg,
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
            # Same canonical lookup as the import path: a registry value the
            # dropdown doesn't hold would leave SelectedIndex at -1, blanking
            # the control and skipping the DNS write on the next Apply.
            $canonical = @($dnsDropdown.Items) | Where-Object { $_ -eq $currentDnsMode } | Select-Object -First 1
            if ($canonical) {
                $dnsDropdown.SelectedItem = $canonical
            } else {
                $dnsDropdown.SelectedItem = "unmanaged"
            }
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
