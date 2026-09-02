# SlimBrave Fluent - policy engine. Dot-sourced by fluent3.ps1.
# Ported from SlimBrave.ps1 with the same semantics, including the fixes that
# shipped in v2.0.x: scoped Reset, and DNS "secure" requiring a template.

# ---------------------------------------------------------------------------
# STATE MODEL
# Row panels are destroyed on every page switch, so selections cannot live in
# them. Every row gets a stable id; state lives here, the UI renders it, and
# Apply reads it. Ids are index-based because a few policy keys legitimately
# appear on two rows (incognito, referrers).
# ---------------------------------------------------------------------------
$script:state = @{}
function Initialize-State {
    for ($ci = 0; $ci -lt $script:cats.Count; $ci++) {
        $cat = $script:cats[$ci]
        for ($ri = 0; $ri -lt $cat.rows.Count; $ri++) {
            $row = $cat.rows[$ri]
            $id = "$ci.$ri"
            $row | Add-Member -NotePropertyName Id -NotePropertyValue $id -Force
            $script:state[$id] = @{ On = $false; Sel = 0 }
        }
    }
}
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
    return $row.value
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
            Remove-ListPolicy $script:machineReg $key
            if (Test-Path $script:userReg) { Remove-ListPolicy $script:userReg $key }
        }
    }

    if ($mode -eq "unmanaged") {
        foreach ($scope in @($script:machineReg, $script:userReg)) {
            if (Test-Path $scope) {
                Remove-ItemProperty -Path $scope -Name "DnsOverHttpsMode" -ErrorAction SilentlyContinue
                Remove-ItemProperty -Path $scope -Name "DnsOverHttpsTemplates" -ErrorAction SilentlyContinue
            }
        }
    } else {
        # "custom" is Chromium's "secure" plus a template; the UI keeps them
        # apart so the template field can be required for one and not the other.
        $writeMode = $mode
        if ($mode -eq "custom") { $writeMode = "secure" }
        Set-ItemProperty -Path $script:machineReg -Name "DnsOverHttpsMode" -Value $writeMode -Type String -Force
        $wantsTemplate = ($mode -eq "custom" -or $mode -eq "secure" -or $mode -eq "automatic")
        if ($wantsTemplate -and -not [string]::IsNullOrWhiteSpace($script:dnsState.Tmpl)) {
            Set-ItemProperty -Path $script:machineReg -Name "DnsOverHttpsTemplates" `
                -Value $script:dnsState.Tmpl -Type String -Force
        } else {
            Remove-ItemProperty -Path $script:machineReg -Name "DnsOverHttpsTemplates" -ErrorAction SilentlyContinue
        }
        $written++
    }
    Set-Status "Applied $written policies. Restart Brave, then check brave://policy"
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
    foreach ($scope in @($script:machineReg, $script:userReg)) {
        if (-not (Test-Path $scope)) { continue }
        foreach ($key in $uniqueKeys) { Remove-ListPolicy $scope $key }
        Remove-ItemProperty -Path $scope -Name "DnsOverHttpsMode" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $scope -Name "DnsOverHttpsTemplates" -ErrorAction SilentlyContinue
    }
    foreach ($id in @($script:state.Keys)) { $script:state[$id].On = $false; $script:state[$id].Sel = 0 }
    $script:dnsState.Mode = 0
    $script:dnsState.Tmpl = ""
    Set-Status "Reset. Only keys SlimBrave Neo manages were removed."
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
    foreach ($row in Get-AllRows) {
        if ($null -eq $feat.PSObject.Properties[$row.key]) { continue }
        $want = $feat.$($row.key)
        if (Test-IsChoiceRow $row) {
            for ($i = 1; $i -lt $row.choices.Count; $i++) {
                if ([string]$row.choices[$i][1] -eq [string]$want) { $script:state[$row.Id].Sel = $i; break }
            }
        } elseif ($row.value -is [array]) {
            $script:state[$row.Id].On = $true
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
