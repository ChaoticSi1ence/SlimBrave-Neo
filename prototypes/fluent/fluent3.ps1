# SlimBrave Fluent v0.5 - full parity prototype (Win11 Settings style).
# 78 rows, 6 presets, DNS page, action bar, expandable descriptions.
# PowerShell 5.1 + GDI+ owner-draw. Writes nothing anywhere.

# Forwarded by the elevation relaunch below, never passed by hand. After
# elevation $env:LOCALAPPDATA belongs to whichever account approved UAC, which
# under over-the-shoulder UAC is the admin and not the user whose Brave profile
# holds the leaked prefs. This carries the invoking user's path across.
# Must stay the literal first statement of the file.
param (
    [string] $OriginalLocalAppData
)

# SlimBrave Neo - Fluent GUI (beta). Relaunches itself elevated so Apply and
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
        Start-Process -FilePath "powershell.exe" -Verb RunAs -ErrorAction Stop `
            -ArgumentList @("-ExecutionPolicy", "Bypass", "-File", $script:selfPath,
                            "-OriginalLocalAppData", $env:LOCALAPPDATA)
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

$data = Get-Content "$PSScriptRoot\catalog.json" -Raw | ConvertFrom-Json
$script:cats = $data.categories
$script:presets = $data.presets
$script:dnsModes = $data.dnsModes
$script:OriginalLocalAppData = $OriginalLocalAppData
. "$PSScriptRoot\engine.ps1"
Initialize-State

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
                    ($out | ConvertTo-Json -Depth 5) | Set-Content -Path $dlg.FileName -Encoding UTF8
                    Set-Status "Exported $($feat.Count) policies"
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
        $bw=110
        $br=New-Object System.Drawing.RectangleF (815-$bw),24,$bw,32
        $bg=$script:F.RowHot; if($st.Hot){$bg=$script:F.Accent}
        Fill-Round $g $br 4 $bg
        if(-not $st.Hot){ Stroke-Round $g $br 4 $script:F.RowEdge }
        $ink=$script:F.Text; if($st.Hot){$ink=[System.Drawing.Color]::FromArgb(27,27,27)}
        $lb=New-Object System.Drawing.SolidBrush $ink
        $sz=$g.MeasureString("Load",$script:btnFont,1000,$script:SF)
        $g.DrawString("Load",$script:btnFont,$lb,($br.X+($bw-$sz.Width)/2),($br.Y+7),$script:SF); $lb.Dispose()
    })
    $p.Add_MouseEnter({$this.Tag.Hot=$true;$this.Invalidate()})
    $p.Add_MouseLeave({$this.Tag.Hot=$false;$this.Invalidate()})
    $p.Add_Click({
        Import-PresetIntoState $this.Tag.P
        Select-Page $script:sel
        Set-Status "$($this.Tag.P.name) loaded - $($this.Tag.P.count) policies staged. Nothing is written until Apply."
    })
    $p.Cursor=[System.Windows.Forms.Cursors]::Hand
    return $p
}

# --------------------------------------------------------------- DNS page
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
    $script:tmplHint="https://dns.example/dns-query"
    function Sync-TmplHint($box){
        if($box.Focused){ return }
        if([string]::IsNullOrEmpty($box.Tag)){
            $box.ForeColor=[System.Drawing.Color]::FromArgb(96,96,96)
            $box.Text=$script:tmplHint
        }
    }
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
