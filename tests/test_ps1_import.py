"""SlimBrave.ps1's Import, checked as text: nothing here can run Windows
PowerShell 5.1, so these pin the constructs the import relies on, as the PS1
tests in test_slimbrave.py do.

Import names everything a file carries that no row takes, matches names in
their exact letter case as the Python scripts do, and shows text from the
file only escaped and capped. Each test below holds one of those to the code
that does it. CI's 5.1 parse and PSScriptAnalyzer catch syntax; how the code
behaves is owed to a Windows run.
"""

import re

from test_slimbrave import ROOT, _ps1_embedded_presets, _ps1_feature_rows, _ps1_function, _ps1_live

PS1 = ROOT / "SlimBrave.ps1"

# The Import status after 'Imported from <file>', clause by clause in its
# fixed order: lead, reason, and the list it names. The reasons are the
# Python scripts' words; only the lead and the punctuation differ (Python:
# '; left unmanaged because <reason>: <items>'). The exclusion-group clause
# follows these, in its old form.
IMPORT_CLAUSES = [
    ("Left unmanaged", "names are case-sensitive", "(@($script:importMiscased)+@($top.Case))"),
    ("Left unmanaged", "the value is not one this policy accepts", "$script:importNotes"),
    ("Left unmanaged", "no row sets that value", "$script:importUnwritten"),
    ("Left unmanaged", "SlimBrave Neo no longer offers it", "$script:importRetired"),
    ("Left unmanaged", "SlimBrave Neo does not offer it", "$script:importUnknown"),
    ("Ignored", "it is not a SlimBrave Neo setting", "$top.Other"),
]

# The lists Import-PresetIntoState fills, one per clause it names.
IMPORT_LISTS = ("importMiscased", "importNotes", "importUnwritten", "importRetired", "importUnknown")

# Every function the import's naming goes through.
IMPORT_FUNCTIONS = ("Import-PresetIntoState", "Add-ImportNameNote", "Get-ImportDnsHint",
                    "Get-ImportCanonical", "Read-ImportFields", "Format-ImportText",
                    "Format-ImportString", "Format-ImportName", "Format-ImportValue",
                    "Format-ImportItem", "Get-ImportClause")


def _imp():
    return _ps1_function(_ps1_live(), "Import-PresetIntoState")


def _legacy(imp):
    return imp[imp.index("$feat -is [array]"):imp.index("$feat = $null")]


def _handler():
    """The Import button's handler, up to and including its failure status."""
    live = _ps1_live()
    handler = live[live.index('"Import" {'):]
    end = 'Set-Status "Import failed - $why"'
    return handler[:handler.index(end) + len(end)]


def _function_at(text, pos):
    """The name of the function whose definition last precedes `pos`."""
    names = [m.group(1) for m in re.finditer(r"^function ([\w-]+)", text[:pos], re.MULTILINE)]
    return names[-1] if names else None


def test_ps1_stays_ascii():
    """A .ps1 without a BOM is read in the ANSI code page by Windows
    PowerShell 5.1, so a typographic quote or dash in a new message would
    reach the status bar garbled. The import's escaper keeps file text
    ASCII too."""
    assert PS1.read_bytes().isascii()


def test_ps1_import_reads_feature_keys_in_exact_case():
    """PSObject.Properties[...] and $feat.$key ignore letter case, so
    "metricsreportingenabled" used to tick a row the Python scripts leave
    alone. The lookup only finds a candidate; its name must equal the row's
    key ordinally, and the value is read from that property. A legacy entry
    names a key only as a JSON string in its exact case."""
    imp = _imp()
    assert "$feat.$($row.key)" not in imp, "a feature value is read case-blind"
    steps = [imp.index(s) for s in (
        "$prop = $feat.PSObject.Properties[$row.key]",
        "if (-not [string]::Equals($prop.Name, $row.key, [System.StringComparison]::Ordinal)) { continue }",
        "[void]$used.Add($prop.Name)",
        "$want = $prop.Value",
    )]
    assert steps == sorted(steps), "the exact-case check does not come between the lookup and the read"
    legacy = _legacy(imp)
    assert "[string]$n" not in legacy, "a legacy entry is cast into a key name"
    assert "-contains" not in legacy and "-notcontains" not in legacy, "a legacy name is matched case-blind"
    assert "if ($n -is [string]) {" in legacy
    assert "if (-not $names.Contains($row.key)) { continue }" in legacy
    # The first-row-per-key guard stays (test_slimbrave.py pins why).
    assert "if ($handled.ContainsKey($row.key)) { continue }" in legacy


def test_ps1_import_collections_compare_ordinally():
    """Names are compared as the Python scripts compare them, code unit by
    code unit. A PowerShell hashtable or [ordered] dictionary ignores case
    in the current culture, and -ceq / -ccontains compare in the invariant
    culture, so every set and dictionary the import keys by a name from the
    file is built with an ordinal comparer, and only the two folds that look
    up a name's right spelling ignore case."""
    live = _ps1_live()
    folds = []
    for name in ("Import-PresetIntoState", "Read-ImportFields"):
        body = _ps1_function(live, name)
        made = re.findall(r"\$(\w+) = \[System\.Collections\.Generic\.(?:HashSet\[string\]|"
                          r"Dictionary\[string,string\])\]::new\(([^)]*)\)", body)
        assert made, f"{name} builds no ordinal collection"
        for var, arg in made:
            assert arg in ("[System.StringComparer]::Ordinal",
                           "[System.StringComparer]::OrdinalIgnoreCase"), f"{name}: ${var} = ...({arg})"
            if arg.endswith("OrdinalIgnoreCase"):
                folds.append(var)
        assert "New-Object System.Collections.Generic" not in body, f"{name} builds a collection without a comparer"
        assert "-ceq" not in body and "-ccontains" not in body, f"{name} compares names in the invariant culture"
    assert folds == ["rowFold", "fold"]
    imp = _ps1_function(live, "Import-PresetIntoState")
    # $script:retiredPolicies is [ordered], which ignores case: copied out.
    assert "foreach ($k in $script:retiredPolicies.Keys) { [void]$retired.Add([string]$k) }" in imp
    assert "$script:retiredPolicies.Contains" not in imp and "$script:retiredPolicies[" not in imp


def test_ps1_import_matches_values_in_exact_case():
    """A string value and a list's entries match exactly, as the Python
    scripts' == compares them: "DISABLE_NON_PROXIED_UDP", which Chromium's
    strcmp enum check refuses, or ["HTTPS://*", "HTTP://*"] no longer ticks
    a row, and neither does a list whose entries are not strings (a nested
    ["*"] used to pass the [string] cast)."""
    imp = _imp()
    assert "$strings -and -not (Compare-Object -CaseSensitive $wantList $mine)" in imp
    assert "Compare-Object $wantList" not in imp
    assert "if (-not ($x -is [string])) { $strings = $false }" in imp
    assert ("[string]::Equals([string](ConvertTo-RegValue $want), [string](ConvertTo-RegValue $row.value), "
            "[System.StringComparison]::Ordinal)") in imp
    assert "-eq [string](ConvertTo-RegValue $row.value)" not in imp


def test_ps1_import_names_a_value_by_its_json_type_once_per_key():
    """A value no row takes is named under one of two reasons: outside its
    policy's JSON type it is not one this policy accepts; in it, no row sets
    that value (Notifications' 3, ChromeVariations 0, a true where the row
    writes false, a foreign list). Kept per key, since two rows share some
    keys and a value either row takes is not a drop; named in file order,
    before the exclusion groups untick a loser, which is named as mutually
    exclusive instead."""
    imp = _imp()
    for branch in ("[void]$taken.Add($row.key)",
                   "$missed[$row.key] = Format-ImportItem $row.key $want",
                   "$wrong[$row.key] = Format-ImportItem $row.key $want"):
        assert imp.count(branch) == 3, f"not in each of the choice, list and scalar rows: {branch}"
    obj = imp[imp.index("$want = $prop.Value"):]
    choice = obj[obj.index("if (Test-IsChoiceRow $row) {"):obj.index("} elseif ($row.value -is [array]) {")]
    # A choice row's right type is a JSON integer.
    assert ("if ($matched) {\n                [void]$taken.Add($row.key)\n"
            "            } elseif ($ok) {\n                $missed[$row.key]") in choice
    tail = imp[imp.index("foreach ($p in $feat.PSObject.Properties)"):]
    steps = [tail.index(s) for s in (
        "if (-not $used.Contains($n)) { Add-ImportNameNote $n $rowFold $retired; continue }",
        "if ($taken.Contains($n)) { continue }",
        "$script:importUnwritten.Add($missed[$n])",
        "$script:importNotes.Add($wrong[$n])",
    )]
    assert steps == sorted(steps)
    assert imp.index("foreach ($p in $feat.PSObject.Properties)") < imp.index("Enforce-ExclusionGroups")


def test_ps1_import_names_every_key_no_row_reads():
    """Every Features key no row read, and every legacy entry that is not a
    row's key, is named and never written (issue #33's pass-through was
    declined). A name that differs from a row's key only in letter case
    carries the spelling it needs; a retired key is named as no longer
    offered; anything else as not offered, with where a DNS name belongs. A
    legacy entry that is not a string is named by its value."""
    live = _ps1_live()
    imp = _ps1_function(live, "Import-PresetIntoState")
    legacy = _legacy(imp)
    assert "if (-not $rowKeys.Contains($n)) { Add-ImportNameNote $n $rowFold $retired }" in legacy
    assert "$shown = Format-ImportValue $n" in legacy
    assert "if ($null -ne $shown) { $script:importUnknown.Add($shown) }" in legacy
    note = _ps1_function(live, "Add-ImportNameNote")
    steps = [note.index(s) for s in ("$canon = Get-ImportCanonical $Name $RowFold",
                                     "} elseif ($Retired.Contains($Name)) {",
                                     "$hint = Get-ImportDnsHint $Name")]
    assert steps == sorted(steps)
    assert "$script:importMiscased.Add((Format-ImportName $Name) + ' (use ' + $canon + ')')" in note
    assert "$script:importRetired.Add((Format-ImportName $Name))" in note
    assert "if ($null -ne $hint) { $item = $item + ' (' + $hint + ')' }" in note
    assert "$script:importUnknown.Add($item)" in note
    hints = re.findall(r"\[string\]::Equals\(\$Name, '(\w+)', \[System\.StringComparison\]::Ordinal\)\) "
                       r"\{ return '([^']*)' \}", _ps1_function(live, "Get-ImportDnsHint"))
    assert dict(hints) == {"DnsOverHttpsMode": "use DnsMode", "DnsOverHttpsTemplates": "use DnsTemplates",
                           "DnsMode": "a top-level field", "DnsTemplates": "a top-level field"}


def test_ps1_import_folds_letter_case_only_for_ascii_names():
    """A mis-cased name is compared ignoring case only when it is printable
    ASCII, as the Python scripts compare only an ASCII one: .NET's
    OrdinalIgnoreCase alone takes a dotless i for I and a long s for S, so
    the two languages would disagree. \\z, not $, which .NET also matches
    before a final newline."""
    canon = _ps1_function(_ps1_live(), "Get-ImportCanonical")
    gate = canon.index("if (-not ($Name -cmatch '^[\\x20-\\x7E]*\\z')) { return $null }")
    assert gate < canon.index("if ($Fold.ContainsKey($Name)) { return $Fold[$Name] }")


def test_ps1_import_reads_the_three_fields_in_exact_case():
    """`features`, `dnsmode` and `DNSTemplates` used to be read as if spelled
    right. The handler now reads Features, DnsMode and DnsTemplates by their
    exact names; a field in the wrong case is named with its spelling, and
    any other top-level name as not a SlimBrave Neo setting."""
    handler = _handler()
    assert "$cfg.DnsMode" not in handler and "$cfg.DnsTemplates" not in handler
    assert "$cfg.PSObject.Properties['Features']" not in handler
    try_at = handler.index("try{")
    assert handler.index("$top=@{Case=[System.Collections.Generic.List[string]]::new(); "
                         "Other=[System.Collections.Generic.List[string]]::new(); Found=\"\"}") < try_at
    assert handler.index("$dupWhy=$null") < try_at
    guard_at = handler.index("if(-not ($cfg -is")
    assert handler.index("$field=Read-ImportFields $cfg $top") < guard_at
    guard = handler[guard_at:handler.index('throw "no Features block"')]
    assert "-not $field.ContainsKey('Features') -or" in guard
    assert guard.index("$field.ContainsKey('Features')") < guard.index("$cfg.Features"), (
        "$cfg.Features is read before Features is known to be spelled exactly")
    assert ("Import-PresetIntoState @{features=$cfg.Features;dns=$field['DnsMode'];"
            "tmpl=$field['DnsTemplates']}") in handler
    fields = _ps1_function(_ps1_live(), "Read-ImportFields")
    for line in ("foreach ($f in @('Features', 'DnsMode', 'DnsTemplates')) { $fold.Add($f, $f) }",
                 "if ($fold.ContainsKey($n) -and [string]::Equals($fold[$n], $n, "
                 "[System.StringComparison]::Ordinal)) {",
                 "$canon = Get-ImportCanonical $n $fold",
                 "$Top.Case.Add((Format-ImportName $n) + ' (use ' + $canon + ')')",
                 "if ([string]::Equals($canon, 'Features', [System.StringComparison]::Ordinal)) "
                 "{ $Top.Found = $n }",
                 "} else { $Top.Other.Add((Format-ImportName $n)) }"):
        assert line in fields, line


def test_ps1_import_status_names_each_class_in_order():
    """One clause per class, in the fixed order and the reason words the
    Python scripts use, after the unchanged lead. 'imported' is gone from the
    value reason. A mis-cased name inside Features comes before one at the
    top level. The exclusion-group clause is last and unchanged."""
    handler = _handler()
    ok = handler[handler.index("if($ok){"):handler.index("} else {", handler.index("Set-Status $msg"))]
    clauses = re.findall(r"^\s*\$msg\+=Get-ImportClause '([^']*)' '([^']*)' (.+?)\s*$", ok, re.MULTILINE)
    assert clauses == IMPORT_CLAUSES
    lead = ok.index('$msg="Imported from $([System.IO.Path]::GetFileName($dlg.FileName))"')
    groups = ok.index('$msg+=" Left unmanaged, because it is mutually exclusive with another imported row: "'
                      '+(($script:importConflicts | Sort-Object -Unique) -join ", ")+"."')
    assert lead < ok.index("$msg+=Get-ImportClause") < ok.index("$msg+=Get-ImportClause 'Ignored'") < groups
    assert "the imported value" not in PS1.read_text(encoding="utf-8")


def test_ps1_import_clause_has_the_python_shape():
    """' <Lead>, because <reason>: a, b, c, d, e and 3 more.' - five items at
    most, as in the Python scripts, so a file naming a thousand keys cannot
    bury the other clauses, and nothing at all when the list is empty."""
    live = _ps1_live()
    assert re.search(r"^\$script:IMPORT_MAX_ITEMS = 5$", live, re.MULTILINE)
    clause = _ps1_function(live, "Get-ImportClause")
    for line in ("if ($null -eq $Items) { return '' }",
                 "if ($all.Count -eq 0) { return '' }",
                 "$shown = [math]::Min($all.Count, $script:IMPORT_MAX_ITEMS)",
                 "$text = ' ' + $Lead + ', because ' + $Reason + ': ' + ($all[0..($shown - 1)] -join ', ')",
                 "if ($all.Count -gt $shown) { $text += ' and ' + ($all.Count - $shown) + ' more' }",
                 "return $text + '.'"):
        assert line in clause, line


def test_ps1_import_escapes_by_the_one_rule():
    """Every name and string value from the file is shown by one rule the
    Python scripts share, hand-written because ConvertTo-Json in 5.1 escapes
    <, >, & and ' its own way: a name like a policy name as it is, anything
    else quoted, each UTF-16 code unit outside 0x20-0x7E as \\uXXXX in
    uppercase hex, a quote and a backslash escaped, the body cut at 64 to 61
    plus '...'. A value is true/false, null, an integer in decimal or a
    quoted string; a fraction, list or object is not shown."""
    live = _ps1_live()
    text = _ps1_function(live, "Format-ImportText")
    assert "ConvertTo-Json" not in text and "-replace" not in text and "[regex]" not in text
    for line in ("$sb = [System.Text.StringBuilder]::new()",
                 "for ($i = 0; ($i -lt $Text.Length) -and ($sb.Length -le $Max); $i++) {",
                 "$code = [int]$ch",
                 "if ($code -eq 0x22) {\n            [void]$sb.Append('\\\"')",
                 "} elseif ($code -eq 0x5C) {\n            [void]$sb.Append('\\\\')",
                 "} elseif (($code -lt 0x20) -or ($code -gt 0x7E)) {\n"
                 "            [void]$sb.Append('\\u' + $code.ToString('X4'))",
                 "} else { [void]$sb.Append([string]$ch) }",
                 "if ($body.Length -gt $Max) { $body = $body.Substring(0, $Max - 3) + '...' }"):
        assert line in text, line
    assert "return '\"' + (Format-ImportText $Text 64) + '\"'" in _ps1_function(live, "Format-ImportString")
    name = _ps1_function(live, "Format-ImportName")
    assert "if ($Name -cmatch '^[A-Za-z0-9_.-]{1,64}\\z') { return $Name }" in name
    assert "return Format-ImportString $Name" in name
    value = _ps1_function(live, "Format-ImportValue")
    steps = [value.index(s) for s in (
        "if ($null -eq $Value) { return 'null' }",
        "if ($Value -is [bool]) {\n        if ($Value) { return 'true' }\n        return 'false'",
        "if (($Value -is [int]) -or ($Value -is [long])) {",
        "$digits = $Value.ToString([System.Globalization.CultureInfo]::InvariantCulture)",
        "if ($digits.Length -gt 64) { $digits = $digits.Substring(0, 61) + '...' }",
        "if ($Value -is [string]) { return Format-ImportString $Value }",
        "return $null",
    )]
    assert steps == sorted(steps)
    item = _ps1_function(live, "Format-ImportItem")
    assert "if ($null -eq $shown) { return (Format-ImportName $Key) }" in item
    assert "return (Format-ImportName $Key) + '=' + $shown" in item


def test_ps1_import_shows_file_text_only_through_the_escaper():
    """Nothing from the file reaches a list unescaped: the old
    "$($row.key)=$want" and "DnsMode=$want" items echoed raw text, a newline
    or a bidi override included. Every append to a clause's list takes an
    item a Format-Import* function made."""
    live = _ps1_live()
    imp = _ps1_function(live, "Import-PresetIntoState")
    assert '"$($row.key)=$want"' not in imp and "DnsMode=$want" not in imp
    assert "$script:importNotes.Add((Format-ImportItem 'DnsMode' $preset.dns))" in imp
    allowed = {
        "$shown", "$missed[$n]", "$wrong[$n]", "$item",
        "(Format-ImportItem 'DnsMode' $preset.dns)",
        "(Format-ImportName $Name) + ' (use ' + $canon + ')'",
        "(Format-ImportName $Name)",
        "(Format-ImportName $n) + ' (use ' + $canon + ')'",
        "(Format-ImportName $n)",
    }
    adds = list(re.finditer(r"(?:\$script:(?:" + "|".join(IMPORT_LISTS) + r")|\$Top\.(?:Case|Other))"
                            r"\.Add\((.*)\)\s*\}?\s*$", live, re.MULTILINE))
    # Import-PresetIntoState 4, Add-ImportNameNote 3, Read-ImportFields 2.
    assert len(adds) == 9
    for m in adds:
        assert m.group(1) in allowed, m.group(0)
        assert _function_at(live, m.start()) in ("Import-PresetIntoState", "Add-ImportNameNote",
                                                 "Read-ImportFields"), m.group(0)
    # $missed, $wrong and $item hold only escaped items.
    assert not re.search(r"\$(?:missed|wrong)\[\$row\.key\] = (?!Format-ImportItem )", imp)
    note = _ps1_function(live, "Add-ImportNameNote")
    assert "$item = Format-ImportName $Name" in note


def test_ps1_import_lists_are_made_before_use():
    """Each clause's list is a fresh List[string] before anything is staged
    or named. A List takes .Add; += on one silently turns it into an array,
    and += onto $null joins strings, so no import list is ever +='d. The
    handler's own collections exist before its try, so a failed read never
    leaves a previous import's names behind."""
    live = _ps1_live()
    imp = _ps1_function(live, "Import-PresetIntoState")
    first = imp.index("$feat = $preset.features")
    for name in IMPORT_LISTS:
        assert imp.index(f"$script:{name} = [System.Collections.Generic.List[string]]::new()") < first, name
    assert not re.search(r"\$script:import(?:Miscased|Notes|Unwritten|Retired|Unknown)\s*\+=", live)
    for m in re.finditer(r"\$script:(" + "|".join(IMPORT_LISTS) + r")\s*=", live):
        assert _function_at(live, m.start()) == "Import-PresetIntoState", m.group(0)


def test_ps1_import_says_why_a_case_only_duplicate_fails():
    """Windows PowerShell 5.1 keeps a JSON object as a PSObject, whose
    property names ignore case, so ConvertFrom-Json throws
    DuplicateKeysInJsonString for {"a":1,"A":2} at any depth. That used to
    read 'not a SlimBrave config'. The error id is read first thing in the
    catch, before the restore loop; the message, which names both keys, is
    shown made safe. A Features in the wrong case is named in the refusal."""
    live = _ps1_live()
    handler = live[live.index('"Import" {'):]
    catch = re.search(r"\} catch \{((?:[^{}]|\{[^{}]*\})*)\}", handler[handler.index("$ok=$true"):])
    assert catch, "the Import handler has no catch after the import"
    body = catch.group(1)
    dup = ("if([string]$_.FullyQualifiedErrorId -like 'DuplicateKeysInJsonString,*')"
           "{ $dupWhy=[string]$_.Exception.Message }")
    assert dup in body
    assert body.index(dup) < body.index("foreach($id in @($snap.Keys))")
    assert body.rstrip().endswith("$ok=$false")
    fail = _handler()
    fail = fail[fail.index('$why="not a SlimBrave config"'):]
    steps = [fail.index(s) for s in (
        "if($null -ne $dupWhy){",
        '$why="keys differ only in letter case"',
        'if($dupWhy){ $why+=": "+(Format-ImportText $dupWhy 300) }',
        '} elseif($top.Found){ $why+=" (found "+(Format-ImportName $top.Found)+"; names are case-sensitive)" }',
        'Set-Status "Import failed - $why"',
    )]
    assert steps == sorted(steps)


def _ps1_row_takes(rows, int_enum, key, want):
    """Whether some PS1 row stages `want` for `key`, by Import's rules."""
    for (_, k), (value, _, choices) in rows.items():
        if k != key:
            continue
        if choices is not None:
            if type(want) is int and any(v == want for _, v in choices[1:]):
                return True
        elif isinstance(value, list):
            if (isinstance(want, list) and all(isinstance(x, str) for x in want)
                    and sorted(want) == sorted(value)):
                return True
        elif isinstance(value, str):
            if want == value:
                return True
        elif k in int_enum:
            if type(want) is int and want == value:
                return True
        elif type(want) in (bool, int) and int(want) == value:
            return True
    return False


def test_ps1_embedded_presets_import_without_a_note():
    """A preset card shows its own status and none of Import's notes, so an
    embedded preset may carry only fields of a config, row keys in their
    exact case and values a row takes: anything else would be dropped
    behind 'N policies staged'."""
    rows = _ps1_feature_rows()
    keys = {k for _, k in rows}
    m = re.search(r"^\$script:intEnumKeys = @\(([^)]*)\)", _ps1_live(), re.MULTILINE)
    int_enum = set(re.findall(r"'([^']*)'", m.group(1)))
    modes = set(re.findall(r'"(\w+)"', re.search(r"^\$script:dnsModes = @\(([^)]*)\)",
                                                  PS1.read_text(encoding="utf-8"), re.MULTILINE).group(1)))
    for name, cfg in _ps1_embedded_presets().items():
        assert set(cfg) <= {"Features", "DnsMode", "DnsTemplates"}, name
        assert cfg.get("DnsMode", "automatic") in modes, name
        for key, want in cfg["Features"].items():
            assert key in keys, f"{name}: {key} is not a row key in this letter case"
            assert _ps1_row_takes(rows, int_enum, key, want), f"{name}: no row takes {key}={want!r}"


def test_ps1_row_keys_suit_the_import_names():
    """Row keys that differ only in letter case would share one spelling in
    $rowFold (and in every PowerShell hashtable keyed by row key); a retired
    key matching a row's key ignoring case would be named as mis-cased
    instead of retired. And items built from a row key show it as written
    only while it looks like a policy name."""
    keys = {k for _, k in _ps1_feature_rows()}
    assert len({k.lower() for k in keys}) == len(keys)
    block = re.search(r"\$script:retiredPolicies = \[ordered\]@\{(.*?)\n\}",
                      PS1.read_text(encoding="utf-8"), re.S).group(1)
    retired = set(re.findall(r'"(\w+)"\s*=', block))
    assert len(retired) == 10
    assert not {k.lower() for k in retired} & {k.lower() for k in keys}
    assert all(re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", k) for k in keys)


def test_ps1_import_code_is_windows_powershell_5_1():
    """No pwsh 7 syntax (??, ?., ternary, && and ||) in the import's code:
    Windows PowerShell 5.1 is the only engine the script targets, and CI's
    5.1 parse is the only place that would catch one."""
    live = _ps1_live()
    for name in IMPORT_FUNCTIONS:
        body = _ps1_function(live, name)
        for token in ("??", "?.", "&&", "||"):
            assert token not in body, f"{name}: {token}"
        assert not re.search(r"\s\?\s", body), f"{name}: a ternary"
