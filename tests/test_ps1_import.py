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

# A backslash and a u, for the \u escapes the PS1's regexes and escapers
# spell out as text: written out with four hex digits in a Python string, one
# would be read as the character itself.
U = "\\" + "u"

# The Import status after 'Imported from <file>', clause by clause in its
# fixed order: lead, reason, the list it names, and the kind that says how
# Format-ImportEntry shows that list's entries. The reasons are the Python
# scripts' words; only the lead and the punctuation differ (Python:
# '; left unmanaged because <reason>: <items>'). The exclusion-group clause
# follows these, in its old form.
IMPORT_CLAUSES = [
    ("Left unmanaged", "names are case-sensitive", "(@($script:importMiscased)+@($top.Case))", "Case"),
    ("Left unmanaged", "the value is not one this policy accepts", "$script:importNotes", "Item"),
    ("Left unmanaged", "no row sets that value", "$script:importUnwritten", "Item"),
    ("Left unmanaged", "SlimBrave Neo no longer offers it", "$script:importRetired", "Name"),
    ("Left unmanaged", "SlimBrave Neo does not offer it", "$script:importUnknown", "Unknown"),
    ("Ignored", "it is not a SlimBrave Neo setting", "$top.Other", "Name"),
]

# The lists Import-PresetIntoState fills, one per clause it names, and the
# type of their entries: the case list pairs each name with its spelling.
IMPORT_LISTS = {"importMiscased": "object", "importNotes": "string", "importUnwritten": "string",
                "importRetired": "string", "importUnknown": "string"}

# What each clause's list is filled with, Add by Add: an item Format-ImportItem
# made ($missed and $wrong hold only those), a name as the file wrote it,
# Format-ImportValue's text for a legacy entry that is no string, or a pair of
# a name and the spelling it needs. Read-ImportFields fills $Top's two.
IMPORT_ADDS = {
    "$script:importNotes": {"$wrong[$n]", "(Format-ImportItem 'DnsMode' $preset.dns)"},
    "$script:importUnwritten": {"$missed[$n]"},
    "$script:importMiscased": {"@($Name, $canon)"},
    "$top.Case": {"@($n, $canon)"},
    "$script:importRetired": {"$Name"},
    "$script:importUnknown": {"$Name", "$shown"},
    "$top.Other": {"$n"},
}

# Every function the import's naming goes through.
IMPORT_FUNCTIONS = ("Import-PresetIntoState", "Test-ImportSameList", "Add-ImportNameNote",
                    "Get-ImportDnsHint", "Get-ImportCanonical", "Read-ImportFields",
                    "Read-ImportTemplate", "Format-ImportText", "Format-ImportString",
                    "Format-ImportName", "Format-ImportValue", "Format-ImportItem",
                    "Format-ImportFileName", "Format-ImportEntry", "Get-ImportClause")


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
    ["*"] used to pass the [string] cast). A list compares ordinally, as
    Python's sorted() and == do: Compare-Object went by the current
    culture, which skips ignorable characters, so "https://*" with a soft
    hyphen (U+00AD) in it ticked Disable Brave Shields."""
    live = _ps1_live()
    imp = _imp()
    assert "$strings -and (Test-ImportSameList $wantList $mine)) {" in imp
    for name in IMPORT_FUNCTIONS:
        assert "Compare-Object" not in _ps1_function(live, name), name
    same = _ps1_function(live, "Test-ImportSameList")
    steps = [same.index(s) for s in (
        "function Test-ImportSameList([string[]]$Want, [string[]]$Mine) {",
        "if ($Want.Length -ne $Mine.Length) { return $false }",
        "$a = [string[]]$Want.Clone()",
        "$b = [string[]]$Mine.Clone()",
        "[Array]::Sort($a, [System.StringComparer]::Ordinal)",
        "[Array]::Sort($b, [System.StringComparer]::Ordinal)",
        "for ($i = 0; $i -lt $a.Length; $i++) {",
        "if (-not [string]::Equals($a[$i], $b[$i], [System.StringComparison]::Ordinal)) { return $false }",
        "return $true",
    )]
    assert steps == sorted(steps)
    for op in ("-eq ", "-ceq", "-ieq", "-contains", "-like", "Sort-Object"):
        assert op not in same, op
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
    legacy entry that is not a string is named by its value, once per value
    text as the Python scripts name it: [5, 5, null, null] names 5 and null
    once each. Its set is not the names' set, so a string "5" and a number
    5 are both named, as there."""
    live = _ps1_live()
    imp = _ps1_function(live, "Import-PresetIntoState")
    legacy = _legacy(imp)
    assert "if (-not $rowKeys.Contains($n)) { Add-ImportNameNote $n $rowFold $retired }" in legacy
    assert ("$shownValues = [System.Collections.Generic.HashSet[string]]::new("
            "[System.StringComparer]::Ordinal)") in legacy
    steps = [legacy.index(s) for s in (
        "$shown = Format-ImportValue $n",
        "if (($null -ne $shown) -and $shownValues.Add($shown)) { $script:importUnknown.Add($shown) }",
    )]
    assert steps == sorted(steps)
    assert "$names.Add($shown)" not in legacy and "$shownValues.Add($n)" not in legacy
    note = _ps1_function(live, "Add-ImportNameNote")
    steps = [note.index(s) for s in ("$canon = Get-ImportCanonical $Name $RowFold",
                                     "$script:importMiscased.Add(@($Name, $canon))",
                                     "} elseif ($Retired.Contains($Name)) {",
                                     "$script:importRetired.Add($Name)",
                                     "} else { $script:importUnknown.Add($Name) }")]
    assert steps == sorted(steps)
    # Where a DNS name belongs is added when the clause is shown.
    entry = _ps1_function(live, "Format-ImportEntry")
    steps = [entry.index(s) for s in ("if ([string]::Equals($Kind, 'Unknown', [System.StringComparison]::Ordinal)) {",
                                      "$hint = Get-ImportDnsHint $Entry",
                                      "if ($null -ne $hint) { $item = $item + ' (' + $hint + ')' }")]
    assert steps == sorted(steps)
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
    # Case holds pairs of a name and its spelling; Other holds names.
    assert handler.index("$top=@{Case=[System.Collections.Generic.List[object]]::new(); "
                         "Other=[System.Collections.Generic.List[string]]::new(); Found=\"\"}") < try_at
    assert handler.index("$dupWhy=$null") < try_at
    assert handler.index("$failWhy=$null") < try_at
    guard_at = handler.index("if(-not ($cfg -is")
    assert handler.index("$field=Read-ImportFields $cfg $top") < guard_at
    guard = handler[guard_at:handler.index('throw "no Features block"')]
    assert "-not $field.ContainsKey('Features') -or" in guard
    assert guard.index("$field.ContainsKey('Features')") < guard.index("$cfg.Features"), (
        "$cfg.Features is read before Features is known to be spelled exactly")
    assert ("Import-PresetIntoState @{features=$cfg.Features;dns=$field['DnsMode'];"
            "tmpl=$template.Text}") in handler
    fields = _ps1_function(_ps1_live(), "Read-ImportFields")
    for line in ("foreach ($f in @('Features', 'DnsMode', 'DnsTemplates')) { $fold.Add($f, $f) }",
                 "if ($fold.ContainsKey($n) -and [string]::Equals($fold[$n], $n, "
                 "[System.StringComparison]::Ordinal)) {",
                 "$canon = Get-ImportCanonical $n $fold",
                 "$Top.Case.Add(@($n, $canon))",
                 "if ([string]::Equals($canon, 'Features', [System.StringComparison]::Ordinal)) "
                 "{ $Top.Found = $n }",
                 "} else { $Top.Other.Add($n) }"):
        assert line in fields, line


def test_ps1_import_status_names_each_class_in_order():
    """One clause per class, in the fixed order and the reason words the
    Python scripts use, after the lead. 'imported' is gone from the value
    reason. A mis-cased name inside Features comes before one at the top
    level. The exclusion-group clause is last and unchanged."""
    handler = _handler()
    ok = handler[handler.index("if($ok){"):handler.index("} else {", handler.index("Set-Status $msg"))]
    clauses = re.findall(r"^\s*\$tail\+=Get-ImportClause '([^']*)' '([^']*)' (.+?) '(\w+)'\s*$", ok, re.MULTILINE)
    assert clauses == IMPORT_CLAUSES
    assert ok.count("$tail+=Get-ImportClause") == len(IMPORT_CLAUSES)
    lead = ok.index('$lead="Imported from "+(Format-ImportFileName ([System.IO.Path]::GetFileName($dlg.FileName)))')
    groups = ok.index('$tail+=" Left unmanaged, because it is mutually exclusive with another imported row: "'
                      '+(($script:importConflicts | Sort-Object -Unique) -join ", ")+"."')
    assert lead < ok.index("$tail+=Get-ImportClause") < ok.index("$tail+=Get-ImportClause 'Ignored'") < groups
    # A full stop ends the lead only when a clause follows it.
    join = ok.index("if($tail){ $msg=$lead+'.'+$tail } else { $msg=$lead }")
    assert groups < join < ok.index("Set-Status $msg")
    assert "the imported value" not in PS1.read_text(encoding="utf-8")


def test_ps1_import_clause_has_the_python_shape():
    """' <Lead>, because <reason>: a, b, c, d, e and 3 more.' - five items at
    most, as in the Python scripts, so a file naming a thousand keys cannot
    bury the other clauses, and nothing at all when the list is empty. Only
    the items shown are formatted; the rest are counted, so the count
    behind ' and N more' is every entry the list holds."""
    live = _ps1_live()
    assert re.search(r"^\$script:IMPORT_MAX_ITEMS = 5$", live, re.MULTILINE)
    clause = _ps1_function(live, "Get-ImportClause")
    steps = [clause.index(s) for s in (
        "function Get-ImportClause([string]$Lead, [string]$Reason, $Items, [string]$Kind) {",
        "if ($null -eq $Items) { return '' }",
        "$all = @($Items)",
        "if ($all.Count -eq 0) { return '' }",
        "$shown = [math]::Min($all.Count, $script:IMPORT_MAX_ITEMS)",
        "$parts = [System.Collections.Generic.List[string]]::new()",
        "for ($i = 0; $i -lt $shown; $i++) { $parts.Add((Format-ImportEntry $Kind $all[$i])) }",
        "$text = ' ' + $Lead + ', because ' + $Reason + ': ' + ($parts -join ', ')",
        "if ($all.Count -gt $shown) { $text += ' and ' + ($all.Count - $shown) + ' more' }",
        "return $text + '.'",
    )]
    assert steps == sorted(steps)
    assert clause.count("Format-Import") == 1 and "foreach" not in clause and "$all[0..(" not in clause


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
    """Nothing from the file reaches the status unescaped: the old
    "$($row.key)=$want" and "DnsMode=$want" items echoed raw text, a newline
    or a bidi override included. A clause's list holds either items
    Format-ImportItem made, which the clause's kind 'Item' shows as they
    are, or the file's names as it wrote them, which every other kind shows
    through Format-ImportName when the status is built. A spelling a pair
    carries is a known name, from a fold's values."""
    live = _ps1_live()
    imp = _ps1_function(live, "Import-PresetIntoState")
    assert '"$($row.key)=$want"' not in imp and "DnsMode=$want" not in imp
    assert "$script:importNotes.Add((Format-ImportItem 'DnsMode' $preset.dns))" in imp
    adds = list(re.finditer(r"(\$script:(?:" + "|".join(IMPORT_LISTS) + r")|\$Top\.(?:Case|Other))"
                            r"\.Add\((.*)\)\s*\}?\s*$", live, re.MULTILINE))
    # Import-PresetIntoState 4, Add-ImportNameNote 3, Read-ImportFields 2.
    assert len(adds) == 9
    seen = {}
    for m in adds:
        target = m.group(1).replace("$Top.", "$top.")
        assert m.group(2) in IMPORT_ADDS[target], m.group(0)
        assert _function_at(live, m.start()) in ("Import-PresetIntoState", "Add-ImportNameNote",
                                                 "Read-ImportFields"), m.group(0)
        seen.setdefault(target, set()).add(m.group(2))
    assert seen == IMPORT_ADDS
    # $missed and $wrong hold only escaped items.
    assert not re.search(r"\$(?:missed|wrong)\[\$row\.key\] = (?!Format-ImportItem )", imp)
    # The kind 'Item' only for lists every Add of which is a made item.
    made = {"$wrong[$n]", "$missed[$n]", "(Format-ImportItem 'DnsMode' $preset.dns)"}
    for _, _, items, kind in IMPORT_CLAUSES:
        lists = re.findall(r"\$(?:script|top)[:.]\w+", items)
        assert lists and all(x in IMPORT_ADDS for x in lists), items
        assert (kind == "Item") == all(IMPORT_ADDS[x] <= made for x in lists), items
        assert (kind == "Case") == all(a.startswith("@(") for x in lists for a in IMPORT_ADDS[x]), items
    entry = _ps1_function(live, "Format-ImportEntry")
    steps = [entry.index(s) for s in (
        "function Format-ImportEntry([string]$Kind, $Entry) {",
        "if ([string]::Equals($Kind, 'Item', [System.StringComparison]::Ordinal)) { return [string]$Entry }",
        "if ([string]::Equals($Kind, 'Case', [System.StringComparison]::Ordinal)) {\n"
        "        return (Format-ImportName $Entry[0]) + ' (use ' + $Entry[1] + ')'",
        "$item = Format-ImportName $Entry",
        "return $item",
    )]
    assert steps == sorted(steps)
    # The spelling is a fold's value: a row key or one of the three fields.
    canon = _ps1_function(live, "Get-ImportCanonical")
    assert "if ($Fold.ContainsKey($Name)) { return $Fold[$Name] }" in canon
    assert "$rowFold.Add($row.key, $row.key)" in imp


def test_ps1_import_lists_are_made_before_use():
    """Each clause's list is a fresh List before anything is staged or
    named: a List[object] for the case list, whose entries are pairs (a
    List[string] would join a pair into one string, silently), and a
    List[string] for the rest. A List takes .Add; += on one silently turns
    it into an array, and += onto $null joins strings, so no import list is
    ever +='d. The handler's own collections exist before its try, so a
    failed read never leaves a previous import's names behind."""
    live = _ps1_live()
    imp = _ps1_function(live, "Import-PresetIntoState")
    first = imp.index("$feat = $preset.features")
    for name, held in IMPORT_LISTS.items():
        assert imp.index(f"$script:{name} = [System.Collections.Generic.List[{held}]]::new()") < first, name
    # Exactly the lists filled with pairs are List[object]; the handler makes
    # $top's two (test_ps1_import_reads_the_three_fields_in_exact_case).
    held = dict(IMPORT_LISTS, Case="object", Other="string")
    for target, adds in IMPORT_ADDS.items():
        name = re.split(r"[:.]", target)[-1]
        assert (held[name] == "object") == all(a.startswith("@(") for a in adds), target
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
        "} elseif($failWhy){\n                            $why=$failWhy\n",
        '} elseif($top.Found){ $why+=" (found "+(Format-ImportName $top.Found)+"; names are case-sensitive)" }',
        'Set-Status "Import failed - $why"',
    )]
    assert steps == sorted(steps)


def test_ps1_import_says_a_key_is_empty():
    """Windows PowerShell 5.1 cannot read a file with a key "" at any depth.
    Its ConvertFrom-Json (PopulateFromDictionary in the non-CoreCLR
    JsonObject.cs) looks each key up in PSObject.Properties[...], whose
    indexer throws PSTraceSource.NewArgumentException("name"): a
    PSArgumentException, error id Argument, which CmdletInvocationException
    keeps (FullyQualifiedErrorId Argument,...ConvertFromJsonCommand). The
    catch knows it by all three - the id on ConvertFrom-Json, the type and
    its parameter - before the restore loop, and the status says 'Import
    failed - a key is empty' instead of 'not a SlimBrave config'. Read from
    source; owed to a Windows run."""
    live = _ps1_live()
    handler = live[live.index('"Import" {'):]
    catch = re.search(r"\} catch \{((?:[^{}]|\{[^{}]*\})*)\}", handler[handler.index("$ok=$true"):])
    body = catch.group(1)
    empty = ("if(([string]$_.FullyQualifiedErrorId -like 'Argument,*.ConvertFromJsonCommand') -and\n"
             "                           ($_.Exception -is [System.Management.Automation.PSArgumentException]) -and\n"
             "                           [string]::Equals([string]$_.Exception.ParamName, 'name', "
             "[System.StringComparison]::Ordinal)){ $failWhy=\"a key is empty\" }")
    assert empty in body
    dup = "if([string]$_.FullyQualifiedErrorId -like 'DuplicateKeysInJsonString,*')"
    assert body.index(dup) < body.index(empty) < body.index("foreach($id in @($snap.Keys))")
    assert body.count("$failWhy=") == 1


def test_ps1_import_reads_a_dns_mode_as_the_python_scripts_do():
    """A DnsMode counts unless it is missing, null or "". PowerShell's own
    truth test took [0] for no mode and {} for one, where the Python
    scripts differ; now false, 0, a list or an object is a value that names
    no mode, so it is named (DnsMode=false, DnsMode) and DNS stays
    unmanaged. The mode word matches ignoring case, OrdinalIgnoreCase on
    printable ASCII only, as Python's .lower() matches the ASCII words: -eq
    compared linguistically, and "se" + U+00AD + "cure" set secure DNS."""
    imp = _imp()
    dns = imp[imp.index('$script:dnsState.Tmpl = ""'):imp.index("Enforce-ExclusionGroups")]
    assert "if ($preset.dns) {" not in dns and "$_ -eq $want" not in dns
    steps = [dns.index(s) for s in (
        "if (($null -ne $preset.dns) -and -not (($preset.dns -is [string]) -and ($preset.dns.Length -eq 0))) {",
        "if (($preset.dns -is [string]) -and ($want -cmatch '^[\\x20-\\x7E]*\\z')) {",
        "$canon = @($script:dnsModes | Where-Object { [string]::Equals($_, $want, "
        "[System.StringComparison]::OrdinalIgnoreCase) })",
        "$script:dnsState.Mode = [Array]::IndexOf($script:dnsModes, $canon[0])",
        "} else { $script:importNotes.Add((Format-ImportItem 'DnsMode' $preset.dns)) }",
        "} elseif ($script:dnsState.Tmpl) {",
    )]
    assert steps == sorted(steps)
    # The same printable-ASCII gate as the names' (Get-ImportCanonical).
    gate = "-cmatch '^[\\x20-\\x7E]*\\z'"
    assert gate in _ps1_function(_ps1_live(), "Get-ImportCanonical")


def test_ps1_import_reads_dns_templates_as_the_python_scripts_do():
    """DnsTemplates: missing, null or "" is no template, a string is the
    template, an array of strings is joined with spaces. Anything else
    passed a [string] cast (5 became the template "5", [0] too), and is now
    refused with the Python scripts' reason, as is a template with a
    control character (C0, DEL, C1, U+2028, U+2029) or a bidi control
    (U+061C, U+200E, U+200F, U+202A-U+202E, U+2066-U+2069). The refusal comes
    after the Features check and before any row is touched, and the status
    says it."""
    live = _ps1_live()
    tmpl = _ps1_function(live, "Read-ImportTemplate")
    ctl = ("'[\\x00-\\x1F\\x7F-\\x9F" + U + "2028" + U + "2029" + U + "061C" + U + "200E"
           + U + "200F" + U + "202A-" + U + "202E" + U + "2066-" + U + "2069]'")
    steps = [tmpl.index(s) for s in (
        "function Read-ImportTemplate($Value) {",
        "$text = $Value",
        "if ($Value -is [array]) {",
        "if (-not ($x -is [string])) { return @{ Text = ''; Why = 'DnsTemplates must be a string' } }",
        "$text = $parts -join ' '",
        "if ($null -eq $text) { return @{ Text = ''; Why = $null } }",
        "if (-not ($text -is [string])) { return @{ Text = ''; Why = 'DnsTemplates must be a string' } }",
        "if ($text -cmatch " + ctl + ") {",
        "return @{ Text = ''; Why = 'DnsTemplates contains a control character' }",
        "return @{ Text = $text; Why = $null }",
    )]
    assert steps == sorted(steps)
    # .NET and Python read these escapes alike: the class is exactly the
    # control characters, over every UTF-16 code unit.
    cls = re.compile(ctl.strip("'"))
    bidi = {0x061C, 0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A)}
    want = {c for c in range(0x10000) if c < 0x20 or 0x7F <= c <= 0x9F or c in (0x2028, 0x2029) or c in bidi}
    assert {c for c in range(0x10000) if cls.search(chr(c))} == want
    handler = _handler()
    steps = [handler.index(s) for s in (
        'throw "no Features block"',
        "$template=Read-ImportTemplate $field['DnsTemplates']",
        "if($null -ne $template.Why){ $failWhy=$template.Why; throw $failWhy }",
        "Import-PresetIntoState @{features=$cfg.Features;dns=$field['DnsMode'];tmpl=$template.Text}",
        "} elseif($failWhy){\n                            $why=$failWhy\n",
    )]
    assert steps == sorted(steps)
    assert "tmpl=$field['DnsTemplates']" not in handler
    # What Import-PresetIntoState is handed is a string, which it takes as is.
    assert "if ($preset.tmpl) { $script:dnsState.Tmpl = [string]$preset.tmpl }" in _imp()


def test_ps1_import_lead_escapes_the_file_name():
    """The lead names the file by the Python scripts' rule: only what could
    move, reorder or hide text - a control or bidi character, a zero-width
    format character, a lone surrogate - as \\uXXXX in uppercase hex, no
    quotes added and nothing cut; a Cyrillic, CJK or emoji name shows as it
    is. A Windows file name can carry a bidi override (U+202E), which
    reordered the whole status bar."""
    live = _ps1_live()
    name = _ps1_function(live, "Format-ImportFileName")
    steps = [name.index(s) for s in (
        "function Format-ImportFileName([string]$Name) {",
        "$sb = [System.Text.StringBuilder]::new()",
        "for ($i = 0; $i -lt $Name.Length; $i++) {",
        "$ch = $Name[$i]",
        "$code = [int]$ch",
        "$unsafe = (($code -lt 0x20) -or (($code -ge 0x7F) -and ($code -le 0x9F)) -or",
        "($code -eq 0x061C) -or ($code -eq 0x200E) -or ($code -eq 0x200F) -or",
        "(($code -ge 0x200B) -and ($code -le 0x200D)) -or",
        "if ((-not $unsafe) -and [char]::IsSurrogate($ch)) {",
        "$unsafe = -not $paired",
        "if ($unsafe) {\n"
        "            [void]$sb.Append('" + U + "' + $code.ToString('X4'))",
        "} else { [void]$sb.Append([string]$ch) }",
        "return $sb.ToString()",
    )]
    assert steps == sorted(steps)
    assert "Substring" not in name and "-le $Max" not in name and "'\"'" not in name
    handler = _handler()
    assert ('$lead="Imported from "+(Format-ImportFileName '
            '([System.IO.Path]::GetFileName($dlg.FileName)))') in handler
    assert "Imported from $(" not in handler


def test_ps1_import_formats_only_the_names_it_shows():
    """A file can name a hundred thousand keys, and Windows PowerShell 5.1
    pays for every script-function call on the UI thread. The lists keep
    names as the file wrote them: nothing escapes a name or looks up a DNS
    hint while they fill, only Get-ImportClause for the first
    $script:IMPORT_MAX_ITEMS of each clause, as the Python scripts store
    raw names and format five. A legacy value is the exception: its text
    is what it is de-duplicated by, as there."""
    live = _ps1_live()
    for name in ("Add-ImportNameNote", "Read-ImportFields"):
        body = _ps1_function(live, name)
        assert "Format-Import" not in body and "Get-ImportDnsHint" not in body, name
    imp = _ps1_function(live, "Import-PresetIntoState")
    assert _legacy(imp).count("Format-Import") == 1
    tail = imp[imp.index("foreach ($p in $feat.PSObject.Properties)"):imp.index("$script:dnsState.Mode = 0")]
    assert "Format-Import" not in tail and "Get-ImportDnsHint" not in tail
    calls = [m.start() for m in re.finditer(r"(?<!function )\bFormat-ImportEntry\b", live)]
    assert [_function_at(live, c) for c in calls] == ["Get-ImportClause"]


def test_ps1_import_shows_a_legacy_value_as_its_text():
    """A legacy entry that is no string waits in importUnknown as the text
    Format-ImportValue gives it, beside the names, and comes out of
    Format-ImportEntry's 'Unknown' as it went in: true, false, null and any
    Int64 in decimal look like a policy name to Format-ImportName, and no
    DNS hint is for one of them."""
    live = _ps1_live()
    name = _ps1_function(live, "Format-ImportName")
    pattern = re.search(r"\$Name -cmatch '([^']*)'", name).group(1)
    assert pattern == "^[A-Za-z0-9_.-]{1,64}\\z"
    plain = re.compile(pattern.replace("\\z", "\\Z"))
    for text in ("true", "false", "null", "0", "-1", str(2**63 - 1), str(-2**63)):
        assert plain.match(text), text
    hints = re.findall(r"\[string\]::Equals\(\$Name, '(\w+)'", _ps1_function(live, "Get-ImportDnsHint"))
    assert len(hints) == 4 and not any(plain.match(h) is None for h in hints)
    assert not {"true", "false", "null"} & set(hints) and not any(h.lstrip("-").isdigit() for h in hints)
    value = _ps1_function(live, "Format-ImportValue")
    for line in ("if ($null -eq $Value) { return 'null' }",
                 "if ($Value) { return 'true' }",
                 "return 'false'",
                 "$digits = $Value.ToString([System.Globalization.CultureInfo]::InvariantCulture)"):
        assert line in value, line


def test_ps1_import_takes_an_integer_past_int64_for_a_fraction():
    """Windows PowerShell 5.1's ConvertFrom-Json reads an integer as an
    [int], then a [long], then a [decimal] or a [double]. Only [int] and
    [long] are integers anywhere in Import, so 2**63 and beyond is named by
    its key alone under 'the value is not one this policy accepts', and a
    legacy entry of one is left out, as the Python scripts now treat an
    integer outside 64 bits."""
    live = _ps1_live()
    imp = _ps1_function(live, "Import-PresetIntoState")
    value = _ps1_function(live, "Format-ImportValue")
    for body in (imp, value):
        for t in ("[decimal]", "[double]", "[single]", "[float]", "[bigint]", "BigInteger", "[ValueType]"):
            assert t not in body, t
    assert set(re.findall(r"\$want -is \[(\w+)\]", imp)) == {"int", "long", "bool", "string", "array"}
    for line in ("$ok = ($want -is [int] -or $want -is [long])",
                 "$fits = (($want -is [int]) -or ($want -is [long]))",
                 "$fits = (($want -is [bool]) -or ($want -is [int]) -or ($want -is [long]))"):
        assert line in imp, line
    assert "if (($Value -is [int]) -or ($Value -is [long])) {" in value
    # Anything the type checks refuse is named by Format-ImportItem, which
    # shows the key alone where Format-ImportValue gives $null.
    assert "if ($null -eq $shown) { return (Format-ImportName $Key) }" in _ps1_function(live, "Format-ImportItem")


def test_ps1_import_puts_features_items_before_the_top_level():
    """Inside a clause, items keep file order, Features first: the Features
    keys (or legacy entries), then the DnsMode note, then the other
    top-level fields - the order the Python scripts now walk. The
    exclusion-group clause stays sorted and is never capped."""
    live = _ps1_live()
    imp = _ps1_function(live, "Import-PresetIntoState")
    assert (imp.index("foreach ($n in $feat)") < imp.index("foreach ($p in $feat.PSObject.Properties)")
            < imp.index("$script:importNotes.Add((Format-ImportItem 'DnsMode' $preset.dns))"))
    handler = _handler()
    ok = handler[handler.index("if($ok){"):]
    assert "(@($script:importMiscased)+@($top.Case))" in ok
    groups = ok[ok.index("if($script:importConflicts.Count -gt 0){"):ok.index("Set-Status $msg")]
    assert '(($script:importConflicts | Sort-Object -Unique) -join ", ")' in groups
    assert "Get-ImportClause" not in groups and "IMPORT_MAX_ITEMS" not in groups


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
