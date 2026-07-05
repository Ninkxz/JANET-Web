# =============================================================================
#  Adsearch.Xpath.Tests.ps1 - Pester 3.4 test for the LastPC XPath literal
#  builder (audit#15): a sAMAccountName containing an apostrophe must produce a
#  VALID XPath expression (via concat), not a string that closes early and throws.
# =============================================================================

# Mirror of the inline $xpathLiteral builder in JanetWeb.adsearch.psm1.
function New-AdXPathLiteral {
    param([string]$v)
    if ($v -notmatch "'") { return "'$v'" }
    $parts = $v -split "'"
    $pieces = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt $parts.Count; $i++) {
        if ($parts[$i] -ne '') { [void]$pieces.Add("'$($parts[$i])'") }
        if ($i -lt $parts.Count - 1) { [void]$pieces.Add('"' + "'" + '"') }
    }
    return 'concat(' + ($pieces -join ', ') + ')'
}

function Test-XPathCompiles {
    param([string]$Expr)
    $doc = New-Object System.Xml.XmlDocument
    $doc.LoadXml('<r><Data>x</Data></r>')
    try { [void]$doc.DocumentElement.SelectNodes("*[$Expr]"); return $true } catch { return $false }
}

Describe 'LastPC XPath literal builder (audit#15)' {

    It 'emits a plain literal for a name with no apostrophe' {
        (New-AdXPathLiteral 'jdoe') | Should Be "'jdoe'"
    }

    It 'emits a concat() for a name containing an apostrophe' {
        (New-AdXPathLiteral "O'Brien") | Should Be 'concat(''O'', "''", ''Brien'')'
    }

    It 'produces a VALID XPath expression for an apostrophe name (the bug: it used to throw)' {
        $expr = "starts-with(Data, $(New-AdXPathLiteral "O'Brien"))"
        (Test-XPathCompiles $expr) | Should Be $true
    }

    It 'handles multiple apostrophes' {
        $expr = "starts-with(Data, $(New-AdXPathLiteral "d'ar'cy"))"
        (Test-XPathCompiles $expr) | Should Be $true
    }
}
