# =============================================================================
#  Acas.Kev.Tests.ps1 - Pester 3.4 tests for the ACAS KEV-badging helpers
#  (Read-AcasKevSet / Test-AcasCvesInKev) that flag known-exploited groups at
#  the point of remediation.
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.acas.psm1') -Force -PassThru

Describe 'ACAS KEV badging helpers' {

    It 'Read-AcasKevSet returns a case-insensitive HashSet (preserved on assignment)' {
        $isSet = & $script:Mod { $s = Read-AcasKevSet; $s -is [System.Collections.Generic.HashSet[string]] }
        $isSet | Should Be $true
    }

    It 'Test-AcasCvesInKev matches a CVE in the set (case-insensitive)' {
        $r = & $script:Mod {
            $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            [void]$set.Add('CVE-2021-44228')
            [pscustomobject]@{
                Hit   = (Test-AcasCvesInKev -CveCell 'CVE-2020-1, CVE-2021-44228' -KevSet $set)
                Lower = (Test-AcasCvesInKev -CveCell 'cve-2021-44228' -KevSet $set)
                Miss  = (Test-AcasCvesInKev -CveCell 'CVE-2019-9999' -KevSet $set)
                Empty = (Test-AcasCvesInKev -CveCell '' -KevSet $set)
            }
        }
        $r.Hit   | Should Be $true
        $r.Lower | Should Be $true
        $r.Miss  | Should Be $false
        $r.Empty | Should Be $false
    }

    It 'Test-AcasCvesInKev is false for an empty/null KEV set (no badging, no error)' {
        $r = & $script:Mod {
            $empty = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            Test-AcasCvesInKev -CveCell 'CVE-2021-44228' -KevSet $empty
        }
        $r | Should Be $false
    }
}

# =============================================================================
#  audit 2026-07-24 (P1) - "the catalog is missing" is NOT "nothing is exploited".
#  Read-AcasKevSet swallowed a missing / unreadable / zero-CVE catalog into the
#  SAME empty set a clean catalog produces: every card rendered un-badged, the
#  analyze summary said nothing at all, and an operator reads that green as "none
#  of this is being actively exploited". The read now records WHY the set is empty
#  and Get-AcasKevSummaryState turns that into a third, visible state.
# =============================================================================
Describe 'ACAS KEV catalog availability - an unreadable catalog is never an all-clear' {

    $kevTmp  = Join-Path $env:TEMP ('acas-kev-' + [guid]::NewGuid().ToString('N').Substring(0,8))
    New-Item -ItemType Directory -Path $kevTmp -Force | Out-Null
    $kevGood    = Join-Path $kevTmp 'good.txt'
    $kevBlank   = Join-Path $kevTmp 'blank.txt'
    $kevMissing = Join-Path $kevTmp 'no-such-catalog.txt'
    Set-Content -LiteralPath $kevGood  -Value "CVE-2021-44228`r`nCVE-2017-0144" -Encoding ASCII
    Set-Content -LiteralPath $kevBlank -Value '# refresh me - no CVEs in here yet' -Encoding ASCII

    # Drive the REAL read, then ask the module what state that read left behind.
    function Get-KevReadState { param([string]$P) & $script:Mod { param($p) $null = Read-AcasKevSet -Path $p; Get-AcasKevCatalogStatus } $P }
    function Get-KevState { param([string]$S, [int]$N) & $script:Mod { param($s, $n) Get-AcasKevSummaryState -CatalogStatus $s -KevGroups $n } $S $N }

    It 'a readable catalog with CVEs loads them and reports ok' {
        (& $script:Mod { param($p) (Read-AcasKevSet -Path $p).Count } $kevGood) | Should Be 2
        Get-KevReadState $kevGood | Should Be 'ok'
    }
    It 'a MISSING catalog reports "missing" (was indistinguishable from a clean read)' {
        Get-KevReadState $kevMissing | Should Be 'missing'
        (& $script:Mod { param($p) (Read-AcasKevSet -Path $p).Count } $kevMissing) | Should Be 0
    }
    It 'a catalog that parses to ZERO CVEs reports "empty", not ok' {
        Get-KevReadState $kevBlank | Should Be 'empty'
    }
    It 'every not-ok catalog state maps to UNAVAILABLE - never "clear"' {
        Get-KevState 'missing'    0 | Should Be 'unavailable'
        Get-KevState 'unreadable' 0 | Should Be 'unavailable'
        Get-KevState 'empty'      0 | Should Be 'unavailable'
        Get-KevState 'unread'     0 | Should Be 'unavailable'
    }
    It 'a KEV hit count can NEVER promote an unavailable catalog to a real verdict' {
        Get-KevState 'missing' 5 | Should Be 'unavailable'
    }
    It 'only a loaded catalog yields the two real verdicts' {
        Get-KevState 'ok' 0 | Should Be 'clear'
        Get-KevState 'ok' 3 | Should Be 'hits'
    }

    Remove-Item -LiteralPath $kevTmp -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'ACAS analyze-remediation - the KEV state is ALWAYS stated (silence is not a verdict)' {

    # One synthetic finding whose CVE is deliberately not in any KEV catalog, so the
    # run can only end in 'clear' or 'unavailable' - the two states the old code
    # rendered IDENTICALLY (as nothing at all).
    $csv = @"
DNS Name,NetBIOS Name,IP Address,Plugin,Plugin Name,Severity,CVE,Steps to Remediate
WKS-KEV1,WKS-KEV1,10.9.9.9,55555,Some Unmatched Product 1.2.3,High,CVE-2999-0001,Upgrade it
"@
    $evts = New-Object System.Collections.ArrayList
    $emit = { param($e) [void]$evts.Add($e) }
    # log4jSource override short-circuits the staging auto-find (no UNC probe, no tree walk).
    $res = & $script:Mod {
        param($aid, $prm, $em)
        Invoke-JanetToolAction -ActionId $aid -Params $prm -Credential $null -Emit $em
    } 'analyze-remediation' @{ csvText = $csv; log4jSource = $env:TEMP } $emit

    $kevLines = @($evts | Where-Object { $_.type -eq 'log' -and $_.text -match '^KEV' })

    It 'the analyze summary carries the catalog state and the derived verdict' {
        [string]$res.summary.kevCatalog | Should Not Be ''
        @('hits','clear','unavailable') -contains ([string]$res.summary.kevState) | Should Be $true
    }
    It 'exactly ONE KEV state line is emitted - a no-hit / no-catalog run is never silent' {
        $kevLines.Count | Should Be 1
    }
    It 'an unavailable catalog warns; a loaded one does not cry wolf' {
        if ([string]$res.summary.kevState -eq 'unavailable') { $kevLines[0].level | Should Be 'warn' }
        else { [string]$res.summary.kevCatalog | Should Be 'ok' }
    }
    It 'the KEV row cell is "?" (unknown) - never blank - when the catalog is unavailable' {
        $cells = @(@($res.rows) | ForEach-Object { [string]$_.KEV })
        if ([string]$res.summary.kevState -eq 'unavailable') {
            @($cells | Where-Object { $_ -ne '?' }).Count | Should Be 0
        } else {
            @($cells | Where-Object { $_ -eq '?' }).Count | Should Be 0
        }
    }
    It 'each card descriptor carries kevKnown so the view can badge "KEV ?"' {
        $known = @(@($res.groups) | Where-Object { $_.ContainsKey('kevKnown') })
        $known.Count | Should Be @($res.groups).Count
    }
}
