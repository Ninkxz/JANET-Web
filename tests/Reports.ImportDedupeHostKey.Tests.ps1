# =============================================================================
#  Reports.ImportDedupeHostKey.Tests.ps1 - the ACAS import dedupe folds a host
#  spelled two ways, but NEVER folds two different machines together.
#
#  THE DEFECT (loop 2026-08-04, P2): the import dedupe keyed on the RAW hostname
#  while every consumer folds the host through Get-ReportsAuditHostKey (ledger,
#  compare, apply, CORA host counts). One physical box carried as both WEB01 and
#  web01.dom therefore kept TWO live rows per plugin. That is routine on AFNET
#  CSVs - the per-row DNS->NetBIOS fallback yields short names on rows with a
#  blank DNS Name - and guaranteed when Append=true mixes a weekly FQDN export
#  with a daily short-name one. Open counts, SLA aging and burndown totals inflate
#  while UniqueHosts (normalized) stays right, so vulns-per-host is skewed in both
#  directions at once.
#
#  WHY THE OBVIOUS FIX IS WRONG: just folding the key also folds two DISTINCT
#  machines in a cross-domain collision (web01.us.af.mil + web01.eu.af.mil), which
#  would silently DELETE one real host's finding. The two sides of this codebase
#  need opposite defaults: in the compare, uncertainty must not CLOSE a finding;
#  in the import, uncertainty must not DROP one. Losing a vulnerability is strictly
#  worse than double-counting it.
#
#  So the fold is applied only where the short key is unambiguous, using the same
#  Get-ReportsHostKeyCollisions the compare uses, computed over the COMBINED
#  existing+incoming population so an Append that INTRODUCES the collision
#  suppresses folding for that key too.
#
#  These are behavioural: they drive the real 'acas-parse-file' dispatcher over
#  temp CSVs. Run: Invoke-Pester -Path .\tests\Reports.ImportDedupeHostKey.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.reports.psm1') -Force -PassThru
$script:Tmp  = Join-Path ([System.IO.Path]::GetTempPath()) ("rpt_dedupe_" + [guid]::NewGuid().ToString('N'))
[void][System.IO.Directory]::CreateDirectory($script:Tmp)

# Minimal ACAS CSV. Plugin names are chosen to parse as real (non-OS) findings.
function New-AcasCsv {
    param([string]$Name, $Rows)   # Rows: @(@{ Host='WEB01'; Ip='10.0.0.1'; Plugin='19506' }, ...)
    $p = Join-Path $script:Tmp "$Name.csv"
    $lines = New-Object System.Collections.ArrayList
    [void]$lines.Add('Plugin,Plugin Name,Severity,IP Address,NetBIOS Name,DNS Name,Solution')
    foreach ($r in @($Rows)) {
        $isFqdn = ([string]$r.Host) -match '\.'
        $net = if ($isFqdn) { '' } else { $r.Host }
        $dns = if ($isFqdn) { $r.Host } else { '' }
        [void]$lines.Add(('{0},Google Chrome Multiple Vulnerabilities,High,{1},{2},{3},Upgrade Chrome' -f $r.Plugin, $r.Ip, $net, $dns))
    }
    Set-Content -LiteralPath $p -Value $lines -Encoding ASCII
    return $p
}

function Invoke-Import {
    param([string]$Path, [bool]$Append = $false, [bool]$Reset = $true)
    & $script:Mod {
        param($fp, $ap, $rs)
        if ($rs) { $script:AcasFindings = New-Object System.Collections.ArrayList }
        $noop = { param($e) }
        Invoke-JanetToolAction -ActionId 'acas-parse-file' -Params @{ FilePath = $fp; Append = $ap } -Emit $noop
    } $Path $Append $Reset
}

function Get-LoadedCount { (& $script:Mod { @($script:AcasFindings).Count }) }

Describe 'import dedupe - one host spelled two ways is ONE finding' {
    It 'WEB01 and web01.dom.mil on the same plugin collapse to a single row' {
        $csv = New-AcasCsv -Name 'onehost' -Rows @(
            @{ Host = 'WEB01';           Ip = '10.0.0.1'; Plugin = '19506' },
            @{ Host = 'web01.dom.mil';   Ip = '10.0.0.1'; Plugin = '19506' }
        )
        [void](Invoke-Import -Path $csv)
        Get-LoadedCount | Should Be 1
    }
    It 'the same host on two plugins still keeps both findings' {
        $csv = New-AcasCsv -Name 'twoplugins' -Rows @(
            @{ Host = 'WEB01';         Ip = '10.0.0.1'; Plugin = '19506' },
            @{ Host = 'web01.dom.mil'; Ip = '10.0.0.1'; Plugin = '19507' }
        )
        [void](Invoke-Import -Path $csv)
        Get-LoadedCount | Should Be 2
    }
    It 'a plain re-import of the same file adds nothing (the original purpose)' {
        $csv = New-AcasCsv -Name 'reimport' -Rows @(
            @{ Host = 'WS-1'; Ip = '10.0.1.1'; Plugin = '19506' },
            @{ Host = 'WS-2'; Ip = '10.0.1.2'; Plugin = '19506' }
        )
        [void](Invoke-Import -Path $csv)
        Get-LoadedCount | Should Be 2
        [void](Invoke-Import -Path $csv -Append $true -Reset $false)
        Get-LoadedCount | Should Be 2
    }
}

Describe 'import dedupe - two DIFFERENT machines are never folded away' {
    # The dangerous case. web01.us.af.mil and web01.eu.af.mil are distinct boxes that
    # fold to the same short key. Folding the dedupe key would delete one real host's
    # vulnerability. Both rows must survive.
    It 'a cross-domain collision keeps BOTH findings' {
        $csv = New-AcasCsv -Name 'collide' -Rows @(
            @{ Host = 'web01.us.af.mil'; Ip = '10.0.2.1'; Plugin = '19506' },
            @{ Host = 'web01.eu.af.mil'; Ip = '10.0.2.9'; Plugin = '19506' }
        )
        [void](Invoke-Import -Path $csv)
        Get-LoadedCount | Should Be 2
    }
    # DOCUMENTED RESIDUAL, asserted so it is a known state and not a surprise.
    # Two rows carrying the IDENTICAL bare short name on different IPs still fold to
    # one. The collision guard flags the key, but falling back to the RAW hostname
    # cannot separate them - the raw hostname is the same string. This is pre-existing
    # behaviour that this change does not alter (the old raw key folded them too).
    #
    # It is deliberately NOT "fixed" by adding the IP to the key: the far more common
    # cause of one short name on two IPs is ONE host whose DHCP lease changed between
    # the weekly and daily export, and keying on IP would re-inflate exactly the counts
    # this change exists to correct. Distinguishing the two needs a real discriminator
    # (an FQDN, or a scan timestamp), not a guess.
    It 'two rows with the IDENTICAL bare name on different IPs still fold (known residual)' {
        $csv = New-AcasCsv -Name 'collideip' -Rows @(
            @{ Host = 'WEB02'; Ip = '10.0.3.1'; Plugin = '19506' },
            @{ Host = 'WEB02'; Ip = '10.0.3.9'; Plugin = '19506' }
        )
        [void](Invoke-Import -Path $csv)
        Get-LoadedCount | Should Be 1
    }
    It 'an APPEND that introduces the collision does not retroactively fold' {
        # First file: one box, two spellings -> folds to 1.
        $a = New-AcasCsv -Name 'appA' -Rows @( @{ Host = 'WEB03'; Ip = '10.0.4.1'; Plugin = '19506' } )
        [void](Invoke-Import -Path $a)
        Get-LoadedCount | Should Be 1
        # Second file introduces a DIFFERENT machine under the same short name.
        $b = New-AcasCsv -Name 'appB' -Rows @( @{ Host = 'web03.eu.af.mil'; Ip = '10.0.4.9'; Plugin = '19506' } )
        [void](Invoke-Import -Path $b -Append $true -Reset $false)
        # The collision is now proven, so the incoming row must NOT be swallowed.
        Get-LoadedCount | Should Be 2
    }
}

Describe 'import dedupe - the fold agrees with what the consumers use' {
    $src = Get-Content (Join-Path $script:Root 'modules\JanetWeb.reports.psm1') -Raw

    It 'the dedupe key is built from Get-ReportsAuditHostKey, like every consumer' {
        ($src -match '\$hk = Get-ReportsAuditHostKey \$e\.Hostname') | Should Be $true
        ($src -match '\$hk = Get-ReportsAuditHostKey \$f\.Hostname') | Should Be $true
    }
    It 'and it falls back to the RAW hostname on a proven collision' {
        (@([regex]::Matches($src, '-not \$dedupeCollisions\.Contains\(\$hk\)')).Count) | Should Be 2
    }
    It 'the collision set is computed over existing AND incoming findings' {
        ($src -match 'foreach \(\$f in \$findings\)            \{ \[void\]\$dedupeNames\.Add') | Should Be $true
    }
}
