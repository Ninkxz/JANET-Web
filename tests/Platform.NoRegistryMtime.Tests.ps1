# =============================================================================
#  Platform.NoRegistryMtime.Tests.ps1 - nothing reads a timestamp off a REGISTRY
#  KEY, because there isn't one.
#
#  THE FAMILY: Get-Item / Get-ChildItem on a registry path returns RegistryKey
#  objects. RegistryKey has NO .LastWriteTime member (the Win32 key mtime is not
#  exposed without P/Invoke). So every such read is silently $null forever, and any
#  code that then calls a METHOD on it - .ToString('yyyy-MM-dd HH:mm') - THROWS
#  "You cannot call a method on a null-valued expression".
#
#  WHY THIS FILE EXISTS: this is the most-repeated defect in the suite. It has been
#  "fixed" at least five separate times - on the desktop fork it had been fixed four
#  times before anyone counted the live instances, and here loop88 killed three
#  probes (M365 C2R, Oracle Java, health-scan) and still missed a fourth, in TWO
#  modules at once (acas + wpt, the same Unquoted Service Path profile copied
#  between them). Every one of those fixes was site-scoped, so the next paste
#  reintroduced it and the tests stayed green.
#
#  So this asserts the SHAPE across every module and expects a count of ZERO. A new
#  profile pasted from an old one fails on its first run.
#
#  The 2026-08-04 instances were especially quiet: the read only threw where the
#  backup key had CHILDREN - i.e. only on hosts the fix had already remediated -
#  so it looked intermittent. In acas the throw was swallowed into a verdict
#  (JANET_PROBE_ERR -> "UNCONFIRMED: verify probe errored" + a Failure audit), so a
#  successful fix could never book a success. Both now read the FixedTimestamp
#  VALUE the fix itself writes into the backup key - which was there all along.
#
#  Run: Invoke-Pester -Path .\tests\Platform.NoRegistryMtime.Tests.ps1
# =============================================================================
$script:Root       = Split-Path $PSScriptRoot -Parent
$script:ModulesDir = Join-Path $script:Root 'modules'

# Registry indicators: an explicit hive prefix, or one of the registry-root
# variables this suite uses (the $backupRoot case is what defeated the eyeball
# sweeps - the line itself names no hive).
$script:RegHints = 'HKLM:|HKCU:|HKCR:|HKEY|Registry::|\$backupRoot|\$svcRoot'

# VERIFIED-CORRECT exceptions. Each must state WHY it is safe, because the whole
# point of this file is that "looks fine" is how the family survives.
$script:Allowed = @(
    @{ File = 'JanetWeb.wpt.psm1'; Match = '\$pfi\.LastWriteTime'
       Why  = 'health-scan pending-reboot age: reads the mtime of the real FILES CBS stages (C:\Windows\WinSxS\pending.xml / reboot.xml), not a key. The registry Get-Item calls a few lines above are existence-only ($null = ...). This IS the loop88 fix; the code comment says so.' }
)

function Get-RegistryMtimeHits {
    $hits = New-Object System.Collections.ArrayList
    foreach ($f in (Get-ChildItem -LiteralPath $script:ModulesDir -Filter '*.psm1')) {
        $lines = Get-Content -LiteralPath $f.FullName
        for ($i = 0; $i -lt $lines.Count; $i++) {
            $line = $lines[$i]
            if ($line -notmatch 'LastWriteTime') { continue }
            if ($line -match '^\s*#') { continue }              # a comment describing the defect is not the defect
            # Look back a few lines: the registry path is often on the assignment above.
            $from = [Math]::Max(0, $i - 3)
            $ctx  = ($lines[$from..$i] -join ' ')
            if ($ctx -notmatch $script:RegHints) { continue }
            $allowed = $false
            foreach ($a in $script:Allowed) {
                if ($f.Name -eq $a.File -and $line -match $a.Match) { $allowed = $true; break }
            }
            if (-not $allowed) { [void]$hits.Add("$($f.Name):$($i+1)  $($line.Trim())") }
        }
    }
    return @($hits)
}

Describe 'no module reads a timestamp off a registry key' {

    It 'the sweep finds ZERO unallowed registry .LastWriteTime reads' {
        $hits = Get-RegistryMtimeHits
        # Joined so a failure names the offending file:line rather than just a count.
        ($hits -join "`n") | Should BeNullOrEmpty
    }

    # Proves the sweep can actually fail. Without this, an over-tightened regex would
    # make the assertion above pass vacuously forever - which is precisely how the
    # site-scoped tests let this family survive five separate "fixes".
    It 'the sweep detects the shape it is looking for (self-check)' {
        $sample = @(
            '                $backupRoot = ''HKLM:\SOFTWARE\JANET\Nemesis\UnquotedSvcPath''',
            '                $newest = Get-ChildItem -LiteralPath $backupRoot -EA SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1',
            '                if ($newest) { $lastFix = $newest.LastWriteTime.ToString(''yyyy-MM-dd HH:mm'') }'
        )
        $found = $false
        for ($i = 0; $i -lt $sample.Count; $i++) {
            if ($sample[$i] -notmatch 'LastWriteTime') { continue }
            if ($sample[$i] -match '^\s*#') { continue }
            $ctx = ($sample[[Math]::Max(0, $i - 3)..$i] -join ' ')
            if ($ctx -match $script:RegHints) { $found = $true }
        }
        $found | Should Be $true
    }
}

Describe 'manifest EXACT pins for this bump (acas 1.11.26, wpt 6.10.10)' {
    # Both modules carried the same defect and both were bumped in one pass, so the exact
    # pins live here together. Log4jJarVersion.Tests.ps1's acas pin was demoted to a floor:
    # it guards the JAR SWEEP, not acas's version, and an exact pin there would fail on
    # every future unrelated acas bump.
    It 'acas is exactly 1.11.26' {
        $m = Import-Module (Join-Path $script:ModulesDir 'JanetWeb.acas.psm1') -Force -PassThru
        [string](& $m { (Get-JanetToolManifest).version }) | Should Be '1.11.26'
    }
    It 'wpt is exactly 6.10.10' {
        $m = Import-Module (Join-Path $script:ModulesDir 'JanetWeb.wpt.psm1') -Force -PassThru
        [string](& $m { (Get-JanetToolManifest).version }) | Should Be '6.10.10'
    }
}

Describe 'the Unquoted Service Path verify reads the timestamp the fix actually writes' {

    # Both modules carry a copy of this profile. They are checked TOGETHER on purpose:
    # the 2026-08-04 instance existed in both, and fixing one would have left the other.
    foreach ($mod in @('JanetWeb.acas.psm1', 'JanetWeb.wpt.psm1')) {
        It "$mod reads FixedTimestamp from the backup key, not a key mtime" {
            $src = Get-Content (Join-Path $script:ModulesDir $mod) -Raw
            ($src -match "Get-ItemProperty -LiteralPath \`$bk\.PSPath -Name 'FixedTimestamp'") | Should Be $true
            ($src -match "\`$newest\.LastWriteTime\.ToString")                                 | Should Be $false
        }
        It "$mod still WRITES FixedTimestamp, so the verify has something to read" {
            $src = Get-Content (Join-Path $script:ModulesDir $mod) -Raw
            ($src -match "-Name 'FixedTimestamp'\s+-Value \(Get-Date -Format 's'\)") | Should Be $true
        }
    }
}
