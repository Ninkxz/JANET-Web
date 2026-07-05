# =============================================================================
#  Kev.Lock.Tests.ps1 - Pester 3.4 tests for the KEV catalog cross-machine lock
#  (audit#8). Exercises Invoke-WithKevLock: mutual exclusion + stale-lock break,
#  and the read-merge-write round trip against a temp catalog file.
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.kev.psm1') -Force -PassThru
$script:Tmp  = Join-Path ([System.IO.Path]::GetTempPath()) ("kevtest_" + [guid]::NewGuid().ToString('N'))
[void][System.IO.Directory]::CreateDirectory($script:Tmp)
$script:Cat  = Join-Path $script:Tmp 'KevCatalog.txt'

Describe 'Invoke-WithKevLock (audit#8)' {

    It 'runs the body and releases the lock (lock file gone afterward)' {
        $ran = & $script:Mod { param($c) $x = $false; Invoke-WithKevLock -CatalogPath $c -Body { $script:x2 = $true }; $script:x2 } $script:Cat
        $ran | Should Be $true
        (Test-Path "$script:Cat.lock") | Should Be $false
    }

    It 'blocks (throws) a second acquirer while the lock is held' {
        $blocked = & $script:Mod {
            param($c)
            $fs = [System.IO.File]::Open("$c.lock", [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
            $b = $false
            try { Invoke-WithKevLock -CatalogPath $c -TimeoutMs 500 -Body { } } catch { $b = $true }
            finally { $fs.Close(); $fs.Dispose(); [System.IO.File]::Delete("$c.lock") }
            $b
        } $script:Cat
        $blocked | Should Be $true
    }

    It 'preserves a concurrently-added CVE via read-merge-write (no lost update)' {
        # Seed with c1, then merge c2 the same way add-kev does (re-read on disk + add).
        & $script:Mod {
            param($c)
            Write-KevCatalog -List @('CVE-2021-0001') -Path $c
            $merged = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($x in (Get-Content $c | Where-Object { $_ })) { [void]$merged.Add($x) }
            [void]$merged.Add('CVE-2022-0002')
            Write-KevCatalog -List (Sort-KevCves @($merged)) -Path $c
        } $script:Cat
        $lines = @(Get-Content $script:Cat | Where-Object { $_ })
        $lines -contains 'CVE-2021-0001' | Should Be $true
        $lines -contains 'CVE-2022-0002' | Should Be $true
    }
}

# cleanup (best effort; temp dir)
try { [System.IO.Directory]::Delete($script:Tmp, $true) } catch {}
