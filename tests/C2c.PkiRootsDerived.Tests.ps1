# =============================================================================
#  C2c.PkiRootsDerived.Tests.ps1 - Pester 3.4 for the v1.17.0 fix to the INERT
#  PkiRoots scan check.
#
#  Before: Get-C2cBaselineDefaults seeded dodRootThumbprints = @(), so on a stock
#  install the PkiRoots check emitted EXT "configure DoD root thumbprints in
#  c2c-baseline.json" instead of a verdict - while certdeploy already computed the
#  ACCURATE missing-anchor set from the SHIPPED bundle in Packages\DoD-Certs.
#
#  After: when (and ONLY when) the baseline array is EMPTY, the scan derives the
#  expected LocalMachine\Root anchor set from that same shipped bundle. An
#  explicitly-configured baseline still wins, and a bundle that cannot be read
#  keeps the old EXT behaviour - never a false PASS.
#
#  The derivation is asserted against an INDEPENDENT re-read of the shipped .cer
#  files (X509Certificate2 in the test), not against the module's own output, so a
#  regression in Get-C2cCertBundle cannot make this test agree with itself.
#
#  Run:  Invoke-Pester -Path .\tests\C2c.PkiRootsDerived.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent

# Shim hygiene: 'Remove-Item function:script:<name>' is INERT (the function provider
# has no scope qualifier) and the naive unqualified form DESTROYS the module's real
# function. Snapshot, then restore exactly what was there.
function Add-ShimGuard {
    param($Mod)
    & $Mod {
        function script:Save-ShimState {
            param([string[]]$Names)
            $h = @{}
            foreach ($n in $Names) {
                $i = Get-Item -LiteralPath "function:$n" -ErrorAction SilentlyContinue
                if ($i) { $h[$n] = $i.ScriptBlock } else { $h[$n] = $null }
            }
            return $h
        }
        function script:Restore-ShimState {
            param($State)
            foreach ($k in @($State.Keys)) {
                if ($State[$k]) { Set-Item -LiteralPath "function:script:$k" -Value $State[$k] }
                else { Remove-Item -LiteralPath "function:$k" -ErrorAction SilentlyContinue }
            }
        }
    }
}
$cm = Import-Module (Join-Path $script:Root 'modules\JanetWeb.c2c.psm1') -Force -PassThru
Add-ShimGuard $cm

$script:BundleDir = Join-Path $script:Root 'Packages\DoD-Certs'

Describe 'C2C PkiRoots - the anchor set derived from the SHIPPED DoD trust bundle' {

    $derived = & $cm { Get-C2cBundleRootThumbprints '' }

    It 'derives a usable set from the shipped Packages\DoD-Certs with nothing configured' {
        [bool]$derived.Ok | Should Be $true
        (@($derived.Thumbprints).Count -gt 0) | Should Be $true
    }
    It 'names its provenance so the row detail can say where the verdict came from' {
        [string]$derived.Source | Should Match '(?i)derived from the .*DoD trust bundle'
        [string]$derived.Error  | Should BeNullOrEmpty
    }
    It 'every derived value is a normalized 40-hex UPPERCASE thumbprint' {
        foreach ($t in @($derived.Thumbprints)) { [string]$t | Should Match '^[0-9A-F]{40}$' }
    }
    It 'the set is de-duplicated' {
        $all = @($derived.Thumbprints)
        @($all | Select-Object -Unique).Count | Should Be $all.Count
    }
    It 'matches an INDEPENDENT read of root\*.cer + loose *.cer (the LocalMachine\Root group)' {
        $expect = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        $files = @()
        $rootSub = Join-Path $script:BundleDir 'root'
        if (Test-Path -LiteralPath $rootSub) { $files += @(Get-ChildItem -LiteralPath $rootSub -Filter '*.cer' -File -ErrorAction SilentlyContinue) }
        $files += @(Get-ChildItem -LiteralPath $script:BundleDir -Filter '*.cer' -File -ErrorAction SilentlyContinue)
        foreach ($f in $files) {
            $c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            try { $c.Import($f.FullName) } catch { continue }
            # Expired anchors are dropped by the bundle reader (a dead trust anchor is never
            # pushed, so it must never be required either) - mirror that here.
            if ($c.NotAfter -lt (Get-Date)) { continue }
            [void]$expect.Add((([string]$c.Thumbprint) -replace '[^0-9A-Fa-f]', '').ToUpperInvariant())
        }
        $got = @($derived.Thumbprints)
        $got.Count | Should Be $expect.Count
        foreach ($t in $got) { $expect.Contains([string]$t) | Should Be $true }
    }
    It 'does NOT require the Intermediate\ (CA store) certs - they are not in LocalMachine\Root' {
        $bundle = & $cm { Get-C2cCertBundle -Folder (Get-C2cDefaultCertBundlePath) }
        [bool]$bundle.Ok | Should Be $true
        @($bundle.CA).Count -gt 0 | Should Be $true
        $got = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($t in @($derived.Thumbprints)) { [void]$got.Add([string]$t) }
        foreach ($c in @($bundle.CA)) {
            $tp = (([string]$c.Thumbprint) -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
            $got.Contains($tp) | Should Be $false
        }
    }
    It 'does NOT require the Untrusted\ (Disallowed) certs - requiring a blacklist in Root would be backwards' {
        $bundle = & $cm { Get-C2cCertBundle -Folder (Get-C2cDefaultCertBundlePath) }
        $got = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($t in @($derived.Thumbprints)) { [void]$got.Add([string]$t) }
        foreach ($c in @($bundle.Disallowed)) {
            $tp = (([string]$c.Thumbprint) -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
            $got.Contains($tp) | Should Be $false
        }
    }
}

Describe 'C2C PkiRoots - a bundle that cannot be read NEVER becomes a PASS' {

    It 'an operator-supplied folder that does not exist is Ok=$false with an empty set' {
        $r = & $cm { Get-C2cBundleRootThumbprints 'Z:\no\such\bundle\folder' }
        [bool]$r.Ok | Should Be $false
        @($r.Thumbprints).Count | Should Be 0
        [string]$r.Error | Should Not BeNullOrEmpty
    }
    It 'an operator-supplied EMPTY folder is Ok=$false - it does NOT silently fall back to the shipped bundle' {
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('c2cpki_' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $tmp -Force | Out-Null
        try {
            $r = & $cm { param($p) Get-C2cBundleRootThumbprints $p } $tmp
            [bool]$r.Ok | Should Be $false
            @($r.Thumbprints).Count | Should Be 0
            [string]$r.Error | Should Match '(?i)no \.cer certificates found|unusable|unreadable'
        } finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'C2C PkiRoots - the scan wires the fallback in, and an explicit baseline still wins' {

    # The derivation happens BEFORE the target parse, so an empty target list exercises
    # the whole config path with zero WinRM and zero runspaces.
    function Invoke-ScanConfigPath {
        param([string[]]$BaselineThumbs, [bool]$DeriveOk = $true)
        $evts = New-Object System.Collections.ArrayList
        $emit = { param($e) [void]$evts.Add($e) }.GetNewClosure()
        $calls = & $cm {
            param($thumbs, $deriveOk, $em)
            $__shims = Save-ShimState @('Get-C2cBaseline', 'Get-C2cBundleRootThumbprints')
            try {
                $script:__derivedCalls = 0
                $script:__thumbs = @($thumbs)
                $script:__deriveOk = [bool]$deriveOk
                function script:Get-C2cBaseline {
                    return @{
                        Config = @{
                            sigMaxAgeDays = 7; sigMaxAgeHours = 24; graceDays = 7
                            taniumService = 'Tanium Client'; securityAgentServices = @('WinDefend')
                            dodRootThumbprints = @($script:__thumbs)
                        }
                        Source = 'test baseline'
                    }
                }
                function script:Get-C2cBundleRootThumbprints {
                    param([string]$Folder = '')
                    $script:__derivedCalls++
                    if ($script:__deriveOk) {
                        return @{ Ok = $true; Thumbprints = @('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'); Source = 'derived from the shipped default DoD trust bundle (TEST): 1 Root anchor(s)'; Error = '' }
                    }
                    return @{ Ok = $false; Thumbprints = @(); Source = ''; Error = 'trust bundle unreadable at TEST' }
                }
                $null = Invoke-JanetToolAction -ActionId 'scan' -Params @{ targets = '' } -Emit $em
                return $script:__derivedCalls
            } finally {
                Restore-ShimState $__shims
                Remove-Variable -Name __derivedCalls, __thumbs, __deriveOk -Scope Script -ErrorAction SilentlyContinue
            }
        } $BaselineThumbs $DeriveOk $emit
        return @{ Calls = [int]$calls; Events = @($evts) }
    }

    It 'with an EMPTY baseline the shipped-bundle derivation runs and is announced' {
        $r = Invoke-ScanConfigPath -BaselineThumbs @()
        $r.Calls | Should Be 1
        $txt = (@($r.Events | Where-Object { $_.type -eq 'log' } | ForEach-Object { [string]$_.text }) -join "`n")
        $txt | Should Match '(?i)PkiRoots: baseline dodRootThumbprints is empty'
        $txt | Should Match '(?i)derived from the shipped default DoD trust bundle'
    }
    It 'an EXPLICITLY-CONFIGURED baseline WINS - the derivation is never even consulted' {
        $r = Invoke-ScanConfigPath -BaselineThumbs @('BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB')
        $r.Calls | Should Be 0
        $txt = (@($r.Events | Where-Object { $_.type -eq 'log' } | ForEach-Object { [string]$_.text }) -join "`n")
        $txt | Should Not Match '(?i)derived from the'
    }
    It 'an EMPTY baseline whose derivation FAILS warns and keeps the check unscored (never a false PASS)' {
        $r = Invoke-ScanConfigPath -BaselineThumbs @() -DeriveOk $false
        $r.Calls | Should Be 1
        $warn = @($r.Events | Where-Object { $_.type -eq 'log' -and $_.level -eq 'warn' } | ForEach-Object { [string]$_.text }) -join "`n"
        $warn | Should Match '(?i)no anchor set could be derived'
        $warn | Should Match '(?i)EXT \(unscored\), never a false PASS'
    }
    It 'the shims were fully restored (Save/Restore, not the inert function:script: delete)' {
        $real = & $cm { Get-C2cBundleRootThumbprints '' }
        [bool]$real.Ok | Should Be $true
        (@($real.Thumbprints).Count -gt 1) | Should Be $true
        $b = & $cm { Get-C2cBaseline }
        [string]$b.Source | Should Not Be 'test baseline'
    }
}

Describe 'C2C PkiRoots - the required-set provenance reaches the remote check' {

    # Assert on CALL SITES, never on comments.
    function Remove-PsComments {
        param([string]$Src)
        $out = New-Object System.Collections.ArrayList
        foreach ($ln in ([string]$Src -split "`r?`n")) {
            if ($ln.TrimStart().StartsWith('#')) { continue }
            $i = $ln.IndexOf(' #')
            if ($i -ge 0) { [void]$out.Add($ln.Substring(0, $i)) } else { [void]$out.Add($ln) }
        }
        return ($out -join "`n")
    }
    $code = Remove-PsComments (& $cm { $script:C2cProbeBlock.ToString() })

    It 'the per-host worker reads the provenance out of the config hashtable' {
        $code | Should Match ([regex]::Escape("`$dodRootSrc    = [string]`$Config['dodRootSource']"))
    }
    It 'the remote probe scriptblock declares $dodRootSrc as its last parameter' {
        $code | Should Match ([regex]::Escape('$dodRoots, $taniumInstalledSrc, $dodRootSrc)'))
    }
    It 'the provenance is actually passed in the Invoke-Command ArgumentList' {
        $code | Should Match ([regex]::Escape('$TaniumInstalledSrc, $dodRootSrc) -ErrorAction Stop'))
    }
    It 'the PASS and FAIL details both carry the source tag' {
        $code | Should Match ([regex]::Escape("required DoD root(s) present in LocalMachine\Root`$srcTxt"))
        $code | Should Match ([regex]::Escape("missing from LocalMachine\Root: `$(`$shorts -join ', ')`$srcTxt"))
    }
    It 'the EXT branch fires ONLY on an empty required set, and no longer tells the operator to edit JSON' {
        $code | Should Match ([regex]::Escape('if ($req.Count -eq 0) {'))
        $code | Should Not Match ([regex]::Escape('configure DoD root thumbprints in c2c-baseline.json'))
        $code | Should Match '(?i)no anchors could be derived from the shipped DoD trust bundle'
    }
    It 'the scan summary reports which anchor source was used' {
        $disp = Remove-PsComments (& $cm { (Get-Item -LiteralPath 'function:Invoke-JanetToolAction').ScriptBlock.ToString() })
        $disp | Should Match ([regex]::Escape('pkiRootSource=$dodRootSrc'))
    }
    It 'the scan action description tells the operator no JSON edit is needed' {
        $scan = @((& $cm { Get-JanetToolManifest }).actions | Where-Object { $_.id -eq 'scan' })[0]
        [string]$scan.description | Should Match '(?i)DERIVED from the SHIPPED DoD trust bundle'
        [string]$scan.description | Should Match '(?i)no JSON to edit'
        [string]$scan.description | Should Match '(?i)stays EXT \(unscored\) rather than reporting a false PASS'
    }
}
