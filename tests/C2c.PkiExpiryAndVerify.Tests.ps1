# =============================================================================
#  C2c.PkiExpiryAndVerify.Tests.ps1 - Pester 3.4 tests for the C2C v1.7.1
#  PkiRoots hardening (expiry guard + persistence re-verify), PkiRoots path ONLY:
#
#    (1) EXPIRY GUARD (admin-side, at bundle read) - Get-C2cCertBundle EXCLUDES
#        expired .cer (NotAfter < now) from Root/CA/Disallowed so they are never
#        serialized/pushed, and reports them via ExpiredCount + Expired[]. A bundle
#        of ONLY expired certs is Ok=$false with a clear "all ... EXPIRED" reason.
#    (2) PERSISTENCE RE-VERIFY (remote) - Add-C2cBundleToStores, after the additive
#        adds, RE-OPENS each store ReadOnly ($VerifyOpener) and confirms each ADDED
#        thumbprint persisted; its return gains Verified + NotVerified.
#        Get-C2cPkiRootsResultToken maps NotVerified.Count>0 -> 'NOT VERIFIED', and the
#        real fix worker surfaces that as host Status 'NOT VERIFIED'.
#
#  Driven with the suite's idioms (matching C2c.CertsAndVersion.Tests.ps1): the
#  module-scope invoker (& $cm { ... }), real self-signed test certs, injected fake
#  store/verify openers, and (for the worker end-to-end case) New-PSSession /
#  Remove-PSSession / Invoke-Command shimmed IN MODULE SCOPE. No WinRM call and no
#  real cert-store write ever leaves this box.
#
#  NOTE: the module ships Pester 3.4 tests (Should Be), so these match that style
#  rather than Pester v5 - the dir has no v5 tests.
#
#  Run:  Invoke-Pester -Path .\tests\C2c.PkiExpiryAndVerify.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$cm = Import-Module (Join-Path $script:Root 'modules\JanetWeb.c2c.psm1') -Force -PassThru

# --- helpers ---------------------------------------------------------------
# Make a throwaway self-signed cert with a chosen validity; return @{ B64; Thumbprint; Raw }.
# NotBefore defaults just behind now; for an EXPIRED cert pass BOTH NotBefore and
# NotAfter in the past (NotBefore < NotAfter) - New-SelfSignedCertificate rejects a
# NotAfter that precedes NotBefore, so a bare negative NotAfter is not allowed.
function New-TestCertEx {
    param([string]$Subject = 'CN=C2C-ExpTest', [datetime]$NotAfter = (Get-Date).AddDays(1), [datetime]$NotBefore = (Get-Date).AddDays(-1))
    $c = New-SelfSignedCertificate -Subject $Subject -CertStoreLocation 'Cert:\CurrentUser\My' -KeyExportPolicy Exportable -KeyLength 2048 -NotBefore $NotBefore -NotAfter $NotAfter
    $raw = $c.RawData
    $tp  = [string]$c.Thumbprint
    Remove-Item ("Cert:\CurrentUser\My\{0}" -f $tp) -Force -ErrorAction SilentlyContinue
    return @{ B64 = [Convert]::ToBase64String($raw); Thumbprint = $tp; Raw = $raw }
}

function New-BundleFolder {
    $root = Join-Path ([System.IO.Path]::GetTempPath()) ("c2c_expiry_{0}" -f ([guid]::NewGuid().ToString('N')))
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    return $root
}

# -----------------------------------------------------------------------------
Describe 'C2C fix-pki - expiry guard at bundle read (Get-C2cCertBundle)' {

    It '(a) reports ExpiredCount=1, lists the expired thumbprint in Expired[], and keeps only the valid cert usable' {
        $f = New-BundleFolder
        try {
            New-Item -ItemType Directory -Path (Join-Path $f 'root') -Force | Out-Null
            $good = New-TestCertEx 'CN=GoodRoot' (Get-Date).AddDays(365)
            $dead = New-TestCertEx 'CN=DeadRoot' (Get-Date).AddDays(-30) (Get-Date).AddDays(-60)
            [System.IO.File]::WriteAllBytes((Join-Path $f 'root\good.cer'), $good.Raw)
            [System.IO.File]::WriteAllBytes((Join-Path $f 'root\dead.cer'), $dead.Raw)

            $b = & $cm { param($p) Get-C2cCertBundle -Folder $p } $f
            $b.Ok           | Should Be $true
            $b.ExpiredCount | Should Be 1
            $b.CertCount    | Should Be 1                            # only the valid cert is usable
            @($b.Root).Count | Should Be 1
            # the expired thumbprint is in Expired[] (with Subject / NotAfter / Store)...
            (@($b.Expired) | ForEach-Object { $_.Thumbprint }) -contains $dead.Thumbprint | Should Be $true
            $exp = @($b.Expired | Where-Object { $_.Thumbprint -eq $dead.Thumbprint })[0]
            $exp.Subject | Should Match 'DeadRoot'
            $exp.Store   | Should Be 'Root'
            ([datetime]$exp.NotAfter) -lt (Get-Date) | Should Be $true
            # ...and it is NOT among the usable Root certs.
            (@($b.Root) | ForEach-Object { $_.Thumbprint }) -contains $dead.Thumbprint | Should Be $false
            (@($b.Root) | ForEach-Object { $_.Thumbprint }) -contains $good.Thumbprint | Should Be $true
        } finally { Remove-Item -LiteralPath $f -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It '(a2) Convert-C2cBundleToJson output contains the VALID thumbprint but NOT the expired one (never pushed)' {
        $f = New-BundleFolder
        try {
            New-Item -ItemType Directory -Path (Join-Path $f 'root') -Force | Out-Null
            $good = New-TestCertEx 'CN=GoodRoot2' (Get-Date).AddDays(365)
            $dead = New-TestCertEx 'CN=DeadRoot2' (Get-Date).AddDays(-30) (Get-Date).AddDays(-60)
            [System.IO.File]::WriteAllBytes((Join-Path $f 'root\good.cer'), $good.Raw)
            [System.IO.File]::WriteAllBytes((Join-Path $f 'root\dead.cer'), $dead.Raw)

            $json = & $cm { param($p) Convert-C2cBundleToJson (Get-C2cCertBundle -Folder $p) } $f
            $json | Should Match ([regex]::Escape($good.Thumbprint))
            $json | Should Not Match ([regex]::Escape($dead.Thumbprint))
        } finally { Remove-Item -LiteralPath $f -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It '(a3) a bundle of ONLY expired certs is Ok=$false with a clear "all ... EXPIRED" reason (fix-pki would abort, dial nothing)' {
        $f = New-BundleFolder
        try {
            New-Item -ItemType Directory -Path (Join-Path $f 'root') -Force | Out-Null
            $dead = New-TestCertEx 'CN=DeadOnly' (Get-Date).AddDays(-5) (Get-Date).AddDays(-60)
            [System.IO.File]::WriteAllBytes((Join-Path $f 'root\dead.cer'), $dead.Raw)

            $b = & $cm { param($p) Get-C2cCertBundle -Folder $p } $f
            $b.Ok           | Should Be $false
            $b.ExpiredCount | Should Be 1
            $b.CertCount    | Should Be 0
            $b.Error        | Should Match '(?i)expired'
        } finally { Remove-Item -LiteralPath $f -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

# -----------------------------------------------------------------------------
Describe 'C2C fix-pki - persistence re-verify in Add-C2cBundleToStores' {

    # A stateful fake store: StoreOpener writes into a shared backing list; VerifyOpener
    # reads that SAME backing when $Persist, or an EMPTY list when stripping. This runs
    # the REAL Add-C2cBundleToStores logic (dot-sourced in module scope) with no real
    # cert-store write.
    function Invoke-AddWithVerify {
        param([string]$Tp, [string]$B64, [bool]$Persist)
        & $cm {
            param($Tp, $B64, $Persist)
            $backing = New-Object System.Collections.ArrayList
            $opener = {
                param($storeName)
                $o = New-Object psobject
                Add-Member -InputObject $o -MemberType NoteProperty -Name Certificates -Value $backing
                Add-Member -InputObject $o -MemberType ScriptMethod -Name Add   -Value { param($c) [void]$backing.Add([pscustomobject]@{ Thumbprint = [string]$c.Thumbprint }) }
                Add-Member -InputObject $o -MemberType ScriptMethod -Name Close -Value { }
                return $o
            }.GetNewClosure()
            $verifier = {
                param($storeName)
                $o = New-Object psobject
                $seen = if ($Persist) { $backing } else { (New-Object System.Collections.ArrayList) }
                Add-Member -InputObject $o -MemberType NoteProperty -Name Certificates -Value $seen
                Add-Member -InputObject $o -MemberType ScriptMethod -Name Close -Value { }
                return $o
            }.GetNewClosure()
            $bundle = [pscustomobject]@{ Root = @([pscustomobject]@{ t = $Tp; b = $B64 }); CA = @(); Disallowed = @() }
            $res = Add-C2cBundleToStores -Bundle $bundle -StoreOpener $opener -VerifyOpener $verifier
            [pscustomobject]@{ Added = $res.Added; Verified = $res.Verified; NotVerified = @($res.NotVerified); NVCount = @($res.NotVerified).Count; Fail = [string]$res.FailDetail }
        } $Tp $B64 $Persist
    }

    It '(b) an add that PERSISTS on re-read -> Verified=1, NotVerified empty' {
        $c = New-TestCertEx 'CN=Persisted' (Get-Date).AddDays(1)
        $r = Invoke-AddWithVerify -Tp $c.Thumbprint -B64 $c.B64 -Persist $true
        $r.Added    | Should Be 1
        $r.Verified | Should Be 1
        $r.NVCount  | Should Be 0
        $r.Fail     | Should Be ''
    }

    It '(b2) an add STRIPPED before re-read -> Verified=0, NotVerified holds the added thumbprint (FailDetail left clean)' {
        $c = New-TestCertEx 'CN=Stripped' (Get-Date).AddDays(1)
        $r = Invoke-AddWithVerify -Tp $c.Thumbprint -B64 $c.B64 -Persist $false
        $r.Added    | Should Be 1
        $r.Verified | Should Be 0
        $r.NVCount  | Should Be 1
        (@($r.NotVerified) -contains $c.Thumbprint) | Should Be $true
        $r.Fail     | Should Be ''       # a stripped-in-session add is NOT a hard .Add failure
    }

    It '(b3) legacy caller (custom StoreOpener, NO VerifyOpener) does NOT touch the real store and trusts the add (Verified=Added)' {
        $c = New-TestCertEx 'CN=LegacyTrust' (Get-Date).AddDays(1)
        $r = & $cm {
            param($tp, $b64)
            $opener = {
                param($storeName)
                $o = New-Object psobject
                Add-Member -InputObject $o -MemberType NoteProperty -Name Certificates -Value @()
                Add-Member -InputObject $o -MemberType ScriptMethod -Name Add   -Value { param($c) }
                Add-Member -InputObject $o -MemberType ScriptMethod -Name Close -Value { }
                return $o
            }
            $bundle = [pscustomobject]@{ Root = @([pscustomobject]@{ t = $tp; b = $b64 }); CA = @(); Disallowed = @() }
            $res = Add-C2cBundleToStores -Bundle $bundle -StoreOpener $opener
            [pscustomobject]@{ Added = $res.Added; Verified = $res.Verified; NVCount = @($res.NotVerified).Count }
        } $c.Thumbprint $c.B64
        $r.Added    | Should Be 1
        $r.Verified | Should Be 1     # trusted (no VerifyOpener injected, custom StoreOpener)
        $r.NVCount  | Should Be 0
    }
}

# -----------------------------------------------------------------------------
Describe 'C2C fix-pki - Get-C2cPkiRootsResultToken NOT VERIFIED classification' {

    It '(c) NotVerified.Count>0 -> NOT VERIFIED token' {
        $tok = & $cm { Get-C2cPkiRootsResultToken @{ Added = 1; Total = 1; FailDetail = ''; NotVerified = @('AABBCCDD') } }
        $tok | Should Be 'NOT VERIFIED'
    }

    It '(c2) empty NotVerified + Added>0 -> FIXED (unchanged); FailDetail wins over NotVerified -> FAIL' {
        (& $cm { Get-C2cPkiRootsResultToken @{ Added = 2; Total = 2; FailDetail = ''; NotVerified = @() } })                 | Should Be 'FIXED'
        (& $cm { Get-C2cPkiRootsResultToken @{ Added = 0; Total = 1; FailDetail = 'add failed'; NotVerified = @('X') } })    | Should Be 'FAIL'
        (& $cm { Get-C2cPkiRootsResultToken @{ Added = 0; Total = 1; FailDetail = ''; NotVerified = @() } })                 | Should Be 'NOCHANGE'
    }
}

# -----------------------------------------------------------------------------
# Drive the REAL per-host fix worker ($script:C2cFixBlock) LOCALLY for a PkiRoots
# pillar whose adds are STRIPPED before re-read, proving the host verdict rolls up to
# 'NOT VERIFIED'. New-PSSession / Remove-PSSession / Invoke-Command shimmed IN MODULE
# SCOPE; Add-C2cBundleToStores wrapped so its openers are a fake that writes to a
# backing but whose VerifyOpener returns EMPTY (stripping). The real classify/rollup
# logic still runs - nothing touches the LocalMachine stores.
Describe 'C2C fix-pki - REAL worker end-to-end (stripped add -> host NOT VERIFIED)' {

    It '(d) a bundle that installs but is stripped on re-read -> pillar NOT VERIFIED -> host Status NOT VERIFIED, detail names the reconciler risk' {
        $c = New-TestCertEx 'CN=WkStripped' (Get-Date).AddDays(1)
        $r = & $cm {
            param($Tp, $B64)
            function script:New-PSSession { param($ComputerName, $SessionOption, $Authentication, $ErrorAction, $Credential) [pscustomobject]@{ Id = 1; Name = 'shim' } }
            function script:Remove-PSSession { param($Session, $ErrorAction) }
            function script:Invoke-Command {
                param($Session, $ComputerName, $ScriptBlock, $ArgumentList, $ErrorAction, $Credential, $Authentication, $SessionOption)
                if ($ScriptBlock -and ($ScriptBlock.ToString().Trim() -eq '$env:COMPUTERNAME')) { return $env:COMPUTERNAME }
                return (& $ScriptBlock @ArgumentList)
            }
            $bundleJson = Convert-C2cBundleToJson ([pscustomobject]@{ Root = @([pscustomobject]@{ Thumbprint = $Tp; B64 = $B64 }); CA = @(); Disallowed = @() })
            $script:__backing = New-Object System.Collections.ArrayList
            $script:__fakeStore = {
                param($storeName)
                $o = New-Object psobject
                Add-Member -InputObject $o -MemberType NoteProperty -Name Certificates -Value $script:__backing
                Add-Member -InputObject $o -MemberType ScriptMethod -Name Add   -Value { param($c) [void]$script:__backing.Add([pscustomobject]@{ Thumbprint = [string]$c.Thumbprint }) }
                Add-Member -InputObject $o -MemberType ScriptMethod -Name Close -Value { }
                return $o
            }
            $script:__fakeVerify = {
                param($storeName)
                $o = New-Object psobject
                Add-Member -InputObject $o -MemberType NoteProperty -Name Certificates -Value (New-Object System.Collections.ArrayList)   # stripped: empty on re-read
                Add-Member -InputObject $o -MemberType ScriptMethod -Name Close -Value { }
                return $o
            }
            # Wrap the real cert/label source so Add-C2cBundleToStores uses the fake openers.
            $wrap = "`n" + '$script:__c2cRealAdd = ${function:Add-C2cBundleToStores}' + "`n" +
                    '${function:Add-C2cBundleToStores} = { param($Bundle,[scriptblock]$StoreOpener,[scriptblock]$VerifyOpener) & $script:__c2cRealAdd -Bundle $Bundle -StoreOpener $script:__fakeStore -VerifyOpener $script:__fakeVerify }'
            $fakeAddSrc = $script:C2cAddCertsSrc + $wrap
            try {
                $res = & $script:C2cFixBlock $env:COMPUTERNAME $null 'Default' $true @('PkiRoots') $false 'Tanium Client' $script:C2cTaniumInstalledSrc $bundleJson $false $script:C2cWinrmHealSrc $fakeAddSrc
                $pki = @(@($res.Pillars) | Where-Object { $_.Name -eq 'PkiRoots' })[0]
                [pscustomobject]@{ Status = [string]$res.Status; PkiResult = $(if ($pki) { [string]$pki.Result } else { '' }); Detail = [string]$res.Detail; PkiDetail = $(if ($pki) { [string]$pki.Detail } else { '' }) }
            } finally {
                Remove-Item function:script:New-PSSession, function:script:Remove-PSSession, function:script:Invoke-Command -ErrorAction SilentlyContinue
            }
        } $c.Thumbprint $c.B64
        $r.PkiResult | Should Be 'NOT VERIFIED'
        $r.Status    | Should Be 'NOT VERIFIED'
        $r.PkiDetail | Should Match 'absent on re-read'
        $r.PkiDetail | Should Match 'reconciler'
    }
}
