# =============================================================================
#  C2c.CertsAndVersion.Tests.ps1 - Pester 3.4 tests for the v1.6.0 additions:
#    * fix-pki  - DoD trust-bundle enumeration (Get-C2cCertBundle) + the ADDITIVE
#                 cert-store installer (Add-C2cBundleToStores) with an injected
#                 fake store so nothing touches the real LocalMachine stores.
#    * version-check - the read-only version matrix (System.Version + ordinal
#                 fallback) via the C2cVersionBlock worker run LOCALLY with the
#                 suite shim idiom, plus Get-C2cInstalledProduct across BOTH hives.
#    * winrm-heal - Invoke-JanetC2cWinrmHeal bucketing (mock Get-Service /
#                 Set-Service / Start-Service + an injected 5985 probe).
#
#  No WinRM call and no real cert-store write ever leaves this box.
#
#  Run:  Invoke-Pester -Path .\tests\C2c.CertsAndVersion.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
# -----------------------------------------------------------------------------
# Shim hygiene (audit 2026-07-25). Every shim teardown in this file used to be spelled
# 'Remove-Item function:script:<name>'. That spelling is INERT: the function provider has no
# scope qualifier in its paths, so 'function:script:X' names an item that does not exist and
# the -ErrorAction SilentlyContinue swallowed the failure - the shim SURVIVED into every later
# Describe/It in the file, where a test could then pass on a leaked stub. The naive correction
# ('Remove-Item function:X') is worse when the shim shadows a MODULE function: it deletes the
# real one. So snapshot first, then put back exactly what was there - the captured ScriptBlock
# for a module function, or nothing at all for a shimmed CMDLET (which had no function entry
# to begin with, and whose shim the unqualified path does remove).
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
# -----------------------------------------------------------------------------
$cm = Import-Module (Join-Path $script:Root 'modules\JanetWeb.c2c.psm1') -Force -PassThru
Add-ShimGuard $cm

# --- helpers ---------------------------------------------------------------
# Make a throwaway self-signed CA cert; return @{ B64; Thumbprint; Raw }.
# audit 2026-07-25 (fable re-audit follow-up): these fixtures stand in for DoD TRUST ANCHORS
# pushed into Root/CA, so they must carry BasicConstraints CA=true - Add-C2cBundleToStores now
# refuses a non-CA cert into a trust-anchor store (Test-C2cIsCa). A plain self-signed cert (the
# old fixture) is a LEAF and is correctly rejected; see C2c.CaGuardAndRollup.Tests.ps1.
function New-TestCert {
    param([string]$Subject = 'CN=C2C-Test')
    $c = New-SelfSignedCertificate -Subject $Subject -CertStoreLocation 'Cert:\CurrentUser\My' -KeyUsage CertSign,CRLSign -TextExtension @('2.5.29.19={text}CA=true') -KeyExportPolicy Exportable -KeyLength 2048 -NotAfter (Get-Date).AddDays(1)
    $raw = $c.RawData
    $tp  = [string]$c.Thumbprint
    Remove-Item ("Cert:\CurrentUser\My\{0}" -f $tp) -Force -ErrorAction SilentlyContinue
    return @{ B64 = [Convert]::ToBase64String($raw); Thumbprint = $tp; Raw = $raw }
}

function New-BundleFolder {
    $root = Join-Path ([System.IO.Path]::GetTempPath()) ("c2c_certtest_{0}" -f ([guid]::NewGuid().ToString('N')))
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    return $root
}

# -----------------------------------------------------------------------------
Describe 'C2C fix-pki - Get-C2cCertBundle enumeration + store mapping' {

    It 'maps root\ -> Root, Intermediate\ -> CA, Untrusted\ -> Disallowed, and loose *.cer -> Root' {
        $f = New-BundleFolder
        try {
            New-Item -ItemType Directory -Path (Join-Path $f 'root') -Force | Out-Null
            New-Item -ItemType Directory -Path (Join-Path $f 'Intermediate') -Force | Out-Null
            New-Item -ItemType Directory -Path (Join-Path $f 'Untrusted') -Force | Out-Null
            $cr = New-TestCert 'CN=RootCert';  [System.IO.File]::WriteAllBytes((Join-Path $f 'root\r.cer'), $cr.Raw)
            $ci = New-TestCert 'CN=InterCert'; [System.IO.File]::WriteAllBytes((Join-Path $f 'Intermediate\i.cer'), $ci.Raw)
            $cu = New-TestCert 'CN=UntrCert';  [System.IO.File]::WriteAllBytes((Join-Path $f 'Untrusted\u.cer'), $cu.Raw)
            $cl = New-TestCert 'CN=LooseCert'; [System.IO.File]::WriteAllBytes((Join-Path $f 'loose.cer'), $cl.Raw)

            $b = & $cm { param($p) Get-C2cCertBundle -Folder $p } $f
            $b.Ok        | Should Be $true
            $b.CertCount | Should Be 4
            @($b.Root).Count       | Should Be 2   # root\ + loose
            @($b.CA).Count         | Should Be 1
            @($b.Disallowed).Count | Should Be 1
            (@($b.Root) | ForEach-Object { $_.Thumbprint }) -contains $cr.Thumbprint | Should Be $true
            (@($b.Root) | ForEach-Object { $_.Thumbprint }) -contains $cl.Thumbprint | Should Be $true
            (@($b.CA)   | ForEach-Object { $_.Thumbprint }) -contains $ci.Thumbprint | Should Be $true
            (@($b.Disallowed) | ForEach-Object { $_.Thumbprint }) -contains $cu.Thumbprint | Should Be $true
        } finally { Remove-Item -LiteralPath $f -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'is case-insensitive on the store subfolder name (ROOT\ still maps to Root)' {
        $f = New-BundleFolder
        try {
            New-Item -ItemType Directory -Path (Join-Path $f 'ROOT') -Force | Out-Null
            $cr = New-TestCert 'CN=CaseRoot'; [System.IO.File]::WriteAllBytes((Join-Path $f 'ROOT\r.cer'), $cr.Raw)
            $b = & $cm { param($p) Get-C2cCertBundle -Folder $p } $f
            $b.Ok | Should Be $true
            @($b.Root).Count | Should Be 1
        } finally { Remove-Item -LiteralPath $f -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'ABORTS (Ok=$false, Error set) when the folder is MISSING - nothing to dial' {
        $b = & $cm { param($p) Get-C2cCertBundle -Folder $p } 'X:\no\such\bundle\folder\at\all'
        $b.Ok    | Should Be $false
        $b.Error | Should Match '(?i)not found'
    }

    It 'ABORTS (Ok=$false) when the folder exists but yields ZERO .cer files' {
        $f = New-BundleFolder
        try {
            $b = & $cm { param($p) Get-C2cCertBundle -Folder $p } $f
            $b.Ok    | Should Be $false
            $b.Error | Should Match '(?i)no \.cer'
        } finally { Remove-Item -LiteralPath $f -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

# -----------------------------------------------------------------------------
Describe 'C2C fix-pki - Add-C2cBundleToStores is ADDITIVE (adds only-missing, never removes)' {

    It 'adds ONLY the certs whose thumbprint is not already present, and never calls Remove' {
        $a = New-TestCert 'CN=AlreadyPresent'
        $b = New-TestCert 'CN=Missing'
        $r = & $cm {
            param($aTp, $aB64, $bTp, $bB64)
            $bundle = [pscustomobject]@{
                Root       = @([pscustomobject]@{ t=$aTp; b=$aB64 }, [pscustomobject]@{ t=$bTp; b=$bB64 })
                CA         = @()
                Disallowed = @()
            }
            # Fake store: Root already contains cert A. Add appends to $this._added; there is
            # NO Remove method, so any removal attempt would throw - proving nothing is removed.
            $opener = {
                param($storeName)
                $o = New-Object psobject
                $existing = @()
                if ($storeName -eq 'Root') { $existing = @([pscustomobject]@{ Thumbprint = $aTp }) }
                Add-Member -InputObject $o -MemberType NoteProperty -Name Certificates -Value $existing
                Add-Member -InputObject $o -MemberType NoteProperty -Name _added -Value (New-Object System.Collections.ArrayList)
                Add-Member -InputObject $o -MemberType ScriptMethod -Name Add   -Value { param($c) [void]$this._added.Add([string]$c.Thumbprint) }
                Add-Member -InputObject $o -MemberType ScriptMethod -Name Close -Value { }
                return $o
            }.GetNewClosure()
            $res = Add-C2cBundleToStores -Bundle $bundle -StoreOpener $opener
            [pscustomobject]@{ Added=$res.Added; Already=$res.Already; Total=$res.Total }
        } $a.Thumbprint $a.B64 $b.Thumbprint $b.B64

        $r.Total   | Should Be 2
        $r.Added   | Should Be 1    # only the missing cert B was added
        $r.Already | Should Be 1    # cert A was already present, left alone
    }

    It 'reports NOCHANGE material (Added=0) when every cert is already present, and Add is never called' {
        $a = New-TestCert 'CN=Pre1'
        $r = & $cm {
            param($aTp, $aB64)
            $bundle = [pscustomobject]@{ Root=@([pscustomobject]@{ t=$aTp; b=$aB64 }); CA=@(); Disallowed=@() }
            $opener = {
                param($storeName)
                $o = New-Object psobject
                Add-Member -InputObject $o -MemberType NoteProperty -Name Certificates -Value @([pscustomobject]@{ Thumbprint = $aTp })
                Add-Member -InputObject $o -MemberType ScriptMethod -Name Add   -Value { param($c) throw 'must not add an already-present cert' }
                Add-Member -InputObject $o -MemberType ScriptMethod -Name Close -Value { }
                return $o
            }.GetNewClosure()
            $res = Add-C2cBundleToStores -Bundle $bundle -StoreOpener $opener
            [pscustomobject]@{ Added=$res.Added; Already=$res.Already; Fail=[string]$res.FailDetail }
        } $a.Thumbprint $a.B64
        $r.Added   | Should Be 0
        $r.Already | Should Be 1
        $r.Fail    | Should Be ''
    }
}

# -----------------------------------------------------------------------------
Describe 'C2C Get-C2cInstalledProduct - matches across BOTH uninstall hives' {

    function Invoke-InstalledProbe {
        param([string]$Match, [string]$Hive)   # Hive = 'x64' or 'wow'
        & $cm {
            param($Match, $Hive)
            $script:__hive = $Hive
            $__shims = Save-ShimState @('Get-ItemProperty')
            function script:Get-ItemProperty {
                param($Path, $LiteralPath, $ErrorAction)
                $isWow = ([string]$Path -match 'WOW6432Node')
                if ($script:__hive -eq 'wow' -and $isWow)  { return [pscustomobject]@{ DisplayName='Google Chrome'; DisplayVersion='130.0.6723.117' } }
                if ($script:__hive -eq 'x64' -and -not $isWow) { return [pscustomobject]@{ DisplayName='Google Chrome'; DisplayVersion='130.0.6723.117' } }
                return @()
            }
            try {
                . ([scriptblock]::Create($script:C2cInstalledProductSrc))
                Get-C2cInstalledProduct -Match $Match
            } finally { Restore-ShimState $__shims }   # audit 2026-07-25: the old 'Remove-Item function:script:X' spelling was inert (see Add-ShimGuard) - the shim leaked
        } $Match $Hive
    }

    It 'finds a product that only exists in the 64-bit hive' {
        $p = Invoke-InstalledProbe -Match 'Google Chrome' -Hive 'x64'
        [bool]$p.Installed | Should Be $true
        $p.Version | Should Be '130.0.6723.117'
    }

    It 'finds a product that only exists in the 32-bit (WOW6432Node) hive' {
        $p = Invoke-InstalledProbe -Match 'Google Chrome' -Hive 'wow'
        [bool]$p.Installed | Should Be $true
        $p.Version | Should Be '130.0.6723.117'
    }

    It 'does not match a different DisplayName substring' {
        $p = Invoke-InstalledProbe -Match 'Mozilla Firefox' -Hive 'x64'
        [bool]$p.Installed | Should Be $false
    }
}

# -----------------------------------------------------------------------------
Describe 'C2C version-check - the version matrix (System.Version + ordinal fallback)' {

    # Run the REAL C2cVersionBlock worker LOCALLY. New-PSSession / Invoke-Command /
    # Get-ItemProperty shimmed IN MODULE SCOPE so no WinRM call leaves the box.
    function Invoke-VersionCheck {
        param([string]$Installed, [string]$Version, [string]$Target)
        & $cm {
            param($Installed, $Version, $Target)
            $script:__inst = ($Installed -eq 'yes'); $script:__ver = $Version
            $__shims = Save-ShimState @('New-PSSession','Remove-PSSession','Invoke-Command','Get-ItemProperty')
            function script:New-PSSession { param($ComputerName, $SessionOption, $Authentication, $ErrorAction, $Credential) [pscustomobject]@{ Id=1; Name='shim' } }
            function script:Remove-PSSession { param($Session, $ErrorAction) }
            function script:Invoke-Command {
                param($Session, $ComputerName, $ScriptBlock, $ArgumentList, $ErrorAction, $Credential, $Authentication, $SessionOption)
                return (& $ScriptBlock @ArgumentList)
            }
            function script:Get-ItemProperty {
                param($Path, $LiteralPath, $ErrorAction)
                if ($script:__inst) { return [pscustomobject]@{ DisplayName='Google Chrome'; DisplayVersion=$script:__ver } }
                return @()
            }
            try {
                # AttemptOffline=$true so an unreachable self short-circuit is skipped.
                $res = & $script:C2cVersionBlock $env:COMPUTERNAME $null 'Default' $true 'Google Chrome' $Target $false '' $script:C2cInstalledProductSrc
                [pscustomobject]@{ Status=[string]$res.Status; Installed=[string]$res.Installed; Version=[string]$res.Version }
            } finally {
                # audit 2026-07-25: this teardown was 'Remove-Item function:script:<name>' - an INERT path
                # (the function provider has no scope qualifier), so the shims leaked. See Add-ShimGuard above.
                Restore-ShimState $__shims
            }
        } $Installed $Version $Target
    }

    It 'installed == target -> UP TO DATE' {
        (Invoke-VersionCheck -Installed 'yes' -Version '130.0.6723.117' -Target '130.0.6723.117').Status | Should Be 'UP TO DATE'
    }
    It 'installed < target -> OUTDATED (System.Version compare)' {
        (Invoke-VersionCheck -Installed 'yes' -Version '129.0.1.0' -Target '130.0.6723.117').Status | Should Be 'OUTDATED'
    }
    It 'installed > target -> NEWER (System.Version compare)' {
        (Invoke-VersionCheck -Installed 'yes' -Version '131.0.0.0' -Target '130.0.6723.117').Status | Should Be 'NEWER'
    }
    It 'not installed -> NOT INSTALLED' {
        (Invoke-VersionCheck -Installed 'no' -Version '' -Target '130.0.6723.117').Status | Should Be 'NOT INSTALLED'
    }
    It 'installed with NO target -> INSTALLED (no version comparison)' {
        (Invoke-VersionCheck -Installed 'yes' -Version '130.0.6723.117' -Target '').Status | Should Be 'INSTALLED'
    }
    It 'non-parseable versions fall back to an ordinal string compare (1.2.3a < 1.2.3b -> OUTDATED)' {
        (Invoke-VersionCheck -Installed 'yes' -Version '1.2.3a' -Target '1.2.3b').Status | Should Be 'OUTDATED'
    }
}

# -----------------------------------------------------------------------------
Describe 'C2C winrm-heal - Invoke-JanetC2cWinrmHeal RPC bucketing' {

    # Drive the heal with an INJECTED 5985 probe (no real socket) + shimmed SCM cmdlets.
    function Invoke-Heal {
        param([string]$Scenario)
        & $cm {
            param($Scenario)
            $script:__scn = $Scenario
            $script:__pc  = 0
            $__shims = Save-ShimState @('Get-Service','Start-Service','Set-Service')
            function script:Get-Service {
                param($ComputerName, $Name, $ErrorAction)
                if ($script:__scn -eq 'offline') { throw 'RPC server unavailable (test)' }
                return [pscustomobject]@{ Name=$Name; Status='Stopped'; StartType='Manual' }
            }
            function script:Start-Service { param($InputObject, $Name, $ErrorAction) }
            function script:Set-Service   { param($ComputerName, $Name, $StartupType, $ErrorAction) }
            $probe = {
                param($c)
                $script:__pc++
                if ($script:__scn -eq 'reachable')  { return $true }
                if ($script:__scn -eq 'recovered')  { return ($script:__pc -ge 2) }  # down, then up after heal
                return $false   # 'failed' + 'offline' never come up
            }
            try {
                $h = Invoke-JanetC2cWinrmHeal -Computer 'FAKEHOST' -Probe $probe
                [pscustomobject]@{ Bucket=[string]$h.Bucket; Detail=[string]$h.Detail }
            } finally {
                # audit 2026-07-25: this teardown was 'Remove-Item function:script:<name>' - an INERT path
                # (the function provider has no scope qualifier), so the shims leaked. See Add-ShimGuard above.
                Restore-ShimState $__shims
            }
        } $Scenario
    }

    It 'already reachable on 5985 -> reachable (no SCM action)' {
        (Invoke-Heal -Scenario 'reachable').Bucket | Should Be 'reachable'
    }
    It 'stopped service, comes up after heal -> winrm-recovered' {
        (Invoke-Heal -Scenario 'recovered').Bucket | Should Be 'winrm-recovered'
    }
    It 'stopped service, still down after heal -> winrm-failed' {
        (Invoke-Heal -Scenario 'failed').Bucket | Should Be 'winrm-failed'
    }
    It 'RPC to the SCM throws (blocked / unreachable) -> offline' {
        (Invoke-Heal -Scenario 'offline').Bucket | Should Be 'offline'
    }
}

# =============================================================================
#  v1.6.0 review gaps closed below (added 2026-07-08):
#    (1) the REAL fix-pki install -> classify -> label path, both at the helper
#        level (the exact Get-C2cPkiRootsResultToken + Get-C2cPillarLabel the
#        worker calls) AND end-to-end through the real $script:C2cFixBlock worker.
#    (2) the Convert-C2cBundleToJson serialize -> deserialize -> install round-trip
#        (incl. the PS5.1 single-element-array footgun).
#    (3) the shipped-bundle auto-default (Get-C2cDefaultCertBundlePath /
#        Resolve-C2cCertBundleFolder) + a fix-pki integration proof.
#  Still no WinRM call and no real cert-store write ever leaves this box.
# =============================================================================

# -----------------------------------------------------------------------------
Describe 'C2C fix-pki - REAL classify + label (the exact token + label map the worker calls)' {
    # Runs the REAL additive installer (Add-C2cBundleToStores) against an injected
    # fake store, then routes its outcome through the REAL helpers the fix worker
    # calls: Get-C2cPkiRootsResultToken (classify) -> Get-C2cPillarLabel (label). A
    # mis-classification OR a mis-wired label ('ROOTS INSTALLED' typo) fails a test.

    It '(1) an all-NEW-certs add -> classifies FIXED -> label ROOTS INSTALLED' {
        $a = New-TestCert 'CN=New1'; $b = New-TestCert 'CN=New2'
        $r = & $cm {
            param($aTp, $aB64, $bTp, $bB64)
            $bundle = [pscustomobject]@{ Root = @([pscustomobject]@{ t=$aTp; b=$aB64 }, [pscustomobject]@{ t=$bTp; b=$bB64 }); CA=@(); Disallowed=@() }
            $opener = {
                param($storeName)
                $o = New-Object psobject
                Add-Member -InputObject $o -MemberType NoteProperty -Name Certificates -Value @()
                Add-Member -InputObject $o -MemberType NoteProperty -Name _added -Value (New-Object System.Collections.ArrayList)
                Add-Member -InputObject $o -MemberType ScriptMethod -Name Add   -Value { param($c) [void]$this._added.Add([string]$c.Thumbprint) }
                Add-Member -InputObject $o -MemberType ScriptMethod -Name Close -Value { }
                return $o
            }
            $ar  = Add-C2cBundleToStores -Bundle $bundle -StoreOpener $opener
            $tok = Get-C2cPkiRootsResultToken $ar
            [pscustomobject]@{ Added=$ar.Added; Token=$tok; Label=(Get-C2cPillarLabel 'PkiRoots' $tok) }
        } $a.Thumbprint $a.B64 $b.Thumbprint $b.B64
        $r.Added | Should Be 2
        $r.Token | Should Be 'FIXED'
        $r.Label | Should Be 'ROOTS INSTALLED'
    }

    It '(2) an all-ALREADY-PRESENT bundle -> classifies NOCHANGE -> label ROOTS ALREADY PRESENT (Add never called)' {
        $a = New-TestCert 'CN=Pre1'
        $r = & $cm {
            param($aTp, $aB64)
            $bundle = [pscustomobject]@{ Root = @([pscustomobject]@{ t=$aTp; b=$aB64 }); CA=@(); Disallowed=@() }
            $opener = {
                param($storeName)
                $o = New-Object psobject
                Add-Member -InputObject $o -MemberType NoteProperty -Name Certificates -Value @([pscustomobject]@{ Thumbprint = $aTp })
                Add-Member -InputObject $o -MemberType ScriptMethod -Name Add   -Value { param($c) throw 'must not add an already-present cert' }
                Add-Member -InputObject $o -MemberType ScriptMethod -Name Close -Value { }
                return $o
            }.GetNewClosure()
            $ar  = Add-C2cBundleToStores -Bundle $bundle -StoreOpener $opener
            $tok = Get-C2cPkiRootsResultToken $ar
            [pscustomobject]@{ Added=$ar.Added; Fail=[string]$ar.FailDetail; Token=$tok; Label=(Get-C2cPillarLabel 'PkiRoots' $tok) }
        } $a.Thumbprint $a.B64
        $r.Added | Should Be 0
        $r.Fail  | Should Be ''
        $r.Token | Should Be 'NOCHANGE'
        $r.Label | Should Be 'ROOTS ALREADY PRESENT'
    }

    It '(3) a store whose .Add THROWS -> classifies FAIL (NOT FIXED) -> label is FAIL, never ROOTS INSTALLED' {
        $a = New-TestCert 'CN=AddThrows'
        $r = & $cm {
            param($aTp, $aB64)
            $bundle = [pscustomobject]@{ Root = @([pscustomobject]@{ t=$aTp; b=$aB64 }); CA=@(); Disallowed=@() }
            $opener = {
                param($storeName)
                $o = New-Object psobject
                Add-Member -InputObject $o -MemberType NoteProperty -Name Certificates -Value @()
                Add-Member -InputObject $o -MemberType ScriptMethod -Name Add   -Value { param($c) throw 'store ACL denied (test)' }
                Add-Member -InputObject $o -MemberType ScriptMethod -Name Close -Value { }
                return $o
            }
            $ar  = Add-C2cBundleToStores -Bundle $bundle -StoreOpener $opener
            $tok = Get-C2cPkiRootsResultToken $ar
            [pscustomobject]@{ Added=$ar.Added; Fail=[string]$ar.FailDetail; Token=$tok; Label=(Get-C2cPillarLabel 'PkiRoots' $tok) }
        } $a.Thumbprint $a.B64
        $r.Added | Should Be 0
        $r.Fail  | Should Not Be ''
        $r.Token | Should Be 'FAIL'
        $r.Token | Should Not Be 'FIXED'
        $r.Label | Should Be 'FAIL'
        $r.Label | Should Not Be 'ROOTS INSTALLED'
    }
}

# -----------------------------------------------------------------------------
# Drive the REAL per-host fix worker ($script:C2cFixBlock) LOCALLY for a PkiRoots
# pillar with a REAL BundleJson (Enable-test shim idiom): New-PSSession /
# Remove-PSSession / Invoke-Command shimmed IN MODULE SCOPE, and the additive
# installer wrapped so its DEFAULT store is an in-memory fake (the real
# Add-C2cBundleToStores logic + the real classify/label helpers still run - only the
# physical X509Store is faked, so nothing touches the LocalMachine stores). This
# exercises the whole worker path end-to-end: BundleJson -> ConvertFrom-Json ->
# Add-C2cBundleToStores -> Get-C2cPkiRootsResultToken -> admin-side $labelOf/
# Get-C2cPillarLabel -> emitted pillar Result + labeled Detail/Report.
#   fixed    - store empty, bundle new     -> FIXED    -> ROOTS INSTALLED
#   nochange - store already has the cert   -> NOCHANGE -> ROOTS ALREADY PRESENT
#   fail     - store .Add throws            -> FAIL     -> (not ROOTS INSTALLED)
function Invoke-C2cPkiWorker {
    param([string]$Scenario, [string]$Tp, [string]$B64)
    & $cm {
        param($Scenario, $Tp, $B64)
        $__shims = Save-ShimState @('New-PSSession','Remove-PSSession','Invoke-Command')
        function script:New-PSSession { param($ComputerName, $SessionOption, $Authentication, $ErrorAction, $Credential) [pscustomobject]@{ Id = 1; Name = 'shim' } }
        function script:Remove-PSSession { param($Session, $ErrorAction) }
        function script:Invoke-Command {
            param($Session, $ComputerName, $ScriptBlock, $ArgumentList, $ErrorAction, $Credential, $Authentication, $SessionOption)
            if ($ScriptBlock -and ($ScriptBlock.ToString().Trim() -eq '$env:COMPUTERNAME')) { return $env:COMPUTERNAME }
            return (& $ScriptBlock @ArgumentList)
        }
        $bundleJson = Convert-C2cBundleToJson ([pscustomobject]@{ Root = @([pscustomobject]@{ Thumbprint = $Tp; B64 = $B64 }); CA = @(); Disallowed = @() })
        $script:__c2cSeed  = if ($Scenario -eq 'nochange') { @($Tp) } else { @() }
        $script:__c2cThrow = ($Scenario -eq 'fail')
        $script:__c2cFakeOpener = {
            param($storeName)
            $o = New-Object psobject
            $seedCerts = @($script:__c2cSeed | ForEach-Object { [pscustomobject]@{ Thumbprint = $_ } })
            Add-Member -InputObject $o -MemberType NoteProperty -Name Certificates -Value $seedCerts
            if ($script:__c2cThrow) { Add-Member -InputObject $o -MemberType ScriptMethod -Name Add -Value { param($c) throw 'fake store: Add denied (ACL, test)' } }
            else                    { Add-Member -InputObject $o -MemberType ScriptMethod -Name Add -Value { param($c) } }
            Add-Member -InputObject $o -MemberType ScriptMethod -Name Close -Value { }
            return $o
        }
        # Wrap the real cert/label source so Add-C2cBundleToStores DEFAULTS to the fake store.
        $wrap = "`n" + '$script:__c2cRealAdd = ${function:Add-C2cBundleToStores}' + "`n" +
                '${function:Add-C2cBundleToStores} = { param($Bundle,[scriptblock]$StoreOpener) if (-not $StoreOpener) { $StoreOpener = $script:__c2cFakeOpener }; & $script:__c2cRealAdd -Bundle $Bundle -StoreOpener $StoreOpener }'
        $fakeAddSrc = $script:C2cAddCertsSrc + $wrap
        try {
            # target = self so the wrong-box guard passes; AttemptOffline so the TCP short-circuit is skipped.
            $res = & $script:C2cFixBlock $env:COMPUTERNAME $null 'Default' $true @('PkiRoots') $false 'Tanium Client' $script:C2cTaniumInstalledSrc $bundleJson $false $script:C2cWinrmHealSrc $fakeAddSrc
            $pki = @(@($res.Pillars) | Where-Object { $_.Name -eq 'PkiRoots' })[0]
            [pscustomobject]@{
                Status    = [string]$res.Status
                PkiResult = $(if ($pki) { [string]$pki.Result } else { '' })
                Detail    = [string]$res.Detail
                Report    = [string]$res.Report
            }
        } finally {
            # audit 2026-07-25: this teardown was 'Remove-Item function:script:<name>' - an INERT path
            # (the function provider has no scope qualifier), so the shims leaked. See Add-ShimGuard above.
            Restore-ShimState $__shims
        }
    } $Scenario $Tp $B64
}

Describe 'C2C fix-pki - REAL worker end-to-end (install/classify/label through $script:C2cFixBlock)' {

    It '(4) a NEW-cert bundle INSTALLS -> pillar FIXED -> host FIXED -> report labeled ROOTS INSTALLED' {
        $c = New-TestCert 'CN=WkFixed'
        $r = Invoke-C2cPkiWorker -Scenario 'fixed' -Tp $c.Thumbprint -B64 $c.B64
        $r.PkiResult | Should Be 'FIXED'
        $r.Status    | Should Be 'FIXED'
        $r.Detail    | Should Match 'ROOTS INSTALLED'
        $r.Report    | Should Match 'ROOTS INSTALLED'
    }

    It '(5) an already-present bundle -> pillar NOCHANGE -> host NO CHANGE -> report labeled ROOTS ALREADY PRESENT' {
        $c = New-TestCert 'CN=WkNoChange'
        $r = Invoke-C2cPkiWorker -Scenario 'nochange' -Tp $c.Thumbprint -B64 $c.B64
        $r.PkiResult | Should Be 'NOCHANGE'
        $r.Status    | Should Be 'NO CHANGE'
        $r.Report    | Should Match 'ROOTS ALREADY PRESENT'
        $r.Report    | Should Not Match 'ROOTS INSTALLED'
    }

    It '(6) a store whose .Add THROWS -> pillar FAIL (NOT FIXED) -> host FAILED -> never labeled ROOTS INSTALLED' {
        $c = New-TestCert 'CN=WkFail'
        $r = Invoke-C2cPkiWorker -Scenario 'fail' -Tp $c.Thumbprint -B64 $c.B64
        $r.PkiResult | Should Be 'FAIL'
        $r.Status    | Should Be 'FAILED'
        $r.Report    | Should Not Match 'ROOTS INSTALLED'
    }
}

# -----------------------------------------------------------------------------
Describe 'C2C fix-pki - Convert-C2cBundleToJson serialize -> deserialize -> install round-trip' {

    It '(7) round-trips multi / single / empty stores as ARRAYS of {t,b}, then installs the deserialized shape' {
        $r1 = New-TestCert 'CN=RT-Root1'; $r2 = New-TestCert 'CN=RT-Root2'   # multiple certs in one store
        $ca = New-TestCert 'CN=RT-CA'                                        # EXACTLY ONE (single-element footgun)
        $out = & $cm {
            param($r1Tp, $r1B64, $r2Tp, $r2B64, $caTp, $caB64)
            $bundle = [pscustomobject]@{
                Root       = @([pscustomobject]@{ Thumbprint = $r1Tp; B64 = $r1B64 }, [pscustomobject]@{ Thumbprint = $r2Tp; B64 = $r2B64 })
                CA         = @([pscustomobject]@{ Thumbprint = $caTp; B64 = $caB64 })   # single element
                Disallowed = @()                                                        # empty store
            }
            $json = Convert-C2cBundleToJson $bundle
            $o    = $json | ConvertFrom-Json
            # feed the DESERIALIZED shape straight into the additive installer (fake store)
            $added  = New-Object System.Collections.ArrayList
            $opener = {
                param($storeName)
                $st = New-Object psobject
                Add-Member -InputObject $st -MemberType NoteProperty -Name Certificates -Value @()
                Add-Member -InputObject $st -MemberType NoteProperty -Name _a -Value $added
                Add-Member -InputObject $st -MemberType ScriptMethod -Name Add   -Value { param($c) [void]$this._a.Add([string]$c.Thumbprint) }
                Add-Member -InputObject $st -MemberType ScriptMethod -Name Close -Value { }
                return $st
            }.GetNewClosure()
            $ar = Add-C2cBundleToStores -Bundle $o -StoreOpener $opener
            [pscustomobject]@{
                RootCount = @($o.Root).Count;       RootIsArr = ($o.Root -is [System.Array])
                CaCount   = @($o.CA).Count;         CaIsArr   = ($o.CA -is [System.Array])
                DisCount  = @($o.Disallowed).Count; DisIsArr  = ($o.Disallowed -is [System.Array])
                RootT0 = [string]$o.Root[0].t; RootB0 = [string]$o.Root[0].b
                CaT0   = [string]$o.CA[0].t;   CaB0   = [string]$o.CA[0].b
                Installed = $ar.Added; AddedTps = @($added.ToArray())
            }
        } $r1.Thumbprint $r1.B64 $r2.Thumbprint $r2.B64 $ca.Thumbprint $ca.B64

        # each store deserializes to an ARRAY of {t,b} of the right count
        $out.RootIsArr | Should Be $true;  $out.RootCount | Should Be 2
        $out.CaIsArr   | Should Be $true;  $out.CaCount   | Should Be 1   # single-element -> 1-element ARRAY, NOT a bare object
        $out.DisIsArr  | Should Be $true;  $out.DisCount  | Should Be 0
        # each element carries its thumbprint (.t) + base64 (.b)
        $out.RootT0 | Should Be $r1.Thumbprint
        $out.RootB0 | Should Be $r1.B64
        $out.CaT0   | Should Be $ca.Thumbprint
        $out.CaB0   | Should Be $ca.B64
        # and the deserialized shape INSTALLS the right certs (closes serialize->deserialize->install)
        $out.Installed | Should Be 3
        (@($out.AddedTps) -contains $r1.Thumbprint) | Should Be $true
        (@($out.AddedTps) -contains $r2.Thumbprint) | Should Be $true
        (@($out.AddedTps) -contains $ca.Thumbprint) | Should Be $true
    }
}

# -----------------------------------------------------------------------------
Describe 'C2C fix-pki - shipped-bundle auto-default (Get-C2cDefaultCertBundlePath / Resolve-C2cCertBundleFolder)' {

    It '(8) Get-C2cDefaultCertBundlePath points at Packages\DoD-Certs (relative to the module, like Get-C2cBaselinePath)' {
        $p = & $cm { Get-C2cDefaultCertBundlePath }
        $p | Should Match '(?i)Packages[\\/]+DoD-Certs$'
    }

    It '(9) an operator-supplied (non-blank) path ALWAYS wins and is tagged operator-supplied (trimmed/unquoted)' {
        $r = & $cm { Resolve-C2cCertBundleFolder '  "\\srv\share\MyCerts"  ' }
        $r.Folder | Should Be '\\srv\share\MyCerts'
        $r.Source | Should Be 'operator-supplied'
    }

    It '(10) a BLANK path falls back to the shipped default WHEN it exists + holds >=1 .cer' {
        $tmp = New-BundleFolder
        try {
            New-Item -ItemType Directory -Path (Join-Path $tmp 'root') -Force | Out-Null
            $c = New-TestCert 'CN=DefRoot'; [System.IO.File]::WriteAllBytes((Join-Path $tmp 'root\d.cer'), $c.Raw)
            $r = & $cm {
                param($def)
                $orig = ${function:Get-C2cDefaultCertBundlePath}
                ${function:Get-C2cDefaultCertBundlePath} = { $def }.GetNewClosure()
                try { Resolve-C2cCertBundleFolder '' } finally { ${function:Get-C2cDefaultCertBundlePath} = $orig }
            } $tmp
            $r.Folder | Should Be $tmp
            $r.Source | Should Be 'shipped default'
        } finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It '(11) a BLANK path with NO usable default -> Folder='''' / Source='''' (keeps fix-pki abort / run-all skip)' {
        $r = & $cm {
            $orig = ${function:Get-C2cDefaultCertBundlePath}
            ${function:Get-C2cDefaultCertBundlePath} = { 'X:\no\such\shipped\bundle' }
            try { Resolve-C2cCertBundleFolder '   ' } finally { ${function:Get-C2cDefaultCertBundlePath} = $orig }
        }
        [string]$r.Folder | Should Be ''
        [string]$r.Source | Should Be ''
    }

    It '(12) fix-pki with a BLANK certBundleFolder resolves the shipped default and PROCEEDS (not rejected); self-target is self-guarded' {
        # Depends on the repo shipping Packages\DoD-Certs; tolerant if it is absent.
        $defOk = & $cm { $p = Get-C2cDefaultCertBundlePath; [bool]((Test-Path -LiteralPath $p) -and (@(Get-ChildItem -LiteralPath $p -Filter '*.cer' -File -Recurse -ErrorAction SilentlyContinue).Count -gt 0)) }
        # v1.10.0: fix-pki is import-scoped - the import must flag the dispatcher for PKI
        # Trust Roots so it survives target resolution; the self-guard then drops it.
        $csv12  = Join-Path ([System.IO.Path]::GetTempPath()) ("c2c_cv12_{0}.csv" -f ([guid]::NewGuid().ToString('N')))
        $body12 = @"
C2C Compliance Status:Compliance,C2C Compliance Status:Date,C2C Compliance Status:Age (Bucketed),Computer Name,Count
"Non-Compliant
Failed Rule - PKI Trust Roots",,,$($env:COMPUTERNAME).area52.afnoapps.usaf.mil,1
"@
        Set-Content -LiteralPath $csv12 -Value $body12 -Encoding UTF8
        $logs  = New-Object System.Collections.ArrayList
        $emit  = { param($e) if ($e -and $e.type -eq 'log') { [void]$logs.Add($e) } }
        try {
            $res = Invoke-JanetToolAction -ActionId 'fix-pki' -Params @{ targets = $env:COMPUTERNAME; csvPath = $csv12; confirm = 'FIX'; certBundleFolder = '' } -Credential $null -Emit $emit
            if ($defOk) {
                # blank path fell back to the shipped default -> the action proceeded (was NOT rejected).
                $res.summary.rejected | Should BeNullOrEmpty
                @($logs | Where-Object { $_.text -match '(?i)shipped default' }).Count | Should Not Be 0
                # only the dispatcher host was targeted -> self-guard dropped it, nothing dialed.
                $res.summary.selfSkipped | Should Not Be 0
            } else {
                # no shipped default present -> blank path keeps the abort-with-clear-error path.
                $res.summary.rejected | Should Be $true
            }
        } finally { Remove-Item -LiteralPath $csv12 -Force -ErrorAction SilentlyContinue }
    }
}
