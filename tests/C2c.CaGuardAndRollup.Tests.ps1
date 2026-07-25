# =============================================================================
#  C2c.CaGuardAndRollup.Tests.ps1 - Pester 3.4 tests for the audit 2026-07-25
#  (fable re-audit follow-up) fixes in modules\JanetWeb.c2c.psm1.
#
#  Mirrors the existing C2c.CertsAndVersion / CertDeploy.CaValidation shim idiom:
#  throwaway self-signed certs built OFFLINE + an INJECTED fake X509Store, and the
#  per-host worker driven LOCALLY with New-PSSession / Invoke-Command shimmed in
#  MODULE SCOPE - so NO real cert-store write and NO WinRM call ever leaves this box.
#
#  Coverage:
#    (1) [P3 SECURITY PARITY] TRUST-ANCHOR GUARD. c2c could push a LEAF (non-CA) cert
#        into the fleet's machine Root/CA trust stores from an operator-supplied
#        certBundleFolder - certdeploy has refused that since its own P2 fix. c2c now
#        carries the same guard (Test-C2cIsCa, duplicated BY DESIGN because a pool /
#        remote runspace cannot see the other module's functions):
#          (1a) the pure BasicConstraints CA=true parse, fail-closed;
#          (1b) Add-C2cBundleToStores REFUSES a non-CA cert into Root and into CA and
#               never adds it, while still trusting the real CA alongside it;
#          (1c) the refused-and-ABSENT anchor classifies REJECTED (never the clean
#               FIXED / NOCHANGE, which roll up to a green host + audit Skipped);
#          (1d) the Disallowed (Untrusted) BLACKLIST is NOT a trust anchor, so a
#               non-CA cert there is still allowed - the guard must not touch it.
#    (2) [P3 DISTRUST GATE] the Untrusted\ -> Disallowed push is fail-closed at the
#        serializer: the worker is not even handed the certs unless armed.
#    (3) [P3 ROLLUP] an all-IN PROGRESS host rolls up IN PROGRESS - it used to match no
#        bucket and fall through to 'NO CHANGE' -> audit 'Skipped', reading "already
#        compliant" for a box the C2C scan would still FAIL.
#
#  Run:  Invoke-Pester -Path .\tests\C2c.CaGuardAndRollup.Tests.ps1
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

# --- helpers: throwaway self-signed certs, built OFFLINE ----------------------
# A real CA cert: BasicConstraints CA=true (+ CertSign key usage).
function New-GuardCaCert {
    param([string]$Subject = 'CN=C2C-Guard-CA')
    $c = New-SelfSignedCertificate -Subject $Subject -CertStoreLocation 'Cert:\CurrentUser\My' -KeyUsage CertSign,CRLSign -TextExtension @('2.5.29.19={text}CA=true') -KeyExportPolicy Exportable -KeyLength 2048 -NotAfter (Get-Date).AddDays(1)
    $raw = $c.RawData; $tp = [string]$c.Thumbprint
    Remove-Item ("Cert:\CurrentUser\My\{0}" -f $tp) -Force -ErrorAction SilentlyContinue
    return @{ B64 = [Convert]::ToBase64String($raw); Thumbprint = $tp; Raw = $raw }
}
# A leaf / end-entity cert: BasicConstraints CA=false (explicit -> deterministic offline).
function New-GuardLeafCert {
    param([string]$Subject = 'CN=C2C-Guard-Leaf')
    $c = New-SelfSignedCertificate -Subject $Subject -CertStoreLocation 'Cert:\CurrentUser\My' -TextExtension @('2.5.29.19={text}CA=false') -KeyExportPolicy Exportable -KeyLength 2048 -NotAfter (Get-Date).AddDays(1)
    $raw = $c.RawData; $tp = [string]$c.Thumbprint
    Remove-Item ("Cert:\CurrentUser\My\{0}" -f $tp) -Force -ErrorAction SilentlyContinue
    return @{ B64 = [Convert]::ToBase64String($raw); Thumbprint = $tp; Raw = $raw }
}
# A default self-signed cert (no BasicConstraints at all) - proves the FAIL-CLOSED path.
function New-GuardPlainCert {
    param([string]$Subject = 'CN=C2C-Guard-Plain')
    $c = New-SelfSignedCertificate -Subject $Subject -CertStoreLocation 'Cert:\CurrentUser\My' -KeyExportPolicy Exportable -KeyLength 2048 -NotAfter (Get-Date).AddDays(1)
    $raw = $c.RawData; $tp = [string]$c.Thumbprint
    Remove-Item ("Cert:\CurrentUser\My\{0}" -f $tp) -Force -ErrorAction SilentlyContinue
    return @{ B64 = [Convert]::ToBase64String($raw); Thumbprint = $tp; Raw = $raw }
}

# An injectable fake X509Store backed by an ArrayList (the suite idiom): Add appends a
# { Thumbprint } stub. There is NO Remove method, so any removal attempt would throw.
# c2c's opener contract is one arg (the store name).
$script:GuardOpenerSrc = {
    param($Backing)
    {
        param($storeName)
        $o = New-Object psobject
        Add-Member -InputObject $o -MemberType NoteProperty -Name Certificates -Value $Backing
        Add-Member -InputObject $o -MemberType ScriptMethod -Name Add   -Value { param($cert) [void]$this.Certificates.Add([pscustomobject]@{ Thumbprint = [string]$cert.Thumbprint }) }
        Add-Member -InputObject $o -MemberType ScriptMethod -Name Close -Value { }
        return $o
    }.GetNewClosure()
}

# =============================================================================
Describe 'C2C (1a) Test-C2cIsCa - pure BasicConstraints CA=true parse (fail-closed)' {

    It 'ACCEPTS a real CA cert (BasicConstraints CA=true)' {
        $ca = New-GuardCaCert
        $ok = & $cm { param($raw) $c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$raw); [bool](Test-C2cIsCa $c) } $ca.Raw
        $ok | Should Be $true
    }
    It 'REJECTS a leaf / end-entity cert (BasicConstraints CA=false)' {
        $leaf = New-GuardLeafCert
        $ok = & $cm { param($raw) $c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$raw); [bool](Test-C2cIsCa $c) } $leaf.Raw
        $ok | Should Be $false
    }
    It 'REJECTS a cert with NO BasicConstraints extension (FAIL-CLOSED)' {
        $plain = New-GuardPlainCert
        $ok = & $cm { param($raw) $c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$raw); [bool](Test-C2cIsCa $c) } $plain.Raw
        $ok | Should Be $false
    }
    It 'REJECTS a null cert (fail-closed, no throw)' {
        (& $cm { [bool](Test-C2cIsCa $null) }) | Should Be $false
    }
}

# =============================================================================
Describe 'C2C (1b)+(1c) Add-C2cBundleToStores - a LEAF cert is refused from the Root/CA push path' {

    It 'anchor store (Root): trusts the CA, REJECTS the non-CA leaf, and the leaf NEVER lands' {
        $ca   = New-GuardCaCert 'CN=C2C-Guard-Root-CA'
        $leaf = New-GuardLeafCert 'CN=C2C-Guard-Root-Leaf'
        $r = & $cm {
            param($caTp, $caB64, $leafTp, $leafB64, $openerSrc)
            $bundle  = [pscustomobject]@{
                Root       = @([pscustomobject]@{ t=$caTp; b=$caB64 }, [pscustomobject]@{ t=$leafTp; b=$leafB64 })
                CA         = @()
                Disallowed = @()
            }
            $backing = New-Object System.Collections.ArrayList
            $res = Add-C2cBundleToStores -Bundle $bundle -StoreOpener (& $openerSrc $backing)
            [pscustomobject]@{
                Added        = [int]$res.Added
                Rejected     = [int]$res.Rejected
                RejectDetail = [string]$res.RejectDetail
                StoreCount   = [int]$backing.Count
                StoreHasLeaf = [bool](@($backing | Where-Object { $_.Thumbprint -eq $leafTp }).Count -gt 0)
                Token        = [string](Get-C2cPkiRootsResultToken $res)
            }
        } $ca.Thumbprint $ca.B64 $leaf.Thumbprint $leaf.B64 $script:GuardOpenerSrc

        $r.Added        | Should Be 1          # only the real CA was trusted
        $r.Rejected     | Should Be 1          # the leaf was refused
        $r.StoreCount   | Should Be 1          # the store holds ONLY the CA
        $r.StoreHasLeaf | Should Be $false     # the leaf never became a fleet trust anchor
        $r.RejectDetail | Should Match 'not a CA certificate'
        # (1c) a wanted anchor refused-and-ABSENT is NOT a clean push: never FIXED / NOCHANGE.
        $r.Token        | Should Be 'REJECTED'
    }

    It 'anchor store (CA/Intermediate): a leaf-only bundle installs NOTHING and classifies REJECTED (not NOCHANGE)' {
        $leaf = New-GuardLeafCert 'CN=C2C-Guard-Inter-Leaf'
        $r = & $cm {
            param($leafTp, $leafB64, $openerSrc)
            $bundle  = [pscustomobject]@{ Root=@(); CA=@([pscustomobject]@{ t=$leafTp; b=$leafB64 }); Disallowed=@() }
            $backing = New-Object System.Collections.ArrayList
            $res = Add-C2cBundleToStores -Bundle $bundle -StoreOpener (& $openerSrc $backing)
            [pscustomobject]@{ Added=[int]$res.Added; Rejected=[int]$res.Rejected; Count=[int]$backing.Count; Token=[string](Get-C2cPkiRootsResultToken $res) }
        } $leaf.Thumbprint $leaf.B64 $script:GuardOpenerSrc

        $r.Added    | Should Be 0
        $r.Rejected | Should Be 1
        $r.Count    | Should Be 0
        $r.Token    | Should Be 'REJECTED'
        $r.Token    | Should Not Be 'NOCHANGE'
    }

    It 'a real CA cert is still ACCEPTED into an anchor store (the guard is NON-BREAKING for legit CAs)' {
        $ca = New-GuardCaCert 'CN=C2C-Guard-Legit-CA'
        $r = & $cm {
            param($caTp, $caB64, $openerSrc)
            $bundle  = [pscustomobject]@{ Root=@([pscustomobject]@{ t=$caTp; b=$caB64 }); CA=@(); Disallowed=@() }
            $backing = New-Object System.Collections.ArrayList
            $res = Add-C2cBundleToStores -Bundle $bundle -StoreOpener (& $openerSrc $backing)
            [pscustomobject]@{ Added=[int]$res.Added; Rejected=[int]$res.Rejected; Count=[int]$backing.Count; Token=[string](Get-C2cPkiRootsResultToken $res) }
        } $ca.Thumbprint $ca.B64 $script:GuardOpenerSrc

        $r.Added    | Should Be 1
        $r.Rejected | Should Be 0
        $r.Count    | Should Be 1
        $r.Token    | Should Be 'FIXED'
    }

    It '(1d) Disallowed (blacklist, NOT a trust anchor): a non-CA leaf is still ALLOWED' {
        $leaf = New-GuardLeafCert 'CN=C2C-Guard-Blacklisted'
        $r = & $cm {
            param($leafTp, $leafB64, $openerSrc)
            $bundle  = [pscustomobject]@{ Root=@(); CA=@(); Disallowed=@([pscustomobject]@{ t=$leafTp; b=$leafB64 }) }
            $backing = New-Object System.Collections.ArrayList
            $res = Add-C2cBundleToStores -Bundle $bundle -StoreOpener (& $openerSrc $backing)
            [pscustomobject]@{ Added=[int]$res.Added; Rejected=[int]$res.Rejected; Count=[int]$backing.Count }
        } $leaf.Thumbprint $leaf.B64 $script:GuardOpenerSrc

        $r.Added    | Should Be 1      # a blacklist entry is normally a leaf - it must still land
        $r.Rejected | Should Be 0      # the anchor guard never applies to Disallowed
        $r.Count    | Should Be 1
    }

    It 'the REJECTED token carries its own pillar label (never "ROOTS INSTALLED")' {
        $lbl = & $cm { Get-C2cPillarLabel 'PkiRoots' 'REJECTED' }
        $lbl | Should Be 'REJECTED (non-CA)'
        $lbl | Should Not Be 'ROOTS INSTALLED'
    }
}

# =============================================================================
Describe 'C2C (2) Convert-C2cBundleToJson - the Untrusted -> Disallowed DISTRUST push is fail-closed' {

    $ca = New-GuardCaCert 'CN=C2C-Guard-Gate'

    It 'OMITS the Disallowed group by default (the worker is never handed the blacklist certs)' {
        $json = & $cm {
            param($tp, $b64)
            Convert-C2cBundleToJson ([pscustomobject]@{ Root=@(); CA=@(); Disallowed=@([pscustomobject]@{ Thumbprint=$tp; B64=$b64 }) })
        } $ca.Thumbprint $ca.B64
        @(($json | ConvertFrom-Json).Disallowed).Count | Should Be 0
    }
    It 'INCLUDES the Disallowed group ONLY when the pushDisallowed gate is armed' {
        $json = & $cm {
            param($tp, $b64)
            Convert-C2cBundleToJson ([pscustomobject]@{ Root=@(); CA=@(); Disallowed=@([pscustomobject]@{ Thumbprint=$tp; B64=$b64 }) }) $true
        } $ca.Thumbprint $ca.B64
        @(($json | ConvertFrom-Json).Disallowed).Count | Should Be 1
    }
    It 'the gate never touches the Root/CA anchor groups' {
        $json = & $cm {
            param($tp, $b64)
            Convert-C2cBundleToJson ([pscustomobject]@{ Root=@([pscustomobject]@{ Thumbprint=$tp; B64=$b64 }); CA=@(); Disallowed=@() })
        } $ca.Thumbprint $ca.B64
        @(($json | ConvertFrom-Json).Root).Count | Should Be 1
    }
    It 'fix-pki declares pushDisallowed as a bool input defaulting to OFF' {
        $man = & $cm { Get-JanetToolManifest }
        $fp  = @($man.actions | Where-Object { $_.id -eq 'fix-pki' })[0]
        $pd  = @($fp.inputs | Where-Object { $_.name -eq 'pushDisallowed' })[0]
        $pd               | Should Not BeNullOrEmpty
        $pd.type          | Should Be 'bool'
        [bool]$pd.default | Should Be $false
        ([string]$pd.label) | Should Match 'BLACKLIST'
        ([string]$pd.label) | Should Match 'DISTRUST'
    }
    It 'the fix-pki confirm text names the Disallowed store and the distrust it causes' {
        $man = & $cm { Get-JanetToolManifest }
        $fp  = @($man.actions | Where-Object { $_.id -eq 'fix-pki' })[0]
        ([string]$fp.confirm) | Should Match 'Disallowed'
        ([string]$fp.confirm) | Should Match 'DISTRUSTS'
    }
}

# =============================================================================
#  (3) Host rollup: drive the REAL per-host worker ($script:C2cFixBlock) LOCALLY with
#  New-PSSession / Remove-PSSession / Invoke-Command shimmed IN MODULE SCOPE. The remote
#  pillar block is replaced by a CRAFTED result set, so this exercises exactly the
#  admin-side rollup + label path - no WinRM, no machine state touched.
function Invoke-C2cRollup {
    param($PillarRows)
    & $cm {
        param($PillarRows)
        $script:__rollupRows = @($PillarRows)
        $__shims = Save-ShimState @('New-PSSession','Remove-PSSession','Invoke-Command')
        function script:New-PSSession { param($ComputerName, $SessionOption, $Authentication, $ErrorAction, $Credential) [pscustomobject]@{ Id = 1; Name = 'shim' } }
        function script:Remove-PSSession { param($Session, $ErrorAction) }
        function script:Invoke-Command {
            param($Session, $ComputerName, $ScriptBlock, $ArgumentList, $ErrorAction, $Credential, $Authentication, $SessionOption)
            # the wrong-box guard's own round-trip
            if ($ScriptBlock -and ($ScriptBlock.ToString().Trim() -eq '$env:COMPUTERNAME')) { return $env:COMPUTERNAME }
            return @{ RemoteName = $env:COMPUTERNAME; Pillars = @($script:__rollupRows) }
        }
        try {
            # target = self so the wrong-box guard passes; AttemptOffline so the TCP probe cannot short-circuit.
            $res = & $script:C2cFixBlock $env:COMPUTERNAME $null 'Default' $true @('Encryption') $false 'Tanium Client' $script:C2cTaniumInstalledSrc '' $false $script:C2cWinrmHealSrc $script:C2cAddCertsSrc
            [pscustomobject]@{ Status = [string]$res.Status; Detail = [string]$res.Detail; Audit = [string](Get-C2cHostAuditResult ([string]$res.Status)) }
        } finally {
            # audit 2026-07-25: this teardown was 'Remove-Item function:script:<name>' - an INERT path
            # (the function provider has no scope qualifier), so the shims leaked. See Add-ShimGuard above.
            Restore-ShimState $__shims
        }
    } $PillarRows
}

Describe 'C2C (3) host rollup - an all-IN PROGRESS host is never booked as NO CHANGE' {

    It 'a lone Encryption IN PROGRESS host rolls up IN PROGRESS (was the clean-looking NO CHANGE)' {
        $r = Invoke-C2cRollup @([pscustomobject]@{ Name='Encryption'; Action='none'; Result='IN PROGRESS'; Detail='C: encryption already in progress (42% done)' })
        $r.Status | Should Be 'IN PROGRESS'
        $r.Status | Should Not Be 'NO CHANGE'
    }

    It 'an IN PROGRESS host does NOT audit as the clean Skipped (a scan would still FAIL the box)' {
        $r = Invoke-C2cRollup @([pscustomobject]@{ Name='MdeOnboard'; Action='onboard'; Result='IN PROGRESS'; Detail='OrgId not yet populated; re-scan in a few minutes' })
        $r.Status | Should Be 'IN PROGRESS'
        $r.Audit  | Should Not Be 'Skipped'
        $r.Audit  | Should Be 'Failure'
    }

    It 'IN PROGRESS alongside a NOCHANGE pillar still rolls up IN PROGRESS (unfinished wins over no-op)' {
        $r = Invoke-C2cRollup @(
            [pscustomobject]@{ Name='MdeOnboard'; Action='onboard'; Result='IN PROGRESS'; Detail='OrgId not yet populated' },
            [pscustomobject]@{ Name='AntiMalware'; Action='none'; Result='NOCHANGE'; Detail='already protected' }
        )
        $r.Status | Should Be 'IN PROGRESS'
    }

    It 'a real FIXED pillar still wins over IN PROGRESS (something DID change)' {
        $r = Invoke-C2cRollup @(
            [pscustomobject]@{ Name='Encryption'; Action='none'; Result='IN PROGRESS'; Detail='D: encrypting' },
            [pscustomobject]@{ Name='Firewall'; Action='enable'; Result='FIXED'; Detail='profiles enabled' }
        )
        $r.Status | Should Be 'FIXED'
    }

    It 'an all-NOCHANGE host still rolls up NO CHANGE (the fix is regression-free)' {
        $r = Invoke-C2cRollup @([pscustomobject]@{ Name='Firewall'; Action='none'; Result='NOCHANGE'; Detail='already enabled' })
        $r.Status | Should Be 'NO CHANGE'
        $r.Audit  | Should Be 'Skipped'
    }

    It 'a PkiRoots REJECTED pillar rolls up FAILED - a refused (ABSENT) anchor is never a clean host' {
        $r = Invoke-C2cRollup @([pscustomobject]@{ Name='PkiRoots'; Action='addstore'; Result='REJECTED'; Detail='refused 1 non-CA cert(s)' })
        $r.Status | Should Be 'FAILED'
        $r.Audit  | Should Be 'Failure'
    }
}
