# =============================================================================
#  CertDeploy.Tests.ps1 - Pester 3.4 tests for the Cert Deploy tool
#  (modules\JanetWeb.certdeploy.psm1). Mirrors the C2c cert test shim idiom
#  (tests\C2c.CertsAndVersion.Tests.ps1): a throwaway self-signed cert + an
#  INJECTED fake X509Store, so NO real cert-store write and NO WinRM call ever
#  leaves this box.
#
#  Coverage:
#    (a) check   - a host missing 2 of N roots -> Status MISSING 2; a fully
#                  present host -> ALL PRESENT (Get-CertDeployStoreMissing with a
#                  fake ReadOnly store + the pure Get-CertDeployCheckRow builder).
#    (b) deploy  - the additive installer adds only-missing by thumbprint and
#                  NEVER calls a remove.
#    (c) deploy  - confirm-word rejection (not "DEPLOY" -> refused, nothing dialed)
#                  + self-guard drops the dispatcher host.
#    (d) import  - a CSV with Compliant+AuditPKI, NonCompliant+AuditPKI+FailedVuln,
#                  and a NO-pki host -> returns EXACTLY the PKI-tagged ones (both
#                  compliant and non-compliant), excludes the non-pki host.
#    (e) manifest- check(false)/deploy(true)/import-pki-hosts(false) with the right
#                  destructive flags + the bundle default resolves to Packages\DoD-Certs.
#
#  Run:  Invoke-Pester -Path .\tests\CertDeploy.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$cm = Import-Module (Join-Path $script:Root 'modules\JanetWeb.certdeploy.psm1') -Force -PassThru

# --- helpers ---------------------------------------------------------------
# Make a throwaway self-signed cert; return @{ B64; Thumbprint; Raw }.
function New-TestCert {
    param([string]$Subject = 'CN=CertDeploy-Test')
    $c = New-SelfSignedCertificate -Subject $Subject -CertStoreLocation 'Cert:\CurrentUser\My' -KeyExportPolicy Exportable -KeyLength 2048 -NotAfter (Get-Date).AddDays(1)
    $raw = $c.RawData
    $tp  = [string]$c.Thumbprint
    Remove-Item ("Cert:\CurrentUser\My\{0}" -f $tp) -Force -ErrorAction SilentlyContinue
    return @{ B64 = [Convert]::ToBase64String($raw); Thumbprint = $tp; Raw = $raw }
}

function New-CertDeployTempCsv {
    param([string]$Content)
    $p = Join-Path ([System.IO.Path]::GetTempPath()) ("certdeploy_test_{0}.csv" -f ([guid]::NewGuid().ToString('N')))
    Set-Content -LiteralPath $p -Value $Content -Encoding UTF8
    return $p
}

# Collect emitted 'row' events + return the action result.
function Invoke-CertDeployAction {
    param([string]$ActionId, [hashtable]$Params, $Cred = $null)
    $script:__rows = New-Object System.Collections.ArrayList
    $emit = { param($e) if ($e -and $e.type -eq 'row') { [void]$script:__rows.Add($e) } }
    $res = Invoke-JanetToolAction -ActionId $ActionId -Params $Params -Credential $Cred -Emit $emit
    [pscustomobject]@{ Result = $res; Rows = @($script:__rows) }
}

# =============================================================================
Describe 'CertDeploy check - missing computation + Status (ALL PRESENT / MISSING N)' {

    # (a) A host that has only 1 of 3 root thumbprints -> 2 missing -> MISSING 2.
    It 'a host missing 2 of 3 roots -> Get-CertDeployStoreMissing reports 2 missing and Get-CertDeployCheckRow -> Status MISSING 2' {
        $a = New-TestCert 'CN=Present1'
        $b = New-TestCert 'CN=Missing1'
        $c = New-TestCert 'CN=Missing2'
        $row = & $cm {
            param($aTp, $bTp, $cTp)
            # Want all three in Root; the fake store only HAS cert A -> B + C are missing.
            $want = [pscustomobject]@{ Root = @($aTp, $bTp, $cTp); CA = @(); Disallowed = @() }
            $opener = {
                param($storeName)
                $o = New-Object psobject
                $existing = @()
                if ($storeName -eq 'Root') { $existing = @([pscustomobject]@{ Thumbprint = $aTp }) }
                Add-Member -InputObject $o -MemberType NoteProperty -Name Certificates -Value $existing
                Add-Member -InputObject $o -MemberType ScriptMethod -Name Close -Value { }
                return $o
            }.GetNewClosure()
            $miss = Get-CertDeployStoreMissing -WantThumbs $want -StoreOpener $opener
            # feed the worker-shaped result into the pure row builder (Ok=$true).
            $res = @{ Host='WS-1'; Ping='TCP 5985'; Ok=$true; MissRoot=@($miss.MissRoot); MissCA=@($miss.MissCA); MissDis=@($miss.MissDis); PresRoot=[int]$miss.PresRoot; PresCA=0; PresDis=0 }
            $r = Get-CertDeployCheckRow -Res $res -BundleCertCount 3 -SubjectMap @{}
            [pscustomobject]@{ MissCount = (@($miss.MissRoot).Count); Pres = [int]$miss.PresRoot; Status = [string]$r.Status; Missing = [string]$r.Missing }
        } $a.Thumbprint $b.Thumbprint $c.Thumbprint
        $row.MissCount | Should Be 2
        $row.Pres      | Should Be 1
        $row.Status    | Should Be 'MISSING 2'
        $row.Missing   | Should Be '2'
    }

    It 'a fully present host -> 0 missing -> Status ALL PRESENT' {
        $a = New-TestCert 'CN=Pres1'
        $b = New-TestCert 'CN=Pres2'
        $row = & $cm {
            param($aTp, $bTp)
            $want = [pscustomobject]@{ Root = @($aTp, $bTp); CA = @(); Disallowed = @() }
            $opener = {
                param($storeName)
                $o = New-Object psobject
                $existing = @([pscustomobject]@{ Thumbprint = $aTp }, [pscustomobject]@{ Thumbprint = $bTp })
                Add-Member -InputObject $o -MemberType NoteProperty -Name Certificates -Value $existing
                Add-Member -InputObject $o -MemberType ScriptMethod -Name Close -Value { }
                return $o
            }.GetNewClosure()
            $miss = Get-CertDeployStoreMissing -WantThumbs $want -StoreOpener $opener
            $res = @{ Host='WS-2'; Ping='TCP 5985'; Ok=$true; MissRoot=@($miss.MissRoot); MissCA=@(); MissDis=@(); PresRoot=[int]$miss.PresRoot; PresCA=0; PresDis=0 }
            $r = Get-CertDeployCheckRow -Res $res -BundleCertCount 2 -SubjectMap @{}
            [pscustomobject]@{ MissCount = (@($miss.MissRoot).Count); Status = [string]$r.Status; Missing = [string]$r.Missing }
        } $a.Thumbprint $b.Thumbprint
        $row.MissCount | Should Be 0
        $row.Status    | Should Be 'ALL PRESENT'
    }
}

# =============================================================================
Describe 'CertDeploy deploy - Add-CertDeployBundleToStores is ADDITIVE (adds only-missing, never removes)' {

    # (b) adds ONLY the not-yet-present cert; a store with no Remove method proves
    #     nothing is removed (a removal attempt would throw a missing-method error).
    It 'adds ONLY the missing cert by thumbprint, leaves the present one, and never calls Remove' {
        $a = New-TestCert 'CN=AlreadyPresent'
        $b = New-TestCert 'CN=Missing'
        $r = & $cm {
            param($aTp, $aB64, $bTp, $bB64)
            $bundle = [pscustomobject]@{
                Root       = @([pscustomobject]@{ t=$aTp; b=$aB64 }, [pscustomobject]@{ t=$bTp; b=$bB64 })
                CA         = @()
                Disallowed = @()
            }
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
            $res = Add-CertDeployBundleToStores -Bundle $bundle -StoreOpener $opener
            $tok = Get-CertDeployResultToken $res
            [pscustomobject]@{ Added=$res.Added; Already=$res.Already; Total=$res.Total; Token=$tok }
        } $a.Thumbprint $a.B64 $b.Thumbprint $b.B64
        $r.Total   | Should Be 2
        $r.Added   | Should Be 1    # only the missing cert B was added
        $r.Already | Should Be 1    # cert A already present, left alone
        $r.Token   | Should Be 'INSTALLED'
    }

    It 'reports ALREADY (Added=0) when every cert is present, and Add is NEVER called (would throw)' {
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
            $res = Add-CertDeployBundleToStores -Bundle $bundle -StoreOpener $opener
            [pscustomobject]@{ Added=$res.Added; Already=$res.Already; Fail=[string]$res.FailDetail; Token=(Get-CertDeployResultToken $res) }
        } $a.Thumbprint $a.B64
        $r.Added   | Should Be 0
        $r.Already | Should Be 1
        $r.Fail    | Should Be ''
        $r.Token   | Should Be 'ALREADY'
    }
}

# =============================================================================
Describe 'CertDeploy deploy - confirm-word gate + self-guard' {

    # (c) confirm-word rejection: not "DEPLOY" -> refused, nothing dialed, no rows.
    It 'REJECTS the run when the confirm word is not exactly DEPLOY (nothing dialed)' {
        $out = Invoke-CertDeployAction -ActionId 'deploy' -Params @{ targets = 'WS-0001'; confirm = 'nope'; certBundleFolder = 'X:\whatever' }
        $out.Result.summary.rejected | Should Be $true
        @($out.Rows).Count | Should Be 0
    }

    It 'REJECTS a lower-case "deploy" (case-sensitive, exact word) before any bundle read' {
        $out = Invoke-CertDeployAction -ActionId 'deploy' -Params @{ targets = 'WS-0001'; confirm = 'deploy'; certBundleFolder = 'X:\whatever' }
        $out.Result.summary.rejected | Should Be $true
        @($out.Rows).Count | Should Be 0
    }

    # self-guard drops the dispatcher host with a SKIPPED row and never fans out.
    It 'self-guard drops the dispatcher/local host (SKIPPED row, zero fan-out)' {
        # Only dispatcher-local targets -> after the self-guard drop there is nothing
        # to dial. A real shipped bundle lets the confirm + bundle read pass; if the
        # shipped default is absent the run aborts before the self-guard (tolerated).
        $defOk = & $cm { $p = Get-CertDeployDefaultBundlePath; [bool]((Test-Path -LiteralPath $p) -and (@(Get-ChildItem -LiteralPath $p -Filter '*.cer' -File -Recurse -ErrorAction SilentlyContinue).Count -gt 0)) }
        $out = Invoke-CertDeployAction -ActionId 'deploy' -Params @{
            targets = ("{0}`n127.0.0.1`nlocalhost" -f $env:COMPUTERNAME)
            confirm = 'DEPLOY'
            certBundleFolder = ''
        }
        if ($defOk) {
            $skips = @($out.Rows | Where-Object { $_.Status -eq 'SKIPPED' })
            $skips.Count | Should Not Be 0
            ($skips[0].Detail) | Should Match 'self-guard'
            $out.Result.summary.selfSkipped | Should Not Be 0
            $out.Result.summary.total | Should Be 0
        } else {
            # no shipped bundle to read -> abort-with-clear-error before the self-guard.
            $out.Result.summary.rejected | Should Be $true
        }
    }
}

# =============================================================================
Describe 'CertDeploy import-pki-hosts - returns every PKI-tagged host (compliant AND non-compliant), excludes non-pki' {

    # (d) HOSTA = Compliant + Audit PKI Trust Roots        -> PKI-tagged (compliant)
    #     HOSTB = Non-Compliant + Audit PKI + Failed Vuln  -> PKI-tagged (non-compliant)
    #     HOSTC = Non-Compliant + Failed Vulnerability only -> NOT pki-tagged (excluded)
    #     HOSTD = Non-Compliant + Failed Rule - PKI Trust Roots -> PKI-tagged via FAILED
    $csvBody = @"
C2C Compliance Status:Compliance,C2C Compliance Status:Date,Computer Name,Count
"Compliant
Audit Rule - PKI Trust Roots",,HOSTA.area52.afnoapps.usaf.mil,1
"Non-Compliant
Audit Rule 2 - PKI Trust Roots
Failed Rule - Vulnerability Compliance",,HOSTB.area52.afnoapps.usaf.mil,1
"Non-Compliant
Failed Rule - Vulnerability Compliance",,HOSTC.area52.afnoapps.usaf.mil,1
"Non-Compliant
Failed Rule 4 - PKI Trust Roots",,HOSTD.area52.afnoapps.usaf.mil,1
"@
    $csv = New-CertDeployTempCsv $csvBody
    $out = Invoke-CertDeployAction -ActionId 'import-pki-hosts' -Params @{ csvPath = $csv }
    $summary = $out.Result.summary
    $hosts   = @($summary.hosts)

    It 'includes the COMPLIANT host that carries an Audit PKI tag (HOSTA)' {
        ($hosts -contains 'HOSTA') | Should Be $true
    }
    It 'includes the NON-COMPLIANT host that carries an Audit PKI tag (HOSTB)' {
        ($hosts -contains 'HOSTB') | Should Be $true
    }
    It 'includes the NON-COMPLIANT host that FAILS PKI Trust Roots (HOSTD)' {
        ($hosts -contains 'HOSTD') | Should Be $true
    }
    It 'EXCLUDES the host with no PKI tag at all (HOSTC)' {
        ($hosts -contains 'HOSTC') | Should Be $false
    }
    It 'summary counts exactly the 3 PKI-tagged hosts of 4 parsed' {
        $summary.total     | Should Be 4
        $summary.pkiTagged | Should Be 3
        @($hosts).Count    | Should Be 3
    }
    It 'streams one row per PKI-tagged host (for the view to load into targets)' {
        @($out.Rows).Count | Should Be 3
    }

    Remove-Item -LiteralPath $csv -Force -ErrorAction SilentlyContinue
}

# =============================================================================
Describe 'CertDeploy manifest - actions + destructive flags + bundle default' {

    $man = & $cm { Get-JanetToolManifest }

    It 'exposes id certdeploy, name Cert Deploy, category Hardening' {
        $man.id       | Should Be 'certdeploy'
        $man.name     | Should Be 'Cert Deploy'
        $man.category | Should Be 'Hardening'
    }

    It '(e) check is destructive=$false' {
        $a = @($man.actions | Where-Object { $_.id -eq 'check' })[0]
        $a | Should Not BeNullOrEmpty
        [bool]$a.destructive | Should Be $false
    }
    It '(e) deploy is destructive=$true (admin-session gated) with a confirm prompt' {
        $a = @($man.actions | Where-Object { $_.id -eq 'deploy' })[0]
        $a | Should Not BeNullOrEmpty
        [bool]$a.destructive | Should Be $true
        [string]$a.confirm   | Should Not Be ''
    }
    It '(e) import-pki-hosts is destructive=$false' {
        $a = @($man.actions | Where-Object { $_.id -eq 'import-pki-hosts' })[0]
        $a | Should Not BeNullOrEmpty
        [bool]$a.destructive | Should Be $false
    }
    It '(e) the bundle default resolves to Packages\DoD-Certs' {
        $p = & $cm { Get-CertDeployDefaultBundlePath }
        $p | Should Match '(?i)Packages[\\/]+DoD-Certs$'
    }
    It 'check + deploy expose a certBundleFolder input; import exposes a csvPath file input' {
        $chk = @($man.actions | Where-Object { $_.id -eq 'check' })[0]
        @($chk.inputs | Where-Object { $_.name -eq 'certBundleFolder' }).Count | Should Be 1
        $dep = @($man.actions | Where-Object { $_.id -eq 'deploy' })[0]
        @($dep.inputs | Where-Object { $_.name -eq 'certBundleFolder' }).Count | Should Be 1
        $imp = @($man.actions | Where-Object { $_.id -eq 'import-pki-hosts' })[0]
        @($imp.inputs | Where-Object { $_.name -eq 'csvPath' -and $_.type -eq 'file' }).Count | Should Be 1
    }
}
