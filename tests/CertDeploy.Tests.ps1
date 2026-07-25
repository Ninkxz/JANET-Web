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
# Make a throwaway self-signed CA cert (BasicConstraints CA=true); return @{ B64; Thumbprint; Raw }.
# CA=true so it passes the trust-anchor guard (Add-CertDeployBundleToStores refuses a non-CA
# cert in Root/CA) - these tests exercise the additive/re-verify STORE mechanics, not the guard.
function New-TestCert {
    param([string]$Subject = 'CN=CertDeploy-Test')
    $c = New-SelfSignedCertificate -Subject $Subject -CertStoreLocation 'Cert:\CurrentUser\My' -KeyUsage CertSign,CRLSign -TextExtension @('2.5.29.19={text}CA=true') -KeyExportPolicy Exportable -KeyLength 2048 -NotAfter (Get-Date).AddDays(1)
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
            # Shared per-store backing so the v1.1.0 ReadOnly re-verify re-open sees the
            # add (a cert added to Root persists on re-read -> INSTALLED, not NOT VERIFIED).
            # Still additive-only: no Remove method exists, so a remove attempt would throw.
            $rootStore = New-Object System.Collections.ArrayList
            [void]$rootStore.Add([pscustomobject]@{ Thumbprint = $aTp })
            $opener = {
                param($storeName, $mode)
                $o = New-Object psobject
                Add-Member -InputObject $o -MemberType NoteProperty -Name Certificates -Value $rootStore
                Add-Member -InputObject $o -MemberType ScriptMethod -Name Add   -Value { param($cert) [void]$this.Certificates.Add([pscustomobject]@{ Thumbprint = [string]$cert.Thumbprint }) }
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

# loop48 (F1): the CHECK worker parses the wanted thumbprints from JSON on the target and calls
# Get-CertDeployStoreMissing. A null / undeserialized want-set made the reader skip every store group
# (nothing compared) -> 0 present / 0 missing / no Err -> the admin side read ALL PRESENT for a host
# whose stores were NEVER inspected. The reader now fails closed: a want-set with zero usable
# thumbprints returns an Err, which the check worker maps to CHECK ERROR (never ALL PRESENT).
Describe 'CertDeploy check - an undeserialized/empty want-set fails closed to Err, never ALL PRESENT (loop48 F1)' {
    $emptyOpener = { param($s) $o = New-Object psobject; Add-Member -InputObject $o -MemberType NoteProperty -Name Certificates -Value @(); Add-Member -InputObject $o -MemberType ScriptMethod -Name Close -Value { }; $o }
    It 'a $null want-set -> Err (bundle thumbprints did not deserialize; stores not compared)' {
        $miss = & $cm { param($op) Get-CertDeployStoreMissing -WantThumbs $null -StoreOpener $op } $emptyOpener
        ([string]$miss.Err) | Should Match '(?i)want-set empty'
    }
    It 'a want-set with all-empty groups -> Err' {
        $miss = & $cm { param($op) Get-CertDeployStoreMissing -WantThumbs ([pscustomobject]@{ Root=@(); CA=@(); Disallowed=@() }) -StoreOpener $op } $emptyOpener
        ([string]$miss.Err) | Should Match '(?i)want-set empty'
    }
    It 'a want-set with only blank/non-hex thumbprints -> Err (no usable thumbprints)' {
        $miss = & $cm { param($op) Get-CertDeployStoreMissing -WantThumbs ([pscustomobject]@{ Root=@('  ',''); CA=@(); Disallowed=@() }) -StoreOpener $op } $emptyOpener
        ([string]$miss.Err) | Should Match '(?i)want-set empty'
    }
    It 'a REAL want-set does NOT trigger the guard (no Err; the wanted cert reads MISSING from an empty store)' {
        $miss = & $cm { param($op) Get-CertDeployStoreMissing -WantThumbs ([pscustomobject]@{ Root=@('1111111111111111111111111111111111111111'); CA=@(); Disallowed=@() }) -StoreOpener $op } $emptyOpener
        ([string]$miss.Err) | Should Be ''
        (@($miss.MissRoot).Count) | Should Be 1
    }
}

Describe 'certdeploy - manifest version floor (want-set-empty fail-close shipped in 1.4.1; exact pin migrated)' {
    It 'certdeploy is at or past v1.4.1' {
        ([version][string](& $cm { Get-JanetToolManifest }).version -ge [version]'1.4.1') | Should Be $true
    }
}

# loop49 (F2): a wanted trust anchor REFUSED by the non-CA guard (e.g. an X.509 v1 root, no
# BasicConstraints) is absent from the store, yet the classifier ignored the Rejected count and read
# ALREADY ("all present") or INSTALLED (audit Success). Now Get-CertDeployResultToken emits REJECTED
# (out of the clean bucket; row -> REJECTED (non-CA), audit -> Failure), even when other certs added.
Describe 'CertDeploy deploy - a guard-rejected (non-CA) absent anchor is REJECTED, not a clean ALREADY/INSTALLED (loop49 F2)' {
    It 'Rejected > 0 with nothing added -> REJECTED (not ALREADY)' {
        (& $cm { Get-CertDeployResultToken @{ Added=0; Already=2; Total=3; FailDetail=''; NotVerified=@(); Rejected=1 } }) | Should Be 'REJECTED'
    }
    It 'Rejected > 0 alongside real adds -> REJECTED (not a clean INSTALLED)' {
        (& $cm { Get-CertDeployResultToken @{ Added=2; Already=0; Total=3; FailDetail=''; NotVerified=@(); Rejected=1 } }) | Should Be 'REJECTED'
    }
    It 'no rejections -> the honest tokens are unchanged (INSTALLED / ALREADY / NOT VERIFIED / FAIL)' {
        (& $cm { Get-CertDeployResultToken @{ Added=1; Already=0; Total=1; FailDetail=''; NotVerified=@(); Rejected=0 } }) | Should Be 'INSTALLED'
        (& $cm { Get-CertDeployResultToken @{ Added=0; Already=1; Total=1; FailDetail=''; NotVerified=@(); Rejected=0 } }) | Should Be 'ALREADY'
        (& $cm { Get-CertDeployResultToken @{ Added=1; Already=0; Total=1; FailDetail=''; NotVerified=@('AABB'); Rejected=1 } }) | Should Be 'NOT VERIFIED'
        (& $cm { Get-CertDeployResultToken @{ Added=0; Already=0; Total=1; FailDetail='boom'; NotVerified=@(); Rejected=1 } }) | Should Be 'FAIL'
    }
}

Describe 'CertDeploy deploy - the REJECTED token maps to a non-clean row Status + a Failure audit (static)' {
    $src = Get-Content (Join-Path $script:Root 'modules\JanetWeb.certdeploy.psm1') -Raw
    It "the token switch maps 'REJECTED' -> a REJECTED (non-CA) row Status" {
        ($src -match "'REJECTED'\s*\{[^}]*'REJECTED \(non-CA\)'") | Should Be $true
    }
    It "the audit default (Failure) catches 'REJECTED (non-CA)' - it is NOT in the Success/Skipped list" {
        ($src -match "'REJECTED \(non-CA\)' \{'Success'\}") | Should Be $false
    }
}

Describe 'certdeploy - manifest version floor (loop-49 rejected-anchor honesty in 1.4.2; exact pin migrated to newest bump)' {
    It 'certdeploy is at or past v1.4.2' {
        ([version][string](& $cm { Get-JanetToolManifest }).version -ge [version]'1.4.2') | Should Be $true
    }
}

# loop78 (informative-failures theme): the DEPLOY harvest ($emitResult) now, on a host whose
# audit result is Failure (FAILED / NOT VERIFIED / REJECTED), runs the raw error in $detail
# through Get-JanetTroubleshootHint and attaches the hint to a Hint row field + an err log
# (FIX:), the raw detail preserved. Static analysis (the harvest runs inside the fan-out over a
# real RunspacePool - no swappable-worker seam; the hint's behavior is proven behaviorally in
# Troubleshoot.Hint.Tests.ps1).
Describe 'certdeploy 1.4.3 - deploy harvest attaches a troubleshooting hint to a failed host' {
    $man = & $cm { Get-JanetToolManifest }
    $src = Get-Content (Join-Path $script:Root 'modules\JanetWeb.certdeploy.psm1') -Raw

    It 'manifest version is at or past 1.4.3 (deploy-harvest hint; exact pin migrated to newest bump)' {
        ([version][string]$man.version -ge [version]'1.4.3') | Should Be $true
    }
    It 'certdeploy imports the shared troubleshoot engine' {
        ($src -match 'Import-Module.*JanetWeb\.troubleshoot\.psm1') | Should Be $true
    }
    It 'the deploy harvest computes a hint only for a Failure host and attaches it to the row' {
        ($src -match '\$hint\s*=\s*if\s*\(\$auditResult\s*-eq\s*''Failure''\s*-and\s*\$detail\)\s*\{\s*Get-JanetTroubleshootHint') | Should Be $true
        ($src -match 'Detail=\$detail;\s*Hint=\[string\]\$hint') | Should Be $true
    }
    It 'the deploy err log carries the FIX hint when one exists (raw detail preserved)' {
        ($src -match "if \(\`$hint\) \{ &\s*\`$send @\{ type='log'; level='err'") | Should Be $true
        ($src -match 'FIX: \$hint')                                              | Should Be $true
    }
}

# loop81 (informative-failures follow-up): the two READ-ONLY paths - the cert CHECK harvest and the
# scan-cert-management reconciler harvest - now, on a host-level CHECK ERROR (raw probe/session/DNS error in
# Detail), run it through Get-JanetTroubleshootHint and attach a Hint row field + a FIX: err log, raw detail
# preserved. ALL PRESENT/MISSING/OFFLINE (check) and the reconciler verdicts/OFFLINE (scan) self-explain, so
# the hint is scoped to CHECK ERROR. Static analysis (both harvests run inside a fan-out over a real RunspacePool).
Describe 'certdeploy 1.4.4 - read-only check + scan harvests attach a hint to a CHECK ERROR host' {
    $man = & $cm { Get-JanetToolManifest }
    $src = Get-Content (Join-Path $script:Root 'modules\JanetWeb.certdeploy.psm1') -Raw

    # audit 2026-07-24: the exact pin moved to the newest bump test
    # (CertDeploy.DisallowedGate.Tests.ps1, v1.5.0) - this one keeps a floor so the
    # 1.4.4 hint behaviour stays pinned without re-breaking on every later bump.
    It 'manifest version is at or past 1.4.4 (floor; exact pin lives in the newest bump test)' {
        ([version][string]$man.version -ge [version]'1.4.4') | Should Be $true
    }
    It 'the check harvest computes a hint only for a CHECK ERROR status and attaches it to the row' {
        ($src -match '\$hint\s*=\s*if\s*\(\$status\s*-eq\s*''CHECK ERROR''\s*-and\s*\$row\.Detail\)\s*\{\s*Get-JanetTroubleshootHint') | Should Be $true
    }
    It 'the scan harvest computes a hint only for a CHECK ERROR reconciler verdict and attaches it to the row' {
        ($src -match '\$hint\s*=\s*if\s*\(\$rec\s*-eq\s*''CHECK ERROR''\s*-and\s*\$row\.Detail\)\s*\{\s*Get-JanetTroubleshootHint') | Should Be $true
    }
    It 'both read-only harvests mutate the row Hint and emit a gated FIX err log' {
        # the $row['Hint'] mutation form is unique to the read-only harvests (deploy uses a row literal) -> 2
        ([regex]::Matches($src, "if \(\`$hint\) \{ \`$row\['Hint'\] = \[string\]\`$hint \}").Count) | Should Be 2
        # the row-based err log ($row.Host, not deploy's $res.Host) -> exactly the two read-only paths
        ([regex]::Matches($src, "level='err'; text=`"\`$\(\[string\]\`$row\.Host\).*FIX: \`$hint").Count) | Should Be 2
    }
}
