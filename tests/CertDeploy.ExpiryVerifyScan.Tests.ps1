# =============================================================================
#  CertDeploy.ExpiryVerifyScan.Tests.ps1 - Pester tests for the v1.1.0 additions
#  to the Cert Deploy tool (modules\JanetWeb.certdeploy.psm1). Mirrors the
#  CertDeploy.Tests.ps1 shim idiom: a throwaway self-signed cert + an INJECTED
#  fake X509Store, so NO real cert-store write and NO WinRM call ever leaves this
#  box. All remote-only paths are exercised through the pure admin-side helpers.
#
#  Coverage:
#    (a) expiry   - a temp bundle with 1 expired + 1 valid .cer -> Get-CertDeployBundle
#                   reports ExpiredCount=1; Convert-CertDeployBundleToJson EXCLUDES the
#                   expired thumbprint when includeExpired=$false and INCLUDES it =$true.
#    (b) verify   - Add-CertDeployBundleToStores re-verify populates Verified/NotVerified:
#                   a persisting fake store -> Verified, empty NotVerified; a stripping
#                   fake store -> NotVerified populated (added-but-absent on re-read).
#    (c) token    - Get-CertDeployResultToken returns NOT VERIFIED when NotVerified is
#                   non-empty (FailDetail still wins as FAIL).
#    (d) scan     - the scan-cert-management manifest action exists with the EXACT
#                   columns/inputs, and Get-CertDeployReconcilerVerdict returns the right
#                   verdict for the InstallRoot yes/no x GPRoots >0/0 combinations.
#
#  Run:  Invoke-Pester -Path .\tests\CertDeploy.ExpiryVerifyScan.Tests.ps1
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

function Get-NormTp { param([string]$T) return (([string]$T) -replace '[^0-9A-Fa-f]','') }

# =============================================================================
Describe 'CertDeploy expiry guard - Get-CertDeployBundle census + Convert...ToJson filtering' {

    # (a) a temp bundle: root\valid.cer (NotAfter +30d) + root\expired.cer (NotAfter -1d).
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("certdeploy_exp_{0}" -f ([guid]::NewGuid().ToString('N')))
    $rootDir = Join-Path $tmp 'root'
    New-Item -ItemType Directory -Path $rootDir -Force | Out-Null

    $valid   = New-SelfSignedCertificate -Subject 'CN=CertDeploy-Valid'   -CertStoreLocation 'Cert:\CurrentUser\My' -KeyLength 2048 -NotAfter (Get-Date).AddDays(30)
    $expired = New-SelfSignedCertificate -Subject 'CN=CertDeploy-Expired' -CertStoreLocation 'Cert:\CurrentUser\My' -KeyLength 2048 -NotBefore (Get-Date).AddDays(-10) -NotAfter (Get-Date).AddDays(-1)
    $validTp = [string]$valid.Thumbprint
    $expTp   = [string]$expired.Thumbprint
    [System.IO.File]::WriteAllBytes((Join-Path $rootDir 'valid.cer'),   $valid.RawData)
    [System.IO.File]::WriteAllBytes((Join-Path $rootDir 'expired.cer'), $expired.RawData)
    Remove-Item ("Cert:\CurrentUser\My\{0}" -f $validTp) -Force -ErrorAction SilentlyContinue
    Remove-Item ("Cert:\CurrentUser\My\{0}" -f $expTp)   -Force -ErrorAction SilentlyContinue

    $bundle = & $cm { param($f) Get-CertDeployBundle -Folder $f } $tmp

    It 'reads both certs (CertCount=2) and reports ExpiredCount=1 with the expired thumbprint in Expired[]' {
        [bool]$bundle.Ok        | Should Be $true
        [int]$bundle.CertCount  | Should Be 2
        [int]$bundle.ExpiredCount | Should Be 1
        $expNorm = Get-NormTp $expTp
        (@($bundle.Expired | ForEach-Object { Get-NormTp $_.Thumbprint }) -contains $expNorm) | Should Be $true
    }
    It 'the Expired[] entry carries Subject + an ISO-8601 NotAfter + Store per contract' {
        $e = @($bundle.Expired)[0]
        ([string]$e.Subject) | Should Match 'CertDeploy-Expired'
        ([string]$e.Store)   | Should Be 'Root'
        # ISO 8601 round-trip 'o' format parses back to a DateTime in the past.
        ([datetime]([string]$e.NotAfter) -lt (Get-Date)) | Should Be $true
    }
    It 'Convert-CertDeployBundleToJson EXCLUDES the expired thumbprint when includeExpired=$false' {
        $json = & $cm { param($b) Convert-CertDeployBundleToJson $b $false } $bundle
        $o = $json | ConvertFrom-Json
        $tps = @(@($o.Root) | ForEach-Object { Get-NormTp $_.t })
        ($tps -contains (Get-NormTp $validTp)) | Should Be $true
        ($tps -contains (Get-NormTp $expTp))   | Should Be $false
        @($tps).Count | Should Be 1
    }
    It 'Convert-CertDeployBundleToJson INCLUDES the expired thumbprint when includeExpired=$true' {
        $json = & $cm { param($b) Convert-CertDeployBundleToJson $b $true } $bundle
        $o = $json | ConvertFrom-Json
        $tps = @(@($o.Root) | ForEach-Object { Get-NormTp $_.t })
        ($tps -contains (Get-NormTp $expTp)) | Should Be $true
        @($tps).Count | Should Be 2
    }

    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

# =============================================================================
Describe 'CertDeploy persistence re-verify - Add-CertDeployBundleToStores populates Verified/NotVerified' {

    # (b) persisting store: the ReadOnly re-read sees the added cert -> Verified, no NotVerified.
    It 'a persisting store -> Verified=1, NotVerified empty, token INSTALLED' {
        $b = New-TestCert 'CN=Persist'
        $r = & $cm {
            param($bTp, $bB64)
            $bundle  = [pscustomobject]@{ Root=@([pscustomobject]@{ t=$bTp; b=$bB64 }); CA=@(); Disallowed=@() }
            $backing = New-Object System.Collections.ArrayList
            $opener  = {
                param($storeName, $mode)
                $o = New-Object psobject
                Add-Member -InputObject $o -MemberType NoteProperty -Name Certificates -Value $backing
                Add-Member -InputObject $o -MemberType ScriptMethod -Name Add   -Value { param($cert) [void]$this.Certificates.Add([pscustomobject]@{ Thumbprint = [string]$cert.Thumbprint }) }
                Add-Member -InputObject $o -MemberType ScriptMethod -Name Close -Value { }
                return $o
            }.GetNewClosure()
            $res = Add-CertDeployBundleToStores -Bundle $bundle -StoreOpener $opener
            [pscustomobject]@{ Added=[int]$res.Added; Verified=[int]$res.Verified; NV=@($res.NotVerified).Count; Fail=[string]$res.FailDetail; Token=(Get-CertDeployResultToken $res) }
        } $b.Thumbprint $b.B64
        $r.Added    | Should Be 1
        $r.Verified | Should Be 1
        $r.NV       | Should Be 0
        $r.Fail     | Should Be ''
        $r.Token    | Should Be 'INSTALLED'
    }

    # (b) stripping store: the ReadWrite handle takes the Add, but the ReadOnly re-read
    #     returns an empty view (a reconciler stripped it in-session) -> NotVerified.
    It 'a stripping store -> NotVerified populated (added but absent on re-read), token NOT VERIFIED' {
        $b = New-TestCert 'CN=Stripped'
        $r = & $cm {
            param($bTp, $bB64)
            $bundle    = [pscustomobject]@{ Root=@([pscustomobject]@{ t=$bTp; b=$bB64 }); CA=@(); Disallowed=@() }
            $writeSink = New-Object System.Collections.ArrayList
            $readView  = New-Object System.Collections.ArrayList   # stays empty on the ReadOnly re-read
            $opener    = {
                param($storeName, $mode)
                $o = New-Object psobject
                if ($mode -eq 'ReadOnly') {
                    Add-Member -InputObject $o -MemberType NoteProperty -Name Certificates -Value $readView
                } else {
                    Add-Member -InputObject $o -MemberType NoteProperty -Name Certificates -Value $writeSink
                }
                Add-Member -InputObject $o -MemberType ScriptMethod -Name Add   -Value { param($cert) [void]$this.Certificates.Add([pscustomobject]@{ Thumbprint = [string]$cert.Thumbprint }) }
                Add-Member -InputObject $o -MemberType ScriptMethod -Name Close -Value { }
                return $o
            }.GetNewClosure()
            $res = Add-CertDeployBundleToStores -Bundle $bundle -StoreOpener $opener
            [pscustomobject]@{ Added=[int]$res.Added; Verified=[int]$res.Verified; NV=@($res.NotVerified).Count; Fail=[string]$res.FailDetail; Token=(Get-CertDeployResultToken $res) }
        } $b.Thumbprint $b.B64
        $r.Added    | Should Be 1
        $r.Verified | Should Be 0
        $r.NV       | Should Be 1
        $r.Fail     | Should Be ''
        $r.Token    | Should Be 'NOT VERIFIED'
    }
}

# =============================================================================
Describe 'CertDeploy Get-CertDeployResultToken - NOT VERIFIED classification' {

    # (c) NotVerified non-empty (FailDetail empty) -> NOT VERIFIED.
    It 'returns NOT VERIFIED when NotVerified is non-empty and FailDetail is empty' {
        $t = & $cm { Get-CertDeployResultToken @{ Added=1; Already=0; Total=1; FailDetail=''; Verified=0; NotVerified=@('AABBCCDD') } }
        $t | Should Be 'NOT VERIFIED'
    }
    It 'returns INSTALLED when adds succeeded and NotVerified is empty' {
        $t = & $cm { Get-CertDeployResultToken @{ Added=1; Already=0; Total=1; FailDetail=''; Verified=1; NotVerified=@() } }
        $t | Should Be 'INSTALLED'
    }
    It 'returns ALREADY when nothing added and NotVerified is empty' {
        $t = & $cm { Get-CertDeployResultToken @{ Added=0; Already=1; Total=1; FailDetail=''; Verified=1; NotVerified=@() } }
        $t | Should Be 'ALREADY'
    }
    It 'FailDetail still wins as FAIL even when NotVerified is non-empty' {
        $t = & $cm { Get-CertDeployResultToken @{ Added=0; Already=0; Total=1; FailDetail='boom'; Verified=0; NotVerified=@('X') } }
        $t | Should Be 'FAIL'
    }
}

# =============================================================================
Describe 'CertDeploy scan-cert-management - manifest action + reconciler verdict' {

    $man  = & $cm { Get-JanetToolManifest }
    $scan = @($man.actions | Where-Object { $_.id -eq 'scan-cert-management' })[0]

    It 'manifest version is bumped to 1.1.0' {
        $man.version | Should Be '1.1.0'
    }
    It '(d) exposes the scan-cert-management action (read-only, correct label + kind)' {
        $scan | Should Not BeNullOrEmpty
        [bool]$scan.destructive | Should Be $false
        $scan.label | Should Be 'SCAN CERT MANAGEMENT (what manages trust)'
        $scan.kind  | Should Be 'stream-table'
    }
    It '(d) has the exact columns Host,Ping,InstallRoot,GPRoots,Reconciler,Detail' {
        (@($scan.columns) -join ',') | Should Be 'Host,Ping,InstallRoot,GPRoots,Reconciler,Detail'
    }
    It '(d) exposes targets(hostlist,required) + attemptOffline(bool,default false) + threads(int,default 16)' {
        $t = @($scan.inputs | Where-Object { $_.name -eq 'targets' })[0]
        $t.type | Should Be 'hostlist'
        [bool]$t.required | Should Be $true
        $ao = @($scan.inputs | Where-Object { $_.name -eq 'attemptOffline' })[0]
        $ao.type | Should Be 'bool'
        [bool]$ao.default | Should Be $false
        $th = @($scan.inputs | Where-Object { $_.name -eq 'threads' })[0]
        $th.type | Should Be 'int'
        [int]$th.default | Should Be 16
    }

    # (d) the pure verdict helper across the InstallRoot yes/no x GPRoots >0/0 grid.
    It 'reconciler verdict: InstallRoot yes + GPRoots 0 -> InstallRoot' {
        (& $cm { Get-CertDeployReconcilerVerdict -InstallRoot $true -GpRoots 0 }) | Should Be 'InstallRoot'
    }
    It 'reconciler verdict: InstallRoot yes + GPRoots 3 -> InstallRoot+GPO' {
        (& $cm { Get-CertDeployReconcilerVerdict -InstallRoot $true -GpRoots 3 }) | Should Be 'InstallRoot+GPO'
    }
    It 'reconciler verdict: InstallRoot no + GPRoots 3 -> GPO' {
        (& $cm { Get-CertDeployReconcilerVerdict -InstallRoot $false -GpRoots 3 }) | Should Be 'GPO'
    }
    It 'reconciler verdict: InstallRoot no + GPRoots 0 -> None detected' {
        (& $cm { Get-CertDeployReconcilerVerdict -InstallRoot $false -GpRoots 0 }) | Should Be 'None detected'
    }

    It 'Get-CertDeployScanRow: None detected row notes a manual .Default push WILL persist' {
        $row = & $cm { Get-CertDeployScanRow -Res @{ Host='WS-1'; Ping='TCP 5985'; Ok=$true; InstallRootPresent=$false; InstallRootToken='no'; GpRoots=0; DefaultRootCount=120 } }
        $row.Reconciler | Should Be 'None detected'
        [string]$row.Detail | Should Match 'WILL persist'
    }
    It 'Get-CertDeployScanRow: a reconciler-present row warns a scripted push may be pruned on reboot' {
        $row = & $cm { Get-CertDeployScanRow -Res @{ Host='WS-2'; Ping='TCP 5985'; Ok=$true; InstallRootPresent=$true; InstallRootToken='yes (v5.5, task)'; GpRoots=0; DefaultRootCount=130 } }
        $row.Reconciler  | Should Be 'InstallRoot'
        $row.InstallRoot | Should Be 'yes (v5.5, task)'
        [string]$row.Detail | Should Match 'pruned on reboot'
    }
    It 'Get-CertDeployScanRow: an OFFLINE worker result passes through as the OFFLINE reconciler cell' {
        $row = & $cm { Get-CertDeployScanRow -Res @{ Host='WS-3'; Ping='Unreachable'; Ok=$false; Status='OFFLINE'; Detail='no tcp' } }
        $row.Reconciler | Should Be 'OFFLINE'
    }
}
