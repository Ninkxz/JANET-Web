# =============================================================================
#  CertDeploy.DisallowedGate.Tests.ps1 - Pester 3.4 tests for the audit 2026-07-24
#  fixes in modules\JanetWeb.certdeploy.psm1.
#
#  Mirrors the CertDeploy.Tests.ps1 / CaValidation shim idiom: throwaway self-signed
#  certs built OFFLINE + an INJECTED fake X509Store, and only the pure admin-side
#  helpers / early-abort action paths - so NO real cert-store write and NO WinRM call
#  ever leaves this box.
#
#  Coverage:
#    (1) [P2] Disallowed (DISTRUST) gate - the Untrusted\ -> LocalMachine\Disallowed push
#        BLACKLISTS certs fleet-wide, which the manifest/arming text used to hide behind
#        "never removes anything". It is now an explicit, default-OFF opt-in:
#          (1a) the deploy manifest exposes pushDisallowed (bool, default $false) and the
#               description + confirm word name the blacklist/DISTRUST;
#          (1b) Convert-CertDeployBundleToJson OMITS the Disallowed group unless the third
#               arg arms it (fail-closed - the worker is never even handed the certs);
#          (1c) Invoke-CertDeployDeployAction refuses to dial a Disallowed-only bundle when
#               the gate is off (push set EMPTY) and reports disallowedExcluded.
#    (2) [P2] honest labelling - Add-CertDeployBundleToStores reports anchor adds and
#        blacklist adds SEPARATELY (AddedAnchors / AddedDistrust) so the row detail can no
#        longer label a Disallowed (distrust) entry "| trusted:".
#    (3) [P3] expired-badge contract - the deploy/check summaries carry the LOWERCASE
#        expiredCount plus expiredSubjects (the view read ExpiredCount / Expired, which no
#        summary ever returned, so the badge was permanently inert).
#    (4) [P4] a cancelled scan-cert-management host reads Cancelled, not CHECK ERROR.
#
#  Run:  Invoke-Pester -Path .\tests\CertDeploy.DisallowedGate.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$cm = Import-Module (Join-Path $script:Root 'modules\JanetWeb.certdeploy.psm1') -Force -PassThru

# --- helpers ---------------------------------------------------------------
# A throwaway self-signed CA cert (BasicConstraints CA=true so it passes the trust-anchor
# guard); returns @{ B64; Thumbprint; Raw }. Never left in a store.
function New-GateCaCert {
    param([string]$Subject = 'CN=CertDeploy-Gate-CA', [datetime]$NotAfter = (Get-Date).AddDays(30))
    $c = New-SelfSignedCertificate -Subject $Subject -CertStoreLocation 'Cert:\CurrentUser\My' -KeyUsage CertSign,CRLSign -TextExtension @('2.5.29.19={text}CA=true') -KeyExportPolicy Exportable -KeyLength 2048 -NotAfter $NotAfter
    $raw = $c.RawData; $tp = [string]$c.Thumbprint
    Remove-Item ("Cert:\CurrentUser\My\{0}" -f $tp) -Force -ErrorAction SilentlyContinue
    return @{ B64 = [Convert]::ToBase64String($raw); Thumbprint = $tp; Raw = $raw }
}
function Get-GateNormTp { param([string]$T) return (([string]$T) -replace '[^0-9A-Fa-f]','') }

# The same injectable fake X509Store the other CertDeploy suites use: Add appends a
# { Thumbprint } stub to an ArrayList; the ReadOnly re-verify re-opens the SAME list.
$script:GateOpenerSrc = {
    param($Backing)
    {
        param($storeName, $mode)
        $o = New-Object psobject
        Add-Member -InputObject $o -MemberType NoteProperty -Name Certificates -Value $Backing
        Add-Member -InputObject $o -MemberType ScriptMethod -Name Add   -Value { param($cert) [void]$this.Certificates.Add([pscustomobject]@{ Thumbprint = [string]$cert.Thumbprint }) }
        Add-Member -InputObject $o -MemberType ScriptMethod -Name Close -Value { }
        return $o
    }.GetNewClosure()
}

# =============================================================================
Describe 'CertDeploy (1a) manifest - the Disallowed blacklist push is an explicit opt-in' {

    $man = & $cm { Get-JanetToolManifest }
    $dep = @($man.actions | Where-Object { $_.id -eq 'deploy' })[0]

    # Newest bump test -> it holds the EXACT pin (the older suites keep floors); bump the
    # manifest and this line together.
    # audit 2026-07-25 (fable re-audit follow-up): 1.5.0 -> 1.6.0 (Check reports the distrust
    # shortfall as its own BLACKLIST NOT ARMED state, store-open failure reads CHECK ERROR,
    # the check done-line counts Cancelled).
    It 'manifest version is exactly 1.6.0 (newest bump holds the exact pin)' {
        [string]$man.version | Should Be '1.6.3'
    }
    It 'exposes pushDisallowed as a bool input defaulting to OFF (guarded like prunePki/fixRdp)' {
        $pd = @($dep.inputs | Where-Object { $_.name -eq 'pushDisallowed' })[0]
        $pd | Should Not BeNullOrEmpty
        $pd.type | Should Be 'bool'
        [bool]$pd.default | Should Be $false
    }
    It 'the pushDisallowed label says BLACKLIST/DISTRUST - not "trust"' {
        $pd = @($dep.inputs | Where-Object { $_.name -eq 'pushDisallowed' })[0]
        ([string]$pd.label) | Should Match 'BLACKLIST'
        ([string]$pd.label) | Should Match 'DISTRUST'
    }
    It 'the deploy description names the blacklist as a fleet-wide DISTRUST, not covered by "never removes"' {
        ([string]$dep.description) | Should Match 'BLACKLIST'
        ([string]$dep.description) | Should Match 'pushDisallowed'
    }
    It 'the arming confirm text names the Disallowed store and the distrust it causes' {
        ([string]$dep.confirm) | Should Match 'Disallowed'
        ([string]$dep.confirm) | Should Match 'DISTRUSTS'
    }
}

# =============================================================================
Describe 'CertDeploy (1b) Convert-CertDeployBundleToJson - Disallowed is FAIL-CLOSED' {

    $ca = New-GateCaCert 'CN=CertDeploy-Gate-Block'

    It 'OMITS the Disallowed group when the gate is not armed (the worker never sees the certs)' {
        $json = & $cm {
            param($tp, $b64)
            $bundle = [pscustomobject]@{ Root=@(); CA=@(); Disallowed=@([pscustomobject]@{ Thumbprint=$tp; B64=$b64 }) }
            Convert-CertDeployBundleToJson $bundle $false $false
        } $ca.Thumbprint $ca.B64
        $o = $json | ConvertFrom-Json
        @($o.Disallowed).Count | Should Be 0
    }
    It 'INCLUDES the Disallowed group when the gate IS armed' {
        $json = & $cm {
            param($tp, $b64)
            $bundle = [pscustomobject]@{ Root=@(); CA=@(); Disallowed=@([pscustomobject]@{ Thumbprint=$tp; B64=$b64 }) }
            Convert-CertDeployBundleToJson $bundle $false $true
        } $ca.Thumbprint $ca.B64
        $o = $json | ConvertFrom-Json
        $tps = @(@($o.Disallowed) | ForEach-Object { Get-GateNormTp $_.t })
        ($tps -contains (Get-GateNormTp $ca.Thumbprint)) | Should Be $true
    }
    It 'the gate does NOT touch the Root/CA anchor groups' {
        $json = & $cm {
            param($tp, $b64)
            $bundle = [pscustomobject]@{ Root=@([pscustomobject]@{ Thumbprint=$tp; B64=$b64 }); CA=@(); Disallowed=@() }
            Convert-CertDeployBundleToJson $bundle $false $false
        } $ca.Thumbprint $ca.B64
        $o = $json | ConvertFrom-Json
        @($o.Root).Count | Should Be 1
    }
}

# =============================================================================
Describe 'CertDeploy (2) Add-CertDeployBundleToStores - trust and DISTRUST adds are reported apart' {

    It 'a Disallowed add lands in AddedDistrust and NOT in AddedAnchors (never labelled "trusted")' {
        $ca = New-GateCaCert 'CN=CertDeploy-Gate-Blacklisted'
        $r = & $cm {
            param($tp, $b64, $openerSrc)
            $bundle  = [pscustomobject]@{ Root=@(); CA=@(); Disallowed=@([pscustomobject]@{ t=$tp; b=$b64 }) }
            $backing = New-Object System.Collections.ArrayList
            $res = Add-CertDeployBundleToStores -Bundle $bundle -StoreOpener (& $openerSrc $backing)
            [pscustomobject]@{ Anchors=@($res.AddedAnchors); Distrust=@($res.AddedDistrust); All=@($res.AddedCerts); Added=[int]$res.Added }
        } $ca.Thumbprint $ca.B64 $script:GateOpenerSrc

        $r.Added                     | Should Be 1
        @($r.Anchors).Count          | Should Be 0
        @($r.Distrust).Count         | Should Be 1
        (@($r.Distrust) -join '; ')  | Should Match 'Disallowed'
        (@($r.Distrust) -join '; ')  | Should Match ([regex]::Escape($ca.Thumbprint))
        @($r.All).Count              | Should Be 1     # the combined list stays intact (back-compat)
    }

    It 'a Root add lands in AddedAnchors and NOT in AddedDistrust' {
        $ca = New-GateCaCert 'CN=CertDeploy-Gate-Trusted'
        $r = & $cm {
            param($tp, $b64, $openerSrc)
            $bundle  = [pscustomobject]@{ Root=@([pscustomobject]@{ t=$tp; b=$b64 }); CA=@(); Disallowed=@() }
            $backing = New-Object System.Collections.ArrayList
            $res = Add-CertDeployBundleToStores -Bundle $bundle -StoreOpener (& $openerSrc $backing)
            [pscustomobject]@{ Anchors=@($res.AddedAnchors); Distrust=@($res.AddedDistrust) }
        } $ca.Thumbprint $ca.B64 $script:GateOpenerSrc

        @($r.Anchors).Count         | Should Be 1
        (@($r.Anchors) -join '; ')  | Should Match 'Root'
        @($r.Distrust).Count        | Should Be 0
    }
}

# =============================================================================
Describe 'CertDeploy (1c)+(3) deploy action early aborts - gate accounting + summary contract' {

    # A temp bundle whose ONLY cert is a within-validity Untrusted\ blacklist cert. With the
    # gate off there is nothing left to push, so the action must abort admin-side (no WinRM).
    $tmpD = Join-Path ([System.IO.Path]::GetTempPath()) ("certdeploy_gate_{0}" -f ([guid]::NewGuid().ToString('N')))
    New-Item -ItemType Directory -Path (Join-Path $tmpD 'Untrusted') -Force | Out-Null
    $blk = New-GateCaCert 'CN=CertDeploy-Gate-Untrusted'
    [System.IO.File]::WriteAllBytes((Join-Path $tmpD 'Untrusted\blacklist.cer'), $blk.Raw)

    It '(1c) a Disallowed-only bundle with the gate OFF aborts (push set EMPTY) and reports disallowedExcluded' {
        $res = & $cm {
            param($folder)
            Invoke-CertDeployDeployAction -Params @{ confirm='DEPLOY'; certBundleFolder=$folder; targets='WS-GATE-1'; pushDisallowed=$false } -Emit { param($e) }
        } $tmpD
        [bool]$res.summary.rejected            | Should Be $true
        @($res.rows).Count                     | Should Be 0
        [int]$res.summary.disallowedExcluded   | Should Be 1
    }

    # A temp bundle whose ONLY cert is an EXPIRED (non-allowlisted) root - the pre-existing
    # dead-anchor abort, reused here to pin the expired-badge summary contract.
    $tmpE = Join-Path ([System.IO.Path]::GetTempPath()) ("certdeploy_exps_{0}" -f ([guid]::NewGuid().ToString('N')))
    New-Item -ItemType Directory -Path (Join-Path $tmpE 'root') -Force | Out-Null
    $expired = New-SelfSignedCertificate -Subject 'CN=CertDeploy-Gate-Expired' -CertStoreLocation 'Cert:\CurrentUser\My' -KeyLength 2048 -NotBefore (Get-Date).AddDays(-10) -NotAfter (Get-Date).AddDays(-1)
    [System.IO.File]::WriteAllBytes((Join-Path $tmpE 'root\expired.cer'), $expired.RawData)
    Remove-Item ("Cert:\CurrentUser\My\{0}" -f [string]$expired.Thumbprint) -Force -ErrorAction SilentlyContinue

    $expRes = & $cm {
        param($folder)
        Invoke-CertDeployDeployAction -Params @{ confirm='DEPLOY'; certBundleFolder=$folder; targets='WS-GATE-2' } -Emit { param($e) }
    } $tmpE

    It '(3) the summary carries the LOWERCASE expiredCount the view actually reads' {
        [int]$expRes.summary.expiredCount | Should Be 1
    }
    It '(3) the summary carries expiredSubjects naming the dead anchor (the badge log line)' {
        @($expRes.summary.expiredSubjects).Count | Should Be 1
        (@($expRes.summary.expiredSubjects) -join '; ') | Should Match 'CertDeploy-Gate-Expired'
    }
    It '(3) the badge keys are NOT the never-returned ExpiredCount / Expired pair' {
        # PowerShell hashtable lookups are case-insensitive, so assert on the KEY SET the
        # server serializes to the browser - it must contain the lowercase contract names.
        $keys = @($expRes.summary.Keys)
        ($keys -ccontains 'expiredCount')    | Should Be $true
        ($keys -ccontains 'expiredSubjects') | Should Be $true
        ($keys -ccontains 'Expired')         | Should Be $false
    }

    Remove-Item -LiteralPath $tmpD -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $tmpE -Recurse -Force -ErrorAction SilentlyContinue
}

# =============================================================================
Describe 'CertDeploy (4) scan-cert-management - an operator cancel is Cancelled, not CHECK ERROR' {

    It 'Get-CertDeployScanRow maps a Cancelled worker result to the Cancelled reconciler cell' {
        $row = & $cm { Get-CertDeployScanRow -Res @{ Host='WS-C1'; Ping=''; Ok=$false; Status='Cancelled'; Detail='cancelled by operator' } }
        $row.Reconciler | Should Be 'Cancelled'
    }
    It 'a genuine probe failure still reads CHECK ERROR' {
        $row = & $cm { Get-CertDeployScanRow -Res @{ Host='WS-C2'; Ping=''; Ok=$false; Status='CHECK ERROR'; Detail='winrm refused' } }
        $row.Reconciler | Should Be 'CHECK ERROR'
    }
}
