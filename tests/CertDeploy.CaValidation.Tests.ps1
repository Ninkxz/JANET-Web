# =============================================================================
#  CertDeploy.CaValidation.Tests.ps1 - Pester 3.4 tests for the TRUST-ANCHOR guard
#  (P2 fix in modules\JanetWeb.certdeploy.psm1). Add-CertDeployBundleToStores now
#  refuses to trust a NON-CA cert (leaf/end-entity) in a trust-anchor store (Root,
#  CA/Intermediate), so an operator-chosen (UNC-capable) bundle folder can no longer
#  push an arbitrary .cer as a fleet-wide trust anchor. The Disallowed (Untrusted)
#  store is a blacklist, not a trust anchor, so a non-CA cert there is still allowed.
#
#  Mirrors the existing CertDeploy.Tests.ps1 shim idiom: throwaway self-signed certs
#  built OFFLINE via New-SelfSignedCertificate + an INJECTED fake X509Store, so NO
#  real trust-store write and NO WinRM call ever leaves this box.
#
#  Coverage:
#    (1) Test-CertDeployIsCa - the pure BasicConstraints(2.5.29.19) CA=true parse:
#        ACCEPTS a real CA cert (CA=true), REJECTS a leaf (CA=false), REJECTS a cert
#        with no/leaf BasicConstraints (FAIL-CLOSED).
#    (2) Add-CertDeployBundleToStores anchor store (Root): the CA cert lands, the
#        non-CA leaf is REJECTED (Rejected=1, never added), Token still INSTALLED,
#        and AddedCerts surfaces exactly the trusted CA (Subject + thumbprint).
#    (3) Add-CertDeployBundleToStores non-anchor store (Disallowed): a non-CA leaf is
#        ALLOWED (blacklist, not a trust anchor) - the guard must NOT touch it.
#
#  Run:  Invoke-Pester -Path .\tests\CertDeploy.CaValidation.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$cm = Import-Module (Join-Path $script:Root 'modules\JanetWeb.certdeploy.psm1') -Force -PassThru

# --- helpers: build throwaway self-signed certs OFFLINE -----------------------
# A real CA cert: BasicConstraints CA=true (+ CertSign key usage).
function New-TestCaCert {
    param([string]$Subject = 'CN=CertDeploy-Test-CA')
    $c = New-SelfSignedCertificate -Subject $Subject -CertStoreLocation 'Cert:\CurrentUser\My' -KeyUsage CertSign,CRLSign -TextExtension @('2.5.29.19={text}CA=true') -KeyExportPolicy Exportable -KeyLength 2048 -NotAfter (Get-Date).AddDays(1)
    $raw = $c.RawData; $tp = [string]$c.Thumbprint
    Remove-Item ("Cert:\CurrentUser\My\{0}" -f $tp) -Force -ErrorAction SilentlyContinue
    return @{ B64 = [Convert]::ToBase64String($raw); Thumbprint = $tp; Raw = $raw }
}
# A leaf/end-entity cert: BasicConstraints CA=false (explicit -> deterministic offline).
function New-TestLeafCert {
    param([string]$Subject = 'CN=CertDeploy-Test-Leaf')
    $c = New-SelfSignedCertificate -Subject $Subject -CertStoreLocation 'Cert:\CurrentUser\My' -TextExtension @('2.5.29.19={text}CA=false') -KeyExportPolicy Exportable -KeyLength 2048 -NotAfter (Get-Date).AddDays(1)
    $raw = $c.RawData; $tp = [string]$c.Thumbprint
    Remove-Item ("Cert:\CurrentUser\My\{0}" -f $tp) -Force -ErrorAction SilentlyContinue
    return @{ B64 = [Convert]::ToBase64String($raw); Thumbprint = $tp; Raw = $raw }
}
# A default self-signed cert (no CA BasicConstraints) - proves the FAIL-CLOSED path.
function New-TestPlainCert {
    param([string]$Subject = 'CN=CertDeploy-Test-Plain')
    $c = New-SelfSignedCertificate -Subject $Subject -CertStoreLocation 'Cert:\CurrentUser\My' -KeyExportPolicy Exportable -KeyLength 2048 -NotAfter (Get-Date).AddDays(1)
    $raw = $c.RawData; $tp = [string]$c.Thumbprint
    Remove-Item ("Cert:\CurrentUser\My\{0}" -f $tp) -Force -ErrorAction SilentlyContinue
    return @{ B64 = [Convert]::ToBase64String($raw); Thumbprint = $tp; Raw = $raw }
}

# A fake, injectable X509Store backed by an ArrayList (same idiom as CertDeploy.Tests.ps1):
# Add appends a { Thumbprint } stub; the ReadOnly re-verify re-opens the SAME backing list.
# No Remove method exists, so any removal attempt would throw -> proves additive-only.
$script:FakeOpenerSrc = {
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
Describe 'CertDeploy Test-CertDeployIsCa - pure BasicConstraints CA=true parse (fail-closed)' {

    It 'ACCEPTS a real CA cert (BasicConstraints CA=true)' {
        $ca = New-TestCaCert
        $ok = & $cm { param($raw) $c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$raw); [bool](Test-CertDeployIsCa $c) } $ca.Raw
        $ok | Should Be $true
    }

    It 'REJECTS a leaf/end-entity cert (BasicConstraints CA=false)' {
        $leaf = New-TestLeafCert
        $ok = & $cm { param($raw) $c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$raw); [bool](Test-CertDeployIsCa $c) } $leaf.Raw
        $ok | Should Be $false
    }

    It 'REJECTS a cert with NO CA BasicConstraints (FAIL-CLOSED)' {
        $plain = New-TestPlainCert
        $ok = & $cm { param($raw) $c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$raw); [bool](Test-CertDeployIsCa $c) } $plain.Raw
        $ok | Should Be $false
    }

    It 'REJECTS a null cert (fail-closed, no throw)' {
        $ok = & $cm { [bool](Test-CertDeployIsCa $null) }
        $ok | Should Be $false
    }
}

# =============================================================================
Describe 'CertDeploy Add-CertDeployBundleToStores - trust-anchor guard (Root/CA reject non-CA)' {

    It 'anchor store (Root): trusts the CA cert, REJECTS the non-CA leaf, and never adds the leaf' {
        $ca   = New-TestCaCert
        $leaf = New-TestLeafCert
        $r = & $cm {
            param($caTp, $caB64, $leafTp, $leafB64, $openerSrc)
            $bundle = [pscustomobject]@{
                Root       = @([pscustomobject]@{ t=$caTp; b=$caB64 }, [pscustomobject]@{ t=$leafTp; b=$leafB64 })
                CA         = @()
                Disallowed = @()
            }
            $backing = New-Object System.Collections.ArrayList
            $opener  = & $openerSrc $backing
            $res = Add-CertDeployBundleToStores -Bundle $bundle -StoreOpener $opener
            [pscustomobject]@{
                Added        = [int]$res.Added
                Rejected     = [int]$res.Rejected
                RejectDetail = [string]$res.RejectDetail
                StoreCount   = [int]$backing.Count
                StoreHasLeaf = [bool](@($backing | Where-Object { $_.Thumbprint -eq $leafTp }).Count -gt 0)
                AddedCerts   = @($res.AddedCerts)
                Token        = [string](Get-CertDeployResultToken $res)
            }
        } $ca.Thumbprint $ca.B64 $leaf.Thumbprint $leaf.B64 $script:FakeOpenerSrc

        $r.Added        | Should Be 1                      # only the CA cert trusted
        $r.Rejected     | Should Be 1                      # the leaf refused
        $r.StoreCount   | Should Be 1                      # store holds ONLY the CA
        $r.StoreHasLeaf | Should Be $false                 # the leaf never landed
        $r.RejectDetail | Should Match 'not a CA certificate'
        $r.Token        | Should Be 'INSTALLED'
        (@($r.AddedCerts) -join '; ') | Should Match ([regex]::Escape($ca.Thumbprint))
        (@($r.AddedCerts) -join '; ') | Should Not Match ([regex]::Escape($leaf.Thumbprint))
    }

    It 'anchor store (CA/Intermediate): a non-CA leaf is REJECTED, nothing trusted (Token ALREADY)' {
        $leaf = New-TestLeafCert
        $r = & $cm {
            param($leafTp, $leafB64, $openerSrc)
            $bundle = [pscustomobject]@{ Root=@(); CA=@([pscustomobject]@{ t=$leafTp; b=$leafB64 }); Disallowed=@() }
            $backing = New-Object System.Collections.ArrayList
            $opener  = & $openerSrc $backing
            $res = Add-CertDeployBundleToStores -Bundle $bundle -StoreOpener $opener
            [pscustomobject]@{ Added=[int]$res.Added; Rejected=[int]$res.Rejected; Count=[int]$backing.Count; Token=[string](Get-CertDeployResultToken $res) }
        } $leaf.Thumbprint $leaf.B64 $script:FakeOpenerSrc

        $r.Added    | Should Be 0
        $r.Rejected | Should Be 1
        $r.Count    | Should Be 0        # nothing landed in the CA anchor store
        $r.Token    | Should Be 'ALREADY'
    }

    It 'a real CA cert into an anchor store is ACCEPTED (guard is NON-BREAKING for legit CAs)' {
        $ca = New-TestCaCert
        $r = & $cm {
            param($caTp, $caB64, $openerSrc)
            $bundle = [pscustomobject]@{ Root=@([pscustomobject]@{ t=$caTp; b=$caB64 }); CA=@(); Disallowed=@() }
            $backing = New-Object System.Collections.ArrayList
            $opener  = & $openerSrc $backing
            $res = Add-CertDeployBundleToStores -Bundle $bundle -StoreOpener $opener
            [pscustomobject]@{ Added=[int]$res.Added; Rejected=[int]$res.Rejected; Count=[int]$backing.Count; Token=[string](Get-CertDeployResultToken $res) }
        } $ca.Thumbprint $ca.B64 $script:FakeOpenerSrc

        $r.Added    | Should Be 1
        $r.Rejected | Should Be 0
        $r.Count    | Should Be 1
        $r.Token    | Should Be 'INSTALLED'
    }
}

# =============================================================================
Describe 'CertDeploy Add-CertDeployBundleToStores - Disallowed (non-anchor) is NOT guarded' {

    It 'Disallowed store: a non-CA leaf is ALLOWED (blacklist, not a trust anchor)' {
        $leaf = New-TestLeafCert
        $r = & $cm {
            param($leafTp, $leafB64, $openerSrc)
            $bundle = [pscustomobject]@{ Root=@(); CA=@(); Disallowed=@([pscustomobject]@{ t=$leafTp; b=$leafB64 }) }
            $backing = New-Object System.Collections.ArrayList
            $opener  = & $openerSrc $backing
            $res = Add-CertDeployBundleToStores -Bundle $bundle -StoreOpener $opener
            [pscustomobject]@{ Added=[int]$res.Added; Rejected=[int]$res.Rejected; Count=[int]$backing.Count; Token=[string](Get-CertDeployResultToken $res) }
        } $leaf.Thumbprint $leaf.B64 $script:FakeOpenerSrc

        $r.Added    | Should Be 1        # the leaf IS added to the Untrusted store
        $r.Rejected | Should Be 0        # the CA guard never applies to Disallowed
        $r.Count    | Should Be 1
        $r.Token    | Should Be 'INSTALLED'
    }
}
