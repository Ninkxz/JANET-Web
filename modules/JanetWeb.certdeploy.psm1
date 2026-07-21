# =============================================================================
#  JanetWeb.certdeploy.psm1  ->  Cert Deploy (proactive DoD/LTMA trust-root push)
#
#  Net-new JANET Web tool (no desktop twin). PROACTIVE cert deployment: the
#  operator pushes the DoD/LTMA trust-root bundle to get AHEAD of PKI Trust Roots
#  non-compliance. A host that merely CARRIES the PKI tag (audit OR failed rule,
#  compliant OR not) should get the roots BEFORE it goes non-compliant. This tool
#  is DELIBERATELY independent of any C2C failure status - it is the LTMA certs.ps1
#  workflow (push the DoD trust bundle to a host list), not a failure remediator.
#
#  It intentionally does NOT depend on modules\JanetWeb.c2c.psm1: the small
#  cert-bundle-read + additive-install + self-guard helpers are COPIED here (each
#  JANET Web module is independent and exports the same two contract functions).
#
#  Three actions:
#    check              (read-only, no admin gate) - read the bundle admin-side,
#                       then per host open each LocalMachine store READ-ONLY and
#                       report which roots are MISSING per store. This is the
#                       ACCURATE needs-certs signal (unlike the C2C audit tag).
#    deploy             (DESTRUCTIVE -> admin-session gate + type DEPLOY) - per host
#                       ADDITIVELY install the bundle into Root/CA/Disallowed over
#                       WinRM. Adds ONLY thumbprints not already present; NEVER
#                       removes anything. Self-guard + wrong-box HARD abort + per-
#                       host watchdog + operator cancel bridge.
#    import-pki-hosts   (read-only, local parse, no WinRM) - parse the Tanium
#                       "C2C Compliance Status" CSV and return EVERY host whose
#                       Compliance cell mentions "PKI Trust Roots" in ANY line
#                       (audit OR failed, compliant OR non-compliant). This is the
#                       proactive "if it has the PKI tag, deploy" set.
#
#  Bundle read + additive install are COPIED from JanetWeb.c2c.psm1:
#    Get-CertDeployBundle          <- Get-C2cCertBundle       (root\ Intermediate\ Untrusted\ *.cer)
#    Resolve-CertDeployBundleFolder<- Resolve-C2cCertBundleFolder
#    Add-CertDeployBundleToStores  <- Add-C2cBundleToStores   (ADDITIVE: adds only-missing, NEVER removes)
#    Test-JanetCertDeployHostIsSelf<- Test-JanetC2cHostIsSelf (dispatcher self-guard)
#  The shipped default bundle is Packages\DoD-Certs (Get-CertDeployDefaultBundlePath),
#  the same base bundle the C2C fix-pki path ships; this module never WRITES it.
#
#  Contract (server convention):
#    Get-JanetToolManifest                                       -> descriptors
#    Invoke-JanetToolAction -ActionId -Params -Credential -Emit  -> { rows; summary }
#  PowerShell 5.1 only. ASCII-only body; UTF-8 WITH BOM.
# =============================================================================

# informative-failures (loop78): shared troubleshooting-hint engine. On a per-host
# DEPLOY failure the harvest turns the raw error into a why+how-to-fix hint. Imported
# at module scope (controller-side) - never inside a remote runspace block.
Import-Module (Join-Path $PSScriptRoot 'JanetWeb.troubleshoot.psm1') -Force -ErrorAction SilentlyContinue

function Get-JanetToolManifest {
    @{
        id       = 'certdeploy'
        name     = 'Cert Deploy'
        version  = '1.4.4'
        category = 'Hardening'
        summary  = 'Proactively deploy the DoD/LTMA trust-root bundle (defaults to the shipped Packages\DoD-Certs) to ANY host list to get AHEAD of PKI Trust Roots non-compliance - even a host that is not failing yet but carries the PKI tag. Read-only CHECK reports which hosts are missing which roots (the accurate needs-certs signal, unlike the C2C audit tag); DEPLOY additively installs the roots into the LocalMachine Root/CA/Disallowed stores over WinRM (adds only-missing by thumbprint, NEVER removes); Import C2C export loads every PKI-tagged host into the target list. Independent of C2C failure status.'
        actions  = @(
            @{
                id          = 'check'
                label       = 'Check Trust Certs (read-only)'
                description = 'READ-ONLY. Read the DoD/LTMA trust bundle ADMIN-SIDE once (root\*.cer -> Root, Intermediate\*.cer -> CA, Untrusted\*.cer -> Disallowed, loose *.cer -> Root; blank folder = the shipped Packages\DoD-Certs), then per host open each LocalMachine store READ-ONLY and compute which bundle roots are MISSING per store. Status ALL PRESENT (0 missing) / MISSING N / OFFLINE / CHECK ERROR. Detail lists the per-store missing counts (Root x / CA y / Disallowed z) plus a few example missing subjects. The Legacy column reports present/total for the four allowlisted legacy DoD intermediates (DOD EMAIL/ID CA-59, SW CA-60/61) in LocalMachine\CA - expired-but-required for legacy chain validation - and names any that are missing. Reachability is TCP-only (5985/5986/445); a DNS wrong-box is soft-skipped as CHECK ERROR. NEVER writes to a store on this path; needs no admin session and no confirm word.'
                kind        = 'stream-table'
                destructive = $false
                columns     = @('Host','Ping','Status','Missing','Legacy','Detail')
                inputs      = @(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='certBundleFolder'; label='DoD/LTMA trust bundle folder (blank = shipped Packages\DoD-Certs)'; type='text'; required=$false },
                    @{ name='attemptOffline'; label='Attempt even if offline (host unreachable)'; type='bool'; required=$false; default=$false },
                    @{ name='threads'; label='Parallel hosts (1-32)'; type='int'; required=$false; default=16 }
                )
            }
            @{
                id          = 'deploy'
                label       = 'Deploy Trust Certs'
                description = 'DESTRUCTIVE (certificate store) - requires a live admin session and the exact confirm word DEPLOY. Read the DoD/LTMA trust bundle ADMIN-SIDE once (blank folder = the shipped Packages\DoD-Certs); abort and dial nothing if it is missing/empty. Per host: TCP reachability, a DNS wrong-box HARD abort, and the dispatcher self-guard (the JANET host is never targeted), then ONE WinRM round-trip that ADDITIVELY installs each store group - each LocalMachine store is opened ReadWrite and ONLY certs whose thumbprint is not already present are added; nothing is EVER removed. Result ROOTS INSTALLED (added N of M across Root/CA/Disallowed) / ROOTS ALREADY PRESENT / FAILED / OFFLINE. Per-host watchdog + operator cancel bridge. TWO INDEPENDENT OPT-IN companions (default OFF - the deploy stays purely additive unless ticked) run the PKI-Fix-ScanFix v1.9 fixes on each host in the SAME WinRM round-trip, after the install, each armable on its own: prunePki prunes EXPIRED retired DOD EMAIL/ID/SW/DERILITY intermediates from the CA store ONLY (the four legacy-keep intermediates this tool intentionally pushes are never touched, nor is any other expired cert); fixRdp rebinds a BROKEN RDP-tcp listener certificate (self-signed / expired / missing) to the newest valid CA-issued My-store cert for the host - the replacement is located BEFORE anything is cleared (no candidate = left untouched), a healthy CA-issued listener is never touched. Companion outcomes ride in the row Detail; they never change the row Status.'
                kind        = 'stream-table'
                destructive = $true
                confirm     = 'Deploy the DoD/LTMA trust-root bundle to the target host(s)? This ADDITIVELY installs the DoD roots into LocalMachine Root/CA/Disallowed (never removes anything). Proceed?'
                columns     = @('Host','Ping','Status','Missing','Detail')
                inputs      = @(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='certBundleFolder'; label='DoD/LTMA trust bundle folder (blank = shipped Packages\DoD-Certs)'; type='text'; required=$false },
                    @{ name='confirm'; label='Type DEPLOY to confirm'; type='text'; required=$true },
                    @{ name='includeExpired'; label='Include EXPIRED certs (dead trust anchors - default OFF)'; type='bool'; required=$false; default=$false },
                    @{ name='prunePki'; label='Prune expired retired DoD intermediates (CA store; the 4 legacy-keeps never touched)'; type='bool'; required=$false; default=$false },
                    @{ name='fixRdp'; label='Repair broken RDP listener (self-signed/expired/missing -> rebind CA-issued; healthy untouched)'; type='bool'; required=$false; default=$false },
                    @{ name='threads'; label='Parallel hosts (1-16)'; type='int'; required=$false; default=8 },
                    @{ name='attemptOffline'; label='Attempt even if offline (host unreachable)'; type='bool'; required=$false; default=$false }
                )
            }
            @{
                id          = 'scan-cert-management'
                label       = 'SCAN CERT MANAGEMENT (what manages trust)'
                description = 'READ-ONLY (no admin session, no confirm). Per host, one WinRM round-trip that inspects WHAT MANAGES the LocalMachine trust store so you know whether a scripted .Default push will actually persist. Detects the DISA InstallRoot agent (uninstall registry DisplayName, a scheduled task, and the %ProgramFiles%\DoD-PKE path), counts the GPO physical Root/CA store (HKLM Policies SystemCertificates), and reads the LocalMachine Root store count for context. Reconciler verdict InstallRoot / GPO / InstallRoot+GPO / None detected / OFFLINE / CHECK ERROR - when a reconciler is present a scripted push may be pruned on reboot (align with InstallRoot/GPO instead); None detected means a manual .Default push WILL persist. Reachability is TCP-only (5985/5986/445); a DNS wrong-box is soft-skipped as CHECK ERROR. NEVER writes anything.'
                kind        = 'stream-table'
                destructive = $false
                columns     = @('Host','Ping','InstallRoot','GPRoots','Reconciler','Detail')
                inputs      = @(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='attemptOffline'; label='Attempt even if offline (host unreachable)'; type='bool'; required=$false; default=$false },
                    @{ name='threads'; label='Parallel hosts (1-32)'; type='int'; required=$false; default=16 }
                )
            }
            @{
                id          = 'import-pki-hosts'
                label       = 'Import C2C export -> load all PKI-tagged hosts'
                description = 'READ-ONLY (local parse, no WinRM, no credential). Parse the Tanium "C2C Compliance Status" CSV export (the multiline Compliance cell per host) and return EVERY host whose Compliance cell mentions "PKI Trust Roots" in ANY line - AUDIT OR FAILED rule, COMPLIANT OR NON-COMPLIANT. This is the proactive set: any host carrying the PKI tag, whether or not it is failing yet. Streams one row per PKI-tagged host so the view can load them into the target list; returns summary { total, pkiTagged, hosts:[...] }.'
                kind        = 'stream-table'
                destructive = $false
                columns     = @('Host','Compliance','Pki','Fqdn')
                inputs      = @(
                    @{ name='csvPath'; label='C2C Compliance CSV file'; type='file'; filter='CSV files (*.csv)|*.csv|All files (*.*)|*.*'; required=$false },
                    @{ name='csvText'; label='...or paste CSV text'; type='textarea'; required=$false }
                )
            }
        )
    }
}

# =============================================================================
#  COPIED HELPERS (from JanetWeb.c2c.psm1; this module never imports c2c)
# =============================================================================

# Resolver for the SHIPPED DoD trust bundle. The repo ships the base bundle at
# Packages\DoD-Certs (Root\ Intermediate\ Untrusted\ *.cer). A blank folder
# auto-falls-back here (Resolve-CertDeployBundleFolder). Read-only: never written.
function Get-CertDeployDefaultBundlePath { Join-Path $PSScriptRoot '..\Packages\DoD-Certs' }

# --- LegacyIntermediates: a NARROW, audited exception to the expiry guard --------
# These four DoD intermediate CAs are EXPIRED but are INTENTIONALLY kept installed on
# endpoints for legacy chain / signature validation - they signed still-in-use certs and
# code (e.g. SW CA-60/61 signed legacy software) that must still validate. The expiry
# guard ("never push a dead trust anchor") consults this allowlist: an expired cert whose
# thumbprint is on this list is PUSHABLE; anything else expired is STILL refused. This does
# NOT weaken the guard for any other cert. Do NOT add a thumbprint here without confirming
# the cert is genuinely required for legacy validation - this is a deliberate exception,
# not a general "allow expired" switch (that is the separate opt-in includeExpired input).
# Keyed by exact uppercase SHA-1 thumbprint (no spaces).
$script:CertDeployLegacyIntermediates = [ordered]@{
    '53FDE0F40638BD1A68A68D1E91089009B33BAE5E' = 'DOD EMAIL CA-59'  # issuer DoD Root CA 3, expired 2025-04-02
    '1907FC2B223EE0301B45745BDB59AAD90FE7C5D7' = 'DOD ID CA-59'     # issuer DoD Root CA 3, expired 2025-04-02
    '5DFFDAB658915FA6B0DB4E0BCF70D5BB1B8425FC' = 'DOD SW CA-60'     # issuer DoD Root CA 3, expired 2025-04-02
    '5F555AB8A87DD146314171621245CF720BF53B8A' = 'DOD SW CA-61'     # issuer DoD Root CA 5, expired 2025-03-31
}
# $true when $Thumbprint (any spacing/case) is an allowlisted legacy intermediate.
function Test-CertDeployLegacyAllowed {
    param([string]$Thumbprint)
    $tp = (([string]$Thumbprint) -replace '[^0-9A-Fa-f]','').ToUpperInvariant()
    return ($tp -and $script:CertDeployLegacyIntermediates.Contains($tp))
}

# Admin-side cert-bundle reader (COPIED from Get-C2cCertBundle, extended to also
# capture each cert's Subject so the read-only Check can show example missing
# subjects). Enumerates (case-insensitive) <folder>\root\*.cer -> Root,
# <folder>\Intermediate\*.cer -> CA, <folder>\Untrusted\*.cer -> Disallowed, and
# loose <folder>\*.cer -> Root. Each .cer -> thumbprint + base64 + subject. Returns
# @{ Ok; Error; Root=@(@{Thumbprint;B64;Subject;File}); CA=@(...); Disallowed=@(...);
#    CertCount; FileCount; Folder }. Ok=$false + Error if missing or ZERO certs.
function Get-CertDeployBundle {
    param([string]$Folder)
    $res = @{ Ok=$false; Error=''; Root=@(); CA=@(); Disallowed=@(); CertCount=0; FileCount=0; Folder=''; ExpiredCount=0; Expired=@(); LegacyAllowed=@(); LegacyAllowedCount=0 }
    $f = ([string]$Folder).Trim().Trim('"')
    $res.Folder = $f
    if (-not $f) { $res.Error = 'no cert bundle folder provided'; return $res }
    if (-not (Test-Path -LiteralPath $f)) { $res.Error = "cert bundle folder not found: $f"; return $res }
    $groups = @{
        Root       = New-Object System.Collections.ArrayList
        CA         = New-Object System.Collections.ArrayList
        Disallowed = New-Object System.Collections.ArrayList
    }
    $loadCer = {
        param($file, $store)
        try {
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $cert.Import($file)
            $b64  = [Convert]::ToBase64String($cert.RawData)
            [void]$groups[$store].Add([pscustomobject]@{ Thumbprint=[string]$cert.Thumbprint; B64=$b64; Subject=[string]$cert.Subject; File=(Split-Path $file -Leaf); NotAfter=$cert.NotAfter; Store=$store })
            return $true
        } catch { return $false }
    }
    $fileCount = 0
    foreach ($m in @(@{ Sub='root'; Store='Root' }, @{ Sub='Intermediate'; Store='CA' }, @{ Sub='Untrusted'; Store='Disallowed' })) {
        $sub = Join-Path $f $m.Sub
        if (Test-Path -LiteralPath $sub) {
            foreach ($cf in @(Get-ChildItem -LiteralPath $sub -Filter '*.cer' -File -ErrorAction SilentlyContinue)) {
                if (& $loadCer $cf.FullName $m.Store) { $fileCount++ }
            }
        }
    }
    # Loose *.cer directly under the folder -> Root (non-recursive).
    foreach ($cf in @(Get-ChildItem -LiteralPath $f -Filter '*.cer' -File -ErrorAction SilentlyContinue)) {
        if (& $loadCer $cf.FullName 'Root') { $fileCount++ }
    }
    $total = $groups.Root.Count + $groups.CA.Count + $groups.Disallowed.Count
    if ($total -eq 0) {
        $res.Error = "no .cer certificates found under $f (expected root\*.cer, Intermediate\*.cer, Untrusted\*.cer, or loose *.cer)"
        return $res
    }
    $res.Root = @($groups.Root); $res.CA = @($groups.CA); $res.Disallowed = @($groups.Disallowed)
    $res.CertCount = $total; $res.FileCount = $fileCount; $res.Ok = $true
    # Expiry census (SHARED CONTRACT): a cert whose NotAfter is in the past (admin-side
    # clock) is a dead trust anchor. Report ExpiredCount + Expired[] so the deploy path
    # can exclude them by default and the read-only Check can always surface the count.
    $now = Get-Date
    $expired = New-Object System.Collections.ArrayList
    $legacy  = New-Object System.Collections.ArrayList   # expired BUT allowlisted -> pushable, reported separately
    foreach ($grp in @('Root','CA','Disallowed')) {
        foreach ($c in @($res.$grp)) {
            if (-not $c) { continue }
            $na = $null
            try { if ($c.NotAfter) { $na = [datetime]$c.NotAfter } } catch { $na = $null }
            if ($na -and ($na -lt $now)) {
                $rec = @{ Thumbprint=[string]$c.Thumbprint; Subject=[string]$c.Subject; NotAfter=$na.ToString('o'); Store=[string]$c.Store }
                # An expired cert on the LegacyIntermediates allowlist is NOT a dead anchor to
                # exclude - it is intentionally pushed. Everything else expired is a dead anchor.
                if (Test-CertDeployLegacyAllowed $c.Thumbprint) { [void]$legacy.Add($rec) }
                else { [void]$expired.Add($rec) }
            }
        }
    }
    $res.Expired = @($expired)
    $res.ExpiredCount = $expired.Count
    $res.LegacyAllowed = @($legacy)
    $res.LegacyAllowedCount = $legacy.Count
    return $res
}

# Resolve the effective bundle folder (COPIED from Resolve-C2cCertBundleFolder). An
# operator-supplied (non-blank) path ALWAYS wins; a blank/whitespace path auto-falls
# back to the SHIPPED default (Packages\DoD-Certs) ONLY when it exists + holds >=1
# .cer, so a one-click Check / Deploy works with nothing typed. Returns
# @{ Folder; Source } where Source is 'operator-supplied' / 'shipped default' / '';
# Folder='' means NEITHER a path was given NOR a usable default was found.
function Resolve-CertDeployBundleFolder {
    param([string]$Supplied)
    $s = ([string]$Supplied).Trim().Trim('"')
    if (-not [string]::IsNullOrWhiteSpace($s)) { return @{ Folder = $s; Source = 'operator-supplied' } }
    $def = Get-CertDeployDefaultBundlePath
    if ($def -and (Test-Path -LiteralPath $def)) {
        # Count the SAME way Get-CertDeployBundle READS: the three named subfolders +
        # loose top-level *.cer, NON-recursively. A -Recurse count could call the default
        # 'usable' when the reader would then find none (certs nested deeper) and abort.
        $cerCount = 0
        foreach ($sub in @('root','Intermediate','Untrusted')) {
            $p = Join-Path $def $sub
            if (Test-Path -LiteralPath $p) { $cerCount += @(Get-ChildItem -LiteralPath $p -Filter '*.cer' -File -ErrorAction SilentlyContinue).Count }
        }
        $cerCount += @(Get-ChildItem -LiteralPath $def -Filter '*.cer' -File -ErrorAction SilentlyContinue).Count
        if ($cerCount -gt 0) { return @{ Folder = $def; Source = 'shipped default' } }
    }
    return @{ Folder = ''; Source = '' }
}

# Serialize a bundle to the compact JSON the DEPLOY worker consumes (thumbprint +
# b64 per store). @()-wrapped so ConvertFrom-Json single-element arrays round-trip.
# SHARED CONTRACT: when -IncludeExpired is $false (default) expired certs (NotAfter
# in the past) are EXCLUDED from the pushed set; $true includes them (dead anchors).
function Convert-CertDeployBundleToJson {
    param($Bundle, [bool]$IncludeExpired = $false)
    $now = Get-Date
    # Capture the allowlist as a LOCAL set so the GetNewClosure() closure below never depends
    # on module-function resolution (a closure may not see Test-CertDeployLegacyAllowed).
    $legacySet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($k in $script:CertDeployLegacyIntermediates.Keys) { [void]$legacySet.Add([string]$k) }
    $sel = {
        param($items)
        @(@($items) | Where-Object { $_ } | Where-Object {
            if ($IncludeExpired) { return $true }
            $na = $null
            try { if ($_.NotAfter) { $na = [datetime]$_.NotAfter } } catch { $na = $null }
            if ((-not $na) -or ($na -ge $now)) { return $true }         # within validity -> keep
            $tp = (([string]$_.Thumbprint) -replace '[^0-9A-Fa-f]','').ToUpperInvariant()
            return $legacySet.Contains($tp)                              # expired -> keep ONLY if allowlisted
        } | ForEach-Object { @{ t=[string]$_.Thumbprint; b=[string]$_.B64 } })
    }.GetNewClosure()
    $payload = @{
        Root       = @(& $sel $Bundle.Root)
        CA         = @(& $sel $Bundle.CA)
        Disallowed = @(& $sel $Bundle.Disallowed)
    }
    return ($payload | ConvertTo-Json -Depth 5 -Compress)
}

# Serialize ONLY the thumbprints per store (the read-only CHECK worker needs no
# base64 - it only asks "is this thumbprint already present?").
function Convert-CertDeployBundleToThumbJson {
    param($Bundle)
    $payload = @{
        Root       = @(@($Bundle.Root)       | ForEach-Object { [string]$_.Thumbprint })
        CA         = @(@($Bundle.CA)         | ForEach-Object { [string]$_.Thumbprint })
        Disallowed = @(@($Bundle.Disallowed) | ForEach-Object { [string]$_.Thumbprint })
    }
    return ($payload | ConvertTo-Json -Depth 5 -Compress)
}

# Build a thumbprint(normalized) -> subject lookup from a bundle, so the admin side
# can name the example MISSING subjects returned by the read-only check worker.
function Get-CertDeploySubjectMap {
    param($Bundle)
    $map = @{}
    foreach ($grp in @('Root','CA','Disallowed')) {
        foreach ($c in @($Bundle.$grp)) {
            if (-not $c) { continue }
            $tp = (([string]$c.Thumbprint) -replace '[^0-9A-Fa-f]','')
            if ($tp -and -not $map.ContainsKey($tp)) { $map[$tp] = [string]$c.Subject }
        }
    }
    return $map
}

# --- Additive cert-store installer (DEPLOY worker + unit test) -----------------
# COPIED from JanetWeb.c2c.psm1 ($script:C2cAddCertsSrc). ADDITIVE by construction:
# for each store group, open the LocalMachine store ReadWrite, add ONLY certs whose
# thumbprint is not already present, and NEVER remove anything. $StoreOpener is
# injectable (default = a real X509Store) so the additive-only guard is unit-testable
# against a fake store. Returns @{ Added; Already; Total; PerStore=@('Root +N/M',...);
# FailDetail }. Dot-sourced remotely by the worker AND in module scope (below).
$script:CertDeployAddCertsSrc = @'
# TRUST-ANCHOR GUARD (P2 fix): a CA-cert test used to gate what may land in a
# TRUST-ANCHOR store (Root, CA/Intermediate). Parse the X509BasicConstraintsExtension
# (OID 2.5.29.19) and return $true ONLY when CertificateAuthority is true. FAIL-CLOSED:
# an ABSENT BasicConstraints extension (or any parse error) is treated as NOT a CA - a
# legit modern CA cert carries BasicConstraints CA=true; a leaf/end-entity does not. This
# is a pure function (no store I/O) so it is directly unit-testable. Applied to Root/CA
# ONLY; the Disallowed (Untrusted) store is a blacklist, not a trust anchor, so a non-CA
# cert there is legitimate and this guard never touches it.
function Test-CertDeployIsCa {
    param($Cert)
    if (-not $Cert) { return $false }
    try {
        foreach ($ext in $Cert.Extensions) {
            if ([string]$ext.Oid.Value -eq '2.5.29.19') {
                $bc = $ext -as [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]
                if (-not $bc) {
                    $bc = New-Object System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension
                    $bc.CopyFrom($ext)
                }
                return [bool]$bc.CertificateAuthority
            }
        }
    } catch { return $false }
    return $false   # no BasicConstraints extension -> fail-closed, NOT a CA
}
function Add-CertDeployBundleToStores {
    param($Bundle, [scriptblock]$StoreOpener)
    if (-not $StoreOpener) {
        $StoreOpener = {
            param($storeName, $mode)
            if (-not $mode) { $mode = 'ReadWrite' }
            $st = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, 'LocalMachine')
            $st.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::$mode)
            return $st
        }
    }
    $added = 0; $already = 0; $total = 0; $failDetail = ''
    $verified = 0
    $rejected = 0; $rejectDetail = ''
    $notVerified = New-Object System.Collections.ArrayList
    $addedCerts  = New-Object System.Collections.ArrayList   # Subject(CN) + thumbprint of each cert WE added (anchor + Disallowed)
    $perStore = New-Object System.Collections.ArrayList
    # Anchor=$true marks a TRUST-ANCHOR store (Root, CA/Intermediate): only actual CA certs
    # may land there. Disallowed is the Untrusted blacklist (Anchor=$false) - a non-CA cert
    # there is legitimate, so the CA guard is NOT applied to it.
    foreach ($sm in @(@{ Prop='Root'; Store='Root'; Anchor=$true }, @{ Prop='CA'; Store='CA'; Anchor=$true }, @{ Prop='Disallowed'; Store='Disallowed'; Anchor=$false })) {
        $items = @()
        try { $items = @($Bundle.($sm.Prop)) | Where-Object { $_ } } catch { $items = @() }
        if ($items.Count -eq 0) { continue }
        $wantedTps = New-Object System.Collections.ArrayList   # all wanted thumbprints in this store
        $addedTps  = New-Object System.Collections.ArrayList   # thumbprints WE added this session
        $st = $null
        try {
            $st = & $StoreOpener $sm.Store 'ReadWrite'
            $present = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($ec in $st.Certificates) { [void]$present.Add((([string]$ec.Thumbprint) -replace '[^0-9A-Fa-f]','')) }
            $sAdd = 0
            foreach ($it in $items) {
                $total++
                $tp = (([string]$it.t) -replace '[^0-9A-Fa-f]','')
                if ($tp) { [void]$wantedTps.Add($tp) }
                if ($tp -and $present.Contains($tp)) { $already++; continue }
                try {
                    $raw  = [Convert]::FromBase64String([string]$it.b)
                    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$raw)
                    # TRUST-ANCHOR GUARD: for Root/CA only, refuse a cert that is NOT an actual CA
                    # (no BasicConstraints CA=true) - an operator-chosen bundle folder must not be able
                    # to push a leaf/end-entity cert as a fleet-wide trust anchor. Keep adding valid CAs.
                    if ($sm.Anchor -and -not (Test-CertDeployIsCa $cert)) {
                        $rejected++
                        $rsubj = [string]$cert.Subject
                        $m = [regex]::Match($rsubj, '(?i)CN=([^,]+)'); if ($m.Success) { $rsubj = $m.Groups[1].Value.Trim() }
                        $rejectDetail += "rejected non-CA cert '$rsubj' ($tp) from $($sm.Store) - not a CA certificate; "
                        continue
                    }
                    $st.Add($cert)
                    if ($tp) { [void]$present.Add($tp); [void]$addedTps.Add($tp) }
                    $sAdd++; $added++
                    $asubj = [string]$cert.Subject
                    $am = [regex]::Match($asubj, '(?i)CN=([^,]+)'); if ($am.Success) { $asubj = $am.Groups[1].Value.Trim() }
                    [void]$addedCerts.Add("$asubj [$tp] -> $($sm.Store)")
                } catch { $failDetail += "add failed in $($sm.Store): $($_.Exception.Message); " }
            }
            [void]$perStore.Add("$($sm.Store) +$sAdd/$($items.Count)")
        } catch {
            $failDetail += "store $($sm.Store) open failed: $($_.Exception.Message); "
        } finally { if ($st) { try { $st.Close() } catch {} } }

        # PERSISTENCE RE-VERIFY (SHARED CONTRACT): re-open the SAME store READ-ONLY (a
        # fresh handle - never the in-memory one) and confirm each wanted thumbprint is
        # actually present. Any thumbprint WE added that is now absent means a reconciler
        # or policy stripped it in-session -> NotVerified.
        $rst = $null
        try {
            $rst = & $StoreOpener $sm.Store 'ReadOnly'
            $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($ec in $rst.Certificates) { [void]$seen.Add((([string]$ec.Thumbprint) -replace '[^0-9A-Fa-f]','')) }
            foreach ($tp in $wantedTps) { if ($seen.Contains($tp)) { $verified++ } }
            foreach ($tp in $addedTps)  { if (-not $seen.Contains($tp)) { [void]$notVerified.Add($tp) } }
        } catch {
            $failDetail += "store $($sm.Store) re-verify open failed: $($_.Exception.Message); "
            foreach ($tp in $addedTps) { [void]$notVerified.Add($tp) }
        } finally { if ($rst) { try { $rst.Close() } catch {} } }
    }
    return @{ Added=$added; Already=$already; Total=$total; PerStore=@($perStore); FailDetail=$failDetail; Verified=$verified; NotVerified=@($notVerified.ToArray()); Rejected=$rejected; RejectDetail=$rejectDetail; AddedCerts=@($addedCerts.ToArray()) }
}
# Classify an Add-CertDeployBundleToStores result into the raw deploy token: any
# .Add/open error -> FAIL; else added-but-stripped-on-re-read -> NOT VERIFIED; else
# 1+ added -> INSTALLED; else nothing to add -> ALREADY. This is the SINGLE classifier
# the deploy worker AND the unit tests call.
function Get-CertDeployResultToken {
    param($AddResult)
    if (-not $AddResult) { return 'FAIL' }
    if ([string]$AddResult.FailDetail) { return 'FAIL' }
    $nv = @()
    try { $nv = @($AddResult.NotVerified) | Where-Object { $_ } } catch { $nv = @() }
    if ($nv.Count -gt 0)               { return 'NOT VERIFIED' }
    # loop49 (F2): a wanted anchor REFUSED by the trust-anchor guard (non-CA cert destined for Root/CA)
    # is absent from the store - the deploy did NOT achieve "all present", so it must not read
    # INSTALLED / ALREADY (a clean/Skipped audit). REJECTED is out of the clean bucket (row -> REJECTED
    # (non-CA), audit -> Failure), even if other certs added successfully this session.
    if ([int]$AddResult.Rejected -gt 0) { return 'REJECTED' }
    if ([int]$AddResult.Added -gt 0)   { return 'INSTALLED' }
    return 'ALREADY'
}
'@
# Define the additive installer + classifier in MODULE scope too (admin-side use +
# direct unit testing). The deploy worker dot-sources the same source string remotely.
try { . ([scriptblock]::Create($script:CertDeployAddCertsSrc)) } catch {}

# --- PKI-Fix-ScanFix v1.9 companions (OPT-IN deploy extra) ----------------------
# PORT of the C2C fix-pki Pb/Pc companion blocks (JanetWeb.c2c.psm1) so the Cert
# Deploy tab can run the SAME remediation the C2C Fix PKI path runs - gated on the
# deploy action's prunePki/fixRdp inputs (both default OFF: deploy stays purely additive).
# Runs ON the target host AFTER the additive install, in the same WinRM round-trip.
# Returns an array of note strings ("PkiExpired FIXED: ...", "PkiRdp SKIP: ...");
# an EMPTY array means both companions found nothing to do (no prunable expired
# retired intermediates AND a healthy/absent-with-no-candidate RDP listener).
$script:CertDeployCompanionsSrc = @'
function Invoke-CertDeployCompanions {
    param([bool]$DoPrune = $true, [bool]$DoRdp = $true)
    $notes = New-Object System.Collections.ArrayList
    # (a) PkiExpired - prune EXPIRED retired DoD intermediates. SAFETY MODEL: expired
    #     does NOT mean deletable (roots, timestamping and machine-identity certs are
    #     often expired-but-required), so deletion is gated on an ALLOWLIST: subject
    #     must match the retired DoD intermediate pattern AND the store is CA ONLY
    #     (never My/Root/TrustedPublisher/Disallowed). The four LegacyIntermediates
    #     thumbprints are EXCLUDED - deploy intentionally pushes those despite expiry
    #     (guard copy of $script:CertDeployLegacyIntermediates; keep the lists in sync).
    if ($DoPrune) {
    try {
        $allowSubject = '^CN=DOD (EMAIL|ID|SW|DERILITY) CA-\d+, OU=PKI, OU=DoD'
        $legacyKeep = @(
            '53FDE0F40638BD1A68A68D1E91089009B33BAE5E'  # DOD EMAIL CA-59
            '1907FC2B223EE0301B45745BDB59AAD90FE7C5D7'  # DOD ID CA-59
            '5DFFDAB658915FA6B0DB4E0BCF70D5BB1B8425FC'  # DOD SW CA-60
            '5F555AB8A87DD146314171621245CF720BF53B8A'  # DOD SW CA-61
        )
        $nowPk = Get-Date
        $prunable = @(Get-ChildItem 'Cert:\LocalMachine\CA' -ErrorAction SilentlyContinue | Where-Object {
            $_.NotAfter -lt $nowPk -and $_.Subject -match $allowSubject -and
            ($legacyKeep -notcontains ((([string]$_.Thumbprint) -replace '[^0-9A-Fa-f]', '').ToUpper()))
        })
        if ($prunable.Count -gt 0) {
            $delOk = 0; $delFail = ''
            foreach ($pc in $prunable) {
                try { Remove-Item -Path $pc.PSPath -Force -ErrorAction Stop; $delOk++ }
                catch { $delFail += "$($pc.Thumbprint): $($_.Exception.Message); " }
            }
            if ($delFail) { [void]$notes.Add("PkiExpired FAIL: removed $delOk of $($prunable.Count) expired retired DoD intermediate(s) from the CA store; errors: " + $delFail.TrimEnd('; ')) }
            else { [void]$notes.Add("PkiExpired FIXED: removed $delOk expired retired DoD intermediate(s) from the CA store (allowlisted DOD EMAIL/ID/SW/DERILITY subjects only; the four legacy-keep intermediates untouched)") }
        }
    } catch { [void]$notes.Add("PkiExpired FAIL: expired-intermediate prune error: " + $_.Exception.Message) }
    }
    # (b) PkiRdp - repair a BROKEN RDP-tcp listener certificate (self-signed / expired /
    #     missing). A healthy CA-issued listener is NEVER touched (silent). Reordered
    #     SAFE for auto-run: the replacement cert (newest valid My-store cert matching
    #     this computer with the Server Authentication EKU 1.3.6.1.5.5.7.3.1) is located
    #     FIRST - with no candidate the listener is left alone (SKIP), nothing cleared.
    if ($DoRdp) {
    try {
        $tsgs = Get-CimInstance -Namespace 'root/cimv2/terminalservices' -ClassName 'Win32_TSGeneralSetting' -Filter "TerminalName='RDP-tcp'" -ErrorAction Stop
        $rdpHash = (([string]$tsgs.SSLCertificateSHA1Hash) -replace '[^0-9A-Fa-f]', '').ToUpper()
        $nowRd = Get-Date
        $lcert = $null
        if ($rdpHash -and $rdpHash -ne ('0' * 40)) {
            foreach ($stN in @('My', 'Remote Desktop')) {
                $lcert = Get-ChildItem "Cert:\LocalMachine\$stN" -ErrorAction SilentlyContinue |
                         Where-Object { ((([string]$_.Thumbprint) -replace '[^0-9A-Fa-f]', '').ToUpper()) -eq $rdpHash } |
                         Select-Object -First 1
                if ($lcert) { break }
            }
        }
        $rdpState = if (-not $lcert) { 'missing' } elseif ($lcert.NotAfter -lt $nowRd) { 'expired' } elseif ($lcert.Subject -eq $lcert.Issuer) { 'self-signed' } else { 'healthy' }
        if ($rdpState -ne 'healthy') {
            $cand = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue | Where-Object {
                (@($_.DnsNameList | ForEach-Object { [string]$_.Unicode } | Where-Object { $_ -eq $env:COMPUTERNAME -or (($_ -split '\.')[0] -eq $env:COMPUTERNAME) }).Count -gt 0) -and $_.NotAfter -gt $nowRd -and $_.HasPrivateKey -and
                @($_.EnhancedKeyUsageList | Where-Object { [string]$_.ObjectId -eq '1.3.6.1.5.5.7.3.1' }).Count -gt 0
            } | Sort-Object NotAfter -Descending | Select-Object -First 1
            if (-not $cand) {
                [void]$notes.Add("PkiRdp SKIP: RDP listener cert is $rdpState but no valid CA-issued My-store cert (Server Auth EKU) matches this host - left untouched")
            } else {
                # Bind FIRST; only on a successful bind do the destructive clears run. On a bind
                # failure the old cert/listener are left intact (FAIL) - no dead-listener window.
                try {
                    Set-CimInstance -InputObject $tsgs -Property @{ SSLCertificateSHA1Hash = [string]$cand.Thumbprint } -ErrorAction Stop | Out-Null
                    Get-ChildItem 'Cert:\LocalMachine\Remote Desktop' -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
                    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations' -Name 'SelfSignedCertStore' -Value '' -Force -ErrorAction SilentlyContinue
                    [void]$notes.Add("PkiRdp FIXED: RDP listener was $rdpState - bound CA-issued cert $($cand.Thumbprint) (expires $($cand.NotAfter.ToShortDateString()))")
                } catch {
                    [void]$notes.Add("PkiRdp FAIL: RDP listener was $rdpState - bind to CA-issued cert $($cand.Thumbprint) FAILED, old cert/listener left intact: $($_.Exception.Message)")
                }
            }
        }
    } catch { [void]$notes.Add("PkiRdp FAIL: RDP listener check/repair error: " + $_.Exception.Message) }
    }
    return @($notes.ToArray())
}
'@
# NOT dot-sourced in module scope: Invoke-CertDeployCompanions touches live machine
# state (cert stores + the RDP listener) with no read-only path, so it must exist
# ONLY on the remote target. Unit tests inspect the source string instead.

# --- READ-ONLY store reader (CHECK worker + unit test) -------------------------
# For each store group, open the LocalMachine store READ-ONLY and, given the bundle
# thumbprints wanted in that store, report present-count + the missing thumbprints.
# NEVER writes a store (OpenFlags::ReadOnly). $StoreOpener is injectable (default =
# a real ReadOnly X509Store) so the read is unit-testable against a fake store.
# $WantThumbs is an object/hashtable with Root/CA/Disallowed thumbprint arrays.
# Returns a pscustomobject { MissRoot; MissCA; MissDis; PresRoot; PresCA; PresDis }.
$script:CertDeployStoreReadSrc = @'
function Get-CertDeployStoreMissing {
    param($WantThumbs, [scriptblock]$StoreOpener)
    if (-not $StoreOpener) {
        $StoreOpener = {
            param($storeName)
            $st = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, 'LocalMachine')
            $st.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
            return $st
        }
    }
    $out = [pscustomobject]@{ MissRoot=@(); MissCA=@(); MissDis=@(); PresRoot=0; PresCA=0; PresDis=0 }
    # F1 (loop48): a want-set with ZERO usable thumbprints means the bundle thumbprints did not
    # deserialize on the target (the bundle always carries certs - Root at minimum). Comparing nothing
    # yields 0 present / 0 missing, which the check worker would read as ALL PRESENT for a host whose
    # stores were NEVER inspected. Fail closed: return an Err so the check row becomes CHECK ERROR.
    $wantCount = 0
    foreach ($p in @('Root','CA','Disallowed')) {
        try { $wantCount += @($WantThumbs.$p | ForEach-Object { (([string]$_) -replace '[^0-9A-Fa-f]','') } | Where-Object { $_ }).Count } catch {}
    }
    if ($wantCount -eq 0) {
        return [pscustomobject]@{ MissRoot=@(); MissCA=@(); MissDis=@(); PresRoot=0; PresCA=0; PresDis=0; Err='want-set empty (bundle thumbprints failed to deserialize on target) - stores NOT compared' }
    }
    foreach ($sm in @(@{ Prop='Root'; Store='Root'; Miss='MissRoot'; Pres='PresRoot' }, @{ Prop='CA'; Store='CA'; Miss='MissCA'; Pres='PresCA' }, @{ Prop='Disallowed'; Store='Disallowed'; Miss='MissDis'; Pres='PresDis' })) {
        $wantTps = @()
        try { $wantTps = @($WantThumbs.($sm.Prop) | ForEach-Object { (([string]$_) -replace '[^0-9A-Fa-f]','') } | Where-Object { $_ }) } catch { $wantTps = @() }
        if ($wantTps.Count -eq 0) { continue }
        $present = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        $st = $null
        try {
            $st = & $StoreOpener $sm.Store
            foreach ($ec in $st.Certificates) { [void]$present.Add((([string]$ec.Thumbprint) -replace '[^0-9A-Fa-f]','')) }
        } catch {} finally { if ($st) { try { $st.Close() } catch {} } }
        $miss = New-Object System.Collections.ArrayList
        $presN = 0
        foreach ($tp in $wantTps) { if ($present.Contains($tp)) { $presN++ } else { [void]$miss.Add($tp) } }
        $out.($sm.Miss) = @($miss.ToArray())
        $out.($sm.Pres) = [int]$presN
    }
    return $out
}
'@
try { . ([scriptblock]::Create($script:CertDeployStoreReadSrc)) } catch {}

# Pure admin-side row builder for the CHECK result (no WinRM). Turns a worker result
# into the display row (Status ALL PRESENT / MISSING N / OFFLINE / CHECK ERROR, the
# Missing cell, and a Detail with per-store counts + example missing subjects).
function Get-CertDeployCheckRow {
    param($Res, [int]$BundleCertCount, $SubjectMap, [string[]]$LegacyInBundleCa = @())
    $status = [string]$Res.Status
    $detail = [string]$Res.Detail
    $missTotal = 0
    $missCell = ''
    $ok = $false
    try { $ok = [bool]$Res.Ok } catch { $ok = $false }
    if ($ok) {
        $mr = @($Res.MissRoot); $mc = @($Res.MissCA); $md = @($Res.MissDis)
        $missTotal = $mr.Count + $mc.Count + $md.Count
        $missCell = [string]$missTotal
        if ($missTotal -eq 0) {
            $status = 'ALL PRESENT'
            $detail = "all $BundleCertCount root(s) present (Root $($Res.PresRoot)/CA $($Res.PresCA)/Disallowed $($Res.PresDis))"
        } else {
            $status = "MISSING $missTotal"
            $ex = New-Object System.Collections.ArrayList
            foreach ($tp in @($mr + $mc + $md)) {
                $key = (([string]$tp) -replace '[^0-9A-Fa-f]','')
                $subj = if ($SubjectMap -and $SubjectMap.ContainsKey($key)) { [string]$SubjectMap[$key] } else { $key }
                if ($ex.Count -lt 3) { [void]$ex.Add($subj) }
            }
            $detail = "Root $($mr.Count) / CA $($mc.Count) / Disallowed $($md.Count) missing"
            if ($ex.Count -gt 0) { $detail += " - e.g. " + ($ex -join '; ') }
        }
    }
    # Legacy intermediates (allowlisted expired CAs, LocalMachine\CA): report present/total
    # for exactly the four. They are bundle-wanted, so each is either present or in MissCA;
    # blank when the host could not be read (offline / check error).
    # Legacy intermediates present/total: ONLY the allowlisted legacy certs actually in THIS
    # bundle's CA group ($LegacyInBundleCa, computed admin-side from the resolved bundle). This
    # avoids a false "4/4" when a custom certBundleFolder lacks them (or has them under root\
    # rather than Intermediate\): certs not in the CA want-set can never be in MissCA. Blank
    # when the host could not be read or no legacy certs are in this bundle's CA group.
    $legacyCell = ''
    $legInBundle = @($LegacyInBundleCa | ForEach-Object { (([string]$_) -replace '[^0-9A-Fa-f]','').ToUpperInvariant() } | Where-Object { $_ })
    if ($ok -and $legInBundle.Count -gt 0) {
        $missCaSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($tp in @($Res.MissCA)) { [void]$missCaSet.Add((([string]$tp) -replace '[^0-9A-Fa-f]','')) }
        $total = $legInBundle.Count
        $missNames = New-Object System.Collections.ArrayList
        foreach ($k in $legInBundle) {
            if ($missCaSet.Contains($k)) {
                $nm = if ($script:CertDeployLegacyIntermediates.Contains($k)) { [string]$script:CertDeployLegacyIntermediates[$k] } else { $k }
                [void]$missNames.Add($nm)
            }
        }
        $legacyCell = "$($total - $missNames.Count)/$total"
        if ($missNames.Count -gt 0) { $detail += "  |  Legacy CA missing: $($missNames -join ', ')" }
    }
    return @{ Host=[string]$Res.Host; Ping=[string]$Res.Ping; Status=$status; Missing=$missCell; Legacy=$legacyCell; Detail=$detail }
}

# --- scan-cert-management verdict + row builder (pure, admin-side) -------------
# Reconciler verdict per SHARED CONTRACT: InstallRoot present -> 'InstallRoot' (or
# 'InstallRoot+GPO' when the GPO physical Root/CA store also holds entries); else
# GPRoots>0 -> 'GPO'; else 'None detected' (a manual .Default push WILL persist).
function Get-CertDeployReconcilerVerdict {
    param([bool]$InstallRoot, [int]$GpRoots)
    if ($InstallRoot) {
        if ($GpRoots -gt 0) { return 'InstallRoot+GPO' }
        return 'InstallRoot'
    }
    if ($GpRoots -gt 0) { return 'GPO' }
    return 'None detected'
}

# Turn a scan worker result into the display row (Reconciler verdict + evidence
# Detail). OFFLINE / CHECK ERROR pass through as the Reconciler cell per contract.
function Get-CertDeployScanRow {
    param($Res)
    $hostName = [string]$Res.Host
    $ping     = [string]$Res.Ping
    $ok = $false
    try { $ok = [bool]$Res.Ok } catch { $ok = $false }
    if (-not $ok) {
        $st  = [string]$Res.Status
        $rec = if ($st -eq 'OFFLINE') { 'OFFLINE' } else { 'CHECK ERROR' }
        return @{ Host=$hostName; Ping=$ping; InstallRoot=''; GPRoots=''; Reconciler=$rec; Detail=[string]$Res.Detail }
    }
    $irPresent = [bool]$Res.InstallRootPresent
    $gp        = [int]$Res.GpRoots
    $verdict   = Get-CertDeployReconcilerVerdict -InstallRoot $irPresent -GpRoots $gp
    $detail    = "InstallRoot: $([string]$Res.InstallRootToken); GPO roots: $gp; LocalMachine Root store holds $([int]$Res.DefaultRootCount) cert(s)."
    if ($verdict -ne 'None detected') {
        $mech = if ($irPresent -and $gp -gt 0) { 'InstallRoot/GPO' } elseif ($irPresent) { 'InstallRoot' } else { 'GPO' }
        $detail += " This host reconciles its trust store - a scripted push may be pruned on reboot; align with $mech."
    } else {
        $detail += " No reconciler detected - a manual .Default push WILL persist."
    }
    return @{ Host=$hostName; Ping=$ping; InstallRoot=[string]$Res.InstallRootToken; GPRoots=[string]$gp; Reconciler=$verdict; Detail=$detail }
}

# --- Self-guard (COPIED from JanetWeb.c2c.psm1) ------------------------------
# Set of identities that resolve to THIS dispatcher host. A deploy that wrote to the
# box running JANET could disrupt the server mid-run, so the dispatcher is dropped
# from every deploy run (read-only Check does not need it, but shares the helper).
function Get-JanetCertDeployLocalIdentity {
    if ($script:CertDeployLocalIdentity) { return $script:CertDeployLocalIdentity }
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($n in @($env:COMPUTERNAME, 'localhost', '127.0.0.1', '::1')) { if ($n) { [void]$set.Add($n) } }
    try { [void]$set.Add([System.Net.Dns]::GetHostName()) } catch {}
    try {
        $fqdn = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName
        if ($fqdn) { [void]$set.Add($fqdn); [void]$set.Add(($fqdn -split '\.')[0]) }
    } catch {}
    try { foreach ($ip in [System.Net.Dns]::GetHostAddresses($env:COMPUTERNAME)) { [void]$set.Add($ip.IPAddressToString) } } catch {}
    try {
        foreach ($nic in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
            if ($nic.OperationalStatus -ne [System.Net.NetworkInformation.OperationalStatus]::Up) { continue }
            foreach ($ua in $nic.GetIPProperties().UnicastAddresses) {
                if ($ua.Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { [void]$set.Add($ua.Address.IPAddressToString) }
            }
        }
    } catch {}
    $script:CertDeployLocalIdentity = $set
    return $set
}

function Test-JanetCertDeployHostIsSelf {
    param([string]$Target)
    if ([string]::IsNullOrWhiteSpace($Target)) { return $false }
    $self = Get-JanetCertDeployLocalIdentity
    if ($self.Contains($Target)) { return $true }
    if ($Target -match '^127\.') { return $true }
    if ($Target -match '^::1$')  { return $true }
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($Target, [ref]$ip)) {
        if ($self.Contains(($Target -split '\.')[0])) { return $true }
    }
    return $false
}

# --- Bool coercion (view sends real bools; CLI/tests may send strings) --------
function Get-CertDeployBool {
    param($Value, [bool]$Default)
    if ($null -eq $Value) { return $Default }
    if ($Value -is [bool]) { return [bool]$Value }
    if ("$Value" -eq '') { return $Default }
    return (@('true','1','yes','on') -contains ([string]$Value).Trim().ToLowerInvariant())
}

# =============================================================================
#  import-pki-hosts: parse the Tanium "C2C Compliance Status" CSV (PKI detection)
#  Reuses the c2c parse APPROACH (Import-Csv handles the multiline quoted Compliance
#  cell; split it into lines; strip the "Failed/Audit Rule[ N] - " prefix). A host is
#  PKI-TAGGED if ANY compliance line (audit OR failed) names "PKI Trust Roots",
#  regardless of the host's overall Compliant / Non-Compliant verdict.
# =============================================================================
function Test-CertDeployPkiLine {
    param([string]$Line)
    $s = [string]$Line
    if ($s -match '(?i)^(Failed|Audit)\s+Rule(\s+\d+)?\s*-\s*(.+)$') { $s = $Matches[3] }
    return ([string]$s).Trim() -match '(?i)^PKI Trust Roots$'
}

# Returns @{ Records=@(@{Short;Fqdn;Compliance;Pki=$bool}); RowCount=int }. Dedup by
# short host: a PKI-tagged row always wins; otherwise the first row is kept.
function ConvertFrom-CertDeployComplianceCsv {
    param([string[]]$Paths, [string]$Text, [scriptblock]$Send)

    $allRows = New-Object System.Collections.ArrayList
    foreach ($path in @($Paths | Where-Object { $_ })) {
        $pp = ([string]$path).Trim().Trim('"')
        if (-not $pp) { continue }
        if (-not (Test-Path -LiteralPath $pp)) {
            if ($Send) { & $Send @{ type='log'; level='warn'; text="File not found: $pp" } }
            continue
        }
        try {
            foreach ($r in (Import-Csv -LiteralPath $pp -Encoding UTF8 -ErrorAction Stop)) { [void]$allRows.Add($r) }
        } catch {
            if ($Send) { & $Send @{ type='log'; level='err'; text="Failed to parse '$pp': $($_.Exception.Message)" } }
        }
    }
    if ($Text -and -not [string]::IsNullOrWhiteSpace($Text)) {
        try { foreach ($r in (ConvertFrom-Csv $Text)) { [void]$allRows.Add($r) } }
        catch { if ($Send) { & $Send @{ type='log'; level='err'; text="Failed to parse pasted CSV: $($_.Exception.Message)" } } }
    }

    # Locate the Compliance + Computer Name columns (tolerate header variants).
    $complCol = $null; $hostCol = $null
    if ($allRows.Count -gt 0) {
        foreach ($p in $allRows[0].PSObject.Properties.Name) {
            if (-not $complCol -and $p -match '(?i)Compliance$')     { $complCol = $p }
            if (-not $hostCol  -and $p -match '(?i)Computer Name$')  { $hostCol  = $p }
        }
    }
    if (-not $complCol) { $complCol = 'C2C Compliance Status:Compliance' }
    if (-not $hostCol)  { $hostCol  = 'Computer Name' }

    $recs = New-Object System.Collections.ArrayList
    foreach ($r in $allRows) {
        $cp = $r.PSObject.Properties[$complCol]
        $hp = $r.PSObject.Properties[$hostCol]
        $complVal = if ($cp) { [string]$cp.Value } else { '' }
        $fqdn     = if ($hp) { ([string]$hp.Value).Trim() } else { '' }
        if (-not $fqdn) { continue }
        $short = ($fqdn -split '\.')[0]
        # Whitelist the short token before it can become a remote target.
        if ($short -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$') { continue }

        $lines = @([regex]::Split($complVal, '\r\n|\n|\r') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        if ($lines.Count -eq 0) { continue }
        $compliance = if     ($lines[0] -match '(?i)^Non-?Compliant') { 'Non-Compliant' }
                      elseif ($lines[0] -match '(?i)^Compliant')      { 'Compliant' }
                      else                                            { [string]$lines[0] }

        # PKI-tagged if ANY compliance line (after the first verdict line) names the
        # PKI Trust Roots rule - audit OR failed, regardless of the verdict.
        $pki = $false
        foreach ($ln in (@($lines) | Select-Object -Skip 1)) {
            if (Test-CertDeployPkiLine $ln) { $pki = $true; break }
        }

        [void]$recs.Add([pscustomobject]@{ Short=$short; Fqdn=$fqdn; Compliance=$compliance; Pki=$pki })
    }

    # Dedup by short host - a PKI-tagged row wins; else first row kept.
    $byHost = @{}
    foreach ($rec in $recs) {
        $key = $rec.Short.ToUpperInvariant()
        if (-not $byHost.ContainsKey($key)) { $byHost[$key] = $rec; continue }
        if ($rec.Pki -and -not $byHost[$key].Pki) { $byHost[$key] = $rec }
    }
    return @{ Records=@($byHost.Values); RowCount=$allRows.Count }
}

function Invoke-CertDeployImportAction {
    param([hashtable]$Params, [scriptblock]$Emit)
    $send = { param($e) if ($Emit) { & $Emit $e } }

    $csvPath = [string]$Params['csvPath']
    $csvText = [string]$Params['csvText']
    $paths = @()
    if ($csvPath) { $paths = @($csvPath -split '[\r\n]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
    if ($paths.Count -eq 0 -and [string]::IsNullOrWhiteSpace($csvText)) {
        & $send @{ type='log'; level='warn'; text='No CSV file selected and no CSV text pasted.' }
        return @{ rows=@(); summary=@{ total=0; pkiTagged=0; hosts=@() } }
    }

    & $send @{ type='status'; text='Parsing C2C Compliance CSV for PKI-tagged hosts...' }
    $parsed = ConvertFrom-CertDeployComplianceCsv -Paths $paths -Text $csvText -Send $send
    $recs = @($parsed.Records)
    if ($recs.Count -eq 0) {
        & $send @{ type='log'; level='warn'; text="Parsed $($parsed.RowCount) row(s) but resolved no hosts - check the CSV headers (a 'Compliance' column and a 'Computer Name' column)." }
        return @{ rows=@(); summary=@{ total=0; pkiTagged=0; hosts=@() } }
    }

    $pkiRecs = @($recs | Where-Object { $_.Pki })
    $rows = New-Object System.Collections.ArrayList
    foreach ($rec in ($pkiRecs | Sort-Object { $_.Short })) {
        $row = @{ Host=$rec.Short; Compliance=$rec.Compliance; Pki='PKI tag'; Fqdn=$rec.Fqdn }
        [void]$rows.Add($row)
        & $send (@{ type='row' } + $row)
    }

    $hosts = @($pkiRecs | ForEach-Object { $_.Short } | Select-Object -Unique)
    $compliant    = @($pkiRecs | Where-Object { $_.Compliance -notmatch '(?i)Non-?Compliant' }).Count
    $nonCompliant = @($pkiRecs | Where-Object { $_.Compliance -match '(?i)Non-?Compliant' }).Count
    & $send @{ type='log'; level='ok'; text="Found $($hosts.Count) PKI-tagged host(s) of $($recs.Count) parsed ($compliant compliant, $nonCompliant non-compliant). All carry the PKI Trust Roots tag - deploy the roots to get ahead of non-compliance." }
    & $send @{ type='status'; text="Imported $($hosts.Count) PKI-tagged host(s)." }
    return @{ rows=@($rows); summary=@{ total=$recs.Count; pkiTagged=$hosts.Count; compliant=$compliant; nonCompliant=$nonCompliant; hosts=@($hosts) } }
}

# =============================================================================
#  check (READ-ONLY): per-host worker + fan-out. Opens each LocalMachine store
#  READ-ONLY and reports which bundle roots are MISSING per store. NEVER writes.
# =============================================================================
$script:CertDeployCheckBlock = {
    param([string]$Computer, $Cred, [string]$Auth, [bool]$AttemptOffline, [string]$ThumbJson, [string]$StoreReadSrc)

    $r = @{ Host=$Computer; Ping=''; Status=''; MissRoot=@(); MissCA=@(); MissDis=@(); PresRoot=0; PresCA=0; PresDis=0; Ok=$false; Detail='' }

    # Reachability: pure-TCP probe (AFNET-safe; never ICMP). WinRM HTTP 5985, then WinRM
    # HTTPS 5986, then SMB 445 (liveness only), 1.5s, break on first connect. $useSsl
    # tracks whether ONLY 5986 answered so the session below auto-switches to -UseSSL
    # (HTTP 5985 is preferred when both are open).
    $reachable = $false; $useSsl = $false
    foreach ($port in 5985,5986,445) {
        $tc = $null
        try {
            $tc = New-Object System.Net.Sockets.TcpClient
            $iar = $tc.BeginConnect($Computer, $port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(1500, $false) -and $tc.Connected) { $reachable = $true; $r.Ping = "TCP $port"; if ($port -eq 5986) { $useSsl = $true } }
        } catch {} finally { if ($tc) { try { $tc.Close() } catch {} } }
        if ($reachable) { break }
    }
    if (-not $reachable) {
        $r.Ping = 'Unreachable'
        if (-not $AttemptOffline) {
            $r.Status = 'OFFLINE'; $r.Detail = 'No TCP on 5985/5986/445 (1.5s timeouts). Enable "Attempt even if offline" to force.'
            return $r
        }
    }

    # -UseSSL only when the host answered ONLY on 5986 (self-signed WinRM HTTPS is common on
    # AFNET, so skip CA/CN validation - the transport stays encrypted; port 5986 is implicit).
    $soP = @{ OperationTimeout=120000; OpenTimeout=15000; CancelTimeout=5000; IdleTimeout=60000 }
    if ($useSsl) { $soP['SkipCACheck']=$true; $soP['SkipCNCheck']=$true }
    $wsOpt = New-PSSessionOption @soP
    $splat = @{ ComputerName=$Computer; SessionOption=$wsOpt; ErrorAction='Stop' }
    if ($useSsl) { $splat['UseSSL']=$true }
    if ($Cred) { $splat['Credential']=$Cred; $splat['Authentication']=$Auth }
    $sess = $null
    try { $sess = New-PSSession @splat } catch { $r.Status = 'CHECK ERROR'; $r.Detail = "Session: $($_.Exception.Message)"; return $r }

    # Wrong-box SOFT-skip (read-only path never writes anyway): if the answering box's
    # name does not match the dialed short name, flag CHECK ERROR and do not report its
    # (wrong) store contents. IP-literal targets have no DNS indirection.
    try {
        $expectedShort = if ($Computer -match '^\d{1,3}(\.\d{1,3}){3}$') { '' } else { ($Computer -split '\.')[0] }
        if ($expectedShort) {
            $answering = Invoke-Command -Session $sess -ScriptBlock { $env:COMPUTERNAME } -ErrorAction Stop
            if (([string]$answering).Trim().ToUpper() -ne $expectedShort.Trim().ToUpper()) {
                Remove-PSSession $sess -ErrorAction SilentlyContinue
                $r.Status = 'CHECK ERROR'; $r.Detail = "DNS MISMATCH: dialed '$expectedShort' but remote is '$answering' - soft-skipped, nothing read"
                return $r
            }
        }
    } catch {
        Remove-PSSession $sess -ErrorAction SilentlyContinue
        $r.Status = 'CHECK ERROR'; $r.Detail = "wrong-box guard probe failed: $($_.Exception.Message)"; return $r
    }

    # The consolidated READ-ONLY probe: dot-source the injectable store reader, parse
    # the wanted thumbprints, and open each store ReadOnly to report present/missing.
    # Get-CertDeployStoreMissing opens with OpenFlags::ReadOnly - never writes a store.
    $checkSb = {
        param([string]$ThumbJson, [string]$StoreReadSrc)
        if ($StoreReadSrc) { try { . ([scriptblock]::Create($StoreReadSrc)) } catch {} }
        $want = $null; try { $want = $ThumbJson | ConvertFrom-Json } catch { $want = $null }
        if (-not (Get-Command Get-CertDeployStoreMissing -ErrorAction SilentlyContinue)) {
            return [pscustomobject]@{ MissRoot=@(); MissCA=@(); MissDis=@(); PresRoot=0; PresCA=0; PresDis=0; Err='store reader helper unavailable on target' }
        }
        return (Get-CertDeployStoreMissing -WantThumbs $want)
    }

    $raw = $null
    try { $raw = Invoke-Command -Session $sess -ScriptBlock $checkSb -ArgumentList $ThumbJson, $StoreReadSrc -ErrorAction Stop }
    catch { $r.Status = 'CHECK ERROR'; $r.Detail = "Probe: $($_.Exception.Message)"; Remove-PSSession $sess -ErrorAction SilentlyContinue; return $r }
    finally { if ($sess) { Remove-PSSession $sess -ErrorAction SilentlyContinue } }

    if ($null -eq $raw) { $r.Status = 'CHECK ERROR'; $r.Detail = 'probe returned no result'; return $r }
    # Honor the remote reader's Err sentinel (e.g. WDAC / constrained-language mode blocked
    # the dot-source of the store reader). Never report a store we never actually read as
    # ALL PRESENT - that would silently skip deploying roots to an uninspected host.
    $errTxt = ''
    try { if ($raw.PSObject.Properties['Err']) { $errTxt = [string]$raw.Err } } catch {}
    if ($errTxt) { $r.Status = 'CHECK ERROR'; $r.Detail = $errTxt; return $r }
    $r.MissRoot = @($raw.MissRoot); $r.MissCA = @($raw.MissCA); $r.MissDis = @($raw.MissDis)
    $r.PresRoot = [int]$raw.PresRoot; $r.PresCA = [int]$raw.PresCA; $r.PresDis = [int]$raw.PresDis
    $r.Ok = $true
    return $r
}

function Invoke-CertDeployCheckAction {
    param([hashtable]$Params, [System.Management.Automation.PSCredential]$Credential, [scriptblock]$Emit)
    $send = { param($e) if ($Emit) { & $Emit $e } }

    $cancelJob = $null
    if ($Params -and $Params.ContainsKey('__job')) { $cancelJob = $Params['__job'] }
    $cancelCheck = { if ($cancelJob) { try { [bool]$cancelJob['Cancel'] } catch { $false } } else { $false } }.GetNewClosure()

    # Read the bundle admin-side ONCE (blank folder -> shipped default). Abort if empty.
    $resolved = Resolve-CertDeployBundleFolder ([string]$Params['certBundleFolder'])
    $bundleFolder = [string]$resolved.Folder
    $bundleSource = [string]$resolved.Source
    if ([string]::IsNullOrWhiteSpace($bundleFolder)) {
        & $send @{ type='log'; level='err'; text="Check aborted: no cert bundle folder supplied and the shipped default ($(Get-CertDeployDefaultBundlePath)) is missing or has no .cer files." }
        return @{ rows=@(); summary=@{ total=0; rejected=$true } }
    }
    $bundle = Get-CertDeployBundle -Folder $bundleFolder
    if (-not $bundle.Ok) {
        & $send @{ type='log'; level='err'; text="Check aborted: $($bundle.Error)." }
        return @{ rows=@(); summary=@{ total=0; rejected=$true } }
    }
    $thumbJson  = Convert-CertDeployBundleToThumbJson $bundle
    $subjectMap = Get-CertDeploySubjectMap $bundle
    # The allowlisted legacy intermediates that are ACTUALLY in THIS bundle's CA group - the
    # only ones the per-host Legacy column may report (avoids a false 4/4 on a bundle lacking them).
    $bundleCaTp = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($c in @($bundle.CA)) { if ($c) { [void]$bundleCaTp.Add((([string]$c.Thumbprint) -replace '[^0-9A-Fa-f]','')) } }
    $legacyInBundleCa = @($script:CertDeployLegacyIntermediates.Keys | Where-Object { $bundleCaTp.Contains([string]$_) })
    & $send @{ type='log'; level='info'; text="Cert bundle: $($bundle.CertCount) cert(s) [Root $(@($bundle.Root).Count)/CA $(@($bundle.CA).Count)/Disallowed $(@($bundle.Disallowed).Count)] from $($bundle.Folder) [$bundleSource]." }
    # Always surface the bundle's expired-cert census (SHARED CONTRACT), regardless of
    # includeExpired - Check is the read-only truth about dead anchors in the bundle.
    $expiredCount = [int]$bundle.ExpiredCount
    if ($expiredCount -gt 0) {
        $expSubs = @(@($bundle.Expired) | ForEach-Object { [string]$_.Subject })
        & $send @{ type='log'; level='warn'; text="Bundle contains $expiredCount EXPIRED cert(s) (dead trust anchors, not allowlisted): $($expSubs -join '; '). Deploy EXCLUDES these by default." }
    } else {
        & $send @{ type='log'; level='info'; text='Bundle contains 0 expired cert(s) - all trust anchors are within validity.' }
    }
    $legacyCount = [int]$bundle.LegacyAllowedCount
    if ($legacyCount -gt 0) {
        $legSubs = @(@($bundle.LegacyAllowed) | ForEach-Object { [string]$_.Subject })
        & $send @{ type='log'; level='info'; text="Bundle contains $legacyCount expired-but-ALLOWLISTED legacy intermediate(s) (LegacyIntermediates - kept for legacy chain validation, Deploy pushes these): $($legSubs -join '; '). Legacy column shows present/total per host." }
    }

    $targets = @(([string]$Params['targets']) -split '[\r\n,;\t ]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ -and ($_ -match '^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$') } | Select-Object -Unique)
    if ($targets.Count -eq 0) {
        & $send @{ type='log'; level='warn'; text='No valid targets.' }
        return @{ rows=@(); summary=@{ total=0; expiredCount=$expiredCount } }
    }

    $attemptOffline = Get-CertDeployBool $Params['attemptOffline'] $false
    $threads = 16
    if ($Params['threads']) { [int]::TryParse([string]$Params['threads'], [ref]$threads) | Out-Null }
    $threads = [Math]::Max(1, [Math]::Min(32, $threads))
    $perHostTimeout = 150
    $auth = if ($Credential) { 'Negotiate' } else { 'Default' }
    $authLabel = if ($Credential) { "as $($Credential.UserName)" } else { 'current session' }

    & $send @{ type='status'; text="Checking trust certs on $($targets.Count) host(s) with $threads thread(s)..." }
    & $send @{ type='log'; level='info'; text="[$(Get-Date -Format 'HH:mm:ss')] START Cert Check on $($targets.Count) host(s) ($authLabel), $threads thread(s)." }

    $iss  = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $threads, $iss, $Host)
    $pool.Open()
    foreach ($h in $targets) { & $send (@{ type='row' } + @{ Host=$h; Ping=''; Status='Queued'; Missing=''; Legacy=''; Detail='waiting for a runspace...' }) }
    $jobs = New-Object System.Collections.ArrayList
    foreach ($h in $targets) {
        $ps = [powershell]::Create(); $ps.RunspacePool = $pool
        [void]$ps.AddScript($script:CertDeployCheckBlock)
        [void]$ps.AddArgument($h); [void]$ps.AddArgument($Credential); [void]$ps.AddArgument($auth); [void]$ps.AddArgument($attemptOffline); [void]$ps.AddArgument($thumbJson); [void]$ps.AddArgument($script:CertDeployStoreReadSrc)
        [void]$jobs.Add([pscustomobject]@{ Host=$h; PS=$ps; Async=$ps.BeginInvoke(); StartedAt=$null })
    }

    $rows = New-Object System.Collections.ArrayList

    $emitResult = {
        param($res)
        $row = Get-CertDeployCheckRow -Res $res -BundleCertCount ([int]$bundle.CertCount) -SubjectMap $subjectMap -LegacyInBundleCa $legacyInBundleCa
        $status = [string]$row.Status
        # informative-failures (loop81): a CHECK ERROR carries the raw probe/session/DNS error in Detail on
        # this read-only path; turn it into a why+how-to-fix hint. ALL PRESENT/MISSING/OFFLINE self-explain.
        $hint = if ($status -eq 'CHECK ERROR' -and $row.Detail) { Get-JanetTroubleshootHint -Message ([string]$row.Detail) -Server ([string]$row.Host) } else { '' }
        if ($hint) { $row['Hint'] = [string]$hint }
        [void]$rows.Add($row)
        & $send (@{ type='row' } + $row)
        $lvl = 'info'
        if     ($status -eq 'ALL PRESENT') { $lvl = 'ok' }
        elseif ($status -like 'MISSING*')  { $lvl = 'warn' }
        elseif ($status -eq 'OFFLINE')     { $lvl = 'warn' }
        elseif ($status -eq 'CHECK ERROR') { $lvl = 'error' }
        & $send @{ type='log'; level=$lvl; text="[$(Get-Date -Format 'HH:mm:ss')] $([string]$row.Host) : $status - $([string]$row.Detail)" }
        if ($hint) { & $send @{ type='log'; level='err'; text="$([string]$row.Host) : $status - $([string]$row.Detail) | FIX: $hint" } }
    }

    $done = 0
    try {
        while ($done -lt $jobs.Count) {
            # Cap the per-host clock to the pool's real concurrency, stamping in queue order:
            # a PS queued in a saturated RunspacePool reports State='Running' immediately, so the
            # old InvocationStateInfo check stamped StartedAt at ENQUEUE for every job and the
            # watchdog then falsely timed out the whole backlog at once (~threads*timeout hosts in).
            $activeCount = @($jobs | Where-Object { $_.PS -and $_.StartedAt }).Count
            foreach ($j in $jobs) {
                if ($j.PS -and -not $j.StartedAt -and $activeCount -lt $pool.GetMaxRunspaces()) { $j.StartedAt = Get-Date; $activeCount++ }
                if ($j.PS -and $j.Async.IsCompleted) {
                    $res = $null
                    try { $res = $j.PS.EndInvoke($j.Async) | Select-Object -First 1 }
                    catch { $res = @{ Host=$j.Host; Ping=''; Status='CHECK ERROR'; Detail="worker error: $($_.Exception.Message)"; Ok=$false } }
                    try { $j.PS.Dispose() } catch {}; $j.PS = $null
                    if ($null -eq $res) { $res = @{ Host=$j.Host; Ping=''; Status='CHECK ERROR'; Detail='worker returned no result'; Ok=$false } }
                    & $emitResult $res
                    $done++; & $send @{ type='progress'; done=$done; total=$jobs.Count }
                }
            }
            if ($done -lt $jobs.Count) {
                $nowPh = Get-Date
                foreach ($j in $jobs) {
                    if ($j.PS -and $j.StartedAt -and ($nowPh - $j.StartedAt).TotalSeconds -gt $perHostTimeout) {
                        try { [void]$j.PS.BeginStop($null, $null) } catch {}; $j.PS = $null
                        & $emitResult @{ Host=$j.Host; Ping=''; Status='CHECK ERROR'; Detail="per-host timeout (${perHostTimeout}s) - possible remote read hang"; Ok=$false }
                        $done++; & $send @{ type='progress'; done=$done; total=$jobs.Count }
                    }
                }
            }
            if ($done -lt $jobs.Count) {
                if ($cancelCheck -and (& $cancelCheck)) {
                    foreach ($j in $jobs) {
                        if ($j.PS) {
                            try { [void]$j.PS.BeginStop($null, $null) } catch {}; $j.PS = $null
                            & $emitResult @{ Host=$j.Host; Ping=''; Status='Cancelled'; Detail='cancelled by operator'; Ok=$false }
                            $done++
                        }
                    }
                    & $send @{ type='log'; level='warn'; text='Run cancelled by operator; in-flight checks stopped.' }
                    break
                }
                Start-Sleep -Milliseconds 150
            }
        }
    } finally { try { $pool.Close(); $pool.Dispose() } catch {} }

    $allPresent = @($rows | Where-Object { $_.Status -eq 'ALL PRESENT' }).Count
    $missing    = @($rows | Where-Object { [string]$_.Status -like 'MISSING*' }).Count
    $offline    = @($rows | Where-Object { $_.Status -eq 'OFFLINE' }).Count
    $errors     = @($rows | Where-Object { $_.Status -eq 'CHECK ERROR' }).Count
    & $send @{ type='log'; level='ok'; text="Cert Check done - ALL PRESENT: $allPresent, MISSING: $missing, OFFLINE: $offline, CHECK ERROR: $errors (of $($targets.Count) host(s))." }
    & $send @{ type='status'; text="Done. $allPresent all-present, $missing missing, $offline offline of $($targets.Count)." }
    return @{ rows=@($rows); summary=@{ total=$targets.Count; allPresent=$allPresent; missing=$missing; offline=$offline; checkErrors=$errors; expiredCount=$expiredCount; source=$bundleSource } }
}

# =============================================================================
#  deploy (DESTRUCTIVE): per-host worker + fan-out. ADDITIVELY installs the bundle
#  into Root/CA/Disallowed over WinRM. Confirm word DEPLOY + admin session + self-
#  guard + wrong-box HARD abort + per-host watchdog + operator cancel.
# =============================================================================
$script:CertDeployDeployBlock = {
    param([string]$Computer, $Cred, [string]$Auth, [bool]$AttemptOffline, [string]$BundleJson, [string]$AddCertsSrc, [bool]$DoPrune, [bool]$DoRdp, [string]$CompanionsSrc)
    $RunCompanions = ($DoPrune -or $DoRdp)

    $r = @{ Host=$Computer; Ping=''; Status=''; Missing=''; Detail=''; Added=0; Total=0 }

    # TCP reachability (WinRM HTTP 5985, then WinRM HTTPS 5986, then SMB 445 liveness,
    # 1.5s, break on first connect). Never ICMP. $useSsl tracks whether ONLY 5986
    # answered so the session below auto-switches to -UseSSL (5985 preferred when both open).
    $reachable = $false; $useSsl = $false
    foreach ($port in 5985,5986,445) {
        $tc = $null
        try {
            $tc = New-Object System.Net.Sockets.TcpClient
            $iar = $tc.BeginConnect($Computer, $port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(1500, $false) -and $tc.Connected) { $reachable = $true; $r.Ping = "TCP $port"; if ($port -eq 5986) { $useSsl = $true } }
        } catch {} finally { if ($tc) { try { $tc.Close() } catch {} } }
        if ($reachable) { break }
    }
    if (-not $reachable) {
        $r.Ping = 'Unreachable'
        if (-not $AttemptOffline) { $r.Status = 'OFFLINE'; $r.Detail = 'No TCP on 5985/5986/445 (1.5s timeouts). Enable "Attempt even if offline" to force.'; return $r }
    }

    # -UseSSL only when the host answered ONLY on 5986 (self-signed WinRM HTTPS is common on
    # AFNET, so skip CA/CN validation - the transport stays encrypted; port 5986 is implicit).
    $soP = @{ OperationTimeout=180000; OpenTimeout=15000; CancelTimeout=5000; IdleTimeout=60000 }
    if ($useSsl) { $soP['SkipCACheck']=$true; $soP['SkipCNCheck']=$true }
    $wsOpt = New-PSSessionOption @soP
    $splat = @{ ComputerName=$Computer; SessionOption=$wsOpt; ErrorAction='Stop' }
    if ($useSsl) { $splat['UseSSL']=$true }
    if ($Cred) { $splat['Credential']=$Cred; $splat['Authentication']=$Auth }
    $sess = $null
    try { $sess = New-PSSession @splat } catch { $r.Status = 'FAILED'; $r.Detail = "Session: $($_.Exception.Message)"; return $r }

    # Wrong-box guard (HARD ABORT, before any change): compare the answering box's
    # name to the dialed short name. IP-literal targets have no DNS indirection.
    try {
        $expectedShort = if ($Computer -match '^\d{1,3}(\.\d{1,3}){3}$') { '' } else { ($Computer -split '\.')[0] }
        if ($expectedShort) {
            $answering = Invoke-Command -Session $sess -ScriptBlock { $env:COMPUTERNAME } -ErrorAction Stop
            if (([string]$answering).Trim().ToUpper() -ne $expectedShort.Trim().ToUpper()) {
                Remove-PSSession $sess -ErrorAction SilentlyContinue
                $r.Status = 'SKIPPED'; $r.Detail = "DNS MISMATCH: dialed '$expectedShort' but remote is '$answering' - ABORTED, nothing changed"
                return $r
            }
        }
    } catch {
        Remove-PSSession $sess -ErrorAction SilentlyContinue
        $r.Status = 'FAILED'; $r.Detail = "wrong-box guard probe failed: $($_.Exception.Message)"; return $r
    }

    # ADDITIVE install: deliver base64 certs grouped by store as JSON; the remote side
    # dot-sources Add-CertDeployBundleToStores and adds only-missing (NEVER removes).
    $installSb = {
        param([string]$BundleJson, [string]$AddCertsSrc, [bool]$DoPrune, [bool]$DoRdp, [string]$CompanionsSrc)
        $RunCompanions = ($DoPrune -or $DoRdp)
        $bundle = $null
        if ($BundleJson) { try { $bundle = $BundleJson | ConvertFrom-Json } catch { $bundle = $null } }
        if ($AddCertsSrc) { try { . ([scriptblock]::Create($AddCertsSrc)) } catch {} }
        if (-not $bundle) { return [pscustomobject]@{ Token='FAIL'; Added=0; Already=0; Total=0; PerStore=@(); FailDetail='no cert bundle delivered to the worker'; Companions=@() } }
        if (-not (Get-Command Add-CertDeployBundleToStores -ErrorAction SilentlyContinue)) { return [pscustomobject]@{ Token='FAIL'; Added=0; Already=0; Total=0; PerStore=@(); FailDetail='cert-store installer helper unavailable on target'; Companions=@() } }
        $ar  = Add-CertDeployBundleToStores -Bundle $bundle
        $tok = if (Get-Command Get-CertDeployResultToken -ErrorAction SilentlyContinue) { Get-CertDeployResultToken $ar }
               elseif ([string]$ar.FailDetail) { 'FAIL' } elseif (@($ar.NotVerified).Count -gt 0) { 'NOT VERIFIED' } elseif ([int]$ar.Added -gt 0) { 'INSTALLED' } else { 'ALREADY' }
        # OPT-IN v1.9 companions (prune expired retired intermediates + RDP listener repair),
        # AFTER the install in the same round-trip. They run even on ALREADY - a host with
        # every root present can still hold prunable expired certs or a broken RDP listener.
        $comp = @()
        if ($RunCompanions -and $CompanionsSrc) {
            try {
                . ([scriptblock]::Create($CompanionsSrc))
                if (Get-Command Invoke-CertDeployCompanions -ErrorAction SilentlyContinue) { $comp = @(Invoke-CertDeployCompanions -DoPrune $DoPrune -DoRdp $DoRdp) }
                else { $comp = @('companions FAIL: helper unavailable on target') }
            } catch { $comp = @('companions FAIL: ' + $_.Exception.Message) }
        }
        return [pscustomobject]@{ Token=$tok; Added=[int]$ar.Added; Already=[int]$ar.Already; Total=[int]$ar.Total; PerStore=@($ar.PerStore); FailDetail=[string]$ar.FailDetail; Verified=[int]$ar.Verified; NotVerified=@($ar.NotVerified); Rejected=[int]$ar.Rejected; RejectDetail=[string]$ar.RejectDetail; AddedCerts=@($ar.AddedCerts); Companions=@($comp) }
    }

    $ir = $null
    try { $ir = Invoke-Command -Session $sess -ScriptBlock $installSb -ArgumentList $BundleJson, $AddCertsSrc, $DoPrune, $DoRdp, $CompanionsSrc -ErrorAction Stop }
    catch { $r.Status = 'FAILED'; $r.Detail = "Deploy: $($_.Exception.Message)"; Remove-PSSession $sess -ErrorAction SilentlyContinue; return $r }
    finally { if ($sess) { Remove-PSSession $sess -ErrorAction SilentlyContinue } }

    if ($null -eq $ir) { $r.Status = 'FAILED'; $r.Detail = 'installer returned no result'; return $r }
    $storeTxt = (@($ir.PerStore) -join ', ')
    $r.Added = [int]$ir.Added; $r.Total = [int]$ir.Total
    switch ([string]$ir.Token) {
        'INSTALLED'    { $r.Status = 'ROOTS INSTALLED';       $r.Detail = "added $($ir.Added) of $($ir.Total) across Root/CA/Disallowed" + $(if ($storeTxt) { " [$storeTxt]" } else { '' }) }
        'ALREADY'      { $r.Status = 'ROOTS ALREADY PRESENT'; $r.Detail = "all $($ir.Total) already present across Root/CA/Disallowed" + $(if ($storeTxt) { " [$storeTxt]" } else { '' }) }
        'NOT VERIFIED' { $r.Status = 'NOT VERIFIED';          $r.Detail = "added $($ir.Added) of $($ir.Total) but $(@($ir.NotVerified).Count) absent on re-read - a reconciler/policy may be stripping in-session" + $(if ($storeTxt) { " [$storeTxt]" } else { '' }) }
        'REJECTED'     { $r.Status = 'REJECTED (non-CA)';     $r.Detail = "refused $([int]$ir.Rejected) non-CA cert(s) destined for a trust-anchor store (ABSENT, NOT installed); added $($ir.Added) of $($ir.Total). " + ([string]$ir.RejectDetail).TrimEnd('; ') + $(if ($storeTxt) { " [$storeTxt]" } else { '' }) }
        default        { $r.Status = 'FAILED';                $r.Detail = "added $($ir.Added) of $($ir.Total); errors: " + ([string]$ir.FailDetail).TrimEnd('; ') + $(if ($storeTxt) { " [$storeTxt]" } else { '' }) }
    }
    # Surface exactly WHICH CAs were trusted (Subject CN + thumbprint) so the operator can
    # verify the landed anchors, and flag any non-CA cert refused by the trust-anchor guard.
    $addedCerts = @($ir.AddedCerts)
    if ($addedCerts.Count -gt 0) { $r.Detail += " | trusted: " + ($addedCerts -join '; ') }
    $rejN = [int]$ir.Rejected
    if ($rejN -gt 0) { $r.Detail += " | REJECTED $rejN non-CA (not added to Root/CA): " + ([string]$ir.RejectDetail).TrimEnd('; ') }
    # Companion outcomes ride in Detail only - the row Status stays the install token.
    if ($RunCompanions) {
        $compNotes = @()
        try { $compNotes = @($ir.Companions) | Where-Object { $_ } } catch { $compNotes = @() }
        if ($compNotes.Count -gt 0) { $r.Detail += ' | ' + ($compNotes -join '; ') }
        else { $r.Detail += ' | companions ran: nothing to fix (no prunable expired intermediates; RDP listener healthy)' }
    }
    return $r
}

function Invoke-CertDeployDeployAction {
    param([hashtable]$Params, [System.Management.Automation.PSCredential]$Credential, [scriptblock]$Emit)
    $send = { param($e) if ($Emit) { & $Emit $e } }

    $cancelJob = $null
    if ($Params -and $Params.ContainsKey('__job')) { $cancelJob = $Params['__job'] }
    $cancelCheck = { if ($cancelJob) { try { [bool]$cancelJob['Cancel'] } catch { $false } } else { $false } }.GetNewClosure()

    # Confirm word - exact 'DEPLOY' (case-sensitive). FIRST gate, before any bundle read.
    $confirm = ([string]$Params['confirm']).Trim()
    if ($confirm -cne 'DEPLOY') {
        & $send @{ type='log'; level='err'; text='Confirm word mismatch: type DEPLOY (exactly) to deploy the trust roots. Nothing was changed.' }
        return @{ rows=@(); summary=@{ total=0; rejected=$true } }
    }

    $attemptOffline = Get-CertDeployBool $Params['attemptOffline'] $false

    # Read the bundle admin-side ONCE (blank folder -> shipped default). Abort if empty.
    $resolved = Resolve-CertDeployBundleFolder ([string]$Params['certBundleFolder'])
    $bundleFolder = [string]$resolved.Folder
    $bundleSource = [string]$resolved.Source
    if ([string]::IsNullOrWhiteSpace($bundleFolder)) {
        & $send @{ type='log'; level='err'; text="Deploy aborted: no cert bundle folder supplied and the shipped default ($(Get-CertDeployDefaultBundlePath)) is missing or has no .cer files. Nothing was dialed." }
        return @{ rows=@(); summary=@{ total=0; rejected=$true } }
    }
    $bundle = Get-CertDeployBundle -Folder $bundleFolder
    if (-not $bundle.Ok) {
        & $send @{ type='log'; level='err'; text="Deploy aborted: $($bundle.Error). Nothing was dialed." }
        return @{ rows=@(); summary=@{ total=0; rejected=$true } }
    }
    & $send @{ type='log'; level='info'; text="Cert bundle: $($bundle.CertCount) cert(s) [Root $(@($bundle.Root).Count)/CA $(@($bundle.CA).Count)/Disallowed $(@($bundle.Disallowed).Count)] from $($bundle.Folder) [$bundleSource]." }

    # EXPIRY GUARD (SHARED CONTRACT): expired certs are dead trust anchors. By default
    # they are EXCLUDED from the pushed set (a "[SKIP]" line names them); includeExpired
    # opt-in pushes them anyway, each flagged in the row/log detail. Convert-...ToJson
    # does the filtering; pushCount here decides whether anything valid remains to dial.
    $includeExpired  = Get-CertDeployBool $Params['includeExpired'] $false
    $expiredCount    = [int]$bundle.ExpiredCount
    $expiredSubjects = @(@($bundle.Expired) | ForEach-Object { [string]$_.Subject })
    $legacyCount     = [int]$bundle.LegacyAllowedCount
    $legacySubjects  = @(@($bundle.LegacyAllowed) | ForEach-Object { [string]$_.Subject })
    $bundleJson      = Convert-CertDeployBundleToJson $bundle $includeExpired
    # pushCount excludes only the TRULY dead anchors ($expiredCount, which already omits the
    # allowlisted legacy intermediates - those stay in CertCount and DO push).
    $pushCount       = if ($includeExpired) { [int]$bundle.CertCount } else { ([int]$bundle.CertCount - $expiredCount) }
    if ($legacyCount -gt 0) {
        & $send @{ type='log'; level='warn'; text="[LEGACY] $legacyCount expired-but-allowlisted intermediate(s) WILL be pushed (LegacyIntermediates - required for legacy chain/signature validation): $($legacySubjects -join '; ')." }
    }
    if ($expiredCount -gt 0) {
        if ($includeExpired) {
            & $send @{ type='log'; level='warn'; text="[INCLUDE] $expiredCount expired cert(s) included and flagged (EXPIRED - dead trust anchor): $($expiredSubjects -join '; ')." }
        } else {
            & $send @{ type='log'; level='warn'; text="[SKIP] $expiredCount expired cert(s) excluded (dead trust anchors, not allowlisted): $($expiredSubjects -join '; ')." }
        }
    }
    if ($pushCount -le 0) {
        & $send @{ type='log'; level='err'; text="Deploy aborted: after excluding $expiredCount expired cert(s) (dead trust anchors) the push set is EMPTY - nothing valid to deploy. Enable 'Include EXPIRED certs' only if you truly need dead anchors. Nothing was dialed." }
        return @{ rows=@(); summary=@{ total=0; rejected=$true; expiredCount=$expiredCount; expiredExcluded=$expiredCount } }
    }

    # OPT-IN v1.9 companions (default OFF - deploy stays purely additive unless ticked). Two
    # INDEPENDENT toggles (prunePki / fixRdp). BACK-COMPAT: an old client that sends only the
    # retired single runCompanions truthy (and NEITHER new param) arms BOTH.
    $legacy  = Get-CertDeployBool $Params['runCompanions'] $false
    $doPrune = if ($Params.ContainsKey('prunePki') -or $Params.ContainsKey('fixRdp')) { Get-CertDeployBool $Params['prunePki'] $false } else { $legacy }
    $doRdp   = if ($Params.ContainsKey('prunePki') -or $Params.ContainsKey('fixRdp')) { Get-CertDeployBool $Params['fixRdp'] $false } else { $legacy }
    $runCompanions = ($doPrune -or $doRdp)
    if ($runCompanions) {
        $on = @(); if ($doPrune) { $on += 'expired retired-DoD-intermediate prune (CA store only; the four legacy-keep intermediates never touched)' }; if ($doRdp) { $on += 'broken-RDP-listener rebind (healthy CA-issued listeners never touched)' }
        & $send @{ type='log'; level='warn'; text="[COMPANIONS] v1.9 fix companions ENABLED: after the install each host also gets the $($on -join ' and ')." }
    }

    $targets = @(([string]$Params['targets']) -split '[\r\n,;\t ]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ -and ($_ -match '^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$') } | Select-Object -Unique)
    if ($targets.Count -eq 0) {
        & $send @{ type='log'; level='warn'; text='No valid targets.' }
        return @{ rows=@(); summary=@{ total=0 } }
    }

    $rows = New-Object System.Collections.ArrayList

    # Self-guard: drop the dispatcher host from the target list (SKIPPED row each).
    $dial        = New-Object System.Collections.ArrayList
    $selfSkipped = New-Object System.Collections.ArrayList
    foreach ($t in $targets) {
        if (Test-JanetCertDeployHostIsSelf $t) {
            [void]$selfSkipped.Add($t)
            $row = @{ Host=$t; Ping=''; Status='SKIPPED'; Missing=''; Detail='self-guard: dispatcher/local host - refused (a self-deploy could disrupt the JANET server mid-run)' }
            [void]$rows.Add($row); & $send (@{ type='row' } + $row)
        } else { [void]$dial.Add($t) }
    }
    if ($selfSkipped.Count -gt 0) {
        & $send @{ type='log'; level='warn'; text="Self-guard: dropped the JANET dispatcher host ($($selfSkipped -join ', '))." }
    }
    if ($dial.Count -eq 0) {
        & $send @{ type='log'; level='warn'; text='Nothing left to deploy after the self-guard - only the dispatcher host was targeted.' }
        return @{ rows=@($rows); summary=@{ total=0; selfSkipped=$selfSkipped.Count } }
    }

    $threads = 8
    if ($Params['threads']) { [int]::TryParse([string]$Params['threads'], [ref]$threads) | Out-Null }
    $threads = [Math]::Max(1, [Math]::Min(16, $threads))
    $perHostTimeout = 200
    $auth = if ($Credential) { 'Negotiate' } else { 'Default' }
    $authLabel = if ($Credential) { "as $($Credential.UserName)" } else { 'current session' }

    & $send @{ type='status'; text="Deploying trust certs to $($dial.Count) host(s) with $threads thread(s)..." }
    & $send @{ type='log'; level='info'; text="[$(Get-Date -Format 'HH:mm:ss')] START Cert Deploy on $($dial.Count) host(s) ($authLabel), $threads thread(s)." }

    $iss  = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $threads, $iss, $Host)
    $pool.Open()
    foreach ($h in $dial) { & $send (@{ type='row' } + @{ Host=$h; Ping=''; Status='Queued'; Missing=''; Detail='waiting for a runspace...' }) }
    $jobs = New-Object System.Collections.ArrayList
    foreach ($h in $dial) {
        $ps = [powershell]::Create(); $ps.RunspacePool = $pool
        [void]$ps.AddScript($script:CertDeployDeployBlock)
        [void]$ps.AddArgument($h); [void]$ps.AddArgument($Credential); [void]$ps.AddArgument($auth); [void]$ps.AddArgument($attemptOffline); [void]$ps.AddArgument($bundleJson); [void]$ps.AddArgument($script:CertDeployAddCertsSrc); [void]$ps.AddArgument($doPrune); [void]$ps.AddArgument($doRdp); [void]$ps.AddArgument($script:CertDeployCompanionsSrc)
        [void]$jobs.Add([pscustomobject]@{ Host=$h; PS=$ps; Async=$ps.BeginInvoke(); StartedAt=$null })
    }

    $emitResult = {
        param($res)
        $detail = [string]$res.Detail
        # includeExpired opt-in: flag the row/log detail so the operator sees dead anchors went out.
        if ($includeExpired -and $expiredCount -gt 0 -and (@('ROOTS INSTALLED','ROOTS ALREADY PRESENT','NOT VERIFIED') -contains [string]$res.Status)) {
            $detail += " (includes $expiredCount EXPIRED cert(s) - dead trust anchor)"
        }
        # JANET audit classification, hoisted above the row so the troubleshooting hint can ride it
        # (same value - switches on the same status). A cert install is a security-state change.
        $auditResult = switch ([string]$res.Status) { 'ROOTS INSTALLED' {'Success'} 'ROOTS ALREADY PRESENT' {'Skipped'} 'SKIPPED' {'Skipped'} 'OFFLINE' {'Skipped'} default {'Failure'} }
        # informative-failures (loop78): a failed host (FAILED / NOT VERIFIED / REJECTED) carries a
        # why+how-to-fix hint derived from the raw detail; raw detail is preserved untouched.
        $hint = if ($auditResult -eq 'Failure' -and $detail) { Get-JanetTroubleshootHint -Message $detail -Server ([string]$res.Host) } else { '' }
        $row = @{ Host=[string]$res.Host; Ping=[string]$res.Ping; Status=[string]$res.Status; Missing=''; Detail=$detail; Hint=[string]$hint }
        [void]$rows.Add($row)
        & $send (@{ type='row' } + $row)
        $itemCount   = if ($row.Status -eq 'ROOTS INSTALLED') { [int]$res.Added } else { 0 }
        & $send @{ type='audit'; action='VulnPatched'; target=$row.Host; result=$auditResult; itemCount=$itemCount; detail=$row.Detail }
        $lvl = 'info'
        if     ($row.Status -eq 'ROOTS INSTALLED')       { $lvl = 'ok' }
        elseif ($row.Status -eq 'ROOTS ALREADY PRESENT') { $lvl = 'info' }
        elseif ($row.Status -eq 'OFFLINE')               { $lvl = 'warn' }
        elseif ($row.Status -eq 'SKIPPED')               { $lvl = 'warn' }
        elseif ($row.Status -eq 'NOT VERIFIED')          { $lvl = 'error' }
        elseif ($row.Status -eq 'REJECTED (non-CA)')     { $lvl = 'error' }
        elseif ($row.Status -eq 'FAILED')                { $lvl = 'error' }
        & $send @{ type='log'; level=$lvl; text="[$(Get-Date -Format 'HH:mm:ss')] $([string]$res.Host) : $([string]$res.Status) - $([string]$res.Detail)" }
        if ($hint) { & $send @{ type='log'; level='err'; text="$([string]$res.Host) : $([string]$res.Status) - $([string]$res.Detail) | FIX: $hint" } }
    }

    $done = 0
    try {
        while ($done -lt $jobs.Count) {
            # Cap the per-host clock to the pool's real concurrency, stamping in queue order:
            # a PS queued in a saturated RunspacePool reports State='Running' immediately, so the
            # old InvocationStateInfo check stamped StartedAt at ENQUEUE for every job and the
            # watchdog then falsely timed out the whole backlog at once (~threads*timeout hosts in).
            $activeCount = @($jobs | Where-Object { $_.PS -and $_.StartedAt }).Count
            foreach ($j in $jobs) {
                if ($j.PS -and -not $j.StartedAt -and $activeCount -lt $pool.GetMaxRunspaces()) { $j.StartedAt = Get-Date; $activeCount++ }
                if ($j.PS -and $j.Async.IsCompleted) {
                    $res = $null
                    try { $res = $j.PS.EndInvoke($j.Async) | Select-Object -First 1 }
                    catch { $res = @{ Host=$j.Host; Ping=''; Status='FAILED'; Detail="worker error: $($_.Exception.Message)"; Added=0 } }
                    try { $j.PS.Dispose() } catch {}; $j.PS = $null
                    if ($null -eq $res) { $res = @{ Host=$j.Host; Ping=''; Status='FAILED'; Detail='worker returned no result'; Added=0 } }
                    & $emitResult $res
                    $done++; & $send @{ type='progress'; done=$done; total=$jobs.Count }
                }
            }
            if ($done -lt $jobs.Count) {
                $nowPh = Get-Date
                foreach ($j in $jobs) {
                    if ($j.PS -and $j.StartedAt -and ($nowPh - $j.StartedAt).TotalSeconds -gt $perHostTimeout) {
                        try { [void]$j.PS.BeginStop($null, $null) } catch {}; $j.PS = $null
                        & $emitResult @{ Host=$j.Host; Ping=''; Status='FAILED'; Detail="per-host timeout (${perHostTimeout}s) - possible remote hang"; Added=0 }
                        $done++; & $send @{ type='progress'; done=$done; total=$jobs.Count }
                    }
                }
            }
            if ($done -lt $jobs.Count) {
                if ($cancelCheck -and (& $cancelCheck)) {
                    foreach ($j in $jobs) {
                        if ($j.PS) {
                            try { [void]$j.PS.BeginStop($null, $null) } catch {}; $j.PS = $null
                            & $emitResult @{ Host=$j.Host; Ping=''; Status='SKIPPED'; Detail='cancelled by operator'; Added=0 }
                            $done++
                        }
                    }
                    & $send @{ type='log'; level='warn'; text='Run cancelled by operator; in-flight deploys stopped.' }
                    break
                }
                Start-Sleep -Milliseconds 150
            }
        }
    } finally { try { $pool.Close(); $pool.Dispose() } catch {} }

    $installed   = @($rows | Where-Object { $_.Status -eq 'ROOTS INSTALLED' }).Count
    $already     = @($rows | Where-Object { $_.Status -eq 'ROOTS ALREADY PRESENT' }).Count
    $failed      = @($rows | Where-Object { $_.Status -eq 'FAILED' }).Count
    $offline     = @($rows | Where-Object { $_.Status -eq 'OFFLINE' }).Count
    $skipped     = @($rows | Where-Object { $_.Status -eq 'SKIPPED' }).Count
    $notVerified = @($rows | Where-Object { $_.Status -eq 'NOT VERIFIED' }).Count
    $rejected    = @($rows | Where-Object { $_.Status -eq 'REJECTED (non-CA)' }).Count
    & $send @{ type='log'; level='ok'; text="Cert Deploy done - INSTALLED: $installed, ALREADY PRESENT: $already, NOT VERIFIED: $notVerified, REJECTED: $rejected, FAILED: $failed, OFFLINE: $offline, SKIPPED: $skipped." }
    & $send @{ type='status'; text="Done. $installed installed, $already already-present, $notVerified not-verified, $rejected rejected, $failed failed of $($rows.Count) row(s)." }
    return @{ rows=@($rows); summary=@{ total=$rows.Count; installed=$installed; already=$already; notVerified=$notVerified; rejected=$rejected; failed=$failed; offline=$offline; skipped=$skipped; selfSkipped=$selfSkipped.Count; expiredCount=$expiredCount; expiredExcluded=$(if ($includeExpired) { 0 } else { $expiredCount }); source=$bundleSource } }
}

# =============================================================================
#  scan-cert-management (READ-ONLY): per-host worker + fan-out. Inspects WHAT
#  MANAGES the LocalMachine trust store (DISA InstallRoot agent / GPO physical
#  store) so the operator knows if a scripted .Default push will actually persist.
#  NEVER writes anything. Mirrors the CHECK path's reachability/session/wrong-box
#  idioms; needs no cert bundle.
# =============================================================================
$script:CertDeployScanBlock = {
    param([string]$Computer, $Cred, [string]$Auth, [bool]$AttemptOffline)

    $r = @{ Host=$Computer; Ping=''; Status=''; InstallRootPresent=$false; InstallRootToken='no'; GpRoots=0; DefaultRootCount=0; Ok=$false; Detail='' }

    # Reachability: pure-TCP probe (AFNET-safe; never ICMP). WinRM HTTP 5985, then WinRM
    # HTTPS 5986, then SMB 445 (liveness only), 1.5s, break on first connect. $useSsl
    # tracks whether ONLY 5986 answered so the session below auto-switches to -UseSSL
    # (HTTP 5985 is preferred when both are open).
    $reachable = $false; $useSsl = $false
    foreach ($port in 5985,5986,445) {
        $tc = $null
        try {
            $tc = New-Object System.Net.Sockets.TcpClient
            $iar = $tc.BeginConnect($Computer, $port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(1500, $false) -and $tc.Connected) { $reachable = $true; $r.Ping = "TCP $port"; if ($port -eq 5986) { $useSsl = $true } }
        } catch {} finally { if ($tc) { try { $tc.Close() } catch {} } }
        if ($reachable) { break }
    }
    if (-not $reachable) {
        $r.Ping = 'Unreachable'
        if (-not $AttemptOffline) {
            $r.Status = 'OFFLINE'; $r.Detail = 'No TCP on 5985/5986/445 (1.5s timeouts). Enable "Attempt even if offline" to force.'
            return $r
        }
    }

    # -UseSSL only when the host answered ONLY on 5986 (self-signed WinRM HTTPS is common on
    # AFNET, so skip CA/CN validation - the transport stays encrypted; port 5986 is implicit).
    $soP = @{ OperationTimeout=120000; OpenTimeout=15000; CancelTimeout=5000; IdleTimeout=60000 }
    if ($useSsl) { $soP['SkipCACheck']=$true; $soP['SkipCNCheck']=$true }
    $wsOpt = New-PSSessionOption @soP
    $splat = @{ ComputerName=$Computer; SessionOption=$wsOpt; ErrorAction='Stop' }
    if ($useSsl) { $splat['UseSSL']=$true }
    if ($Cred) { $splat['Credential']=$Cred; $splat['Authentication']=$Auth }
    $sess = $null
    try { $sess = New-PSSession @splat } catch { $r.Status = 'CHECK ERROR'; $r.Detail = "Session: $($_.Exception.Message)"; return $r }

    # Wrong-box SOFT-skip (read-only path never writes anyway).
    try {
        $expectedShort = if ($Computer -match '^\d{1,3}(\.\d{1,3}){3}$') { '' } else { ($Computer -split '\.')[0] }
        if ($expectedShort) {
            $answering = Invoke-Command -Session $sess -ScriptBlock { $env:COMPUTERNAME } -ErrorAction Stop
            if (([string]$answering).Trim().ToUpper() -ne $expectedShort.Trim().ToUpper()) {
                Remove-PSSession $sess -ErrorAction SilentlyContinue
                $r.Status = 'CHECK ERROR'; $r.Detail = "DNS MISMATCH: dialed '$expectedShort' but remote is '$answering' - soft-skipped, nothing read"
                return $r
            }
        }
    } catch {
        Remove-PSSession $sess -ErrorAction SilentlyContinue
        $r.Status = 'CHECK ERROR'; $r.Detail = "wrong-box guard probe failed: $($_.Exception.Message)"; return $r
    }

    # The consolidated READ-ONLY probe: detect the DISA InstallRoot agent, count the
    # GPO physical Root/CA store, and read the .Default LocalMachine Root store count.
    $scanSb = {
        $res = [pscustomobject]@{ InstallRootPresent=$false; InstallRootToken='no'; GpRoots=0; DefaultRootCount=0; Err='' }
        try {
            # 1. DISA InstallRoot: uninstall registry (64- + 32-bit), a scheduled task, %ProgramFiles%\DoD-PKE.
            $irName = ''; $irVer = ''
            foreach ($up in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')) {
                foreach ($k in @(Get-ItemProperty -Path $up -ErrorAction SilentlyContinue)) {
                    $dn = [string]$k.DisplayName
                    if ($dn -match 'InstallRoot') { $irName = $dn; $irVer = [string]$k.DisplayVersion; break }
                }
                if ($irName) { break }
            }
            $irTask = $false
            try {
                if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
                    if (@(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { [string]$_.TaskName -match 'InstallRoot' }).Count -gt 0) { $irTask = $true }
                } else {
                    $csv = schtasks /query /fo csv 2>$null
                    if (($csv -join "`n") -match 'InstallRoot') { $irTask = $true }
                }
            } catch {}
            $irPath = $false
            foreach ($pf in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
                if ($pf) { if (Test-Path -LiteralPath (Join-Path $pf 'DoD-PKE')) { $irPath = $true } }
            }
            $present = ($irName -ne '') -or $irTask -or $irPath
            $res.InstallRootPresent = $present
            if ($present) {
                $bits = New-Object System.Collections.ArrayList
                if ($irVer) { [void]$bits.Add("v$irVer") } elseif ($irName) { [void]$bits.Add('reg') }
                if ($irTask) { [void]$bits.Add('task') }
                if ($irPath -and -not $irName -and -not $irTask) { [void]$bits.Add('DoD-PKE path') }
                $res.InstallRootToken = if ($bits.Count -gt 0) { "yes ($($bits -join ', '))" } else { 'yes' }
            }
            # 2. GPO physical Root/CA store (HKLM Policies SystemCertificates) - >0 means GPO manages roots.
            $gp = 0
            foreach ($gpk in @('HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\Certificates','HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\CA\Certificates')) {
                if (Test-Path -LiteralPath $gpk) { $gp += @(Get-ChildItem -LiteralPath $gpk -ErrorAction SilentlyContinue).Count }
            }
            $res.GpRoots = [int]$gp
            # 3. .Default LocalMachine Root store count (context for the Detail).
            try {
                $st = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root','LocalMachine')
                $st.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
                $res.DefaultRootCount = @($st.Certificates).Count
                $st.Close()
            } catch {}
        } catch { $res.Err = $_.Exception.Message }
        return $res
    }

    $raw = $null
    try { $raw = Invoke-Command -Session $sess -ScriptBlock $scanSb -ErrorAction Stop }
    catch { $r.Status = 'CHECK ERROR'; $r.Detail = "Probe: $($_.Exception.Message)"; Remove-PSSession $sess -ErrorAction SilentlyContinue; return $r }
    finally { if ($sess) { Remove-PSSession $sess -ErrorAction SilentlyContinue } }

    if ($null -eq $raw) { $r.Status = 'CHECK ERROR'; $r.Detail = 'probe returned no result'; return $r }
    $errTxt = ''
    try { if ($raw.PSObject.Properties['Err']) { $errTxt = [string]$raw.Err } } catch {}
    if ($errTxt) { $r.Status = 'CHECK ERROR'; $r.Detail = $errTxt; return $r }
    $r.InstallRootPresent = [bool]$raw.InstallRootPresent
    $r.InstallRootToken   = [string]$raw.InstallRootToken
    $r.GpRoots            = [int]$raw.GpRoots
    $r.DefaultRootCount   = [int]$raw.DefaultRootCount
    $r.Ok = $true
    return $r
}

function Invoke-CertDeployScanAction {
    param([hashtable]$Params, [System.Management.Automation.PSCredential]$Credential, [scriptblock]$Emit)
    $send = { param($e) if ($Emit) { & $Emit $e } }

    $cancelJob = $null
    if ($Params -and $Params.ContainsKey('__job')) { $cancelJob = $Params['__job'] }
    $cancelCheck = { if ($cancelJob) { try { [bool]$cancelJob['Cancel'] } catch { $false } } else { $false } }.GetNewClosure()

    $targets = @(([string]$Params['targets']) -split '[\r\n,;\t ]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ -and ($_ -match '^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$') } | Select-Object -Unique)
    if ($targets.Count -eq 0) {
        & $send @{ type='log'; level='warn'; text='No valid targets.' }
        return @{ rows=@(); summary=@{ total=0; installRoot=0; gpoManaged=0; none=0; offline=0 } }
    }

    $attemptOffline = Get-CertDeployBool $Params['attemptOffline'] $false
    $threads = 16
    if ($Params['threads']) { [int]::TryParse([string]$Params['threads'], [ref]$threads) | Out-Null }
    $threads = [Math]::Max(1, [Math]::Min(32, $threads))
    $perHostTimeout = 150
    $auth = if ($Credential) { 'Negotiate' } else { 'Default' }
    $authLabel = if ($Credential) { "as $($Credential.UserName)" } else { 'current session' }

    & $send @{ type='status'; text="Scanning cert management on $($targets.Count) host(s) with $threads thread(s)..." }
    & $send @{ type='log'; level='info'; text="[$(Get-Date -Format 'HH:mm:ss')] START Scan Cert Management on $($targets.Count) host(s) ($authLabel), $threads thread(s)." }

    $iss  = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $threads, $iss, $Host)
    $pool.Open()
    foreach ($h in $targets) { & $send (@{ type='row' } + @{ Host=$h; Ping=''; InstallRoot=''; GPRoots=''; Reconciler='Queued'; Detail='waiting for a runspace...' }) }
    $jobs = New-Object System.Collections.ArrayList
    foreach ($h in $targets) {
        $ps = [powershell]::Create(); $ps.RunspacePool = $pool
        [void]$ps.AddScript($script:CertDeployScanBlock)
        [void]$ps.AddArgument($h); [void]$ps.AddArgument($Credential); [void]$ps.AddArgument($auth); [void]$ps.AddArgument($attemptOffline)
        [void]$jobs.Add([pscustomobject]@{ Host=$h; PS=$ps; Async=$ps.BeginInvoke(); StartedAt=$null })
    }

    $rows = New-Object System.Collections.ArrayList

    $emitResult = {
        param($res)
        $row = Get-CertDeployScanRow -Res $res
        $rec = [string]$row.Reconciler
        # informative-failures (loop81): a CHECK ERROR carries the raw probe/session/DNS error in Detail on
        # this read-only reconciler scan; turn it into a why+how-to-fix hint. OFFLINE / verdicts self-explain.
        $hint = if ($rec -eq 'CHECK ERROR' -and $row.Detail) { Get-JanetTroubleshootHint -Message ([string]$row.Detail) -Server ([string]$row.Host) } else { '' }
        if ($hint) { $row['Hint'] = [string]$hint }
        [void]$rows.Add($row)
        & $send (@{ type='row' } + $row)
        $lvl = 'info'
        if     ($rec -eq 'None detected') { $lvl = 'ok' }
        elseif ($rec -eq 'OFFLINE')       { $lvl = 'warn' }
        elseif ($rec -eq 'CHECK ERROR')   { $lvl = 'error' }
        else                              { $lvl = 'warn' }
        & $send @{ type='log'; level=$lvl; text="[$(Get-Date -Format 'HH:mm:ss')] $([string]$row.Host) : $rec - $([string]$row.Detail)" }
        if ($hint) { & $send @{ type='log'; level='err'; text="$([string]$row.Host) : $rec - $([string]$row.Detail) | FIX: $hint" } }
    }

    $done = 0
    try {
        while ($done -lt $jobs.Count) {
            # Cap the per-host clock to the pool's real concurrency, stamping in queue order:
            # a PS queued in a saturated RunspacePool reports State='Running' immediately, so the
            # old InvocationStateInfo check stamped StartedAt at ENQUEUE for every job and the
            # watchdog then falsely timed out the whole backlog at once (~threads*timeout hosts in).
            $activeCount = @($jobs | Where-Object { $_.PS -and $_.StartedAt }).Count
            foreach ($j in $jobs) {
                if ($j.PS -and -not $j.StartedAt -and $activeCount -lt $pool.GetMaxRunspaces()) { $j.StartedAt = Get-Date; $activeCount++ }
                if ($j.PS -and $j.Async.IsCompleted) {
                    $res = $null
                    try { $res = $j.PS.EndInvoke($j.Async) | Select-Object -First 1 }
                    catch { $res = @{ Host=$j.Host; Ping=''; Status='CHECK ERROR'; Detail="worker error: $($_.Exception.Message)"; Ok=$false } }
                    try { $j.PS.Dispose() } catch {}; $j.PS = $null
                    if ($null -eq $res) { $res = @{ Host=$j.Host; Ping=''; Status='CHECK ERROR'; Detail='worker returned no result'; Ok=$false } }
                    & $emitResult $res
                    $done++; & $send @{ type='progress'; done=$done; total=$jobs.Count }
                }
            }
            if ($done -lt $jobs.Count) {
                $nowPh = Get-Date
                foreach ($j in $jobs) {
                    if ($j.PS -and $j.StartedAt -and ($nowPh - $j.StartedAt).TotalSeconds -gt $perHostTimeout) {
                        try { [void]$j.PS.BeginStop($null, $null) } catch {}; $j.PS = $null
                        & $emitResult @{ Host=$j.Host; Ping=''; Status='CHECK ERROR'; Detail="per-host timeout (${perHostTimeout}s) - possible remote read hang"; Ok=$false }
                        $done++; & $send @{ type='progress'; done=$done; total=$jobs.Count }
                    }
                }
            }
            if ($done -lt $jobs.Count) {
                if ($cancelCheck -and (& $cancelCheck)) {
                    foreach ($j in $jobs) {
                        if ($j.PS) {
                            try { [void]$j.PS.BeginStop($null, $null) } catch {}; $j.PS = $null
                            & $emitResult @{ Host=$j.Host; Ping=''; Status='CHECK ERROR'; Detail='cancelled by operator'; Ok=$false }
                            $done++
                        }
                    }
                    & $send @{ type='log'; level='warn'; text='Run cancelled by operator; in-flight scans stopped.' }
                    break
                }
                Start-Sleep -Milliseconds 150
            }
        }
    } finally { try { $pool.Close(); $pool.Dispose() } catch {} }

    $installRoot = @($rows | Where-Object { @('InstallRoot','InstallRoot+GPO') -contains [string]$_.Reconciler }).Count
    $gpoManaged  = @($rows | Where-Object { @('GPO','InstallRoot+GPO') -contains [string]$_.Reconciler }).Count
    $none        = @($rows | Where-Object { [string]$_.Reconciler -eq 'None detected' }).Count
    $offline     = @($rows | Where-Object { [string]$_.Reconciler -eq 'OFFLINE' }).Count
    & $send @{ type='log'; level='ok'; text="Scan Cert Management done - InstallRoot: $installRoot, GPO: $gpoManaged, None detected: $none, OFFLINE: $offline (of $($targets.Count) host(s))." }
    & $send @{ type='status'; text="Done. $installRoot InstallRoot, $gpoManaged GPO, $none none, $offline offline of $($targets.Count)." }
    return @{ rows=@($rows); summary=@{ total=$targets.Count; installRoot=$installRoot; gpoManaged=$gpoManaged; none=$none; offline=$offline } }
}

function Invoke-JanetToolAction {
    param(
        [string]$ActionId,
        [hashtable]$Params,
        [System.Management.Automation.PSCredential]$Credential,
        [scriptblock]$Emit
    )
    $send = { param($e) if ($Emit) { & $Emit $e } }

    switch ($ActionId) {
        'check'                { return (Invoke-CertDeployCheckAction  -Params $Params -Credential $Credential -Emit $Emit) }
        'deploy'               { return (Invoke-CertDeployDeployAction -Params $Params -Credential $Credential -Emit $Emit) }
        'scan-cert-management' { return (Invoke-CertDeployScanAction   -Params $Params -Credential $Credential -Emit $Emit) }
        'import-pki-hosts'     { return (Invoke-CertDeployImportAction -Params $Params -Emit $Emit) }
        default {
            & $send @{ type='error'; text="Unknown action '$ActionId'." }
            return @{ rows=@(); summary=@{} }
        }
    }
}

Export-ModuleMember -Function Get-JanetToolManifest, Invoke-JanetToolAction, Get-CertDeployBundle, Resolve-CertDeployBundleFolder, Convert-CertDeployBundleToJson, Convert-CertDeployBundleToThumbJson, Get-CertDeploySubjectMap, Get-CertDeployDefaultBundlePath, Test-JanetCertDeployHostIsSelf, Get-CertDeployBool, ConvertFrom-CertDeployComplianceCsv, Test-CertDeployPkiLine, Get-CertDeployCheckRow, Get-CertDeployReconcilerVerdict, Get-CertDeployScanRow, Invoke-CertDeployCheckAction, Invoke-CertDeployDeployAction, Invoke-CertDeployScanAction, Invoke-CertDeployImportAction
