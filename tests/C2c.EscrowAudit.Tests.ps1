# =============================================================================
#  C2c.EscrowAudit.Tests.ps1 - Pester 3.4 for the v1.17.0 READ-ONLY BitLocker
#  escrow audit (action 'audit-encryption').
#
#  The gap it closes: "escrow-first, fail-closed" only ever bound volumes JANET
#  CHANGES. A volume already On short-circuits to ALREADY ENCRYPTED and its key
#  protectors were never enumerated, so the whole pre-JANET installed base was
#  unaudited - and a TPM-ONLY volume with no escrowed key hits the recovery prompt
#  on the next firmware change with NO KEY TO TYPE.
#
#  THE TEST THAT MATTERS MOST is the last Describe: a fix for a key-visibility gap
#  must not itself leak keys. The endpoint probe is RUN LOCALLY against a shimmed
#  Get-BitLockerVolume whose KeyProtector objects DO carry a real-shaped recovery
#  password, and EVERY emitted field - probe output, row cells, detail, summary
#  line, per-volume report - is asserted not to match \d{6}(-\d{6}){7}.
#
#  No WinRM call and no AD bind ever leaves this box:
#    * the pure verdict/rollup engine is called directly with synthetic records;
#    * the endpoint probe is dot-sourced in module scope and driven with the
#      BitLocker / Volume / Tpm cmdlets shimmed;
#    * the AD side is driven through its injectable -SearcherFactory with a fake
#      DirectorySearcher, so PropertiesToLoad and the fail-closed paths are real
#      assertions rather than source regex.
#
#  Run:  Invoke-Pester -Path .\tests\C2c.EscrowAudit.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent

# -----------------------------------------------------------------------------
# Shim hygiene. 'Remove-Item function:script:<name>' is INERT (the function provider
# has no scope qualifier in its paths) and the naive unqualified form DESTROYS the
# module's real function. Snapshot first, then put back exactly what was there.
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

# A real-SHAPED BitLocker recovery password (8 x 6 digits). It is a fabricated
# constant used ONLY as the poison the leak test hunts for.
$script:PoisonKey = '123456-234567-345678-456789-567890-678901-789012-890123'
$script:KeyRegex  = '\d{6}(-\d{6}){7}'

# Assert on CALL SITES, never on comments (the 07-25 audit's C3 lesson: a test that
# matches a string living only in a comment tests documentation). Drop whole-line
# comments and trailing ' #...' before asserting - neither source below puts a '#'
# inside a string literal.
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

Describe 'C2C escrow audit - the manifest declares a READ-ONLY action with no confirm gate' {

    $man = & $cm { Get-JanetToolManifest }
    $act = @($man.actions | Where-Object { $_.id -eq 'audit-encryption' })[0]

    It 'the module version is at least 1.17.0' {
        # The exact pin MOVED to C2c.Lockscreen.Tests.ps1 with the 1.18.0 bump; floor here.
        ([version]$man.version -ge [version]'1.17.0') | Should Be $true
    }
    It 'the audit-encryption action exists' {
        $act | Should Not BeNullOrEmpty
    }
    It 'is NOT destructive (read-only census)' {
        [bool]$act.destructive | Should Be $false
    }
    It 'declares NO confirm text and NO confirm input (read-only needs no arm gate)' {
        ([string]$act.confirm) | Should BeNullOrEmpty
        @($act.inputs | Where-Object { $_.name -eq 'confirm' }).Count | Should Be 0
    }
    It 'takes targets / attemptOffline / threads only' {
        @($act.inputs | Where-Object { $_.name -eq 'targets' -and $_.required }).Count | Should Be 1
        @($act.inputs | Where-Object { $_.name -eq 'attemptOffline' }).Count | Should Be 1
        @($act.inputs | Where-Object { $_.name -eq 'threads' }).Count | Should Be 1
    }
    It 'declares the escrow columns the view renders' {
        $cols = @($act.columns)
        $cols -contains 'Volumes'  | Should Be $true
        $cols -contains 'Escrowed' | Should Be $true
        $cols -contains 'Tpm'      | Should Be $true
        $cols -contains 'Status'   | Should Be $true
    }
    It 'the description promises the recovery password is never emitted' {
        [string]$act.description | Should Match '(?i)recovery password is NEVER read and NEVER emitted'
        [string]$act.description | Should Match '(?i)msFVE-RecoveryPassword is never loaded'
    }
    It 'the description names the fail-closed rule and the separate buckets' {
        [string]$act.description | Should Match '(?i)FAIL-CLOSED'
        [string]$act.description | Should Match '(?i)NEVER ESCROWED'
        [string]$act.description | Should Match '(?i)notEscrowed and unknown SEPARATELY'
    }
    It 'the dispatcher routes audit-encryption to the read-only action (no arm/confirm branch)' {
        $src = & $cm { (Get-Item -LiteralPath 'function:Invoke-JanetToolAction').ScriptBlock.ToString() }
        $src | Should Match ([regex]::Escape("if (`$ActionId -eq 'audit-encryption')"))
        $src | Should Match ([regex]::Escape('Invoke-C2cEncryptionAuditAction'))
    }
}

Describe 'C2C escrow audit - GUID normalization' {

    It 'strips braces and lower-cases so an endpoint {GUID} matches an AD guid' {
        (& $cm { ConvertTo-C2cEscrowGuid '{4E9E1234-5678-90AB-CDEF-1234567890AB}' }) | Should Be '4e9e1234-5678-90ab-cdef-1234567890ab'
    }
    It 'accepts a bare GUID unchanged (case-folded)' {
        (& $cm { ConvertTo-C2cEscrowGuid '4e9e1234-5678-90ab-cdef-1234567890ab' }) | Should Be '4e9e1234-5678-90ab-cdef-1234567890ab'
    }
    It 'returns empty for anything that is not a GUID - a non-GUID can never be matched into ESCROWED' {
        (& $cm { ConvertTo-C2cEscrowGuid 'not-a-guid' }) | Should Be ''
        (& $cm { ConvertTo-C2cEscrowGuid '' })           | Should Be ''
        (& $cm { ConvertTo-C2cEscrowGuid $null })        | Should Be ''
    }
}

Describe 'C2C escrow audit - the six per-host verdicts' {

    $g = '4e9e1234-5678-90ab-cdef-1234567890ab'

    function New-Vol {
        param([string]$Mp = 'C:', [string]$Ps = 'On', [string]$Vs = 'FullyEncrypted',
              [string[]]$Types = @('Tpm', 'RecoveryPassword'), [string[]]$Ids = @(), [string]$Err = '')
        [pscustomobject]@{
            MountPoint = $Mp; VolumeType = 'OperatingSystem'; ProtectionStatus = $Ps; VolumeStatus = $Vs
            EncryptionMethod = 'XtsAes256'; KeyProtectorTypes = $Types; RecoveryIds = $Ids; Err = $Err
        }
    }

    It 'ESCROWED (AD) when a protector GUID matches an AD msFVE-RecoveryGuid' {
        $v = New-Vol -Ids @("{$g}")
        $r = & $cm { param($vv, $gg) Get-C2cEscrowHostResult -Volumes @($vv) -AdGuids @($gg) -AdOk $true -AdObjectCount 1 } $v $g
        [string]$r.Status   | Should Be 'ESCROWED (AD)'
        [string]$r.Escrowed | Should Be '1/1'
    }
    It 'NOT ESCROWED when the box has a recovery protector but AD holds a different GUID' {
        $v = New-Vol -Ids @("{$g}")
        $r = & $cm { param($vv) Get-C2cEscrowHostResult -Volumes @($vv) -AdGuids @('11111111-1111-1111-1111-111111111111') -AdOk $true -AdObjectCount 1 } $v
        [string]$r.Status   | Should Be 'NOT ESCROWED'
        [string]$r.Escrowed | Should Be '0/1'
    }
    It 'TPM-ONLY - LOCKOUT RISK when an encrypted volume carries NO RecoveryPassword protector' {
        $v = New-Vol -Types @('Tpm') -Ids @()
        $r = & $cm { param($vv, $gg) Get-C2cEscrowHostResult -Volumes @($vv) -AdGuids @($gg) -AdOk $true -AdObjectCount 1 } $v $g
        [string]$r.Status | Should Be 'TPM-ONLY - LOCKOUT RISK'
        [string]$r.Detail | Should Match '(?i)TPM-ONLY'
    }
    It 'NOT ENCRYPTED when the volume is Off / FullyDecrypted' {
        $v = New-Vol -Ps 'Off' -Vs 'FullyDecrypted' -Types @() -Ids @()
        $r = & $cm { param($vv) Get-C2cEscrowHostResult -Volumes @($vv) -AdGuids @() -AdOk $true -AdObjectCount 0 } $v
        [string]$r.Status | Should Be 'NOT ENCRYPTED'
    }
    It 'an EncryptionInProgress volume counts as encrypted (it already has protectors to escrow)' {
        $v = New-Vol -Ps 'Off' -Vs 'EncryptionInProgress' -Types @('Tpm') -Ids @()
        $r = & $cm { param($vv) Get-C2cEscrowHostResult -Volumes @($vv) -AdGuids @() -AdOk $true -AdObjectCount 0 } $v
        [string]$r.Status | Should Be 'TPM-ONLY - LOCKOUT RISK'
    }
    It 'the worst volume wins the host rollup (a green C: cannot hide a TPM-only D:)' {
        $ok  = New-Vol -Mp 'C:' -Ids @("{$g}")
        $bad = New-Vol -Mp 'D:' -Types @('Tpm') -Ids @()
        $r = & $cm { param($a, $b, $gg) Get-C2cEscrowHostResult -Volumes @($a, $b) -AdGuids @($gg) -AdOk $true -AdObjectCount 1 } $ok $bad $g
        [string]$r.Status  | Should Be 'TPM-ONLY - LOCKOUT RISK'
        [int]$r.Volumes    | Should Be 2
        [string]$r.Escrowed | Should Be '1/2'
    }
}

Describe 'C2C escrow audit - FAIL CLOSED: unknown is never escrowed' {

    $g = '4e9e1234-5678-90ab-cdef-1234567890ab'
    $encVol = [pscustomobject]@{
        MountPoint='C:'; VolumeType='OperatingSystem'; ProtectionStatus='On'; VolumeStatus='FullyEncrypted'
        EncryptionMethod='XtsAes256'; KeyProtectorTypes=@('Tpm','RecoveryPassword'); RecoveryIds=@("{$g}"); Err=''
    }

    It 'an ACL-denied / failed AD search is ESCROW UNKNOWN even though the GUID is in the (unread) directory' {
        $r = & $cm { param($vv) Get-C2cEscrowHostResult -Volumes @($vv) -AdGuids @() -AdOk $false -AdError 'access is denied' } $encVol
        [string]$r.Status | Should Be 'ESCROW UNKNOWN'
        [string]$r.Detail | Should Match '(?i)UNREADABLE'
    }
    It 'an AD search that returned nothing but WAS readable is NOT ESCROWED (a real finding, not unknown)' {
        $r = & $cm { param($vv) Get-C2cEscrowHostResult -Volumes @($vv) -AdGuids @() -AdOk $true -AdObjectCount 0 } $encVol
        [string]$r.Status | Should Be 'NOT ESCROWED'
    }
    It 'an unreadable protector list is ESCROW UNKNOWN, never ESCROWED' {
        $v = [pscustomobject]@{
            MountPoint='C:'; VolumeType='OperatingSystem'; ProtectionStatus='On'; VolumeStatus='FullyEncrypted'
            EncryptionMethod='XtsAes256'; KeyProtectorTypes=@(); RecoveryIds=@(); Err='key protectors unreadable: access denied'
        }
        $r = & $cm { param($vv, $gg) Get-C2cEscrowHostResult -Volumes @($vv) -AdGuids @($gg) -AdOk $true -AdObjectCount 1 } $v $g
        [string]$r.Status | Should Be 'ESCROW UNKNOWN'
    }
    It 'an encrypted volume with ZERO returned protectors is ESCROW UNKNOWN, not TPM-ONLY' {
        $v = [pscustomobject]@{
            MountPoint='C:'; VolumeType='OperatingSystem'; ProtectionStatus='On'; VolumeStatus='FullyEncrypted'
            EncryptionMethod='XtsAes256'; KeyProtectorTypes=@(); RecoveryIds=@(); Err=''
        }
        $r = & $cm { param($vv) Get-C2cEscrowHostResult -Volumes @($vv) -AdGuids @() -AdOk $true -AdObjectCount 0 } $v
        [string]$r.Status | Should Be 'ESCROW UNKNOWN'
    }
    It 'a host whose fixed volumes could not be enumerated at all is ESCROW UNKNOWN' {
        $r = & $cm { Get-C2cEscrowHostResult -Volumes @() -VolErr 'Get-BitLockerVolume failed: access denied' }
        [string]$r.Status | Should Be 'ESCROW UNKNOWN'
    }
    It 'a probe that returned zero volumes with no error is still ESCROW UNKNOWN (never green by default)' {
        $r = & $cm { Get-C2cEscrowHostResult -Volumes @() }
        [string]$r.Status | Should Be 'ESCROW UNKNOWN'
    }
    It 'a $null volume element (an empty array that crossed WinRM as $null) is ESCROW UNKNOWN, not NOT ENCRYPTED' {
        $r = & $cm { Get-C2cEscrowHostResult -Volumes @($null) }
        [string]$r.Status  | Should Be 'ESCROW UNKNOWN'
        [int]$r.Volumes    | Should Be 0
    }
    It 'the severity ladder puts ESCROW UNKNOWN ABOVE ESCROWED (AD) so unknown can never roll up green' {
        $u = & $cm { Get-C2cEscrowRank 'ESCROW UNKNOWN' }
        $e = & $cm { Get-C2cEscrowRank 'ESCROWED (AD)' }
        ($u -gt $e) | Should Be $true
    }
    It 'the worker treats a session / probe failure as ESCROW UNKNOWN, never as offline-green' {
        $src = & $cm { $script:C2cEscrowAuditBlock.ToString() }
        $src | Should Match ([regex]::Escape("`$r.Status = 'ESCROW UNKNOWN'; `$r.Detail = `"Session:"))
        $src | Should Match ([regex]::Escape("`$r.Status = 'ESCROW UNKNOWN'; `$r.Detail = `"Probe:"))
    }
    It 'the worker soft-skips a DNS wrong box as ESCROW UNKNOWN (never reports another machine)' {
        $src = & $cm { $script:C2cEscrowAuditBlock.ToString() }
        $src | Should Match '(?i)DNS MISMATCH'
    }
    It 'reachability is TCP-only (5985/5986/445) - ICMP is GPO-blocked on AFNET' {
        $code = Remove-PsComments (& $cm { $script:C2cEscrowAuditBlock.ToString() })
        $code | Should Match ([regex]::Escape('foreach ($port in 5985,5986,445)'))
        $code | Should Not Match 'Test-Connection'
    }
}

Describe 'C2C escrow audit - the AD searcher: hygiene, GUID extraction, fail-closed' {

    # Fake DirectorySearcher. Every property the engine sets is declared so the sets are
    # observable; FindAll/Dispose are script methods. The engine wraps the optional sets
    # (ReferralChasing / timeouts / scope) in try/catch exactly like adsearch does.
    function New-FakeSearcher {
        param($Results = @(), [bool]$ThrowOnFind = $false)
        $o = New-Object psobject
        foreach ($p in @('ReferralChasing','ServerTimeLimit','ClientTimeout','SizeLimit','PageSize','SearchScope','Filter')) {
            $o | Add-Member -MemberType NoteProperty -Name $p -Value $null
        }
        $o | Add-Member -MemberType NoteProperty -Name PropertiesToLoad -Value (New-Object System.Collections.ArrayList)
        $o | Add-Member -MemberType NoteProperty -Name FakeResults -Value $Results
        $o | Add-Member -MemberType NoteProperty -Name ThrowOnFind -Value $ThrowOnFind
        $o | Add-Member -MemberType NoteProperty -Name Disposed -Value $false
        $o | Add-Member -MemberType ScriptMethod -Name FindAll -Value {
            if ($this.ThrowOnFind) { throw 'The user has insufficient access rights.' }
            return $this.FakeResults
        }
        $o | Add-Member -MemberType ScriptMethod -Name Dispose -Value { $this.Disposed = $true }
        return $o
    }
    # A hashtable answers .PropertyNames from its own key of that name and supports the
    # [] indexer the engine uses - close enough to ResultPropertyCollection for this.
    function New-FakeResult {
        param([hashtable]$Props, [string]$Path = '')
        $p = @{}
        foreach ($k in $Props.Keys) { $p[$k] = $Props[$k] }
        $p['PropertyNames'] = @($Props.Keys)
        return [pscustomobject]@{ Properties = $p; Path = $Path }
    }

    $dn      = 'CN=BOX01,OU=Workstations,DC=example,DC=mil'
    $guid    = [guid]'4e9e1234-5678-90ab-cdef-1234567890ab'
    $guidRaw = $guid.ToByteArray()

    # NOTE: .GetNewClosure() rebinds the scriptblock to a fresh dynamic module, so a factory
    # that CALLS New-FakeSearcher would not resolve it. Build the fakes eagerly and let the
    # closure capture them as plain variables.
    function New-Factory {
        param($DnSearcher, $EscrowSearcher)
        return { param([string]$Path) if (-not $Path) { return $DnSearcher } else { return $EscrowSearcher } }.GetNewClosure()
    }

    It 'loads msFVE-RecoveryGuid / whenCreated / name and NEVER msFVE-RecoveryPassword' {
        $sDn  = New-FakeSearcher -Results @((New-FakeResult @{ 'distinguishedname' = @($dn) }))
        $sEsc = New-FakeSearcher -Results @((New-FakeResult @{ 'msfve-recoveryguid' = @(, $guidRaw); 'name' = @('2026-07-25T00:00:00Z{4e9e1234-5678-90ab-cdef-1234567890ab}') }))
        $res  = & $cm { param($f) Get-C2cAdEscrowInfo -ComputerName 'BOX01' -SearcherFactory $f } (New-Factory $sDn $sEsc)
        [bool]$res.Ok | Should Be $true
        $loaded = @($sEsc.PropertiesToLoad)
        ($loaded -contains 'msFVE-RecoveryGuid') | Should Be $true
        ($loaded -contains 'whenCreated')        | Should Be $true
        ($loaded -contains 'name')               | Should Be $true
        @($loaded | Where-Object { "$_" -match '(?i)recoverypassword' }).Count | Should Be 0
    }
    It 'filters on objectClass=msFVE-RecoveryInformation under the computer DN' {
        $sDn  = New-FakeSearcher -Results @((New-FakeResult @{ 'distinguishedname' = @($dn) }))
        $sEsc = New-FakeSearcher -Results @()
        $null = & $cm { param($f) Get-C2cAdEscrowInfo -ComputerName 'BOX01' -SearcherFactory $f } (New-Factory $sDn $sEsc)
        [string]$sEsc.Filter | Should Be '(objectClass=msFVE-RecoveryInformation)'
    }
    It 'converts the msFVE-RecoveryGuid octet string to a matchable GUID' {
        $sDn  = New-FakeSearcher -Results @((New-FakeResult @{ 'distinguishedname' = @($dn) }))
        $sEsc = New-FakeSearcher -Results @((New-FakeResult @{ 'msfve-recoveryguid' = @(, $guidRaw) }))
        $res  = & $cm { param($f) Get-C2cAdEscrowInfo -ComputerName 'BOX01' -SearcherFactory $f } (New-Factory $sDn $sEsc)
        [bool]$res.Ok   | Should Be $true
        [int]$res.Count | Should Be 1
        (@($res.Guids)[0]) | Should Be '4e9e1234-5678-90ab-cdef-1234567890ab'
        [string]$res.Dn    | Should Be $dn
    }
    It 'falls back to the {guid} embedded in the object name when the octet string is unreadable' {
        $sDn  = New-FakeSearcher -Results @((New-FakeResult @{ 'distinguishedname' = @($dn) }))
        $sEsc = New-FakeSearcher -Results @((New-FakeResult @{ 'name' = @('2026-07-25T00:00:00Z{4e9e1234-5678-90ab-cdef-1234567890ab}') }))
        $res  = & $cm { param($f) Get-C2cAdEscrowInfo -ComputerName 'BOX01' -SearcherFactory $f } (New-Factory $sDn $sEsc)
        [bool]$res.Ok   | Should Be $true
        [int]$res.Count | Should Be 1
    }
    It 'a computer object ABSENT from AD is Ok=$false (the caller must report ESCROW UNKNOWN)' {
        $sDn = New-FakeSearcher -Results @()
        $res = & $cm { param($f) Get-C2cAdEscrowInfo -ComputerName 'GHOST01' -SearcherFactory $f } (New-Factory $sDn $sDn)
        [bool]$res.Ok | Should Be $false
        [string]$res.Error | Should Match '(?i)not found in AD'
    }
    It 'an ACL-denied msFVE search is Ok=$false with the denial in Error - never a clean empty set' {
        $sDn  = New-FakeSearcher -Results @((New-FakeResult @{ 'distinguishedname' = @($dn) }))
        $sEsc = New-FakeSearcher -ThrowOnFind $true
        $res  = & $cm { param($f) Get-C2cAdEscrowInfo -ComputerName 'BOX01' -SearcherFactory $f } (New-Factory $sDn $sEsc)
        [bool]$res.Ok | Should Be $false
        [string]$res.Error | Should Match '(?i)insufficient access rights'
        @($res.Guids).Count | Should Be 0
    }
    It 'a failed computer lookup is Ok=$false (never falls through to an empty escrow set)' {
        $sDn = New-FakeSearcher -ThrowOnFind $true
        $res = & $cm { param($f) Get-C2cAdEscrowInfo -ComputerName 'BOX01' -SearcherFactory $f } (New-Factory $sDn $sDn)
        [bool]$res.Ok | Should Be $false
        [string]$res.Error | Should Match '(?i)computer lookup failed'
    }
    It 'an IP-literal target is Ok=$false (no AD computer object to reconcile against)' {
        $res = & $cm { Get-C2cAdEscrowInfo -ComputerName '10.1.2.3' }
        [bool]$res.Ok | Should Be $false
        [string]$res.Error | Should Match '(?i)IP-literal'
    }
    It 'disposes every searcher it opens (adsearch hygiene - LDAP handles are unmanaged)' {
        $sDn  = New-FakeSearcher -Results @((New-FakeResult @{ 'distinguishedname' = @($dn) }))
        $sEsc = New-FakeSearcher -Results @()
        $null = & $cm { param($f) Get-C2cAdEscrowInfo -ComputerName 'BOX01' -SearcherFactory $f } (New-Factory $sDn $sEsc)
        [bool]$sDn.Disposed  | Should Be $true
        [bool]$sEsc.Disposed | Should Be $true
    }
    It 'the AD source sets ReferralChasing None, both timeouts, and a OneLevel scope under the computer DN' {
        $src = & $cm { $script:C2cEscrowAdSrc }
        $src | Should Match ([regex]::Escape('ReferralChasingOption]::None'))
        $src | Should Match ([regex]::Escape('ServerTimeLimit'))
        $src | Should Match ([regex]::Escape('ClientTimeout'))
        $src | Should Match ([regex]::Escape('SearchScope]::OneLevel'))
        $src | Should Match ([regex]::Escape('(objectClass=msFVE-RecoveryInformation)'))
    }
}

# =============================================================================
#  THE NON-NEGOTIABLE. A fix for a key-visibility gap must not itself leak keys.
# =============================================================================
Describe 'C2C escrow audit - NO recovery password can reach a row, a log line, a summary or the CSV' {

    It 'the AD searcher CODE (comments stripped) never mentions RecoveryPassword at all' {
        $code = Remove-PsComments (& $cm { $script:C2cEscrowAdSrc })
        $code | Should Not Match '(?i)RecoveryPassword'
        # ...while the attributes it DOES load are present as real call sites.
        $code | Should Match ([regex]::Escape("'msFVE-RecoveryGuid'"))
    }
    It 'the endpoint probe CODE (comments stripped) never reads the .RecoveryPassword property' {
        $code = Remove-PsComments (& $cm { $script:C2cEscrowProbeSrc })
        $code | Should Not Match '\.RecoveryPassword'
        # the only protector fields it DOES read:
        $code | Should Match ([regex]::Escape('$kp.KeyProtectorType'))
        $code | Should Match ([regex]::Escape('$kp.KeyProtectorId'))
    }
    It 'the verdict/rollup CODE (comments stripped) never mentions RecoveryPassword as a field read' {
        $code = Remove-PsComments (& $cm { $script:C2cEscrowVerdictSrc })
        $code | Should Not Match '\.RecoveryPassword'
    }

    It 'the endpoint probe, run against protectors that DO carry a key, emits no key-shaped field' {
        $out = & $cm {
            param($poison)
            $__shims = Save-ShimState @('Get-BitLockerVolume','Get-Volume','Get-CimInstance','Get-Tpm')
            try {
                $script:__poison = $poison
                function script:Get-Volume {
                    param($ErrorAction)
                    @(
                        [pscustomobject]@{ DriveType='Fixed';     DriveLetter='C' }
                        [pscustomobject]@{ DriveType='Fixed';     DriveLetter='D' }
                        [pscustomobject]@{ DriveType='Removable'; DriveLetter='E' }
                    )
                }
                function script:Get-CimInstance { param($ClassName, $ErrorAction) @() }
                function script:Get-Tpm { param($ErrorAction) [pscustomobject]@{ TpmPresent=$true; TpmReady=$true; TpmOwned=$true } }
                function script:Get-BitLockerVolume {
                    param($MountPoint, $ErrorAction)
                    $kpOs = @(
                        [pscustomobject]@{ KeyProtectorType='Tpm';              KeyProtectorId='{aaaaaaaa-1111-2222-3333-444444444444}'; RecoveryPassword='' }
                        [pscustomobject]@{ KeyProtectorType='RecoveryPassword'; KeyProtectorId='{4e9e1234-5678-90ab-cdef-1234567890ab}'; RecoveryPassword=$script:__poison }
                    )
                    $kpD = @(
                        [pscustomobject]@{ KeyProtectorType='RecoveryPassword'; KeyProtectorId='{bbbbbbbb-1111-2222-3333-444444444444}'; RecoveryPassword=$script:__poison }
                    )
                    @(
                        [pscustomobject]@{ MountPoint='C:'; VolumeType='OperatingSystem'; ProtectionStatus='On'; VolumeStatus='FullyEncrypted'; EncryptionMethod='XtsAes256'; KeyProtector=$kpOs }
                        [pscustomobject]@{ MountPoint='D:'; VolumeType='Data';            ProtectionStatus='On'; VolumeStatus='FullyEncrypted'; EncryptionMethod='XtsAes256'; KeyProtector=$kpD }
                        # E: is REMOVABLE (BitLocker To Go). It must never be read or reported.
                        [pscustomobject]@{ MountPoint='E:'; VolumeType='Data';            ProtectionStatus='On'; VolumeStatus='FullyEncrypted'; EncryptionMethod='XtsAes256'; KeyProtector=$kpD }
                    )
                }
                $facts = Get-C2cEscrowFacts
                $roll  = Get-C2cEscrowHostResult -Volumes @($facts.Volumes) -VolErr ([string]$facts.VolErr) `
                            -AdGuids @('4e9e1234-5678-90ab-cdef-1234567890ab', 'bbbbbbbb-1111-2222-3333-444444444444') `
                            -AdOk $true -AdObjectCount 2 `
                            -Tpm ([string]$facts.Tpm) -TpmErr ([string]$facts.TpmErr)
                return @{
                    FactsJson = ($facts | ConvertTo-Json -Depth 8 -Compress)
                    RollJson  = ($roll  | ConvertTo-Json -Depth 8 -Compress)
                    Status    = [string]$roll.Status
                    Mounts    = @(@($facts.Volumes) | ForEach-Object { [string]$_.MountPoint })
                    Props     = @(@($facts.Volumes)[0].PSObject.Properties | ForEach-Object { $_.Name })
                }
            } finally { Restore-ShimState $__shims; Remove-Variable -Name __poison -Scope Script -ErrorAction SilentlyContinue }
        } $script:PoisonKey

        # 1. the whole probe payload
        [string]$out.FactsJson | Should Not Match $script:KeyRegex
        # 2. the whole rollup - row cells, detail, per-volume report, escrow counts
        [string]$out.RollJson  | Should Not Match $script:KeyRegex
        # 3. and the verdict still worked
        [string]$out.Status    | Should Be 'ESCROWED (AD)'
    }

    It 'only the whitelisted per-volume fields survive the probe (no KeyProtector object rides along)' {
        $out = & $cm {
            param($poison)
            $__shims = Save-ShimState @('Get-BitLockerVolume','Get-Volume','Get-CimInstance','Get-Tpm')
            try {
                $script:__poison = $poison
                function script:Get-Volume { param($ErrorAction) @([pscustomobject]@{ DriveType='Fixed'; DriveLetter='C' }) }
                function script:Get-CimInstance { param($ClassName, $ErrorAction) @() }
                function script:Get-Tpm { param($ErrorAction) [pscustomobject]@{ TpmPresent=$true; TpmReady=$true; TpmOwned=$true } }
                function script:Get-BitLockerVolume {
                    param($MountPoint, $ErrorAction)
                    @([pscustomobject]@{ MountPoint='C:'; VolumeType='OperatingSystem'; ProtectionStatus='On'; VolumeStatus='FullyEncrypted'; EncryptionMethod='XtsAes256'
                        KeyProtector=@([pscustomobject]@{ KeyProtectorType='RecoveryPassword'; KeyProtectorId='{4e9e1234-5678-90ab-cdef-1234567890ab}'; RecoveryPassword=$script:__poison }) })
                }
                $facts = Get-C2cEscrowFacts
                return @{
                    Props  = @(@($facts.Volumes)[0].PSObject.Properties | ForEach-Object { $_.Name })
                    Mounts = @(@($facts.Volumes) | ForEach-Object { [string]$_.MountPoint })
                }
            } finally { Restore-ShimState $__shims; Remove-Variable -Name __poison -Scope Script -ErrorAction SilentlyContinue }
        } $script:PoisonKey

        $props = @($out.Props)
        ($props -contains 'KeyProtector')      | Should Be $false
        ($props -contains 'RecoveryPassword')  | Should Be $false
        ($props -contains 'RecoveryIds')       | Should Be $true
        ($props -contains 'KeyProtectorTypes') | Should Be $true
        ($props -contains 'MountPoint')        | Should Be $true
        @($out.Mounts).Count | Should Be 1
    }

    It 'REMOVABLE / non-fixed volumes are never read or reported' {
        $out = & $cm {
            $__shims = Save-ShimState @('Get-BitLockerVolume','Get-Volume','Get-CimInstance','Get-Tpm')
            try {
                function script:Get-Volume {
                    param($ErrorAction)
                    @(
                        [pscustomobject]@{ DriveType='Fixed';     DriveLetter='C' }
                        [pscustomobject]@{ DriveType='Removable'; DriveLetter='E' }
                        [pscustomobject]@{ DriveType='CD-ROM';    DriveLetter='F' }
                    )
                }
                function script:Get-CimInstance { param($ClassName, $ErrorAction) @() }
                function script:Get-Tpm { param($ErrorAction) [pscustomobject]@{ TpmPresent=$true; TpmReady=$true; TpmOwned=$true } }
                function script:Get-BitLockerVolume {
                    param($MountPoint, $ErrorAction)
                    @(
                        [pscustomobject]@{ MountPoint='C:'; VolumeType='OperatingSystem'; ProtectionStatus='On'; VolumeStatus='FullyEncrypted'; EncryptionMethod='XtsAes256'; KeyProtector=@() }
                        [pscustomobject]@{ MountPoint='E:'; VolumeType='Data'; ProtectionStatus='On'; VolumeStatus='FullyEncrypted'; EncryptionMethod='XtsAes128'; KeyProtector=@() }
                        [pscustomobject]@{ MountPoint='F:'; VolumeType='Data'; ProtectionStatus='Off'; VolumeStatus='FullyDecrypted'; EncryptionMethod=''; KeyProtector=@() }
                        [pscustomobject]@{ MountPoint='\\?\Volume{1111}\'; VolumeType='Data'; ProtectionStatus='Off'; VolumeStatus='FullyDecrypted'; EncryptionMethod=''; KeyProtector=@() }
                    )
                }
                $facts = Get-C2cEscrowFacts
                return @(@($facts.Volumes) | ForEach-Object { [string]$_.MountPoint })
            } finally { Restore-ShimState $__shims }
        }
        @($out) -join ',' | Should Be 'C:'
    }

    It 'an unreadable Get-BitLockerVolume yields a VolErr, not a silent empty (fail closed)' {
        $st = & $cm {
            $__shims = Save-ShimState @('Get-BitLockerVolume','Get-Volume','Get-CimInstance','Get-Tpm')
            try {
                function script:Get-Volume { param($ErrorAction) @([pscustomobject]@{ DriveType='Fixed'; DriveLetter='C' }) }
                function script:Get-CimInstance { param($ClassName, $ErrorAction) @() }
                function script:Get-Tpm { param($ErrorAction) [pscustomobject]@{ TpmPresent=$true; TpmReady=$true; TpmOwned=$true } }
                function script:Get-BitLockerVolume { param($MountPoint, $ErrorAction) throw 'Access is denied' }
                $facts = Get-C2cEscrowFacts
                $roll  = Get-C2cEscrowHostResult -Volumes @($facts.Volumes) -VolErr ([string]$facts.VolErr) -AdGuids @() -AdOk $true
                return [string]$roll.Status
            } finally { Restore-ShimState $__shims }
        }
        $st | Should Be 'ESCROW UNKNOWN'
    }

    It 'the shims were fully restored (Save/Restore, not the inert function:script: delete)' {
        $leaked = & $cm {
            @(@('Get-BitLockerVolume','Get-Volume','Get-CimInstance','Get-Tpm') | Where-Object {
                $i = Get-Item -LiteralPath "function:$_" -ErrorAction SilentlyContinue
                $i -and ($i.ScriptBlock.ToString() -match '(?i)__poison|DriveLetter=')
            })
        }
        @($leaked).Count | Should Be 0
    }
}
