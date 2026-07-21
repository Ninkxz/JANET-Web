# =============================================================================
#  AdTo.WriteGuards.Tests.ps1 - Pester 3.4 for the loop-12 adto write-path
#  hardening (v0.2.2). The loop-12 Opus deep-dive of the AD-write tool found:
#   F1 (P2): 'fix' applied client-plan rules to ANY in-domain DN with no
#            object-type guard - a crafted/fat-fingered plan naming a DOMAIN
#            CONTROLLER computer object or a PRIVILEGED (adminCount>=1) account
#            would get ACCOUNTDISABLE set (a DoS of a critical AD object). The DN
#            guard proves in-domain, not object criticality. Now refused + audited.
#   F2 (P2): 'validate-iao' reported VALIDATED with NO post-commit re-read
#            (fail-open), unlike 'fix' which re-reads. Now fail-closed re-read.
#   F3 (P3): bind-redirect rejections were not audited. Now emit an audit event.
#
#  No real AD: New-AdToEntry (the LDAP bind), Test-AdToDnInLocalDomain, the domain
#  suffix, and (for validate) Test-AdToIaoAuthorized are shadowed in MODULE scope,
#  so the write logic runs against fake DirectoryEntry objects and NOTHING binds
#  a real directory.
#
#  Run:  Invoke-Pester -Path .\tests\AdTo.WriteGuards.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$m = Import-Module (Join-Path $script:Root 'modules\JanetWeb.adto.psm1') -Force -PassThru

# Build a fake DirectoryEntry: .Properties['x'].Value get/set + .CommitChanges().
function New-FakeDe {
    param([int]$Uac = 512, [int]$AdminCount = 0, [string]$Attr = 'info', [string]$AttrValue = '')
    $props = @{
        userAccountControl = [pscustomobject]@{ Value = $Uac }
        adminCount         = [pscustomobject]@{ Value = $AdminCount }
    }
    $props[$Attr] = [pscustomobject]@{ Value = $AttrValue }
    $de = [pscustomobject]@{ _props = $props; Committed = $false }
    Add-Member -InputObject $de -MemberType ScriptProperty -Name Properties -Value { $this._props }
    Add-Member -InputObject $de -MemberType ScriptMethod  -Name CommitChanges -Value { $this.Committed = $true }
    $de
}

# Run 'fix' with New-AdToEntry returning $script:__fakeFix (shared, so the write +
# the fix path's verification re-read see the same mutated object).
function Invoke-FixWith {
    param($Fake, [string]$Rule)
    $evs = New-Object System.Collections.ArrayList
    $emit = { param($e) [void]$evs.Add($e) }
    $res = & $m {
        param($fake, $rule, $em)
        $script:__fakeFix = $fake
        function script:New-AdToEntry { param($Dn, $Credential) $script:__fakeFix }
        function script:Test-AdToDnInLocalDomain { param($Value, $ExpectDomainSuffix) $true }
        function script:Get-AdToExpectedDomainSuffix { 'DC=test,DC=local' }
        try {
            $plan = (@(@{ dn = 'CN=OBJ,OU=x,DC=test,DC=local'; rules = @($rule) }) | ConvertTo-Json -Compress -Depth 5)
            if ($plan -notmatch '^\[') { $plan = '[' + $plan + ']' }   # single-element array stays an array
            Invoke-JanetToolAction -ActionId 'fix' -Params @{ confirm='FIX'; plan=$plan } -Credential $null -Emit $em
        } finally {
            Remove-Item function:script:New-AdToEntry, function:script:Test-AdToDnInLocalDomain, function:script:Get-AdToExpectedDomainSuffix -ErrorAction SilentlyContinue
        }
    } $Fake $Rule $emit
    @{ Result = $res; Events = @($evs) }
}

Describe 'adto 0.2.4 - manifest loads at the bumped version' {
    $mani = & $m { Get-JanetToolManifest }
    It 'manifest id is adto and version is 0.2.4' {
        [string]$mani.id      | Should Be 'adto'
        [string]$mani.version | Should Be '0.2.4'
    }
    It 'fix + validate-iao are destructive' {
        foreach ($aid in @('fix','validate-iao')) {
            $a = @($mani.actions | Where-Object { $_.id -eq $aid })[0]
            [bool]$a.destructive | Should Be $true
        }
    }
}

Describe 'adto F1 - fix REFUSES a domain controller + a privileged object (protected-object guard)' {
    It 'a DC computer object (SERVER_TRUST=0x2000) is PROTECTED, never committed' {
        $de = New-FakeDe -Uac 0x2000 -AdminCount 0     # SERVER_TRUST set = DC
        $o = Invoke-FixWith -Fake $de -Rule 'staleObject'
        $row = @($o.Events | Where-Object { $_.type -eq 'row' })[0]
        [string]$row.Status | Should Be 'PROTECTED'
        $de.Committed | Should Be $false
        @($o.Events | Where-Object { $_.type -eq 'audit' -and $_.result -eq 'Skipped' -and $_.detail -match 'PROTECTED' }).Count | Should BeGreaterThan 0
    }
    It 'an adminCount>=1 (privileged/break-glass) object is PROTECTED, never committed' {
        $de = New-FakeDe -Uac 514 -AdminCount 1        # normal UAC but AdminSDHolder-protected
        $o = Invoke-FixWith -Fake $de -Rule 'inactiveEnabled'
        $row = @($o.Events | Where-Object { $_.type -eq 'row' })[0]
        [string]$row.Status | Should Be 'PROTECTED'
        $de.Committed | Should Be $false
    }
    It 'a READ-ONLY DC (PARTIAL_SECRETS_ACCOUNT=0x04000000, no SERVER_TRUST) is PROTECTED (loop13)' {
        # An RODC computer object carries WORKSTATION_TRUST(0x1000)+PARTIAL_SECRETS_ACCOUNT,
        # NOT SERVER_TRUST - it slipped the original guard. Now caught.
        $de = New-FakeDe -Uac (0x1000 -bor 0x04000000) -AdminCount 0
        $o = Invoke-FixWith -Fake $de -Rule 'staleObject'
        $row = @($o.Events | Where-Object { $_.type -eq 'row' })[0]
        [string]$row.Status | Should Be 'PROTECTED'
        $de.Committed | Should Be $false
    }
    It 'a NORMAL workstation/user object is still FIXED (no over-block)' {
        $de = New-FakeDe -Uac 512 -AdminCount 0        # NORMAL_ACCOUNT, not privileged, not a DC
        $o = Invoke-FixWith -Fake $de -Rule 'inactiveEnabled'
        $row = @($o.Events | Where-Object { $_.type -eq 'row' })[0]
        [string]$row.Status | Should Be 'FIXED'
        $de.Committed | Should Be $true
        # ACCOUNTDISABLE (0x2) was OR-ed in
        ([int]$de.Properties['userAccountControl'].Value -band 0x2) | Should Be 2
    }
}

Describe 'adto F1b (loop53) - a NULL/unreadable userAccountControl fails closed, never "already compliant"' {
    # A non-account object (group/OU/contact - no UAC) or an ACL-denied UAC read: Properties.Value is $null.
    # New-FakeDe types -Uac [int] (can't be null), so build a null-UAC fake inline.
    function New-FakeDeNullUac {
        param([int]$AdminCount = 0)
        $props = @{
            userAccountControl = [pscustomobject]@{ Value = $null }
            adminCount         = [pscustomobject]@{ Value = $AdminCount }
        }
        $de = [pscustomobject]@{ _props = $props; Committed = $false }
        Add-Member -InputObject $de -MemberType ScriptProperty -Name Properties -Value { $this._props }
        Add-Member -InputObject $de -MemberType ScriptMethod  -Name CommitChanges -Value { $this.Committed = $true }
        $de
    }
    It 'a clear-op rule on a null-UAC object -> FAILED (not NO CHANGE "already compliant"); nothing committed' {
        $de = New-FakeDeNullUac
        $o = Invoke-FixWith -Fake $de -Rule 'passwordNeverExpires'
        $row = @($o.Events | Where-Object { $_.type -eq 'row' })[0]
        [string]$row.Status | Should Be 'FAILED'
        ([string]$row.Detail) | Should Match '(?i)userAccountControl (absent|unreadable)'
        $de.Committed | Should Be $false
    }
    It 'a set-op rule on a null-UAC object -> FAILED, NO corrupting write (was: wrote a full UAC wiping NORMAL_ACCOUNT)' {
        $de = New-FakeDeNullUac
        $o = Invoke-FixWith -Fake $de -Rule 'smartcardNotRequired'
        $row = @($o.Events | Where-Object { $_.type -eq 'row' })[0]
        [string]$row.Status | Should Be 'FAILED'
        $de.Committed | Should Be $false
    }
    It 'the FAILED-null path books a Failure audit (not Skipped/Success)' {
        $de = New-FakeDeNullUac
        $o = Invoke-FixWith -Fake $de -Rule 'passwordNeverExpires'
        @($o.Events | Where-Object { $_.type -eq 'audit' -and $_.result -eq 'Failure' }).Count | Should BeGreaterThan 0
    }
}

Describe 'adto F3 - a bind-redirect rejection is AUDITED, not just a UI row' {
    It 'a DN that fails the local-domain guard emits a Skipped audit event' {
        $evs = New-Object System.Collections.ArrayList
        $emit = { param($e) [void]$evs.Add($e) }
        $null = & $m {
            param($em)
            function script:New-AdToEntry { param($Dn, $Credential) throw 'should never bind a rejected DN' }
            function script:Test-AdToDnInLocalDomain { param($Value, $ExpectDomainSuffix) $false }   # force reject
            function script:Get-AdToExpectedDomainSuffix { 'DC=test,DC=local' }
            try {
                Invoke-JanetToolAction -ActionId 'fix' -Params @{ confirm='FIX'; plan='[{"dn":"DC=evil,DC=com","rules":["staleObject"]}]' } -Credential $null -Emit $em
            } finally {
                Remove-Item function:script:New-AdToEntry, function:script:Test-AdToDnInLocalDomain, function:script:Get-AdToExpectedDomainSuffix -ErrorAction SilentlyContinue
            }
        } $emit
        $row = @($evs | Where-Object { $_.type -eq 'row' })[0]
        [string]$row.Status | Should Be 'REJECTED'
        @($evs | Where-Object { $_.type -eq 'audit' -and $_.result -eq 'Skipped' -and $_.detail -match 'REJECTED.*bind-redirect' }).Count | Should BeGreaterThan 0
    }
}

Describe 'adto F2 - validate-iao is FAIL-CLOSED: VALIDATED only when the stamp re-reads' {
    # persist=$true: same fake for write + re-read -> stamp present -> VALIDATED.
    # persist=$false: re-read returns a fresh empty object -> no stamp -> FAILED.
    function Invoke-ValidateWith {
        param([bool]$Persist)
        $evs = New-Object System.Collections.ArrayList
        $emit = { param($e) [void]$evs.Add($e) }
        $res = & $m {
            param($persist, $em)
            $script:__vCalls = 0
            $script:__vWrite = (& { $p = @{ userAccountControl=[pscustomobject]@{Value=512}; adminCount=[pscustomobject]@{Value=0}; info=[pscustomobject]@{Value=''} }
                $d = [pscustomobject]@{ _props=$p; Committed=$false }
                Add-Member -InputObject $d -MemberType ScriptProperty -Name Properties -Value { $this._props }
                Add-Member -InputObject $d -MemberType ScriptMethod -Name CommitChanges -Value { $this.Committed=$true }; $d })
            function script:New-AdToEntry {
                param($Dn, $Credential)
                $script:__vCalls++
                if ($script:__vCalls -eq 1) { return $script:__vWrite }         # the write target
                if ($persist) { return $script:__vWrite }                        # re-read sees the stamp
                # non-persist: a fresh empty object (stamp never landed)
                $p = @{ info=[pscustomobject]@{Value=''} }
                $d = [pscustomobject]@{ _props=$p }
                Add-Member -InputObject $d -MemberType ScriptProperty -Name Properties -Value { $this._props }
                return $d
            }
            function script:Test-AdToDnInLocalDomain { param($Value, $ExpectDomainSuffix) $true }
            function script:Get-AdToExpectedDomainSuffix { 'DC=test,DC=local' }
            function script:Test-AdToIaoAuthorized { param($Identity, $Baseline) $true }   # RBAC satisfied for the test
            try {
                Invoke-JanetToolAction -ActionId 'validate-iao' -Params @{ confirm='VALIDATE'; plan='[{"dn":"CN=U,OU=x,DC=test,DC=local"}]' } -Credential $null -Emit $em
            } finally {
                Remove-Item function:script:New-AdToEntry, function:script:Test-AdToDnInLocalDomain, function:script:Get-AdToExpectedDomainSuffix, function:script:Test-AdToIaoAuthorized -ErrorAction SilentlyContinue
            }
        } $Persist $emit
        @{ Result = $res; Events = @($evs) }
    }

    It 'stamp persists on re-read -> VALIDATED' {
        $o = Invoke-ValidateWith -Persist $true
        $row = @($o.Events | Where-Object { $_.type -eq 'row' })[0]
        [string]$row.Status | Should Be 'VALIDATED'
    }
    It 'stamp does NOT persist (commit did not land) -> FAILED, not a false VALIDATED' {
        $o = Invoke-ValidateWith -Persist $false
        $row = @($o.Events | Where-Object { $_.type -eq 'row' })[0]
        [string]$row.Status | Should Be 'FAILED'
        @($o.Events | Where-Object { $_.type -eq 'audit' -and $_.result -eq 'Failure' }).Count | Should BeGreaterThan 0
    }
}
