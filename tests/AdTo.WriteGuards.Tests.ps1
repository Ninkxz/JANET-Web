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
#  Extended for the 2026-07-24 audit (v0.2.7):
#   F1'  (P2): "never logged on = maximally stale" had no object-age floor, so a
#              freshly PRE-STAGED computer / just-created user was flagged stale or
#              inactive - and BOTH rules map to a set-ACCOUNTDISABLE, so the fixer
#              auto-DISABLED a brand-new account. Now aged from whenCreated + a
#              newObjectGraceDays floor.
#   F5'  (P3): the loop54 uacUnreadable fail-closed hit was wired only into the
#              User/Admin/Service branch; Computer/Server derived $disabled from a
#              UAC it had never read and could scan an ACL-hidden object COMPLIANT.
#   F9'  (P4): the 'Object' display column truncated a CN carrying an RFC-4514
#              ESCAPED comma (CN=Smith\, John,..) to 'Smith\' - the very escaping
#              the DN guard deliberately allows.
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

# Shim hygiene (audit 2026-07-24): the shims below are declared with 'function script:X' INSIDE
# the module, which REPLACES the module's own X - they share one scope. Their teardown
# 'Remove-Item function:script:X' does NOT undo that: the function provider has no scope
# qualifier in its paths, so 'function:script:X' names a non-existent item and the -EA
# SilentlyContinue swallows it - the SHIM LEAKED into every later Describe (whose $p/$persist
# closures are long out of scope, so e.g. Get-AdToBaselinePath then returned $null and
# Get-AdToBaseline blew up on a null LiteralPath). Snapshot the genuine definitions before
# anything is shimmed and Set-Item them back after each shimmed call - Set-Item function:script:X
# DOES target the module scope, and restoring the captured ScriptBlock keeps its module binding
# (and therefore $PSScriptRoot).
$script:AdToRealFns = & $m {
    $h = @{}
    foreach ($n in 'Get-AdToBaselinePath','New-AdToEntry','Test-AdToDnInLocalDomain','Get-AdToExpectedDomainSuffix','Test-AdToIaoAuthorized') {
        $c = Get-Item ("function:$n") -ErrorAction SilentlyContinue
        if ($c) { $h[$n] = $c.ScriptBlock }
    }
    $h
}
function Restore-AdToFns {
    & $m { param($h) foreach ($k in @($h.Keys)) { Set-Item ("function:script:$k") -Value $h[$k] } } $script:AdToRealFns
}

# The real, unshimmed baseline, read ONCE before any Describe can shim the path resolver, so the
# compliance Describes below never depend on the shim/restore order of the write-path Describes.
$script:AdToBase = & $m { Get-AdToBaseline }

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
    param($Fake, [string]$Rule, [string]$Dn = 'CN=OBJ,OU=x,DC=test,DC=local')
    $evs = New-Object System.Collections.ArrayList
    $emit = { param($e) [void]$evs.Add($e) }
    $res = & $m {
        param($fake, $rule, $em, $dn)
        $script:__fakeFix = $fake
        function script:New-AdToEntry { param($Dn, $Credential) $script:__fakeFix }
        function script:Test-AdToDnInLocalDomain { param($Value, $ExpectDomainSuffix) $true }
        function script:Get-AdToExpectedDomainSuffix { 'DC=test,DC=local' }
        try {
            $plan = (@(@{ dn = $dn; rules = @($rule) }) | ConvertTo-Json -Compress -Depth 5)
            if ($plan -notmatch '^\[') { $plan = '[' + $plan + ']' }   # single-element array stays an array
            Invoke-JanetToolAction -ActionId 'fix' -Params @{ confirm='FIX'; plan=$plan } -Credential $null -Emit $em
        } finally {
            Remove-Item function:script:New-AdToEntry, function:script:Test-AdToDnInLocalDomain, function:script:Get-AdToExpectedDomainSuffix -ErrorAction SilentlyContinue
        }
    } $Fake $Rule $emit $Dn
    Restore-AdToFns
    @{ Result = $res; Events = @($evs) }
}

Describe 'adto 0.2.9 - manifest loads at the bumped version' {
    $mani = & $m { Get-JanetToolManifest }
    It 'manifest id is adto and version is 0.2.9' {
        [string]$mani.id      | Should Be 'adto'
        [string]$mani.version | Should Be '0.2.9'
    }
    It 'fix + validate-iao are destructive' {
        foreach ($aid in @('fix','validate-iao')) {
            $a = @($mani.actions | Where-Object { $_.id -eq $aid })[0]
            [bool]$a.destructive | Should Be $true
        }
    }
}

# =============================================================================
#  audit 2026-07-25 (fable re-audit follow-up) - the ENGINE already reported
#  "Cancelled. X fixed of Y" (and summary.cancelled), but the write-run view painted
#  "<verb> done" GREEN and popped a "<verb> complete" dialog on active:false
#  UNCONDITIONALLY, so a cancelled DESTRUCTIVE AD write ended on a success headline.
#  The engine side is asserted below (it was never wrong); these pin the view fix.
# =============================================================================
Describe 'adto write runs report a CANCEL honestly (audit 2026-07-25)' {

    $view = [System.IO.File]::ReadAllText((Join-Path $script:Root 'web\js\views\adto.view.js'))
    $bind = [regex]::Match($view, '(?s)function bindWriteRun\(verb\)\s*\{.*?\n      \}').Value

    It 'the write-run binder was located' {
        ($bind -match 'run\.subscribe') | Should Be $true
    }
    It 'it reads the engine verdict off the final event' {
        ($bind -match 'res\.summary\.cancelled') | Should Be $true
    }
    It 'a hard-killed job (no final event) still counts as cancelled via the run state' {
        ($bind -match "run\.state\.status\) === 'cancelled'") | Should Be $true
    }
    It 'the green "done" headline + complete dialog are now behind the NOT-cancelled branch' {
        ($bind -match "if \(stopped\) \{")                          | Should Be $true
        ($bind -match "CANCELLED - partial write")                  | Should Be $true
        # the unconditional success pair is gone: both now live in the else branch
        ($bind -match "(?s)\} else \{[^}]*st-ok'\)")                | Should Be $true
    }
    It 'the engine still ships summary.cancelled for BOTH write actions (unchanged, but load-bearing)' {
        $src = [System.IO.File]::ReadAllText((Join-Path $script:Root 'modules\JanetWeb.adto.psm1'))
        ([regex]::Matches($src, 'cancelled=\$cancelled').Count -ge 3) | Should Be $true
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

Describe 'adto F2b (loop54) - the SCAN reads an unreadable userAccountControl as NON-COMPLIANT, not COMPLIANT' {
    $base = $script:AdToBase
    $now  = [datetime]'2026-07-21T00:00:00Z'
    $recent = $now.AddDays(-1).ToFileTimeUtc()
    It 'a Service account with UacReadable=$false -> a uacUnreadable hit (NON-COMPLIANT), never silently COMPLIANT' {
        $obj = @{ Uac=0; UacReadable=$false; LastLogonTicks=$recent; Description='svc'; Manager='CN=M,DC=t,DC=l'; RecertValue=''; ServicePrincipalName=@() }
        $r = & $m { param($o,$b,$n) Test-AdToCompliance -Obj $o -Category 'Service' -Baseline $b -Now $n } $obj $base $now
        [string]$r.Status | Should Be 'NON-COMPLIANT'
        (@($r.Rules) -contains 'uacUnreadable') | Should Be $true
    }
    It 'a readable UAC (UacReadable=$true, no bad bits) does NOT get the uacUnreadable hit (no over-flag)' {
        $obj = @{ Uac=0x200; UacReadable=$true; LastLogonTicks=$recent; Description='svc'; Manager='CN=M,DC=t,DC=l'; RecertValue=''; ServicePrincipalName=@() }
        $r = & $m { param($o,$b,$n) Test-AdToCompliance -Obj $o -Category 'Service' -Baseline $b -Now $n } $obj $base $now
        (@($r.Rules) -contains 'uacUnreadable') | Should Be $false
    }
    It 'a readable UAC with PASSWD_NOTREQD (0x20) set is still flagged - the real bad-bit path still works' {
        $obj = @{ Uac=(0x200 -bor 0x20); UacReadable=$true; LastLogonTicks=$recent; Description='svc'; Manager='CN=M,DC=t,DC=l'; RecertValue=''; ServicePrincipalName=@() }
        $r = & $m { param($o,$b,$n) Test-AdToCompliance -Obj $o -Category 'Service' -Baseline $b -Now $n } $obj $base $now
        (@($r.Rules) -contains 'passwordNotRequired') | Should Be $true
    }
    It 'an object built WITHOUT a UacReadable key is treated as readable (back-compat)' {
        $obj = @{ Uac=0x200; LastLogonTicks=$recent; Description='svc'; Manager='CN=M,DC=t,DC=l'; RecertValue=''; ServicePrincipalName=@() }
        $r = & $m { param($o,$b,$n) Test-AdToCompliance -Obj $o -Category 'Service' -Baseline $b -Now $n } $obj $base $now
        (@($r.Rules) -contains 'uacUnreadable') | Should Be $false
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
        # audit 2026-07-25: this block was the one shim site in this file with no restore after it.
        # The inert 'Remove-Item function:script:' above does nothing (see header), so New-AdToEntry
        # (a stub that THROWS) leaked out of this It. It was masked only because the next Describe
        # re-shims all three names and then restores them - i.e. green by accident of file order.
        Restore-AdToFns
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
        Restore-AdToFns
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

# loop55 (F3, item61): an overlay entry that tunes ONE field of a rule (or a typo) must NOT silently
# disable the rule. Old merge REPLACED the rule with the overlay's fields, so a missing 'enabled' became
# [bool]$null=$false (rule OFF) and a missing 'appliesTo' became @($null) (never fires) -> every violating
# object scanned COMPLIANT with no trace. Now the overlay MERGES onto the embedded default.
Describe 'adto F3b (loop55) - baseline overlay merges, does not silently disable a rule on a typo' {
    # Read Get-AdToBaseline with a partial overlay supplied via a real temp file (shim only the path
    # resolver - adto-specific - so Test-Path/Get-Content stay real and cannot leak into sibling tests).
    function Get-OverlaidBaseline {
        param([string]$Json)
        $tmp = Join-Path $env:TEMP ("adto-overlay-loop55-$PID.json")
        Set-Content -LiteralPath $tmp -Value $Json -Encoding UTF8
        try {
            & $m {
                param($p)
                function script:Get-AdToBaselinePath { $p }
                try { Get-AdToBaseline } finally { Remove-Item function:script:Get-AdToBaselinePath -ErrorAction SilentlyContinue }
            } $tmp
        } finally { Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue; Restore-AdToFns }
    }

    It 'overlay tuning only requiresIao keeps the default enabled=true (not silently OFF)' {
        $b = Get-OverlaidBaseline -Json '{ "rules": { "passwordNotRequired": { "requiresIao": true } } }'
        [bool]$b.rules['passwordNotRequired'].enabled | Should Be $true
    }
    It 'overlay tuning only requiresIao keeps the default appliesTo (rule still fires)' {
        $b = Get-OverlaidBaseline -Json '{ "rules": { "passwordNotRequired": { "requiresIao": true } } }'
        (@($b.rules['passwordNotRequired'].appliesTo) -contains 'User') | Should Be $true
    }
    It 'the field the overlay DID provide is applied' {
        $b = Get-OverlaidBaseline -Json '{ "rules": { "passwordNotRequired": { "requiresIao": true } } }'
        [bool]$b.rules['passwordNotRequired'].requiresIao | Should Be $true
    }
    It 'an EXPLICIT enabled=false still disables the rule (intentional override honored)' {
        $b = Get-OverlaidBaseline -Json '{ "rules": { "passwordNotRequired": { "enabled": false } } }'
        [bool]$b.rules['passwordNotRequired'].enabled | Should Be $false
    }
}

# -----------------------------------------------------------------------------
#  audit 2026-07-24 (P2, item F1'): a NEVER-LOGGED-ON object is not automatically
#  the stalest object in the domain. lastLogon=0 is the DEFINING state of a
#  freshly pre-staged computer account and of a user created this morning, and the
#  old +Inf age made staleObject / inactiveEnabled fire on both - each of which
#  maps to a set-ACCOUNTDISABLE in $script:AdToUacFix, so the fixer DISABLED a
#  brand-new account on the first scan after it was created. Age from whenCreated
#  instead, with a newObjectGraceDays hard floor on top.
# -----------------------------------------------------------------------------
Describe "adto F1' (audit 2026-07-24) - a freshly created, never-logged-on object is NOT flagged stale/inactive" {
    $base = $script:AdToBase
    $now  = [datetime]::SpecifyKind([datetime]'2026-07-21T00:00:00', [System.DateTimeKind]::Utc)
    $created2d  = $now.AddDays(-2)      # pre-staged 2 days ago
    $created400 = $now.AddDays(-400)    # genuinely abandoned

    function Test-Obj {
        param($Obj, [string]$Cat, $Baseline, $Now)
        & $m { param($o,$c,$b,$n) Test-AdToCompliance -Obj $o -Category $c -Baseline $b -Now $n } $Obj $Cat $Baseline $Now
    }

    It 'a COMPUTER pre-staged 2 days ago that has never logged on is COMPLIANT (was: staleObject)' {
        $obj = @{ Uac=0x1000; UacReadable=$true; LastLogonTicks=0; WhenCreated=$created2d }
        $r = Test-Obj $obj 'Computer' $base $now
        (@($r.Rules) -contains 'staleObject') | Should Be $false
        [string]$r.Status | Should Be 'COMPLIANT'
    }

    It 'that pre-staged computer is therefore NOT auto-DISABLED by the fixer (no ACCOUNTDISABLE bit)' {
        $obj = @{ Uac=0x1000; UacReadable=$true; LastLogonTicks=0; WhenCreated=$created2d }
        $r  = Test-Obj $obj 'Computer' $base $now
        $fx = & $m { param($u,$rules) Get-AdToFixedUac -Uac $u -Rules $rules } 0x1000 @($r.Rules)
        ([int]$fx.Uac -band 0x2) | Should Be 0
        @($fx.Applied).Count | Should Be 0
    }

    It 'a USER created 2 days ago that has never logged on is NOT flagged inactiveEnabled' {
        $obj = @{ Uac=0x200; UacReadable=$true; LastLogonTicks=0; WhenCreated=$created2d; Description='new hire'; Manager='CN=M,DC=t,DC=l'; RecertValue='' }
        $r = Test-Obj $obj 'User' $base $now
        (@($r.Rules) -contains 'inactiveEnabled') | Should Be $false
    }

    It 'and that new user is not auto-DISABLED either (its remaining findings are non-UAC / IAO work)' {
        $obj = @{ Uac=0x200; UacReadable=$true; LastLogonTicks=0; WhenCreated=$created2d; Description='new hire'; Manager='CN=M,DC=t,DC=l'; RecertValue='' }
        $r  = Test-Obj $obj 'User' $base $now
        $fx = & $m { param($u,$rules) Get-AdToFixedUac -Uac $u -Rules $rules } 0x200 @($r.Rules)
        ([int]$fx.Uac -band 0x2) | Should Be 0
    }

    It 'a computer created 400 days ago that has never logged on IS still staleObject (no over-forgiveness)' {
        $obj = @{ Uac=0x1000; UacReadable=$true; LastLogonTicks=0; WhenCreated=$created400 }
        $r = Test-Obj $obj 'Computer' $base $now
        (@($r.Rules) -contains 'staleObject') | Should Be $true
    }

    It 'an object with NO whenCreated at all stays fail-toward-flagged (undatable = pre-0.2.7 behaviour)' {
        $obj = @{ Uac=0x1000; UacReadable=$true; LastLogonTicks=0 }
        $r = Test-Obj $obj 'Computer' $base $now
        (@($r.Rules) -contains 'staleObject') | Should Be $true
    }

    It 'the newObjectGraceDays FLOOR holds even when staleComputerDays is tuned down to 1' {
        $b2 = @{} + $base; $b2['staleComputerDays'] = 1
        $obj = @{ Uac=0x1000; UacReadable=$true; LastLogonTicks=0; WhenCreated=$created2d }
        $r = Test-Obj $obj 'Computer' $b2 $now
        (@($r.Rules) -contains 'staleObject') | Should Be $false
    }

    It 'a real recent logon still short-circuits staleness (normal path unchanged)' {
        $obj = @{ Uac=0x1000; UacReadable=$true; LastLogonTicks=($now.AddDays(-3).ToFileTimeUtc()); WhenCreated=$created400 }
        $r = Test-Obj $obj 'Computer' $base $now
        (@($r.Rules) -contains 'staleObject') | Should Be $false
    }

    It 'Get-AdToWhenCreated reads an LDAP GeneralizedTime string as well as a DateTime' {
        $d = & $m { Get-AdToWhenCreated '20260719103000.0Z' }
        $d | Should Not BeNullOrEmpty
        $d.ToString('yyyy-MM-dd') | Should Be '2026-07-19'
    }
    It 'Get-AdToWhenCreated returns $null for an undatable value (caller then fails toward flagged)' {
        (& $m { Get-AdToWhenCreated 'not-a-date' }) | Should BeNullOrEmpty
        (& $m { Get-AdToWhenCreated $null })        | Should BeNullOrEmpty
    }
}

# -----------------------------------------------------------------------------
#  audit 2026-07-24 (P3, item F5'): loop54 added the fail-closed uacUnreadable hit
#  to the User/Admin/Service branch only. The Computer/Server branch derived
#  $disabled from the SAME userAccountControl that folds to 0 when it is absent or
#  ACL-hidden, so an unreadable computer object was scanned as if its UAC had been
#  read and confirmed clean.
# -----------------------------------------------------------------------------
Describe "adto F5' (audit 2026-07-24) - the Computer/Server branch fails closed on an unreadable userAccountControl" {
    $base = $script:AdToBase
    $now  = [datetime]::SpecifyKind([datetime]'2026-07-21T00:00:00', [System.DateTimeKind]::Utc)
    $recent = $now.AddDays(-1).ToFileTimeUtc()

    foreach ($cat in @('Computer','Server')) {
        It "a $cat with UacReadable=`$false gets the uacUnreadable hit (was: silently COMPLIANT)" {
            $obj = @{ Uac=0; UacReadable=$false; LastLogonTicks=$recent; WhenCreated=$now.AddDays(-400) }
            $r = & $m { param($o,$c,$b,$n) Test-AdToCompliance -Obj $o -Category $c -Baseline $b -Now $n } $obj $cat $base $now
            (@($r.Rules) -contains 'uacUnreadable') | Should Be $true
            [string]$r.Status | Should Be 'NON-COMPLIANT'
        }
        It "a $cat with an unreadable UAC is NOT asserted staleObject off a UAC never read (no auto-disable)" {
            $obj = @{ Uac=0; UacReadable=$false; LastLogonTicks=0; WhenCreated=$now.AddDays(-400) }
            $r  = & $m { param($o,$c,$b,$n) Test-AdToCompliance -Obj $o -Category $c -Baseline $b -Now $n } $obj $cat $base $now
            (@($r.Rules) -contains 'staleObject') | Should Be $false
            $fx = & $m { param($u,$rules) Get-AdToFixedUac -Uac $u -Rules $rules } 0x1000 @($r.Rules)
            ([int]$fx.Uac -band 0x2) | Should Be 0
        }
    }
    It 'a READABLE computer UAC does not get the hit and still flags a genuinely stale object (no over-flag)' {
        $obj = @{ Uac=0x1000; UacReadable=$true; LastLogonTicks=($now.AddDays(-400).ToFileTimeUtc()); WhenCreated=$now.AddDays(-800) }
        $r = & $m { param($o,$b,$n) Test-AdToCompliance -Obj $o -Category 'Computer' -Baseline $b -Now $n } $obj $base $now
        (@($r.Rules) -contains 'uacUnreadable') | Should Be $false
        (@($r.Rules) -contains 'staleObject')   | Should Be $true
    }
}

# -----------------------------------------------------------------------------
#  audit 2026-07-24 (P4, item F9'): the destructive fix/validate paths labelled the
#  'Object' column with (($dn -split ',')[0] -replace '^CN=',''), which truncates a
#  CN carrying an RFC-4514 ESCAPED comma - exactly the escaping the DN guard
#  deliberately ALLOWS (see the loop8 P3 note on Test-AdToDnInLocalDomain). The
#  operator saw (and the audit trail recorded) 'Smith\' for CN=Smith\, John.
# -----------------------------------------------------------------------------
Describe "adto F9' (audit 2026-07-24) - an RFC-4514 escaped comma does not truncate the Object column" {
    It 'Get-AdToShortName keeps the whole CN across an escaped comma' {
        (& $m { Get-AdToShortName 'CN=Smith\, John,OU=Users,DC=test,DC=local' }) | Should Be 'Smith, John'
    }
    It 'a plain CN is unchanged (no regression)' {
        (& $m { Get-AdToShortName 'CN=WKS001,OU=Workstations,DC=test,DC=local' }) | Should Be 'WKS001'
    }
    It 'an escaped BACKSLASH before a real separator is not mistaken for an escaped comma' {
        (& $m { Get-AdToShortName 'CN=path\\,OU=x,DC=test,DC=local' }) | Should Be 'path\'
    }
    It 'other escaped RDN specials survive too (RFC 4514 escapes + and ")' {
        (& $m { Get-AdToShortName 'CN=A\+B,OU=x,DC=test,DC=local' }) | Should Be 'A+B'
    }
    It 'an empty dn yields an empty name (no throw)' {
        (& $m { Get-AdToShortName '' }) | Should Be ''
    }
    It 'the FIX result row for an escaped-comma DN is labelled with the FULL name, not the truncation' {
        $de = New-FakeDe -Uac 512 -AdminCount 0
        $o  = Invoke-FixWith -Fake $de -Rule 'inactiveEnabled' -Dn 'CN=Smith\, John,OU=Users,DC=test,DC=local'
        $row = @($o.Events | Where-Object { $_.type -eq 'row' })[0]
        [string]$row.Object | Should Be 'Smith, John'
        [string]$row.Status | Should Be 'FIXED'
    }
}
