# =============================================================================
#  JanetWeb.adto.psm1  -  AD Nemesis (Technical Order account compliance)
#
#  Reviews EVERY AD object against the account-management Technical Order, splits
#  the fleet into User / Admin / Service / Computer / Server, and flags each object
#  COMPLIANT / NON-COMPLIANT with the EXACT reason(s) + how to fix. Read-only scan
#  (this file); the destructive fixes + the IAO account-validation role come next.
#
#  Grounding: there is NO TO reference doc in this environment, so the rule set is
#  an EDITABLE baseline (JanetLocal\adto-baseline.json, c2c-baseline pattern) that
#  ships STARTER AF/DISA-flavoured defaults - VALIDATE against the real TO before
#  trusting a verdict. Checks live in code; thresholds/patterns/toggles live in the
#  baseline. The engine reuses the adsearch credentialed-ADSI idiom.
#
#  Contract:
#    Get-JanetToolManifest                                   -> tool + action descriptors
#    Invoke-JanetToolAction -ActionId -Params -Credential -Emit  -> { rows; summary }
# =============================================================================

# userAccountControl bit flags (the ones the TO checks key off).
$script:AdToUac = @{
    ACCOUNTDISABLE          = 0x00002
    PASSWD_NOTREQD          = 0x00020
    ENCRYPTED_TEXT_PWD      = 0x00080   # reversible encryption
    WORKSTATION_TRUST       = 0x01000
    SERVER_TRUST            = 0x02000   # domain controller
    DONT_EXPIRE_PASSWORD    = 0x10000
    SMARTCARD_REQUIRED      = 0x40000
}

# The five categories the operator asked the fleet to be split into.
$script:AdToCategories = @('User', 'Admin', 'Service', 'Computer', 'Server')

# Per-rule reason + remediation text (the "why + how to fix"). One entry per baseline rule.
$script:AdToRuleText = @{
    inactiveEnabled     = @{ why = 'inactive past the {0}-day threshold but still ENABLED'; fix = 'disable the account (or IAO-recertify if still required)' }
    passwordNeverExpires = @{ why = 'password set to NEVER EXPIRE'; fix = 'clear DONT_EXPIRE_PASSWORD so the password ages out' }
    passwordNotRequired  = @{ why = 'PASSWD_NOTREQD set (a blank password is permitted)'; fix = 'clear PASSWD_NOTREQD and set a TO-compliant password' }
    reversibleEncryption = @{ why = 'reversible password encryption ENABLED'; fix = 'clear ENCRYPTED_TEXT_PWD_ALLOWED and reset the password' }
    descriptionMissing   = @{ why = 'description/justification is EMPTY'; fix = 'populate description with the account owner + purpose' }
    managerMissing       = @{ why = 'no manager set (no accountable owner)'; fix = 'set the manager attribute to the accountable person' }
    smartcardNotRequired = @{ why = 'smartcard (CAC) logon NOT required'; fix = 'set SMARTCARD_REQUIRED on the account' }
    adminHasSpn          = @{ why = 'privileged account carries an SPN (a service runs under an admin)'; fix = 'remove the SPN or move the service to a dedicated service account' }
    recertifyOverdue     = @{ why = 'not IAO-validated within {0} days'; fix = 'an IAO validates the account (stamps {1}<date>)' }
    staleObject          = @{ why = 'stale past the {0}-day threshold (no recent logon)'; fix = 'disable then remove the object once confirmed dead' }
}

# --- Baseline (embedded defaults overlaid by JanetLocal\adto-baseline.json) ----
function Get-AdToBaselinePath { Join-Path (Split-Path $PSScriptRoot -Parent) 'JanetLocal\adto-baseline.json' }
function Get-AdToBaseline {
    $def = @{
        inactiveDays = 45; staleComputerDays = 90; recertifyDays = 365
        recertifyAttribute = 'info'; recertifyStampPrefix = 'TO-VALIDATED:'; serverOsPattern = 'Server'
        iaoValidators = @()   # sAMAccountNames allowed to run validate-iao (empty = nobody yet; fail closed)
        adminSamPatterns = @('\.adm$', '^adm[-_]', '[-_]adm$', '^da[-_]', '^ea[-_]', 'admin')
        serviceSamPatterns = @('^svc[-_]?', '[-_]svc$', '^sa[-_]', '^s-', 'service')
        serviceOuPatterns = @('Service Accounts', 'ServiceAccounts', 'OU=Svc')
        adminOuPatterns = @('Admin', 'Privileged', 'PAW', 'Tier0', 'Tier 0')
        rules = @{
            inactiveEnabled     = @{ enabled = $true; appliesTo = @('User','Admin','Service'); requiresIao = $false }
            passwordNeverExpires = @{ enabled = $true; appliesTo = @('User','Admin'); requiresIao = $false }
            passwordNotRequired  = @{ enabled = $true; appliesTo = @('User','Admin','Service'); requiresIao = $false }
            reversibleEncryption = @{ enabled = $true; appliesTo = @('User','Admin','Service'); requiresIao = $false }
            descriptionMissing   = @{ enabled = $true; appliesTo = @('Admin','Service'); requiresIao = $false }
            managerMissing       = @{ enabled = $true; appliesTo = @('User'); requiresIao = $false }
            smartcardNotRequired = @{ enabled = $true; appliesTo = @('User','Admin'); requiresIao = $false }
            adminHasSpn          = @{ enabled = $true; appliesTo = @('Admin'); requiresIao = $false }
            recertifyOverdue     = @{ enabled = $true; appliesTo = @('User','Admin','Service'); requiresIao = $true }
            staleObject          = @{ enabled = $true; appliesTo = @('Computer','Server'); requiresIao = $false }
        }
        Source = 'embedded defaults'
    }
    $path = Get-AdToBaselinePath
    if (Test-Path -LiteralPath $path) {
        try {
            $j = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
            foreach ($k in 'inactiveDays','staleComputerDays','recertifyDays','recertifyAttribute','recertifyStampPrefix','serverOsPattern') {
                if ($null -ne $j.$k) { $def[$k] = $j.$k }
            }
            foreach ($k in 'adminSamPatterns','serviceSamPatterns','serviceOuPatterns','adminOuPatterns','iaoValidators') {
                if ($j.$k) { $def[$k] = @($j.$k) }
            }
            if ($j.rules) {
                foreach ($rn in @($j.rules.PSObject.Properties.Name)) {
                    $r = $j.rules.$rn
                    $def.rules[$rn] = @{
                        enabled     = [bool]$r.enabled
                        appliesTo   = @($r.appliesTo)
                        requiresIao = [bool]$r.requiresIao
                    }
                }
            }
            $def['Source'] = "overlay $path"
        } catch { $def['Source'] = "embedded defaults (overlay parse failed: $($_.Exception.Message))" }
    }
    return $def
}

# --- Pure: categorise ONE normalized AD object ---------------------------------
# $Obj = @{ SamAccountName; DistinguishedName; ObjectClass ('user'|'computer');
#           OperatingSystem; Uac (int); ServicePrincipalName (array); AdminCount (int) }
function Get-AdToCategory {
    param([hashtable]$Obj, [hashtable]$Baseline)
    $b = $Baseline; if (-not $b) { $b = Get-AdToBaseline }
    $sam = [string]$Obj.SamAccountName
    $dn  = [string]$Obj.DistinguishedName
    $cls = [string]$Obj.ObjectClass

    if ($cls -eq 'computer') {
        $os  = [string]$Obj.OperatingSystem
        $uac = [int]($Obj.Uac)
        if (($uac -band $script:AdToUac.SERVER_TRUST) -ne 0) { return 'Server' }   # DC
        if ($os -and ($os -match [string]$b.serverOsPattern)) { return 'Server' }
        return 'Computer'
    }

    # user-class object -> Admin / Service / User (first match wins, admin outranks service)
    $hasSpn = @($Obj.ServicePrincipalName).Count -gt 0
    $isAdmin = ([int]($Obj.AdminCount) -ge 1)
    foreach ($p in @($b.adminSamPatterns)) { if ($sam -match $p) { $isAdmin = $true; break } }
    foreach ($p in @($b.adminOuPatterns))  { if ($dn -match [regex]::Escape($p)) { $isAdmin = $true; break } }
    if ($isAdmin) { return 'Admin' }

    $isSvc = $hasSpn
    foreach ($p in @($b.serviceSamPatterns)) { if ($sam -match $p) { $isSvc = $true; break } }
    foreach ($p in @($b.serviceOuPatterns))  { if ($dn -match [regex]::Escape($p)) { $isSvc = $true; break } }
    if ($isSvc) { return 'Service' }

    return 'User'
}

# --- Pure: parse the last IAO validation date out of the recert attribute ------
function Get-AdToRecertDate {
    param([string]$AttrValue, [string]$Prefix)
    if ([string]::IsNullOrWhiteSpace($AttrValue)) { return $null }
    $m = [regex]::Match($AttrValue, ([regex]::Escape($Prefix) + '\s*(\d{4}-\d{2}-\d{2})'))
    if (-not $m.Success) { return $null }
    $d = [datetime]::MinValue
    if ([datetime]::TryParse($m.Groups[1].Value, [ref]$d)) { return $d }
    return $null
}

# --- Pure: evaluate ONE object against the TO ----------------------------------
# Returns @{ Status='COMPLIANT'|'NON-COMPLIANT'; Rules=@(names); RequiresIao=bool;
#            Detail='reason -> fix; ...' }. $Now is injectable for testability.
function Test-AdToCompliance {
    param([hashtable]$Obj, [string]$Category, [hashtable]$Baseline, [datetime]$Now = [datetime]::UtcNow)
    $b = $Baseline; if (-not $b) { $b = Get-AdToBaseline }
    $uac = [int]($Obj.Uac)
    $disabled = ($uac -band $script:AdToUac.ACCOUNTDISABLE) -ne 0

    $hits = New-Object System.Collections.ArrayList
    $parts = New-Object System.Collections.ArrayList
    $needIao = $false

    $fire = {
        param($rule, $whyArgs)
        $rc = $b.rules[$rule]
        if (-not $rc -or -not $rc.enabled) { return }
        if (@($rc.appliesTo) -notcontains $Category) { return }
        $txt = $script:AdToRuleText[$rule]
        $why = if ($whyArgs) { [string]::Format($txt.why, $whyArgs) } else { $txt.why }
        $fix = if ($whyArgs -and $txt.fix -match '\{\d') { [string]::Format($txt.fix, $whyArgs) } else { $txt.fix }
        [void]$hits.Add($rule)
        [void]$parts.Add(("{0} -> {1}" -f $why, $fix))
        if ($rc.requiresIao) { $script:__needIao = $true }
    }
    $script:__needIao = $false

    $ageDays = {
        param($ticks)
        $t = 0L; [void][int64]::TryParse([string]$ticks, [ref]$t)
        if ($t -le 0) { return [double]::PositiveInfinity }   # never logged on = maximally stale
        try { return ($Now - [datetime]::FromFileTimeUtc($t)).TotalDays } catch { return [double]::PositiveInfinity }
    }

    if ($Category -in @('User','Admin','Service')) {
        if (-not $disabled -and (& $ageDays $Obj.LastLogonTicks) -gt [double]$b.inactiveDays) { & $fire 'inactiveEnabled' @($b.inactiveDays) }
        if (($uac -band $script:AdToUac.DONT_EXPIRE_PASSWORD) -ne 0) { & $fire 'passwordNeverExpires' $null }
        if (($uac -band $script:AdToUac.PASSWD_NOTREQD) -ne 0)       { & $fire 'passwordNotRequired' $null }
        if (($uac -band $script:AdToUac.ENCRYPTED_TEXT_PWD) -ne 0)   { & $fire 'reversibleEncryption' $null }
        if ([string]::IsNullOrWhiteSpace([string]$Obj.Description))  { & $fire 'descriptionMissing' $null }
        if ([string]::IsNullOrWhiteSpace([string]$Obj.Manager))     { & $fire 'managerMissing' $null }
        if (($uac -band $script:AdToUac.SMARTCARD_REQUIRED) -eq 0)   { & $fire 'smartcardNotRequired' $null }
        if ($Category -eq 'Admin' -and @($Obj.ServicePrincipalName).Count -gt 0) { & $fire 'adminHasSpn' $null }
        $recert = Get-AdToRecertDate ([string]$Obj.RecertValue) ([string]$b.recertifyStampPrefix)
        if ($null -eq $recert -or ($Now - $recert).TotalDays -gt [double]$b.recertifyDays) { & $fire 'recertifyOverdue' @($b.recertifyDays, $b.recertifyStampPrefix) }
    }
    if ($Category -in @('Computer','Server')) {
        if (-not $disabled -and (& $ageDays $Obj.LastLogonTicks) -gt [double]$b.staleComputerDays) { & $fire 'staleObject' @($b.staleComputerDays) }
    }

    $status = if ($hits.Count -gt 0) { 'NON-COMPLIANT' } else { 'COMPLIANT' }
    return @{ Status = $status; Rules = @($hits); RequiresIao = [bool]$script:__needIao; Detail = (@($parts) -join '; ') }
}

# --- Auto-fixable rules -> a userAccountControl bit operation -------------------
# Only these rules are auto-remediable by the 'fix' action (all are UAC bit flips).
# descriptionMissing / managerMissing need a human-supplied VALUE; adminHasSpn is
# risky (could break a live service); recertifyOverdue is the IAO's job - none are
# in this map, so the fixer reports them as skipped-manual, never guesses.
$script:AdToUacFix = @{
    inactiveEnabled      = @{ op = 'set';   bit = $script:AdToUac.ACCOUNTDISABLE }       # disable the account
    staleObject          = @{ op = 'set';   bit = $script:AdToUac.ACCOUNTDISABLE }       # disable the stale computer/server
    passwordNeverExpires = @{ op = 'clear'; bit = $script:AdToUac.DONT_EXPIRE_PASSWORD }
    passwordNotRequired  = @{ op = 'clear'; bit = $script:AdToUac.PASSWD_NOTREQD }
    reversibleEncryption = @{ op = 'clear'; bit = $script:AdToUac.ENCRYPTED_TEXT_PWD }
    smartcardNotRequired = @{ op = 'set';   bit = $script:AdToUac.SMARTCARD_REQUIRED }
}

# --- Pure: compute the fixed userAccountControl for a set of rules --------------
# Returns @{ Uac; Applied=@(rules); Skipped=@(rules not auto-fixable) }. $Uac unchanged
# if no rule applied. Idempotent (setting a set bit / clearing a clear bit is a no-op).
function Get-AdToFixedUac {
    param([int]$Uac, [string[]]$Rules)
    $new = $Uac; $applied = @(); $skipped = @()
    foreach ($r in @($Rules)) {
        $f = $script:AdToUacFix[$r]
        if (-not $f) { $skipped += $r; continue }
        if ($f.op -eq 'set') { $new = $new -bor [int]$f.bit } else { $new = $new -band (-bnot [int]$f.bit) }
        $applied += $r
    }
    return @{ Uac = $new; Applied = @($applied); Skipped = @($skipped) }
}

# --- Pure: IAO express-permission gate (the FIRST RBAC instance in the suite) ---
# Only an identity on the baseline iaoValidators allow-list may run validate-iao.
# Enforced SERVER-SIDE in the engine (not just the UI) - the JANET gating principle.
# Match is case-insensitive against the bare sAMAccountName (DOMAIN\user and user@dom
# are both reduced to the account name).
function Test-AdToIaoAuthorized {
    param([string]$Identity, [hashtable]$Baseline)
    $b = $Baseline; if (-not $b) { $b = Get-AdToBaseline }
    $list = @($b.iaoValidators)
    if ($list.Count -eq 0) { return $false }           # empty allow-list = nobody is an IAO yet (fail closed)
    $id = ([string]$Identity).Trim()
    if ($id -match '\\') { $id = ($id -split '\\')[-1] }
    if ($id -match '@')  { $id = ($id -split '@')[0] }
    foreach ($v in $list) { if ($id -and ([string]$v).Trim() -ieq $id) { return $true } }
    return $false
}

# --- Pure: build the IAO recert stamp written into the recert attribute ---------
function New-AdToRecertStamp {
    param([string]$Prefix, [datetime]$Date, [string]$By)
    $s = "{0}{1:yyyy-MM-dd}" -f $Prefix, $Date
    if ($By) { $s = "$s by $By" }
    return $s
}

# --- Pure: bind-redirect guard for a SearchBase / plan DN (audit P2 + P3) --------
#  New-AdToEntry / the scan bind LDAP://<value> with the CREDENTIAL, so a value that
#  is not a plain DN under THIS host's domain can steer that bind at an attacker host.
#  Returns $true when the value is SAFE to bind (accept), $false when it must be
#  REJECTED. A value is safe only when it (a) starts with an RDN attribute (OU=/DC=),
#  (b) carries no '/' ('evilhost/DC=x' or 'LDAP://evil' would redirect the bind), and
#  (c) ends at the local domain's DC= suffix - so a serverless bind cannot be steered
#  at a foreign domain like DC=evil,DC=com whose DsGetDcName would land the bind on the
#  attacker's DC (P2). '\' is DELIBERATELY allowed: RFC 4514 escapes RDN special chars
#  with '\' (e.g. CN=Smith\, John,...), a legitimate DN char, not a redirect vector (P3).
#  -match/-notmatch is case-insensitive, which is correct: DN case varies.
#
#  PILOT ASSUMPTION: a single AD domain (the JANET host's own, derived from
#  $env:USERDNSDOMAIN). A child that is a strict SUBTREE of the local domain (a
#  deeper DN under the SAME DC= suffix, e.g. OU=x,DC=area52,DC=mil) is ACCEPTED; a
#  DIFFERENT domain - sibling, parent, or a foreign child like DC=evil,DC=area52,
#  DC=mil whose own DC-tail differs (real domain evil.area52.mil) - is REJECTED. A
#  genuine separate child / trusted DOMAIN needs the pilot allowlist. Fail-safe
#  (over-restrictive), documented pilot-pending.
function Test-AdToDnInLocalDomain {
    param([string]$Value, [string]$ExpectDomainSuffix)
    if ($Value -notmatch '^[A-Za-z]{1,8}=') { return $false }
    if ($Value -match '/') { return $false }
    # Reject any control char (NUL..US, incl. CR/LF/TAB): a real DN never carries one, and .NET's
    # regex '$' ALSO matches just before a trailing newline - so a value like "...DC=MIL`n" would
    # otherwise slip past the component-boundary anchor below. (audit loop9 P3)
    if ($Value -match '[\x00-\x1f]') { return $false }
    if (-not $ExpectDomainSuffix) { return $false }
    # the domain suffix must sit at a COMPONENT boundary (string start or right after a comma),
    # not merely as a trailing substring (blocks e.g. CN=ABDC=AREA52,DC=MIL)
    # RFC-4514: an RDN value escapes special chars (comma, plus, quote, ...) with a backslash,
    # e.g. CN=Smith\, John. Strip every \<char> escape pair BEFORE the boundary/count checks so an
    # escaped comma inside a value can't manufacture a fake component boundary (false-accept to an
    # ancestor domain) or inflate the DC-count (false-reject a legit escaped DN). (audit loop8 P3)
    $bare = $Value -replace '\\.', ''
    if ($bare -notmatch ('(^|,)' + [regex]::Escape($ExpectDomainSuffix) + '$')) { return $false }
    # and the value must carry NO EXTRA DC= component beyond the expected suffix - so a child
    # subdomain prepend (DC=evil,DC=area52,DC=mil -> the distinct domain evil.area52.mil) is rejected
    $dcInValue  = ([regex]::Matches($bare, '(?i)(^|,)DC=')).Count
    $dcInSuffix = ([regex]::Matches($ExpectDomainSuffix, '(?i)(^|,)DC=')).Count
    if ($dcInValue -ne $dcInSuffix) { return $false }
    return $true
}

# Derive THIS host's expected domain DN suffix (e.g. AREA52.MIL -> DC=AREA52,DC=MIL)
# from $env:USERDNSDOMAIN. Empty string when USERDNSDOMAIN is unset -> the guard then
# fails CLOSED for any non-blank value (we cannot prove it targets the local domain).
function Get-AdToExpectedDomainSuffix {
    $d = [string]$env:USERDNSDOMAIN
    if (-not $d) { return '' }
    return (($d -split '\.' | Where-Object { $_ } | ForEach-Object { "DC=$_" }) -join ',')
}

# --- Live harvest + tool contract ---------------------------------------------
# (Below the pure core so the compliance logic can be unit-tested without a domain.)

function Get-JanetToolManifest {
    @{
        id       = 'adto'
        name     = 'AD Nemesis'
        version  = '0.2.2'
        category = 'Remediation'
        summary  = 'Review every AD object against the account-management Technical Order. Splits the fleet into User / Admin / Service / Computer / Server, flags each COMPLIANT / NON-COMPLIANT with the exact reason + fix, bulk-remediates the auto-fixable findings (userAccountControl flips), and offers IAO Validate (express permission, gated server-side) to clear recert findings. Rule set is the editable JanetLocal\adto-baseline.json.'
        actions  = @(
            @{
                id          = 'scan'
                label       = 'AD TO Compliance Scan'
                description = 'Enumerate AD objects under a base DN (or the whole domain), categorise each, and flag TO compliance with per-object reasons. Read-only; runs under the current Kerberos identity (or the session credential).'
                kind        = 'stream-table'
                destructive = $false
                columns     = @('Object','Category','Status','Rules','Detail','DN')
                inputs      = @(
                    @{ name='SearchBase'; label='Limit to OU / base-DN (blank = whole domain)'; type='text'; required=$false },
                    @{ name='Categories'; label='Categories (comma list; blank = all)'; type='text'; required=$false },
                    @{ name='OnlyNonCompliant'; label='Only show NON-COMPLIANT objects'; type='bool'; required=$false; default=$false }
                )
            }
            @{
                id          = 'fix'
                label       = 'Fix Selected (auto-remediable)'
                description = 'DESTRUCTIVE: apply the auto-remediable rules to the planned objects (userAccountControl flips only): disable inactive/stale, clear never-expire / passwd-not-required / reversible-encryption, set smartcard-required. Verify-first. Description / manager / SPN / recert are NEVER auto-guessed - they route to manual / the IAO.'
                kind        = 'stream-table'
                destructive = $true
                columns     = @('Object','Category','Status','Applied','Detail','DN')
                inputs      = @(
                    @{ name='plan';    label='Plan JSON (per-object DN + rules)'; type='textarea'; required=$true },
                    @{ name='confirm'; label='Type FIX to arm'; type='text'; required=$true }
                )
            }
            @{
                id          = 'validate-iao'
                label       = 'IAO Validate Accounts (express)'
                description = 'IAO-ONLY: stamp TO-VALIDATED:<date> into the recert attribute of the planned objects, clearing the recert finding. Refused server-side unless the operator is on the baseline iaoValidators allow-list - this is the express permission set. It writes ONLY the recert stamp, nothing else.'
                kind        = 'stream-table'
                destructive = $true
                columns     = @('Object','Status','Detail','DN')
                inputs      = @(
                    @{ name='plan';    label='Plan JSON (per-object DN)'; type='textarea'; required=$true },
                    @{ name='confirm'; label='Type VALIDATE to arm'; type='text'; required=$true }
                )
            }
        )
    }
}

# Normalize a DirectorySearcher result into the hashtable the pure functions expect.
function ConvertTo-AdToObject {
    param($SearchResult)
    $p = $SearchResult.Properties
    $get = { param($n) if ($p[$n] -and $p[$n].Count -gt 0) { $p[$n][0] } else { $null } }
    $cls = @($p['objectclass']); $isComputer = ($cls -contains 'computer')
    $ll1 = [string](& $get 'lastlogontimestamp'); $ll2 = [string](& $get 'lastlogon')
    $ll  = if ($ll1) { $ll1 } else { $ll2 }
    @{
        SamAccountName       = [string](& $get 'samaccountname')
        DistinguishedName    = [string](& $get 'distinguishedname')
        ObjectClass          = if ($isComputer) { 'computer' } else { 'user' }
        OperatingSystem      = [string](& $get 'operatingsystem')
        Uac                  = [int]("0" + [string](& $get 'useraccountcontrol'))
        ServicePrincipalName = @($p['serviceprincipalname'])
        AdminCount           = [int]("0" + [string](& $get 'admincount'))
        LastLogonTicks       = $ll
        Description          = [string](& $get 'description')
        Manager              = [string](& $get 'manager')
        RecertValue          = [string](& $get ((Get-AdToBaseline).recertifyAttribute))
    }
}

function Invoke-JanetToolAction {
    param([string]$ActionId, [hashtable]$Params, $Credential, [scriptblock]$Emit)
    $send = { param($e) if ($Emit) { & $Emit $e } }
    if ($ActionId -eq 'fix')          { return Invoke-AdToFix      -Params $Params -Credential $Credential -Send $send }
    if ($ActionId -eq 'validate-iao') { return Invoke-AdToValidate -Params $Params -Credential $Credential -Send $send }
    if ($ActionId -ne 'scan') { & $send @{ type='log'; level='warn'; text="Unknown action '$ActionId'." }; return @{ rows=@(); summary=@{ total=0 } } }

    $baseline = Get-AdToBaseline
    $wantCats = @()
    if ($Params['Categories']) { $wantCats = @([string]$Params['Categories'] -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
    $onlyBad  = [bool]$Params['OnlyNonCompliant']
    $searchBase = ([string]$Params['SearchBase']).Trim()

    # Validate the SearchBase is a plain distinguished name UNDER THIS HOST'S DOMAIN (or blank =
    # whole domain). LDAP://<searchBase> is a BIND path, not a filter: 'evildc/DC=x' or a bare
    # foreign 'DC=evil,DC=com' would redirect / serverless-bind the CREDENTIALED bind to an
    # attacker-controlled domain. Require a plain DN ending at the local domain suffix; block '/',
    # allow RFC-escaped '\' (audit P2 + P3). Blank stays allowed (whole-domain scan).
    $expectDom = Get-AdToExpectedDomainSuffix
    if ($searchBase -and -not (Test-AdToDnInLocalDomain -Value $searchBase -ExpectDomainSuffix $expectDom)) {
        & $send @{ type='log'; level='err'; text="Rejected SearchBase '$searchBase': must be a plain distinguished name ending at this host's domain ($(if ($expectDom) { $expectDom } else { '<USERDNSDOMAIN not set>' })), e.g. OU=Squadron,$expectDom - no server prefix, no '/' path chars, no foreign domain." }
        return @{ rows=@(); summary=@{ total=0; rejected=$true } }
    }

    & $send @{ type='status'; text="AD TO scan starting (baseline: $($baseline.Source))..." }
    & $send @{ type='log'; level='info'; text="AD TO compliance scan. Baseline: $($baseline.Source). Inactive>$($baseline.inactiveDays)d, stale>$($baseline.staleComputerDays)d, recert>$($baseline.recertifyDays)d." }

    # Bind (honour the session credential; else current Kerberos identity).
    $root = $null
    try {
        if ($Credential -is [System.Management.Automation.PSCredential]) {
            $path = if ($searchBase) { "LDAP://$searchBase" } else { 'LDAP://RootDSE' }
            if (-not $searchBase) {
                $rootDse = New-Object System.DirectoryServices.DirectoryEntry('LDAP://RootDSE', $Credential.UserName, $Credential.GetNetworkCredential().Password)
                $searchBase = [string]$rootDse.Properties['defaultNamingContext'][0]
            }
            $root = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$searchBase", $Credential.UserName, $Credential.GetNetworkCredential().Password)
        } else {
            $root = if ($searchBase) { [ADSI]"LDAP://$searchBase" } else { [ADSI]'' }
        }
    } catch { & $send @{ type='log'; level='err'; text="AD bind failed: $($_.Exception.Message)" }; return @{ rows=@(); summary=@{ total=0; rejected=$true } } }

    $ds = New-Object System.DirectoryServices.DirectorySearcher($root)
    # Do NOT auto-follow a directory-returned EXTERNAL referral to another server:
    # even a local-domain-rooted scan could otherwise be redirected to a host the DN
    # guard never vetted (loop-7 AD-bind hardening capstone). Inert in a single AD
    # domain (no referrals); closes the residual redirect.
    $ds.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::None
    $ds.Filter = '(|(&(objectCategory=person)(objectClass=user))(objectCategory=computer))'
    $ds.PageSize = 1000
    foreach ($a in 'samaccountname','distinguishedname','objectclass','operatingsystem','useraccountcontrol','serviceprincipalname','admincount','lastlogontimestamp','lastlogon','description','manager',$baseline.recertifyAttribute) { [void]$ds.PropertiesToLoad.Add($a) }

    $rows = New-Object System.Collections.ArrayList
    $byCat = @{}; foreach ($c in $script:AdToCategories) { $byCat[$c] = @{ total=0; bad=0 } }
    $iaoCount = 0; $total = 0; $bad = 0
    $now = [datetime]::UtcNow

    try {
        $results = $ds.FindAll()
        foreach ($sr in $results) {
            $obj = ConvertTo-AdToObject $sr
            $cat = Get-AdToCategory -Obj $obj -Baseline $baseline
            if ($wantCats.Count -gt 0 -and $wantCats -notcontains $cat) { continue }
            $ev = Test-AdToCompliance -Obj $obj -Category $cat -Baseline $baseline -Now $now
            $total++; $byCat[$cat].total++
            if ($ev.Status -eq 'NON-COMPLIANT') { $bad++; $byCat[$cat].bad++; if ($ev.RequiresIao) { $iaoCount++ } }
            if ($onlyBad -and $ev.Status -eq 'COMPLIANT') { continue }
            $row = @{ Object=$obj.SamAccountName; Category=$cat; Status=$ev.Status; Rules=(@($ev.Rules) -join ', '); Detail=$ev.Detail; DN=$obj.DistinguishedName }
            [void]$rows.Add($row)
            & $send (@{ type='row' } + $row)
            if ($total % 250 -eq 0) { & $send @{ type='progress'; done=$total; total=$total } }
        }
        $results.Dispose()
    } catch { & $send @{ type='log'; level='err'; text="AD search failed: $($_.Exception.Message)" }; return @{ rows=@($rows); summary=@{ total=$total; rejected=$true } } }

    $catLine = (@($script:AdToCategories | ForEach-Object { "{0} {1}/{2}" -f $_, $byCat[$_].bad, $byCat[$_].total }) -join '  |  ')
    & $send @{ type='log'; level=($(if($bad){'warn'}else{'ok'})); text="AD TO scan done. $bad NON-COMPLIANT of $total. By category (bad/total): $catLine. $iaoCount need IAO validation." }
    & $send @{ type='status'; text="Done. $bad non-compliant of $total AD object(s)." }
    return @{ rows=@($rows); summary=@{ total=$total; nonCompliant=$bad; iaoRequired=$iaoCount; byCategory=$byCat; source=$baseline.Source } }
}

# Bind a DirectoryEntry for a DN, honouring the session credential (service account).
function New-AdToEntry {
    param([string]$Dn, $Credential)
    if ($Credential -is [System.Management.Automation.PSCredential]) {
        return New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Dn", $Credential.UserName, $Credential.GetNetworkCredential().Password)
    }
    return [ADSI]"LDAP://$Dn"
}

# --- Action: fix (destructive, admin-gated) - UAC-flip remediations only --------
function Invoke-AdToFix {
    param([hashtable]$Params, $Credential, [scriptblock]$Send)
    if ([string]$Params['confirm'] -ne 'FIX') { & $Send @{ type='log'; level='err'; text='Refused: type FIX (exactly) in Confirm to arm the fix.' }; return @{ rows=@(); summary=@{ total=0; rejected=$true } } }
    $plan = @(); try { $plan = @(ConvertFrom-Json ([string]$Params['plan'])) } catch { & $Send @{ type='log'; level='err'; text="Plan JSON parse failed: $($_.Exception.Message)" }; return @{ rows=@(); summary=@{ total=0; rejected=$true } } }
    if ($plan.Count -eq 0) { & $Send @{ type='log'; level='warn'; text='Empty plan - nothing to fix.' }; return @{ rows=@(); summary=@{ total=0 } } }

    $expectDom = Get-AdToExpectedDomainSuffix   # this host's domain DN suffix, computed once
    $rows = New-Object System.Collections.ArrayList; $i = 0
    foreach ($e in $plan) {
        $i++; & $Send @{ type='progress'; done=$i; total=$plan.Count }
        $dn = [string]$e.dn; if (-not $dn) { continue }
        $short = (($dn -split ',')[0] -replace '^CN=', '')
        # New-AdToEntry binds LDAP://$dn with the CREDENTIAL: a dn from the client plan that is not a
        # plain distinguished name (e.g. 'evildc/DC=x') OR a bare foreign domain (e.g. DC=evil,DC=com,
        # which serverless-binds the attacker's DC) would redirect that credentialed bind. Refuse
        # anything that is not a plain DN ending at THIS host's domain before touching the directory
        # (block '/', allow RFC-escaped '\'; same hardened guard as the scan site - audit P2 + P3).
        if (-not (Test-AdToDnInLocalDomain -Value $dn -ExpectDomainSuffix $expectDom)) {
            $row = @{ Object=$short; Category=''; Status='REJECTED'; Applied=''; Detail='refused: dn is not a plain distinguished name in this host''s domain (bind-redirect guard)'; DN=$dn }
            [void]$rows.Add($row); & $Send (@{ type='row' } + $row)
            # Audit the redirect refusal (loop12 F3): a plan steering a credentialed write at a
            # foreign/redirected DN is a security-relevant event and must leave an audit trail,
            # not just a UI row.
            & $Send @{ type='audit'; action='AdToFix'; target=[string]$dn; result='Skipped'; itemCount=0; detail='[REJECTED] bind-redirect guard: dn not a plain distinguished name in this domain' }
            continue
        }
        $rules = @($e.rules)
        try {
            $de  = New-AdToEntry -Dn $dn -Credential $Credential
            $cur = [int]("0" + [string]$de.Properties['userAccountControl'].Value)
            # Protected-object guard (loop12 F1): this bulk-remediation tool must NEVER modify a
            # domain controller or an AdminSDHolder-protected (privileged) object. The DN guard
            # above proves the target is in-domain, but NOT that it is a safe object - a crafted
            # or fat-fingered plan naming a DC computer object or a break-glass admin account
            # would otherwise get ACCOUNTDISABLE set (a DoS of a critical AD object). Refuse a
            # DC (SERVER_TRUST bit in its own UAC) or any object with adminCount>=1, before the
            # write, and audit the refusal.
            $isDc = (($cur -band [int]$script:AdToUac.SERVER_TRUST) -ne 0)
            $adminCount = 0; try { $adminCount = [int]("0" + [string]$de.Properties['adminCount'].Value) } catch {}
            if ($isDc -or $adminCount -ge 1) {
                $why = if ($isDc) { 'domain controller (SERVER_TRUST)' } else { 'privileged/protected (adminCount>=1)' }
                $row = @{ Object=$short; Category=''; Status='PROTECTED'; Applied=''; Detail=("refused: AD TO fix never modifies a $why object"); DN=$dn }
                [void]$rows.Add($row); & $Send (@{ type='row' } + $row)
                & $Send @{ type='audit'; action='AdToFix'; target=[string]$dn; result='Skipped'; itemCount=0; detail=("[PROTECTED] refused: $why") }
                continue
            }
            $fx  = Get-AdToFixedUac -Uac $cur -Rules $rules
            $skipNote = if ($fx.Skipped.Count) { " | manual/IAO (not auto-fixed): " + (@($fx.Skipped) -join ', ') } else { '' }
            if ($fx.Applied.Count -eq 0) {
                $row = @{ Object=$short; Category=''; Status='NO CHANGE'; Applied=''; Detail=("no auto-fixable rule in plan$skipNote"); DN=$dn }
            } elseif ($fx.Uac -eq $cur) {
                $row = @{ Object=$short; Category=''; Status='NO CHANGE'; Applied=(@($fx.Applied) -join ', '); Detail=("already compliant (UAC unchanged)$skipNote"); DN=$dn }
            } else {
                $de.Properties['userAccountControl'].Value = $fx.Uac
                $de.CommitChanges()
                $ver = [int]("0" + [string]((New-AdToEntry -Dn $dn -Credential $Credential).Properties['userAccountControl'].Value))
                $ok  = ($ver -eq $fx.Uac)
                $row = @{ Object=$short; Category=''; Status=($(if ($ok) { 'FIXED' } else { 'FAILED' })); Applied=(@($fx.Applied) -join ', '); Detail=("UAC {0} -> {1}{2}" -f $cur, $fx.Uac, $skipNote); DN=$dn }
            }
        } catch { $row = @{ Object=$short; Category=''; Status='FAILED'; Applied=''; Detail=("LDAP write failed: {0}" -f $_.Exception.Message); DN=$dn } }
        [void]$rows.Add($row); & $Send (@{ type='row' } + $row)
        $appliedN = if ([string]$row.Applied) { @([string]$row.Applied -split ',').Count } else { 0 }
        $auditRes = switch ([string]$row.Status) { 'FIXED' { 'Success' } 'FAILED' { 'Failure' } default { 'Skipped' } }
        & $Send @{ type='audit'; action='AdToFix'; target=[string]$dn; result=$auditRes; itemCount=$appliedN; detail=("[{0}] {1}" -f $row.Status, $row.Detail) }
    }
    $fixed = @($rows | Where-Object { $_.Status -eq 'FIXED' }).Count
    & $Send @{ type='status'; text="Done. $fixed fixed of $($rows.Count) object(s)." }
    return @{ rows=@($rows); summary=@{ total=$rows.Count; fixed=$fixed } }
}

# --- Action: validate-iao (destructive, IAO EXPRESS PERMISSION ONLY) ------------
# The first RBAC instance in the suite: refused server-side unless the operator is on
# the baseline iaoValidators allow-list. Writes ONLY the recert stamp, nothing else.
function Invoke-AdToValidate {
    param([hashtable]$Params, $Credential, [scriptblock]$Send)
    if ([string]$Params['confirm'] -ne 'VALIDATE') { & $Send @{ type='log'; level='err'; text='Refused: type VALIDATE (exactly) in Confirm to arm.' }; return @{ rows=@(); summary=@{ total=0; rejected=$true } } }
    $baseline = Get-AdToBaseline
    # IAO identity = the WINDOWS identity that launched JANET (the individual operator), NOT the
    # target-reaching session credential (which is a shared service/admin account under the
    # server deployment). This ties the express permission to the PERSON. In a headless
    # service-account deployment the process owner is the service account, so it is not on the
    # IAO list and validation fails closed - IAO validation is meaningful only when a person
    # launched JANET interactively (audit P1-c).
    $who = try { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $env:USERNAME }
    if (-not (Test-AdToIaoAuthorized -Identity $who -Baseline $baseline)) {
        & $Send @{ type='log'; level='err'; text=("IAO EXPRESS PERMISSION DENIED: the JANET operator '{0}' is not on the iaoValidators allow-list. Only an IAO may validate accounts (identity = the Windows user running JANET, not the target credential)." -f $who) }
        return @{ rows=@(); summary=@{ total=0; rejected=$true; denied=$true } }
    }
    $plan = @(); try { $plan = @(ConvertFrom-Json ([string]$Params['plan'])) } catch { & $Send @{ type='log'; level='err'; text="Plan JSON parse failed: $($_.Exception.Message)" }; return @{ rows=@(); summary=@{ total=0; rejected=$true } } }
    if ($plan.Count -eq 0) { & $Send @{ type='log'; level='warn'; text='Empty plan - nothing to validate.' }; return @{ rows=@(); summary=@{ total=0 } } }

    $attr  = [string]$baseline.recertifyAttribute
    $byId  = (([string]$who) -split '\\')[-1]
    & $Send @{ type='log'; level='info'; text=("IAO '{0}' validating {1} account(s); stamping '{2}' into '{3}'." -f $byId, $plan.Count, $baseline.recertifyStampPrefix, $attr) }
    $expectDom = Get-AdToExpectedDomainSuffix   # this host's domain DN suffix, computed once
    $rows = New-Object System.Collections.ArrayList; $i = 0
    foreach ($e in $plan) {
        $i++; & $Send @{ type='progress'; done=$i; total=$plan.Count }
        $dn = [string]$e.dn; if (-not $dn) { continue }
        $short = (($dn -split ',')[0] -replace '^CN=', '')
        # Same hardened bind-redirect guard as the fix + scan paths: New-AdToEntry binds LDAP://$dn
        # with the credential, so refuse any plan dn that is not a plain distinguished name ending at
        # THIS host's domain (block '/' and foreign domains; allow RFC-escaped '\') before binding.
        if (-not (Test-AdToDnInLocalDomain -Value $dn -ExpectDomainSuffix $expectDom)) {
            $row = @{ Object=$short; Status='REJECTED'; Detail='refused: dn is not a plain distinguished name in this host''s domain (bind-redirect guard)'; DN=$dn }
            [void]$rows.Add($row); & $Send (@{ type='row' } + $row)
            # Audit the redirect refusal (loop12 F3): same rationale as the fix path.
            & $Send @{ type='audit'; action='AdToIaoValidate'; target=[string]$dn; result='Skipped'; itemCount=0; detail='[REJECTED] bind-redirect guard: dn not a plain distinguished name in this domain' }
            continue
        }
        $stamp = New-AdToRecertStamp -Prefix ([string]$baseline.recertifyStampPrefix) -Date (Get-Date) -By $byId
        try {
            $de = New-AdToEntry -Dn $dn -Credential $Credential
            # APPEND the stamp - preserve any existing content in the attribute, replacing only a
            # prior TO-VALIDATED line (audit P2: was a whole-value overwrite that clobbered notes).
            $prior = [string]$de.Properties[$attr].Value
            $keep = @($prior -split "`r?`n") | Where-Object { $_.Trim() -ne '' -and $_ -notmatch ('^\s*' + [regex]::Escape([string]$baseline.recertifyStampPrefix)) }
            $newVal = (@(@($keep) + $stamp)) -join "`n"
            $de.Properties[$attr].Value = $newVal
            $de.CommitChanges()
            # Fail-closed re-read (loop12 F2): mirror the fix path - confirm the stamp actually
            # persisted before reporting VALIDATED. A referral/replication quirk could let
            # CommitChanges() return without persisting; reporting a clean IAO recert on an
            # unpersisted stamp is the fail-open class the c2c persistence-verify work closed.
            $after = [string]((New-AdToEntry -Dn $dn -Credential $Credential).Properties[$attr].Value)
            if ($after -match [regex]::Escape($stamp)) {
                $row = @{ Object=$short; Status='VALIDATED'; Detail=("stamped '{0}' into {1}" -f $stamp, $attr); DN=$dn }
            } else {
                $row = @{ Object=$short; Status='FAILED'; Detail=("stamp not present on re-read - commit did not persist into '{0}'" -f $attr); DN=$dn }
            }
        } catch { $row = @{ Object=$short; Status='FAILED'; Detail=("LDAP write failed: {0}" -f $_.Exception.Message); DN=$dn } }
        [void]$rows.Add($row); & $Send (@{ type='row' } + $row)
        & $Send @{ type='audit'; action='AdToIaoValidate'; target=[string]$dn; result=$(if ([string]$row.Status -eq 'VALIDATED') { 'Success' } else { 'Failure' }); itemCount=1; detail=("IAO '{0}': {1}" -f $byId, $row.Detail) }
    }
    $ok = @($rows | Where-Object { $_.Status -eq 'VALIDATED' }).Count
    & $Send @{ type='status'; text="Done. $ok validated of $($rows.Count)." }
    return @{ rows=@($rows); summary=@{ total=$rows.Count; validated=$ok } }
}

Export-ModuleMember -Function Get-JanetToolManifest, Invoke-JanetToolAction, Get-AdToBaseline, Get-AdToCategory, Get-AdToRecertDate, Test-AdToCompliance, Get-AdToFixedUac, Test-AdToIaoAuthorized, New-AdToRecertStamp, Test-AdToDnInLocalDomain, Get-AdToExpectedDomainSuffix
