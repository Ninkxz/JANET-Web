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
#
#  v0.2.8 (audit 2026-07-25, fable re-audit follow-up):
#    P4  a CANCELLED fix / IAO-validate run no longer paints a GREEN "<verb> done"
#        headline + "<verb> complete" dialog over the engine's honest
#        "Cancelled. X fixed of Y" status (web/js/views/adto.view.js). The view now
#        reads summary.cancelled (and the run-state's own 'cancelled' status, for a
#        hard-killed job that never emits a final event) and says PARTIAL WRITE
#        instead of success. Engine unchanged - it was already telling the truth.
#
#  v0.2.7 (audit 2026-07-24): safety + cancel pass.
#    P2  a never-logged-on object is aged from whenCreated (plus a new-object grace
#        floor), so a freshly PRE-STAGED computer / user is no longer "maximally
#        stale" and auto-DISABLED by the fixer on its first scan.
#    P2  __job operator-cancel bridge across scan + fix + validate (adto was the only
#        module in the suite without one, so CANCEL SCAN was inert and a destructive
#        bulk write could not be aborted), plus a DirectorySearcher time limit.
#    P3  the loop54 uacUnreadable fail-closed guard now covers Computer/Server too -
#        that branch derived $disabled from a UAC it had never read.
#    P3  DirectoryEntry / DirectorySearcher / SearchResultCollection are disposed,
#        including on the error path (each leaked an LDAP connection per run).
#    P3  the fix/validate REJECTED text names an unset USERDNSDOMAIN as the cause
#        instead of blaming the operator's (perfectly valid) DN.
#    P4  dead local $needIao removed; the Object column keeps an RFC-4514 escaped
#        comma instead of truncating the CN at it.
# =============================================================================

# userAccountControl bit flags (the ones the TO checks key off).
$script:AdToUac = @{
    ACCOUNTDISABLE          = 0x00002
    PASSWD_NOTREQD          = 0x00020
    ENCRYPTED_TEXT_PWD      = 0x00080   # reversible encryption
    WORKSTATION_TRUST       = 0x01000
    SERVER_TRUST            = 0x02000   # writable domain controller
    DONT_EXPIRE_PASSWORD    = 0x10000
    SMARTCARD_REQUIRED      = 0x40000
    PARTIAL_SECRETS_ACCOUNT = 0x04000000  # read-only domain controller (RODC) - no SERVER_TRUST bit
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
        # audit 2026-07-24 (P2): objects YOUNGER than this are never flagged inactive/stale.
        # A pre-staged computer or a just-created user has lastLogon=0 by definition, and the
        # fixer auto-DISABLES both inactiveEnabled and staleObject - disabling a brand-new
        # account is a self-inflicted outage. A genuinely dormant new object is caught a
        # grace window later. 0 disables the floor (pre-0.2.7 behaviour).
        newObjectGraceDays = 30
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
            foreach ($k in 'inactiveDays','staleComputerDays','recertifyDays','newObjectGraceDays','recertifyAttribute','recertifyStampPrefix','serverOsPattern') {
                if ($null -ne $j.$k) { $def[$k] = $j.$k }
            }
            foreach ($k in 'adminSamPatterns','serviceSamPatterns','serviceOuPatterns','adminOuPatterns','iaoValidators') {
                if ($j.$k) { $def[$k] = @($j.$k) }
            }
            if ($j.rules) {
                foreach ($rn in @($j.rules.PSObject.Properties.Name)) {
                    $r = $j.rules.$rn
                    # loop55 (F3): MERGE the overlay rule onto the embedded default, do NOT replace it. An
                    # overlay entry tuning one field (or a typo) previously nulled the others - a missing
                    # 'enabled' became [bool]$null=$false (rule OFF), a missing 'appliesTo' became @($null)
                    # (never fires), silently scanning every violating object COMPLIANT with no trace. Only
                    # override a field the overlay EXPLICITLY provides; omitted fields keep the default.
                    $base = if ($def.rules.ContainsKey($rn)) { $def.rules[$rn] } else { @{ enabled=$true; appliesTo=@(); requiresIao=$false } }
                    $merged = @{ enabled=[bool]$base.enabled; appliesTo=@($base.appliesTo); requiresIao=[bool]$base.requiresIao }
                    if ($null -ne $r.enabled)     { $merged.enabled     = [bool]$r.enabled }
                    if ($null -ne $r.appliesTo)   { $merged.appliesTo   = @($r.appliesTo) }
                    if ($null -ne $r.requiresIao) { $merged.requiresIao = [bool]$r.requiresIao }
                    $def.rules[$rn] = $merged
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

# --- Pure: normalize an AD whenCreated value to a UTC datetime -----------------
# audit 2026-07-24 (P2): the object-age floor needs a creation date it can trust.
# DirectorySearcher hands whenCreated back as a System.DateTime whose Kind is
# Unspecified but whose VALUE is already UTC (so ToUniversalTime() would wrongly
# shift it by the host's offset); a raw/serialized read can instead be an LDAP
# GeneralizedTime string ('20260722103000.0Z'). Returns $null when the value cannot
# be dated, so the caller can fail toward its previous behaviour rather than invent
# an age for an object it knows nothing about.
function Get-AdToWhenCreated {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) {
        $dt = [datetime]$Value
        if ($dt.Kind -eq [System.DateTimeKind]::Local) { return $dt.ToUniversalTime() }
        return [datetime]::SpecifyKind($dt, [System.DateTimeKind]::Utc)
    }
    $s = ([string]$Value).Trim()
    if (-not $s) { return $null }
    $d = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $m = [regex]::Match($s, '^(\d{14})')
    if ($m.Success) {
        if ([datetime]::TryParseExact($m.Groups[1].Value, 'yyyyMMddHHmmss', $inv, $styles, [ref]$d)) { return $d }
        return $null
    }
    if ([datetime]::TryParse($s, $inv, $styles, [ref]$d)) { return $d }
    return $null
}

# --- Pure: the display 'Object' name = the leading RDN value of a DN -----------
# audit 2026-07-24 (P4): (($dn -split ',')[0] -replace '^CN=','') truncated a CN that
# carries an RFC-4514 ESCAPED comma - 'CN=Smith\, John,OU=x,DC=..' showed (and was
# AUDITED) as 'Smith\'. That escaping is exactly what the DN guard deliberately
# ALLOWS, so a legitimately-planned object was mislabelled in the destructive fix /
# validate result grid. Consume only UNESCAPED commas ('\\.' swallows any escape pair,
# including an escaped backslash), then unescape the value for display.
function Get-AdToShortName {
    param([string]$Dn)
    if (-not $Dn) { return '' }
    $rdn = [regex]::Match($Dn, '^(?:[^\\,]|\\.)*').Value
    return (($rdn -replace '^CN=', '') -replace '\\(.)', '$1')
}

# Dispose an AD object (DirectoryEntry / DirectorySearcher / SearchResultCollection)
# that MAY be a test shim rather than the real disposable type. audit 2026-07-24 (P3).
function Close-AdToDisposable {
    param($Obj)
    if ($null -eq $Obj) { return }
    if ($Obj -is [System.IDisposable]) { try { $Obj.Dispose() } catch {} }
}

# --- Pure: evaluate ONE object against the TO ----------------------------------
# Returns @{ Status='COMPLIANT'|'NON-COMPLIANT'; Rules=@(names); RequiresIao=bool;
#            Detail='reason -> fix; ...' }. $Now is injectable for testability.
function Test-AdToCompliance {
    param([hashtable]$Obj, [string]$Category, [hashtable]$Baseline, [datetime]$Now = [datetime]::UtcNow)
    $b = $Baseline; if (-not $b) { $b = Get-AdToBaseline }
    $uac = [int]($Obj.Uac)
    # loop54 (F2): an unreadable UAC (ACL-hidden / non-account object) folds to 0 above; a fresh scan carries
    # UacReadable=$false. When it's false the UAC bad-bit rules cannot be trusted (0 reads as "no bad bits"),
    # so we fire a fail-closed uacUnreadable hit instead of silently passing. (Absent flag = readable, for
    # any caller/test that builds an object by hand.)
    $uacReadable = if ($Obj.ContainsKey('UacReadable')) { [bool]$Obj.UacReadable } else { $true }
    $disabled = ($uac -band $script:AdToUac.ACCOUNTDISABLE) -ne 0

    $hits = New-Object System.Collections.ArrayList
    $parts = New-Object System.Collections.ArrayList
    # audit 2026-07-24 (P4): the local $needIao was dead - $fire writes (and the return
    # reads) the module-scope $script:__needIao that shadows it. Removed.

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

    # Days since the object was CREATED; +Inf when whenCreated is absent/unreadable, so an
    # object we cannot date behaves exactly as it did before 0.2.7 (fail-toward-flagged: the
    # scan still surfaces it for a human, it just isn't silently aged).
    $created = Get-AdToWhenCreated $Obj.WhenCreated
    $objAgeDays = if ($created) { ($Now - $created).TotalDays } else { [double]::PositiveInfinity }
    # audit 2026-07-24 (P2): "never logged on" is NOT "maximally stale". A PRE-STAGED computer
    # account and a user created this morning both have lastLogon=0 by definition, and the old
    # +Inf made them the stalest objects in the domain - inactiveEnabled / staleObject fired,
    # and BOTH map to a set-ACCOUNTDISABLE in $script:AdToUacFix, so the fixer disabled a
    # brand-new account before anyone had a chance to use it. Age a never-logged-on object from
    # its creation date (its TRUE idle age) instead; only an undatable object stays +Inf.
    $ageDays = {
        param($ticks)
        $t = 0L; [void][int64]::TryParse([string]$ticks, [ref]$t)
        if ($t -le 0) { return $objAgeDays }   # never logged on -> idle since creation
        try { return ($Now - [datetime]::FromFileTimeUtc($t)).TotalDays } catch { return $objAgeDays }
    }
    # ...and a hard floor on top of it: inside the grace window nothing is flagged
    # inactive/stale however low the thresholds are tuned. An absent knob ([double]$null = 0)
    # disables the floor, so a hand-built baseline keeps the old behaviour.
    $isNewObject = ($objAgeDays -lt [double]$b.newObjectGraceDays)

    if ($Category -in @('User','Admin','Service')) {
        if (-not $uacReadable) { [void]$hits.Add('uacUnreadable'); [void]$parts.Add('userAccountControl absent/unreadable -> UAC compliance NOT confirmed (fail-closed)') }
        # audit 2026-07-28: $uacReadable -and, matching the Computer/Server staleObject guard below.
        # An ACL-hidden UAC folds to 0, so $disabled reads $false for an object we never read -
        # a DISABLED, hidden, idle user was scoring "still ENABLED" and entering the fix plan.
        if ($uacReadable -and -not $disabled -and -not $isNewObject -and (& $ageDays $Obj.LastLogonTicks) -gt [double]$b.inactiveDays) { & $fire 'inactiveEnabled' @($b.inactiveDays) }
        if ($uacReadable -and (($uac -band $script:AdToUac.DONT_EXPIRE_PASSWORD) -ne 0)) { & $fire 'passwordNeverExpires' $null }
        if ($uacReadable -and (($uac -band $script:AdToUac.PASSWD_NOTREQD) -ne 0))       { & $fire 'passwordNotRequired' $null }
        if ($uacReadable -and (($uac -band $script:AdToUac.ENCRYPTED_TEXT_PWD) -ne 0))   { & $fire 'reversibleEncryption' $null }
        if ([string]::IsNullOrWhiteSpace([string]$Obj.Description))  { & $fire 'descriptionMissing' $null }
        if ([string]::IsNullOrWhiteSpace([string]$Obj.Manager))     { & $fire 'managerMissing' $null }
        if ($uacReadable -and (($uac -band $script:AdToUac.SMARTCARD_REQUIRED) -eq 0))   { & $fire 'smartcardNotRequired' $null }
        if ($Category -eq 'Admin' -and @($Obj.ServicePrincipalName).Count -gt 0) { & $fire 'adminHasSpn' $null }
        $recert = Get-AdToRecertDate ([string]$Obj.RecertValue) ([string]$b.recertifyStampPrefix)
        if ($null -eq $recert -or ($Now - $recert).TotalDays -gt [double]$b.recertifyDays) { & $fire 'recertifyOverdue' @($b.recertifyDays, $b.recertifyStampPrefix) }
    }
    if ($Category -in @('Computer','Server')) {
        # audit 2026-07-24 (P3): loop54's fail-closed uacUnreadable hit was wired ONLY into the
        # User/Admin/Service branch above, yet $disabled here is derived from the SAME UAC that
        # folds to 0 when it is ACL-hidden or absent - so an unreadable computer/server object
        # read as "enabled, no bad bits" and, if it had logged on recently, scanned COMPLIANT
        # with no trace. Fire the same fail-closed hit, and do NOT assert staleness off a UAC we
        # never read: the object is already NON-COMPLIANT, and staleObject is the rule that
        # auto-DISABLES (a disabled-but-unreadable machine would otherwise be "re-disabled" on
        # an unverified enabled/disabled reading).
        if (-not $uacReadable) { [void]$hits.Add('uacUnreadable'); [void]$parts.Add('userAccountControl absent/unreadable -> UAC compliance NOT confirmed (fail-closed)') }
        if ($uacReadable -and -not $disabled -and -not $isNewObject -and (& $ageDays $Obj.LastLogonTicks) -gt [double]$b.staleComputerDays) { & $fire 'staleObject' @($b.staleComputerDays) }
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
        # audit 2026-07-28: 0.2.8 -> 0.2.9. inactiveEnabled is now gated on $uacReadable, matching
        # the Computer/Server staleObject guard - an ACL-hidden UAC folds to 0, so a DISABLED,
        # hidden, idle user was scoring "still ENABLED" and landing in the fix plan.
        version  = '0.2.9'
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
# audit 2026-07-23: -RecertAttribute lets the caller pass the attribute name from its
# already-loaded baseline; the Get-AdToBaseline fallback (JSON re-read + parse) was
# paid PER AD OBJECT on whole-domain scans. Fallback kept for bare/legacy callers.
function ConvertTo-AdToObject {
    param($SearchResult, [string]$RecertAttribute)
    $p = $SearchResult.Properties
    $get = { param($n) if ($p[$n] -and $p[$n].Count -gt 0) { $p[$n][0] } else { $null } }
    $cls = @($p['objectclass']); $isComputer = ($cls -contains 'computer')
    $ll1 = [string](& $get 'lastlogontimestamp'); $ll2 = [string](& $get 'lastlogon')
    $ll  = if ($ll1) { $ll1 } else { $ll2 }
    # loop54 (F2): an ACL-hidden userAccountControl is simply absent from the DirectorySearcher result, so
    # [int]("0"+[string]$null)=0 reads as "no bad bits" -> COMPLIANT. Carry a UacReadable flag so the
    # compliance test can fail closed on an unreadable UAC instead of silently passing it.
    $uacRaw = (& $get 'useraccountcontrol')
    if ([string]::IsNullOrWhiteSpace($RecertAttribute)) { $RecertAttribute = [string](Get-AdToBaseline).recertifyAttribute }
    @{
        SamAccountName       = [string](& $get 'samaccountname')
        DistinguishedName    = [string](& $get 'distinguishedname')
        ObjectClass          = if ($isComputer) { 'computer' } else { 'user' }
        OperatingSystem      = [string](& $get 'operatingsystem')
        Uac                  = [int]("0" + [string]$uacRaw)
        UacReadable          = (-not [string]::IsNullOrEmpty([string]$uacRaw))
        ServicePrincipalName = @($p['serviceprincipalname'])
        AdminCount           = [int]("0" + [string](& $get 'admincount'))
        LastLogonTicks       = $ll
        # audit 2026-07-24 (P2): carry whenCreated so Test-AdToCompliance can age a
        # never-logged-on object from its creation date instead of calling it +Inf stale.
        WhenCreated          = (& $get 'whencreated')
        Description          = [string](& $get 'description')
        Manager              = [string](& $get 'manager')
        RecertValue          = [string](& $get $RecertAttribute)
    }
}

function Invoke-JanetToolAction {
    param([string]$ActionId, [hashtable]$Params, $Credential, [scriptblock]$Emit)
    $send = { param($e) if ($Emit) { & $Emit $e } }

    # Operator-cancel bridge (audit 2026-07-24): the server injects the synchronized job
    # hashtable as $Params['__job']; its 'Cancel' flag (set by POST /job/<id>/cancel) lets a
    # running action break. adto was the ONLY module in the suite that never read it, so the
    # view's CANCEL SCAN button was inert - and, far worse, a bulk fix / IAO validate walking
    # a plan and COMMITTING userAccountControl object by object could not be stopped once
    # armed. Absent in direct/test calls -> $cancelCheck returns $false. GetNewClosure() so
    # the closure keeps $cancelJob when it is handed to the fix/validate functions.
    $cancelJob = $null
    if ($Params -and $Params.ContainsKey('__job')) { $cancelJob = $Params['__job'] }
    $cancelCheck = { if ($cancelJob) { try { [bool]$cancelJob['Cancel'] } catch { $false } } else { $false } }.GetNewClosure()

    if ($ActionId -eq 'fix')          { return Invoke-AdToFix      -Params $Params -Credential $Credential -Send $send -CancelCheck $cancelCheck }
    if ($ActionId -eq 'validate-iao') { return Invoke-AdToValidate -Params $Params -Credential $Credential -Send $send -CancelCheck $cancelCheck }
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

    $rows = New-Object System.Collections.ArrayList
    $byCat = @{}; foreach ($c in $script:AdToCategories) { $byCat[$c] = @{ total=0; bad=0 } }
    $iaoCount = 0; $total = 0; $bad = 0; $cancelled = $false
    $now = [datetime]::UtcNow

    # audit 2026-07-24 (P3): the RootDSE/root DirectoryEntry, the DirectorySearcher and the
    # SearchResultCollection were NEVER disposed - and the search catch below returned with the
    # collection still open - so every scan leaked an unmanaged LDAP connection + handles for the
    # life of the (long-running) server process. Hold them in one scope and dispose in a finally,
    # which also runs on the early returns below.
    $rootDse = $null; $root = $null; $ds = $null; $results = $null
    try {
        # Bind (honour the session credential; else current Kerberos identity).
        try {
            if ($Credential -is [System.Management.Automation.PSCredential]) {
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
        # audit 2026-07-24 (P2): bound the search. There was NO timeout at all, so a wedged or
        # hostile DC could block inside FindAll()/the page fetch forever, pinning the job runspace
        # with no way out - the operator's Cancel cannot interrupt a blocking LDAP call, it can
        # only be honoured between objects (below). ServerPageTimeLimit bounds each 1000-object
        # page; ClientTimeout bounds the whole search.
        $ds.ServerPageTimeLimit = [timespan]::FromSeconds(120)
        $ds.ClientTimeout       = [timespan]::FromMinutes(15)
        foreach ($a in 'samaccountname','distinguishedname','objectclass','operatingsystem','useraccountcontrol','serviceprincipalname','admincount','lastlogontimestamp','lastlogon','whencreated','description','manager',$baseline.recertifyAttribute) { [void]$ds.PropertiesToLoad.Add($a) }

        try {
            $results = $ds.FindAll()
            foreach ($sr in $results) {
                # audit 2026-07-24 (P2): honour the operator's Cancel between objects (the scan is
                # read-only, so stopping here is always safe; the rows already emitted stand).
                if (& $cancelCheck) { $cancelled = $true; & $send @{ type='log'; level='warn'; text='Scan cancelled by operator - the counts below cover only the objects scanned so far.' }; break }
                $obj = ConvertTo-AdToObject $sr -RecertAttribute ([string]$baseline.recertifyAttribute)   # audit 2026-07-23: no per-object baseline re-read
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
        } catch { & $send @{ type='log'; level='err'; text="AD search failed: $($_.Exception.Message)" }; return @{ rows=@($rows); summary=@{ total=$total; rejected=$true } } }
    } finally {
        # order matters: the result collection first, then the searcher, then the entries.
        Close-AdToDisposable $results; Close-AdToDisposable $ds
        Close-AdToDisposable $root;    Close-AdToDisposable $rootDse
    }

    $verb = if ($cancelled) { 'CANCELLED' } else { 'done' }
    $catLine = (@($script:AdToCategories | ForEach-Object { "{0} {1}/{2}" -f $_, $byCat[$_].bad, $byCat[$_].total }) -join '  |  ')
    & $send @{ type='log'; level=($(if($bad -or $cancelled){'warn'}else{'ok'})); text="AD TO scan $verb. $bad NON-COMPLIANT of $total. By category (bad/total): $catLine. $iaoCount need IAO validation." }
    & $send @{ type='status'; text="$(if ($cancelled) { 'Cancelled' } else { 'Done' }). $bad non-compliant of $total AD object(s)." }
    return @{ rows=@($rows); summary=@{ total=$total; nonCompliant=$bad; iaoRequired=$iaoCount; byCategory=$byCat; source=$baseline.Source; cancelled=$cancelled } }
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
    param([hashtable]$Params, $Credential, [scriptblock]$Send, [scriptblock]$CancelCheck)
    if ([string]$Params['confirm'] -cne 'FIX') { & $Send @{ type='log'; level='err'; text='Refused: type FIX (exactly) in Confirm to arm the fix.' }; return @{ rows=@(); summary=@{ total=0; rejected=$true } } }
    $plan = @(); try { $plan = @(ConvertFrom-Json ([string]$Params['plan'])) } catch { & $Send @{ type='log'; level='err'; text="Plan JSON parse failed: $($_.Exception.Message)" }; return @{ rows=@(); summary=@{ total=0; rejected=$true } } }
    if ($plan.Count -eq 0) { & $Send @{ type='log'; level='warn'; text='Empty plan - nothing to fix.' }; return @{ rows=@(); summary=@{ total=0 } } }

    $expectDom = Get-AdToExpectedDomainSuffix   # this host's domain DN suffix, computed once
    # audit 2026-07-24 (P3): with USERDNSDOMAIN unset the suffix is blank and the guard fails
    # closed for EVERY dn. Say so ONCE up front - the per-row text used to blame the operator's
    # (perfectly valid) DN and sent them hunting a typo that was never there.
    if (-not $expectDom) { & $Send @{ type='log'; level='err'; text="This host's USERDNSDOMAIN is not set, so no plan dn can be proven to be in the local domain - the bind-redirect guard will REJECT every object. This is a JANET host environment problem, not a problem with the plan." } }
    $rows = New-Object System.Collections.ArrayList; $i = 0; $cancelled = $false
    foreach ($e in $plan) {
        # audit 2026-07-24 (P2): honour the operator's Cancel BETWEEN objects. This loop COMMITS
        # userAccountControl per object, so an aborted bulk run must stop cleanly before the next
        # bind - never mid-commit. Objects already written keep their rows + audit events.
        if ($CancelCheck -and (& $CancelCheck)) {
            $cancelled = $true
            & $Send @{ type='log'; level='warn'; text=("Fix CANCELLED by operator after {0} of {1} planned object(s) - the remainder were NOT touched." -f $i, $plan.Count) }
            break
        }
        $i++; & $Send @{ type='progress'; done=$i; total=$plan.Count }
        $dn = [string]$e.dn; if (-not $dn) { continue }
        $short = Get-AdToShortName $dn   # audit 2026-07-24 (P4): RFC-4514 escaped-comma safe
        # New-AdToEntry binds LDAP://$dn with the CREDENTIAL: a dn from the client plan that is not a
        # plain distinguished name (e.g. 'evildc/DC=x') OR a bare foreign domain (e.g. DC=evil,DC=com,
        # which serverless-binds the attacker's DC) would redirect that credentialed bind. Refuse
        # anything that is not a plain DN ending at THIS host's domain before touching the directory
        # (block '/', allow RFC-escaped '\'; same hardened guard as the scan site - audit P2 + P3).
        if (-not (Test-AdToDnInLocalDomain -Value $dn -ExpectDomainSuffix $expectDom)) {
            # audit 2026-07-24 (P3): name the REAL cause. The scan path at the top of the file
            # already distinguishes these two; the write paths blamed the dn either way.
            $why = if (-not $expectDom) {
                "refused: this host's USERDNSDOMAIN is not set, so NO dn can be proven in-domain (bind-redirect guard fails closed) - the plan dn is not at fault"
            } else {
                "refused: dn is not a plain distinguished name in this host's domain ($expectDom) (bind-redirect guard)"
            }
            $row = @{ Object=$short; Category=''; Status='REJECTED'; Applied=''; Detail=$why; DN=$dn }
            [void]$rows.Add($row); & $Send (@{ type='row' } + $row)
            # Audit the redirect refusal (loop12 F3): a plan steering a credentialed write at a
            # foreign/redirected DN is a security-relevant event and must leave an audit trail,
            # not just a UI row.
            & $Send @{ type='audit'; action='AdToFix'; target=[string]$dn; result='Skipped'; itemCount=0; detail=("[REJECTED] bind-redirect guard: {0}" -f $why) }
            continue
        }
        $rules = @($e.rules)
        $de = $null
        try {
            $de  = New-AdToEntry -Dn $dn -Credential $Credential
            # loop53 (F1): a NULL / absent / unreadable userAccountControl must NOT coerce to 0. A non-account
            # object (group / OU / contact - no UAC at all, but binds and passes the DN guard) or an
            # ACL-denied read would otherwise read $cur=0, which Get-AdToFixedUac computes as "no bad bits ->
            # already compliant", asserting compliance of bits never read - and a set-op rule would WRITE a
            # corrupting full UAC (wiping NORMAL_ACCOUNT) before the re-read caught it. Fail closed: we cannot
            # evaluate or fix a UAC we never read. (A real account's UAC is always non-zero.)
            $rawUac = $de.Properties['userAccountControl'].Value
            if ($null -eq $rawUac) {
                $row = @{ Object=$short; Category=''; Status='FAILED'; Applied=''; Detail='userAccountControl absent/unreadable (not a user/computer account, or read access-denied) - compliance NOT evaluated, nothing changed'; DN=$dn }
                [void]$rows.Add($row); & $Send (@{ type='row' } + $row)
                & $Send @{ type='audit'; action='AdToFix'; target=[string]$dn; result='Failure'; itemCount=0; detail='[FAILED] userAccountControl absent/unreadable - nothing changed' }
                continue
            }
            $cur = [int]$rawUac
            # Protected-object guard (loop12 F1): this bulk-remediation tool must NEVER modify a
            # domain controller or an AdminSDHolder-protected (privileged) object. The DN guard
            # above proves the target is in-domain, but NOT that it is a safe object - a crafted
            # or fat-fingered plan naming a DC computer object or a break-glass admin account
            # would otherwise get ACCOUNTDISABLE set (a DoS of a critical AD object). Refuse a
            # DC (SERVER_TRUST bit in its own UAC) or any object with adminCount>=1, before the
            # write, and audit the refusal.
            # loop13: catch a READ-ONLY DC too - an RODC computer object carries
            # PARTIAL_SECRETS_ACCOUNT, NOT SERVER_TRUST, and is not adminCount-protected, so
            # it slipped both halves of the original guard (disabling an RODC breaks a branch
            # office's auth). adminCount parse now fails CLOSED (refuse when uncertain).
            $isDc = (($cur -band [int]$script:AdToUac.SERVER_TRUST) -ne 0) -or (($cur -band [int]$script:AdToUac.PARTIAL_SECRETS_ACCOUNT) -ne 0)
            $adminCount = 0; try { $adminCount = [int]("0" + [string]$de.Properties['adminCount'].Value) } catch { $adminCount = 1 }
            if ($isDc -or $adminCount -ge 1) {
                $why = if ($isDc) { 'domain controller (SERVER_TRUST/RODC)' } else { 'privileged/protected (adminCount>=1)' }
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
                # audit 2026-07-24 (P3): the verification re-read bound a SECOND DirectoryEntry and
                # dropped it on the floor - one leaked LDAP connection per FIXED object.
                $ver = 0; $vde = $null
                try {
                    $vde = New-AdToEntry -Dn $dn -Credential $Credential
                    $ver = [int]("0" + [string]$vde.Properties['userAccountControl'].Value)
                } finally { Close-AdToDisposable $vde }
                $ok  = ($ver -eq $fx.Uac)
                $row = @{ Object=$short; Category=''; Status=($(if ($ok) { 'FIXED' } else { 'FAILED' })); Applied=(@($fx.Applied) -join ', '); Detail=("UAC {0} -> {1}{2}" -f $cur, $fx.Uac, $skipNote); DN=$dn }
            }
        } catch { $row = @{ Object=$short; Category=''; Status='FAILED'; Applied=''; Detail=("LDAP write failed: {0}" -f $_.Exception.Message); DN=$dn } }
        finally { Close-AdToDisposable $de }   # audit 2026-07-24 (P3): also runs on the 'continue' paths above
        [void]$rows.Add($row); & $Send (@{ type='row' } + $row)
        $appliedN = if ([string]$row.Applied) { @([string]$row.Applied -split ',').Count } else { 0 }
        $auditRes = switch ([string]$row.Status) { 'FIXED' { 'Success' } 'FAILED' { 'Failure' } default { 'Skipped' } }
        & $Send @{ type='audit'; action='AdToFix'; target=[string]$dn; result=$auditRes; itemCount=$appliedN; detail=("[{0}] {1}" -f $row.Status, $row.Detail) }
    }
    $fixed = @($rows | Where-Object { $_.Status -eq 'FIXED' }).Count
    & $Send @{ type='status'; text="$(if ($cancelled) { 'Cancelled' } else { 'Done' }). $fixed fixed of $($rows.Count) object(s)." }
    return @{ rows=@($rows); summary=@{ total=$rows.Count; fixed=$fixed; planned=$plan.Count; cancelled=$cancelled } }
}

# --- Action: validate-iao (destructive, IAO EXPRESS PERMISSION ONLY) ------------
# The first RBAC instance in the suite: refused server-side unless the operator is on
# the baseline iaoValidators allow-list. Writes ONLY the recert stamp, nothing else.
function Invoke-AdToValidate {
    param([hashtable]$Params, $Credential, [scriptblock]$Send, [scriptblock]$CancelCheck)
    if ([string]$Params['confirm'] -cne 'VALIDATE') { & $Send @{ type='log'; level='err'; text='Refused: type VALIDATE (exactly) in Confirm to arm.' }; return @{ rows=@(); summary=@{ total=0; rejected=$true } } }
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
    # audit 2026-07-24 (P3): same up-front honesty as the fix path - a blank suffix means the
    # guard rejects EVERY dn for a host-environment reason, not because the IAO's plan is wrong.
    if (-not $expectDom) { & $Send @{ type='log'; level='err'; text="This host's USERDNSDOMAIN is not set, so no plan dn can be proven to be in the local domain - the bind-redirect guard will REJECT every object. This is a JANET host environment problem, not a problem with the plan." } }
    $rows = New-Object System.Collections.ArrayList; $i = 0; $cancelled = $false
    foreach ($e in $plan) {
        # audit 2026-07-24 (P2): honour the operator's Cancel between objects - this loop COMMITS
        # a recert stamp per object and must be abortable without stopping mid-write.
        if ($CancelCheck -and (& $CancelCheck)) {
            $cancelled = $true
            & $Send @{ type='log'; level='warn'; text=("IAO validation CANCELLED by operator after {0} of {1} planned object(s) - the remainder were NOT stamped." -f $i, $plan.Count) }
            break
        }
        $i++; & $Send @{ type='progress'; done=$i; total=$plan.Count }
        $dn = [string]$e.dn; if (-not $dn) { continue }
        $short = Get-AdToShortName $dn   # audit 2026-07-24 (P4): RFC-4514 escaped-comma safe
        # Same hardened bind-redirect guard as the fix + scan paths: New-AdToEntry binds LDAP://$dn
        # with the credential, so refuse any plan dn that is not a plain distinguished name ending at
        # THIS host's domain (block '/' and foreign domains; allow RFC-escaped '\') before binding.
        if (-not (Test-AdToDnInLocalDomain -Value $dn -ExpectDomainSuffix $expectDom)) {
            # audit 2026-07-24 (P3): name the REAL cause (unset USERDNSDOMAIN vs a bad dn).
            $why = if (-not $expectDom) {
                "refused: this host's USERDNSDOMAIN is not set, so NO dn can be proven in-domain (bind-redirect guard fails closed) - the plan dn is not at fault"
            } else {
                "refused: dn is not a plain distinguished name in this host's domain ($expectDom) (bind-redirect guard)"
            }
            $row = @{ Object=$short; Status='REJECTED'; Detail=$why; DN=$dn }
            [void]$rows.Add($row); & $Send (@{ type='row' } + $row)
            # Audit the redirect refusal (loop12 F3): same rationale as the fix path.
            & $Send @{ type='audit'; action='AdToIaoValidate'; target=[string]$dn; result='Skipped'; itemCount=0; detail=("[REJECTED] bind-redirect guard: {0}" -f $why) }
            continue
        }
        $stamp = New-AdToRecertStamp -Prefix ([string]$baseline.recertifyStampPrefix) -Date (Get-Date) -By $byId
        $de = $null
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
            # audit 2026-07-24 (P3): dispose the re-read entry - one leaked LDAP connection per object.
            $after = ''; $vde = $null
            try {
                $vde = New-AdToEntry -Dn $dn -Credential $Credential
                $after = [string]$vde.Properties[$attr].Value
            } finally { Close-AdToDisposable $vde }
            if ($after -match [regex]::Escape($stamp)) {
                $row = @{ Object=$short; Status='VALIDATED'; Detail=("stamped '{0}' into {1}" -f $stamp, $attr); DN=$dn }
            } else {
                $row = @{ Object=$short; Status='FAILED'; Detail=("stamp not present on re-read - commit did not persist into '{0}'" -f $attr); DN=$dn }
            }
        } catch { $row = @{ Object=$short; Status='FAILED'; Detail=("LDAP write failed: {0}" -f $_.Exception.Message); DN=$dn } }
        finally { Close-AdToDisposable $de }   # audit 2026-07-24 (P3)
        [void]$rows.Add($row); & $Send (@{ type='row' } + $row)
        & $Send @{ type='audit'; action='AdToIaoValidate'; target=[string]$dn; result=$(if ([string]$row.Status -eq 'VALIDATED') { 'Success' } else { 'Failure' }); itemCount=1; detail=("IAO '{0}': {1}" -f $byId, $row.Detail) }
    }
    $ok = @($rows | Where-Object { $_.Status -eq 'VALIDATED' }).Count
    & $Send @{ type='status'; text="$(if ($cancelled) { 'Cancelled' } else { 'Done' }). $ok validated of $($rows.Count)." }
    return @{ rows=@($rows); summary=@{ total=$rows.Count; validated=$ok; planned=$plan.Count; cancelled=$cancelled } }
}

Export-ModuleMember -Function Get-JanetToolManifest, Invoke-JanetToolAction, Get-AdToBaseline, Get-AdToCategory, Get-AdToRecertDate, Get-AdToWhenCreated, Get-AdToShortName, Test-AdToCompliance, Get-AdToFixedUac, Test-AdToIaoAuthorized, New-AdToRecertStamp, Test-AdToDnInLocalDomain, Get-AdToExpectedDomainSuffix
