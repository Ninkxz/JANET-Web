# =============================================================================
#  History.CoverageReconcile.Tests.ps1 - Pester 3.4 for fleet coverage
#  reconciliation (capability audit 2026-07-25 #8, JanetWeb.history 1.2.0).
#
#  The Staleness Board only ever verdicts hosts the operator PASTES, and
#  wpt/ad-computers already enumerates the whole domain's computer objects - but
#  only to feed an OU picker. The two never met, so "you patched 400 hosts but 60
#  are dead AD objects" was a by-hand diff between two grids. coverage-reconcile
#  joins them.
#
#  What these tests pin, in priority order:
#    1. FAIL CLOSED. A capped or errored read - on EITHER side - renders UNKNOWN,
#       never COVERED. COVERED is the verdict that makes a lead STOP looking at a
#       machine; it must never rest on rows we did not read. This includes an
#       unreadable userAccountControl (the audit's C2 finding) and an incomplete
#       AD enumeration, which cannot prove a host is absent from the directory.
#    2. The verdict table: COVERED / STALE (live) / NEVER TOUCHED (live) /
#       GHOST (JANET touched a host AD says is dead) / DEAD OBJECT.
#    3. The SearchBase DN guard rejects a redirected/foreign bind BEFORE any LDAP
#       call is attempted (LDAP://<base> is a BIND path, not a filter).
#    4. The __job operator-cancel bridge actually reaches the enumeration.
#
#  No directory and no log share are touched: Read-HistAdComputers and
#  Resolve-HistRoot are shadowed in MODULE scope and SAVED/RESTORED (the naive
#  'Remove-Item function:script:X' form is INERT against a module-scope function
#  and its unqualified sibling DESTROYS the module's real one - see
#  tests\Patchlib.Tests.ps1). The ONE test that does issue a real ADSI call aims
#  at a deliberately nonexistent domain and asserts only that it FAILS CLOSED.
#
#  Run:  Invoke-Pester -Path .\tests\History.CoverageReconcile.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.history.psm1') -Force -PassThru
$script:Tmp  = Join-Path ([System.IO.Path]::GetTempPath()) ('histcovtest_' + [guid]::NewGuid().ToString('N'))
[void][System.IO.Directory]::CreateDirectory($script:Tmp)

# --- fake AD objects in the shape Read-HistAdComputers returns -----------------
function New-CovAd {
    param([string]$Name, [bool]$Enabled = $true, [bool]$UacKnown = $true, [int]$LogonDaysAgo = 1)
    $ll = if ($LogonDaysAgo -lt 0) { [datetime]::MinValue } else { (Get-Date).AddDays(-1 * $LogonDaysAgo) }
    return [pscustomobject]@{
        Name = $Name.ToUpperInvariant(); Dn = "CN=$Name,OU=Lab,DC=area52,DC=mil"
        Os = 'Windows 10 Enterprise'; UacKnown = $UacKnown
        Uac = $(if ($Enabled) { 4096 } else { 4098 }); Enabled = $Enabled; LastLogon = $ll
    }
}

# --- audit tree: <root>\<Tool>\<userFolder>\<yyyy-MM>_detail.csv ---------------
# Touches: @( @{ Host='WS-1'; DaysAgo=5; Tool='WPT' }, ... )
function New-CovAuditTree {
    param([string]$Name, $Touches = @())
    $root = Join-Path $script:Tmp $Name
    $dir  = Join-Path $root 'WPT\test.operator'
    [void][System.IO.Directory]::CreateDirectory($dir)
    $byMonth = @{}
    foreach ($t in @($Touches)) {
        $dt = (Get-Date).AddDays(-1 * [int]$t.DaysAgo)
        $m  = $dt.ToString('yyyy-MM')
        if (-not $byMonth.ContainsKey($m)) { $byMonth[$m] = (New-Object System.Collections.ArrayList) }
        [void]$byMonth[$m].Add(('{0},s1,Test Operator,ASI,{1},1.0.0,Patch,{2},Success,1,ok' -f `
            $dt.ToString('yyyy-MM-dd HH:mm:ss'), ([string]$t.Tool), ([string]$t.Host)))
    }
    foreach ($m in @($byMonth.Keys)) {
        $lines = New-Object System.Collections.ArrayList
        [void]$lines.Add('Timestamp,SessionId,Operator,ASI,Tool,ToolVersion,Action,Target,Result,ItemCount,Detail')
        foreach ($l in $byMonth[$m]) { [void]$lines.Add($l) }
        Set-Content -LiteralPath (Join-Path $dir ($m + '_detail.csv')) -Value $lines -Encoding ASCII
    }
    return $root
}

# --- module-scope shims, SAVED so they can be RESTORED -------------------------
& $script:Mod {
    $script:__origResolveHistRoot = ${function:Resolve-HistRoot}
    $script:__origReadHistAd      = ${function:Read-HistAdComputers}
}
function Set-CovRootOverride {
    param([string]$Path, [bool]$Exists = $true)
    & $script:Mod {
        param($p, $e)
        ${function:script:Resolve-HistRoot} = { @{ Root = $p; OnShare = $false; Reason = "test root ($p)"; Exists = $e } }.GetNewClosure()
    } $Path $Exists
}
function Set-CovAdShim {
    param($Rows = @(), [bool]$Capped = $false, [bool]$Cancelled = $false, [int]$Errors = 0)
    & $script:Mod {
        param($rows, $cap, $can, $err)
        $script:__covRows  = @($rows)
        $script:__covCap   = [bool]$cap
        $script:__covCan   = [bool]$can
        $script:__covErr   = [int]$err
        $script:__covCalls = New-Object System.Collections.ArrayList
        function script:Read-HistAdComputers {
            param([string]$SearchBase = '', $Credential = $null, [int]$Cap = 0, [scriptblock]$IsCancelled = $null, [scriptblock]$OnProgress = $null)
            $sawCancel = $false
            if ($IsCancelled) { $sawCancel = [bool](& $IsCancelled) }
            [void]$script:__covCalls.Add(@{ SearchBase = $SearchBase; SawCancel = $sawCancel })
            return @{ Rows = $script:__covRows; Capped = $script:__covCap; Cancelled = $script:__covCan; Errors = $script:__covErr; ErrorMessages = @('shimmed AD read failure') }
        }
    } $Rows $Capped $Cancelled $Errors
}
# Return a COUNT and an INDEXED item rather than the collection: 'return @($x)'
# unwraps a one-element array back to the bare element, and a bare hashtable's
# .Count is its KEY count (2), not 1 - the same unary-comma / collection-unwrap
# trap that has silently broken guards in this suite before. An int and a single
# object cannot be unwrapped into the wrong answer.
function Get-CovAdCallCount { return [int](& $script:Mod { @($script:__covCalls).Count }) }
function Get-CovAdCallAt { param([int]$Index) return (& $script:Mod { param($i) @($script:__covCalls)[$i] } $Index) }
function Restore-CovShims {
    & $script:Mod {
        ${function:script:Resolve-HistRoot}      = $script:__origResolveHistRoot
        ${function:script:Read-HistAdComputers}  = $script:__origReadHistAd
        Remove-Variable -Name __covRows, __covCap, __covCan, __covErr, __covCalls -Scope Script -ErrorAction SilentlyContinue
    }
}

function Invoke-Coverage {
    param([hashtable]$Params = @{})
    $evts = New-Object System.Collections.ArrayList
    $r = Invoke-JanetToolAction -ActionId 'coverage-reconcile' -Params $Params -Emit { param($e) [void]$evts.Add($e) }
    return @{ Result = $r; Events = @($evts) }
}
function Get-CovRow {
    param($Run, [string]$HostName)
    return @($Run.Result.rows | Where-Object { [string]$_.Host -eq $HostName.ToUpperInvariant() })[0]
}

# -----------------------------------------------------------------------------
Describe 'SearchBase DN guard (LDAP://<base> is a BIND path, not a filter)' {

    $script:Suffix = 'DC=area52,DC=mil'
    function Test-Dn { param([string]$V) return (& $script:Mod { param($v, $s) Test-HistDnInLocalDomain -Value $v -ExpectDomainSuffix $s } $V $script:Suffix) }

    It 'accepts a plain OU DN inside this host domain' { (Test-Dn 'OU=Squadron,DC=area52,DC=mil') | Should Be $true }
    It 'accepts the bare domain root'                  { (Test-Dn 'DC=area52,DC=mil') | Should Be $true }
    It 'rejects a server-prefixed path that would redirect the bind' { (Test-Dn 'evildc/DC=area52,DC=mil') | Should Be $false }
    It 'rejects a full LDAP:// URL'                    { (Test-Dn 'LDAP://evil/DC=area52,DC=mil') | Should Be $false }
    It 'rejects a FOREIGN domain (serverless bind to someone else''s DC)' { (Test-Dn 'OU=X,DC=evil,DC=com') | Should Be $false }
    It 'rejects a child-subdomain prepend'             { (Test-Dn 'DC=evil,DC=area52,DC=mil') | Should Be $false }
    It 'rejects a trailing-substring near miss (CN=ABDC=AREA52,DC=MIL)' { (Test-Dn 'CN=ABDC=AREA52,DC=MIL') | Should Be $false }
    It 'rejects a trailing newline that regex $ would otherwise tolerate' { (Test-Dn "OU=X,DC=area52,DC=mil`n") | Should Be $false }
    It 'rejects everything when USERDNSDOMAIN is unknown (no suffix = no trust)' {
        (& $script:Mod { Test-HistDnInLocalDomain -Value 'OU=X,DC=area52,DC=mil' -ExpectDomainSuffix '' }) | Should Be $false
    }

    It 'refuses the action on a bad SearchBase and never issues an LDAP call' {
        Set-CovAdShim -Rows @((New-CovAd -Name 'WS-0001'))
        Set-CovRootOverride -Path (New-CovAuditTree -Name 'guard') -Exists $true
        $run = Invoke-Coverage -Params @{ searchBase = 'evildc/DC=area52,DC=mil' }
        $run.Result.summary.rejected | Should Be $true
        @($run.Result.rows).Count | Should Be 0
        (Get-CovAdCallCount) | Should Be 0
        (@($run.Events | Where-Object { $_.type -eq 'error' }).Count -ge 1) | Should Be $true
    }
}

# -----------------------------------------------------------------------------
Describe 'Get-HistCoverageVerdict - the verdict table, isolated' {

    function Verdict { param($Alive, [bool]$InAd, [bool]$Touched, [int]$Days = 0, [string]$Reason = '')
        return (& $script:Mod { param($a, $i, $t, $d, $r) Get-HistCoverageVerdict -AdAlive $a -InAd $i -Touched $t -DaysAgo $d -ThresholdDays 30 -UnknownReason $r } $Alive $InAd $Touched $Days $Reason)
    }

    It 'COVERED - a live AD object touched inside the threshold' { (Verdict $true $true $true 5) | Should Be 'COVERED' }
    It 'STALE (live) - a live AD object last touched outside the threshold' { (Verdict $true $true $true 60) | Should Be 'STALE (live)' }
    It 'NEVER TOUCHED (live) - a live AD object with no audit row at all' { (Verdict $true $true $false 0) | Should Be 'NEVER TOUCHED (live)' }
    It 'GHOST - JANET touched a host AD says is dead' { (Verdict $false $true $true 5) | Should Be 'GHOST' }
    It 'DEAD OBJECT - AD says dead and JANET never touched it' { (Verdict $false $true $false 0) | Should Be 'DEAD OBJECT' }
    It 'GHOST - a touched host the directory has no object for' { (Verdict $null $false $true 5) | Should Be 'GHOST' }
    It 'UNKNOWN when the AD status itself is unreadable - never COVERED' { (Verdict $null $true $true 1) | Should Be 'UNKNOWN (AD status unreadable)' }
    It 'FAILS CLOSED: an UnknownReason beats every other input, including a fresh touch' {
        (Verdict $true $true $true 1 'UNKNOWN (read error)') | Should Be 'UNKNOWN (read error)'
    }
}

# -----------------------------------------------------------------------------
Describe 'coverage-reconcile joins the AD population against the audit trail' {

    $script:Fleet = @(
        (New-CovAd -Name 'WS-COVERED'),                                   # enabled, logged on yesterday
        (New-CovAd -Name 'WS-STALECOV'),                                  # enabled, touched long ago
        (New-CovAd -Name 'WS-UNTOUCHED'),                                 # enabled, never touched
        (New-CovAd -Name 'WS-DISABLED' -Enabled $false),                  # disabled, never touched
        (New-CovAd -Name 'WS-GHOST'    -Enabled $false),                  # disabled, but JANET touched it
        (New-CovAd -Name 'WS-ADSTALE'  -LogonDaysAgo 200),                # enabled but no AD logon in 200d
        (New-CovAd -Name 'WS-NOUAC'    -UacKnown $false)                  # userAccountControl unreadable
    )
    $script:Touches = @(
        @{ Host = 'WS-COVERED';  DaysAgo = 3;  Tool = 'WPT' },
        @{ Host = 'WS-STALECOV'; DaysAgo = 90; Tool = 'ACAS' },
        @{ Host = 'WS-GHOST';    DaysAgo = 2;  Tool = 'UPR' }
    )

    function Invoke-Fleet {
        param([hashtable]$Extra = @{})
        Set-CovAdShim -Rows $script:Fleet
        Set-CovRootOverride -Path (New-CovAuditTree -Name ('fleet_' + [guid]::NewGuid().ToString('N').Substring(0, 8)) -Touches $script:Touches) -Exists $true
        $p = @{ thresholdDays = 30; adStaleDays = 90; lookbackMonths = 12 }
        foreach ($k in $Extra.Keys) { $p[$k] = $Extra[$k] }
        return (Invoke-Coverage -Params $p)
    }

    It 'renders COVERED for a live host touched inside the threshold, with its tool and days-ago' {
        $run = Invoke-Fleet
        $r = Get-CovRow $run 'WS-COVERED'
        ([string]$r.Verdict)  | Should Be 'COVERED'
        ([string]$r.AdStatus) | Should Be 'Enabled'
        ([string]$r.LastTool) | Should Be 'WPT'
        ([int]$r.DaysAgo)     | Should Be 3
    }

    It 'renders STALE (live) for a live host whose last touch is older than the threshold' {
        $run = Invoke-Fleet
        ([string](Get-CovRow $run 'WS-STALECOV').Verdict) | Should Be 'STALE (live)'
    }

    It 'renders NEVER TOUCHED (live) for a live host with no audit row' {
        $run = Invoke-Fleet
        ([string](Get-CovRow $run 'WS-UNTOUCHED').Verdict) | Should Be 'NEVER TOUCHED (live)'
    }

    It 'renders GHOST when JANET touched a host the directory says is disabled' {
        $run = Invoke-Fleet
        $r = Get-CovRow $run 'WS-GHOST'
        ([string]$r.Verdict)  | Should Be 'GHOST'
        ([string]$r.AdStatus) | Should Be 'Disabled'
    }

    It 'renders DEAD OBJECT for a disabled host JANET never touched' {
        $run = Invoke-Fleet
        ([string](Get-CovRow $run 'WS-DISABLED').Verdict) | Should Be 'DEAD OBJECT'
    }

    It 'labels an enabled object with no AD logon inside adStaleDays as Stale-90d, not Enabled' {
        $run = Invoke-Fleet
        $r = Get-CovRow $run 'WS-ADSTALE'
        ([string]$r.AdStatus) | Should Be 'Stale-90d'
        ([string]$r.Verdict)  | Should Be 'DEAD OBJECT'
    }

    It 'FAILS CLOSED on an unreadable userAccountControl - UNKNOWN, never COVERED (audit C2)' {
        $run = Invoke-Fleet
        $r = Get-CovRow $run 'WS-NOUAC'
        ([string]$r.AdStatus) | Should Be 'UNKNOWN'
        ([string]$r.Verdict)  | Should Match '^UNKNOWN'
    }

    It 'counts every verdict in the summary and surfaces the GHOST warning' {
        $run = Invoke-Fleet
        [int]$run.Result.summary.total     | Should Be 7
        [int]$run.Result.summary.covered   | Should Be 1
        [int]$run.Result.summary.staleLive | Should Be 1
        [int]$run.Result.summary.never     | Should Be 1
        [int]$run.Result.summary.ghost     | Should Be 1
        [int]$run.Result.summary.dead      | Should Be 2
        [int]$run.Result.summary.unknown   | Should Be 1
        ((@($run.Events | Where-Object { $_.type -eq 'log' } | ForEach-Object { [string]$_.text }) -join ' ') -like '*GHOST*') | Should Be $true
    }

    It 'honours thresholdDays - widening it turns STALE (live) into COVERED' {
        $run = Invoke-Fleet -Extra @{ thresholdDays = 120 }
        ([string](Get-CovRow $run 'WS-STALECOV').Verdict) | Should Be 'COVERED'
    }

    It 'honours adStaleDays - widening it keeps the 200-day-logon object Enabled' {
        $run = Invoke-Fleet -Extra @{ adStaleDays = 365 }
        ([string](Get-CovRow $run 'WS-ADSTALE').AdStatus) | Should Be 'Enabled'
    }

    It 'is read-only: it emits no audit row' {
        $run = Invoke-Fleet
        @($run.Events | Where-Object { $_.type -eq 'audit' }).Count | Should Be 0
    }
}

# -----------------------------------------------------------------------------
Describe 'coverage-reconcile FAILS CLOSED (a capped or errored read is never COVERED)' {

    $script:LiveFleet = @((New-CovAd -Name 'WS-COVERED'))
    $script:LiveTouch = @(@{ Host = 'WS-COVERED'; DaysAgo = 3; Tool = 'WPT' })

    It 'renders UNKNOWN (read error) for EVERY host when the audit source cannot be read' {
        Set-CovAdShim -Rows $script:LiveFleet
        Set-CovRootOverride -Path (Join-Path $script:Tmp '__unreadable__') -Exists $false
        $run = Invoke-Coverage -Params @{ thresholdDays = 30 }
        ([string](Get-CovRow $run 'WS-COVERED').Verdict) | Should Be 'UNKNOWN (read error)'
        [int]$run.Result.summary.covered | Should Be 0
        [int]$run.Result.summary.unknown | Should Be 1
        $run.Result.summary.readFailed | Should Be $true
    }

    It 'renders UNKNOWN (read error) when a monthly audit CSV is locked, even for a host it DID find' {
        Set-CovAdShim -Rows $script:LiveFleet
        $root = New-CovAuditTree -Name 'covLocked' -Touches $script:LiveTouch
        $csv  = Join-Path $root ('WPT\test.operator\' + (Get-Date).ToString('yyyy-MM') + '_detail.csv')
        $fs = [System.IO.File]::Open($csv, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        try {
            Set-CovRootOverride -Path $root -Exists $true
            $run = Invoke-Coverage -Params @{ thresholdDays = 30; lookbackMonths = 1 }
            ([string](Get-CovRow $run 'WS-COVERED').Verdict) | Should Be 'UNKNOWN (read error)'
            [int]$run.Result.summary.covered | Should Be 0
            ([int]$run.Result.summary.readErrors -ge 1) | Should Be $true
        } finally { $fs.Close(); $fs.Dispose() }
    }

    It 'surfaces an AD enumeration failure as an error event and never claims coverage from it' {
        Set-CovAdShim -Rows @() -Errors 1
        Set-CovRootOverride -Path (New-CovAuditTree -Name 'covAdFail' -Touches $script:LiveTouch) -Exists $true
        $run = Invoke-Coverage -Params @{ targets = 'WS-COVERED' }
        $run.Result.summary.adFailed | Should Be $true
        $run.Result.summary.readFailed | Should Be $true
        (@($run.Events | Where-Object { $_.type -eq 'error' }).Count -ge 1) | Should Be $true
        [int]$run.Result.summary.covered | Should Be 0
    }

    It 'a CAPPED AD enumeration cannot prove a pasted host is absent - UNKNOWN, not NOT IN AD' {
        Set-CovAdShim -Rows @((New-CovAd -Name 'WS-OTHER')) -Capped $true
        Set-CovRootOverride -Path (New-CovAuditTree -Name 'covAdCap' -Touches $script:LiveTouch) -Exists $true
        $run = Invoke-Coverage -Params @{ targets = 'WS-COVERED' }
        $r = Get-CovRow $run 'WS-COVERED'
        ([string]$r.AdStatus) | Should Be 'UNKNOWN'
        ([string]$r.Verdict)  | Should Be 'UNKNOWN (AD read incomplete)'
        $run.Result.summary.adCapped | Should Be $true
    }

    It 'a COMPLETE AD enumeration DOES prove absence - the fix is not a blanket UNKNOWN' {
        Set-CovAdShim -Rows @((New-CovAd -Name 'WS-OTHER'))
        Set-CovRootOverride -Path (New-CovAuditTree -Name 'covAdOk' -Touches $script:LiveTouch) -Exists $true
        $run = Invoke-Coverage -Params @{ targets = 'WS-COVERED' }
        $r = Get-CovRow $run 'WS-COVERED'
        ([string]$r.AdStatus) | Should Be 'NOT IN AD'
        ([string]$r.Verdict)  | Should Be 'GHOST'          # JANET touched it; AD has no object
    }

    It 'a pasted host absent from AD and never touched is a DEAD OBJECT, not a ghost' {
        Set-CovAdShim -Rows @((New-CovAd -Name 'WS-OTHER'))
        Set-CovRootOverride -Path (New-CovAuditTree -Name 'covAdOk2' -Touches $script:LiveTouch) -Exists $true
        $run = Invoke-Coverage -Params @{ targets = 'WS-NEVER-SEEN' }
        ([string](Get-CovRow $run 'WS-NEVER-SEEN').Verdict) | Should Be 'DEAD OBJECT'
    }

    It 'warns when the AD enumeration is capped (a truncated read is not the whole fleet)' {
        Set-CovAdShim -Rows @((New-CovAd -Name 'WS-OTHER')) -Capped $true
        Set-CovRootOverride -Path (New-CovAuditTree -Name 'covCapWarn' -Touches @()) -Exists $true
        $run = Invoke-Coverage -Params @{}
        ((@($run.Events | Where-Object { $_.type -eq 'log' } | ForEach-Object { [string]$_.text }) -join ' ') -like '*capped at*') | Should Be $true
    }
}

# -----------------------------------------------------------------------------
Describe 'operator-cancel bridge and the live LDAP path' {

    It 'passes the __job cancel bridge through to the enumeration' {
        Set-CovAdShim -Rows @()
        Set-CovRootOverride -Path (New-CovAuditTree -Name 'covCancel' -Touches @()) -Exists $true
        $job = [hashtable]::Synchronized(@{ Cancel = $true })
        $null = Invoke-Coverage -Params @{ '__job' = $job; targets = 'WS-X' }
        (Get-CovAdCallCount) | Should Be 1
        (Get-CovAdCallAt 0).SawCancel | Should Be $true
    }

    It 'reports a cancelled enumeration as PARTIAL rather than as an empty fleet' {
        Set-CovAdShim -Rows @() -Cancelled $true
        Set-CovRootOverride -Path (New-CovAuditTree -Name 'covCancel2' -Touches @()) -Exists $true
        $run = Invoke-Coverage -Params @{ targets = 'WS-X' }
        $run.Result.summary.cancelled | Should Be $true
        ([string](Get-CovRow $run 'WS-X').Verdict) | Should Be 'UNKNOWN (AD read incomplete)'
    }

    It 'passes the operator SearchBase through to the enumeration unchanged' {
        Set-CovAdShim -Rows @()
        Set-CovRootOverride -Path (New-CovAuditTree -Name 'covBase' -Touches @()) -Exists $true
        $suffix = (& $script:Mod { Get-HistExpectedDomainSuffix })
        if ($suffix) {
            $base = "OU=Lab,$suffix"
            $null = Invoke-Coverage -Params @{ searchBase = $base; targets = 'WS-X' }
            ([string](Get-CovAdCallAt 0).SearchBase) | Should Be $base
        } else {
            # Not domain-joined: the guard correctly refuses EVERY base, which is
            # itself the documented fail-closed behaviour.
            $null = Invoke-Coverage -Params @{ searchBase = 'OU=Lab,DC=area52,DC=mil'; targets = 'WS-X' }
            (Get-CovAdCallCount) | Should Be 0
        }
    }

    It 'the REAL Read-HistAdComputers fails closed on an unreachable domain (no throw, Errors>0, no rows)' {
        Restore-CovShims
        $res = & $script:Mod { Read-HistAdComputers -SearchBase 'OU=X,DC=no-such-domain-for-tests,DC=invalid' }
        @($res.Rows).Count | Should Be 0
        ([int]$res.Errors -ge 1) | Should Be $true
        $res.Capped | Should Be $false
    }
}

# -----------------------------------------------------------------------------
Describe 'cleanup' {
    It 'restores the real Resolve-HistRoot and Read-HistAdComputers' {
        Restore-CovShims
        (& $script:Mod { (Get-Command Resolve-HistRoot).Definition -like '*HistShareRoot*' }) | Should Be $true
        (& $script:Mod { (Get-Command Read-HistAdComputers).Definition -like '*objectCategory=computer*' }) | Should Be $true
    }
    It 'declares coverage-reconcile in the manifest as a non-destructive action' {
        $a = @((Get-JanetToolManifest).actions | Where-Object { $_.id -eq 'coverage-reconcile' })
        $a.Count | Should Be 1
        $a[0].destructive | Should Be $false
    }
    It 'removes its temp tree' {
        Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue
        (Test-Path -LiteralPath $script:Tmp) | Should Be $false
    }
}
