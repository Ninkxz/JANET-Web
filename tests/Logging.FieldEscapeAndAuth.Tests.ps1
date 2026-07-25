# =============================================================================
#  Logging.FieldEscapeAndAuth.Tests.ps1 - Pester 3.4 tests for two low-severity
#  correctness fixes:
#
#    FIX (Logging) Write-JanetWebRun now routes RowType/Action through
#         ConvertTo-JanetWebMinField like every sibling field, so a comma (or
#         CR/LF) in a free-text RowType/Action can no longer desync the row's
#         column count.
#    FIX (Auth)    The blank-password detector in Prompt-JanetWebCredential
#         (JanetWeb.Auth.ps1) used "$probe.Password -ne $null", which is always
#         true for a System.String (blank is "", not $null) and made the
#         no-usable-password branch unreachable. It now uses
#         [string]::IsNullOrEmpty($probe.Password).
#
#  Both are driven against the REAL source: the CSV test dot-sources the actual
#  module and reads back a real file it wrote; the Auth test extracts the real
#  $usable assignment via the PS parser and runs it against synthetic $probe
#  objects (Prompt-JanetWebCredential itself pops a live Get-Credential dialog,
#  so it cannot be called directly in a unit test). No live host / share touched.
#
#  Extended for the audit 2026-07-24 pass (same driven-against-real-source rule):
#    Edipi/SourceHost escaping, the CR sigil in Protect-JanetWebCsvField, the
#    hosts-touched non-host filter, and replay idempotence. Each of those Describes
#    fails against the pre-fix source.
#
#  Run:  Invoke-Pester -Path .\tests\Logging.FieldEscapeAndAuth.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent

# -----------------------------------------------------------------------------
Describe 'FIX - Write-JanetWebRun escapes RowType/Action (JanetWeb.Logging.ps1)' {

    . (Join-Path $script:Root 'server\JanetWeb.Logging.ps1')

    $script:__tmpRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('jwlog_' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:__tmpRoot -Force | Out-Null

    function New-TestContext {
        $ctx = [pscustomobject]@{
            Lock       = (New-Object object)
            OnShare    = $false
            NetRoot    = 'C:\__janetweb_no_such_share__'
            JanetLocal = $script:__tmpRoot
            Operator   = 'Test Operator'
            Edipi      = '0000000000'
            SessionId  = 'sess-1'
            SourceHost = 'TESTHOST'
            Version    = '1.0.0'
            RunCount   = 0
            RunSuccess = 0
            RunFailed  = 0
        }
        return $ctx
    }

    It 'a comma in RowType/Action is escaped so the written row keeps the header''s column count' {
        $ctx = New-TestContext
        Write-JanetWebRun -Context $ctx -Tool 'fieldescapetest' -RowType 'Run,Extra' -Action 'Patch,Now' `
            -Scope 'S' -Profile 'P' -Mode 'M' -HostsTotal 5 -Success 5 -Failed 0 -DurationSec 10 -Notes 'n' -GroupKey 'g'

        $toolName = Resolve-JanetWebToolName -ToolId 'fieldescapetest'
        $fileName = 'ACAS-Nemesis-Runs_' + (Get-Date -Format 'yyyy-MM-dd') + '.csv'
        $localFile = Join-Path (Join-Path $script:__tmpRoot $toolName) $fileName

        Test-Path -LiteralPath $localFile | Should Be $true
        $lines = Get-Content -LiteralPath $localFile
        $header = $lines[0]
        $row    = $lines[1]

        $headerCols = ($header -split ',').Count
        $rowCols    = ($row -split ',').Count
        $rowCols | Should Be $headerCols

        # The comma was neutralized (semicolon), not dropped, and not left raw.
        $row | Should Match 'Run;Extra'
        $row | Should Match 'Patch;Now'
        $row | Should Not Match 'Run,Extra'
        $row | Should Not Match 'Patch,Now'
    }

    Remove-Item -LiteralPath $script:__tmpRoot -Recurse -Force -ErrorAction SilentlyContinue
}

# -----------------------------------------------------------------------------
Describe 'FIX - blank-password detection uses IsNullOrEmpty (JanetWeb.Auth.ps1)' {

    # Prompt-JanetWebCredential pops a live Get-Credential dialog, so extract the
    # real "$usable = ..." assignment via the PS parser and run it in isolation
    # against synthetic $probe objects, exactly as the fixed source expresses it.
    $authPath = Join-Path $script:Root 'server\JanetWeb.Auth.ps1'
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($authPath, [ref]$tokens, [ref]$errors)
    $assign = $ast.FindAll(
        { param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                    $n.Left.Extent.Text -eq '$usable' -and $n.Right.Extent.Text -match 'IsNullOrEmpty' },
        $true) | Select-Object -First 1
    $script:__usableCheck = [scriptblock]::Create("param(`$probe) $($assign.Extent.Text); `$usable")

    It 'source uses IsNullOrEmpty (not the dead "-ne `$null" check)' {
        $assign | Should Not BeNullOrEmpty
        $assign.Extent.Text | Should Match 'IsNullOrEmpty'
    }
    It 'a blank password ("") is detected as NOT usable' {
        $probe = [pscustomobject]@{ Password = '' }
        (& $script:__usableCheck $probe) | Should Be $false
    }
    It 'a real password IS usable (happy path unchanged)' {
        $probe = [pscustomobject]@{ Password = 'hunter2' }
        (& $script:__usableCheck $probe) | Should Be $true
    }
    It 'no probe object at all => NOT usable' {
        (& $script:__usableCheck $null) | Should Be $false
    }
}

# -----------------------------------------------------------------------------
Describe 'FIX - Resolve-JanetWebToolName rejects dot-only ids (JanetWeb.Logging.ps1)' {

    # A dot-only tool id ('.', '..') survived the char-strip and would resolve a log
    # path AT or ABOVE the log root. The fix falls those back to the frozen default.
    . (Join-Path $script:Root 'server\JanetWeb.Logging.ps1')

    It "'..' does not climb above the log root - falls back to the default" {
        Resolve-JanetWebToolName -ToolId '..' | Should Be 'JANET-WEB'
    }
    It "'.' (current dir) falls back to the default" {
        Resolve-JanetWebToolName -ToolId '.' | Should Be 'JANET-WEB'
    }
    It "a longer dot run ('...') falls back to the default" {
        Resolve-JanetWebToolName -ToolId '...' | Should Be 'JANET-WEB'
    }
    It 'an empty id still falls back to the default (unchanged)' {
        Resolve-JanetWebToolName -ToolId '' | Should Be 'JANET-WEB'
    }
    It 'a mapped id still resolves to its desktop folder (happy path unchanged)' {
        Resolve-JanetWebToolName -ToolId 'wpt' | Should Be 'WPT'
    }
    It 'an ordinary unmapped id still passes through sanitized (happy path unchanged)' {
        Resolve-JanetWebToolName -ToolId 'kev' | Should Be 'kev'
    }
    It 'a dots+separator traversal id is stripped to one safe segment, not resolved as a path' {
        # '../evil': the '/' becomes '_', so it can't climb, and it is not dot-only.
        Resolve-JanetWebToolName -ToolId '../evil' | Should Be '.._evil'
    }
}

# -----------------------------------------------------------------------------
Describe 'FIX (audit 2026-07-24) - Edipi/SourceHost go through the field escaper' {

    # These two rode onto the Runs + TouchedHosts rows RAW while every sibling field
    # on the same row was escaped. They are environment-derived, so a comma or a
    # CR/LF in either one desynced the column count or forged a whole extra audit
    # row in the trail of record. Drive the REAL writers and read the file back.
    . (Join-Path $script:Root 'server\JanetWeb.Logging.ps1')

    $script:__escRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('jwesc_' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:__escRoot -Force | Out-Null

    # A hostile identity: delimiter + newline + a complete forged audit row.
    $script:__evilEdipi = "1234567890,X`r`n2026-01-01 00:00:00,FORGEDOP,9999999999,sess-X,EVILHOST"
    $script:__evilHost  = "PC-01,Y`nFORGEDHOST"

    function New-EscapeContext {
        [pscustomobject]@{
            Lock          = (New-Object object)
            OnShare       = $false
            NetRoot       = 'C:\__janetweb_no_such_share__'
            JanetLocal    = $script:__escRoot
            Operator      = 'Test Operator'
            Edipi         = $script:__evilEdipi
            SessionId     = 'sess-1'
            SourceHost    = $script:__evilHost
            UserFolder    = 'tester - TESTHOST_tester'
            NemesisFolder = 'tester - Test Operator'
            Version       = '1.0.0'
            RunCount      = 0
            RunSuccess    = 0
            RunFailed     = 0
        }
    }

    It 'Runs CSV: a delimiter+newline in Edipi/SourceHost cannot forge a second row' {
        $ctx = New-EscapeContext
        Write-JanetWebRun -Context $ctx -Tool 'escaperuntest' -RowType 'Run' -Action 'Patch' `
            -Scope 'S' -Profile 'P' -Mode 'M' -HostsTotal 1 -Success 1 -Failed 0 -DurationSec 3 -Notes 'n'

        $file = Join-Path (Join-Path $script:__escRoot (Resolve-JanetWebToolName -ToolId 'escaperuntest')) `
                          ('ACAS-Nemesis-Runs_' + (Get-Date -Format 'yyyy-MM-dd') + '.csv')
        Test-Path -LiteralPath $file | Should Be $true
        $lines = @(Get-Content -LiteralPath $file)

        # header + EXACTLY one data row: the injected newline did not open a new row.
        $lines.Count | Should Be 2
        ($lines[1] -split ',').Count | Should Be (($lines[0] -split ',').Count)
        # the payload survives (neutralized), and no line starts with the forged row
        $lines[1] | Should Match '1234567890;X'
        @($lines | Where-Object { $_ -match '^2026-01-01 00:00:00,FORGEDOP' }).Count | Should Be 0
        @($lines | Where-Object { $_ -match '^FORGEDHOST' }).Count | Should Be 0
    }

    It 'TouchedHosts CSV: a delimiter+newline in Edipi/SourceHost cannot forge a second row' {
        $ctx = New-EscapeContext
        Write-JanetWebTouchedHost -Context $ctx -Tool 'esctouchtest' -Action 'TouchHost' -TargetHost 'HOSTA' -Result 'Success' -Detail 'd'

        $file = Join-Path (Join-Path (Join-Path $script:__escRoot (Resolve-JanetWebToolName -ToolId 'esctouchtest')) 'tester - TESTHOST_tester') `
                          ("TouchedHosts_$((Get-Date).ToString('yyyy-MM')).csv")
        Test-Path -LiteralPath $file | Should Be $true
        $lines = @(Get-Content -LiteralPath $file)

        $lines.Count | Should Be 2
        ($lines[1] -split ',').Count | Should Be (($lines[0] -split ',').Count)
        $lines[1] | Should Match 'PC-01;Y'
        @($lines | Where-Object { $_ -match '^2026-01-01 00:00:00,FORGEDOP' }).Count | Should Be 0
        @($lines | Where-Object { $_ -match '^FORGEDHOST' }).Count | Should Be 0
    }

    Remove-Item -LiteralPath $script:__escRoot -Recurse -Force -ErrorAction SilentlyContinue
}

# -----------------------------------------------------------------------------
Describe 'FIX (audit 2026-07-24) - Protect-JanetWebCsvField carries the CR sigil' {

    . (Join-Path $script:Root 'server\JanetWeb.Logging.ps1')

    It 'a leading CR is guarded, like the three sibling escapers do' {
        (Protect-JanetWebCsvField "`r=cmd|'/c calc'!A0") | Should Be ("'" + "`r=cmd|'/c calc'!A0")
    }
    It 'the four original sigils still guard (behaviour unchanged)' {
        (Protect-JanetWebCsvField '=1+1')  | Should Be "'=1+1"
        (Protect-JanetWebCsvField '+1')    | Should Be "'+1"
        (Protect-JanetWebCsvField '-1')    | Should Be "'-1"
        (Protect-JanetWebCsvField '@SUM')  | Should Be "'@SUM"
        (Protect-JanetWebCsvField "`tx")   | Should Be "'`tx"
    }
    It 'ordinary text is untouched' {
        (Protect-JanetWebCsvField 'PC-01') | Should Be 'PC-01'
    }
}

# -----------------------------------------------------------------------------
Describe 'FIX (audit 2026-07-24) - hosts-touched counts machines only' {

    # The AGGREGATE Context.Hosts set had no filter at all, so report labels, file
    # paths and the engine's sentinel targets inflated the headline number. Both the
    # aggregate and the per-tool tally now share Test-JanetWebHostTarget.
    . (Join-Path $script:Root 'server\JanetWeb.Logging.ps1')

    $script:__cntRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('jwcnt_' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:__cntRoot -Force | Out-Null

    function New-HostCountContext {
        [pscustomobject]@{
            Lock          = (New-Object object)
            OnShare       = $false
            NetRoot       = 'C:\__janetweb_no_such_share__'
            JanetLocal    = $script:__cntRoot
            Operator      = 'Test Operator'
            Edipi         = '0000000000'
            Asi           = ''
            SessionId     = 'cnt-1'
            SourceHost    = 'TESTHOST'
            UserFolder    = 'tester - TESTHOST_tester'
            NemesisFolder = 'tester - Test Operator'
            Version       = '1.0.0'
            Hosts         = (New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase))
            Vulns         = 0
            Failures      = 0
            PerTool       = ([hashtable]::Synchronized(@{}))
            UsageDirty    = $false
        }
    }

    It 'report labels, file paths and sentinel targets do not count as hosts' {
        $ctx = New-HostCountContext
        # real machines
        Write-JanetAction -Context $ctx -Tool 'wpt'     -Action 'TouchHost' -Target 'PC-01'                    -Result 'Success'
        Write-JanetAction -Context $ctx -Tool 'wpt'     -Action 'TouchHost' -Target 'pc-02.area52.ds.af.mil'   -Result 'Success'
        # NOT machines (reports emits every one of these shapes)
        Write-JanetAction -Context $ctx -Tool 'reports' -Action 'TouchHost' -Target 'Dirty30 (12 hosts)'       -Result 'Success'
        Write-JanetAction -Context $ctx -Tool 'reports' -Action 'TouchHost' -Target 'C:\out\Dirty30.html'      -Result 'Success'
        Write-JanetAction -Context $ctx -Tool 'reports' -Action 'TouchHost' -Target 'AcasWeekly_2026-07.csv'   -Result 'Success'
        Write-JanetAction -Context $ctx -Tool 'reports' -Action 'TouchHost' -Target '\\dm-tn-01\sh$\scan.xlsx' -Result 'Failure'
        Write-JanetAction -Context $ctx -Tool 'wpt'     -Action 'TouchHost' -Target 'N/A'                      -Result 'Failure'
        Write-JanetAction -Context $ctx -Tool 'wpt'     -Action 'TouchHost' -Target '(custom command)'         -Result 'Skipped'

        $ctx.Hosts.Count | Should Be 2                          # aggregate: PC-01 + the FQDN
        $ctx.PerTool['Reports'].Hosts.Count | Should Be 0        # per-tool agrees
        $ctx.PerTool['WPT'].Hosts.Count     | Should Be 2
        $ctx.Failures | Should Be 2                              # failure tally is NOT host-filtered (the 2 Failure rows above)
    }

    It 'real host shapes still count (no over-filtering)' {
        Test-JanetWebHostTarget -Target 'PC-01'                  | Should Be $true
        Test-JanetWebHostTarget -Target 'pc-02.area52.ds.af.mil' | Should Be $true
        Test-JanetWebHostTarget -Target '10.1.2.3'               | Should Be $true
        Test-JanetWebHostTarget -Target 'PC-03\Java 8'           | Should Be $false   # label (space) - upr sends 'PC-03\Java8'
        Test-JanetWebHostTarget -Target 'PC-03\Java8'            | Should Be $true    # upr 'host\product' is host-bearing
    }
    It 'non-host shapes are rejected (labels, paths, URLs, sentinels)' {
        Test-JanetWebHostTarget -Target ''                       | Should Be $false
        Test-JanetWebHostTarget -Target '   '                    | Should Be $false
        Test-JanetWebHostTarget -Target 'N/A'                    | Should Be $false
        Test-JanetWebHostTarget -Target '(custom command)'       | Should Be $false
        Test-JanetWebHostTarget -Target '(start)'                | Should Be $false
        Test-JanetWebHostTarget -Target 'Dirty30 (12 hosts)'     | Should Be $false
        Test-JanetWebHostTarget -Target 'C:\out\Dirty30.html'    | Should Be $false
        Test-JanetWebHostTarget -Target 'AcasWeekly_2026-07.csv' | Should Be $false
        Test-JanetWebHostTarget -Target '\\dm-tn-01\sh$\x.xlsx'  | Should Be $false
        Test-JanetWebHostTarget -Target 'https://kev/list'       | Should Be $false
    }

    Remove-Item -LiteralPath $script:__cntRoot -Recurse -Force -ErrorAction SilentlyContinue
}

# -----------------------------------------------------------------------------
Describe 'FIX (audit 2026-07-24) - spool replay is idempotent' {

    # The rename to <name>.replayed_<stamp> was the ONLY "already replayed" marker
    # and its failure was swallowed, so a rename the OS refused (peer handle, AV,
    # ACL) re-uploaded the WHOLE spool file at the next launch - duplicate rows in
    # the audit trail of record. Both roots are local temp dirs (no share touched).
    . (Join-Path $script:Root 'server\JanetWeb.Logging.ps1')

    $script:__repRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('jwrep_' + [guid]::NewGuid().ToString('N'))
    $script:__repNet   = Join-Path $script:__repRoot 'share'
    $script:__repLocal = Join-Path $script:__repRoot 'JanetLocal'
    $script:__repDir   = Join-Path (Join-Path $script:__repLocal 'WPT') 'tester - PC_tester'
    New-Item -ItemType Directory -Path $script:__repNet, $script:__repDir -Force | Out-Null
    $script:__repHdr = 'Timestamp,SessionId,Operator,ASI,Tool,ToolVersion,Action,Target,Result,ItemCount,Detail'
    $script:__repCtx = [pscustomobject]@{ JanetLocal = $script:__repLocal; NetRoot = $script:__repNet; Lock = (New-Object object); OnShare = $true }

    function Get-ReplayedRowCount {
        param([string]$Name)
        $d = Join-Path (Join-Path (Join-Path $script:__repNet 'WPT') 'tester - PC_tester') $Name
        if (-not (Test-Path -LiteralPath $d)) { return 0 }
        return (@(Get-Content -LiteralPath $d).Count - 1)   # minus the header
    }

    It 'replays a spooled file once, and the second pass is a no-op' {
        $f = Join-Path $script:__repDir '2026-07_detail.csv'
        Set-Content -LiteralPath $f -Encoding UTF8 -Value @($script:__repHdr,
            't,s,o,,WPT,1,TouchHost,PC-01,Success,1,d', 't,s,o,,WPT,1,TouchHost,PC-02,Success,1,d')
        Invoke-JanetWebReplay -Context $script:__repCtx
        Get-ReplayedRowCount '2026-07_detail.csv' | Should Be 2
        Invoke-JanetWebReplay -Context $script:__repCtx
        Get-ReplayedRowCount '2026-07_detail.csv' | Should Be 2
    }

    It 'a rename the OS refuses leaves a receipt instead of duplicating the rows' {
        $f = Join-Path $script:__repDir '2026-06_detail.csv'
        Set-Content -LiteralPath $f -Encoding UTF8 -Value @($script:__repHdr, 't,s,o,,WPT,1,TouchHost,PC-09,Success,1,d')
        # Hold the spool file open: readable (so the replay itself still works) but
        # NOT renamable - exactly the case whose swallowed failure caused the double.
        $fs = [System.IO.File]::Open($f, 'Open', 'Read', 'Read')
        try {
            Invoke-JanetWebReplay -Context $script:__repCtx -WarningAction SilentlyContinue
            Get-ReplayedRowCount '2026-06_detail.csv' | Should Be 1
            Test-Path -LiteralPath ($f + '.replayed') | Should Be $true
            # the pass that used to double the rows
            Invoke-JanetWebReplay -Context $script:__repCtx -WarningAction SilentlyContinue
            Get-ReplayedRowCount '2026-06_detail.csv' | Should Be 1
        } finally { $fs.Close() }
        # still suppressed once the handle is gone (the receipt is the durable marker)
        Invoke-JanetWebReplay -Context $script:__repCtx -WarningAction SilentlyContinue
        Get-ReplayedRowCount '2026-06_detail.csv' | Should Be 1
    }

    Remove-Item -LiteralPath $script:__repRoot -Recurse -Force -ErrorAction SilentlyContinue
}
