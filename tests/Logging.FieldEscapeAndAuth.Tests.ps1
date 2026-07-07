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
            NetRoot    = 'X:\__no_such_share__'
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
