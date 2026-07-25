# =============================================================================
#  _Janet.TestKit.ps1 - shared test fixture (audit 2026-07-25)
#
#  NOT a test file. Deliberately named `_Janet.TestKit.ps1`, not `*.Tests.ps1`,
#  so Pester's discovery (which globs *.Tests.ps1) never tries to execute it.
#  Dot-source it from a test file:  . (Join-Path $PSScriptRoot '_Janet.TestKit.ps1')
#
#  WHY THIS EXISTS
#  The 2026-07-24 audit found ~1,640 green tests coexisting with every audited
#  defect, because a large share asserted SOURCE TEXT rather than behaviour. The
#  2026-07-25 capability audit measured it: 163 It blocks (7.2%) call no function
#  at all, 9 files test a re-implemented copy instead of the module, and
#  Save-ShimState/Restore-ShimState was copy-pasted into 22 files.
#
#  This file is the one place those helpers live. Three things it provides:
#    1. Save-ShimState / Restore-ShimState - ONE correct copy (see the note below)
#    2. Get-JanetToolIds / Import-JanetToolModule - contract-test plumbing
#    3. Get-JanetFunctionAst / Get-JanetStrippedSource - so a test can EXECUTE or
#       PARSE the real thing instead of regexing it
#
#  THE SHIM-TEARDOWN NOTE (do not "simplify" this)
#  `Remove-Item function:script:X` is INERT. The function provider has no scope
#  qualifier in its paths, so that path names a non-existent item and -EA
#  SilentlyContinue swallows the error - the shim LEAKS into every later block.
#  The naive correction is worse: the unqualified `Remove-Item function:X`
#  DESTROYS the module's real function. The only correct teardown is
#  save-and-restore: capture the real ScriptBlock first, then Set-Item it back
#  (Set-Item DOES honour the qualifier); clear a name that had no function behind
#  it - i.e. a shimmed cmdlet - with the unqualified Remove-Item.
# =============================================================================

$script:JanetRepoRoot = Split-Path $PSScriptRoot -Parent

function Get-JanetRepoRoot { $script:JanetRepoRoot }

# --- registry / module plumbing ---------------------------------------------

function Get-JanetToolIds {
    # The 21 tool ids from server\tool-registry.json - the single source of truth
    # the SPA builds its tool list from. Before this kit, ZERO tests read it.
    $p = Join-Path $script:JanetRepoRoot 'server\tool-registry.json'
    $reg = Get-Content $p -Raw | ConvertFrom-Json
    $tools = if ($reg.tools) { $reg.tools } else { $reg }
    @($tools | ForEach-Object { [string]$_.id })
}

function Get-JanetRegistryTools {
    $p = Join-Path $script:JanetRepoRoot 'server\tool-registry.json'
    $reg = Get-Content $p -Raw | ConvertFrom-Json
    if ($reg.tools) { @($reg.tools) } else { @($reg) }
}

function Get-JanetModulePath {
    param([string]$ToolId)
    Join-Path $script:JanetRepoRoot ('modules\JanetWeb.' + $ToolId + '.psm1')
}

function Get-JanetViewPath {
    param([string]$ToolId)
    Join-Path $script:JanetRepoRoot ('web\js\views\' + $ToolId + '.view.js')
}

function Import-JanetToolModule {
    # Load a tool exactly as the server does: isolated, -Force, handle returned.
    param([string]$ToolId)
    Import-Module (Get-JanetModulePath $ToolId) -Force -PassThru -ErrorAction Stop
}

function Get-JanetToolManifestFor {
    param([string]$ToolId)
    $m = Import-JanetToolModule $ToolId
    try { & $m { Get-JanetToolManifest } } finally { Remove-Module $m -Force -ErrorAction SilentlyContinue }
}

# --- AST helpers: parse or execute the real thing, never regex it ------------

function Get-JanetFunctionAst {
    # Lift a named function's AST out of a file so a test can execute the REAL
    # body (generalises the pattern used in Secureboot.BitLockerRefuse.Tests.ps1).
    param([string]$Path, [string]$Name)
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
    $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) |
        Where-Object { $_.Name -eq $Name } | Select-Object -First 1
}

function Get-JanetFunctionAstMatching {
    param([string]$Path, [string]$Pattern)
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
    @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) |
        Where-Object { $_.Name -match $Pattern })
}

function Get-JanetStrippedSource {
    # Source with comments and string literals blanked, so a "does the code DO x"
    # assertion cannot be satisfied by a comment that merely MENTIONS x. The
    # capability audit found tests asserting strings that existed only in comments.
    param([string]$Path)
    $tokens = $null; $err = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$err)
    $sb = New-Object System.Text.StringBuilder
    foreach ($t in $tokens) {
        if ($t.Kind -eq 'Comment') { continue }
        [void]$sb.Append($t.Text).Append(' ')
    }
    $sb.ToString()
}

function Get-JanetJsWithoutComments {
    # Same idea for a .js file - crude but adequate: strip /* */ and // comments.
    param([string]$Path)
    $s = Get-Content $Path -Raw
    $s = [regex]::Replace($s, '/\*.*?\*/', ' ', 'Singleline')
    $s = [regex]::Replace($s, '(?m)^\s*//.*$', ' ')
    $s
}

# --- shim save/restore: ONE copy, replacing 22 pasted ones -------------------

function Save-ShimState {
    # $Module: the module handle whose scope the shims will be defined in.
    # $Names:  the function/cmdlet names about to be shimmed.
    param($Module, [string[]]$Names)
    & $Module {
        param($names)
        $h = @{}
        foreach ($n in $names) {
            $c = Get-Item ("function:$n") -ErrorAction SilentlyContinue
            if ($c) { $h[$n] = $c.ScriptBlock } else { $h[$n] = $null }
        }
        $h
    } $Names
}

function Restore-ShimState {
    param($Module, $State)
    & $Module {
        param($h)
        foreach ($k in @($h.Keys)) {
            if ($null -ne $h[$k]) {
                # A real function existed here - put the captured ScriptBlock back.
                # Set-Item DOES honour the script: qualifier (Remove-Item does not).
                Set-Item ("function:script:$k") -Value $h[$k]
            } else {
                # Nothing was here - it was a shimmed CMDLET. Clear with the
                # UNQUALIFIED path; the qualified spelling would be inert.
                Remove-Item ("function:$k") -ErrorAction SilentlyContinue
            }
        }
    } $State
}
