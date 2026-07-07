# =============================================================================
#  Upr.UninstallStringParse.Tests.ps1 - Pester 3.4 test for the P2-5 injection/LPE
#  fix in JanetWeb.upr.psm1. The real uninstall runs inside a remote WinRM
#  scriptblock, so (matching the house style of Upr.Adobe.Tests.ps1) this test
#  mirrors Get-SafeUninstallPlan VERBATIM and proves it:
#    (a) rebuilds a clean MsiExec /x{GUID} invocation from a real-form string,
#    (b) splits an EXE uninstaller into executable + a discrete argument array,
#    (c) NEVER emits a `cmd /c` shell string for a malicious
#        '...uninst.exe" & evil.cmd' input - it rejects or safely decomposes,
#        so shell metacharacters are inert literals, not commands.
#  Pure logic: no registry, no msiexec, no host contact.
# =============================================================================

# --- Mirror of Get-SafeUninstallPlan in JanetWeb.upr.psm1 (keep in sync) ---
function Get-SafeUninstallPlan {
    param([string]$UnStr)
    if ([string]::IsNullOrWhiteSpace($UnStr)) {
        return [pscustomobject]@{ Kind = 'Reject'; Exe = $null; Args = @(); Guid = $null; Reason = 'empty uninstall string' }
    }
    $s = $UnStr.Trim()
    if ($s -match '(?i)msiexec(\.exe)?\b' -and $s -match '(\{[0-9A-Fa-f\-]{8,}\})') {
        $guid = $Matches[1]
        return [pscustomobject]@{ Kind = 'Msi'; Exe = 'msiexec.exe'; Args = @('/x', $guid, '/qn', '/norestart'); Guid = $guid; Reason = $null }
    }
    $exe = $null; $rest = ''
    if ($s -match '^\s*"([^"]+)"\s*(.*)$') {
        $exe = $Matches[1]; $rest = $Matches[2]
    } elseif ($s -match '^\s*(\S+\.(?:exe|com))\s*(.*)$') {
        $exe = $Matches[1]; $rest = $Matches[2]
    } else {
        return [pscustomobject]@{ Kind = 'Reject'; Exe = $null; Args = @(); Guid = $null; Reason = "unparseable uninstall string (no quoted or .exe-terminated executable)" }
    }
    $argList = @()
    if (-not [string]::IsNullOrWhiteSpace($rest)) {
        foreach ($tok in [regex]::Matches($rest, '"([^"]*)"|(\S+)')) {
            if ($tok.Groups[1].Success) { $argList += $tok.Groups[1].Value } else { $argList += $tok.Groups[2].Value }
        }
    }
    return [pscustomobject]@{ Kind = 'Exe'; Exe = $exe; Args = $argList; Guid = $null; Reason = $null }
}

Describe 'UPR safe uninstall-string decomposition (P2-5 injection/LPE fix)' {

    Context '(a) MSI product: rebuild strictly from the ProductCode GUID' {
        $guid = '{AC76BA86-1033-1033-7760-BC15014EA700}'
        $plan = Get-SafeUninstallPlan "MsiExec.exe /X$guid"

        It 'is classified as an MSI removal' {
            $plan.Kind | Should Be 'Msi'
        }
        It 'extracts the clean ProductCode GUID' {
            $plan.Guid | Should Be $guid
        }
        It 'invokes msiexec with the GUID as a discrete /x argument' {
            $plan.Exe        | Should Be 'msiexec.exe'
            $plan.Args[0]    | Should Be '/x'
            $plan.Args[1]    | Should Be $guid
            ($plan.Args -contains '/qn') | Should Be $true
        }
        It 'also handles a QuietUninstallString MsiExec form' {
            $p2 = Get-SafeUninstallPlan "MsiExec.exe /X$guid /qn"
            $p2.Kind | Should Be 'Msi'
            $p2.Guid | Should Be $guid
        }
    }

    Context '(b) EXE uninstaller: split into executable + argument array' {
        $plan = Get-SafeUninstallPlan '"C:\Program Files\Vendor\uninstall.exe" /S /norestart'

        It 'is classified as an EXE removal' {
            $plan.Kind | Should Be 'Exe'
        }
        It 'resolves the quoted executable path exactly (spaces intact)' {
            $plan.Exe | Should Be 'C:\Program Files\Vendor\uninstall.exe'
        }
        It 'returns the switches as a discrete argument array, not a shell line' {
            @($plan.Args).Count | Should Be 2
            $plan.Args[0] | Should Be '/S'
            $plan.Args[1] | Should Be '/norestart'
        }
        It 'never produces a cmd /c token for a benign EXE string' {
            $plan.Exe | Should Not Match '(?i)cmd(\.exe)?$'
            ($plan.Args -join ' ') | Should Not Match '/c'
        }
    }

    Context '(c) malicious UninstallString must NOT reach a shell' {
        # Attacker plants: quoted uninstaller then a cmd chaining operator.
        $evil = '"C:\Windows\Temp\uninst.exe" & C:\Users\Public\evil.cmd'
        $plan = Get-SafeUninstallPlan $evil

        It 'does not launch cmd.exe' {
            $plan.Exe | Should Not Match '(?i)cmd(\.exe)?$'
        }
        It 'never emits a `/c "<raw string>"` shell command line' {
            # No plan field carries the interpolated cmd form the old code built.
            $plan.Exe | Should Be 'C:\Windows\Temp\uninst.exe'
            ($plan.Args -join ' ') | Should Not Match '/c\b'
        }
        It 'isolates the & chaining operator as an inert literal argument token' {
            # Passed via Start-Process -ArgumentList (no shell) => never executed.
            ($plan.Args -contains '&') | Should Be $true
            ($plan.Args -contains 'C:\Users\Public\evil.cmd') | Should Be $true
        }
        It 'rejects (not cmd /c) an unquoted, unparseable string with a metacharacter' {
            $p2 = Get-SafeUninstallPlan 'C:\Program Files\app\uninst & C:\pub\evil.cmd'
            $p2.Kind | Should Be 'Reject'
            $p2.Exe  | Should Be $null
        }
        It 'rejects an empty uninstall string rather than shelling nothing' {
            (Get-SafeUninstallPlan '').Kind | Should Be 'Reject'
        }
    }
}
