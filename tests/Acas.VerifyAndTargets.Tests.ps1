# =============================================================================
#  Acas.VerifyAndTargets.Tests.ps1 - Pester 3.4 tests for two ACAS safety fixes:
#    FIX 1 (fail-open on remediation verify): a verify probe that THREW must map
#           to UNCONFIRMED (amber via AcasOkOf), NEVER Success - only a probe that
#           actually ran may yield a green result.
#    FIX 2 (CSV targets bypass the hostname whitelist): Test-AcasHostToken gates
#           every host token before it can become a remote target; a hostile token
#           (embedded space/switch/UNC) is rejected, not silently forwarded.
#    FIX 3 (ACAS reboot self-guard): Test-AcasHostIsSelf drops the dispatcher host.
#  Unit-scope: no host contact, no remote/destructive calls.
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.acas.psm1') -Force -PassThru

Describe 'ACAS verify classifier (FIX 1: thrown probe -> UNCONFIRMED, never Success)' {

    It 'a thrown-both-probes result string is NOT rendered Success by AcasOkOf' {
        # This is the exact shape the worker now returns when both verify probes threw
        # (host went unreachable mid-op). Formerly the both-throw path fell through to
        # the self-reported update string, which AcasOkOf renders GREEN.
        $r = & $script:Mod {
            $errStr = 'UNCONFIRMED: verify probe errored (pre+post) - remediation could not be confirmed (host may have gone unreachable mid-update) | OK (no output) <<PRE=n/a>><<POST=n/a>>'
            & $script:AcasOkOf $errStr
        }
        $r | Should Be $false
    }

    It 'a post-only thrown probe is UNCONFIRMED, not counted as a confirmed fix' {
        $r = & $script:Mod {
            $errStr = 'UNCONFIRMED: verify probe errored (post) - remediation could not be confirmed (host may have gone unreachable mid-update) | OK <<PRE=1.0>><<POST=n/a>>'
            & $script:AcasOkOf $errStr
        }
        $r | Should Be $false
    }

    It 'a REAL version bump still classifies as Success (green preserved)' {
        $r = & $script:Mod {
            & $script:AcasOkOf 'OK | bumped: 1.0 -> 2.0 <<PRE=1.0>><<POST=2.0>>'
        }
        $r | Should Be $true
    }
}

Describe 'ACAS target whitelist (FIX 2: hostile CSV/by-id token rejected before dispatch)' {

    It 'Test-AcasHostToken rejects hostile tokens (space / switch / UNC / pipe / semicolon)' {
        $r = & $script:Mod {
            [pscustomobject]@{
                Space   = (Test-AcasHostToken 'host name')
                Switch  = (Test-AcasHostToken 'host -Force')
                Unc     = (Test-AcasHostToken '\\evil\share')
                Pipe    = (Test-AcasHostToken 'host|calc')
                Semi    = (Test-AcasHostToken 'host;shutdown')
                Empty   = (Test-AcasHostToken '')
            }
        }
        $r.Space  | Should Be $false
        $r.Switch | Should Be $false
        $r.Unc    | Should Be $false
        $r.Pipe   | Should Be $false
        $r.Semi   | Should Be $false
        $r.Empty  | Should Be $false
    }

    It 'Test-AcasHostToken accepts a bare short hostname and an IPv4 literal' {
        $r = & $script:Mod {
            [pscustomobject]@{
                Host = (Test-AcasHostToken 'MSEKL-1234')
                Ip   = (Test-AcasHostToken '192.168.1.50')
            }
        }
        $r.Host | Should Be $true
        $r.Ip   | Should Be $true
    }

    It 'ConvertTo-AcasHostList drops a hostile (non-delimiter) token while keeping a valid one' {
        # '|' is not one of the blob delimiters [\r\n,;\t ], so 'host|calc' survives the
        # split as a single token and must be rejected by the whitelist gate.
        $out = & $script:Mod { @(ConvertTo-AcasHostList "good-host`nhost|calc") }
        @($out) -contains 'good-host' | Should Be $true
        @($out) -contains 'host|calc' | Should Be $false
        @($out).Count | Should Be 1
    }
}

Describe 'ACAS reboot self-guard (FIX 3: never reboot the dispatcher host)' {

    It 'Test-AcasHostIsSelf is true for this box (COMPUTERNAME) and false for a foreign host' {
        $r = & $script:Mod {
            [pscustomobject]@{
                Self    = (Test-AcasHostIsSelf $env:COMPUTERNAME)
                Foreign = (Test-AcasHostIsSelf 'NOT-THIS-BOX-9999')
                Empty   = (Test-AcasHostIsSelf '')
            }
        }
        $r.Self    | Should Be $true
        $r.Foreign | Should Be $false
        $r.Empty   | Should Be $false
    }
}
