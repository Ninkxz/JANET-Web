# =============================================================================
#  Platform.GuardParity.Tests.ps1 - Pester 3.4  (audit 2026-07-25)
#
#  THE STRUCTURAL FIX FOR THE `return ,$set` DEFECT CLASS.
#
#  The self-guard getter (the thing that stops a fleet tool acting on the box
#  running it) is DUPLICATED into 13 modules BY DESIGN - guard helpers are
#  injected as source into pool runspaces, which have no module scope, so each
#  tool must carry its own copy. Duplication is intended. DIVERGENCE is the
#  defect, and on 2026-07-24 seven of those copies had silently diverged:
#
#      return $set      # unrolls the HashSet -> Object[] -> comparer LOST
#      return ,$set     # correct: the comma stops PowerShell unrolling it
#
#  Losing the comparer makes .Contains() case-SENSITIVE, so a lowercase hostname
#  slipped past every "never touch this box" check. The suite was fully green
#  throughout, because the tests asserted text, not behaviour.
#
#  WHY SEMANTIC INVARIANTS, NOT A BYTE HASH
#  A byte/AST-hash comparison of the 13 bodies fails TODAY on cosmetics: two
#  modules wrap the DNS lookup in an extra try/catch and three differ by a
#  trailing semicolon. None of that is a security difference. A test that goes
#  red on a semicolon gets ignored, and an ignored test is worse than no test.
#  So this asserts the properties that MATTER and would each have caught a real
#  regression - including the exact one that shipped.
#
#  Run:  Invoke-Pester -Path .\tests\Platform.GuardParity.Tests.ps1
# =============================================================================
. (Join-Path $PSScriptRoot '_Janet.TestKit.ps1')

$script:Guards = @()
foreach ($f in Get-ChildItem (Join-Path (Get-JanetRepoRoot) 'modules') -Filter 'JanetWeb.*.psm1') {
    foreach ($fn in (Get-JanetFunctionAstMatching -Path $f.FullName -Pattern 'LocalIdentity$')) {
        $body = $fn.Body.Extent.Text
        # comment-stripped view, so a comment mentioning a construct cannot satisfy an assertion
        $bare = ($body -replace '(?m)#.*$', '')
        $script:Guards += [pscustomobject]@{
            Module = $f.BaseName
            Fn     = $fn.Name
            Body   = $body
            Bare   = $bare
        }
    }
}

Describe 'Guard parity - the self-guard getters are all present' {

    It 'found a Get-*LocalIdentity in every module that has one (13 today)' {
        @($script:Guards).Count -ge 13 | Should Be $true
    }
    It 'no module declares two of them' {
        $d = @($script:Guards | Group-Object Module | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name })
        ($d -join ',') | Should Be ''
    }
}

Describe 'Guard parity - the invariants that make the guard actually work' {

    It 'EVERY copy returns with the unary comma (the 2026-07-24 defect)' {
        # This is the assertion that would have caught the original bug in all
        # seven diverged modules on the day it shipped.
        $bad = @($script:Guards | Where-Object { $_.Bare -notmatch 'return\s*,\s*\$' } | ForEach-Object { $_.Module })
        ($bad -join ',') | Should Be ''
    }
    It 'EVERY copy returns the comma form on BOTH the cached path and the tail' {
        # The cached early-return is the sneaky one: a module can look correct at
        # the tail and still unroll on the second call, which is the path a real
        # fleet run takes for every host after the first.
        $bad = @($script:Guards | Where-Object {
            @([regex]::Matches($_.Bare, 'return\s*,\s*\$')).Count -lt 2
        } | ForEach-Object { $_.Module })
        ($bad -join ',') | Should Be ''
    }
    It 'NO copy has a bare `return $set` left anywhere in it' {
        $bad = @($script:Guards | Where-Object { $_.Bare -match 'return\s+\$(set|hs)\b' } | ForEach-Object { $_.Module })
        ($bad -join ',') | Should Be ''
    }
    It 'EVERY copy builds a HashSet with the OrdinalIgnoreCase comparer' {
        $bad = @($script:Guards | Where-Object {
            $_.Bare -notmatch 'HashSet\[string\]' -or $_.Bare -notmatch 'OrdinalIgnoreCase'
        } | ForEach-Object { $_.Module })
        ($bad -join ',') | Should Be ''
    }
    It 'EVERY copy seeds COMPUTERNAME, localhost, 127.0.0.1 and ::1' {
        $bad = @()
        foreach ($g in $script:Guards) {
            foreach ($tok in @('\$env:COMPUTERNAME', "'localhost'", "'127\.0\.0\.1'", "'::1'")) {
                if ($g.Bare -notmatch $tok) { $bad += ($g.Module + ':' + $tok) }
            }
        }
        ($bad -join ',') | Should Be ''
    }
    It 'EVERY copy adds the resolved DNS hostname (the FQDN alias case)' {
        $bad = @($script:Guards | Where-Object { $_.Bare -notmatch 'GetHostEntry' } | ForEach-Object { $_.Module })
        ($bad -join ',') | Should Be ''
    }
    It 'EVERY copy caches into a script-scoped variable' {
        $bad = @($script:Guards | Where-Object { $_.Bare -notmatch '\$script:\w*LocalIdentity\s*=' } | ForEach-Object { $_.Module })
        ($bad -join ',') | Should Be ''
    }
}

Describe 'Guard parity - the getters behave identically at runtime' {

    # The behavioural half. Text invariants above prove the SHAPE; this proves the
    # BEHAVIOUR, on the cached path as well as the first call, for every module
    # that exposes one. This is what SelfGuard.CaseInsensitive.Tests.ps1 does per
    # tool - here it is driven off the registry so a NEW tool cannot be forgotten.
    $script:GuardCases = @()
    foreach ($id in (Get-JanetToolIds)) {
        $mp = Get-JanetModulePath $id
        if (-not (Test-Path $mp)) { continue }
        $fns = Get-JanetFunctionAstMatching -Path $mp -Pattern 'LocalIdentity$'
        if (@($fns).Count -eq 1) {
            $script:GuardCases += [pscustomobject]@{ Tool = $id; Fn = $fns[0].Name }
        }
    }

    It 'every registry tool that has a guard getter returns a case-insensitive set (twice)' {
        $bad = @()
        foreach ($c in $script:GuardCases) {
            $m = $null
            try {
                $m = Import-JanetToolModule $c.Tool
                $fn = $c.Fn
                # Call TWICE - the second call takes the cached early-return path.
                # NOTE the unary comma: crossing the `& $m { }` boundary puts the
                # result on the pipeline, which unrolls a HashSet to Object[] and
                # loses the comparer - the SAME defect this file exists to catch.
                # Written without it first, this harness reported all 13 modules
                # broken while every one of them was fine. Do not remove the comma.
                $r1 = & $m { param($n) ,(& $n) } $fn
                $r2 = & $m { param($n) ,(& $n) } $fn
                foreach ($r in @($r1, $r2)) {
                    if ($null -eq $r) { $bad += ($c.Tool + ':null'); continue }
                    if (-not ($r -is [System.Collections.Generic.HashSet[string]])) {
                        $bad += ($c.Tool + ':' + $r.GetType().Name)
                        continue
                    }
                    $host1 = $env:COMPUTERNAME
                    if (-not $r.Contains($host1.ToLower())) { $bad += ($c.Tool + ':lower') }
                    if (-not $r.Contains($host1.ToUpper())) { $bad += ($c.Tool + ':upper') }
                }
            } catch {
                $bad += ($c.Tool + ':threw:' + $_.Exception.Message)
            } finally {
                if ($m) { Remove-Module $m -Force -ErrorAction SilentlyContinue }
            }
        }
        ($bad -join ',') | Should Be ''
    }
}
