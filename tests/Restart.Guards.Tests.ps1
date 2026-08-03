# =============================================================================
#  Restart.Guards.Tests.ps1 - Pester 3.4 tests for restart-engine guards:
#  IP-target DNS-guard skip (audit#9) and dispatcher self-exclusion (audit#10).
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.restart.psm1') -Force -PassThru

Describe 'IP-target DNS-mismatch guard skip (audit#9)' {
    # The dispatch code computes the expected COMPUTERNAME passed into the remote
    # guard: '' for an IP literal (skip the compare), shortname otherwise.
    function Get-ExpectedName { param([string]$h) if ($h -match '^\d{1,3}(\.\d{1,3}){3}$') { '' } else { ($h -split '\.')[0] } }

    It 'passes empty expected-name for an IPv4 literal (guard is skipped)' {
        (Get-ExpectedName '192.168.1.50') | Should Be ''
    }
    It 'passes the shortname for an FQDN target' {
        (Get-ExpectedName 'WS01.area.af.mil') | Should Be 'WS01'
    }
    It 'passes the shortname for a bare hostname' {
        (Get-ExpectedName 'WS01') | Should Be 'WS01'
    }
}

Describe 'Dispatcher self-exclusion (audit#10)' {
    It 'flags this host by COMPUTERNAME' {
        (& $script:Mod { param($n) Test-JanetHostIsSelf $n } $env:COMPUTERNAME) | Should Be $true
    }
    It 'flags localhost and any 127.x loopback' {
        (& $script:Mod { Test-JanetHostIsSelf 'localhost' }) | Should Be $true
        (& $script:Mod { Test-JanetHostIsSelf '127.0.0.5' }) | Should Be $true
    }
    It 'does not flag an unrelated hostname' {
        (& $script:Mod { Test-JanetHostIsSelf 'WS-NOT-ME-12345' }) | Should Be $false
    }
    It 'does not flag an empty token' {
        (& $script:Mod { Test-JanetHostIsSelf '' }) | Should Be $false
    }
}

# loop79 (informative-failures follow-up): Get-RrsShutdownErrorHint now DELEGATES its raw-detail text
# signatures to the shared Get-JanetTroubleshootHint (the six duplicated branches are gone; the shared
# engine is a strict superset). It still owns the numeric shutdown.exe return codes for the tool-specific
# and no-usable-detail cases.
Describe 'restart shutdown-error hint delegates detail text to the shared engine (loop79)' {
    function Rrs { param([int]$c,[string]$d='') (& $script:Mod { param($cc,$dd) Get-RrsShutdownErrorHint -Code $cc -Detail $dd } $c $d) }

    It 'a detail-string failure returns the shared engine hint (not the old duplicated wording)' {
        (Rrs 0 'Access is denied. (0x80070005)')  | Should Match 'not a local administrator|not authorized'
        (Rrs 0 'Connecting failed: 0x80090351')   | Should Match 'TrustedHosts|realm|CAC'
        # a signature the OLD restart mapper never had, now reachable via delegation:
        (Rrs 0 'A required privilege is not held by the client') | Should Match 'Privilege not held|user right'
    }
    It 'the numeric switch still owns the tool-specific / no-detail return codes' {
        (Rrs 1190 '') | Should Match 'ALREADY SCHEDULED'
        (Rrs 1115 '') | Should Match 'SHUTDOWN_IN_PROGRESS'
        (Rrs 1314 '') | Should Match 'PRIVILEGE_NOT_HELD'
        (Rrs 9999 '') | Should Match 'Unknown shutdown.exe return code 9999'
    }
    It 'rc -1 (synthetic tool-side timeout) keeps its PRECISE numeric hint, not the shared generic timeout (loop80)' {
        # regression: delegate-then-fallback let the shared "timeout" signature shadow the -1 hint.
        (Rrs -1 'shutdown.exe timed out after 30s') | Should Match 'Tool-side timeout'
        (Rrs -1 'shutdown.exe timed out after 30s') | Should Not Match 'raise the per-host timeout'
    }
    It 'a genuine remote error on -3 / -4 STILL delegates to the shared engine (richer hint preserved)' {
        (Rrs -3 'remote: Access is denied') | Should Match 'not a local administrator|not authorized'
    }

    $src = Get-Content (Join-Path $script:Root 'modules\JanetWeb.restart.psm1') -Raw
    It 'restart imports the shared troubleshoot engine and delegates in the mapper' {
        ($src -match 'Import-Module.*JanetWeb\.troubleshoot\.psm1')                 | Should Be $true
        ($src -match '\$h\s*=\s*Get-JanetTroubleshootHint\s+-Message\s+\$Detail')   | Should Be $true
    }
    It 'the six duplicated detail-string branches are gone from the mapper' {
        ($src -match "return 'WinRM auth: 0x80090351 SEC_E_NO_AUTHENTICATING_AUTHORITY") | Should Be $false
        ($src -match "return 'Target not in the WinRM TrustedHosts")                     | Should Be $false
    }
    It 'restart manifest bumped to 1.5.0-beta14 (loop 2026-08-03 P1: armed-wave time resolved once, at arm time)' {
        (& $script:Mod { (Get-JanetToolManifest).version }) | Should Be '1.5.0-beta14'
    }
}

# =============================================================================
#  audit 2026-07-24 findings
# =============================================================================

# P2-1: the countdown message is spliced into shutdown.exe's command line. The old
# escaper turned a bare '"' into '\"' but left the backslashes in front of it alone,
# so a message containing  \"  closed the /c token and everything after it became
# ARGUMENTS: /s (shut DOWN, not restart), /t 0 (no warning), or /f pushed out.
Describe 'shutdown.exe /c message cannot inject an argument (audit 2026-07-24)' {
    function Arg { param([string]$m) (& $script:Mod { param($mm) ConvertTo-RrsShutdownMessageArg -Message $mm } $m) }

    # The real parser Windows uses on the command line ProcessStartInfo builds. argv[0]
    # is parsed by the exe-name rule, so the token list starts with the image name.
    $script:ArgvOk = $true
    try {
        if (-not ('JanetRrsTest.Argv' -as [type])) {
            Add-Type -Namespace JanetRrsTest -Name Argv -ErrorAction Stop -MemberDefinition @'
[DllImport("shell32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern System.IntPtr CommandLineToArgvW(string lpCmdLine, out int pNumArgs);
[DllImport("kernel32.dll")]
public static extern System.IntPtr LocalFree(System.IntPtr hMem);
'@
        }
    } catch { $script:ArgvOk = $false }
    function Split-Argv {
        param([string]$CommandLine)
        $n = 0
        $p = [JanetRrsTest.Argv]::CommandLineToArgvW($CommandLine, [ref]$n)
        if ($p -eq [IntPtr]::Zero) { return @() }
        $out = New-Object System.Collections.ArrayList
        try {
            for ($i = 0; $i -lt $n; $i++) {
                $sp = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($p, $i * [IntPtr]::Size)
                [void]$out.Add([System.Runtime.InteropServices.Marshal]::PtrToStringUni($sp))
            }
        } finally { [void][JanetRrsTest.Argv]::LocalFree($p) }
        return ,$out.ToArray()
    }

    # trailing backslash + an embedded quote (one of them backslash-prefixed) + an
    # injection payload. Under the OLD escaper this yields a real '/s' argument.
    $script:Evil = 'Save work \" & /s /t 0 /f "C:\'

    It 'the hostile message still produces ONE well-formed quoted argument' {
        $tok = Arg $script:Evil
        $tok.StartsWith('"') | Should Be $true
        $tok.EndsWith('"')   | Should Be $true
        # every interior quote escaped, no dangling trailing backslash - the OLD
        # output ("...x\\" ...") fails this outright.
        ($tok -match '^"(?:[^"\\]|\\[\s\S])*"$') | Should Be $true
        (& $script:Mod { param($t) Test-RrsShutdownMessageArg -Arg $t } $tok) | Should Be $true
    }
    if ($script:ArgvOk) {
        It 'Windows parses the built command line back to exactly /r /t 60 /c <msg> /f' {
            $cmd  = 'shutdown.exe /r /t 60 /c ' + (Arg $script:Evil) + ' /f'
            $argv = Split-Argv $cmd
            $argv.Count  | Should Be 7            # shutdown.exe /r /t 60 /c <msg> /f
            $argv[1]     | Should Be '/r'
            $argv[2]     | Should Be '/t'
            $argv[3]     | Should Be '60'
            $argv[4]     | Should Be '/c'
            $argv[5]     | Should Be $script:Evil  # the WHOLE message, still one argument
            $argv[6]     | Should Be '/f'
        }
        It 'the old escaper really did inject /s (this is the bug being fixed)' {
            $old  = '"' + ((($script:Evil -replace '[\r\n]+',' ') -replace '"','\"') -replace '(\\+)$','$1$1') + '"'
            $argv = Split-Argv ('shutdown.exe /r /t 60 /c ' + $old + ' /f')
            ($argv -contains '/s') | Should Be $true    # <-- the injection the fix removes
            $argv.Count | Should Not Be 7
        }
        It 'a message ending in a backslash (UNC path) keeps /f out of the message' {
            $m    = 'Copy from \\fileserver\share\'
            $argv = Split-Argv ('shutdown.exe /r /t 60 /c ' + (Arg $m) + ' /f')
            $argv[5] | Should Be $m
            $argv[6] | Should Be '/f'
        }
    }
    It 'a plain message is left alone and CR/LF/TAB collapse to spaces' {
        (Arg 'System is restarting for maintenance. Save your work.') | Should Be '"System is restarting for maintenance. Save your work."'
        (Arg "line1`r`nline2`tline3") | Should Be '"line1 line2 line3"'
    }
    It 'the message is capped under the 512-char shutdown.exe /c limit' {
        $tok = Arg ('x' * 900)
        $tok.Length | Should BeLessThan 512
    }

    $srcQ = Get-Content (Join-Path $script:Root 'modules\JanetWeb.restart.psm1') -Raw
    It 'neither remote shutdown block builds the /c token from raw message text any more' {
        ($srcQ -match "-replace\s+'`"','\\`"'") | Should Be $false
        # both remote blocks re-validate the pre-quoted token they were handed
        ([regex]::Matches($srcQ, [regex]::Escape('$mArg -notmatch'))).Count | Should Be 2
    }
}

# P2-2: verify-boottime parsed a bare HH:mm as TODAY. A wave dispatched 23:50 and
# verified 00:10 then compared every host against a reference ~24h in the FUTURE and
# reported the entire fleet "Did NOT restart - confirmed".
Describe 'verify-boottime reference time resolves across midnight (audit 2026-07-24)' {
    function Ref { param($raw, $now) (& $script:Mod { param($r, $n) Get-RrsReferenceTime -Raw $r -Now $n } $raw $now) }

    # A bare 'HH:mm' is parsed by [datetime]::TryParse, which anchors on the REAL system
    # date - in production $Now is (Get-Date) so the two always agree. These cases must
    # therefore build $Now off today's date, not a frozen calendar day, or they rot the
    # moment the wall clock moves past the day they were written (audit 2026-07-25).
    $script:Today = (Get-Date).Date

    It 'a bare HH:mm just after midnight resolves to YESTERDAY, not today' {
        $now = $script:Today.AddMinutes(10)                      # 00:10 today
        (Ref '23:50' $now).ToString('yyyy-MM-dd HH:mm') | Should Be $script:Today.AddDays(-1).AddHours(23).AddMinutes(50).ToString('yyyy-MM-dd HH:mm')
    }
    It 'a bare HH:mm earlier the same day still resolves to today' {
        $now = $script:Today.AddHours(9).AddMinutes(30)          # 09:30 today
        (Ref '08:00' $now).ToString('yyyy-MM-dd HH:mm') | Should Be $script:Today.AddHours(8).ToString('yyyy-MM-dd HH:mm')
    }
    It 'verifying a few minutes EARLY keeps today (forward tolerance)' {
        $now = $script:Today.AddHours(23).AddMinutes(45)         # 23:45 today
        (Ref '23:50' $now).ToString('yyyy-MM-dd HH:mm') | Should Be $script:Today.AddHours(23).AddMinutes(50).ToString('yyyy-MM-dd HH:mm')
    }
    It 'a dated reference is used exactly as written' {
        $now = [datetime]::new(2026, 7, 24, 0, 10, 0)
        (Ref '2026-07-20T22:00:00' $now).ToString('yyyy-MM-dd HH:mm') | Should Be '2026-07-20 22:00'
    }
    It 'an unparseable or blank reference returns nothing (boot time only)' {
        (Ref 'not a time' ([datetime]::new(2026, 7, 24, 0, 10, 0))) | Should Be $null
        (Ref '' ([datetime]::new(2026, 7, 24, 0, 10, 0)))           | Should Be $null
    }
}

# P3: an Exceptions (never-restart) entry that fails the host-token filter used to be
# dropped in SILENCE - and the host it was meant to protect was rebooted.
Describe 'never-restart Exceptions parse fails CLOSED (audit 2026-07-24)' {
    It 'Split-JanetHostTokens reports the tokens the host filter rejects' {
        $r = (& $script:Mod { param($x) Split-JanetHostTokens -Raw $x } "DC01`nBAD*HOST`nDC02")
        $r.Accepted.Count | Should Be 2
        $r.Rejected.Count | Should Be 1
        $r.Rejected[0]    | Should Be 'BAD*HOST'
    }
    It 'ConvertTo-JanetHostList keeps its accepted-only contract (targets unchanged)' {
        $t = (& $script:Mod { param($x) ConvertTo-JanetHostList $x } "DC01`nBAD*HOST`nDC02")
        $t.Count | Should Be 2
        ($t -join ',') | Should Be 'DC01,DC02'
    }
    It 'dispatch-restart ABORTS on a malformed exception entry instead of rebooting the wave' {
        $events = New-Object System.Collections.ArrayList
        $emit   = { param($e) [void]$events.Add($e) }
        $res = & $script:Mod { param($p, $em) Invoke-JanetToolAction -ActionId 'dispatch-restart' -Params $p -Emit $em } @{
            targets       = 'WS-NOT-ME-12345'
            exceptions    = "WS-NOT-ME-12345*`nDC01"   # the '*' entry is the malformed one
            restartTime   = '23:50'
            dryRun        = $true
            requireConsent = $false
        } $emit
        $res.rows.Count              | Should Be 0
        $res.summary.badExceptions   | Should Be 1
        $res.summary.error           | Should Be 'unparseable never-restart exception entry'
        # and it must say so LOUDLY (err level), naming the offending entry
        $errs = @($events | Where-Object { $_.type -eq 'log' -and $_.level -eq 'err' })
        $errs.Count | Should Not Be 0
        ($errs[0].text -match 'WS-NOT-ME-12345\*') | Should Be $true
        ($errs[0].text -match 'fail-closed')       | Should Be $true
    }
}

# =============================================================================
#  audit 2026-07-25 findings (fable re-audit follow-up)
# =============================================================================

# P3: the /c sanitiser collapsed only CR/LF/TAB. A U+0000 sailed through both the
# escaper and the Test-RrsShutdownMessageArg re-validation, and Win32 CreateProcess
# reads the command line as a NUL-TERMINATED wide string - so the line was CUT at the
# NUL, dropping /f and leaving a dangling-quote /c.
Describe 'shutdown.exe /c message strips NUL / C0 controls (audit 2026-07-25)' {
    function ArgC { param([string]$m) (& $script:Mod { param($mm) ConvertTo-RrsShutdownMessageArg -Message $mm } $m) }

    It 'a message carrying U+0000 yields a token with no NUL in it' {
        $tok = ArgC ("hi" + [char]0 + "bye /s")
        $tok.Contains([char]0) | Should Be $false
        $tok | Should Be '"hi bye /s"'
    }
    It 'the whole C0 control range is collapsed, not just CR/LF/TAB' {
        $m = 'a' + [char]1 + [char]7 + [char]11 + [char]12 + [char]27 + [char]31 + 'b'
        $tok = ArgC $m
        # nothing below 0x20 survives; the run collapses to a single space
        ($tok -match '[\x00-\x1F]') | Should Be $false
        $tok | Should Be '"a b"'
    }
    It 'the sanitised token still passes the quoted-argument re-validation' {
        $tok = ArgC ("Save work" + [char]0 + '\" & /s /t 0 /f "C:\')
        (& $script:Mod { param($t) Test-RrsShutdownMessageArg -Arg $t } $tok) | Should Be $true
    }
    It 'the 500-char cut still happens BEFORE escaping (a cut can never split a backslash pair)' {
        # a control char inflates nothing, and a long all-backslash message still ends
        # in an escaped (doubled) run inside a well-formed token
        $tok = ArgC (('\' * 900) + [char]0)
        $tok.StartsWith('"') | Should Be $true
        $tok.Length          | Should Be 1002   # 500 kept chars, doubled, plus the two quotes
        ($tok -match '^"(?:[^"\\]|\\[\s\S])*"$') | Should Be $true
        (& $script:Mod { param($t) Test-RrsShutdownMessageArg -Arg $t } $tok) | Should Be $true
    }
}

# P3: the fail-closed exceptions abort (audit 2026-07-24) was firing on ORDINARY
# annotations - '# never reboot DCs' and 'DC01 (primary)' - and hard-aborting the whole
# dispatch wave. Comments/annotations must be tolerated; real junk must still abort.
Describe 'never-restart Exceptions tolerate comments + annotations (audit 2026-07-25)' {
    function Split-Ex { param([string]$x) (& $script:Mod { param($r) Split-JanetHostTokens -Raw $r } $x) }

    It 'a whole-line # comment is skipped, not rejected' {
        $r = Split-Ex "# never reboot DCs`nDC01`nDC02"
        $r.Rejected.Count | Should Be 0
        ($r.Accepted -join ',') | Should Be 'DC01,DC02'
    }
    It 'a whole-line ; comment is skipped, not rejected' {
        $r = Split-Ex "; flight line - leave alone`nDC01"
        $r.Rejected.Count | Should Be 0
        ($r.Accepted -join ',') | Should Be 'DC01'
    }
    It 'a trailing parenthetical annotation is stripped, keeping the host' {
        $r = Split-Ex "DC01 (primary)`nDC02 (standby)"
        $r.Rejected.Count | Should Be 0
        ($r.Accepted -join ',') | Should Be 'DC01,DC02'
    }
    It 'blank lines and trailing commas are still skipped' {
        $r = Split-Ex "DC01,`n`n   `nDC02,"
        $r.Rejected.Count | Should Be 0
        ($r.Accepted -join ',') | Should Be 'DC01,DC02'
    }
    It 'a genuinely malformed entry is STILL rejected (fail-closed keeps its teeth)' {
        $r = Split-Ex "# never reboot DCs`nDC01 (primary)`nBAD*HOST"
        $r.Rejected.Count | Should Be 1
        $r.Rejected[0]    | Should Be 'BAD*HOST'
        ($r.Accepted -join ',') | Should Be 'DC01'
    }
    It 'a commented/annotated exceptions list does NOT abort the dispatch wave' {
        $events = New-Object System.Collections.ArrayList
        $emit   = { param($e) [void]$events.Add($e) }
        $res = & $script:Mod { param($p, $em) Invoke-JanetToolAction -ActionId 'dispatch-restart' -Params $p -Emit $em } @{
            targets        = 'WS-NOT-ME-12345'
            exceptions     = "# never reboot DCs`nDC01 (primary)"
            restartTime    = '23:50'
            dryRun         = $true
            requireConsent = $false
        } $emit
        $res.summary.error         | Should Be $null
        $res.summary.badExceptions | Should Be $null
        (@($events | Where-Object { $_.type -eq 'log' -and $_.level -eq 'err' -and $_.text -match 'fail-closed' }).Count) | Should Be 0
    }
    It 'a malformed entry alongside the comments STILL aborts the wave, naming the entry' {
        $events = New-Object System.Collections.ArrayList
        $emit   = { param($e) [void]$events.Add($e) }
        $res = & $script:Mod { param($p, $em) Invoke-JanetToolAction -ActionId 'dispatch-restart' -Params $p -Emit $em } @{
            targets        = 'WS-NOT-ME-12345'
            exceptions     = "# never reboot DCs`nDC01 (primary)`nWS-NOT-ME-12345*"
            restartTime    = '23:50'
            dryRun         = $true
            requireConsent = $false
        } $emit
        $res.rows.Count            | Should Be 0
        $res.summary.badExceptions | Should Be 1
        $res.summary.error         | Should Be 'unparseable never-restart exception entry'
        $errs = @($events | Where-Object { $_.type -eq 'log' -and $_.level -eq 'err' })
        ($errs[0].text -match 'WS-NOT-ME-12345\*') | Should Be $true
    }
}
