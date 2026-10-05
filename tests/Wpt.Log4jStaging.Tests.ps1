# =============================================================================
#  Wpt.Log4jStaging.Tests.ps1 - Pester 3.4 tests for the App Updater's Log4j
#  jar staging (wpt v6.10.12, hardened in v6.10.13).
#
#  app-update-apply used to REFUSE the 'Apache Log4j - Replace Vulnerable Jars'
#  profile and point the operator at ACAS, because the profile Script reads a
#  UNC the target cannot reach (double-hop). It now resolves the two jars
#  host-side and the worker copies them into a fresh admin-only folder in each
#  session and runs the Script against that folder.
#
#  Three layers, none of which contacts a host:
#    - the resolver runs for real against temp folders;
#    - the worker's REAL text runs with every remoting command replaced by a
#      recorder, so its staging logic executes and can be observed;
#    - the dispatcher runs for real with the resolver and the worker swapped for
#      fakes, through the real fan-out.
#  The first cut of this file asserted on message text and on a private copy of
#  the worker's regex; it stayed green with the redirect broken and the
#  fail-closed return deleted. These tests fail on those mutations.
#
#  Run:  Invoke-Pester -Path .\tests\Wpt.Log4jStaging.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:WptPath = Join-Path $script:Root 'modules\JanetWeb.wpt.psm1'
$m = Import-Module $script:WptPath -Force -PassThru
$script:WptSrc = Get-Content -LiteralPath $script:WptPath -Raw
$script:L4jProfile = 'Apache Log4j - Replace Vulnerable Jars'

function New-L4jDir { param([string[]]$Names)
    $d = Join-Path $env:TEMP ('JwL4jStage_' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -ItemType Directory -Path $d -Force)
    foreach ($n in $Names) { Set-Content -LiteralPath (Join-Path $d $n) -Value 'x' }
    return $d
}
# Resolver result as 'leaf|leaf' plus the folder, so a failure names what came back.
function Resolve-L4j { param([string[]]$Dirs)
    $hits = @(& $m { param($c) Resolve-WptLog4jSource -Candidates $c } $Dirs)
    @{ Count = $hits.Count
       Names = (@($hits | ForEach-Object { Split-Path -Leaf $_ }) -join '|')
       Dir   = $(if ($hits.Count) { Split-Path -Parent $hits[0] } else { '' }) }
}

Describe 'Resolve-WptLog4jSource (host-side jar selection)' {
    $made = @()
    try {
        $floorPair = New-L4jDir @('log4j-api-2.26.1.jar', 'log4j-core-2.26.1.jar');  $made += $floorPair
        $newerPair = New-L4jDir @('log4j-api-2.30.0.jar', 'log4j-core-2.30.0.jar');  $made += $newerPair
        $oldPair   = New-L4jDir @('log4j-api-2.25.5.jar', 'log4j-core-2.25.5.jar');  $made += $oldPair
        $apiOnly   = New-L4jDir @('log4j-api-2.26.1.jar');                           $made += $apiOnly
        $mixed     = New-L4jDir @('log4j-api-2.26.1.jar', 'log4j-core-2.9.0.jar');   $made += $mixed
        $empty     = New-L4jDir @();                                                 $made += $empty
        # Last cycle's jars, two qualifying pairs and unrelated log4j artifacts side by side.
        $crowded   = New-L4jDir @('log4j-api-2.25.5.jar', 'log4j-core-2.25.5.jar',
                                  'log4j-api-2.26.1.jar', 'log4j-core-2.26.1.jar',
                                  'log4j-api-2.30.0.jar', 'log4j-core-2.30.0.jar',
                                  'log4j-slf4j-impl-2.30.0.jar', 'log4j-1.2-api-2.30.0.jar');  $made += $crowded

        It 'returns the api and core FILES of a pair exactly at the floor' {
            $r = Resolve-L4j @($floorPair)
            $r.Names | Should Be 'log4j-api-2.26.1.jar|log4j-core-2.26.1.jar'
            $r.Dir   | Should Be $floorPair
        }
        It 'accepts a pair NEWER than the floor (floor, not an exact pin)' {
            (Resolve-L4j @($newerPair)).Names | Should Be 'log4j-api-2.30.0.jar|log4j-core-2.30.0.jar'
        }
        It 'returns ONLY the highest qualifying pair from a crowded folder - never a below-floor or stray jar' {
            $r = Resolve-L4j @($crowded)
            $r.Count | Should Be 2
            $r.Names | Should Be 'log4j-api-2.30.0.jar|log4j-core-2.30.0.jar'
        }
        It 'refuses a pair below the floor' {
            (Resolve-L4j @($oldPair)).Count | Should Be 0
        }
        It 'refuses a folder holding only one of the two jars' {
            (Resolve-L4j @($apiOnly)).Count | Should Be 0
        }
        It 'refuses a pair whose core jar is below the floor (2.9.0 is not above 2.26.1)' {
            (Resolve-L4j @($mixed)).Count | Should Be 0
        }
        It 'skips non-qualifying folders and falls through to the next candidate' {
            (Resolve-L4j @($empty, $oldPair, $floorPair)).Dir | Should Be $floorPair
        }
        It 'returns nothing for a folder that does not exist' {
            (Resolve-L4j @((Join-Path $env:TEMP ('JwL4jMissing_' + [guid]::NewGuid().ToString('N'))))).Count | Should Be 0
        }
    } finally {
        foreach ($d in $made) { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Log4j profile shape the worker depends on' {
    $l4j = (& $m { Get-WptAppUpdateProfiles })[$script:L4jProfile]
    It 'the profile is flagged NeedsStaging' {
        [bool]$l4j.NeedsStaging | Should Be $true
    }
    It 'the profile Script has exactly one single-quoted $sourceShare assignment to redirect' {
        @([regex]::Matches($l4j.Script.ToString(), "\`$sourceShare\s*=\s*'[^']*'")).Count | Should Be 1
    }
}

Describe 'WptAppUpdateBlock staging (the REAL worker text, remoting replaced by recorders)' {
    $l4j   = (& $m { Get-WptAppUpdateProfiles })[$script:L4jProfile]
    $blk   = & $m { "$script:WptAppUpdateBlock" }
    $jars  = @('C:\stage\log4j-api-2.26.1.jar', 'C:\stage\log4j-core-2.26.1.jar')
    $temp  = 'C:\WINDOWS\Temp\JanetLog4j_0123456789abcdef0123456789abcdef'

    # Functions defined here outrank the cmdlets of the same name for the worker's scope
    # only, so the worker's own logic runs end to end while nothing leaves this process.
    # Invoke-Command tells its four call sites apart by the scriptblock it is handed.
    function Invoke-ShimmedWorker {
        param([scriptblock]$Remote, [string[]]$StageJars = @(), [bool]$IsVerify = $false, [string]$FailOn = '', [string]$TempReply = $temp)
        $calls = New-Object System.Collections.ArrayList
        function Test-WptHostReachable { param($c) @{ Reachable = $true; UseSsl = $false } }
        function Test-WptRemoteNameMatch { param($Computer, $ActualName) $true }
        function New-PSSession { [CmdletBinding()] param($ComputerName, $SessionOption, [switch]$UseSSL, $Credential, $Authentication)
            [void]$calls.Add(@{ Op = 'open' }); 'FAKE-SESSION' }
        function Remove-PSSession { [CmdletBinding()] param($Session) [void]$calls.Add(@{ Op = 'close' }) }
        function Copy-Item { [CmdletBinding()] param($LiteralPath, $Destination, $ToSession, [switch]$Force)
            if ($FailOn -eq 'copy') { throw 'simulated copy failure' }
            [void]$calls.Add(@{ Op = 'copy'; From = $LiteralPath; To = $Destination; Session = $ToSession }) }
        function Invoke-Command { [CmdletBinding()] param($ComputerName, $SessionOption, [switch]$UseSSL, $Credential, $Authentication, $Session, [scriptblock]$ScriptBlock, $ArgumentList)
            $t = $ScriptBlock.ToString()
            if ($t -match '\$sourceShare')           { [void]$calls.Add(@{ Op = 'run'; Text = $t; Session = $Session }); return 'OK (shim)' }
            if ($t.Trim() -eq '$env:COMPUTERNAME')   { return 'H' }
            if ($t -match 'NewGuid')                 { [void]$calls.Add(@{ Op = 'mkdir'; Text = $t; Session = $Session }); return $TempReply }
            if ($t -match 'Remove-Item')             { [void]$calls.Add(@{ Op = 'cleanup'; Dir = @($ArgumentList)[0]; Session = $Session }); return }
            [void]$calls.Add(@{ Op = 'run'; Text = $t; Session = $Session }); 'OK (shim)'
        }
        $r = & ([scriptblock]::Create($blk)) 'H' $null 'Default' $Remote '' '' $IsVerify $StageJars
        @{ Result = $r; Calls = @($calls); Ops = (@($calls | ForEach-Object { $_.Op }) -join ',') }
    }
    function Get-Ops { param($o, [string]$Op) @($o.Calls | Where-Object { $_.Op -eq $Op }) }

    It 'opens one session, makes the folder, copies the two jars, runs, cleans up, closes - in that order' {
        $o = Invoke-ShimmedWorker -Remote $l4j.Script -StageJars $jars
        [string]$o.Result.Status | Should Be 'OK'
        $o.Ops | Should Be 'open,mkdir,copy,copy,run,cleanup,close'
    }
    It 'copies exactly the jars it was handed, into the folder the target returned, over that session' {
        $o = Invoke-ShimmedWorker -Remote $l4j.Script -StageJars $jars
        $copies = @(Get-Ops $o 'copy')
        (@($copies | ForEach-Object { $_.From }) -join '|') | Should Be ($jars -join '|')
        @($copies | Where-Object { $_.To -ne $temp -or $_.Session -ne 'FAKE-SESSION' }).Count | Should Be 0
    }
    It 'runs the Script redirected to that folder - the UNC is gone from what executes' {
        $o = Invoke-ShimmedWorker -Remote $l4j.Script -StageJars $jars
        $run = @(Get-Ops $o 'run')
        $run.Count | Should Be 1
        [string]$run[0].Session | Should Be 'FAKE-SESSION'
        $run[0].Text | Should Match ([regex]::Escape("`$sourceShare = '$temp'"))
        $run[0].Text | Should Not Match 'dm-tn-01'
    }
    It 'removes the folder it staged into' {
        $o = Invoke-ShimmedWorker -Remote $l4j.Script -StageJars $jars
        $clean = @(Get-Ops $o 'cleanup')
        $clean.Count | Should Be 1
        [string]$clean[0].Dir | Should Be $temp
    }
    It 'makes that folder NEW (no -Force), GUID-named and restricted to Administrators/SYSTEM' {
        $o = Invoke-ShimmedWorker -Remote $l4j.Script -StageJars $jars
        $mk = [string]@(Get-Ops $o 'mkdir')[0].Text
        $mk | Should Match 'JanetLog4j_'' \+ \[guid\]::NewGuid\(\)'
        $mk | Should Match 'New-Item -ItemType Directory -Path \$d -ErrorAction Stop'
        $mk | Should Not Match 'New-Item[^\r\n]*-Force'
        $mk | Should Match '/inheritance:r'
        $mk | Should Match ([regex]::Escape("'*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F'"))
        $mk | Should Match 'if \(\$LASTEXITCODE -ne 0\) \{ throw'
    }
    It 'never stages into a fixed, guessable folder name' {
        $blk | Should Not Match ([regex]::Escape("'C:\Windows\Temp\JanetLog4j'"))
    }
    It 'refuses a folder reply that is not the shape it asked for - nothing copied, run or deleted' {
        foreach ($bad in @('C:\Windows\Temp\JanetLog4j', 'C:\Windows', '', "C:\Win'dows\Temp\JanetLog4j_0123456789abcdef0123456789abcdef")) {
            $o = Invoke-ShimmedWorker -Remote $l4j.Script -StageJars $jars -TempReply $bad
            [string]$o.Result.Status | Should Be 'Failed'
            [string]$o.Result.Detail | Should Match 'unexpected staging folder'
            $o.Ops | Should Be 'open,mkdir,close'
        }
    }
    It 'fails closed when the Script has no $sourceShare to redirect - nothing copied or run' {
        $o = Invoke-ShimmedWorker -Remote { 'no assignment here' } -StageJars $jars
        [string]$o.Result.Status | Should Be 'Failed'
        [string]$o.Result.Detail | Should Match 'no \$sourceShare assignment to redirect'
        $o.Ops | Should Be 'open,mkdir,cleanup,close'
    }
    It 'a failed copy fails the host, the Script never runs, and the folder is still removed' {
        $o = Invoke-ShimmedWorker -Remote $l4j.Script -StageJars $jars -FailOn 'copy'
        [string]$o.Result.Status | Should Be 'Failed'
        [string]$o.Result.Detail | Should Match 'simulated copy failure'
        $o.Ops | Should Be 'open,mkdir,cleanup,close'
    }
    It 'Verify never stages, even when jars are supplied' {
        $o = Invoke-ShimmedWorker -Remote { 'verify probe' } -StageJars $jars -IsVerify $true
        $o.Ops | Should Be 'run'
        [string]$o.Result.Status | Should Be 'Verified'
    }
    It 'a profile with no jars takes the plain path - no session, no staging' {
        $o = Invoke-ShimmedWorker -Remote { 'plain profile' }
        $o.Ops | Should Be 'run'
        [string]$o.Result.Status | Should Be 'OK'
    }
}

Describe 'app-update-apply dispatch of the Log4j profile (real dispatcher + fan-out, fake resolver + worker)' {
    # The fake worker echoes the 8th argument it received, so a row proves what the
    # dispatcher actually handed the worker through ArgFactory and the runspace pool.
    function Invoke-L4jApply { param([object[]]$Resolved = @(), [string]$Profile = $script:L4jProfile)
        $evs  = New-Object System.Collections.ArrayList
        $emit = { param($e) [void]$evs.Add($e) }
        $res = & $m {
            param($em, $resolved, $prof)
            $origBlock = $script:WptAppUpdateBlock
            $script:WptL4jTestResolved = $resolved
            function script:Resolve-WptLog4jSource { @($script:WptL4jTestResolved) }
            $script:WptAppUpdateBlock = { param($h, $c, $a, $remote, $method, $arg, $isVerify, $jars)
                @{ Host = $h; Reachable = $true; Status = 'OK'; Detail = ('jars=' + (@($jars) -join '|') + ' n=' + @($jars).Count) } }
            try {
                Invoke-JanetToolAction -ActionId 'app-update-apply' -Params @{ targets = 'JW-L4J-FAKE-01'; profile = $prof; threads = 1 } -Credential $null -Emit $em
            } finally { $script:WptAppUpdateBlock = $origBlock }
        } $emit $Resolved $Profile
        @{ Result = $res; Events = @($evs)
           Rows = @($evs | Where-Object { $_.type -eq 'row' })
           Err  = @($evs | Where-Object { $_.type -eq 'log' -and $_.level -eq 'err' } | ForEach-Object { [string]$_.text }) }
    }
    $pair = @('C:\stage\log4j-api-2.26.1.jar', 'C:\stage\log4j-core-2.26.1.jar')

    It 'no qualifying pair -> NOTHING is fanned out, every target is counted failed, and the log says so' {
        $o = Invoke-L4jApply -Resolved @()
        $o.Rows.Count | Should Be 0
        [int]$o.Result.summary.total  | Should Be 1
        [int]$o.Result.summary.failed | Should Be 1
        ($o.Err -join ' ') | Should Match 'Nothing was run'
    }
    It 'a lone jar is not a pair -> fails closed the same way' {
        $o = Invoke-L4jApply -Resolved @($pair[0])
        $o.Rows.Count | Should Be 0
        [int]$o.Result.summary.failed | Should Be 1
    }
    It 'a resolved pair reaches the worker as exactly those two files' {
        $o = Invoke-L4jApply -Resolved $pair
        $o.Rows.Count | Should Be 1
        [string]$o.Rows[0].Detail | Should Be ('jars=' + ($pair -join '|') + ' n=2')
        $o.Err.Count | Should Be 0
    }
    It 'a profile that does not need staging is handed no jars and never consults the resolver' {
        $o = Invoke-L4jApply -Resolved $pair -Profile 'Microsoft 365 - Force Update'
        $o.Rows.Count | Should Be 1
        [string]$o.Rows[0].Detail | Should Be 'jars= n=0'
    }
    It 'app-update-apply no longer redirects the operator to ACAS' {
        $script:WptSrc | Should Not Match 'Run it from ACAS Nemesis -> Remediation \(Log4j\)'
    }
}
# The dispatch tests replaced a module function; reload so nothing leaks past this file.
$m = Import-Module $script:WptPath -Force -PassThru

# EXACT pin for this bump, per the convention that the newest bump pins exactly and
# older tests demote to a floor (Log4jJarVersion's 6.10.11 exact pin was demoted).
Describe 'manifest EXACT pin for the App Updater Log4j staging hardening (wpt 6.10.13)' {
    It 'wpt is exactly 6.10.13' {
        [string](& $m { (Get-JanetToolManifest).version }) | Should Be '6.10.13'
    }
}
