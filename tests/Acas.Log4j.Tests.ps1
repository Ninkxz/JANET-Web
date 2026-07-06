# =============================================================================
#  Acas.Log4j.Tests.ps1 - Pester tests for the generalized
#  'Apache Log4j - Replace Vulnerable Jars' remediation profile.
#
#  The profile's Script runs remotely, but its discovery + copy-before-delete
#  swap is pure filesystem work. These tests drive the REAL Script body against
#  a TEMP tree: they pull $prof.Script.ToString() from the module, prepend
#  override assignments for $sourceShare / $searchRoots / $knownTargets (the
#  Script guards its defaults with `if (-not $x)`, so injected values win - the
#  same pattern the host uses when it rewrites $sourceShare to the staged temp),
#  create a fresh scriptblock and invoke it. No live host, no services.
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.acas.psm1') -Force -PassThru

# Pull the profile's Script body text out of the module's private table.
$script:ScriptText = & $script:Mod {
    $script:AcasUpdateProfiles['Apache Log4j - Replace Vulnerable Jars'].Script.ToString()
}

function New-Log4jTemp {
    # Returns a fresh temp workspace root. Caller cleans up.
    $base = Join-Path ([System.IO.Path]::GetTempPath()) ("JanetLog4jTest_{0}" -f ([System.Guid]::NewGuid().ToString('N')))
    New-Item -ItemType Directory -Path $base -Force | Out-Null
    return $base
}

function New-Jar {
    param([string]$Dir, [string]$Name, [string]$Content)
    New-Item -ItemType Directory -Path $Dir -Force | Out-Null
    $fp = Join-Path $Dir $Name
    Set-Content -LiteralPath $fp -Value $Content -Encoding ASCII -Force
    return $fp
}

function Invoke-Log4jScript {
    # Prepend override assignments, then run the real Script body.
    param([string]$SourceShare, [string[]]$SearchRoots, [array]$KnownTargets)
    $rootsLit = ($SearchRoots | ForEach-Object { "'" + ($_ -replace "'", "''") + "'" }) -join ', '
    $ktLit = if ($KnownTargets -and $KnownTargets.Count -gt 0) {
        (($KnownTargets | ForEach-Object {
            "@{ Path='" + ($_.Path -replace "'", "''") + "'; Service='" + ($_.Service -replace "'", "''") + "' }"
        }) -join "`n")
    } else { '' }
    $inject  = "`$sourceShare = '" + ($SourceShare -replace "'", "''") + "'`n"
    $inject += "`$searchRoots = @($rootsLit)`n"
    $inject += "`$knownTargets = @($ktLit)`n"
    $sb = [scriptblock]::Create($inject + $script:ScriptText)
    return (& $sb)
}

Describe 'Log4j profile - metadata sanity' {
    It 'exposes the profile with a Script and updated Desc mentioning discovery' {
        $meta = & $script:Mod {
            $p = $script:AcasUpdateProfiles['Apache Log4j - Replace Vulnerable Jars']
            [pscustomobject]@{ HasScript = ($p.Script -is [scriptblock]); Desc = [string]$p.Desc; Staging = [bool]$p.NeedsStaging }
        }
        $meta.HasScript | Should Be $true
        $meta.Staging   | Should Be $true
        ($meta.Desc -match 'discover|recursive|search root') | Should Be $true
    }
    It 'Script text still carries the single-quoted $sourceShare assignment the host rewrites' {
        ([regex]::Matches($script:ScriptText, '\$sourceShare\s*=\s*''[^'']*''')).Count | Should Be 1
    }
}

Describe 'Log4j profile - discovery + safe swap on a temp tree' {
    BeforeEach {
        $script:tmp    = New-Log4jTemp
        $script:src    = Join-Path $script:tmp 'source'
        $script:disco  = Join-Path $script:tmp 'roots'
        $script:stale  = Join-Path $script:disco 'AcmeApp\lib'
        $script:cur    = Join-Path $script:disco 'GoodApp\lib'
        $script:bkOnly = Join-Path $script:disco 'OldApp\lib\Backup_20200101_000000'

        # source (staged) 2.25.4 jars
        New-Jar -Dir $script:src -Name 'log4j-api-2.25.4.jar'  -Content 'NEW-API'  | Out-Null
        New-Jar -Dir $script:src -Name 'log4j-core-2.25.4.jar' -Content 'NEW-CORE' | Out-Null
        # stale lib dir (both api + core at 2.17.0)
        New-Jar -Dir $script:stale -Name 'log4j-core-2.17.0.jar' -Content 'OLD-CORE' | Out-Null
        New-Jar -Dir $script:stale -Name 'log4j-api-2.17.0.jar'  -Content 'OLD-API'  | Out-Null
        # already-current lib dir (must be skipped, untouched)
        New-Jar -Dir $script:cur -Name 'log4j-core-2.25.4.jar' -Content 'ALREADY-CUR' | Out-Null
        # a pre-existing Backup_* dir with an old jar (must be ignored, never touched)
        New-Jar -Dir $script:bkOnly -Name 'log4j-core-2.10.0.jar' -Content 'ARCHIVED' | Out-Null

        $script:result = Invoke-Log4jScript -SourceShare $script:src -SearchRoots @($script:disco) -KnownTargets @()
    }
    AfterEach {
        if ($script:tmp -and (Test-Path -LiteralPath $script:tmp)) {
            Remove-Item -LiteralPath $script:tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'returns OK and reports exactly one discovered lib dir replaced' {
        $script:result | Should Match '^OK'
        $script:result | Should Match 'discovered=1'
        $script:result | Should Match 'pendingReboot=0'
    }
    It 'places the 2.25.4 jars into the discovered stale dir' {
        (Test-Path -LiteralPath (Join-Path $script:stale 'log4j-api-2.25.4.jar'))  | Should Be $true
        (Test-Path -LiteralPath (Join-Path $script:stale 'log4j-core-2.25.4.jar')) | Should Be $true
        (Get-Content -LiteralPath (Join-Path $script:stale 'log4j-core-2.25.4.jar')) | Should Be 'NEW-CORE'
    }
    It 'removes the stale jars from the discovered dir top level' {
        (Test-Path -LiteralPath (Join-Path $script:stale 'log4j-core-2.17.0.jar')) | Should Be $false
        (Test-Path -LiteralPath (Join-Path $script:stale 'log4j-api-2.17.0.jar'))  | Should Be $false
    }
    It 'backs the stale jars up into a Backup_* dir before deleting them' {
        $bk = @(Get-ChildItem -LiteralPath $script:stale -Directory | Where-Object { $_.Name -like 'Backup_*' })
        $bk.Count | Should Be 1
        (Test-Path -LiteralPath (Join-Path $bk[0].FullName 'log4j-core-2.17.0.jar')) | Should Be $true
        (Test-Path -LiteralPath (Join-Path $bk[0].FullName 'log4j-api-2.17.0.jar'))  | Should Be $true
        (Get-Content -LiteralPath (Join-Path $bk[0].FullName 'log4j-core-2.17.0.jar')) | Should Be 'OLD-CORE'
    }
    It 'never leaves the lib dir with zero log4j jars (copy-before-delete)' {
        $live = @(Get-ChildItem -LiteralPath $script:stale -File -Filter 'log4j-*.jar')
        $live.Count | Should Be 2
    }
    It 'leaves the already-current dir untouched (skipped-current, no Backup created)' {
        $curJars = @(Get-ChildItem -LiteralPath $script:cur -File -Filter 'log4j-*.jar')
        $curJars.Count | Should Be 1
        (Get-Content -LiteralPath (Join-Path $script:cur 'log4j-core-2.25.4.jar')) | Should Be 'ALREADY-CUR'
        (@(Get-ChildItem -LiteralPath $script:cur -Directory | Where-Object { $_.Name -like 'Backup_*' })).Count | Should Be 0
        $script:result | Should Match 'current=1'
    }
    It 'ignores jars under a pre-existing Backup_* dir (not discovered, not deleted)' {
        (Test-Path -LiteralPath (Join-Path $script:bkOnly 'log4j-core-2.10.0.jar')) | Should Be $true
    }
}

Describe 'Log4j profile - locked stale jar is replaced pending reboot' {
    It 'places the new jar + keeps the old + reports pending-reboot when a stale jar is locked' {
        $tmp   = New-Log4jTemp
        $src   = Join-Path $tmp 'source'
        $disco = Join-Path $tmp 'roots'
        $lib   = Join-Path $disco 'LockApp\lib'
        New-Jar -Dir $src -Name 'log4j-api-2.25.4.jar'  -Content 'NEW-API'  | Out-Null
        New-Jar -Dir $src -Name 'log4j-core-2.25.4.jar' -Content 'NEW-CORE' | Out-Null
        $stalePath = New-Jar -Dir $lib -Name 'log4j-core-2.17.0.jar' -Content 'LOCKED-OLD'

        # FileShare.Read: a reader (Copy-Item backup) can still open it, but a delete
        # (which needs FileShare.Delete) is blocked - the running-JVM scenario.
        $fs = [System.IO.File]::Open($stalePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        try {
            $result = Invoke-Log4jScript -SourceShare $src -SearchRoots @($disco) -KnownTargets @()

            $result | Should Match '^OK'
            $result | Should Match 'pendingReboot=1'
            $result | Should Match 'discovered=0'
            $result | Should Match 'pending-reboot\(locked\)'
            ($result -like ('*' + $stalePath + '*')) | Should Be $true

            # New jars placed...
            (Test-Path -LiteralPath (Join-Path $lib 'log4j-api-2.25.4.jar'))  | Should Be $true
            (Test-Path -LiteralPath (Join-Path $lib 'log4j-core-2.25.4.jar')) | Should Be $true
            # ...old jar preserved (locked, could not delete) - dir never jar-less...
            (Test-Path -LiteralPath $stalePath) | Should Be $true
            # ...and the backup copy was still made.
            $bk = @(Get-ChildItem -LiteralPath $lib -Directory | Where-Object { $_.Name -like 'Backup_*' })
            $bk.Count | Should Be 1
            (Test-Path -LiteralPath (Join-Path $bk[0].FullName 'log4j-core-2.17.0.jar')) | Should Be $true
        } finally {
            $fs.Close(); $fs.Dispose()
            if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
}

Describe 'Log4j profile - known service path still swaps (service-guarded path preserved)' {
    It 'swaps a known target dir (bogus/absent service -> pure swap) and reports live=1' {
        $tmp   = New-Log4jTemp
        $src   = Join-Path $tmp 'source'
        $lib   = Join-Path $tmp 'KnownApp\lib'
        New-Jar -Dir $src -Name 'log4j-api-2.25.4.jar'  -Content 'NEW-API'  | Out-Null
        New-Jar -Dir $src -Name 'log4j-core-2.25.4.jar' -Content 'NEW-CORE' | Out-Null
        New-Jar -Dir $lib -Name 'log4j-core-2.17.0.jar' -Content 'OLD-CORE' | Out-Null
        New-Jar -Dir $lib -Name 'log4j-api-2.17.0.jar'  -Content 'OLD-API'  | Out-Null
        try {
            # No searchRoots -> discovery finds nothing; only the known path acts.
            $result = Invoke-Log4jScript -SourceShare $src -SearchRoots @() `
                        -KnownTargets @(@{ Path=$lib; Service='JanetWebNoSuchService_ZZZ' })

            $result | Should Match '^OK'
            $result | Should Match 'live=1'
            $result | Should Match 'discovered=0'
            (Test-Path -LiteralPath (Join-Path $lib 'log4j-core-2.25.4.jar')) | Should Be $true
            (Test-Path -LiteralPath (Join-Path $lib 'log4j-core-2.17.0.jar')) | Should Be $false
            $bk = @(Get-ChildItem -LiteralPath $lib -Directory | Where-Object { $_.Name -like 'Backup_*' })
            $bk.Count | Should Be 1
        } finally {
            if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
}

Describe 'Log4j profile - source precheck preserved' {
    It 'FAILs fast when the staged source jars are missing (no filesystem mutation)' {
        $tmp   = New-Log4jTemp
        $src   = Join-Path $tmp 'empty-source'   # exists but has no jars
        New-Item -ItemType Directory -Path $src -Force | Out-Null
        try {
            $result = Invoke-Log4jScript -SourceShare $src -SearchRoots @() -KnownTargets @()
            $result | Should Match '^FAIL: source jar missing'
        } finally {
            if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
}
