# =============================================================================
#  Server.UploadName.Tests.ps1 - Pester 3.4 for Get-JanetWebSafeUploadName and
#  Get-JanetWebSafeUploadSubdir, the WRITE-path traversal defense for /upload
#  (loop14 - twin of the loop13 read-path Server.PathTraversal tests). A crafted
#  X-Janet-Filename / X-Janet-Subdir must NEVER let an upload land outside the
#  uploads folder or onto a Windows device - arbitrary file write = full compromise.
#
#  Dot-sourcing JanetWeb.Server.ps1 only DEFINES its functions (no top-level exec,
#  the listener lives inside Start-JanetWebServer), so no server is started.
#
#  Run:  Invoke-Pester -Path .\tests\Server.UploadName.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
. (Join-Path $script:Root 'server\JanetWeb.Server.ps1')

Describe 'Get-JanetWebSafeUploadName - filename cannot traverse or hit a device (loop14)' {
    It 'keeps a plain filename' {
        Get-JanetWebSafeUploadName 'report.csv' | Should Be 'report.csv'
    }
    It 'strips a ../ traversal to a bare leaf' {
        Get-JanetWebSafeUploadName '../../etc/passwd' | Should Be 'passwd'
    }
    It 'strips a backslash traversal to a bare leaf' {
        Get-JanetWebSafeUploadName '..\..\Windows\System32\evil.dll' | Should Be 'evil.dll'
    }
    It 'strips an absolute path to a bare leaf' {
        Get-JanetWebSafeUploadName 'C:\Windows\win.ini' | Should Be 'win.ini'
    }
    It 'decodes URL-encoding THEN strips traversal (no double-encoding bypass)' {
        # %2e%2e%2f = ../  -> unescaped then Split-Path -Leaf keeps only the leaf
        Get-JanetWebSafeUploadName '%2e%2e%2f%2e%2e%2fsecret.txt' | Should Be 'secret.txt'
    }
    It 'replaces invalid filename characters' {
        # < > : are invalid on Windows -> each becomes _
        Get-JanetWebSafeUploadName 'a<b>c.txt' | Should Be 'a_b_c.txt'
    }
    It "prefixes a reserved device name (CON) so it can't target a device" {
        Get-JanetWebSafeUploadName 'CON.txt' | Should Be '_CON.txt'
    }
    It 'prefixes a reserved COM port name (case-insensitive)' {
        Get-JanetWebSafeUploadName 'com1.dll' | Should Be '_com1.dll'
    }
    It 'falls back to upload.dat for empty' {
        Get-JanetWebSafeUploadName '' | Should Be 'upload.dat'
    }
    It 'falls back to upload.dat for a dot-only name' {
        Get-JanetWebSafeUploadName '..' | Should Be 'upload.dat'
    }
}

Describe 'Get-JanetWebSafeUploadSubdir - subdir is a bare token or a random fallback (loop14)' {
    It 'honors a clean bare token' {
        $r = Get-JanetWebSafeUploadSubdir 'log4j'
        $r.Name | Should Be 'log4j'; $r.Shared | Should Be $true
    }
    It 'honors letters/digits/underscore/hyphen' {
        (Get-JanetWebSafeUploadSubdir 'a-b_c9').Shared | Should Be $true
    }
    It 'rejects a token with a path separator (-> random, not shared)' {
        $r = Get-JanetWebSafeUploadSubdir '../evil'
        $r.Shared | Should Be $false
        $r.Name   | Should Match '^[0-9a-f]{8}$'
    }
    It 'rejects a token with a space' {
        (Get-JanetWebSafeUploadSubdir 'has space').Shared | Should Be $false
    }
    It 'rejects an over-long token (>32)' {
        (Get-JanetWebSafeUploadSubdir ('x' * 33)).Shared | Should Be $false
    }
    It 'rejects a reserved device name' {
        (Get-JanetWebSafeUploadSubdir 'CON').Shared | Should Be $false
    }
    It 'gives a random fallback for empty' {
        $r = Get-JanetWebSafeUploadSubdir ''
        $r.Shared | Should Be $false
        $r.Name   | Should Match '^[0-9a-f]{8}$'
    }
}
