# =============================================================================
#  Acas.RebootAudit.Tests.ps1 - Pester 3.4 for the schedule-reboot audit action
#  (loop28, roadmap item 19). schedule-reboot's worker returns "OK (reboot
#  scheduled ...)" for a shutdown.exe /r /t 300 - the reboot is 5 minutes out and
#  abortable (shutdown /a) and rc=1190 "already scheduled" also returns OK - yet
#  the fan-out booked a VulnPatched Success audit at SCHEDULE time. Booking
#  "vuln patched" for a pending, abortable reboot is a false compliance record
#  (an inspector reading the audit log sees a host patched that only had a reboot
#  queued). Scheduling a reboot is a TOUCH (contacted + scheduled the host), not a
#  confirmed patch, so the audit is now TouchHost - matching verify-post-reboot,
#  which already audits TouchHost. VulnPatched stays on the actual patch-install /
#  update-profile confirmations.
#
#  Static analysis of the schedule-reboot handler block (the fan-out audit action
#  is an inline arg in the action handler; the handler's self-guard is separately
#  exercised by Acas.SelfGuard.Tests.ps1).
#
#  Run:  Invoke-Pester -Path .\tests\Acas.RebootAudit.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.acas.psm1') -Force -PassThru
$script:Src  = Get-Content (Join-Path $script:Root 'modules\JanetWeb.acas.psm1') -Raw

# Isolate the 'schedule-reboot' handler block (up to the next handler).
$script:SchedBlock = ([regex]::Match($script:Src, "(?s)'schedule-reboot'\s*\{.*?'verify-post-reboot'")).Value

Describe 'schedule-reboot audit - a scheduled (pending, abortable) reboot is TouchHost, not VulnPatched' {
    It 'the schedule-reboot handler block was isolated' {
        ($script:SchedBlock.Length -gt 0) | Should Be $true
    }
    It 'schedule-reboot audits TouchHost (scheduling is a touch, not a confirmed patch)' {
        ($script:SchedBlock -match "AuditAction 'TouchHost'") | Should Be $true
    }
    It 'schedule-reboot does NOT book VulnPatched at schedule time (the false-clean fix)' {
        ($script:SchedBlock -match "AuditAction 'VulnPatched'") | Should Be $false
    }
}

Describe 'verify-post-reboot audit - still TouchHost (confirming a reboot is a touch)' {
    $verBlock = ([regex]::Match($script:Src, "(?s)'verify-post-reboot'\s*\{.*?(?='[a-z][a-z-]+'\s*\{|\Z)")).Value
    It 'verify-post-reboot audits TouchHost' {
        ($verBlock -match "AuditAction 'TouchHost'") | Should Be $true
    }
}

Describe 'acas - manifest exact version pin (newest bump = loop-28 schedule-reboot audit)' {
    It 'acas is at v1.11.9' {
        $mani = & $script:Mod { Get-JanetToolManifest }
        [string]$mani.version | Should Be '1.11.9'
    }
}
