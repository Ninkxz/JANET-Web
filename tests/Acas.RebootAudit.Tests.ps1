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

# loop38 (item34): the IN-CARD 'reboot-selected' arm is the sibling the loop28 fix missed - it booked
# VulnPatched at schedule time (same false compliance record). Its worker/row differ from schedule-reboot
# (it has a self-guard + an 'already-pending' row), so isolate its own handler block. Now TouchHost.
Describe 'reboot-selected audit - the in-card reboot arm is TouchHost, not VulnPatched (loop38 fix)' {
    # The reboot-selected arm lives inside the by-key handler; isolate from its ActionId guard to the
    # else (verify) branch so we test ONLY the reboot sub-block, not the verify-selected sibling below it.
    # Terminate on the branch-split '} else {' that sits on its OWN line (newline + indent); the inline
    # rowOf carries a '} else { ''scheduled'' }' that a bare '} else {' would wrongly stop at.
    $script:RsBlock = ([regex]::Match($script:Src, "(?s)if \(\`$ActionId -eq 'reboot-selected'\) \{.*?\r?\n\s+\} else \{")).Value
    It 'the reboot-selected sub-block was isolated' {
        ($script:RsBlock.Length -gt 0) | Should Be $true
    }
    It 'reboot-selected audits TouchHost (scheduling is a touch, not a confirmed patch)' {
        ($script:RsBlock -match "AuditAction 'TouchHost'") | Should Be $true
    }
    It 'reboot-selected does NOT book VulnPatched at schedule time (the false-clean fix)' {
        ($script:RsBlock -match "AuditAction 'VulnPatched'") | Should Be $false
    }
}

Describe 'acas - manifest version floor (reboot-selected audit shipped in 1.11.10; exact pin migrated to newest bump)' {
    It 'acas is at or past v1.11.10' {
        $mani = & $script:Mod { Get-JanetToolManifest }
        ([version][string]$mani.version -ge [version]'1.11.10') | Should Be $true
    }
}
