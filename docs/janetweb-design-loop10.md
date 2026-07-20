# JANET Web — design loop 10 (2026-07-20)

## Decision 1 — turn the loop-9 finding into a suite-wide audit
Loop 9 found ONE self-guard gap by deep-diving one tool. The right response to a
contract-violation is not to fix that instance and move on, but to ask "where else?" — so
loop 10 ran a mechanical self-guard-coverage sweep across every destructive action in every
tool. That's how you find the *class*, not the *instance*. It surfaced that loop-9's own
"the ONLY" claim was wrong (clean-user-apps was also unguarded) and that pkginstall had no
self-guard infrastructure at all.

## Decision 2 — DON'T blindly guard all 16 the sweep flagged
This is the load-bearing judgment of the loop. A naive reading ("16 destructive fan-outs
lack a self-guard → add 16 guards") would be WRONG: it would break legitimate self-use of
benign actions (you WANT to be able to abort a scheduled reboot on the dispatcher, heal its
own WMI, unlock its own maintenance banner, cleanup its own disk). The repo already encodes
a harm-driven philosophy — `maintenance-lock` guards only on hardlock, `registry-key-apply`
only on reboot-after, `bulk-patch` only on forced — i.e. guard the mode that would
reboot/lock-out/abort-dispatch, not the benign one. I applied that yardstick and fixed only
the 3 where self-action is genuinely harmful (install software / delete software), leaving
13 benign-on-self actions unguarded by design and DOCUMENTING that so the next sweep doesn't
re-litigate it.

## Decision 3 — verify the agents' disagreement before acting
The loop-9 Opus review and the loop-10 sweep DISAGREED on clean-user-apps (guarded vs not).
I read the actual code rather than trusting either: line 6265 (loop-9's cited "guard") is
inside the RowOf send-loop, not a self-guard — the sweep was right, clean-user-apps was
unguarded. Reading the source settled it and corrected the loop-9 record. Never adjudicate a
security question on subagent word alone.

## Decision 4 — pkginstall guard is unconditional; clean-user-apps is live-only
pkginstall deploy has no dry-run — every invocation installs — so install-on-self is always
unwanted → unconditional guard. clean-user-apps has a dry-run default and dry-run on self is
a harmless preview, so it guards only the live path (mirrors maintenance-lock). Matching the
guard scope to the actual harm, per the existing conditional-guard precedent.

## Decision 5 — new helper in pkginstall, shared helper in wpt
pkginstall had zero self-guard infra, so it needed its own `Get-PkgInstallLocalIdentity`+
`Test-PkgInstallHostIsSelf` (a verbatim mirror of the c2c/upr/remoteadmin identity set —
name/FQDN/loopback + every bound NIC IPv4, the DNS-miss-proof form). wpt already has
`Remove-WptSelfTargets`, so clean-user-apps reuses it (no divergent helper). Consistency
over cleverness.

## Decision 6 — test the negative (dry-run not guarded) hermetically
A live-only guard needs a test proving it does NOT over-guard dry-run. But a dry-run on self
proceeds to fan-out (no short-circuit), which would hit real local WinRM on 127.0.0.1. Swap
the worker block (`$script:WptCleanUserAppsBlock`) for a fake — the RemoteAdmin/c2c test
idiom — so the negative test stays hermetic. A guard test that made a real host connection
would be worse than no test.

## Versioning
pkginstall `2.5.7→2.5.8`, wpt `6.8.3→6.8.4` (both behavioral: add a guard). `Wpt.SelfGuardApply`
holds the exact wpt pin (6.8.4); `PkgInstall.SelfGuard` holds the exact pkginstall pin
(2.5.8). Two tools, one coherent defect-class fix, one commit.
