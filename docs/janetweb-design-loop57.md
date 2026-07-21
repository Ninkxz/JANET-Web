# JANET Web — design loop 57 (2026-07-21)

## Decision 1 — dive the last un-dived acting tool
adto and remoteadmin dives are complete. secureboot was the last acting/hardening tool never given a loop-era
false-clean dive, and it's destructive (enables Secure Boot by dropping a password-bearing payload and running it as
SYSTEM). That combination — a destructive firmware change whose effect is deferred to a reboot — is exactly where a
"reported enabled but isn't" false-clean tends to hide, so it was the highest-value place to look.

## Decision 2 — accept a fail-closed verdict, act on the one real finding
The dive came back with the core soundly fail-closed (task-creation failure → Error, vendor null/nonzero → error,
Unknown a hard stop, wrong-box hard-abort before the payload drop, scan scoring every failure away from compliant,
no coercions). As with remoteadmin, the discipline is to report that plainly and act only on what's substantiated —
the P2 stale-result replay — not manufacture a P1. I re-verified the P2 in-code (hostname-only result name at :505,
unverified best-effort pre-delete at :594, first-file-with-SetResult poll at :627) before touching anything.

## Decision 3 — eliminate the shared filename, don't patch the delete
Two fixes were on the table. (a) Make the pre-run delete fail-closed: `Test-Path` after it and abort the host as
Error if a stale file survives. (b) Give the result file a per-run-unique name so no stale file can share it. I chose
(b). It removes the ROOT CAUSE — the result filename being keyed on the host alone — rather than guarding one of the
two cleanup points that would have to fail. `$taskName` is already `SBE_<random>`, already per-run unique, and already
names the payload `$scriptFile`; using it for the result file too is the same idiom, one line, and makes a cross-run
collision structurally impossible. (a) also has a subtle cost the rename avoids: nothing about it prevents a *future*
second cleanup gap, whereas (b) is immune by construction. A Timestamp-based staleness check was rejected outright —
the payload's timestamp is the target's clock, so server/target skew could false-Timeout a genuinely fresh result.

## Decision 4 — propagate through one variable, verify the cleanup still lines up
`$resultFile` feeds `$remotePath` (baked into the payload as `$ResultPath`), `$uncPath` (the poll read), and the
`finally` cleanup (`Remove-Item $uncPath`). All three derive from the single `$resultFile` string, so the one-line
change carries through every site without further edits — I confirmed the `finally` deletes `$uncPath` (now the
unique name) so today's file is still cleaned and only crashed prior runs leave a small JSON in Temp (acceptable
cruft, and no worse than today's same-named lingering file).

## Decision 5 — static-analysis test, matched to the code; version
The filename is constructed inside `$script:SbeLiveWorker`, a module-less runspace scriptblock that can't be invoked
without live SMB, so a behavioral test isn't available — this is the inline-remote-logic case that gets static
analysis (the certdeploy / wpt-verify-clean precedent), NOT the pure-helper case that gets a behavioral unit test.
Three asserts: the `$resultFile` RHS references `$taskName`, the old hostname-only form is gone (narrowly matched to
the `$resultFile =` line so it can't false-match a sibling), and the exact `1.6.2` version pin. Because the enable
path's result-binding changed, secureboot bumps 1.6.1 → 1.6.2; per the suite convention the newest bump's own test
holds the exact pin and the previous exact pin (ConfirmWord, 1.6.1) migrates to a floor. The other five dive findings
are ranked items 62–66 for later loops; none is a hard false-clean of firmware state.
