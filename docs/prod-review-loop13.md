# Production Review - Loop 13 (Phase 2, cycle 11) - 2026-07-12

Both blockers are now STATUS-QUO by explicit operator decision (this cycle): the stale certdeploy
"companions" WIP (untouched since ~19:01, blocking the certdeploy XSS-3 + running unaudited on restart)
stays deferred - do not touch; the Desktop-parity mirror stays deferred until `X:\J.A.N.E.T` is committed
clean. So neither is re-escalated below; both remain open by choice, not oversight.

**Rating: GREEN.** No new committed Web delta since loop 12; the Web attack surface is audited end to end
(loops 3-10 per-tool, 11 whole-surface XSS, 12 server boundary). This cycle added durable regression
coverage rather than manufacturing audit churn over byte-identical GREEN code. Suite 831/831.

## Deliverable - lock in the #1 security property with a regression test
The loop-12 audit proved the static-file **path-traversal defense** by hand, but nothing in the committed
suite guarded it. Arbitrary file read is the single worst outcome for this app (token file, other repos
on the SMB drive), so an untested boundary that a future serving-path refactor could silently break is a
real gap. Closed it without weakening the guard:
- Extracted the inline resolve+containment from the accept loop into a pure, unit-testable
  `Get-JanetWebAssetPath(WebDir, UrlPath) -> in-root leaf or $null`. **Behavior-preserving**: the
  audit#28 underscore-404 and the traversal-404 both collapse to a `$null` return -> identical 404
  branch; the accept loop now calls the helper. PS 5.1 parse-clean + BOM.
- `tests/Server.PathTraversal.Tests.ps1` (9 tests): serves `/`->index.html + real nested assets; 404s
  underscore/dev assets, `../` and `..\` traversal, `/js/../../` escape, absolute `C:/` path, the sibling
  `web2` prefix (trailing-separator containment), a missing file, and a directory. Payloads pass RAW to
  the function - NOT relying on System.Uri to collapse `..` upstream - so the function's own Resolve-Path
  + StartsWith defense is what's proven (defense-in-depth: still safe if a future change loses the Uri
  layer). Commit 7154662c5.

Not a defect fix (the defense was already GREEN in loop 12) -> no new ledger row; this is regression
insurance on an existing correct guard.

## Verdict
Web GREEN, 831/831, path-traversal defense now regression-locked. Remaining open work is entirely
operator-deferred: certdeploy XSS-3 (stale WIP), Desktop-parity backlog (concurrent sync), certdeploy
owner confirm-string P2. Next cycle: re-check both trees for a commit that unblocks either; if still
frozen, continue durable test/quality hardening on already-audited surface rather than re-auditing it.
