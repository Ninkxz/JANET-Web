# JANET Web — design loop 83 (2026-07-21)

## Decision 1 — the deferred loop-74 item needs BOTH a wire AND new signatures
Loop 74 wired upr's HOST-level connection failure (`$res.Error`, hint on `-not $ok`). The deferred piece is the
PER-CANDIDATE uninstall failure: a host that IS reached but where an individual EOL product fails to uninstall.
That failure lives in `$cand.Result` (e.g. `FAIL (Office -- … exit 1603)`, `rejected: executable not found: …`),
and — critically — the shared engine currently returns '' for ALL of these (verified inert on 5 real shapes). So
this loop is two coupled halves: (a) grow the signature set with MSI/uninstaller exit-code signatures, (b) wire
upr's per-candidate Result through the engine. Neither delivers value alone.

## Decision 2 — the per-candidate wire goes in New-UprEmitRows, not the host-level loop
`Invoke-UprFanOut` (`:1264`) computes the HOST hint only when `-not $ok -and $res.Error` — a host-level failure.
A host that's reached with failing candidates returns `ok=$true`, so that host hint is '' and its row-attach loop
(`:1266`) never touches the per-candidate rows. So the per-candidate hint belongs in `New-UprEmitRows` (`:1440`),
where each candidate row is built with its own `$resultTxt`. Predicate: the EXISTING `$candResult -eq 'Failure'`
classifier (`:1460`, already used for the per-app audit) — not OK*, not Skipped*. Attaches `$row['Hint']` +
a `FIX:` err log. No overwrite risk: the two hint sources are mutually exclusive (host-failure vs reached-host).

## Decision 3 — new signatures: MSI/uninstaller exit codes, general to upr/wpt/pkginstall
The new failure class is install/uninstall exit codes — general to every tool that runs msiexec/installers, so the
SHARED engine is the right home. Five signatures, all word-boundaried (a bare code is a false-positive magnet):
- **1618 / ERROR_INSTALL_ALREADY_RUNNING** — another MSI in progress → wait / clear a stuck msiexec.
- **1605 / ERROR_UNKNOWN_PRODUCT** — not installed (already removed / stale entry) → nothing to uninstall.
- **1603 / ERROR_INSTALL_FAILURE** — the catch-all fatal → locked file / pending reboot / rights; capture `/l*v`.
- **executable not found / process did not start** — uninstaller binary gone → orphaned registry entry.
- **unparseable / empty uninstall string** — the safe-uninstall guard rejected it → use the vendor uninstaller.
Ordering: placed AFTER the file-locked signature (a "file in use" message is more specific than a bare 1603, so
file-locked wins first); 1618/1605 before 1603 (1603 is the catch-all). Numerics `\b`-bounded like the RPC/priv
codes.

## Decision 4 — additive; conditional row mutation (the acas/loop-81 pattern)
The per-candidate row is a hashtable literal; `$row['Hint']` is mutated only when a hint exists. The per-app audit,
the OK/Skipped/Failure classification, the row Result, and the host tally are unchanged; a single `FIX:` err log
rides per failing candidate. An OK/Skipped candidate is byte-identical. upr already imports the engine (loop 74).

## Decision 5 — tests: static for the wire, behavioral for the signatures; run the whole tool suite
The wire is pinned by static analysis in `Upr.VerifyResult.Tests.ps1` (New-UprEmitRows returns a scriptblock run
inside the fan-out — no seam), matching upr's convention. The new engine signatures are pinned BEHAVIORALLY in
`Troubleshoot.Hint.Tests.ps1` (the engine is pure). upr 1.2.5 → 1.2.6; the new Describe holds the exact pin,
loop-74's 1.2.5 floored. **loop-37 lesson:** engine change is shared — ran the upr suite + all engine-consumers.
This is the last item on the informative-failures follow-up list; after it the theme's rollout is complete.
