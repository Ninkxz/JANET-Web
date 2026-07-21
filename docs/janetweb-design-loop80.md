# JANET Web — design loop 80 (2026-07-21)

## Decision 1 — extend the theme to a READ-ONLY path (the scan CHECK ERROR)
The primary rollout (loops 70-78) wired the hint into each tool's DESTRUCTIVE harvest. But an operator also
hits "cannot be done" on a READ-ONLY scan — a host that can't be probed shows up as a CHECK ERROR row with a
raw WinRM/session/DNS error, and the operator wants the same why+how-to-fix there. secureboot's read-only scan
(`Invoke-SbeScanAction`) was noted as a follow-up since loop 76; this loop wires it.

## Decision 2 — scope the hint to CHECK ERROR, not every non-OK verdict
The scan's non-OK verdicts are OFFLINE / DNS MISMATCH / CHECK ERROR / Cancelled. Only **CHECK ERROR** carries a
raw, cryptic error the operator can act on (`"Session: <exc>"`, `"Probe: <exc>"`, `"worker error: <exc>"`,
`"per-host timeout …"`). OFFLINE already carries a complete actionable detail ("No TCP on 5985/5986/445 … Enable
'Attempt even if offline'"), DNS MISMATCH explains itself ("dialed X but remote is Y"), and Cancelled is an
operator action. Running those through the engine returns '' anyway (no matching signature), but scoping the
predicate to `CHECK ERROR` is explicit and self-documenting.

## Decision 3 — host-level CHECK ERROR only, not the ambiguous-probe CHECK ERROR
There are TWO ways a row reads CHECK ERROR: (a) host-level — the probe never completed, `$hostStatus != 'OK'`,
`$detail` = the raw session/probe error; (b) probe-completed-but-ambiguous — `$hostStatus == 'OK'` but the
verdict classifier couldn't confirm UEFI+GPT, `$detail` = "could not positively confirm the UEFI + GPT boot
path". Only (a) has an actionable remote error. So the predicate is `$verdict -eq 'CHECK ERROR' -and
$hostStatus -ne 'OK' -and $detail` — (b) gets no hint (the engine would return '' for its text regardless, but
the guard makes the intent explicit).

## Decision 4 — additive; same shape as the enable-harvest wire (loop 76)
The verdict, the row (minus the new field), the per-host log, the counters, and the end-of-scan tally are all
unchanged; `$hint` is computed after `$detail` is finalized and only read, the row gains a `Hint` field, and a
single err `FIX:` line is emitted for a recognized CHECK ERROR. Every OK / OFFLINE / DNS MISMATCH / Cancelled
row is byte-identical (Hint=''). secureboot already imports the engine (loop 76), so no new import.

## Decision 5 — static analysis, matching secureboot's convention; run the whole tool suite
The scan harvest runs inside the fan-out over a real RunspacePool with no swappable-worker seam, and
secureboot's harvest tests are static, so the wire is pinned by static analysis (the hint's behavior is proven
behaviorally in `Troubleshoot.Hint.Tests.ps1`): the `CHECK ERROR`-only predicate computes the hint, the row
carries `Detail=$detail; Hint=[string]$hint`, the err log is gated on `$hint` and carries `FIX:`. secureboot
1.6.5 → 1.6.6; the new Describe holds the exact pin, loop-76's 1.6.5 pin floors. Full secureboot suite green.
Next follow-ups: c2c scan/version harvests, certdeploy check/scan CHECK ERROR rows, per-candidate upr failures.
