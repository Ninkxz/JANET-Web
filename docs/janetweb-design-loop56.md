# JANET Web — design loop 56 (2026-07-21)

## Decision 1 — dive a NEW acting tool, not re-dive adto
adto's dive is complete (F1/F2/F3 closed). The remaining un-loop-era-dived acting tools are remoteadmin and
secureboot. remoteadmin's Run Script is the sharpest destructive surface in the suite (it runs operator-supplied
arbitrary code on remote hosts), so it's the highest-value place to hunt the campaign's false-clean/audit-honesty
class and re-audit the safety guards. Picked it over secureboot for that reason.

## Decision 2 — accept a GREEN dive and act only on what's real
The dive came back with the tool's core genuinely fail-closed: every non-success terminal state maps to Failure,
the four safety layers are present and correctly ordered before fan-out, and there's no coercion. That is itself a
valuable result — a destructive tool re-audited clean. The discipline is to report the GREEN plainly and act ONLY on
the one substantiated finding (C1), not to manufacture a P1 to justify the loop. A finding is a lead: I re-verified
C1 in-code (worker `return $r` is last; `:473` takes `-First 1`; the row reads `$res.*`) before touching anything.

## Decision 3 — fix the latent binding bug even though it can't bite today
C1 is P3 and currently a no-op (nothing leaks, so `-First 1` == `-Last 1`), and it leans fail-closed (a non-Success
stray audits Failure). But this is a run-*arbitrary*-code tool whose worker is the most likely thing in the suite to
evolve, and the row's Host/Status/Output all come from the selected object. `-Last 1` is the correct, intent-matching
selection (the return value is by definition the last stream object), it's a one-token change, and it removes a
whole class of future "row built from garbage." Cheap correctness on a destructive path — worth it.

## Decision 4 — leave C2 and S1 alone, and say why
C2 (open-cshare "Opened") and S1 (run-script "didn't throw") are both by-design, not defects: the first is a
non-destructive visual launch the operator verifies, the second is inherent to running arbitrary code (there's no
exit code to read). The dive explicitly cautioned that "fixing" S1 with invented exit-code parsing would ADD
coercion risk — the exact class the campaign removes. Documenting the non-action in the review doc matters so a
future loop doesn't reopen them.

## Decision 5 — behavioral test via the existing worker-swap idiom; version
The test file already swaps `$script:RemoteAdminScriptBlock` for a fake and runs the REAL aggregation end to end, so
C1 is behaviorally testable without WinRM: a fake worker that leaks a stray object before its return proves the row
is built from the return (`-Last 1`) and not the stray (`-First 1`) — a genuine regression, not a static assert.
Because it's a code change to a destructive tool's result-binding, remoteadmin bumps 1.0.1 → 1.0.2 and a version pin
is added (none existed before; it now anchors future bumps). remoteadmin's dive is complete.
