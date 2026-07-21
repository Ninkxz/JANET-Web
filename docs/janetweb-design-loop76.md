# JANET Web — design loop 76 (2026-07-21)

## Decision 1 — the destructive enable path, not (yet) the scan
secureboot has two remote actions: a read-only fleet scan and the destructive enable. The enable is where a "cannot be
done" outcome is most consequential (a firmware change that didn't happen) and where the raw error is a WinRM/auth/BIOS
string the mapper handles. The scan's `CHECK ERROR` verdict can also carry a probe error, but its `$res` shape and
error source differ; scoping this loop to the enable harvest keeps the wire clean and consistent with the other tools,
and the scan is noted as a follow-up.

## Decision 2 — reuse the existing four-way classify for the failure predicate
The enable harvest already computes `$isOk`/`$isSkip`/`$isUnknown`/`$isDryR` and books a failure exactly when none of
them hold (and it's not a dry run). So the hint's failure predicate is the same four-way condition plus `$res.Error` —
no new notion of "did this host fail", and dry-run/skip/unknown/ok rows are all excluded, matching how the harvest
already colours the log level.

## Decision 3 — attach to the row and the existing err log
The harvest already emits a per-host err log for failures; the hint is appended there (`| FIX: $hint`), and the row
gains a `Hint` field — the same two surfaces the other tools use. The audit detail keeps the raw error (an enable
failure's audit already carries the failure message). Consistent with the fleet.

## Decision 4 — additive only
The classify, counters, row (minus the new field), audit, and log level are all unchanged; the hint is computed after
the classify and only read. Success/skip/unknown/dry-run rows compute no hint and get no `FIX:` suffix, so those paths
are byte-identical.

## Decision 5 — static analysis, matching the tool's convention; run the whole suite
The enable harvest runs inside the fan-out over a real RunspacePool with no swappable-worker seam, and secureboot's
harvest tests are static, so the wire is pinned by static analysis (the hint's behavior is proven behaviorally
elsewhere): imports the engine, the four-way failure predicate computes the hint, the row carries `Hint`, the err log
appends `| FIX:`. Because the enable harvest is shared by every enable run, I ran the full secureboot suite (47) — the
change is additive and touches neither the scan verdict logic nor the classify, so nothing regressed. secureboot
1.6.4 → 1.6.5; the new Describe holds the exact pin, the loop-59 Describe floors. Next tool: c2c.
