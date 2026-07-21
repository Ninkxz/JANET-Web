# JANET Web — design loop 59 (2026-07-21)

## Decision 1 — finish secureboot's audit honesty before moving on
Loop 58 closed the dry_run fail-open (item 64). Item 62 is the last secureboot finding that's an actual honesty
false-clean (books Success for work this run didn't do); the remaining three (63/65/66) are wording/tally/hardening
polish. Closing 62 now finishes the tool's "don't claim Success you didn't earn" story in the same run of loops,
rather than leaving a known audit-inflation open while pivoting to a fresh tool.

## Decision 2 — fix the status resolution, not the audit or the payload
The false-clean surfaces in the audit, but its ROOT is one place: `AlreadyPending` had no status of its own and fell
through to `Success`. Three candidate fix sites — the payload branches (add a Skipped flag ×3), the audit block (special-
case AlreadyPending), or the resolvedStatus chain (one branch) — and the chain is correct because the classify is
*already* driven entirely by `Status` and *already* handles `Skipped` honestly (skipCount, audit Skipped, itemCount 0).
So mapping AlreadyPending → Skipped at the single resolution point fixes the count, the audit result, the itemCount,
and the summary wording at once, with nothing downstream to touch. I verified the classify handles Skipped before
relying on it (the loop-50 discipline: confirm the downstream is honest, don't assume).

## Decision 3 — align the returned Skipped field to the resolved status
`New-Result` never set a `Skipped` property, and the return computed `Skipped` from `$result.Skipped` independently
of `Status`. After the fix, an AlreadyPending row is `Status='Skipped'` but would carry `Skipped=$false` — a latent
inconsistency. The field isn't consumed downstream today (only the resolver reads `.Skipped`, and off the *vendor*
result, not the returned object), so this is defensive: deriving the field from `$resolvedStatus` guarantees
Status and Skipped can never disagree for any future consumer. No behavior change for the existing cases (they were
already consistent); only AlreadyPending's field flips to match its new status.

## Decision 4 — static analysis, matched to inline runspace logic; version
The resolvedStatus mapping lives inside `$script:SbeLiveWorker`, a module-less runspace scriptblock that can't be
invoked without live SMB/WinRM (the same constraint as the loop-57 filename fix, and unlike loop-58's pure
`Get-SbeDryRunSafe` which got a behavioral test). So the regression test is static analysis of the block: the chain
maps `AlreadyPending → 'Skipped'`, and — to pin the whole honesty chain, not just the mapping — that a non-Success
row books `itemCount 0` and that `Status='Skipped'` routes to `$isSkip`. Because a re-run's audit moves from Success/
itemCount-1 to Skipped/itemCount-0, this is behavioral: secureboot 1.6.3 → 1.6.4, the newest bump's test (now the
Scan static-analysis Describe) holds the exact pin and the loop-58 ConfirmWord pin migrates to a floor.
