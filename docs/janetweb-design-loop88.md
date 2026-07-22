# JANET Web — design loop 88 (2026-07-22)

## Decision 1 — fix the real bug the self-review exposed, not just my inert commit
The loop-87 self-review didn't just find a flaw in my commit — it found the whole freshness-based Chrome/Edge
verify has NEVER worked, because `Get-Item <registry-key>.LastWriteTime` is always `$null` (a `RegistryKey` is not
a `FileInfo`). So the fix isn't "adjust my loop-87 logic"; it's "give the verdict a working timestamp source." My
loop-87 ClientState/`LastInstallerResult` read was already correct — it just never executed.

## Decision 2 — the timestamp source is a registry VALUE, not the key's mtime
Getting a registry key's true last-write time needs P/Invoke (`RegQueryInfoKey`) — heavy and fragile inside a
generated remote scriptblock. But the ClientState key already carries a real timestamp as a VALUE:
`LastCheckSuccess` (unix epoch of the last successful update check, confirmed on the live box). That's both simpler
and more meaningful than a key mtime: it says "the updater successfully checked recently" — for an auto-updating
browser, that IS "current". So `$mod = epoch(LastCheckSuccess)`, and the verdict stays fresh-AND-succeeded.

## Decision 3 — fold in the self-review's #2 and #3 while I'm in here
The self-review flagged two latent casts in the same code: an empty-string `LastInstallerResult` (`[int]''`→0 =
false success) and a UInt32 DWORD ≥ 0x80000000 (`[int]` overflow → throw). Both are near-unreachable (the field is
a REG_DWORD in 0–4), but since I'm reworking the cast anyway: guard `"$v" -ne ''` and use `[int64]`/`TryParse`. The
canonical `Get-AcasClientVerified` gets the same TryParse so it's total over its input domain.

## Decision 4 — the test EXECUTES a generated probe (the missing test class)
Three loops of static/canonical-only tests hid runtime failures; this one hid an ALWAYS-null read. The fix's test
creates a sandbox `HKCU:\…\Update\Clients\{G}` + `…\ClientState\{G}`, generates the real probe pointing at that
root, RUNS it, and asserts the verdict — for both the acas and wpt probes. That single executing test would have
caught the inert bug (it asserts `LastUpdated` is a real date, not `n/a`, and `Verified` actually toggles). It
cleans up its HKCU keys.

## Decision 5 — one P1 per loop; the sccm P1 is deferred, not ignored
The wpt deep-dive surfaced a second P1 (the sccm `type`/`Type` emit crash + destructive-audit loss). It's real and
serious, but it's a separate fix touching the JS view, and pairing it with this loop's inert-verify P1 is exactly
how the last several loops shipped incomplete fixes. It gets loop 89 with a clear design (case-sensitive emit merge
à la upr's `New-UprRowEvent`, no JS change) and the other wpt findings (cleanup-disk DNS guard, Oracle-Java
freshness verify, bool-coercion sweep) are ranked backlog. acas 1.11.16 → 1.11.17, wpt 6.8.16 → 6.8.17.
