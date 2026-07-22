# JANET Web — design loop 87 (2026-07-22)

## Decision 1 — fix the false-clean the same way loop 40 fixed C2R (the established, tested pattern)
The mtime-only Chrome/Edge verify is byte-for-byte the class of bug loop 40 fixed for Office C2R: a registry key
that bumps its mtime on every attempt (including failures) makes "fresh" a false proxy for "current". C2R's fix
(`Get-AcasC2rVerified`) added a SUCCESS signal (`LastScenarioResult`). The correct fix here is the same shape — find
the Chrome/Edge success signal and require fresh AND success.

## Decision 2 — ground the success signal in the ACTUAL registry, not an assumption
Rather than guess the Omaha/EdgeUpdate schema, I read the live registry on the dev box: `Clients\{GUID}` (which the
probe already reads for `pv` + mtime) has NO install-result field, but the sibling `ClientState\{GUID}` carries
`LastInstallerResult` (0 on the box, = last install succeeded), `LastCheckSuccess`, `InstallerRepeatedFailureCount`,
etc. `LastInstallerResult -eq 0` is the direct analog of C2R's scenario-success. (Guarded against non-zero
`LastInstallerError`, which is present even on overall success — the authoritative field is `LastInstallerResult`.)

## Decision 3 — canonical fn + inline mirrors (the C2R structure), so it's unit-testable
`Get-AcasClientVerified` is a pure verdict (`HasTimestamp` / `AgeDays` / `LastInstallerResult` / `WindowDays=14`),
identical in shape to `Get-AcasC2rVerified`. The two generated remote probes (acas `New-AcasClientVerify`, wpt
`New-WptUpdateClientVerify`) run in module-less runspaces so they can't call it — they mirror it inline, deriving the
ClientState path with `$p -replace '\Clients\','\ClientState\'`. The canonical is unit-tested; the probes are
static-asserted to carry the same gate. No new wpt canonical (the logic is byte-identical to the acas one; a
duplicate would just drift).

## Decision 4 — indeterminate, not false, when there's no signal
When the ClientState key or `LastInstallerResult` is absent, `Verified` is `$null` (indeterminate), NOT `$true`. A
verify-only row is OK only on a POSITIVE confirmation (loop 26's canonical verify-only rule), so `$null` correctly
renders amber rather than a false green. This is strictly more honest than the old mtime-only `$true` and never
regresses a genuinely-current host into a FAIL (stale → `$false` was already the prior behavior).

## Decision 5 — scope the "old pattern gone" test to the function; the Store-app case is out of scope
There is a THIRD mtime-only verify at `acas:628` — the EXPERIMENTAL Microsoft Store app (`Microsoft.WindowsApp`),
which uses the APPX install-FOLDER mtime. It's the same false-clean class but a Store app has no Omaha
`ClientState`/`LastInstallerResult` analog (no clean success signal) and the profile is experimental, so it's out of
scope — left as-is, noted as backlog. Accordingly the "old mtime-only verdict is gone" assertion is SCOPED to the
`New-AcasClientVerify` / `New-WptUpdateClientVerify` function bodies (the C2R test could assert globally because its
window was 7; the client window is 14, shared with the Store-app block). acas 1.11.15 → 1.11.16, wpt 6.8.15 → 6.8.16.
