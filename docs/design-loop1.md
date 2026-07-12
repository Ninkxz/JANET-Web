# Design - Loop 1 - Pin the offline Defender package SHA256 across validate -> push

## Goal
Close the mpam-fe **validate->push TOCTOU** (loop-1 audit P3, on the fleet binary-execution path). Today
`Resolve-C2cDefenderPackage` validates the staged `mpam-fe.exe` ONCE admin-side (`c2c.psm1:2929`), but the file
is re-read from disk at `Copy-Item -ToSession` per host (`:2447`) - possibly much later in a long fan-out - and
then executed on the target (`Invoke-Command ... Start-Process`, `:2448-2452`). A swap of the source file between
validation and copy defeats the (now-hardened) `Test-C2cDefenderPackage` gate. This is the single most dangerous
capability in the suite (remote admin code execution), so it warrants a cryptographic pin.

## Surface (all in `modules\JanetWeb.c2c.psm1`; additive, guarded)
1. **Capture the hash at validation.** `Resolve-C2cDefenderPackage` (`:2863`) already returns `@{Path;Note;...}`
   for a validated package - add `Sha256 = (Get-FileHash -LiteralPath $cand -Algorithm SHA256).Hash`.
2. **Thread it to the worker.** The dispatcher reads `$offPkg.Sha256` into `$offlineDefSha256` (near `:2929`)
   and appends it as the LAST `AddArgument` (`:3213`), with a matching LAST param `[string]$OfflineDefSha256`
   on `$C2cFixBlock` (`:1401`). (ArgumentList/param order was verified 18/18 in the audit - appending at both
   ends keeps it aligned.)
3. **Re-verify on the target before exec.** In the offline-push `Invoke-Command` (`:2448`): pass the expected
   hash into the scriptblock's `ArgumentList`; after the file is on the target and BEFORE `Start-Process`,
   compute `Get-FileHash $Pkg -Algorithm SHA256` and, if it does not equal the expected hash, **abort** -
   delete the copy and return a FAIL note `"package SHA256 mismatch (validate->push tamper) - NOT executed"`.
   If the expected hash is empty (defensive), keep today's behavior (no regression).

## Risks / non-goals
- **Guard integrity:** purely additive - never weakens the existing Authenticode/size/identity gate or the
  self-guard/confirm. A mismatch fails CLOSED (does not execute).
- **Order alignment:** the one real hazard is the AddArgument<->param order; appended last at both ends and
  re-counted after the edit.
- **`Get-FileHash`** is present on PS 3+ (every supported target).
- **Not validated live:** the on-target re-hash executes only against a real staged package on a real host ->
  **pilot-pending**. What IS verifiable now: `Resolve-C2cDefenderPackage` returns a `Sha256` field, the arg/param
  counts stay aligned, and the module parses clean + the full suite stays green.

## Test plan
- PS 5.1 parse-clean; `Get-JanetToolManifest` still loads.
- Full Pester suite green (the offline path is not unit-tested; the change is additive + fail-closed).
- Add a focused assertion (extend `C2c.JavaAndPkiCompanions.Tests.ps1` or a small new file) that
  `Resolve-C2cDefenderPackage` returns an object carrying a `Sha256` property (empty when the shipped folder is
  empty, non-empty for a >=50MB fixture) - so the capture side can't silently regress.
- Document the on-target re-hash as pilot-pending in the loop-1 wrap.
