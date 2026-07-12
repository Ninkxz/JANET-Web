# Production Review - Loop 14 (Phase 2, cycle 12) - 2026-07-12

Both real backlogs remain operator-deferred (status-quo decision, loop 13): the stale certdeploy WIP and
the Desktop-parity mirror. Not re-escalated. No new committed Web delta since loop 13; surface audited
end to end. This cycle continued durable regression coverage on the security-critical boundary.

**Rating: GREEN.** No new findings. Landed the WRITE-path traversal lock-in (twin of loop-13's read
path) plus a minor latent-determinism fix it surfaced. Suite 848/848.

## Deliverable - lock in the upload write-path traversal defense
loop-12 verified the /upload filename+subdir sanitization defeats traversal, but it was untested.
Arbitrary file WRITE via a crafted `X-Janet-Filename` / `X-Janet-Subdir` is as severe as the read-path
traversal locked in loop 13, so this closes the symmetric gap.
- Extracted the inline sanitization into pure helpers `Get-JanetWebSafeUploadName` /
  `Get-JanetWebSafeUploadSubdir`; the accept loop calls them. `tests/Server.UploadName.Tests.ps1` (17):
  `../`/`..\`/absolute strip to a bare leaf, URL-decode-then-strip (no double-encoding bypass),
  invalid-char scrub, reserved-device `_`-prefix, empty/dot -> upload.dat; subdir honors only a bare
  `[A-Za-z0-9_-]{1,32}` token else a random 8-hex (not shared). Commit a11875169.

## Latent-determinism fix (surfaced by the test - NOT a security change)
The inline handler used `Split-Path -Leaf`, which RESOLVES a bare `..` against the process current
directory (so an upload literally named `..` produced a cwd-derived name and the `-eq '..'` fallback was
silently dead). Switched to a pure regex leaf-strip (`-replace '^.*[\\/]',''`) - cwd-independent and,
unlike `[IO.Path]::GetFileName` (which THROWS on invalid path chars like `<` in .NET Framework 4.x /
PS 5.1), never throws. Both the old and new outputs were already traversal-free (no security delta); a
`..` name now deterministically -> `upload.dat`. No guard weakened. No Desktop twin (server-only) -> no
ledger row.

## Verdict
Web GREEN, 848/848. Both read-path (loop 13) and write-path (loop 14) file-traversal defenses now carry
committed regression tests. Remaining open work is entirely operator-deferred: certdeploy XSS-3 (stale
WIP), Desktop-parity backlog (concurrent sync), certdeploy owner confirm-string P2. Next cycle: re-check
both trees for an unblocking commit; else continue durable hardening on already-audited surface.
