# Experimental -> Production Merge Summary - 2026-07-12

Phase 1 of the merge loop. Production = `X:\JANET Web`; reference = `X:\JANET Web Experimental` (left intact).

## Safety
- Both web trees git-clean at start; no concurrent external edits (recent mtimes were this session's own work).
- Pre-merge full backup: `X:\Archive\JANETWeb_premerge_2026-07-12_130441.zip` (13.6 MB, includes .git).

## Git relationship
Unrelated histories (Experimental was `git init`'d on a copy, never cloned), bidirectionally diverged.
Production already carried its OWN v1.15.0 (the four field ScanFix ports + offline Defender rung) and
`Sync-TakeToWork` - so the merge is the **audit hardening + new tools on top**, ported commit-by-commit in
audit order (safety fixes first), preserving messages. No production work was overwritten.

## What landed on production `master`
1. **All applicable audit fixes** (9 existing source files, loops 1-8): the six 2026-07-12 P2s in c2c
   (mpam Authenticode gate, PkiRdp Server-Auth EKU, Java vendor gate, BitLocker resume escrow, MDE blob
   expiry, offline-Defender SHA256 pin - all verified present), adsearch LDAP bind-redirect DN-guard +
   RFC-4514-escape hardening + ReferralChasing=None, wpt CSV formula-injection + pool injection +
   maintenance-lock self-guard, fail-closed admin-session gate, run-script wrong-box DNS-mismatch abort,
   dhcp stored-XSS escapes, shell.js client-CSV neutralizer, kev add-kev gating.
2. **Both net-new Web tools** (additive): AD-TO (`adto`) and WinRM Bridge (`winrmbridge`) - modules, SPA
   views, tool-registry.json entries. Registry now lists 22 tools (was 20). Server.ps1 needed no change
   (registry-driven dynamic module load). Both tools' actions carry explicit destructive flags, so the
   merged fail-closed gate classifies them.
3. **Audit record**: all Fable review docs (2026-07-11, 2026-07-12 loops 1-8), design-loop docs, the rollup.
4. **`docs/desktop-parity-ledger.md`**: 23 findings, 5 CLOSED-WEB-ONLY (reasoned), 18 CHECK (Phase-2 Desktop
   mirror mandatory).

## Fixes NOT ported (production lacks the underlying feature - documented, not silently dropped)
- Self-guard hardening for `pkginstall`, `upr`, `adsearch` identity helpers and `acas`/`wpt` NIC enumeration:
  production's self-guard implementation is thinner (those helpers/NIC-loops don't exist in prod), so the
  per-NIC/`return ,$set` fixes and the upr manual-uninstall self-guard have no prod target. Porting the
  self-guard FEATURE to those tools is Phase-2 tool-parity work, not an audit fix.
- The experimental Pester suites (8 invariant-locking suites) were not brought this phase - several assume
  experimental's fuller module set; porting/adapting them to prod is a Phase-2 cycle. Production's own
  739-test suite is the current gate and is green.

## State
Full production Pester suite **739/0 green**; git status clean; 22 tools registered; Experimental untouched.
Phase 1 complete -> Phase 2 (hourly audit + Java-into-WPT/ACAS + Desktop mirror) begins next cycles.
