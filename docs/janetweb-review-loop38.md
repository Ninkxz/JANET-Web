# JANET Web — review loop 38 (2026-07-21)

Fable-inline synthesis + one Fable deep-dive worker on acas. Self-review of loop-37 → **GREEN**.
Baseline: loop-37 authoritative **1315** green (0 failed, definitively confirmed).

## Self-review of loop-37 (winupgrade repair-verdict fail-close) — GREEN
The unparseable-sfc → `unknown` → PARTIAL change is localized to the pure helper (`:668/672`) and its
runtime inline mirror (`:2685/2689`), verified in lockstep; `unknown` never sets `rebootNeeded` (that's
dism-reboot/sfc-repaired only), and a genuine "did not find any integrity violations" still substring-matches
→ CLEAN, so no false-unknown for clean hosts. The authoritative run also caught a pre-existing test that had
pinned the old fail-open (`VersionAndRemediation`), corrected in `3b4597b`. Nothing to reopen.

## Workstream: fresh false-clean deep-dive on acas (the most-used remediation tool, 242KB, v1.11.9)
A Fable worker read the module end-to-end; I re-verified each finding in-code. acas is largely fail-closed
(thrown probe → UNCONFIRMED, version-unchanged → UNCONFIRMED, self-classified FAIL/SKIP authoritative, DNS
wrong-box hard-abort, KB-install exemplary, unreachable/cred-fail → FAIL). The dive found a **confirmed
false-compliance audit** plus a cluster of verify-honesty gaps.

### F1 (FIXED this loop, item34) — `reboot-selected` books VulnPatched at reboot-SCHEDULE time
`:3630` — the in-card reboot arm passed `-AuditAction 'VulnPatched'`, so scheduling an abortable reboot
(`shutdown /r /t 300`; rc=1190 "already scheduled" also OK) booked a **VulnPatched Success audit,
itemCount=1** per host. loop28 (item19) fixed the *identical* bug on the standalone `schedule-reboot` arm
(`:3389`, TouchHost) with a comment saying verbatim "booking VulnPatched at schedule time was a false
compliance record" — but missed this by-key sibling; `verify-post-reboot` (`:3644`) also correctly audits
TouchHost. Trigger: operator clicks a card's Reboot → `shutdown /a` cancels it → the audit ledger still shows
the host VulnPatched. **Fix**: `TouchHost`, matching both siblings. The row itself was already honest
('scheduled'/'already-pending'/'failed'); only the audit action was wrong.

### Ranked (NOT fixed — each needs its own design pass)
- **item35 (F2, verify = mtime-recency, HIGH)** — the Office/Chrome/Edge/Java/Store Verify probes set
  `Verified=$true` purely from a registry key's `LastWriteTime` recency (`:129`/`:157`/`:459`/`:568`), never
  comparing against the version the finding demands. A verify-only ("Test Selected") run then shows an **OK
  row → PATCHED tile** for a still-vulnerable host; worst case a *failed* Office C2R update refreshes the same
  key's mtime → reads fresh/OK. This is the known-open "copied-registry always-OK" chip generalized. Mitigant:
  verify-only audits TouchHost, so the harm is the PATCHED stat card / operator verdict, not the audit ledger.
  Fix needs the probes to compare an actual installed version against the required version (or return
  `Verified=$null` → UNCONFIRMED when it can't).
- **item36 (F4, "bumped" = any string inequality, MEDIUM-HIGH)** — `:2076-2085`: after an update, `preV -ne
  postV` (raw string `-ne`, not `[version]`, not directional) → `"bumped"` → OK → VulnPatched Success. A
  post-probe that degrades to `'error'` (Defender catch, `:204`), `'n/a'` (Office key vanished, `:123`), or
  `'not installed'` (`:146`) is an inequality → booked as a confirmed fix; a downgrade counts too. Fix: require
  post to parse as `[version]` and be `> pre`, else UNCONFIRMED — but carefully, since non-version profiles
  (spec-exec returns COMPLIANT/VULNERABLE/DRIFT) must not regress.
- **item37 (F3, Log4j verify scans only 2 paths, MEDIUM)** — `:945-975`: the Verify checks only the HID +
  Adobe dirs and reports `Verified=$true` / "recursive scan (all jars 2.25.4)" while the *remediation Script*
  recurses all of `C:\Program Files*`. A verify-only run on a host with a vulnerable `log4j-core` under any
  other product dir reads OK/PATCHED. Update-mode is saved only accidentally by the pre==post UNCONFIRMED
  rewrap. Fix: make Verify recurse like the Script.
- **item38 (F5, null/empty → 'OK (no output)', LOW/latent)** — `:2483-2484`/`:1956`/`:2034`/`:2130`: a null or
  empty worker/probe result defaults toward `'OK (no output)'` / exit 0 rather than UNCONFIRMED. Every current
  worker returns a string so there's no live trigger, but the defaults resolve ambiguity toward OK — the wrong
  direction for this tool. Latent; harden toward UNCONFIRMED.
- **item39 (F6, Chrome/Edge in-Script proof is direction-agnostic, LOW)** — `:280-282`/`:353-356`: `$cur -ne
  $before` → "OK (updated X→Y)" even when Y<X (rollback/channel switch during the 90s poll). String compare,
  not `[version]` + greater-than. Same class as item36, in the profile Script.
- **Latent sharp edge (noted, no item)** — `AcasOkOf` (`:2361`) is SKIP-blind (returns true for `SKIP*`), but
  every consumer is `Invoke-AcasFanOut`, which checks `$isSkip` FIRST (`:2492`) and buckets SKIP as Skipped
  (itemCount=0). Not a live bug; a future caller using the predicate without the `$isSkip` precedence would
  count SKIP as patched. Could harden `AcasOkOf` to exclude `SKIP*` for self-consistency with `AcasUpdateRowOf`.

### Guarded (checked, honest — not findings)
KB-install path (MECM/UsoClient → UNCONFIRMED, null ReturnValue → rejection, errors win); Script-authoritative
FAIL/SKIP/UNCONFIRMED never rewrapped (`:2064`); thrown probes → UNCONFIRMED (`:2067`); Java/spec-fix engines
fail closed on missing source; spec-exec COMPLIANT does genuine bit math with fail-closed `[int]` casts
(`:521-541`); Edge STIG read-back (`:1047`); unreachable/cred-fail → FAIL; UNCONFIRMED counts into `failed`,
never `ok`; the fan-out three-way `$isSkip` classify.

## SECRET parity
- **SECRET parity:** the JanetSec acas fork shares the reboot-selected arm — mirror the `VulnPatched →
  TouchHost` audit fix at its equivalent of `:3630`. (The F2–F6 items, once designed, are parity candidates too.)
