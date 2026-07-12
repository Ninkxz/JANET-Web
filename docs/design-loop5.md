# Design - Loop 5 - Fail-closed destructive gate + explicit manifest flags

## Goal
Close the latent-P2 the loop-5 server-core audit found: the admin-session gate at
`server\JanetWeb.Server.ps1:736` treats an action as destructive ONLY if its manifest positively sets
`destructive=$true`. Any state-changing action whose author forgot the flag → `$actObj.destructive` is
`$null` → treated read-only → **runs with no admin session**. The ACAS by-id actions were already
special-cased (proving the class is real). Today's manifests mostly flag explicitly (185 flags across 22
modules), but nothing structurally prevents a miss, and the default is dangerous. Make it fail-closed.

## Surface (2 files of real change + 1 test; behavior-preserving by construction)
1. **`server\JanetWeb.Server.ps1:736` - flip the default to DENY.** New rule: an action is destructive
   UNLESS it POSITIVELY asserts read-only. Concretely, treat as destructive when NOT (the manifest action
   object exists AND carries an explicit `destructive` property equal to `$false`), excluding the existing
   acas read-only by-id set. So: explicit `$false` → ungated (read-only, unchanged); explicit `$true` →
   gated; **omitted → gated** (was: ungated). This can only ADD gating, never remove it - it cannot open a
   path that was closed.
2. **Complete the manifest flags (the safety half).** Because the flip newly gates any UNFLAGGED action, an
   unflagged READ-ONLY action (e.g. a scan/query that today runs without a session) would newly demand one -
   a UX regression. So FIRST enumerate every action across all 22 `Get-JanetToolManifest` outputs and, for
   any action lacking an explicit `destructive` boolean, ADD one: `$false` for genuinely read-only
   (scan/query/list/preview/status/diagnose), `$true` for anything that writes/changes a machine, AD, cert
   store, DHCP scope, service, etc. Classify by READING each action's `Invoke-JanetToolAction` handler - do
   not guess. Adding `$false` to a read-only action is a no-op; adding `$true` to a currently-unflagged
   DESTRUCTIVE action is itself a latent-P2 FIX (that action now correctly requires a session). The sweep is
   therefore strictly safe-or-beneficial: it can only preserve read-only behavior or close a gating hole.
3. **`tests/Manifest.DestructiveFlag.Tests.ps1` (NEW, BOM).** Loads every module's manifest and asserts EVERY
   action declares an explicit `destructive` boolean (`$true`/`$false`, not absent) - so a future action
   can't reintroduce the omit-defaults-open ambiguity. One `It` per module (or per action) for pinpointing.

## Risks / non-goals
- **Cannot regress a read-only flow** IF the enumeration is complete - the test guarantees completeness, and
  every read-only action is explicitly `$false` (unchanged gating). The gate flip is then inert for every
  currently-flagged action and only bites a future omission (fail-closed).
- **The one thing to gate carefully:** the classification of each currently-UNFLAGGED action. Over-flagging a
  read-only action `$true` would newly gate it (regression); under-flagging a destructive one `$false` would
  leave the hole. I (Fable) spot-check every action the sweep flips, against its handler, before commit.
- Non-goal: the token-on-argv P3 (separate, documented) and any manifest schema refactor.

## Test plan
- The new completeness test green (every action explicitly flagged).
- Full Pester suite green - especially any existing action/dispatch test, to confirm no read-only action was
  newly gated. If a test that runs a read-only action without a session goes red, that action was mis-flagged
  `$true` - fix the classification, not the test.
- PS 5.1 parse-clean + BOM on every changed .ps1. Manifests still load (`Get-JanetToolManifest` non-empty).
- I diff-review every `destructive=$true` the sweep ADDS (each is a claim "this action changes state") and
  every `$false` (each a claim "this action is read-only") against the handler before it lands.
