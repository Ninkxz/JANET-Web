# JANET Web — design loop 62 (2026-07-21)

## Decision 1 — close the hard-rule gap next
With pkginstall's two false-cleans closed (loops 60-61), item 69 is the standout remaining finding: it's not an
improvement but a **violation of a stated hard rule** — the most destructive tool in the suite had no confirm-word.
The prompt lists confirm-words among the established destructive-tool patterns to never weaken; here one was simply
absent. It goes ahead of item 70 (a P3 accounting gap).

## Decision 2 — the adto input+gate pattern, not a view dialog
Two confirm-word shapes exist in the codebase: a `confirm` form input + module gate (adto FIX/VALIDATE), and a
view-side typed dialog (secureboot ENABLE, pinned in the JS). I chose adto's: a required `confirm` manifest input the
generic form renders, plus a module-side `-ne 'DEPLOY'` refusal. It needs **no JS change**, and the module gate — not
the browser — is the fail-closed barrier, so a direct `POST` to the action with an armed session is refused too. The
view already shows a danger dialog; the input is the typed word on top of it. (The dive suggested "gate + confirmWord
in the view"; the input *is* the view-visible confirm-word, so the JS is unnecessary.)

## Decision 3 — gate at the single shared dispatch, before everything
`Invoke-JanetToolAction` handles both deploy actions through one path, so one gate covers both. It goes immediately
after the unknown-action check and **before** target parsing, the self-guard, and fan-out — a missing/wrong confirm
must cost nothing and touch no host. It returns `summary=@{ total=0; rejected=$true }`, the same rejected shape adto
uses, so any caller inspecting the summary sees the refusal.

## Decision 4 — case-insensitive, matching the convention
`-ne 'DEPLOY'` is case-insensitive, exactly like adto's `-ne 'FIX'` and the other tools. A first draft test asserted
a lowercase `deploy` should be refused; that was wrong — it would make pkginstall the one tool where case matters,
surprising the operator. The confirm-word's job is to force a deliberate typed word, which lowercase still satisfies.
The test was corrected to reject a genuinely *wrong* word (`INSTALL`) and to document that `deploy` is accepted.

## Decision 5 — behavioral tests, and the loop-37 lesson applied up front
The gate is directly behaviorally testable through `Invoke-JanetToolAction` (unlike the runspace-scriptblock fixes of
recent loops), so the regression tests are behavioral: blank/wrong confirm → rejected before fan-out; `DEPLOY` →
reaches the self-guard. Adding a required gate *would* have broken the 3 existing self-guard tests (they passed no
confirm), so — before writing anything — I grepped every test for the deploy action IDs, found only SelfGuard on the
gate path, and made `Invoke-Pkg` inject `confirm='DEPLOY'` by default so those tests still exercise the self-guard
while explicit-confirm tests exercise the gate. Because the deploy actions now refuse without the word, this is
behavioral: pkginstall 2.5.10 → 2.5.11, the newest bump's Describe holds the exact pin and the loop-61 PSADT Describe
floors. Item 70 remains.
