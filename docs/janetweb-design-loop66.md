# JANET Web — design loop 66 (2026-07-21)

## Decision 1 — close the hard-rule gap next
The loop-65 dive left dhcp with five ranked items; item 75 is the one that's a hard-rule *violation* (a destructive
tool missing both the self-guard and the confirm-word every sibling has), not just an improvement. It goes ahead of
the dryRun/optionId/verify items — a destructive engine that can be pointed at its own host, unarmed, is the priority.

## Decision 2 — mirror the established self-guard, don't invent
Five destructive engines already have a pinned self-guard (Acas/Wpt/Upr/Pkginstall/Message). Rather than a bespoke
check, `Get-DhcpLocalIdentity`/`Test-DhcpHostIsSelf` are line-for-line the pkginstall pair (COMPUTERNAME, FQDN, short
name, loopback, `127.*`, every bound NIC IPv4). Consistency means the guard behaves identically across tools and is
already proven by the sibling tests. The one dhcp-specific nuance — the tool targets a single DHCP *server* — is
already enforced upstream (the one-server-only filter), so the self-guard just tests that single `$server`.

## Decision 3 — the adto input+gate confirm-word, case-insensitive, no JS
As with pkginstall's loop-62 DEPLOY word, the confirm-word is a required manifest `confirm` input plus a module gate,
not a browser dialog: the module — not the view — is the fail-closed barrier, so a direct POST is refused too, and no
JS changes. `APPLY` is the umbrella verb for all four write actions (apply + the three bulk modes). The match is
case-insensitive (`-ne 'APPLY'`), matching adto/secureboot/pkginstall — making dhcp the one case-sensitive tool would
surprise the operator, and the word's job is a deliberate typed token, which lowercase still satisfies.

## Decision 4 — gate once, before anything, for exactly the write actions
Both guards go in `Invoke-JanetToolAction` immediately after the single `$server` is resolved and before the option-id
parse and the action switch — so a missing word or a self-target costs nothing and opens no DHCP session. The action
set is the explicit `@('apply','bulk-append','bulk-prepend','bulk-remove')`; `connect`/`load` are read-only and must
stay ungated (arming a read would be user-hostile). Both refusals return the `rejected=$true` summary shape (the
self-guard adds `selfSkipped=1`), matching the confirm-gate shape used elsewhere.

## Decision 5 — behavioral tests, and the loop-37 lesson applied up front
The gate is reachable through `Invoke-JanetToolAction`, so the tests are behavioral: no/wrong confirm → rejected
before any session; a correct word + a self target → self-guard rejected. Before writing, I grepped every test for the
dhcp action ids and found two more files (`FixVerify`/`FixVerify3`) that import dhcp — but they drive
`Invoke-JanetDhcpApply`/`Invoke-DhcpLoad` directly, below the gate, so the gate doesn't touch them; I ran all three to
confirm. My own loop-65 ReadError test also calls `Invoke-JanetDhcpBulk` directly, so it too is unaffected. Because
the write actions now refuse without the word or against self, this is behavioral: dhcp 1.1.9 → 1.1.10, the newest
Describe holds the exact pin and the loop-65 ReadError Describe floors. Items 76-79 remain for a follow-up loop.
