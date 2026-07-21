# JANET Web — design loop 75 (2026-07-21)

## Decision 1 — dhcp is an upgrade, not a fresh wire
Unlike the five tools wired so far (which had bare `"FAIL: <msg>"` and no hint), dhcp already had a hint in all its
failure catches — just a thin, auth-only one. So loop 75 isn't "add a hint" but "upgrade the hint", which is higher
value than it looks: dhcp's thin mapper returned nothing for a DNS/RPC/SMB/timeout failure, the exact cases the shared
engine covers and the exact cases a DHCP-server admin hits when a server is offline or firewalled.

## Decision 2 — a drop-in swap, because the signatures already match
The shared `Get-JanetTroubleshootHint` takes `-Message`/`-Server` — identical to `Get-JanetWsmanAuthHint`. So the
upgrade is a mechanical replace of all five call sites, with no change to the surrounding `if ($hint) { … }` logging.
The shared engine is a strict superset of the thin one (it matches the same auth phrases and more), so no recognized
failure loses its hint; some previously-unrecognized failures gain one.

## Decision 3 — retire the local mapper (consolidation)
Loop 70's whole premise was one shared engine instead of per-tool copies. dhcp's thin mapper was one of the two ad-hoc
originals; once its call sites use the shared engine, it's dead code, so I removed it. That leaves restart's
`Get-RrsShutdownErrorHint` as the last ad-hoc mapper — but that one is *richer* than the shared engine (it also maps
numeric shutdown codes), so it stays for now; a later loop can fold its text signatures into the shared engine and
have restart delegate, rather than lose coverage.

## Decision 4 — keep dhcp's log format, don't churn for cosmetics
The other tools emit `| FIX: $hint`; dhcp emits ` -- $hint`. Aligning the separator would touch five log lines for a
purely cosmetic gain and risk a stale test, so I left dhcp's convention. The operator-visible win — the hint's content
and coverage — is what matters; the separator is noise.

## Decision 5 — static analysis, and run the whole tool's suite
dhcp's catches fire only on a real remote failure (no cheap behavioral seam), and the shared engine's behavior is
already unit-tested, so the wire is pinned by static analysis: imports the engine, five-plus call sites use it, the
dead function and its calls are gone. Because the swap touches shared failure paths, I ran all three dhcp-touching
files (68) — the loop-65 behavioral ReadError test exercises a *different* path (the bulk harvest, not the catches) and
is unaffected, confirming the swap is behavior-preserving. dhcp 1.1.13 → 1.1.14; the new Describe holds the exact pin,
the loop-69 Describe floors. Next tool: secureboot.
