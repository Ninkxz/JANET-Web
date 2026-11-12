# C2C workspace

The C2C workspace groups compliance work into Defender, Vulnerabilities/AQC,
Patching, Firewall, BitLocker, Tanium monitoring and PKI certificates.
All 26 original workstation patching pages remain under Patching. Advanced tools
retains the original C2C utilities and full pillar-fix controls.

Defender opens a dedicated Defender/MDE remediation page. The existing repair
action, manual/imported target scope and confirmation safeguards are preserved.
The read-only scan adds typed local evidence for protection, signature age,
tenant status, update readiness, disk space and machine Firefox inventory.
Cloud reporting, Intune enrollment and numeric AQC remain unknown where there is
no authoritative source. The Intune escalation option creates a local draft only.

The MECM Peanut butter shot stages reviewed hosts into the existing bulk patch
workflow. It clears old results and resets application restart posture before
the explicit Load and scan steps. Windows updates follow MECM restart policy.

## Verification

Eight Node workspace behavior tests pass, including dedicated Defender routing,
retained feature coverage, unknown/offline evidence and cancellation behavior.
Isolated PowerShell checks passed for compliance evidence (9), TASKORD tiers
(20), signature age (7), patch overdue state (10), pillar target scope (25), WPT
bulk patch return values (8) and platform contracts (55). PowerShell 5.1 parsing
and a synthetic remoting/JSON round trip were also checked.

Real UI review used synthetic devices. The MultiVolAntiMalware suite is incomplete:
its fixture performs local TCP probes and was interrupted. WPT PatchMode was not
run because its fixture attempts a real TCP connection. The complete release
packaging gate and the changed build's operation on NIPR remain unverified.

Keep the matching UI and C2C backend together. Preserve existing site baselines,
approved packages and certificates when transferring to an established setup.
Existing live JANET use does not establish this revision's live behavior.

The presentation is in `presentations/JANET-Briefing.pptx`.
