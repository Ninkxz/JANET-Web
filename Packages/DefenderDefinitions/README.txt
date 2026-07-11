DefenderDefinitions - offline Defender definition package staging folder
=========================================================================

Drop Microsoft's FULL offline Defender definition installer here:

    mpam-fe.exe        (x64 full package; mpam-feX64.exe also accepted)

Download (from a connected machine): https://www.microsoft.com/en-us/wdsi/defenderupdates
-> "Microsoft Defender Antivirus for Windows 10/11 (64-bit)".

How the C2C Nemesis tool uses it (Defender-ScanFix v2.1 LAST rung):
- fix-antimalware / run-all check this folder at launch. Empty folder = the
  offline rung is simply disabled; nothing else changes.
- The file is validated ADMIN-SIDE before any host is dialed: it must exist,
  be a full package (>= 50 MB) and carry a VALID Microsoft Authenticode
  signature. Anything else is rejected with a warning and never pushed.
- It is pushed ONLY to hosts where EVERY online signature source already
  failed (default channel -> Microsoft Update -> MMPC), copied over the
  existing WinRM session to C:\Windows\Temp, executed, verified by re-reading
  the signature age, then deleted from the target.

Keep exactly one current package here and refresh it when you rotate media -
definitions age out fast, and a stale offline package will "succeed" but
still leave the host over the signature-age budget (reported as FAIL).
