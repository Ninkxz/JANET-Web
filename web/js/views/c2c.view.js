/* ============================================================================
   c2c.view.js  -  C2C Nemesis (tool id: 'c2c')
   Comply-to-Connect (AFI/MPTO rule 3.B.2.B) quarantine predictor + remediation.

   ONE host list (TARGET COMPUTERS) drives everything:

   1. READ-ONLY "C2C Readiness Scan" (action 'scan') + "Version Check"
      (action 'version-check'): read-only probes across the Target Computers.
      Change NOTHING and are NOT gated on an admin session.

   2. DUAL-MODE FIX (destructive, admin-session gated): the six endpoint-fixable
      pillars (Monitoring / Firewall / Encryption / AntiMalware / Patches / PKI
      Trust Roots) are ALWAYS shown as fix cards.
        - MANUAL MODE (no import): each per-card Fix, and RUN ALL, dial the TARGET
          COMPUTERS list - load machines and run a manual C2C patch, no import
          required. The engine runs manual mode (no allow-list) when no csvPath is
          sent, dialing exactly the typed hosts.
        - IMPORT MODE (a CSV is imported): each card fixes ONLY the hosts the import
          flagged for that pillar (server-re-derived + intersected as an allow-list;
          never the whole list).
      Every fixer is VERIFY-FIRST (NOCHANGE on a host already compliant), so running
      a pillar against a host that does not need it is safe.

   3. OPTIONAL IMPORT of the Tanium "C2C Compliance Status" CSV: (a) auto-loads the
      non-compliant hosts into Target Computers, (b) checks + badges the pillars each
      host failed and switches the fix cards to import-scoped targeting, and (c) shows
      the routed-elsewhere pillars (Vuln -> ACAS/KEV, OSVersion -> Windows Upgrade,
      STIG -> Reports) as info notes.

   Credentials are UNIVERSAL (shell header top-right) - this view renders NO
   per-tool credential control; it only READS ctx.session.state.credSet.
   ========================================================================== */
(function () {
  'use strict';

  // engine row events are keyed 'Host'; CSV header keeps the desktop label 'Computer'.
  var EXPORT_COLS = [['Host', 'Computer'], ['Ping', 'Ping'], ['Status', 'Status'], ['Detail', 'Detail']];

  // The 11 C2C checks, tiered to the TASKORD 26-0822 dashboard. Only the QUARANTINE
  // tier predicts quarantine; AUDIT + INFO are advisory; Monitoring is ATTEST.
  var CHECKS = [
    ['Monitoring', '[ATTEST] Endpoint monitoring (Tanium installed + client running) - a dead client cannot attest -> NOT ATTESTING'],
    ['Firewall', '[QUARANTINE] Endpoint firewall active (Domain + Private + Public profiles enabled)'],
    ['AntiMalware', '[QUARANTINE] Defender installed + signatures < 7 days + MDE Org ID matches (RunningMode/RTP/Sense are advisory)'],
    ['Patches', '[QUARANTINE] Security patches installed within a 7-day grace (0 overdue MECM/CCM updates)'],
    ['VulnThreshold', '[QUARANTINE] AQC Score (filtered) < 25  [EXT - server-side (ARAD/ACAS); the #1 quarantine driver - import the CSV to score]'],
    ['Encryption', '[QUARANTINE] C: / OS volume BitLocker Protection ON (other fixed volumes are advisory)'],
    ['AppWhitelist', '[INFO] Application whitelist (AppLocker or WDAC enforcing) - advisory, not a TASKORD rule'],
    ['Agents', '[INFO] Patching + security agents (CcmExec + a security agent) - advisory, not a TASKORD rule'],
    ['PkiRoots', '[AUDIT] PKI trust roots baseline present (DoD roots in LocalMachine\\Root) - audit, never quarantines'],
    ['OsVersion', '[AUDIT] OS Version Win11 + 24H2+ + Enterprise - audit, never quarantines (remediate via Windows Upgrade)'],
    ['Coams', '[INFO] All 7 COAMS tags applied  [EXT - ARAD/ePO server-side, not endpoint-readable]']
  ];

  // Endpoint-fixable pillars (drive the per-pillar cards + run-all). Must match the
  // engine's $script:C2cFixablePillars. The stable ORDER here is the card order.
  var FIXABLE = ['Monitoring', 'Firewall', 'Encryption', 'AntiMalware', 'Patches', 'PkiRoots'];

  // Short UPPERCASE tab labels (acas-style numbered rail labels: '01  MONITORING').
  var PILLAR_TAB = {
    Monitoring: 'MONITORING', Firewall: 'FIREWALL', Encryption: 'ENCRYPTION',
    AntiMalware: 'ANTIMALWARE', Patches: 'PATCHES', PkiRoots: 'PKI TRUST ROOTS'
  };

  // Per-fixable-pillar card metadata: canonical key -> action id + display + blurb.
  var FIX_META = {
    Monitoring:  { action: 'fix-monitoring',  label: 'Monitoring (Tanium)',    desc: 'Verify Tanium SOFTWARE installed (uninstall registry) + heal the client service (Automatic + start).' },
    Firewall:    { action: 'fix-firewall',    label: 'Firewall',               desc: 'Enable any disabled Domain / Private / Public firewall profile.' },
    Encryption:  { action: 'fix-encryption',  label: 'Encryption (BitLocker)', desc: 'Resume suspended protectors on EVERY fixed volume; opt-in ENABLE decrypted fixed volumes (OS: TPM; data: auto-unlock). Removable/USB never touched.' },
    AntiMalware: { action: 'fix-antimalware', label: 'AntiMalware (Defender)', desc: 'Start WinDefend / Sense (Automatic); force RTP only in Active mode (never Passive / EDR Block Mode); update stale signatures.' },
    Patches:     { action: 'fix-patches',     label: 'Patches (MECM cycle)',   desc: 'Trigger the MECM SUM scan (113) + eval (108); installs run async.' },
    PkiRoots:    { action: 'fix-pki',         label: 'PKI Trust Roots',        desc: 'Install the DoD trust bundle .cer ADDITIVELY into Root/CA/Disallowed (uses the cert bundle folder below; blank = shipped Packages\\DoD-Certs). Expired certs are auto-skipped - never pushed.' }
  };

  // Routed-elsewhere pillars: import shows these as non-runnable info notes.
  var ROUTED = [
    { key: 'Vuln',      label: 'Vuln (ACAS / KEV)',   route: 'ACAS / Reports / KEV tools' },
    { key: 'OSVersion', label: 'OS Version',          route: 'Windows Upgrade tool' },
    { key: 'STIG',      label: 'STIG',                route: 'Reports / STIG' }
  ];

  function statusCellCls(v) {
    switch (String(v)) {
      // green: no failing pillars (scan) / at least one pillar fixed or encryption started (fix)
      // / version at-or-installed.
      case 'READY':
      case 'FIXED':
      case 'STARTED':
      case 'UP TO DATE':
      case 'INSTALLED': return 'st-ok';
      // red: at least one scored pillar failed -> predicted quarantine; or unreachable; the fix
      // failed; or an outdated product version.
      case 'QUARANTINE RISK':
      case 'OFFLINE':
      case 'OUTDATED':
      case 'FAILED': return 'st-bad';
      // amber: no fail but a check errored, the host couldn't be evaluated, operator cancel,
      // a partial fix, a self/DNS skip, product not installed, or Tanium not reporting
      // (NOT ATTESTING - box invisible to the C2C dashboard, distinct from a quarantine).
      // audit 2026-07-24: NOT VERIFIED (a first-class host status the fix engine emits - the
      // change was made but could NOT be confirmed) had NO class at all, so it rendered like a
      // plain uncoloured row next to green compliant ones. It is fail-closed evidence: amber.
      // audit 2026-07-25 (fable re-audit follow-up): IN PROGRESS moved DOWN here from the blue
      // group. It is now a first-class host rollup status (an all-in-progress host used to book
      // NO CHANGE), and an UNFINISHED remediation must not sit in the same colour family as
      // "nothing to do" - the box would still fail the C2C scan. Amber, like PARTIAL.
      case 'CHECK ERRORS':
      case 'NOT ATTESTING':
      case 'NOT VERIFIED':
      case 'IN PROGRESS':
      case 'Cancelled':
      case 'ERROR':
      case 'DNS MISMATCH':
      case 'PARTIAL':
      case 'NOT INSTALLED':
      case 'SKIPPED': return 'st-warn';
      // blue: nothing changed (fix), a newer-than-target version, or live in-progress phases
      // streamed by the engine.
      case 'NO CHANGE':
      case 'NEWER':
      case 'Scanning':
      case 'Probing':
      case 'Working': return 'st-info';
      case 'Queued': return 'cell-dim';
      default: return '';
    }
  }
  function pingCellCls(v) {
    var s = String(v == null ? '' : v);
    if (s === '') return '';
    if (/^(tcp |\d)/i.test(s)) return 'st-ok';         // "TCP 5985" (web engines) or "<n> ms" (desktop)
    if (/unreach|offline/i.test(s)) return 'st-bad';
    if (/dns|error/i.test(s)) return 'st-warn';
    return 'cell-dim';
  }

  JanetViews.register('c2c', {
    mount: function (host, ctx) {
      var ui = ctx.ui, C = ctx.components, el = ctx.util.el;

      // ---- run/result state ----
      var run = null, unsub = null, offTargets = null;
      var lastImport = null;             // last import summary
      var importCsvPath = null;          // server-side path of the last uploaded C2C CSV (drives ALL per-pillar + run-all targeting)
      var pillarCards = {};              // pillar key -> { hosts, via, cb, fixBtn, enableCb?, bundleInput? } for the per-pillar fix cards
      var encEnableChecked = false;      // persists the ENABLE-BitLocker opt-in across card rebuilds
      var pkiBundleValue = '';           // persists the PKI cert bundle folder across card rebuilds
      var pkiPruneChecked = false;       // persists the "prune expired retired DoD intermediates" opt-in (default OFF)
      var pkiRdpChecked = false;         // persists the "repair broken RDP listener" opt-in (default OFF)
      // audit 2026-07-25 (fable re-audit follow-up): persists the "BLACKLIST the bundle Untrusted
      // certs into Disallowed" opt-in (default OFF) - a fleet-wide DISTRUST, so it is armed
      // explicitly, exactly like the certdeploy tool's pushDisallowed.
      var pkiDistrustChecked = false;
      var importTiles = null;            // hero StatCards (built in the import card below)

      // =================== layout ===================
      var root = el('div'); root.style.cssText = 'display:flex;flex-direction:column;height:100%;min-height:0;background:var(--bg)';

      var body = el('div'); body.style.cssText = 'flex:1;min-height:0;display:flex;gap:14px;padding:14px 16px 0';
      root.appendChild(body);

      // ---------- LEFT: CONFIG COLUMN ----------
      var left = el('div'); left.style.cssText = 'flex:0 0 470px;display:flex;flex-direction:column;gap:12px;min-height:0;overflow:auto';
      body.appendChild(left);

      // --- TARGET COMPUTERS (TargetManager) - the ONE list that drives scan AND fixes ---
      var compCard = sectionCard('TARGET COMPUTERS');
      compCard.style.cssText += ';flex:0 0 auto;display:flex;flex-direction:column';
      var compHint = el('div'); compHint.style.cssText = 'font-size:11.5px;line-height:1.4;color:var(--muted);margin:-2px 0 8px';
      compHint.textContent = 'The single host list for BOTH the read-only Scan / Version Check and the destructive FIX cards below. Type / paste / Import TXT, or Import a C2C CSV (optional) to auto-load the non-compliant hosts. Every fixer is verify-first, so a host already compliant reports NO CHANGE.';
      compCard.appendChild(compHint);
      var targets = C.TargetManager({
        model: ctx.util.targetModel(''),
        hint: 'One host per line - comma/space/semicolon ok; # starts a comment. Drives the Scan, the Version Check and every Fix.',
        placeholder: 'WS-0001\nWS-0002\n# lab row\nWS-0003',
        importLabel: 'Import TXT', importAccept: '.txt',
        countNoun: 'computer',
        onImport: function (n, name) { log.append({ text: '[' + ts() + '] Added ' + n + ' computer(s) from ' + name, level: 'info' }); }
      });
      var tgHolder = el('div'); tgHolder.style.cssText = 'flex:1;min-height:0;display:flex'; tgHolder.appendChild(targets.el);
      compCard.appendChild(tgHolder);
      left.appendChild(compCard);

      // --- FIX PILLARS (dual-mode: manual Target list OR import-flagged; destructive; admin session) ---
      var fixCard = sectionCard('FIX PILLARS (per pillar - manual or import-scoped)', 'cyan');
      var fixIntro = el('div'); fixIntro.style.cssText = 'font-size:12px;line-height:1.4;color:var(--muted);margin-bottom:8px';
      fixIntro.textContent = 'DUAL MODE. With NO import (MANUAL): each pillar card fixes the hosts in Target Computers - load machines, type FIX, then Fix a pillar or check cards and RUN ALL. Import the C2C compliance CSV to switch to IMPORT-SCOPED: one card per flagged pillar, dialing ONLY the hosts the import flagged for that pillar (never the whole list) - click a host count to review them. Every fixer is verify-first (NO CHANGE where a host is already compliant). Requires an admin session.';
      fixCard.appendChild(fixIntro);

      // controls row (shared across every pillar card)
      var fixControls = el('div'); fixControls.style.cssText = 'display:flex;flex-direction:column;gap:8px;margin-bottom:8px';

      // prominent RUN ALL (union of every tab's checked hosts, each host getting the
      // pillars it is checked under)
      var runAllRow = el('div'); runAllRow.style.cssText = 'display:flex';
      var runAllBtn = ui.button('RUN ALL', { variant: 'danger', title: 'Fix every host in the CHECKED pillar cards, in one pass (destructive). Each host is fixed for exactly the pillars whose cards are checked. Verify-first: a host already compliant for a pillar reports NO CHANGE.' });
      runAllBtn.style.cssText += ';flex:1;font-weight:700';
      runAllBtn.onclick = function () { doRunAll(); };
      runAllRow.appendChild(runAllBtn);
      fixControls.appendChild(runAllRow);

      var ctlRow1 = el('div'); ctlRow1.style.cssText = 'display:flex;align-items:center;gap:8px;flex-wrap:wrap';
      var ctlSp = el('div'); ctlSp.style.flex = '1'; ctlRow1.appendChild(ctlSp);
      var fixCancelBtn = ui.button('CANCEL RUN', { size: 'sm', title: 'Cancel the in-flight fix run (queued targets skip; in-flight fixes finish).' });
      fixCancelBtn.disabled = true;
      fixCancelBtn.onclick = function () { if (run) { run.cancel(); log.append({ text: '[' + ts() + '] CANCEL requested - queued targets will skip; in-flight fixes finish.', level: 'warn' }); } };
      ctlRow1.appendChild(fixCancelBtn);
      fixControls.appendChild(ctlRow1);

      var ctlRow2 = el('div'); ctlRow2.style.cssText = 'display:flex;align-items:center;gap:8px;flex-wrap:wrap';
      ctlRow2.appendChild(ui.label('Confirm:'));
      var confirmInput = ui.input({ title: 'Type FIX (exactly) to arm any per-card fix or the run-all.' }); confirmInput.placeholder = 'type FIX'; confirmInput.style.width = '110px';
      ctlRow2.appendChild(confirmInput);
      ctlRow2.appendChild(ui.label('Max concurrent:'));
      var fixThreads = ui.number({ value: 8, min: 1, max: 16, title: 'Parallel hosts (1-16).' }); fixThreads.style.width = '68px';
      ctlRow2.appendChild(fixThreads);
      fixControls.appendChild(ctlRow2);

      var fixOffline = ui.checkbox('Attempt even if offline (host unreachable)', { title: 'Try a session even if the TCP 5985/5986/445 probe fails.' });
      fixOffline.style.margin = '0'; fixControls.appendChild(fixOffline);

      var fixWinrmHeal = ui.checkbox('Recover WinRM via RPC if 5985 is down (best-effort; often blocked - default off)', { title: 'Opt-in. For a host whose TCP 5985 probe fails, try remote SCM recovery over RPC (Get-Service / Start-Service / Set-Service Automatic against the target) then re-probe. RPC is frequently blocked on AFNET, so leave this off unless you know it is allowed. Never acts on the dispatcher host.' });
      fixWinrmHeal.style.margin = '0'; fixControls.appendChild(fixWinrmHeal);

      fixCard.appendChild(fixControls);

      // FIXABLE PILLARS header row (acas cardsHdrRow parity): label + Check All / Uncheck All.
      var fixCardsHdr = el('div'); fixCardsHdr.style.cssText = 'display:flex;align-items:center;gap:8px;margin-bottom:6px';
      var fixCardsHdrLbl = el('div', 'j-section-h', 'FIXABLE PILLARS'); fixCardsHdr.appendChild(fixCardsHdrLbl);
      var fchSp = el('div'); fchSp.style.flex = '1'; fixCardsHdr.appendChild(fchSp);
      var checkAllBtn = ui.ghostButton('Check All', { size: 'sm', title: 'Check every pillar card (include all in RUN ALL).' });
      var uncheckAllBtn = ui.ghostButton('Uncheck All', { size: 'sm', title: 'Uncheck every pillar card.' });
      checkAllBtn.onclick = function () { Object.keys(pillarCards).forEach(function (k) { var c = pillarCards[k]; if (c && c.cb) c.cb.checked = true; }); updateFixCounts(); };
      uncheckAllBtn.onclick = function () { Object.keys(pillarCards).forEach(function (k) { var c = pillarCards[k]; if (c && c.cb) c.cb.checked = false; }); updateFixCounts(); };
      fixCardsHdr.appendChild(checkAllBtn); fixCardsHdr.appendChild(uncheckAllBtn);
      fixCard.appendChild(fixCardsHdr);

      // per-pillar fix-card stack: a muted placeholder until an import loads it, then one
      // compact 'j-card' per fixable pillar WITH findings (rebuilt on each import). Each card's
      // host count opens a read-only drill-down; no inline grids.
      var fixBody = el('div'); fixBody.style.cssText = 'display:flex;flex-direction:column;gap:8px;min-height:0;overflow:auto;max-height:440px';
      fixCard.appendChild(fixBody);
      left.appendChild(fixCard);

      // --- LOCKSCREEN / WALLPAPER CACHE FIX (opt-in, destructive; admin session required) ---
      var lockCard = sectionCard('LOCKSCREEN / WALLPAPER CACHE FIX (opt-in, destructive)');
      var lockIntro = el('div'); lockIntro.style.cssText = 'font-size:12px;line-height:1.4;color:var(--muted);margin-bottom:8px';
      lockIntro.textContent = 'Clears the stuck quarantine lock screen / wallpaper after unquarantine: writes the Windows DEFAULT image into HKLM Personalization policy on each Target Computer - ONLY where no value is already set. Not a scored pillar; never part of the run-all. Uses the Type-FIX confirm, Max concurrent and offline options in FIX PILLARS above.';
      lockCard.appendChild(lockIntro);
      var lockArm = ui.checkbox('Arm the cache fix (writes HKLM policy only where unset - never overwrites)', { title: "Opt-in. On each target: LockScreenImage (lock screen) + DesktopImagePath/Url/Status (wallpaper) under HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization, pointed at the target's own default image (LockScreen.jpg -> img100.jpg; wallpaper img0.jpg). A value already set by an operator or GPO is NEVER overwritten." });
      lockArm.style.margin = '0 0 8px';
      lockArm._cb.addEventListener('change', function () { updateTargetButtons(); });
      lockCard.appendChild(lockArm);
      var lockBtn = ui.button('APPLY LOCKSCREEN / WALLPAPER FIX', { variant: 'gold', title: 'Run the cache fix on every host in Target Computers (destructive - writes HKLM policy). Only-if-unset: a host with both values already set reports NO CHANGE; no default image on the target reports SKIPPED.' });
      lockBtn.style.cssText += ';width:100%;font-weight:700';
      lockBtn.disabled = true;
      lockBtn.onclick = function () { doLockscreenFix(); };
      lockCard.appendChild(lockBtn);
      var lockFoot = el('div', 'muted', 'Requires an admin session + the FIX confirm above. FIXED / NO CHANGE / SKIPPED / FAILED stream into the results grid like every other fix.');
      lockFoot.style.cssText = 'font-size:11px;line-height:1.35;margin-top:6px';
      lockCard.appendChild(lockFoot);
      left.appendChild(lockCard);

      // --- JAVA CLEANUP (opt-in, destructive; admin session required) ---
      var javaCard = sectionCard('JAVA CLEANUP - REMOVE OUTDATED (opt-in, destructive)');
      var javaIntro = el('div'); javaIntro.style.cssText = 'font-size:12px;line-height:1.4;color:var(--muted);margin-bottom:8px';
      javaIntro.textContent = 'Removes Oracle/Sun Java OLDER than 8u491 from each Target Computer: installed products (msiexec, Oracle/Sun publisher only), JavaSoft registry residue (stale keys that keep vulnerability scanners flagging a host after Java is gone) and Program Files\\Java folders. OpenJDK / Temurin / Corretto and unparseable (UNKNOWN) versions are NEVER touched. Not a scored pillar; never part of the run-all. Uses the Type-FIX confirm, Max concurrent and offline options in FIX PILLARS above.';
      javaCard.appendChild(javaIntro);
      var javaArm = ui.checkbox('Arm the Java cleanup (uninstall + registry + folder removal of OLD Oracle/Sun Java only)', { title: 'Opt-in. OLD = below 1.8.0_491 (legacy 1.x families included). Uninstall via msiexec /x {GUID} /qn /norestart (no forced reboots; 3010 = reboot pending). Registry: old version subkeys under HKLM JavaSoft (native + WOW6432Node) removed, CurrentVersion repaired. Folders: old dirs under Program Files\\Java (in-use folders report FAILED). OpenJDK/Temurin/Corretto and UNKNOWN versions are never removed.' });
      javaArm.style.margin = '0 0 8px';
      javaArm._cb.addEventListener('change', function () { updateTargetButtons(); });
      javaCard.appendChild(javaArm);
      // audit 2026-07-25 (fable re-audit follow-up): the no-op label is NO JAVA REMOVED, not
      // "NO OLD JAVA" - since the vendor gate it can also mean OLD items were found but left
      // (publisher is not Oracle/Sun). The label must not assert the opposite of the Detail.
      var javaBtn = ui.button('REMOVE OUTDATED JAVA', { variant: 'gold', title: 'Run the Java cleanup on every host in Target Computers (destructive - uninstalls old Oracle/Sun Java and deletes its residue). A host where nothing was removed reports NO JAVA REMOVED - either nothing old was found, or what was found is not an Oracle/Sun product (the row Detail says which).' });
      javaBtn.style.cssText += ';width:100%;font-weight:700';
      javaBtn.disabled = true;
      javaBtn.onclick = function () { doJavaFix(); };
      javaCard.appendChild(javaBtn);
      var javaFoot = el('div', 'muted', 'Requires an admin session + the FIX confirm above. JAVA CLEANED / NO JAVA REMOVED / FAILED stream into the results grid like every other fix.');
      javaFoot.style.cssText = 'font-size:11px;line-height:1.35;margin-top:6px';
      javaCard.appendChild(javaFoot);
      left.appendChild(javaCard);

      // --- IMPORT C2C COMPLIANCE CSV (optional convenience; local parse, no admin gate) ---
      var importCard = sectionCard('IMPORT C2C COMPLIANCE CSV (optional)', 'cyan');
      var importIntro = el('div'); importIntro.style.cssText = 'font-size:12px;line-height:1.4;color:var(--muted);margin-bottom:8px';
      importIntro.textContent = 'OPTIONAL. Import the Tanium "C2C Compliance Status" CSV to auto-load its non-compliant hosts into Target Computers and pre-check + badge the pillars each host failed. Fixes never require this - it is a convenience.';
      importCard.appendChild(importIntro);
      var importFileInput = el('input'); importFileInput.type = 'file'; importFileInput.accept = '.csv,.txt'; importFileInput.style.display = 'none';
      var importBtn = ui.ctaButton('IMPORT C2C CSV', { title: 'Choose the Tanium C2C Compliance Status CSV export, upload it to the JANET Web host, and parse it (auto-load targets + badge pillars).' });
      importBtn.style.maxWidth = '260px';
      var importRow = el('div'); importRow.style.cssText = 'display:flex;gap:8px;align-items:center;flex-wrap:wrap'; importRow.appendChild(importBtn);
      // Escape hatch back to MANUAL targeting once a CSV has been imported (else you are stuck
      // in import-scoped mode until reload). Hidden until an import is live.
      var clearImportBtn = ui.ghostButton('Clear import (manual mode)', { size: 'sm', title: 'Drop the loaded C2C import and return the fix cards to MANUAL mode (dial the Target Computers list). Does not clear Target Computers.' });
      clearImportBtn.style.display = 'none';
      clearImportBtn.onclick = function () {
        if (isRunning()) return;
        importCsvPath = null; lastImport = null;
        importTiles.setAll({ total: 0, noncompliant: 0, fixable: 0, routed: 0 });
        importStatus.textContent = 'Import cleared - MANUAL mode.'; importStatus.className = 'muted';
        clearImportBtn.style.display = 'none';
        showFixPlaceholder();   // rebuild manual cards
        log.append({ text: '[' + ts() + '] Import cleared - fixes are MANUAL (dial the Target Computers list).', level: 'info' });
      };
      importRow.appendChild(clearImportBtn);
      importCard.appendChild(importRow); importCard.appendChild(importFileInput);
      // hero StatCards (populate after import)
      importTiles = C.StatCards({ cards: [
        { key: 'total', label: 'TOTAL HOSTS', color: 'cyan' },
        { key: 'noncompliant', label: 'NON-COMPLIANT', color: 'bad' },
        { key: 'fixable', label: 'FIXABLE HOSTS', color: 'accent' },
        { key: 'routed', label: 'ROUTED-ONLY', color: 'gold' }
      ] });
      importTiles.el.style.marginTop = '10px';
      importCard.appendChild(importTiles.el);
      var importStatus = el('div', 'muted', 'Idle.'); importStatus.style.cssText = 'margin-top:8px;font-size:12px';
      importCard.appendChild(importStatus);
      importFileInput.addEventListener('change', function () { if (importFileInput.files && importFileInput.files.length) doImport(); });
      importBtn.onclick = function () { if (isRunning()) return; importFileInput.value = ''; importFileInput.click(); };
      left.appendChild(importCard);

      // --- What this scans (read-only info) ---
      var infoCard = sectionCard('WHAT THIS SCANS - Comply-to-Connect (rule 3.B.2.B)', 'cyan');
      var intro = el('div'); intro.style.cssText = 'font-size:12.5px;line-height:1.45;color:var(--text);margin-bottom:8px';
      intro.textContent = 'One consolidated READ-ONLY probe per host (changes nothing) over WinRM, aligned to the '
        + 'C2C TASKORD 26-0822 dashboard. Only the 5 QUARANTINE pillars (Firewall, AntiMalware, Patches, '
        + 'Encryption, AQC/Vuln) predict quarantine; PKI Trust Roots + OS Version are AUDIT (shown, never '
        + 'quarantine) and AppWhitelist / Agents / COAMS are INFO (advisory). '
        + 'The same Target Computers list also drives the destructive FIX cards - Monitoring, Firewall, '
        + 'Encryption, AntiMalware, Patches and PKI Trust Roots - per pillar or all at once. '
        + 'Import the Tanium C2C Compliance report (optional) to auto-load targets + badge which pillar each host failed. '
        + 'Vuln routes to ACAS / Reports / KEV, OS Version to Windows Upgrade, STIG to Reports.';
      infoCard.appendChild(intro);
      var list = el('ol'); list.style.cssText = 'margin:0 0 8px 18px;padding:0;font-size:12px;line-height:1.5;color:var(--text)';
      CHECKS.forEach(function (c) {
        var li = el('li'); li.style.margin = '2px 0';
        var strong = el('span'); strong.style.cssText = 'font-weight:700;color:var(--text)'; strong.textContent = c[0] + ' - ';
        li.appendChild(strong);
        li.appendChild(document.createTextNode(c[1]));
        list.appendChild(li);
      });
      infoCard.appendChild(list);
      var verdictNote = el('div'); verdictNote.style.cssText = 'font-size:12px;line-height:1.45;color:var(--muted)';
      verdictNote.textContent = 'Verdict scores ONLY the QUARANTINE tier: '
        + 'QUARANTINE RISK (1+ quarantine-pillar fail) / NOT ATTESTING (only Tanium down - box invisible to the dashboard) / '
        + 'CHECK ERRORS (a quarantine check could not be evaluated) / READY (audit + info findings are shown as advisory, never quarantine). '
        + 'The full per-check report streams to the activity log ([QUARANTINE] fails in red, [AUDIT]/[INFO] as advisory).';
      infoCard.appendChild(verdictNote);
      left.appendChild(infoCard);

      // --- Scan options (attempt-offline + concurrency) ---
      var optCard = sectionCard('SCAN OPTIONS');
      var offlineCb = ui.checkbox('Attempt even if offline (host unreachable)', { title: 'Proceed against a host that fails the TCP 5985/5986/445 reachability probe (e.g. firewalled but WinRM up). Reachability is TCP-only - AFNET drops ICMP. A host answering only on 5986 uses WinRM-over-HTTPS.' });
      optCard.appendChild(offlineCb);
      var threadsRow = el('div'); threadsRow.style.cssText = 'display:flex;align-items:center;gap:10px;margin-top:8px';
      threadsRow.appendChild(ui.label('Max concurrent:'));
      var threadsInput = ui.number({ value: 16, min: 1, max: 64, title: 'Parallel hosts (1-64).' });
      threadsInput.style.width = '80px';
      threadsRow.appendChild(threadsInput);
      optCard.appendChild(threadsRow);
      left.appendChild(optCard);

      // --- VERSION CHECK (read-only; uses the Target Computers list above) ---
      var verCard = sectionCard('VERSION CHECK (read-only)', 'cyan');
      var verIntro = el('div'); verIntro.style.cssText = 'font-size:12px;line-height:1.4;color:var(--muted);margin-bottom:8px';
      verIntro.textContent = 'Read the 64/32-bit uninstall registry on each Target Computer for a product whose DisplayName contains the string below, and (optionally) compare its version to a target. Changes nothing. Streams into the same Results grid.';
      verCard.appendChild(verIntro);
      var verMatchRow = el('div'); verMatchRow.style.cssText = 'display:flex;align-items:center;gap:8px;margin-bottom:6px;flex-wrap:wrap';
      verMatchRow.appendChild(ui.label('DisplayName contains:'));
      var verMatchInput = ui.input({ title: 'Substring matched (case-insensitive) against each installed product DisplayName, e.g. "Google Chrome".' });
      verMatchInput.placeholder = 'Google Chrome';
      verMatchInput.style.cssText += ';flex:1;min-width:140px';
      verMatchRow.appendChild(verMatchInput);
      verCard.appendChild(verMatchRow);
      var verTgtRow = el('div'); verTgtRow.style.cssText = 'display:flex;align-items:center;gap:8px;margin-bottom:6px;flex-wrap:wrap';
      verTgtRow.appendChild(ui.label('Target version (optional):'));
      var verTgtInput = ui.input({ title: 'Optional. When set, the installed version is compared with System.Version (else an ordinal string compare) -> UP TO DATE / OUTDATED / NEWER. Leave blank for INSTALLED / NOT INSTALLED only.' });
      verTgtInput.placeholder = '130.0.6723.117';
      verTgtInput.style.cssText += ';flex:1;min-width:140px';
      verTgtRow.appendChild(verTgtInput);
      verCard.appendChild(verTgtRow);
      var verHeal = ui.checkbox('Recover WinRM via RPC if 5985 is down (best-effort; often blocked - default off)', { title: 'Opt-in. For a host whose TCP 5985 probe fails, try remote SCM recovery over RPC then re-probe before reading. RPC is frequently blocked on AFNET. Never acts on the dispatcher host.' });
      verHeal.style.margin = '0 0 8px'; verCard.appendChild(verHeal);
      var verBtn = ui.button('VERSION CHECK', { variant: 'cyan', size: 'sm', title: 'Read-only version check across the Target Computers list.' });
      verBtn.onclick = function () { doVersionCheck(); };
      verCard.appendChild(verBtn);
      left.appendChild(verCard);

      // --- Action bar (single Scan button via RunBar; read-only, NO admin-session guard) ---
      var actionCard = ui.card({}); actionCard.style.cssText += ';display:flex;flex-direction:column;gap:8px';
      var runbar = C.RunBar({
        label: 'C2C READINESS SCAN', cancelLabel: 'CANCEL SCAN IN PROGRESS', morphToCancel: true,
        title: 'Read-only C2C readiness probe across every computer (changes nothing).',
        guards: [
          function () { return targets.count() ? null : 'No Computers|Add at least one computer to the list before scanning.'; }
        ],
        onGuardFail: function (m) { var p = m.split('|'); ctx.confirm({ title: p[0], body: p[1] || p[0], okText: 'OK', cancelText: null }); },
        onRun: doRun,
        onCancel: function () { if (run) { run.cancel(); log.append({ text: '[' + ts() + '] CANCEL requested - queued targets will skip; in-flight probes finish.', level: 'warn' }); } }
      });
      var rbWrap = el('div'); rbWrap.appendChild(runbar.el);
      actionCard.appendChild(rbWrap);
      left.appendChild(actionCard);

      // ---------- RIGHT: RESULTS ----------
      var right = el('div'); right.style.cssText = 'flex:1;min-width:0;display:flex;flex-direction:column;min-height:0';
      var resultsCard = ui.card({}); resultsCard.style.cssText += ';flex:1;min-height:0;display:flex;flex-direction:column';
      var resHdr = el('div', 'j-section-h', 'RESULTS'); resHdr.style.marginBottom = '6px';
      resultsCard.appendChild(resHdr);
      var grid = C.ResultsGrid({
        title: 'C2C Nemesis results',
        emptyText: 'No results yet - add computers then Scan or Fix.',
        keyMode: { hostCol: 'Host' }, popOut: true,
        columns: [
          { key: 'Host', label: 'HOST', width: 170 },
          { key: 'Ping', label: 'PING', width: 90, render: function (r) { return { text: r.Ping == null ? '' : String(r.Ping), cls: pingCellCls(r.Ping) }; } },
          { key: 'Status', label: 'STATUS', width: 150, render: function (r) { return { text: r.Status == null ? '' : String(r.Status), cls: statusCellCls(r.Status) }; } },
          { key: 'Detail', label: 'DETAIL', render: function (r) { var t = r.Detail == null ? '' : String(r.Detail); return { text: t, title: t }; } }
        ],
        rowClass: function (r) {
          var s = String(r.Status);
          if (s === 'READY' || s === 'FIXED' || s === 'STARTED' || s === 'UP TO DATE' || s === 'INSTALLED') return 'row-ok';
          if (s === 'QUARANTINE RISK' || s === 'OFFLINE' || s === 'FAILED' || s === 'OUTDATED') return 'row-bad';
          if (s === 'CHECK ERRORS' || s === 'Cancelled' || s === 'ERROR' || s === 'DNS MISMATCH' || s === 'PARTIAL' || s === 'SKIPPED' || s === 'NOT INSTALLED') return 'row-warn';
          return '';
        }
      });
      var gridHolder = el('div'); gridHolder.style.cssText = 'flex:1;min-height:0;display:flex'; gridHolder.appendChild(grid.el);
      resultsCard.appendChild(gridHolder);
      right.appendChild(resultsCard);
      body.appendChild(right);

      // ---------- FOOTER: progress + export ----------
      var footer = el('div'); footer.style.cssText = 'display:flex;gap:14px;padding:12px 16px;min-height:150px;max-height:34%';
      var progCol = el('div'); progCol.style.cssText = 'flex:0 0 320px;display:flex;flex-direction:column;gap:8px';
      var progCard = ui.card({}); progCard.style.cssText += ';display:flex;flex-direction:column;gap:8px';
      var countLine = el('div'); countLine.style.cssText = 'font-family:var(--ui);font-weight:700;font-size:14px;color:var(--text)';
      countLine.textContent = '0 / 0';
      progCard.appendChild(countLine);
      var prog = C.ProgressStatusStrip({ showCount: true });
      progCard.appendChild(prog.el);
      var expRow = el('div'); expRow.style.cssText = 'display:flex;gap:8px';
      var exportBtn = ui.ghostButton('Export CSV', { size: 'sm', title: 'Export the per-host result rows to a CSV file.' });
      exportBtn.onclick = doExport;
      var clearBtn = ui.button('Clear', { variant: 'danger', size: 'sm', title: 'Clear the results grid + reset progress.' });
      clearBtn.onclick = function () { if (isRunning()) return; grid.clear(); prog.reset(); countLine.textContent = '0 / 0'; runbar.setStatus('', 'muted'); };
      expRow.appendChild(exportBtn); expRow.appendChild(clearBtn);
      progCard.appendChild(expRow);
      progCol.appendChild(progCard);
      footer.appendChild(progCol);
      root.appendChild(footer);

      // ---------- ACTIVITY LOG: full-width dock across the bottom ----------
      var logCard = ui.card({}); logCard.classList.add('j-logdock'); logCard.style.cssText += ';margin:0 16px 14px';
      var log = C.ActivityLog({ title: 'ACTIVITY LOG', defaultName: 'C2CReadiness_ActivityLog' });
      logCard.appendChild(log.el);
      root.appendChild(logCard);

      // =================== helpers ===================
      function sectionCard(title, headerColor) {
        var box = ui.card({});
        var h = el('div', 'j-section-h', title); h.style.marginBottom = '8px';
        if (headerColor === 'cyan') h.style.color = 'var(--cyan)';
        box.insertBefore(h, box.firstChild);
        return box;
      }
      function ts() { return ctx.util.clockStr(); }
      function isRunning() { return !!(run && run.state && run.state.active); }
      function threads() { return Math.max(1, Math.min(64, parseInt(threadsInput.value, 10) || 16)); }
      function threadsFix() { return Math.max(1, Math.min(16, parseInt(fixThreads.value, 10) || 8)); }
      var esc = Janet.util.esc;   // the single shared escaper (audit: local copy duplicated it)
      function alertDialog(title, bodyTxt) { ctx.confirm({ title: title, body: bodyTxt, okText: 'OK', cancelText: null }); }
      function keyByHost(ev) { return ev.Host != null ? String(ev.Host) : (ev.host != null ? String(ev.host) : null); }
      // Short name that PRESERVES an IPv4 literal (mirrors the backend Get-C2cShortHost). The
      // engine short-names every dial target, so seeding the results grid with short names keeps
      // display == dispatch (an FQDN-typed host would otherwise leave a phantom 'Queued' row that
      // the short-named result row never overwrites). IPv6 has no dots so split('.') keeps it whole.
      function shortHost(h) { h = String(h == null ? '' : h); return /^(\d{1,3}\.){3}\d{1,3}$/.test(h) ? h : h.split('.')[0]; }
      // Case-insensitive de-dupe of a short-named host list (one machine -> one grid row / one dial).
      function shortUniq(list) { var seen = {}, out = []; (list || []).forEach(function (h) { var s = shortHost(h); if (!s) return; var k = s.toLowerCase(); if (!seen[k]) { seen[k] = 1; out.push(s); } }); return out; }
      var NEED_TARGETS = 'Add hosts to Target Computers first (type / paste / Import TXT, or Import a C2C CSV to auto-load them).';

      function lockInputs(on) {
        offlineCb._cb.disabled = on; threadsInput.disabled = on; clearBtn.disabled = on;
        importBtn.disabled = on; clearImportBtn.disabled = on;
        verBtn.disabled = on; verMatchInput.disabled = on; verTgtInput.disabled = on; verHeal._cb.disabled = on;
        fixThreads.disabled = on; fixOffline._cb.disabled = on; confirmInput.disabled = on;
        fixWinrmHeal._cb.disabled = on;
        lockArm._cb.disabled = on;
        javaArm._cb.disabled = on;
        // Check All / Uncheck All must lock with the per-card checkboxes they drive, or a
        // mid-run click silently rewrites the checked set the NEXT run-all would dispatch.
        checkAllBtn.disabled = on; uncheckAllBtn.disabled = on;
        // per-card include checkbox + extras (Encryption ENABLE checkbox / PKI bundle input)
        Object.keys(pillarCards).forEach(function (k) {
          var c = pillarCards[k];
          if (c.cb) c.cb.disabled = on;
          if (c.enableCb) c.enableCb._cb.disabled = on;
          if (c.bundleInput) c.bundleInput.disabled = on;
        });
        // the shared cancel button is only usable WHILE a run is active.
        fixCancelBtn.disabled = !on;
        // per-card Fix buttons + run-all get their enabled state from the fix counts.
        updateFixCounts();
        // lockscreen / scan / version buttons still key off the Target Computers count.
        updateTargetButtons();
      }

      // Live-update every per-pillar Fix button + the RUN ALL label/enabled state. Mode-aware:
      // IMPORT mode - N = the pillar's FULL import-flagged count (frozen per card). MANUAL mode
      // (no import) - N = the LIVE Target Computers count for every pillar, and each checked
      // pillar maps every target host. Called on mount, on any card checkbox change, on Target
      // Computers edits, and whenever a run starts/stops (via lockInputs). Returns the union.
      function updateFixCounts() {
        var locked = isRunning();
        var manual = !importCsvPath;
        var tHosts = manual ? targets.hosts() : null;
        var manualN = manual ? tHosts.length : 0;
        var union = {};       // host -> { pillar: true }
        var totalPairs = 0;
        FIXABLE.forEach(function (k) {
          var c = pillarCards[k]; if (!c) return;
          var n = manual ? manualN : c.hosts.length;
          if (c.hostLbl) c.hostLbl.textContent = n + ' host' + (n === 1 ? '' : 's');
          if (c.fixBtn) {
            c.fixBtn.textContent = 'Fix ' + PILLAR_TAB[k] + ' on ' + n + ' host' + (n === 1 ? '' : 's');
            c.fixBtn.disabled = locked || n === 0;
          }
          if (c.cb && c.cb.checked) {
            (manual ? tHosts : c.hosts).forEach(function (h) { if (!h) return; (union[h] = union[h] || {})[k] = true; totalPairs++; });
          }
        });
        var hostCount = Object.keys(union).length;
        runAllBtn.textContent = 'RUN ALL - ' + hostCount + ' host' + (hostCount === 1 ? '' : 's') + ' / ' + totalPairs + ' pillar fix' + (totalPairs === 1 ? '' : 'es');
        runAllBtn.disabled = locked || totalPairs === 0;
        return { union: union, totalPairs: totalPairs, hostCount: hostCount, manual: manual };
      }

      // Lockscreen / scan / version still key off the Target Computers count (unchanged).
      function updateTargetButtons() {
        var n = targets.count();
        var locked = isRunning();
        lockBtn.textContent = 'APPLY LOCKSCREEN / WALLPAPER FIX (' + n + ' host' + (n === 1 ? '' : 's') + ')';
        lockBtn.disabled = locked || n === 0 || !lockArm._cb.checked;
        javaBtn.textContent = 'REMOVE OUTDATED JAVA (' + n + ' host' + (n === 1 ? '' : 's') + ')';
        javaBtn.disabled = locked || n === 0 || !javaArm._cb.checked;
      }

      // audit 2026-07-24: 'errors' was total-minus-the-rest, so NOT ATTESTING (Tanium down - the box
      // is INVISIBLE to the C2C dashboard, its own verdict) was silently reported as "CHECK ERRORS",
      // and neither counted as bad - a fleet where EVERY host was NOT ATTESTING closed the run green.
      // Each verdict now gets its own bucket, with an 'other' catch-all so a future status cannot
      // vanish into an arithmetic remainder.
      function summarize() {
        var t = { ready: 0, risk: 0, notAttesting: 0, errors: 0, offline: 0, other: 0, total: 0 };
        grid.rows().forEach(function (r) {
          var s = String(r.Status);
          if (s === 'READY') t.ready++;
          else if (s === 'QUARANTINE RISK') t.risk++;
          else if (s === 'NOT ATTESTING') t.notAttesting++;
          else if (s === 'CHECK ERRORS') t.errors++;
          else if (s === 'OFFLINE') t.offline++;
          else t.other++;
        });
        t.total = grid.rows().length;
        return t;
      }

      // ---- bind a streaming SCAN run handle to the grid/log/progress surfaces ----
      function bindRun(verb) {
        if (unsub) unsub();
        unsub = run.subscribe({
          status: function (t) { prog.setPhase(t); runbar.setStatus(t, 'st-info'); },
          progress: function (p) { prog.setProgress(p.done, p.total); countLine.textContent = p.done + ' / ' + p.total; },
          row: function (r) { grid.upsert(r); },
          log: function (l) { log.append(l); },
          error: function (e) { log.append({ text: '[' + ts() + '] ' + (e && e.text ? e.text : 'error'), level: 'err' }); },
          active: function (a) {
            runbar.setActive(a);
            if (!a) {
              lockInputs(false);
              var c = summarize();
              countLine.textContent = c.total + ' / ' + c.total;
              // audit 2026-07-24: every non-READY bucket marks the run bad. NOT ATTESTING, CHECK ERRORS
              // and anything unbucketed are all "we could not verify this host is compliant" - reported
              // up a chain of command, that must never close green.
              var bad = c.risk + c.offline + c.notAttesting + c.errors + c.other;
              log.append({ text: '[' + ts() + '] FINISHED ' + verb + '. READY=' + c.ready + '  QUARANTINE RISK=' + c.risk + '  NOT ATTESTING=' + c.notAttesting + '  CHECK ERRORS=' + c.errors + '  OFFLINE=' + c.offline + (c.other ? '  OTHER=' + c.other : ''), level: bad ? 'warn' : 'ok' });
              runbar.setStatus('Done - Ready ' + c.ready + ' / Risk ' + c.risk + ' / NotAttesting ' + c.notAttesting + ' / Errors ' + c.errors + ' / Offline ' + c.offline, bad ? 'st-bad' : 'st-ok');
            }
          }
        });
      }

      // ---- C2C Readiness Scan (read-only; no admin session, no confirm) ----
      function doRun() {
        if (isRunning()) return;
        var hosts = targets.hosts();
        grid.clear(); prog.reset(); countLine.textContent = '0 / ' + hosts.length;
        hosts.forEach(function (h) { grid.upsert({ Host: h, Ping: '', Status: 'Queued', Detail: 'Queued' }); });
        log.banner('C2C Readiness Scan on ' + hosts.length + ' computer(s)');
        lockInputs(true);
        run = ctx.run('scan', {
          targets: hosts.join('\n'),
          attemptOffline: offlineCb._cb.checked,
          threads: threads()
        }, { keyOf: keyByHost, destructive: false });
        bindRun('C2C Readiness Scan');
      }

      // ---- Version Check (read-only; no admin session, no confirm) ----
      function doVersionCheck() {
        if (isRunning()) return;
        var hosts = targets.hosts();
        if (!hosts.length) { alertDialog('No Computers', 'Add at least one computer to the Target Computers list before a version check.'); return; }
        var match = String(verMatchInput.value || '').trim();
        if (!match) { alertDialog('No product', 'Enter a DisplayName substring (e.g. Google Chrome) to check.'); return; }
        var tgt = String(verTgtInput.value || '').trim();
        grid.clear(); prog.reset(); countLine.textContent = '0 / ' + hosts.length;
        hosts.forEach(function (h) { grid.upsert({ Host: h, Ping: '', Status: 'Queued', Detail: 'Queued' }); });
        log.banner('C2C Version Check "' + match + '"' + (tgt ? ' vs ' + tgt : '') + ' on ' + hosts.length + ' computer(s)');
        lockInputs(true);
        run = ctx.run('version-check', {
          targets: hosts.join('\n'),
          productMatch: match,
          targetVersion: tgt,
          winrmHeal: verHeal._cb.checked,
          attemptOffline: offlineCb._cb.checked,
          threads: threads()
        }, { keyOf: keyByHost, destructive: false });
        bindVersionRun(match, tgt);
      }

      function bindVersionRun(match, tgt) {
        if (unsub) unsub();
        unsub = run.subscribe({
          status: function (t) { prog.setPhase(t); runbar.setStatus(t, 'st-info'); },
          progress: function (p) { prog.setProgress(p.done, p.total); countLine.textContent = p.done + ' / ' + p.total; },
          row: function (r) { grid.upsert(r); },
          log: function (l) { log.append(l); },
          error: function (e) { log.append({ text: '[' + ts() + '] ' + (e && e.text ? e.text : 'error'), level: 'err' }); },
          active: function (a) {
            runbar.setActive(a);
            if (!a) {
              lockInputs(false);
              var c = verTally();
              countLine.textContent = c.total + ' / ' + c.total;
              var bad = c.outdated + c.offline;
              log.append({ text: '[' + ts() + '] FINISHED version check "' + match + '"' + (tgt ? ' vs ' + tgt : '') + '. UP TO DATE=' + c.upToDate + '  OUTDATED=' + c.outdated + '  NEWER=' + c.newer + '  INSTALLED=' + c.installed + '  NOT INSTALLED=' + c.notInstalled + '  OFFLINE=' + c.offline, level: bad ? 'warn' : 'ok' });
              runbar.setStatus('Version check done - ' + (tgt ? ('UpToDate ' + c.upToDate + ' / Outdated ' + c.outdated + ' / Newer ' + c.newer) : ('Installed ' + c.installed + ' / Not ' + c.notInstalled)) + ' / Offline ' + c.offline, bad ? 'st-bad' : 'st-ok');
            }
          }
        });
      }

      function verTally() {
        var t = { upToDate: 0, outdated: 0, newer: 0, installed: 0, notInstalled: 0, offline: 0, total: 0 };
        grid.rows().forEach(function (r) {
          var s = String(r.Status);
          if (s === 'UP TO DATE') t.upToDate++;
          else if (s === 'OUTDATED') t.outdated++;
          else if (s === 'NEWER') t.newer++;
          else if (s === 'INSTALLED') t.installed++;
          else if (s === 'NOT INSTALLED') t.notInstalled++;
          else if (s === 'OFFLINE') t.offline++;
        });
        t.total = grid.rows().length;
        return t;
      }

      // ---- Import C2C Compliance CSV (optional convenience; read-only, no admin session) ----
      function doImport() {
        if (isRunning()) return;
        var files = importFileInput.files ? Array.prototype.slice.call(importFileInput.files) : [];
        if (!files.length) { alertDialog('No file', 'Choose the Tanium C2C Compliance Status CSV export first.'); return; }
        var f = files[0];
        if (/\.(xlsx|xlsm|xlsb|xls)$/i.test(f.name || '')) {
          alertDialog('Excel workbook - not a CSV', esc(f.name) + ' is an Excel workbook. The C2C import must be a CSV - re-export from Tanium (or Save As -> CSV UTF-8), then import that.');
          return;
        }
        importStatus.textContent = 'Uploading ' + f.name + ' ...'; importStatus.className = 'st-info';
        log.banner('Import C2C Compliance CSV: ' + f.name);
        ctx.uploadFile(f).then(function (p) {
          log.append({ text: 'Uploaded to host: ' + p, level: 'dim' });
          // Hold the uploaded path LOCALLY until the parse actually applies. It only becomes
          // importCsvPath (re-sent with every per-pillar fix + run-all) once the summary is
          // applied. A FAILED re-import must not leave importCsvPath pointing at the broken
          // CSV while the pillar cards still show the previous import (UI/dispatch divergence).
          var pendingCsvPath = p;
          importStatus.textContent = 'Parsing ' + f.name + ' ...'; importStatus.className = 'st-info';
          run = ctx.run('import', { csvPath: p });
          if (unsub) unsub();
          unsub = run.subscribe({
            status: function (t) { importStatus.textContent = t; },
            row: function () {},   // import rows drive the tiles/log + per-pillar cards, not the results grid
            log: function (l) { log.append(l); },
            error: function (e) {
              importStatus.textContent = 'Import failed'; importStatus.className = 'st-bad';
              log.append({ text: '[' + ts() + '] ' + (e && e.text ? e.text : 'error'), level: 'err' });
              // A failed re-import invalidates the previous targeting state: clear the path
              // and rebuild the MANUAL cards so UI and dispatch state agree.
              importCsvPath = null; clearImportBtn.style.display = 'none'; showFixPlaceholder();
            },
            active: function (a) { importBtn.disabled = a; },
            // The run bus delivers the action's return value ({rows,summary}) as the
            // 'final' payload (RunController.reduce -> dispatch(key,'final',ev.result)),
            // so res.summary is the import summary. Guarded so a bad/empty payload logs
            // instead of silently doing nothing (dispatch swallows handler throws).
            final: function (res) {
              try {
                importCsvPath = pendingCsvPath;   // set BEFORE building cards so they build import-scoped (not manual)
                applyImportSummary((res && res.summary) || {});
                updateFixCounts();                // reflect import-scoped state in the fix-button counts
                clearImportBtn.style.display = '';   // offer the escape back to MANUAL mode
              }
              catch (err) {
                importCsvPath = null; clearImportBtn.style.display = 'none'; showFixPlaceholder();   // roll back so UI/dispatch agree
                importStatus.textContent = 'Import parsed but the summary could not be applied.'; importStatus.className = 'st-bad';
                log.append({ text: '[' + ts() + '] Import summary apply error: ' + (err && err.message ? err.message : err), level: 'err' });
              }
            }
          });
        }).catch(function (e) {
          importStatus.textContent = 'Upload failed: ' + (e && e.message); importStatus.className = 'st-bad';
          log.append({ text: 'Upload failed: ' + (e && e.message), level: 'err' });
        });
      }

      // Import loads one CARD per fixable pillar (each fixing ALL that pillar's flagged
      // hosts; the host count opens a read-only drill-down). It also keeps its legacy
      // conveniences: hero tiles, auto-loading the non-compliant hosts into Target Computers
      // (for the read-only Scan + the Lockscreen fix), and logging the audit + routed findings.
      function applyImportSummary(s) {
        lastImport = s || {};
        var pillars = (s && s.pillars) ? s.pillars : [];
        var byName = {}; pillars.forEach(function (p) { if (p && p.name != null) byName[p.name] = p; });
        var auditPillars = (s && s.auditPillars) ? s.auditPillars : [];
        var auditByName = {}; auditPillars.forEach(function (p) { if (p && p.name != null) auditByName[p.name] = p; });

        // hero tiles
        var runAllPlan = (s && s.runAllPlan && s.runAllPlan.length) ? s.runAllPlan.length : 0;
        var nonCompliant = (s && s.nonCompliant) || 0;
        var routedOnly = Math.max(0, nonCompliant - runAllPlan);
        importTiles.setAll({ total: (s && s.total) || 0, noncompliant: nonCompliant, fixable: runAllPlan, routed: routedOnly });
        importStatus.textContent = 'Imported ' + ((s && s.total) || 0) + ' host(s): ' + ((s && s.compliant) || 0) + ' compliant, ' + nonCompliant + ' non-compliant.';
        importStatus.className = 'st-ok';

        // (a) auto-load hosts into Target Computers (merge, never clobber): the non-compliant
        // hosts PLUS any audit-only hosts (e.g. compliant boxes failing the PKI audit). This
        // still feeds the read-only Scan + the Lockscreen fix (they dial Target Computers).
        var flaggedHosts = (s && s.nonCompliantHosts && s.nonCompliantHosts.length) ? s.nonCompliantHosts.slice() : [];
        var auditSeen = {}; flaggedHosts.forEach(function (h) { auditSeen[String(h).toLowerCase()] = true; });
        auditPillars.forEach(function (p) {
          (p && p.hosts ? p.hosts : []).forEach(function (h) { var k = String(h).toLowerCase(); if (!auditSeen[k]) { auditSeen[k] = true; flaggedHosts.push(h); } });
        });
        if (flaggedHosts.length) {
          var existing = targets.hosts();
          var seen = {}; existing.forEach(function (h) { seen[String(h).toLowerCase()] = true; });
          var added = 0;
          flaggedHosts.forEach(function (h) { var k = String(h).toLowerCase(); if (!seen[k]) { seen[k] = true; existing.push(h); added++; } });
          targets.setText(existing.join('\n'));
          log.append({ text: '[' + ts() + '] Loaded ' + flaggedHosts.length + ' non-compliant host(s) into Target Computers (' + added + ' new).', level: 'accent' });
        }

        // (b) build the per-pillar fix cards from the run-all plan (rebuilt each import).
        buildPillarCards(s);

        // (c) audit-rule findings (advisory - never quarantine)
        var auditTxt = auditPillars.map(function (p) {
          return (p && (p.failedCount || 0) > 0) ? (p.name + ' ' + p.failedCount + ' (audit -> ' + (p.routing || 'review') + ')') : null;
        }).filter(Boolean);
        if (auditTxt.length) log.append({ text: '[' + ts() + '] AUDIT findings (advisory, non-quarantine): ' + auditTxt.join('  |  '), level: 'info' });

        // (d) routed-elsewhere info notes
        var routedTxt = ROUTED.map(function (m) {
          var p = byName[m.key] || auditByName[m.key]; var c = p ? (p.failedCount || 0) : 0;
          return c > 0 ? (m.label + ' ' + c + ' -> ' + m.route) : null;
        }).filter(Boolean);
        if (routedTxt.length) log.append({ text: '[' + ts() + '] Routed elsewhere: ' + routedTxt.join('  |  '), level: 'info' });
      }

      // MANUAL-mode fix cards, shown whenever NO C2C CSV is imported. Every fixable pillar gets
      // a card whose host set is the LIVE Target Computers list (not an import subset) - its Fix
      // and RUN ALL dial exactly those. This is the "load machines + run a manual C2C patch"
      // path; the backend runs in manual mode (no import allow-list) when no csvPath is sent.
      function showFixPlaceholder() {
        fixBody.innerHTML = ''; pillarCards = {};
        // Entering MANUAL mode (mount / FAILED re-import / explicit Clear import) RE-ARMS from
        // scratch: clear the FIX confirm word and the persisted ENABLE-BitLocker tick. Without this
        // a failed re-import would fall open into MANUAL with the previous import's auto-loaded hosts
        // still in Target Computers AND a live "FIX" + ENABLE tick - a near one-click destructive run.
        if (confirmInput) confirmInput.value = '';
        encEnableChecked = false;
        var intro = el('div', 'muted', 'MANUAL MODE - no C2C import. Each pillar below fixes the hosts in Target Computers (verify-first: an already-compliant host reports NO CHANGE). Check pillars then RUN ALL, or Fix one pillar. Import a C2C CSV to switch to import-scoped targeting (dial only the flagged hosts).');
        intro.style.cssText = 'font-size:11.5px;line-height:1.45;padding:9px 10px;margin-bottom:2px;border:1px dashed var(--edge);border-radius:4px';
        fixBody.appendChild(intro);
        var live = targets.hosts();
        FIXABLE.forEach(function (k) { fixBody.appendChild(buildPillarCard(k, live, {}, true)); });
        updateFixCounts(); updateTargetButtons();
      }

      // Build one compact fix CARD per fixable pillar WITH findings, from the run-all plan
      // (host -> its fixable pillars). Each pillar keeps its FULL import-flagged host list
      // (import order) + a via map (failed / audit) for the drill-down. Rebuilt from scratch
      // on each import (imports replace state).
      function buildPillarCards(s) {
        fixBody.innerHTML = ''; pillarCards = {};
        var plan = (s && s.runAllPlan) ? s.runAllPlan : [];
        var perPillar = {};   // pillar -> { hosts: [import order], via: { host -> 'failed'|'audit' } }
        plan.forEach(function (entry) {
          var host = entry && entry.host; if (!host) return;
          var pil = (entry.pillars || []);
          var aud = (entry.auditPillars || []);
          pil.forEach(function (p) {
            var pp = perPillar[p] = perPillar[p] || { hosts: [], via: {} };
            if (pp.via[host] === undefined) pp.hosts.push(host);
            pp.via[host] = (aud.indexOf(p) >= 0) ? 'audit' : 'failed';
          });
        });

        var built = 0;
        FIXABLE.forEach(function (k) {
          var pp = perPillar[k];
          if (!pp || !pp.hosts.length) return;
          fixBody.appendChild(buildPillarCard(k, pp.hosts, pp.via));
          built++;
        });

        if (!built) {
          var none = el('div', 'muted', 'No endpoint-fixable pillar had a flagged host in this import (Vuln / OS Version / STIG route to other tools - see the activity log).');
          none.style.cssText = 'font-size:12px;line-height:1.45;padding:14px 8px;text-align:center;border:1px dashed var(--edge);border-radius:4px';
          fixBody.appendChild(none);
        }
        updateFixCounts();
      }

      // One compact fix card (acas buildVulnCard idiom): row1 = include-checkbox + title/pills/
      // desc + a clickable host-count that opens the read-only drill-down; the pillar extras
      // (Encryption ENABLE / PKI bundle); row2 = the Fix button. Registered in pillarCards so
      // the shared controls + RUN ALL read its state. The Fix dials the pillar's FULL flagged set.
      function buildPillarCard(key, hosts, via, manual) {
        var meta = FIX_META[key];
        var failedCount = 0, auditCount = 0;
        hosts.forEach(function (h) { if (via[h] === 'audit') auditCount++; else failedCount++; });

        var box = el('div', 'j-card');
        box.style.cssText += ';position:relative;padding:10px 12px';

        // row 1: include-checkbox + text (title + pills + desc) + right column (host count)
        var r1 = el('div'); r1.style.cssText = 'display:flex;align-items:flex-start;gap:8px';
        var cb = el('input'); cb.type = 'checkbox'; cb.checked = false; cb.style.marginTop = '3px';
        cb.title = 'Include this pillar in RUN ALL.';
        cb.addEventListener('change', function () { updateFixCounts(); });
        r1.appendChild(cb);

        var textWrap = el('div'); textWrap.style.cssText = 'flex:1;min-width:0';
        var badges = el('div'); badges.style.cssText = 'display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-bottom:3px';
        var titleLbl = el('span'); titleLbl.style.cssText = 'font-family:var(--mono);font-size:13px;color:var(--text);font-weight:700';
        titleLbl.textContent = PILLAR_TAB[key];
        badges.appendChild(titleLbl);
        if (manual) {
          var manPill = ui.pill('manual');
          manPill.style.cssText += ';background:transparent;border:1px solid var(--cyan,#3aa0c0);color:var(--cyan,#3aa0c0)';
          badges.appendChild(manPill);
        } else {
          var failPill = ui.pill(failedCount + ' failed');
          failPill.style.cssText += ';background:transparent;border:1px solid var(--sev-crit,#E0505A);color:var(--sev-crit,#E0505A)';
          badges.appendChild(failPill);
          if (auditCount > 0) {
            var auditPill = ui.pill(auditCount + ' audit');
            auditPill.style.cssText += ';background:transparent;border:1px solid var(--gold,#d0a848);color:var(--gold,#d0a848)';
            badges.appendChild(auditPill);
          }
        }
        textWrap.appendChild(badges);
        var desc = el('div', 'muted', meta.desc); desc.style.cssText = 'font-size:11.5px;line-height:1.35;overflow:hidden;text-overflow:ellipsis';
        textWrap.appendChild(desc);
        r1.appendChild(textWrap);

        // right column: clickable host-count label -> read-only drill-down
        var right = el('div'); right.style.cssText = 'display:flex;flex-direction:column;align-items:flex-end;gap:5px;flex:0 0 auto';
        var hostLbl = el('div'); hostLbl.style.cssText = 'font-family:var(--mono);font-size:11px;color:var(--cyan);cursor:pointer;text-decoration:underline dotted';
        hostLbl.textContent = hosts.length + ' host' + (hosts.length === 1 ? '' : 's');
        hostLbl.title = manual ? 'Click to review the Target Computers this Fix will dial.' : 'Click to review the import-flagged host list.';
        hostLbl.onclick = function () { showPillarHosts(key); };
        right.appendChild(hostLbl);
        r1.appendChild(right);
        box.appendChild(r1);

        var entry = pillarCards[key] = { hosts: hosts.slice(), via: via, manual: !!manual, cb: cb, fixBtn: null, hostLbl: hostLbl, enableCb: null, bundleInput: null };

        // Encryption extra: the ENABLE-BitLocker opt-in (stays on its pillar's card)
        if (key === 'Encryption') {
          var enc = ui.checkbox('ENABLE BitLocker on ALL FullyDecrypted FIXED volumes - OS + DATA (XtsAes256)', { title: 'Opt-in. Starts XtsAes256 FULL-VOLUME encryption on EVERY FullyDecrypted FIXED volume: the OS volume (TPM protector) AND fixed DATA volumes such as D:, E: (recovery-password protector, NO TPM, plus BitLocker auto-unlock). Every volume escrows its recovery key FIRST (Entra-first, AD fallback) and is fail-closed - if escrow fails the protector is removed and encryption is NEVER started. Removable / USB drives are never touched. Applies to this pillar Fix AND to RUN ALL.' });
          enc._cb.checked = encEnableChecked;
          enc._cb.onchange = function () { encEnableChecked = enc._cb.checked; };
          enc.style.margin = '6px 0 0';
          box.appendChild(enc);
          entry.enableCb = enc;
        }
        // PKI extra: the DoD trust-bundle folder path (stays on its pillar's card)
        if (key === 'PkiRoots') {
          var pr = el('div'); pr.style.cssText = 'display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-top:6px';
          pr.appendChild(ui.label('Cert bundle folder:'));
          var bi = ui.input({ title: 'Server-readable path (e.g. a UNC path) to the DoD trust bundle folder holding root\\*.cer, Intermediate\\*.cer, Untrusted\\*.cer (and/or loose *.cer -> Root). Certs are added ADDITIVELY to LocalMachine Root/CA/Disallowed. LEAVE BLANK to use the SHIPPED DoD bundle (Packages\\DoD-Certs).' });
          bi.placeholder = 'leave blank -> shipped DoD bundle (Packages\\DoD-Certs)';
          bi.value = pkiBundleValue;
          bi.style.cssText += ';flex:1;min-width:220px;font-size:11.5px';
          bi.addEventListener('input', function () { pkiBundleValue = String(bi.value || ''); });
          pr.appendChild(bi);
          box.appendChild(pr);
          entry.bundleInput = bi;

          // Two OPT-IN companions (both default UNCHECKED). The core additive bundle install
          // always runs; these destructive extras run ONLY when ticked. Shared contract with
          // the certdeploy tool: prunePki / fixRdp.
          var pruneCb = ui.checkbox('Prune expired retired DoD intermediates', { title: 'Opt-in (default OFF). Prunes EXPIRED retired DoD intermediates from the CA store ONLY when the subject matches the retired DOD EMAIL/ID/SW/DERILITY CA-n allowlist AND it is not one of the four legacy-keep intermediates this tool intentionally pushes. Roots, machine identity and timestamping certs are never touched.' });
          pruneCb._cb.checked = pkiPruneChecked;
          pruneCb._cb.onchange = function () { pkiPruneChecked = pruneCb._cb.checked; };
          pruneCb.style.margin = '6px 0 0';
          box.appendChild(pruneCb);
          entry.pruneCb = pruneCb;

          var rdpCb = ui.checkbox('Repair broken RDP listener', { title: 'Opt-in (default OFF). Rebinds a BROKEN RDP-tcp listener certificate (self-signed / expired / missing) to the newest valid CA-issued My-store cert matching the host. The replacement is located BEFORE anything is cleared (no candidate = left untouched, SKIP); a healthy CA-issued listener is never touched.' });
          rdpCb._cb.checked = pkiRdpChecked;
          rdpCb._cb.onchange = function () { pkiRdpChecked = rdpCb._cb.checked; };
          rdpCb.style.margin = '4px 0 0';
          box.appendChild(rdpCb);
          entry.rdpCb = rdpCb;

          // THIRD opt-in (audit 2026-07-25, fable re-audit follow-up): the bundle's Untrusted\
          // group is pushed into LocalMachine\Disallowed, which BLACKLISTS those certs fleet-wide
          // - the opposite direction to the roots this card installs, and not what the TASKORD PKI
          // rule scores. It used to ride along unconditionally; it is now armed on its own, default
          // OFF, matching the certdeploy tool's pushDisallowed.
          var distrustCb = ui.checkbox('Also BLACKLIST the bundle Untrusted certs (DISTRUST)', { title: 'Opt-in (default OFF). Adds the bundle Untrusted\\*.cer group to the LocalMachine Disallowed store on every target - a fleet-wide BLACKLIST (DISTRUST) of those certs, NOT a trust add. Unticked, only the Root/CA trust anchors are pushed and the Untrusted certs are never delivered to any host.' });
          distrustCb._cb.checked = pkiDistrustChecked;
          distrustCb._cb.onchange = function () { pkiDistrustChecked = distrustCb._cb.checked; };
          distrustCb.style.margin = '4px 0 0';
          box.appendChild(distrustCb);
          entry.distrustCb = distrustCb;

          // Prominent one-click: install the DoD trust roots on the flagged hosts in one obvious
          // click (same path + guards as the card's Fix button - type-FIX confirm, admin gate,
          // self-guard - honouring the current bundle folder + the two boxes above).
          var oneClick = ui.button('FIX PKI TRUST ROOTS', { variant: 'gold', title: 'One-click: install the DoD trust roots on the flagged hosts (destructive). Uses the bundle folder above (blank = shipped DoD default) and the two opt-in boxes. Same guards as the Fix button: type FIX to confirm, admin session, self-guard.' });
          oneClick.style.cssText += ';margin-top:8px;width:100%';
          oneClick.onclick = function () { doPillarFix('PkiRoots'); };
          box.appendChild(oneClick);
          var hint = el('div'); hint.style.cssText = 'font-size:10.5px;color:var(--text-dim);margin-top:4px';
          hint.textContent = 'One-click: install the DoD trust roots on the flagged hosts.';
          box.appendChild(hint);
        }

        // row 2: the Fix button (dials the pillar's FULL import-flagged host set)
        var r2 = el('div'); r2.style.cssText = 'display:flex;align-items:center;gap:8px;margin-top:8px';
        var sp = el('div'); sp.style.flex = '1'; r2.appendChild(sp);
        var fixBtn = ui.button('Fix ' + PILLAR_TAB[key] + ' on ' + hosts.length + ' host' + (hosts.length === 1 ? '' : 's'), { variant: 'danger', size: 'sm', title: 'Run the ' + meta.label + ' remediation on ' + (manual ? 'the Target Computers list' : 'ALL ' + hosts.length + ' import-flagged host(s) for this pillar') + ' (destructive). Verify-first: a host already compliant reports NO CHANGE.' });
        fixBtn.onclick = function () { doPillarFix(key); };
        r2.appendChild(fixBtn);
        box.appendChild(r2);
        entry.fixBtn = fixBtn;

        return box;
      }

      // Read-only drill-down: review the exact host set a pillar Fix will dial. IMPORT mode ->
      // the frozen import-flagged set; MANUAL mode -> the LIVE Target Computers list.
      function showPillarHosts(key) {
        var c = pillarCards[key]; if (!c) return;
        var manual = c.manual;
        var hosts = manual ? targets.hosts() : (c.hosts || []);
        var via = manual ? {} : (c.via || {});
        var body = el('div');
        var d = el('div'); d.style.cssText = 'font-size:11.5px;color:var(--text-dim);margin-bottom:8px';
        d.textContent = manual
          ? hosts.length + ' Target Computer(s). Fix ' + PILLAR_TAB[key] + ' dials these (verify-first).'
          : hosts.length + ' import-flagged host(s). Fix ' + PILLAR_TAB[key] + ' dials ONLY these.';
        body.appendChild(d);
        var listBox = el('div'); listBox.style.cssText = 'max-height:300px;overflow:auto;font-family:var(--mono);font-size:11.5px;border:1px solid var(--edge);border-radius:3px;padding:6px 8px;background:var(--bg)';
        if (hosts.length) {
          hosts.forEach(function (h) {
            var r = el('div'); r.textContent = h;
            if (via[h] === 'audit') { var a = el('span', 'muted', '  (audit)'); r.appendChild(a); }
            listBox.appendChild(r);
          });
        } else { var em = el('div', 'muted'); em.textContent = manual ? '(no hosts - add computers to Target Computers)' : '(no hosts flagged - re-import the C2C CSV)'; listBox.appendChild(em); }
        body.appendChild(listBox);
        ctx.confirm({ title: (manual ? 'Target Computers - ' : 'Import-flagged hosts - ') + PILLAR_TAB[key], body: body, okText: 'Close', cancelText: null });
      }

      // ---- Per-pillar fix (DESTRUCTIVE; admin session + FIX confirm) ----
      // IMPORT mode: dials the pillar's FULL import-flagged set (re-sending the CSV so the engine
      // re-derives + intersects - a host not flagged for the pillar is dropped server-side).
      // MANUAL mode (no import): dials the LIVE Target Computers list, no csvPath -> the engine
      // runs manual mode and dials exactly those hosts for this pillar.
      async function doPillarFix(key) {
        if (isRunning()) return;
        var meta = FIX_META[key];
        var c = pillarCards[key];
        var manual = !importCsvPath;
        // Short-name + de-dupe the dial list so display == dispatch (the engine short-names every
        // target). Import hosts are already short/unique; manual hosts (typed) may be FQDNs.
        var hosts = shortUniq(manual ? targets.hosts() : ((c && c.hosts) ? c.hosts.slice() : []));
        if (!hosts.length) { alertDialog('No hosts', manual ? NEED_TARGETS : 'No import-flagged hosts for the ' + PILLAR_TAB[key] + ' pillar.'); return; }
        if (!ctx.session.state.credSet) { alertDialog('Admin session required', 'Set ADW credentials (top-right) and start an admin session before running a fix - it changes machines.'); return; }
        if (confirmInput.value !== 'FIX') { alertDialog('Type FIX to Confirm', 'Type FIX (exactly, uppercase) in the Confirm box to arm the destructive fix.'); return; }
        var bundleFolder = (c && c.bundleInput) ? String(c.bundleInput.value || '').trim() : '';
        var enableEnc = key === 'Encryption' && c && c.enableCb && c.enableCb._cb.checked;
        var pkiPrune = key === 'PkiRoots' && c && c.pruneCb && c.pruneCb._cb.checked;
        var pkiRdp = key === 'PkiRoots' && c && c.rdpCb && c.rdpCb._cb.checked;
        var pkiDistrust = key === 'PkiRoots' && c && c.distrustCb && c.distrustCb._cb.checked;
        var scopeTxt = manual ? 'Target Computer(s)' : 'import-flagged host(s) for ' + PILLAR_TAB[key];

        var pf = [
          { label: hosts.length + ' ' + scopeTxt + (manual ? ' (MANUAL mode - no import scoping)' : ''), ok: hosts.length > 0 },
          { label: 'Admin session (' + (ctx.session.state.user || 'session') + ')', ok: !!ctx.session.state.credSet },
          { label: 'Verify-first: a host already compliant for ' + meta.label + ' reports NO CHANGE', ok: true }
        ];
        if (key === 'Encryption') pf.push({ label: enableEnc ? 'ENABLE BitLocker: WILL start XtsAes256 encryption on EVERY FullyDecrypted FIXED volume (OS + DATA; removable/USB untouched)' : 'Resume-only (ENABLE not ticked)', ok: true });
        if (key === 'PkiRoots') pf.push({ label: 'Cert bundle: ' + (bundleFolder || 'shipped DoD default (Packages\\DoD-Certs)'), ok: true });
        if (key === 'PkiRoots') pf.push({ label: 'Prune expired retired DoD intermediates: ' + (pkiPrune ? 'YES (opt-in ticked)' : 'no (default off)'), ok: true });
        if (key === 'PkiRoots') pf.push({ label: 'Repair broken RDP listener: ' + (pkiRdp ? 'YES (opt-in ticked)' : 'no (default off)'), ok: true });
        // audit 2026-07-25: the distrust push is the one trust change that goes the OTHER way -
        // surface it in the arm dialog exactly like certdeploy does, armed or not.
        if (key === 'PkiRoots') pf.push({ label: pkiDistrust ? 'BLACKLIST Untrusted certs into Disallowed: YES - this DISTRUSTS them fleet-wide' : 'BLACKLIST Untrusted certs into Disallowed: no (default off) - only Root/CA are pushed', ok: true });
        if (key === 'PkiRoots') pf.push({ label: 'Trust-anchor guard: a non-CA (leaf) cert is REFUSED from Root/CA and never installed', ok: true });
        if (fixWinrmHeal._cb.checked) pf.push({ label: 'WinRM-heal (RPC) armed for unreachable hosts', ok: true });

        var ok = await ctx.arm({
          title: 'Arm Fix ' + meta.label,
          banner: 'DESTRUCTIVE - THIS CHANGES LIVE MACHINES',
          body: 'About to run <b>Fix ' + esc(meta.label) + '</b> on <b>' + hosts.length + '</b> ' + scopeTxt + '.'
            + (manual ? '<br><b>MANUAL mode</b> (no C2C import): this dials exactly the hosts in Target Computers - there is no import allow-list.' : '')
            + '<br>This fixer is <b>verify-first</b>: a host already compliant for this pillar is reported NO CHANGE and left untouched.'
            + (key === 'PkiRoots' && pkiDistrust ? '<br><b>BLACKLIST armed:</b> the bundle\'s <b>Untrusted\\</b> certs will also be added to the LocalMachine <b>Disallowed</b> store on every target - that <b>DISTRUSTS</b> them fleet-wide (the opposite direction to the roots being installed). Untick it to push Root/CA only.' : '')
            + (enableEnc ? '<br><b>ENABLE BitLocker:</b> this run will START XtsAes256 FULL-VOLUME encryption on <b>every FullyDecrypted FIXED volume</b> of the <b>' + hosts.length + '</b> host(s) - the OS volume (TPM) AND fixed DATA volumes (D:, E:, ... via recovery-password + AD/Entra escrow + auto-unlock). Removable / USB drives are never touched. Escrow-first, fail-closed; the OS volume needs TPM-ready + domain-joined. Encryption runs for hours in the background.' : ''),
          preflight: pf, okText: 'Run Fix ' + meta.label, cancelText: 'Cancel'
        });
        if (!ok) { log.append({ text: '[' + ts() + '] Fix ' + meta.label + ' cancelled at the arming dialog.', level: 'warn' }); return; }

        grid.clear(); prog.reset(); countLine.textContent = '0 / ' + hosts.length;
        hosts.forEach(function (h) { grid.upsert({ Host: h, Ping: '', Status: 'Queued', Detail: 'Queued' }); });
        log.banner('C2C Fix ' + meta.label + ' on ' + hosts.length + ' ' + (manual ? 'target host(s) [MANUAL]' : 'import-flagged host(s)'));
        lockInputs(true);
        var params = { targets: hosts.join('\n'), confirm: confirmInput.value, threads: threadsFix(), attemptOffline: fixOffline._cb.checked, winrmHeal: fixWinrmHeal._cb.checked };
        if (!manual) params.csvPath = importCsvPath;   // omit csvPath -> engine runs MANUAL mode
        if (key === 'Encryption') params.enableEncryption = enableEnc;
        if (key === 'PkiRoots') { params.certBundleFolder = bundleFolder; params.prunePki = pkiPrune; params.fixRdp = pkiRdp; params.pushDisallowed = pkiDistrust; }
        run = ctx.run(meta.action, params, { keyOf: keyByHost, destructive: true });
        bindFixRun();
      }

      // ---- Lockscreen / Wallpaper cache fix (opt-in utility; DESTRUCTIVE; TARGET-driven;
      // admin session + FIX confirm + arm checkbox). Not a scored pillar - never in run-all. ----
      async function doLockscreenFix() {
        if (isRunning()) return;
        var hosts = shortUniq(targets.hosts());   // engine short-names each target; keep display == dispatch
        if (!hosts.length) { alertDialog('No target hosts', NEED_TARGETS); return; }
        if (!lockArm._cb.checked) { alertDialog('Not armed', 'Tick "Arm the cache fix" checkbox first - this utility is opt-in.'); return; }
        if (!ctx.session.state.credSet) { alertDialog('Admin session required', 'Set ADW credentials (top-right) and start an admin session before running a fix - it changes machines.'); return; }
        if (confirmInput.value !== 'FIX') { alertDialog('Type FIX to Confirm', 'Type FIX (exactly, uppercase) in the Confirm box to arm the destructive fix.'); return; }

        var pf = [
          { label: hosts.length + ' target host(s) queued', ok: hosts.length > 0 },
          { label: 'Admin session (' + (ctx.session.state.user || 'session') + ')', ok: !!ctx.session.state.credSet },
          { label: 'Only-if-unset: a value already set (operator or GPO) is NEVER overwritten - reports NO CHANGE', ok: true },
          { label: 'No default image on a target -> SKIPPED (the policy is never pointed at a missing file)', ok: true }
        ];
        if (fixWinrmHeal._cb.checked) pf.push({ label: 'WinRM-heal (RPC) armed for unreachable hosts', ok: true });

        var ok = await ctx.arm({
          title: 'Arm Lockscreen / Wallpaper Cache Fix',
          banner: 'DESTRUCTIVE - THIS CHANGES LIVE MACHINES',
          body: 'About to write the <b>DEFAULT</b> lock screen / wallpaper into <b>HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization</b> on the <b>' + hosts.length + '</b> host(s) in Target Computers.'
            + '<br><b>Only-if-unset:</b> a value already present (operator or GPO) is NEVER overwritten - the host reports NO CHANGE. No default image found on a target -> SKIPPED.',
          preflight: pf, okText: 'Run Lockscreen / Wallpaper Fix', cancelText: 'Cancel'
        });
        if (!ok) { log.append({ text: '[' + ts() + '] Lockscreen / Wallpaper fix cancelled at the arming dialog.', level: 'warn' }); return; }

        grid.clear(); prog.reset(); countLine.textContent = '0 / ' + hosts.length;
        hosts.forEach(function (h) { grid.upsert({ Host: h, Ping: '', Status: 'Queued', Detail: 'Queued' }); });
        log.banner('C2C Lockscreen / Wallpaper Cache Fix on ' + hosts.length + ' target host(s)');
        lockInputs(true);
        run = ctx.run('fix-lockscreen', { targets: hosts.join('\n'), confirm: confirmInput.value, threads: threadsFix(), attemptOffline: fixOffline._cb.checked, winrmHeal: fixWinrmHeal._cb.checked }, { keyOf: keyByHost, destructive: true });
        bindFixRun();
      }

      // ---- Java cleanup (opt-in utility; DESTRUCTIVE; TARGET-driven; admin session +
      // FIX confirm + arm checkbox). Not a scored pillar - never in run-all. ----
      async function doJavaFix() {
        if (isRunning()) return;
        var hosts = shortUniq(targets.hosts());
        if (!hosts.length) { alertDialog('No target hosts', NEED_TARGETS); return; }
        if (!javaArm._cb.checked) { alertDialog('Not armed', 'Tick "Arm the Java cleanup" checkbox first - this utility is opt-in.'); return; }
        if (!ctx.session.state.credSet) { alertDialog('Admin session required', 'Set ADW credentials (top-right) and start an admin session before running a fix - it changes machines.'); return; }
        if (confirmInput.value !== 'FIX') { alertDialog('Type FIX to Confirm', 'Type FIX (exactly, uppercase) in the Confirm box to arm the destructive fix.'); return; }

        var pf = [
          { label: hosts.length + ' target host(s) queued', ok: hosts.length > 0 },
          { label: 'Admin session (' + (ctx.session.state.user || 'session') + ')', ok: !!ctx.session.state.credSet },
          { label: 'Removes ONLY Oracle/Sun Java below 8u491 - OpenJDK/Temurin/Corretto and UNKNOWN versions are never touched', ok: true },
          { label: 'No forced reboots (msiexec /norestart; 3010 reported as reboot pending)', ok: true }
        ];
        if (fixWinrmHeal._cb.checked) pf.push({ label: 'WinRM-heal (RPC) armed for unreachable hosts', ok: true });

        var ok = await ctx.arm({
          title: 'Arm Java Cleanup - Remove Outdated',
          banner: 'DESTRUCTIVE - THIS CHANGES LIVE MACHINES',
          body: 'About to remove <b>Oracle/Sun Java OLDER than 8u491</b> (installed products via msiexec, JavaSoft registry residue, Program Files\\Java folders) from the <b>' + hosts.length + '</b> host(s) in Target Computers.'
            + '<br><b>Never touched:</b> OpenJDK / Temurin / Corretto, Java 1.8.0_491+, modern JDKs (9/11/17/21) and any UNKNOWN (unparseable) version - those are listed for manual review instead.',
          preflight: pf, okText: 'Run Java Cleanup', cancelText: 'Cancel'
        });
        if (!ok) { log.append({ text: '[' + ts() + '] Java cleanup cancelled at the arming dialog.', level: 'warn' }); return; }

        grid.clear(); prog.reset(); countLine.textContent = '0 / ' + hosts.length;
        hosts.forEach(function (h) { grid.upsert({ Host: h, Ping: '', Status: 'Queued', Detail: 'Queued' }); });
        log.banner('C2C Java Cleanup on ' + hosts.length + ' target host(s)');
        lockInputs(true);
        run = ctx.run('fix-java', { targets: hosts.join('\n'), confirm: confirmInput.value, threads: threadsFix(), attemptOffline: fixOffline._cb.checked, winrmHeal: fixWinrmHeal._cb.checked }, { keyOf: keyByHost, destructive: true });
        bindFixRun();
      }

      // ---- Run-all: the UNION across the CHECKED pillar cards - every host of a checked
      // card gets that card's pillar (import-scoped; the engine intersects the plan against
      // the re-derived CSV). ----
      async function doRunAll() {
        if (isRunning()) return;
        var info = updateFixCounts();
        var manual = info.manual;
        var union = info.union;
        var hosts = Object.keys(union);
        if (!hosts.length) { alertDialog('Nothing to run', manual ? 'Add hosts to Target Computers and check at least one pillar card before RUN ALL.' : 'Check at least one pillar card before RUN ALL.'); return; }
        if (!ctx.session.state.credSet) { alertDialog('Admin session required', 'Set ADW credentials (top-right) and start an admin session before running - it changes machines.'); return; }
        if (confirmInput.value !== 'FIX') { alertDialog('Type FIX to Confirm', 'Type FIX (exactly, uppercase) in the Confirm box to arm the run-all.'); return; }

        // Each host gets exactly the pillars it is checked under across the tabs.
        var plan = hosts.map(function (h) { return { host: h, pillars: Object.keys(union[h]) }; });
        var pillarsUsed = {}; plan.forEach(function (e) { e.pillars.forEach(function (p) { pillarsUsed[p] = true; }); });
        var pillarList = Object.keys(pillarsUsed);
        var encTab = pillarCards.Encryption;
        var pkiTab = pillarCards.PkiRoots;
        var enableEnc = !!(encTab && encTab.enableCb && encTab.enableCb._cb.checked && pillarsUsed.Encryption);
        var bundleFolder = (pkiTab && pkiTab.bundleInput) ? String(pkiTab.bundleInput.value || '').trim() : String(pkiBundleValue || '').trim();
        var pkiChecked = !!pillarsUsed.PkiRoots;
        var pkiPrune = !!(pkiChecked && ((pkiTab && pkiTab.pruneCb) ? pkiTab.pruneCb._cb.checked : pkiPruneChecked));
        var pkiRdp = !!(pkiChecked && ((pkiTab && pkiTab.rdpCb) ? pkiTab.rdpCb._cb.checked : pkiRdpChecked));
        // audit 2026-07-25: the distrust push is opt-in here too - a run-all must never blacklist
        // certs fleet-wide just because a host planned PkiRoots.
        var pkiDistrust = !!(pkiChecked && ((pkiTab && pkiTab.distrustCb) ? pkiTab.distrustCb._cb.checked : pkiDistrustChecked));

        var pf = [
          { label: 'Admin session (' + (ctx.session.state.user || 'session') + ')', ok: !!ctx.session.state.credSet },
          { label: hosts.length + ' host(s) / ' + info.totalPairs + ' pillar fix(es): ' + pillarList.join(', '), ok: true },
          { label: 'Verify-first: each pillar reports NO CHANGE on a host already compliant', ok: true }
        ];
        if (pillarsUsed.Encryption) pf.push({ label: enableEnc ? 'ENABLE BitLocker: WILL start XtsAes256 encryption on EVERY FullyDecrypted FIXED volume (OS + DATA; removable/USB untouched)' : 'Encryption resume-only (ENABLE not ticked)', ok: true });
        if (pkiChecked) pf.push({ label: bundleFolder ? 'PKI cert bundle: ' + bundleFolder : 'PKI: using shipped DoD default (Packages\\DoD-Certs)', ok: true });
        if (pkiChecked) pf.push({ label: 'PKI companions: prune expired intermediates ' + (pkiPrune ? 'ON' : 'off') + ', repair RDP listener ' + (pkiRdp ? 'ON' : 'off') + ' (opt-in, default off)', ok: true });
        if (pkiChecked) pf.push({ label: pkiDistrust ? 'PKI: BLACKLIST Untrusted certs into Disallowed is ON - this DISTRUSTS them fleet-wide' : 'PKI: BLACKLIST Untrusted certs into Disallowed is off (default) - only Root/CA are pushed', ok: true });
        if (manual) pf.push({ label: 'MANUAL mode - no C2C import: dials exactly the Target Computers you checked pillars for', ok: true });
        if (fixWinrmHeal._cb.checked) pf.push({ label: 'WinRM-heal (RPC) armed for unreachable hosts', ok: true });

        var ok = await ctx.arm({
          title: 'Arm RUN ALL',
          banner: 'DESTRUCTIVE - THIS CHANGES LIVE MACHINES',
          body: 'About to fix <b>' + hosts.length + '</b> host(s) across <b>' + pillarList.length + '</b> pillar(s) (<b>' + info.totalPairs + '</b> host-pillar fix(es)): <b>' + esc(pillarList.join(', ')) + '</b>.'
            + (manual ? '<br><b>MANUAL mode</b> (no C2C import): dials exactly the Target Computers checked under each pillar - no import allow-list.' : '')
            + '<br>Each host is fixed for exactly the pillars it is checked under. Every fixer is <b>verify-first</b> - a host already compliant for a pillar is reported NO CHANGE and left untouched.'
            + (enableEnc ? '<br><b>ENABLE BitLocker:</b> hosts will START XtsAes256 full-volume encryption on <b>every FullyDecrypted FIXED volume</b> - the OS volume (TPM) AND fixed DATA volumes (D:, E:, ... via recovery-password + AD/Entra escrow + auto-unlock); removable / USB drives are never touched. Runs for hours in the background.' : (pillarsUsed.Encryption ? '<br>Encryption is resume-only (tick ENABLE BitLocker on the Encryption card to start encryption).' : ''))
            + (pkiDistrust ? '<br><b>BLACKLIST armed:</b> hosts that plan PkiRoots will also get the bundle\'s <b>Untrusted\\</b> certs added to the LocalMachine <b>Disallowed</b> store - a fleet-wide <b>DISTRUST</b>, the opposite direction to the roots being installed.' : ''),
          preflight: pf, okText: 'RUN ALL', cancelText: 'Cancel'
        });
        if (!ok) { log.append({ text: '[' + ts() + '] Run-all cancelled at the arming dialog.', level: 'warn' }); return; }

        // Seed the grid with SHORT names (the engine short-names every plan host), so a manual
        // FQDN-typed target does not leave a phantom 'Queued' row its short result row can't key to.
        var dialHosts = shortUniq(hosts);
        grid.clear(); prog.reset(); countLine.textContent = '0 / ' + dialHosts.length;
        dialHosts.forEach(function (h) { grid.upsert({ Host: h, Ping: '', Status: 'Queued', Detail: 'Queued' }); });
        log.banner('C2C RUN ALL on ' + dialHosts.length + ' host(s) [' + pillarList.join(', ') + ']');
        lockInputs(true);
        var raParams = {
          plan: JSON.stringify(plan),
          enableEncryption: enableEnc,
          certBundleFolder: bundleFolder,
          prunePki: pkiPrune,
          fixRdp: pkiRdp,
          pushDisallowed: pkiDistrust,
          winrmHeal: fixWinrmHeal._cb.checked,
          confirm: confirmInput.value,
          threads: threadsFix(),
          attemptOffline: fixOffline._cb.checked
        };
        if (!manual) raParams.csvPath = importCsvPath;   // omit csvPath -> engine runs MANUAL mode (trusts the plan)
        run = ctx.run('run-all', raParams, { keyOf: keyByHost, destructive: true });
        bindFixRun();
      }

      function bindFixRun() {
        if (unsub) unsub();
        unsub = run.subscribe({
          status: function (t) { prog.setPhase(t); },
          progress: function (p) { prog.setProgress(p.done, p.total); countLine.textContent = p.done + ' / ' + p.total; },
          row: function (r) { grid.upsert(r); },
          log: function (l) { log.append(l); },
          error: function (e) { log.append({ text: '[' + ts() + '] ' + (e && e.text ? e.text : 'error'), level: 'err' }); },
          active: function (a) {
            if (!a) {
              lockInputs(false);
              var c = fixTally();
              countLine.textContent = c.total + ' / ' + c.total;
              // audit 2026-07-24: NOT VERIFIED / any unbucketed status join failed+partial as bad, so an
              // unconfirmed fix can never close the run green.
              var bad = c.failed + c.partial + c.notVerified + c.other;
              // audit 2026-07-25: an IN PROGRESS host is not a failure, but it is not DONE either -
              // the run closes amber (never green) so nobody reads it as compliant.
              var unfinished = c.inProgress;
              log.append({ text: '[' + ts() + '] FINISHED C2C fix. FIXED=' + c.fixed + '  NO CHANGE=' + c.noChange + '  IN PROGRESS=' + c.inProgress + '  PARTIAL=' + c.partial + '  NOT VERIFIED=' + c.notVerified + '  FAILED=' + c.failed + '  OFFLINE=' + c.offline + '  SKIPPED=' + c.skipped + (c.other ? '  OTHER=' + c.other : ''), level: (bad || unfinished) ? 'warn' : 'ok' });
              runbar.setStatus('Fix done - Fixed ' + c.fixed + ' / Partial ' + c.partial + ' / NotVerified ' + c.notVerified + ' / InProgress ' + c.inProgress + ' / NoChange ' + c.noChange + ' / Failed ' + c.failed, bad ? 'st-bad' : (unfinished ? 'st-warn' : 'st-ok'));
            }
          }
        });
      }

      // audit 2026-07-24: NOT VERIFIED (host rollup :2424 - a fix ran but could NOT be confirmed)
      // matched no bucket here, so it vanished from the done-line and the counters never reconciled
      // to total: an unverified host was silently indistinguishable from a compliant one. It now has
      // its own counter, plus an 'other' catch-all (the module's own tally idiom) so no future status
      // can disappear either. Both count as bad in the caller - "we could not verify" is never green.
      // audit 2026-07-25 (fable re-audit follow-up): IN PROGRESS gets its own counter too - the
      // engine now rolls an all-in-progress host up as IN PROGRESS instead of burying it in
      // NO CHANGE, and an unfinished remediation must never close the run green.
      function fixTally() {
        var t = { fixed: 0, noChange: 0, inProgress: 0, partial: 0, notVerified: 0, failed: 0, offline: 0, skipped: 0, other: 0, total: 0 };
        grid.rows().forEach(function (r) {
          var s = String(r.Status);
          if (s === 'FIXED') t.fixed++;
          else if (s === 'NO CHANGE') t.noChange++;
          else if (s === 'IN PROGRESS') t.inProgress++;
          else if (s === 'PARTIAL') t.partial++;
          else if (s === 'NOT VERIFIED') t.notVerified++;
          else if (s === 'FAILED') t.failed++;
          else if (s === 'OFFLINE') t.offline++;
          else if (s === 'SKIPPED') t.skipped++;
          else t.other++;
        });
        t.total = grid.rows().length;
        return t;
      }

      function doExport() {
        var rows = grid.rows();
        if (!rows.length) { alertDialog('Nothing to export', 'Run a scan or fix first - there are no result rows yet.'); return; }
        ctx.util.exportCsv('C2CReadiness_results', EXPORT_COLS, rows);
        log.append({ text: '[' + ts() + '] Exported ' + rows.length + ' row(s) to CSV.', level: 'info' });
      }

      // =================== init ===================
      showFixPlaceholder();                               // MANUAL-mode fix cards until a C2C CSV import switches to import-scoped
      // Live-refresh the lockscreen/scan counts AND (in manual mode) every per-pillar Fix / RUN ALL
      // host count as the Target Computers list changes.
      offTargets = targets.model.onChange(function () { updateTargetButtons(); updateFixCounts(); });
      updateTargetButtons();

      log.append({ text: 'C2C Nemesis ready. DUAL-mode fixes: with NO import, each pillar card fixes the hosts in Target Computers (MANUAL) - type FIX, then Fix a pillar or check cards + RUN ALL. Import the Tanium C2C Compliance CSV to switch to import-scoped targeting (one card per flagged pillar; dials ONLY the flagged hosts).', level: 'accent' });
      log.append({ text: 'Read-only side (no import needed): C2C Readiness Scan + Version Check across the Target Computers list (11 TASKORD-tiered checks: 5 QUARANTINE, 2 AUDIT, 3 INFO, Monitoring=ATTEST). The full per-check report streams here.', level: 'dim' });

      host.appendChild(root);
      this._root = root; this._unsub = function () { if (unsub) unsub(); if (offTargets) offTargets(); };
    }
  });
})();
