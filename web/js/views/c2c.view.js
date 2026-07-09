/* ============================================================================
   c2c.view.js  -  C2C Nemesis (tool id: 'c2c')
   Comply-to-Connect (AFI/MPTO rule 3.B.2.B) quarantine predictor + remediation.

   ONE host list (TARGET COMPUTERS) drives everything:

   1. READ-ONLY "C2C Readiness Scan" (action 'scan') + "Version Check"
      (action 'version-check'): read-only probes across the Target Computers.
      Change NOTHING and are NOT gated on an admin session.

   2. TARGET-DRIVEN FIX (destructive, admin-session gated): the six endpoint-
      fixable pillars (Monitoring / Firewall / Encryption / AntiMalware / Patches
      / PKI Trust Roots) are ALWAYS shown as fix cards. Each per-card Fix, and the
      "FIX SELECTED PILLARS ON TARGET LIST" run-all, dial the TARGET COMPUTERS
      list - no import required. Anything you can put in Target Computers is
      fixable. Every fixer is VERIFY-FIRST (NOCHANGE on a host already compliant),
      so running a pillar against a host that does not need it is safe.

   3. OPTIONAL IMPORT of the Tanium "C2C Compliance Status" CSV: a convenience
      that (a) auto-loads the non-compliant hosts into Target Computers, (b) checks
      + badges the pillars each host failed, and (c) shows the routed-elsewhere
      pillars (Vuln -> ACAS/KEV, OSVersion -> Windows Upgrade, STIG -> Reports) as
      info notes. The import NEVER gates the fix cards or the ability to run a fix.

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

  // Endpoint-fixable pillars (drive the per-pillar tabs + run-all). Must match the
  // engine's $script:C2cFixablePillars. The stable ORDER here is the tab order.
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
      case 'CHECK ERRORS':
      case 'NOT ATTESTING':
      case 'Cancelled':
      case 'ERROR':
      case 'DNS MISMATCH':
      case 'PARTIAL':
      case 'NOT INSTALLED':
      case 'SKIPPED': return 'st-warn';
      // blue: nothing changed (fix), encryption already running, a newer-than-target version,
      // or live in-progress phases streamed by the engine.
      case 'NO CHANGE':
      case 'IN PROGRESS':
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
      var pillarTabs = {};               // pillar key -> { grid, fixBtn, enableCb?, bundleInput? } for the per-pillar TabHost
      var encEnableChecked = false;      // persists the ENABLE-BitLocker opt-in across TabHost rebuilds
      var pkiBundleValue = '';           // persists the PKI cert bundle folder across TabHost rebuilds
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

      // --- FIX PILLARS (import-flagged hosts per pillar; destructive; admin session required) ---
      var fixCard = sectionCard('FIX PILLARS (import-flagged hosts, per pillar)', 'cyan');
      var fixIntro = el('div'); fixIntro.style.cssText = 'font-size:12px;line-height:1.4;color:var(--muted);margin-bottom:8px';
      fixIntro.textContent = 'Import the C2C compliance CSV to load one TAB per fixable pillar, each listing ONLY the hosts that pillar flagged. Check the hosts to fix in a tab, type FIX once, then Fix that pillar - or RUN ALL to fix every checked host across all tabs in one pass. Per-pillar fixes and Run All dial ONLY the import-flagged hosts you check - never the whole Target Computers list. Every fixer is verify-first (NO CHANGE where a host is already compliant). Requires an admin session.';
      fixCard.appendChild(fixIntro);

      // controls row (shared across every pillar tab)
      var fixControls = el('div'); fixControls.style.cssText = 'display:flex;flex-direction:column;gap:8px;margin-bottom:8px';

      // prominent RUN ALL (union of every tab's checked hosts, each host getting the
      // pillars it is checked under)
      var runAllRow = el('div'); runAllRow.style.cssText = 'display:flex';
      var runAllBtn = ui.button('RUN ALL', { variant: 'danger', title: 'Fix every host you have checked across all pillar tabs, in one pass (destructive). Each host is fixed for exactly the pillars it is checked under. Verify-first: a host already compliant for a pillar reports NO CHANGE.' });
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

      var fixOffline = ui.checkbox('Attempt even if offline (host unreachable)', { title: 'Try a session even if the TCP 5985/445 probe fails.' });
      fixOffline.style.margin = '0'; fixControls.appendChild(fixOffline);

      var fixWinrmHeal = ui.checkbox('Recover WinRM via RPC if 5985 is down (best-effort; often blocked - default off)', { title: 'Opt-in. For a host whose TCP 5985 probe fails, try remote SCM recovery over RPC (Get-Service / Start-Service / Set-Service Automatic against the target) then re-probe. RPC is frequently blocked on AFNET, so leave this off unless you know it is allowed. Never acts on the dispatcher host.' });
      fixWinrmHeal.style.margin = '0'; fixControls.appendChild(fixWinrmHeal);

      fixCard.appendChild(fixControls);

      // per-pillar TabHost body: a muted placeholder until an import loads it, then one
      // selectable tab per fixable pillar WITH findings (rebuilt on each import).
      var fixBody = el('div'); fixBody.style.cssText = 'display:flex;flex-direction:column;gap:8px;min-height:0';
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

      // --- IMPORT C2C COMPLIANCE CSV (optional convenience; local parse, no admin gate) ---
      var importCard = sectionCard('IMPORT C2C COMPLIANCE CSV (optional)', 'cyan');
      var importIntro = el('div'); importIntro.style.cssText = 'font-size:12px;line-height:1.4;color:var(--muted);margin-bottom:8px';
      importIntro.textContent = 'OPTIONAL. Import the Tanium "C2C Compliance Status" CSV to auto-load its non-compliant hosts into Target Computers and pre-check + badge the pillars each host failed. Fixes never require this - it is a convenience.';
      importCard.appendChild(importIntro);
      var importFileInput = el('input'); importFileInput.type = 'file'; importFileInput.accept = '.csv,.txt'; importFileInput.style.display = 'none';
      var importBtn = ui.ctaButton('IMPORT C2C CSV', { title: 'Choose the Tanium C2C Compliance Status CSV export, upload it to the JANET Web host, and parse it (auto-load targets + badge pillars).' });
      importBtn.style.maxWidth = '260px';
      var importRow = el('div'); importRow.style.cssText = 'display:flex;gap:8px;align-items:center;flex-wrap:wrap'; importRow.appendChild(importBtn);
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
      var offlineCb = ui.checkbox('Attempt even if offline (host unreachable)', { title: 'Proceed against a host that fails the TCP 5985/445 reachability probe (e.g. firewalled but WinRM up). Reachability is TCP-only - AFNET drops ICMP.' });
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
      function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
      function alertDialog(title, bodyTxt) { ctx.confirm({ title: title, body: bodyTxt, okText: 'OK', cancelText: null }); }
      function keyByHost(ev) { return ev.Host != null ? String(ev.Host) : (ev.host != null ? String(ev.host) : null); }
      var NEED_TARGETS = 'Add hosts to Target Computers first (type / paste / Import TXT, or Import a C2C CSV to auto-load them).';

      function lockInputs(on) {
        offlineCb._cb.disabled = on; threadsInput.disabled = on; clearBtn.disabled = on;
        importBtn.disabled = on;
        verBtn.disabled = on; verMatchInput.disabled = on; verTgtInput.disabled = on; verHeal._cb.disabled = on;
        fixThreads.disabled = on; fixOffline._cb.disabled = on; confirmInput.disabled = on;
        fixWinrmHeal._cb.disabled = on;
        lockArm._cb.disabled = on;
        // per-tab extras (Encryption ENABLE checkbox / PKI bundle input) + row checkboxes
        Object.keys(pillarTabs).forEach(function (k) {
          var t = pillarTabs[k];
          if (t.enableCb) t.enableCb._cb.disabled = on;
          if (t.bundleInput) t.bundleInput.disabled = on;
        });
        // the shared cancel button is only usable WHILE a run is active.
        fixCancelBtn.disabled = !on;
        // per-tab Fix buttons + run-all get their enabled state from the tab selections.
        updateFixCounts();
        // lockscreen / scan / version buttons still key off the Target Computers count.
        updateTargetButtons();
      }

      // Live-update every per-pillar Fix button + the RUN ALL label/enabled state from the
      // CURRENT per-tab host selections (union). Called on mount, on any grid click, and
      // whenever a run starts/stops (via lockInputs). Returns the computed union.
      function updateFixCounts() {
        var locked = isRunning();
        var haveImport = !!importCsvPath;
        var union = {};       // host -> { pillar: true }
        var totalPairs = 0;
        FIXABLE.forEach(function (k) {
          var t = pillarTabs[k]; if (!t || !t.grid) return;
          var checked = t.grid.getChecked();
          if (t.fixBtn) {
            t.fixBtn.textContent = 'Fix ' + PILLAR_TAB[k] + ' on ' + checked.length + ' selected host' + (checked.length === 1 ? '' : 's');
            t.fixBtn.disabled = locked || !haveImport || checked.length === 0;
          }
          checked.forEach(function (r) { var h = r.Host; if (!h) return; (union[h] = union[h] || {})[k] = true; totalPairs++; });
        });
        var hostCount = Object.keys(union).length;
        runAllBtn.textContent = 'RUN ALL - ' + hostCount + ' host' + (hostCount === 1 ? '' : 's') + ' / ' + totalPairs + ' pillar fix' + (totalPairs === 1 ? '' : 'es');
        runAllBtn.disabled = locked || !haveImport || totalPairs === 0;
        return { union: union, totalPairs: totalPairs, hostCount: hostCount };
      }

      // Lockscreen / scan / version still key off the Target Computers count (unchanged).
      function updateTargetButtons() {
        var n = targets.count();
        var locked = isRunning();
        lockBtn.textContent = 'APPLY LOCKSCREEN / WALLPAPER FIX (' + n + ' host' + (n === 1 ? '' : 's') + ')';
        lockBtn.disabled = locked || n === 0 || !lockArm._cb.checked;
      }

      function summarize() {
        var ready = 0, risk = 0, offline = 0;
        grid.rows().forEach(function (r) {
          var s = String(r.Status);
          if (s === 'READY') ready++;
          else if (s === 'QUARANTINE RISK') risk++;
          else if (s === 'OFFLINE') offline++;
        });
        var total = grid.rows().length;
        var errors = total - ready - risk - offline;
        return { ready: ready, risk: risk, errors: errors, offline: offline, total: total };
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
              var bad = c.risk + c.offline;
              log.append({ text: '[' + ts() + '] FINISHED ' + verb + '. READY=' + c.ready + '  QUARANTINE RISK=' + c.risk + '  CHECK ERRORS=' + c.errors + '  OFFLINE=' + c.offline, level: bad ? 'warn' : 'ok' });
              runbar.setStatus('Done - Ready ' + c.ready + ' / Risk ' + c.risk + ' / Errors ' + c.errors + ' / Offline ' + c.offline, bad ? 'st-bad' : 'st-ok');
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
          // CSV while the pillar tabs still show the previous import (UI/dispatch divergence).
          var pendingCsvPath = p;
          importStatus.textContent = 'Parsing ' + f.name + ' ...'; importStatus.className = 'st-info';
          run = ctx.run('import', { csvPath: p });
          if (unsub) unsub();
          unsub = run.subscribe({
            status: function (t) { importStatus.textContent = t; },
            row: function () {},   // import rows drive the tiles/log + per-pillar tabs, not the results grid
            log: function (l) { log.append(l); },
            error: function (e) {
              importStatus.textContent = 'Import failed'; importStatus.className = 'st-bad';
              log.append({ text: '[' + ts() + '] ' + (e && e.text ? e.text : 'error'), level: 'err' });
              // A failed re-import invalidates the previous targeting state: clear the path
              // and rebuild the pre-import placeholder so UI and dispatch state agree.
              // showFixPlaceholder() calls updateFixCounts(), which re-disables the fix buttons.
              importCsvPath = null; showFixPlaceholder();
            },
            active: function (a) { importBtn.disabled = a; },
            // The run bus delivers the action's return value ({rows,summary}) as the
            // 'final' payload (RunController.reduce -> dispatch(key,'final',ev.result)),
            // so res.summary is the import summary. Guarded so a bad/empty payload logs
            // instead of silently doing nothing (dispatch swallows handler throws).
            final: function (res) {
              try {
                applyImportSummary((res && res.summary) || {});
                importCsvPath = pendingCsvPath;   // parse APPLIED - the path is now live for fixes
                updateFixCounts();                // reflect haveImport=true in the fix-button state
              }
              catch (err) {
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

      // Import loads one TAB per fixable pillar (each listing ONLY that pillar's flagged
      // hosts). It also keeps its legacy conveniences: hero tiles, auto-loading the
      // non-compliant hosts into Target Computers (for the read-only Scan + the Lockscreen
      // fix), and logging the audit + routed-elsewhere findings.
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

        // (b) build the per-pillar TabHost from the run-all plan (rebuilt each import).
        buildPillarTabs(s);

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

      // Muted placeholder shown in the FIX PILLARS body before any import loads the tabs.
      function showFixPlaceholder() {
        fixBody.innerHTML = ''; pillarTabs = {};
        var ph = el('div', 'muted', 'Import the C2C compliance CSV to load per-pillar targets. Each fixable pillar gets a tab listing only the hosts it flagged - check the hosts to fix, then Fix that pillar or RUN ALL.');
        ph.style.cssText = 'font-size:12px;line-height:1.45;padding:14px 8px;text-align:center;border:1px dashed var(--edge);border-radius:4px';
        fixBody.appendChild(ph);
        updateFixCounts(); updateTargetButtons();
      }

      // Build one selectable tab per fixable pillar WITH findings, from the run-all plan
      // (host -> its fixable pillars). Each host row carries Via (failed / audit) + its
      // OTHER fixable pillars. Rebuilt from scratch on each import (imports replace state).
      function buildPillarTabs(s) {
        fixBody.innerHTML = ''; pillarTabs = {};
        var plan = (s && s.runAllPlan) ? s.runAllPlan : [];
        var perPillar = {};   // pillar -> [ { Host, Via, Other } ]
        plan.forEach(function (entry) {
          var host = entry && entry.host; if (!host) return;
          var pil = (entry.pillars || []);
          var aud = (entry.auditPillars || []);
          pil.forEach(function (p) {
            var via = (aud.indexOf(p) >= 0) ? 'audit' : 'failed';
            var other = pil.filter(function (x) { return x !== p; }).join(', ');
            (perPillar[p] = perPillar[p] || []).push({ Host: host, Via: via, Other: other });
          });
        });

        var order = 0;
        var tabDefs = [];
        FIXABLE.forEach(function (k) {
          var rows = perPillar[k];
          if (!rows || !rows.length) return;
          order++;
          var num = (order < 10 ? '0' : '') + order;
          tabDefs.push({ id: k, label: num + '  ' + PILLAR_TAB[k] + ' (' + rows.length + ')', build: function (panel) { buildPillarPanel(k, rows, panel); } });
        });

        if (!tabDefs.length) {
          var none = el('div', 'muted', 'No endpoint-fixable pillar had a flagged host in this import (Vuln / OS Version / STIG route to other tools - see the activity log).');
          none.style.cssText = 'font-size:12px;line-height:1.45;padding:14px 8px;text-align:center;border:1px dashed var(--edge);border-radius:4px';
          fixBody.appendChild(none);
          updateFixCounts(); return;
        }

        var th = C.TabHost({ rail: 'top', helpId: 'c2c', tabs: tabDefs });
        var holder = el('div'); holder.style.cssText = 'flex:1;min-height:230px;display:flex'; holder.appendChild(th.el);
        fixBody.appendChild(holder);
        updateFixCounts();
      }

      // Lazy per-pillar panel builder: a selectable grid of the pillar's flagged hosts +
      // the pillar's extras (Encryption ENABLE checkbox / PKI bundle input) + a live-count
      // Fix button. Registered in pillarTabs so the shared controls read its selection.
      function buildPillarPanel(key, rows, panel) {
        var wrap = el('div'); wrap.style.cssText = 'display:flex;flex-direction:column;gap:8px;min-height:0;flex:1';
        var meta = FIX_META[key];
        var desc = el('div', 'muted', meta.desc); desc.style.cssText = 'font-size:11.5px;line-height:1.35';
        wrap.appendChild(desc);

        var pgrid = C.ResultsGrid({
          title: PILLAR_TAB[key] + ' targets', selectable: true, keyMode: { hostCol: 'Host' }, popOut: false,
          emptyText: 'No hosts flagged for this pillar.',
          columns: [
            { key: 'Host', label: 'HOST', width: 160 },
            { key: 'Via', label: 'VIA', width: 70, render: function (r) { return { text: String(r.Via || ''), cls: (String(r.Via) === 'failed' ? 'st-bad' : 'st-warn') }; } },
            { key: 'Other', label: 'OTHER PILLARS', render: function (r) { var t = String(r.Other || ''); return { text: t, title: t, cls: 'cell-dim' }; } }
          ]
        });
        rows.forEach(function (r) { pgrid.upsert(r); });   // all rows default UNCHECKED (operator opts in)
        var gh = el('div'); gh.style.cssText = 'flex:1;min-height:160px;display:flex'; gh.appendChild(pgrid.el);
        wrap.appendChild(gh);
        // Recompute the live counts after any click inside the grid. Row checkbox clicks
        // stopPropagation, so listen in the CAPTURE phase then let the grid settle (setTimeout).
        pgrid.el.addEventListener('click', function () { setTimeout(updateFixCounts, 0); }, true);

        var entry = pillarTabs[key] = { grid: pgrid, fixBtn: null, enableCb: null, bundleInput: null };

        // Encryption extra: the ENABLE-BitLocker opt-in (stays with its pillar's tab)
        if (key === 'Encryption') {
          var enc = ui.checkbox('ENABLE BitLocker on ALL FullyDecrypted FIXED volumes - OS + DATA (XtsAes256)', { title: 'Opt-in. Starts XtsAes256 FULL-VOLUME encryption on EVERY FullyDecrypted FIXED volume: the OS volume (TPM protector) AND fixed DATA volumes such as D:, E: (recovery-password protector, NO TPM, plus BitLocker auto-unlock). Every volume escrows its recovery key FIRST (Entra-first, AD fallback) and is fail-closed - if escrow fails the protector is removed and encryption is NEVER started. Removable / USB drives are never touched. Applies to this pillar Fix AND to RUN ALL.' });
          enc._cb.checked = encEnableChecked;
          enc._cb.onchange = function () { encEnableChecked = enc._cb.checked; };
          enc.style.margin = '2px 0';
          wrap.appendChild(enc);
          entry.enableCb = enc;
        }
        // PKI extra: the DoD trust-bundle folder path (stays with its pillar's tab)
        if (key === 'PkiRoots') {
          var pr = el('div'); pr.style.cssText = 'display:flex;align-items:center;gap:8px;flex-wrap:wrap';
          pr.appendChild(ui.label('Cert bundle folder:'));
          var bi = ui.input({ title: 'Server-readable path (e.g. a UNC path) to the DoD trust bundle folder holding root\\*.cer, Intermediate\\*.cer, Untrusted\\*.cer (and/or loose *.cer -> Root). Certs are added ADDITIVELY to LocalMachine Root/CA/Disallowed. LEAVE BLANK to use the SHIPPED DoD bundle (Packages\\DoD-Certs).' });
          bi.placeholder = 'leave blank -> shipped DoD bundle (Packages\\DoD-Certs)';
          bi.value = pkiBundleValue;
          bi.style.cssText += ';flex:1;min-width:220px;font-size:11.5px';
          bi.addEventListener('input', function () { pkiBundleValue = String(bi.value || ''); });
          pr.appendChild(bi);
          wrap.appendChild(pr);
          entry.bundleInput = bi;
        }

        var r2 = el('div'); r2.style.cssText = 'display:flex;align-items:center;gap:8px;margin-top:2px';
        var sp = el('div'); sp.style.flex = '1'; r2.appendChild(sp);
        var fixBtn = ui.button('Fix ' + PILLAR_TAB[key] + ' on 0 selected hosts', { variant: 'danger', size: 'sm', title: 'Run the ' + meta.label + ' remediation on the CHECKED hosts in this tab (destructive). Verify-first: a host already compliant reports NO CHANGE.' });
        fixBtn.onclick = function () { doPillarFix(key); };
        r2.appendChild(fixBtn);
        wrap.appendChild(r2);
        entry.fixBtn = fixBtn;

        panel.appendChild(wrap);
        updateFixCounts();
      }

      // ---- Per-pillar fix (DESTRUCTIVE; import-scoped; admin session + FIX confirm) ----
      // Dials ONLY the CHECKED hosts in this pillar's tab (a subset of the hosts the import
      // flagged for the pillar), re-sending the CSV so the engine re-derives + intersects.
      async function doPillarFix(key) {
        if (isRunning()) return;
        var meta = FIX_META[key];
        var t = pillarTabs[key];
        if (!importCsvPath) { alertDialog('No import loaded', 'Import the C2C compliance CSV first - per-pillar fixes dial only the import-flagged hosts.'); return; }
        var hosts = (t && t.grid) ? t.grid.getChecked().map(function (r) { return r.Host; }).filter(Boolean) : [];
        if (!hosts.length) { alertDialog('No hosts checked', 'Check at least one host in the ' + PILLAR_TAB[key] + ' tab to fix.'); return; }
        if (!ctx.session.state.credSet) { alertDialog('Admin session required', 'Set ADW credentials (top-right) and start an admin session before running a fix - it changes machines.'); return; }
        if (confirmInput.value !== 'FIX') { alertDialog('Type FIX to Confirm', 'Type FIX (exactly, uppercase) in the Confirm box to arm the destructive fix.'); return; }
        var bundleFolder = (t && t.bundleInput) ? String(t.bundleInput.value || '').trim() : '';
        var enableEnc = key === 'Encryption' && t && t.enableCb && t.enableCb._cb.checked;

        var pf = [
          { label: hosts.length + ' checked host(s) - import-flagged for ' + PILLAR_TAB[key], ok: hosts.length > 0 },
          { label: 'Admin session (' + (ctx.session.state.user || 'session') + ')', ok: !!ctx.session.state.credSet },
          { label: 'Verify-first: a host already compliant for ' + meta.label + ' reports NO CHANGE', ok: true }
        ];
        if (key === 'Encryption') pf.push({ label: enableEnc ? 'ENABLE BitLocker: WILL start XtsAes256 encryption on EVERY FullyDecrypted FIXED volume (OS + DATA; removable/USB untouched)' : 'Resume-only (ENABLE not ticked)', ok: true });
        if (key === 'PkiRoots') pf.push({ label: 'Cert bundle: ' + (bundleFolder || 'shipped DoD default (Packages\\DoD-Certs)'), ok: true });
        if (fixWinrmHeal._cb.checked) pf.push({ label: 'WinRM-heal (RPC) armed for unreachable hosts', ok: true });

        var ok = await ctx.arm({
          title: 'Arm Fix ' + meta.label,
          banner: 'DESTRUCTIVE - THIS CHANGES LIVE MACHINES',
          body: 'About to run <b>Fix ' + esc(meta.label) + '</b> on the <b>' + hosts.length + '</b> checked host(s) the import flagged for this pillar.'
            + '<br>This fixer is <b>verify-first</b>: a host already compliant for this pillar is reported NO CHANGE and left untouched.'
            + (enableEnc ? '<br><b>ENABLE BitLocker:</b> this run will START XtsAes256 FULL-VOLUME encryption on <b>every FullyDecrypted FIXED volume</b> of the <b>' + hosts.length + '</b> host(s) - the OS volume (TPM) AND fixed DATA volumes (D:, E:, ... via recovery-password + AD/Entra escrow + auto-unlock). Removable / USB drives are never touched. Escrow-first, fail-closed; the OS volume needs TPM-ready + domain-joined. Encryption runs for hours in the background.' : ''),
          preflight: pf, okText: 'Run Fix ' + meta.label, cancelText: 'Cancel'
        });
        if (!ok) { log.append({ text: '[' + ts() + '] Fix ' + meta.label + ' cancelled at the arming dialog.', level: 'warn' }); return; }

        grid.clear(); prog.reset(); countLine.textContent = '0 / ' + hosts.length;
        hosts.forEach(function (h) { grid.upsert({ Host: h, Ping: '', Status: 'Queued', Detail: 'Queued' }); });
        log.banner('C2C Fix ' + meta.label + ' on ' + hosts.length + ' import-flagged host(s)');
        lockInputs(true);
        var params = { targets: hosts.join('\n'), csvPath: importCsvPath, confirm: confirmInput.value, threads: threadsFix(), attemptOffline: fixOffline._cb.checked, winrmHeal: fixWinrmHeal._cb.checked };
        if (key === 'Encryption') params.enableEncryption = enableEnc;
        if (key === 'PkiRoots') params.certBundleFolder = bundleFolder;
        run = ctx.run(meta.action, params, { keyOf: keyByHost, destructive: true });
        bindFixRun();
      }

      // ---- Lockscreen / Wallpaper cache fix (opt-in utility; DESTRUCTIVE; TARGET-driven;
      // admin session + FIX confirm + arm checkbox). Not a scored pillar - never in run-all. ----
      async function doLockscreenFix() {
        if (isRunning()) return;
        var hosts = targets.hosts();
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

      // ---- Run-all: the UNION of every tab's checked hosts, each host getting exactly
      // the pillars it is checked under (import-scoped; the engine intersects the plan
      // against the re-derived CSV). ----
      async function doRunAll() {
        if (isRunning()) return;
        if (!importCsvPath) { alertDialog('No import loaded', 'Import the C2C compliance CSV first - RUN ALL fixes only the import-flagged hosts you check.'); return; }
        var info = updateFixCounts();
        var union = info.union;
        var hosts = Object.keys(union);
        if (!hosts.length) { alertDialog('Nothing checked', 'Check at least one host in a pillar tab before RUN ALL.'); return; }
        if (!ctx.session.state.credSet) { alertDialog('Admin session required', 'Set ADW credentials (top-right) and start an admin session before running - it changes machines.'); return; }
        if (confirmInput.value !== 'FIX') { alertDialog('Type FIX to Confirm', 'Type FIX (exactly, uppercase) in the Confirm box to arm the run-all.'); return; }

        // Each host gets exactly the pillars it is checked under across the tabs.
        var plan = hosts.map(function (h) { return { host: h, pillars: Object.keys(union[h]) }; });
        var pillarsUsed = {}; plan.forEach(function (e) { e.pillars.forEach(function (p) { pillarsUsed[p] = true; }); });
        var pillarList = Object.keys(pillarsUsed);
        var encTab = pillarTabs.Encryption;
        var pkiTab = pillarTabs.PkiRoots;
        var enableEnc = !!(encTab && encTab.enableCb && encTab.enableCb._cb.checked && pillarsUsed.Encryption);
        var bundleFolder = (pkiTab && pkiTab.bundleInput) ? String(pkiTab.bundleInput.value || '').trim() : String(pkiBundleValue || '').trim();
        var pkiChecked = !!pillarsUsed.PkiRoots;

        var pf = [
          { label: 'Admin session (' + (ctx.session.state.user || 'session') + ')', ok: !!ctx.session.state.credSet },
          { label: hosts.length + ' host(s) / ' + info.totalPairs + ' pillar fix(es): ' + pillarList.join(', '), ok: true },
          { label: 'Verify-first: each pillar reports NO CHANGE on a host already compliant', ok: true }
        ];
        if (pillarsUsed.Encryption) pf.push({ label: enableEnc ? 'ENABLE BitLocker: WILL start XtsAes256 encryption on EVERY FullyDecrypted FIXED volume (OS + DATA; removable/USB untouched)' : 'Encryption resume-only (ENABLE not ticked)', ok: true });
        if (pkiChecked) pf.push({ label: bundleFolder ? 'PKI cert bundle: ' + bundleFolder : 'PKI: using shipped DoD default (Packages\\DoD-Certs)', ok: true });
        if (fixWinrmHeal._cb.checked) pf.push({ label: 'WinRM-heal (RPC) armed for unreachable hosts', ok: true });

        var ok = await ctx.arm({
          title: 'Arm RUN ALL',
          banner: 'DESTRUCTIVE - THIS CHANGES LIVE MACHINES',
          body: 'About to fix <b>' + hosts.length + '</b> host(s) across <b>' + pillarList.length + '</b> pillar(s) (<b>' + info.totalPairs + '</b> host-pillar fix(es)): <b>' + esc(pillarList.join(', ')) + '</b>.'
            + '<br>Each host is fixed for exactly the pillars it is checked under. Every fixer is <b>verify-first</b> - a host already compliant for a pillar is reported NO CHANGE and left untouched.'
            + (enableEnc ? '<br><b>ENABLE BitLocker:</b> hosts will START XtsAes256 full-volume encryption on <b>every FullyDecrypted FIXED volume</b> - the OS volume (TPM) AND fixed DATA volumes (D:, E:, ... via recovery-password + AD/Entra escrow + auto-unlock); removable / USB drives are never touched. Runs for hours in the background.' : (pillarsUsed.Encryption ? '<br>Encryption is resume-only (tick ENABLE BitLocker on the Encryption tab to start encryption).' : '')),
          preflight: pf, okText: 'RUN ALL', cancelText: 'Cancel'
        });
        if (!ok) { log.append({ text: '[' + ts() + '] Run-all cancelled at the arming dialog.', level: 'warn' }); return; }

        grid.clear(); prog.reset(); countLine.textContent = '0 / ' + hosts.length;
        hosts.forEach(function (h) { grid.upsert({ Host: h, Ping: '', Status: 'Queued', Detail: 'Queued' }); });
        log.banner('C2C RUN ALL on ' + hosts.length + ' host(s) [' + pillarList.join(', ') + ']');
        lockInputs(true);
        run = ctx.run('run-all', {
          plan: JSON.stringify(plan),
          csvPath: importCsvPath,
          enableEncryption: enableEnc,
          certBundleFolder: bundleFolder,
          winrmHeal: fixWinrmHeal._cb.checked,
          confirm: confirmInput.value,
          threads: threadsFix(),
          attemptOffline: fixOffline._cb.checked
        }, { keyOf: keyByHost, destructive: true });
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
              var bad = c.failed + c.partial;
              log.append({ text: '[' + ts() + '] FINISHED C2C fix. FIXED=' + c.fixed + '  NO CHANGE=' + c.noChange + '  PARTIAL=' + c.partial + '  FAILED=' + c.failed + '  OFFLINE=' + c.offline + '  SKIPPED=' + c.skipped, level: bad ? 'warn' : 'ok' });
              runbar.setStatus('Fix done - Fixed ' + c.fixed + ' / Partial ' + c.partial + ' / NoChange ' + c.noChange + ' / Failed ' + c.failed, bad ? 'st-bad' : 'st-ok');
            }
          }
        });
      }

      function fixTally() {
        var t = { fixed: 0, noChange: 0, partial: 0, failed: 0, offline: 0, skipped: 0, total: 0 };
        grid.rows().forEach(function (r) {
          var s = String(r.Status);
          if (s === 'FIXED') t.fixed++;
          else if (s === 'NO CHANGE') t.noChange++;
          else if (s === 'PARTIAL') t.partial++;
          else if (s === 'FAILED') t.failed++;
          else if (s === 'OFFLINE') t.offline++;
          else if (s === 'SKIPPED') t.skipped++;
        });
        t.total = grid.rows().length;
        return t;
      }

      function doExport() {
        var rows = grid.rows();
        if (!rows.length) { alertDialog('Nothing to export', 'Run a scan or fix first - there are no result rows yet.'); return; }
        var csv = ctx.util.toCsv(EXPORT_COLS.map(function (p) { return p[1]; }), rows, EXPORT_COLS.map(function (p) { return p[0]; }));
        ctx.util.downloadBlob('C2CReadiness_results_' + ctx.util.fileStamp() + '.csv', 'text/csv', csv);
        log.append({ text: '[' + ts() + '] Exported ' + rows.length + ' row(s) to CSV.', level: 'info' });
      }

      // =================== init ===================
      showFixPlaceholder();                               // muted placeholder until a C2C CSV import loads the per-pillar tabs
      offTargets = targets.model.onChange(function () { updateTargetButtons(); });   // live lockscreen/scan button counts
      updateTargetButtons();

      log.append({ text: 'C2C Nemesis ready. Import the Tanium C2C Compliance CSV to load one tab per fixable pillar (each listing only the hosts it flagged); check the hosts to fix, type FIX, then Fix that pillar or RUN ALL. Per-pillar fixes + RUN ALL dial ONLY the import-flagged hosts you check.', level: 'accent' });
      log.append({ text: 'Read-only side (no import needed): C2C Readiness Scan + Version Check across the Target Computers list (11 TASKORD-tiered checks: 5 QUARANTINE, 2 AUDIT, 3 INFO, Monitoring=ATTEST). The full per-check report streams here.', level: 'dim' });

      host.appendChild(root);
      this._root = root; this._unsub = function () { if (unsub) unsub(); if (offTargets) offTargets(); };
    },
    unmount: function () { try { if (this._unsub) this._unsub(); } catch (e) {} if (this._root) this._root.remove(); }
  });
})();
