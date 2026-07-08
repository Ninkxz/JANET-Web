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

  // The 11 C2C checks (rule 3.B.2.B). 9 are scored on the endpoint; 2 are EXT
  // (external / server-side - reported in the activity log but never scored).
  var CHECKS = [
    ['Monitoring', 'Endpoint monitoring installed (Tanium SOFTWARE installed + client service running)'],
    ['Firewall', 'Endpoint firewall active (Domain + Private + Public profiles enabled)'],
    ['AntiMalware', 'Anti-malware active + signatures fresh (Defender AMRunningMode: Active needs RTP; Passive / EDR Block Mode needs MDE Sense onboarded)'],
    ['Patches', 'All requisite patches installed (0 pending MECM/CCM updates)'],
    ['VulnThreshold', 'Below the vulnerability threshold  [EXT - scored server-side (ARAD/ACAS)]'],
    ['Encryption', 'Data-at-rest encryption active (BitLocker On + FullyEncrypted for EVERY fixed volume; removable/USB excluded)'],
    ['AppWhitelist', 'Application whitelist active (AppLocker or WDAC enforcing)'],
    ['Agents', 'Patching + security agents installed and active (CcmExec + a security agent)'],
    ['PkiRoots', 'PKI trust roots baseline present (DoD roots in LocalMachine\\Root)'],
    ['Coams', 'All 7 COAMS tags applied  [EXT - ARAD/ePO server-side, not endpoint-readable]'],
    ['Hostname', 'AFNET/AFNS valid hostname (matches the naming convention)']
  ];

  // Endpoint-fixable pillars (drive the ALWAYS-ON fix cards + run-all). Must match
  // the engine's $script:C2cFixablePillars.
  var FIXABLE = ['Monitoring', 'Firewall', 'Encryption', 'AntiMalware', 'Patches', 'PkiRoots'];

  // Per-fixable-pillar card metadata: canonical key -> action id + display + blurb.
  var FIX_META = {
    Monitoring:  { action: 'fix-monitoring',  label: 'Monitoring (Tanium)',    desc: 'Verify Tanium SOFTWARE installed (uninstall registry) + heal the client service (Automatic + start).' },
    Firewall:    { action: 'fix-firewall',    label: 'Firewall',               desc: 'Enable any disabled Domain / Private / Public firewall profile.' },
    Encryption:  { action: 'fix-encryption',  label: 'Encryption (BitLocker)', desc: 'Resume suspended protectors on EVERY fixed volume; opt-in ENABLE decrypted fixed volumes (OS: TPM; data: auto-unlock). Removable/USB never touched.' },
    AntiMalware: { action: 'fix-antimalware', label: 'AntiMalware (Defender)', desc: 'Start WinDefend / Sense (Automatic); force RTP only in Active mode (never Passive / EDR Block Mode); update stale signatures.' },
    Patches:     { action: 'fix-patches',     label: 'Patches (MECM cycle)',   desc: 'Trigger the MECM SUM scan (113) + eval (108); installs run async.' },
    PkiRoots:    { action: 'fix-pki',         label: 'PKI Trust Roots',        desc: 'Install the DoD trust bundle .cer ADDITIVELY into Root/CA/Disallowed (uses the shared cert bundle folder above; blank = shipped Packages\\DoD-Certs).' }
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
      // a partial fix, a self/DNS skip, or product not installed.
      case 'CHECK ERRORS':
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
      var lastImport = null;             // last import summary (for routed notes / re-badge)
      var fixChecked = {};               // pillar -> bool (card checkbox; default TRUE for all six)
      var importBadge = {};              // pillar -> failedCount from the last import (badge/hint)
      var importHosts = {};              // pillar -> flagged host list from the last import (info only)
      var encEnableCb = null;            // the ENABLE-BitLocker checkbox on the Encryption card
      var encEnableChecked = false;      // persists the ENABLE opt-in across renderFixCards() rebuilds
      var importTiles = null;            // hero StatCards (built in the import card below)
      FIXABLE.forEach(function (k) { fixChecked[k] = true; });   // every pillar checked by default

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

      // --- FIX PILLARS ON TARGET LIST (destructive; admin session required) ---
      var fixCard = sectionCard('FIX PILLARS ON TARGET LIST (destructive)', 'cyan');
      var fixIntro = el('div'); fixIntro.style.cssText = 'font-size:12px;line-height:1.4;color:var(--muted);margin-bottom:8px';
      fixIntro.textContent = 'Pick the pillars, type FIX once, then Fix one pillar or run "FIX SELECTED PILLARS ON TARGET LIST" - all against the Target Computers above. No import needed. Every fixer is verify-first (NO CHANGE where a host is already compliant), so it is safe to run a pillar on a host that does not need it. Requires an admin session.';
      fixCard.appendChild(fixIntro);

      // controls row (ALWAYS visible now)
      var fixControls = el('div'); fixControls.style.cssText = 'display:flex;flex-direction:column;gap:8px;margin-bottom:8px';

      // prominent target-driven RUN ALL
      var runAllRow = el('div'); runAllRow.style.cssText = 'display:flex';
      var runAllBtn = ui.button('FIX SELECTED PILLARS ON TARGET LIST', { variant: 'danger', title: 'Fix every CHECKED pillar on every host in the Target Computers list, in one pass (destructive). Verify-first: a host already compliant for a pillar reports NO CHANGE.' });
      runAllBtn.style.cssText += ';flex:1;font-weight:700';
      runAllBtn.onclick = function () { doRunAll(); };
      runAllRow.appendChild(runAllBtn);
      fixControls.appendChild(runAllRow);

      var ctlRow1 = el('div'); ctlRow1.style.cssText = 'display:flex;align-items:center;gap:8px;flex-wrap:wrap';
      var selAllBtn = ui.ghostButton('Check all', { size: 'sm', title: 'Check every fixable pillar.' });
      var selNoneBtn = ui.ghostButton('Check none', { size: 'sm', title: 'Uncheck every fixable pillar.' });
      selAllBtn.onclick = function () { setAllChecked(true); };
      selNoneBtn.onclick = function () { setAllChecked(false); };
      ctlRow1.appendChild(selAllBtn); ctlRow1.appendChild(selNoneBtn);
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

      // Shared DoD trust-bundle folder path (used by the PKI Trust Roots card + run-all).
      var pkiRow = el('div'); pkiRow.style.cssText = 'display:flex;align-items:center;gap:8px;flex-wrap:wrap';
      pkiRow.appendChild(ui.label('PKI cert bundle folder:'));
      var pkiBundleInput = ui.input({ title: 'Server-readable path (e.g. a UNC path) to the DoD trust bundle folder holding root\\*.cer, Intermediate\\*.cer, Untrusted\\*.cer (and/or loose *.cer -> Root). Read admin-side once; certs are added ADDITIVELY to LocalMachine Root/CA/Disallowed. LEAVE BLANK to use the SHIPPED DoD bundle (Packages\\DoD-Certs) - one-click fix-pki. Type a folder to override with your own.' });
      pkiBundleInput.placeholder = 'leave blank -> shipped DoD bundle (Packages\\DoD-Certs)';
      pkiBundleInput.style.cssText += ';flex:1;min-width:220px;font-size:11.5px';
      pkiRow.appendChild(pkiBundleInput);
      fixControls.appendChild(pkiRow);
      var pkiHint = el('div', 'muted', 'PKI: leave the folder blank for the shipped DoD trust bundle (Packages\\DoD-Certs), or type a folder to override. Put any hosts in Target Computers and run Fix PKI to push the bundle (the LTMA workflow).');
      pkiHint.style.cssText = 'font-size:11px;line-height:1.35;margin:-2px 0 0 2px';
      fixControls.appendChild(pkiHint);

      fixCard.appendChild(fixControls);

      // fixable-card body (six cards, always rendered) + routed notes (import only)
      var fixBody = el('div'); fixBody.style.cssText = 'display:flex;flex-direction:column;gap:8px';
      fixCard.appendChild(fixBody);
      left.appendChild(fixCard);

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
      intro.textContent = 'One consolidated READ-ONLY probe per host (changes nothing) over WinRM. '
        + 'Predicts whether each host would be QUARANTINED. 9 checks are scored on the endpoint; '
        + '2 are EXT (external / server-side) - reported but never scored. '
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
      verdictNote.textContent = 'Verdict = count of FAIL among the 9 scored checks: '
        + 'READY (0 fail, 0 error) / QUARANTINE RISK (1+ fail) / CHECK ERRORS (0 fail but 1+ error). '
        + 'EXT checks (VulnThreshold, Coams) are shown but never count. The full per-check report streams to the activity log.';
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

      function checkedFixable() { return FIXABLE.filter(function (k) { return fixChecked[k] !== false; }); }

      function lockInputs(on) {
        offlineCb._cb.disabled = on; threadsInput.disabled = on; clearBtn.disabled = on;
        importBtn.disabled = on;
        verBtn.disabled = on; verMatchInput.disabled = on; verTgtInput.disabled = on; verHeal._cb.disabled = on;
        selAllBtn.disabled = on; selNoneBtn.disabled = on;
        fixThreads.disabled = on; fixOffline._cb.disabled = on; confirmInput.disabled = on;
        fixWinrmHeal._cb.disabled = on; pkiBundleInput.disabled = on;
        if (encEnableCb) encEnableCb._cb.disabled = on;
        // per-card checkboxes
        Array.prototype.forEach.call(fixBody.querySelectorAll('[data-fixcb]'), function (c) { c.disabled = on; });
        // the shared cancel button is only usable WHILE a run is active.
        fixCancelBtn.disabled = !on;
        // fix buttons + run-all get their enabled state from the target count (unless locked)
        updateTargetButtons();
      }

      // Live-update every target-driven Fix button + the run-all label/enabled state
      // from the CURRENT Target Computers count. Called on mount, on target edits,
      // and whenever a run starts/stops (via lockInputs).
      function updateTargetButtons() {
        var n = targets.count();
        var locked = isRunning();
        runAllBtn.textContent = 'FIX SELECTED PILLARS ON TARGET LIST (' + n + ' host' + (n === 1 ? '' : 's') + ')';
        runAllBtn.disabled = locked || n === 0;
        Array.prototype.forEach.call(fixBody.querySelectorAll('[data-fixbtn]'), function (b) {
          var key = b.getAttribute('data-fixbtn');
          var meta = FIX_META[key];
          b.textContent = 'Fix ' + meta.label + ' on ' + n + ' target host' + (n === 1 ? '' : 's');
          b.disabled = locked || n === 0;
        });
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
          importStatus.textContent = 'Parsing ' + f.name + ' ...'; importStatus.className = 'st-info';
          run = ctx.run('import', { csvPath: p });
          if (unsub) unsub();
          unsub = run.subscribe({
            status: function (t) { importStatus.textContent = t; },
            row: function () {},   // import rows drive the badges/log, not the results grid
            log: function (l) { log.append(l); },
            error: function (e) { importStatus.textContent = 'Import failed'; importStatus.className = 'st-bad'; log.append({ text: '[' + ts() + '] ' + (e && e.text ? e.text : 'error'), level: 'err' }); },
            active: function (a) { importBtn.disabled = a; },
            // The run bus delivers the action's return value ({rows,summary}) as the
            // 'final' payload (RunController.reduce -> dispatch(key,'final',ev.result)),
            // so res.summary is the import summary. Guarded so a bad/empty payload logs
            // instead of silently doing nothing (dispatch swallows handler throws).
            final: function (res) {
              try { applyImportSummary((res && res.summary) || {}); }
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

      // Import is a CONVENIENCE: it loads targets + badges/checks pillars. It never
      // gates the fix cards (those are always present + target-driven).
      function applyImportSummary(s) {
        lastImport = s || {};
        var pillars = (s && s.pillars) ? s.pillars : [];
        var byName = {}; pillars.forEach(function (p) { if (p && p.name != null) byName[p.name] = p; });

        // hero tiles
        var runAllPlan = (s && s.runAllPlan && s.runAllPlan.length) ? s.runAllPlan.length : 0;
        var nonCompliant = (s && s.nonCompliant) || 0;
        var routedOnly = Math.max(0, nonCompliant - runAllPlan);
        importTiles.setAll({ total: (s && s.total) || 0, noncompliant: nonCompliant, fixable: runAllPlan, routed: routedOnly });
        importStatus.textContent = 'Imported ' + ((s && s.total) || 0) + ' host(s): ' + ((s && s.compliant) || 0) + ' compliant, ' + nonCompliant + ' non-compliant.';
        importStatus.className = 'st-ok';

        // (a) auto-load the non-compliant hosts into Target Computers (merge, never clobber)
        var flaggedHosts = (s && s.nonCompliantHosts && s.nonCompliantHosts.length) ? s.nonCompliantHosts.slice() : [];
        if (flaggedHosts.length) {
          var existing = targets.hosts();
          var seen = {}; existing.forEach(function (h) { seen[String(h).toLowerCase()] = true; });
          var added = 0;
          flaggedHosts.forEach(function (h) { var k = String(h).toLowerCase(); if (!seen[k]) { seen[k] = true; existing.push(h); added++; } });
          targets.setText(existing.join('\n'));
          log.append({ text: '[' + ts() + '] Loaded ' + flaggedHosts.length + ' non-compliant host(s) into Target Computers (' + added + ' new).', level: 'accent' });
        }

        // (b) record per-pillar import badges + host lists; CHECK the pillars that failed
        importBadge = {}; importHosts = {};
        FIXABLE.forEach(function (k) {
          var p = byName[k];
          if (p && (p.failedCount || 0) > 0) {
            importBadge[k] = p.failedCount;
            importHosts[k] = (p.hosts && p.hosts.length) ? p.hosts.slice() : [];
            fixChecked[k] = true;   // auto-check a pillar the import flagged
          }
        });
        renderFixCards();

        // (c) routed-elsewhere info notes
        var routedTxt = ROUTED.map(function (m) {
          var p = byName[m.key]; var c = p ? (p.failedCount || 0) : 0;
          return c > 0 ? (m.label + ' ' + c + ' -> ' + m.route) : null;
        }).filter(Boolean);
        if (routedTxt.length) log.append({ text: '[' + ts() + '] Routed elsewhere: ' + routedTxt.join('  |  '), level: 'info' });
      }

      function setAllChecked(on) {
        FIXABLE.forEach(function (k) { fixChecked[k] = on; });
        renderFixCards();
      }

      // ---- render the six fixable cards (ALWAYS) + routed notes (import only) ----
      function renderFixCards() {
        fixBody.innerHTML = ''; encEnableCb = null;
        fixBody.appendChild(sectionEyebrow('FIXABLE PILLARS  (target-driven)'));
        FIXABLE.forEach(function (k) { fixBody.appendChild(buildFixCard(k)); });

        var routed = routedPresent();
        if (routed.length) {
          fixBody.appendChild(sectionEyebrow('ROUTED ELSEWHERE  (from import - ' + routed.length + ')'));
          routed.forEach(function (r) { fixBody.appendChild(buildRoutedCard(r.meta, r.data)); });
        }
        updateTargetButtons();
      }

      function routedPresent() {
        if (!lastImport || !lastImport.pillars) return [];
        var byName = {}; lastImport.pillars.forEach(function (p) { if (p && p.name != null) byName[p.name] = p; });
        return ROUTED.map(function (m) { return { meta: m, data: byName[m.key] }; })
                     .filter(function (x) { return x.data && (x.data.failedCount || 0) > 0; });
      }

      function sectionEyebrow(t) {
        var h = el('div', 'j-eyebrow', t); h.style.cssText += ';margin:6px 0 2px'; return h;
      }

      function buildFixCard(key) {
        var meta = FIX_META[key];
        var badge = importBadge[key];      // failedCount from last import, or undefined
        var box = el('div', 'j-card'); box.style.cssText += ';padding:10px 12px';
        var r1 = el('div'); r1.style.cssText = 'display:flex;align-items:flex-start;gap:8px';
        var cb = el('input'); cb.type = 'checkbox'; cb.checked = fixChecked[key] !== false; cb.style.marginTop = '3px';
        cb.setAttribute('data-fixcb', key);
        cb.title = 'Include ' + meta.label + ' in the run-all.';
        cb.addEventListener('change', function () { fixChecked[key] = cb.checked; });
        r1.appendChild(cb);

        var txt = el('div'); txt.style.cssText = 'flex:1;min-width:0';
        var nm = el('div'); nm.style.cssText = 'font-weight:700;font-size:12.5px;color:var(--text)'; nm.textContent = meta.label;
        var ds = el('div'); ds.style.cssText = 'font-size:11.5px;line-height:1.35;color:var(--muted)'; ds.textContent = meta.desc;
        txt.appendChild(nm); txt.appendChild(ds);
        r1.appendChild(txt);

        // import badge (right): "N flagged by import" -> click reviews the flagged hosts
        if (badge != null) {
          var right = el('div'); right.style.cssText = 'display:flex;flex-direction:column;align-items:flex-end;gap:5px;flex:0 0 auto';
          var hostLbl = el('div'); hostLbl.style.cssText = 'font-family:var(--mono);font-size:11px;color:var(--cyan);cursor:pointer;text-decoration:underline dotted;text-align:right';
          hostLbl.textContent = badge + ' flagged by import';
          hostLbl.title = 'Click to review the hosts the import flagged for ' + meta.label + '. (Fix dials the Target Computers list, not this list.)';
          hostLbl.onclick = function () { showImportHosts(key); };
          right.appendChild(hostLbl);
          r1.appendChild(right);
        }
        box.appendChild(r1);

        // Encryption card: the ENABLE-BitLocker opt-in toggle
        if (key === 'Encryption') {
          encEnableCb = ui.checkbox('ENABLE BitLocker on ALL FullyDecrypted FIXED volumes - OS + DATA (XtsAes256)', { title: 'Opt-in. Starts XtsAes256 FULL-VOLUME encryption on EVERY FullyDecrypted FIXED volume: the OS volume (TPM protector) AND fixed DATA volumes such as D:, E: (recovery-password protector, NO TPM, plus BitLocker auto-unlock). Every volume escrows its recovery key FIRST (Entra-first, AD fallback) and is fail-closed - if escrow fails the protector is removed and encryption is NEVER started. Removable / USB drives are never touched. The OS volume needs a TPM-ready + domain-joined host; a DATA volume only enables once the OS volume is BitLocker-on. Runs for hours in the background. Applies to this card and to the run-all.' });
          encEnableCb._cb.checked = encEnableChecked;   // restore, don't reset, on card rebuild
          encEnableCb._cb.onchange = function () { encEnableChecked = encEnableCb._cb.checked; };
          encEnableCb.style.margin = '6px 0 2px 22px';
          box.appendChild(encEnableCb);
        }

        var r2 = el('div'); r2.style.cssText = 'display:flex;align-items:center;gap:8px;margin-top:8px';
        var r2sp = el('div'); r2sp.style.flex = '1'; r2.appendChild(r2sp);
        var fixBtn = ui.button('Fix ' + meta.label, { variant: 'danger', size: 'sm', title: 'Run the ' + meta.label + ' remediation on every host in the Target Computers list (destructive). Verify-first: a host already compliant reports NO CHANGE.' });
        fixBtn.setAttribute('data-fixbtn', key);
        fixBtn.onclick = function () { doPillarFix(key); };
        r2.appendChild(fixBtn);
        box.appendChild(r2);
        return box;
      }

      function buildRoutedCard(meta, data) {
        var count = (data && data.failedCount) || 0;
        var box = el('div', 'j-card'); box.style.cssText += ';padding:9px 12px;opacity:0.85';
        var r1 = el('div'); r1.style.cssText = 'display:flex;align-items:center;gap:8px';
        var txt = el('div'); txt.style.cssText = 'flex:1;min-width:0';
        var nm = el('div'); nm.style.cssText = 'font-weight:700;font-size:12.5px;color:var(--muted)'; nm.textContent = meta.label;
        var ds = el('div'); ds.style.cssText = 'font-size:11.5px;line-height:1.35;color:var(--muted)'; ds.textContent = 'Route: ' + meta.route;
        txt.appendChild(nm); txt.appendChild(ds);
        r1.appendChild(txt);
        var hostLbl = el('div'); hostLbl.style.cssText = 'font-family:var(--mono);font-size:11px;color:var(--muted);flex:0 0 auto';
        hostLbl.textContent = count + ' host' + (count === 1 ? '' : 's');
        r1.appendChild(hostLbl);
        box.appendChild(r1);
        return box;
      }

      // review the hosts the IMPORT flagged for a pillar (informational only).
      function showImportHosts(key) {
        var hosts = (importHosts[key] || []).slice();
        var b = el('div');
        var d = el('div'); d.style.cssText = 'font-size:11.5px;color:var(--text-dim);margin-bottom:8px';
        d.innerHTML = '<b>' + esc((FIX_META[key] && FIX_META[key].label) || key) + '</b><br>' + hosts.length + ' host(s) the import flagged for this pillar.<br>Fix dials the <b>Target Computers</b> list (they were auto-loaded on import).';
        b.appendChild(d);
        var listBox = el('div'); listBox.style.cssText = 'max-height:260px;overflow:auto;font-family:var(--mono);font-size:11.5px;border:1px solid var(--edge);border-radius:3px;padding:6px 8px;background:var(--bg)';
        if (hosts.length) hosts.forEach(function (h) { var r = el('div'); r.textContent = h; listBox.appendChild(r); });
        else { var em = el('div', 'muted'); em.textContent = '(no hosts resolved)'; listBox.appendChild(em); }
        b.appendChild(listBox);
        ctx.confirm({ title: 'Import-flagged hosts - ' + ((FIX_META[key] && FIX_META[key].label) || key), body: b, okText: 'Close', cancelText: null });
      }

      // ---- Per-card fix (DESTRUCTIVE; TARGET-driven; admin session + FIX confirm) ----
      async function doPillarFix(key) {
        if (isRunning()) return;
        var meta = FIX_META[key];
        var hosts = targets.hosts();
        if (!hosts.length) { alertDialog('No target hosts', NEED_TARGETS); return; }
        if (!ctx.session.state.credSet) { alertDialog('Admin session required', 'Set ADW credentials (top-right) and start an admin session before running a fix - it changes machines.'); return; }
        if (confirmInput.value !== 'FIX') { alertDialog('Type FIX to Confirm', 'Type FIX (exactly, uppercase) in the Confirm box to arm the destructive fix.'); return; }
        // Cert bundle is OPTIONAL: a blank folder auto-falls-back to the shipped DoD
        // bundle (Packages\DoD-Certs) engine-side, so one-click fix-pki works.
        var bundleFolder = String(pkiBundleInput.value || '').trim();
        var enableEnc = key === 'Encryption' && encEnableCb && encEnableCb._cb.checked;

        var pf = [
          { label: hosts.length + ' target host(s) queued', ok: hosts.length > 0 },
          { label: 'Admin session (' + (ctx.session.state.user || 'session') + ')', ok: !!ctx.session.state.credSet },
          { label: 'Verify-first: a host already compliant for ' + meta.label + ' reports NO CHANGE (safe to run on any host)', ok: true }
        ];
        if (key === 'Encryption') pf.push({ label: enableEnc ? 'ENABLE BitLocker: WILL start XtsAes256 encryption on EVERY FullyDecrypted FIXED volume (OS + DATA; removable/USB untouched)' : 'Resume-only (ENABLE not ticked)', ok: true });
        if (key === 'PkiRoots') pf.push({ label: 'Cert bundle: ' + (bundleFolder || 'shipped DoD default (Packages\\DoD-Certs)'), ok: true });
        if (fixWinrmHeal._cb.checked) pf.push({ label: 'WinRM-heal (RPC) armed for unreachable hosts', ok: true });

        var ok = await ctx.arm({
          title: 'Arm Fix ' + meta.label,
          banner: 'DESTRUCTIVE - THIS CHANGES LIVE MACHINES',
          body: 'About to run <b>Fix ' + esc(meta.label) + '</b> on the <b>' + hosts.length + '</b> host(s) in Target Computers.'
            + '<br>This fixer is <b>verify-first</b>: a host already compliant for this pillar is reported NO CHANGE and left untouched, so running it against hosts that do not need it is safe.'
            + (enableEnc ? '<br><b>ENABLE BitLocker:</b> this run will START XtsAes256 FULL-VOLUME encryption on <b>every FullyDecrypted FIXED volume</b> of the <b>' + hosts.length + '</b> host(s) - the OS volume (TPM) AND fixed DATA volumes (D:, E:, ... via recovery-password + AD/Entra escrow + auto-unlock). Removable / USB drives are never touched. Escrow-first, fail-closed; the OS volume needs TPM-ready + domain-joined. Encryption runs for hours in the background.' : ''),
          preflight: pf, okText: 'Run Fix ' + meta.label, cancelText: 'Cancel'
        });
        if (!ok) { log.append({ text: '[' + ts() + '] Fix ' + meta.label + ' cancelled at the arming dialog.', level: 'warn' }); return; }

        grid.clear(); prog.reset(); countLine.textContent = '0 / ' + hosts.length;
        hosts.forEach(function (h) { grid.upsert({ Host: h, Ping: '', Status: 'Queued', Detail: 'Queued' }); });
        log.banner('C2C Fix ' + meta.label + ' on ' + hosts.length + ' target host(s)');
        lockInputs(true);
        var params = { targets: hosts.join('\n'), confirm: confirmInput.value, threads: threadsFix(), attemptOffline: fixOffline._cb.checked, winrmHeal: fixWinrmHeal._cb.checked };
        if (key === 'Encryption') params.enableEncryption = enableEnc;
        if (key === 'PkiRoots') params.certBundleFolder = bundleFolder;
        run = ctx.run(meta.action, params, { keyOf: keyByHost, destructive: true });
        bindFixRun();
      }

      // ---- Target-driven run-all: every CHECKED pillar on every Target host ----
      async function doRunAll() {
        if (isRunning()) return;
        var hosts = targets.hosts();
        if (!hosts.length) { alertDialog('No target hosts', NEED_TARGETS); return; }
        var checkedPillars = checkedFixable();
        if (!checkedPillars.length) { alertDialog('Nothing checked', 'Check at least one fixable pillar before running.'); return; }
        if (!ctx.session.state.credSet) { alertDialog('Admin session required', 'Set ADW credentials (top-right) and start an admin session before running - it changes machines.'); return; }
        if (confirmInput.value !== 'FIX') { alertDialog('Type FIX to Confirm', 'Type FIX (exactly, uppercase) in the Confirm box to arm the run-all.'); return; }

        // Every host gets every CHECKED pillar - the engine runs each pillar verify-first.
        var plan = hosts.map(function (h) { return { host: h, pillars: checkedPillars.slice() }; });
        var enableEnc = !!(encEnableCb && encEnableCb._cb.checked && checkedPillars.indexOf('Encryption') >= 0);
        var bundleFolder = String(pkiBundleInput.value || '').trim();
        var pkiChecked = checkedPillars.indexOf('PkiRoots') >= 0;

        var pf = [
          { label: 'Admin session (' + (ctx.session.state.user || 'session') + ')', ok: !!ctx.session.state.credSet },
          { label: hosts.length + ' target host(s) x ' + checkedPillars.length + ' pillar(s): ' + checkedPillars.join(', '), ok: true },
          { label: 'Verify-first: each pillar reports NO CHANGE on a host already compliant, so "all pillars on all targets" is safe', ok: true }
        ];
        pf.push({ label: enableEnc ? 'ENABLE BitLocker: WILL start XtsAes256 encryption on EVERY FullyDecrypted FIXED volume (OS + DATA; removable/USB untouched)' : 'Encryption resume-only (ENABLE not ticked)', ok: true });
        if (pkiChecked) pf.push({ label: bundleFolder ? 'PKI cert bundle: ' + bundleFolder : 'PKI: using shipped DoD default (Packages\\DoD-Certs)', ok: true });
        if (fixWinrmHeal._cb.checked) pf.push({ label: 'WinRM-heal (RPC) armed for unreachable hosts', ok: true });

        var ok = await ctx.arm({
          title: 'Arm FIX SELECTED PILLARS ON TARGET LIST',
          banner: 'DESTRUCTIVE - THIS CHANGES LIVE MACHINES',
          body: 'About to fix <b>' + hosts.length + '</b> target host(s), each getting all <b>' + checkedPillars.length + '</b> checked pillar(s): <b>' + esc(checkedPillars.join(', ')) + '</b>.'
            + '<br>Every fixer is <b>verify-first</b> - a host already compliant for a pillar is reported NO CHANGE and left untouched. That is why running all checked pillars against every target is safe: only what is actually wrong per host changes.'
            + (enableEnc ? '<br><b>ENABLE BitLocker:</b> hosts will START XtsAes256 full-volume encryption on <b>every FullyDecrypted FIXED volume</b> - the OS volume (TPM) AND fixed DATA volumes (D:, E:, ... via recovery-password + AD/Entra escrow + auto-unlock); removable / USB drives are never touched. Runs for hours in the background.' : '<br>Encryption is resume-only (tick ENABLE BitLocker on the Encryption card to start encryption).'),
          preflight: pf, okText: 'RUN ON TARGET LIST', cancelText: 'Cancel'
        });
        if (!ok) { log.append({ text: '[' + ts() + '] Run-all cancelled at the arming dialog.', level: 'warn' }); return; }

        grid.clear(); prog.reset(); countLine.textContent = '0 / ' + hosts.length;
        hosts.forEach(function (h) { grid.upsert({ Host: h, Ping: '', Status: 'Queued', Detail: 'Queued' }); });
        log.banner('C2C RUN ALL on ' + hosts.length + ' target host(s) [' + checkedPillars.join(', ') + ']');
        lockInputs(true);
        run = ctx.run('run-all', {
          plan: JSON.stringify(plan),
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
      renderFixCards();                                   // six fix cards render immediately (no import needed)
      offTargets = targets.model.onChange(function () { updateTargetButtons(); });   // live fix-button counts
      updateTargetButtons();

      log.append({ text: 'C2C Nemesis ready. Add hosts to Target Computers (type / paste / Import TXT, or Import a C2C CSV to auto-load them), pick pillars, then Fix - one pillar or all at once. Every fixer is verify-first, so it only changes what is actually wrong per host. Import is optional.', level: 'accent' });
      log.append({ text: 'Read-only side: C2C Readiness Scan + Version Check across the same Target Computers (9 scored checks + 2 EXT). The full per-check report streams here.', level: 'dim' });

      host.appendChild(root);
      this._root = root; this._unsub = function () { if (unsub) unsub(); if (offTargets) offTargets(); };
    },
    unmount: function () { try { if (this._unsub) this._unsub(); } catch (e) {} if (this._root) this._root.remove(); }
  });
})();
