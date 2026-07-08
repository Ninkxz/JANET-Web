/* ============================================================================
   c2c.view.js  -  C2C Nemesis (tool id: 'c2c')
   Comply-to-Connect (AFI/MPTO rule 3.B.2.B) quarantine predictor + remediation.

   TWO surfaces share one Results grid + Activity log:

   1. READ-ONLY "C2C Readiness Scan" (action id 'scan'): paste/add targets, the
      engine fans one worker per host, runs ONE consolidated read-only probe (11
      C2C checks: 9 scored locally, 2 EXT/reported), streams the full per-check
      report to the log, and emits one verdict row per host. Changes NOTHING and
      is NOT gated on an admin session.

   2. IMPORT-DRIVEN FIX (v1.5.0, destructive, admin-session gated) - mirrors the
      ACAS Nemesis Updater idiom: IMPORT the Tanium C2C Compliance CSV, and the
      import populates one CARD PER FIXABLE PILLAR (Monitoring / Firewall /
      Encryption / AntiMalware / Patches), each carrying its OWN affected-host
      list. Each card = checkbox (checked by default) + affected-host count +
      View hosts + a per-card Fix; the Encryption card carries the ENABLE
      BitLocker toggle. RUN ALL fixes every CHECKED card's hosts (each host, its
      own checked failed pillars) in one pass. PkiRoots / Vuln / OSVersion / STIG
      are shown as ROUTED-ELSEWHERE info cards (never dialed). The .sst PKI fixer
      was dropped in v1.5.0.

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
    ['AntiMalware', 'Anti-malware installed + signatures up to date (Defender RTP + sig age)'],
    ['Patches', 'All requisite patches installed (0 pending MECM/CCM updates)'],
    ['VulnThreshold', 'Below the vulnerability threshold  [EXT - scored server-side (ARAD/ACAS)]'],
    ['Encryption', 'Data-at-rest encryption active (BitLocker On for the system drive)'],
    ['AppWhitelist', 'Application whitelist active (AppLocker or WDAC enforcing)'],
    ['Agents', 'Patching + security agents installed and active (CcmExec + a security agent)'],
    ['PkiRoots', 'PKI trust roots baseline present (DoD roots in LocalMachine\\Root)'],
    ['Coams', 'All 7 COAMS tags applied  [EXT - ARAD/ePO server-side, not endpoint-readable]'],
    ['Hostname', 'AFNET/AFNS valid hostname (matches the naming convention)']
  ];

  // Endpoint-fixable pillars (drive the import-built FIX cards + RUN ALL). Must
  // match the engine's $script:C2cFixablePillars (v1.5.0 - PkiRoots dropped).
  var FIXABLE = ['Monitoring', 'Firewall', 'Encryption', 'AntiMalware', 'Patches'];

  // Per-fixable-pillar card metadata: canonical key -> action id + display + blurb.
  var FIX_META = {
    Monitoring:  { action: 'fix-monitoring',  label: 'Monitoring (Tanium)',    desc: 'Verify Tanium SOFTWARE installed (uninstall registry) + heal the client service (Automatic + start).' },
    Firewall:    { action: 'fix-firewall',    label: 'Firewall',               desc: 'Enable any disabled Domain / Private / Public firewall profile.' },
    Encryption:  { action: 'fix-encryption',  label: 'Encryption (BitLocker)', desc: 'Resume suspended protectors; opt-in ENABLE on FullyDecrypted OS volumes.' },
    AntiMalware: { action: 'fix-antimalware', label: 'AntiMalware (Defender)', desc: 'Start WinDefend / Sense (Automatic), enable RTP, update stale signatures.' },
    Patches:     { action: 'fix-patches',     label: 'Patches (MECM cycle)',   desc: 'Trigger the MECM SUM scan (113) + eval (108); installs run async.' }
  };

  // Routed-elsewhere pillars: shown as non-runnable info cards (host counts only).
  var ROUTED = [
    { key: 'Vuln',      label: 'Vuln (ACAS / KEV)',   route: 'ACAS / Reports / KEV tools' },
    { key: 'OSVersion', label: 'OS Version',          route: 'Windows Upgrade tool' },
    { key: 'STIG',      label: 'STIG',                route: 'Reports / STIG' },
    { key: 'PkiRoots',  label: 'PKI Trust Roots',     route: 'DoD roots via GPO / desk-side (.sst import not available)' }
  ];

  function statusCellCls(v) {
    switch (String(v)) {
      // green: no failing pillars (scan) / at least one pillar fixed or encryption started (fix).
      case 'READY':
      case 'FIXED':
      case 'STARTED': return 'st-ok';
      // red: at least one scored pillar failed -> predicted quarantine; or unreachable; or the fix failed.
      case 'QUARANTINE RISK':
      case 'OFFLINE':
      case 'FAILED': return 'st-bad';
      // amber: no fail but a check errored, the host couldn't be evaluated, operator cancel,
      // a partial fix, or a self/DNS skip.
      case 'CHECK ERRORS':
      case 'Cancelled':
      case 'ERROR':
      case 'DNS MISMATCH':
      case 'PARTIAL':
      case 'SKIPPED': return 'st-warn';
      // blue: nothing changed (fix), encryption already running, or live in-progress phases streamed by the engine.
      case 'NO CHANGE':
      case 'IN PROGRESS':
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
      var run = null, unsub = null;
      var lastImport = null;             // last import summary (pillars + host lists + runAllPlan)
      var fixChecked = {};               // pillar name -> bool (card checkbox state; default true)
      var encEnableCb = null;            // the ENABLE-BitLocker checkbox on the Encryption card
      var importTiles = null;            // hero StatCards (built in the import card below)

      // =================== layout ===================
      var root = el('div'); root.style.cssText = 'display:flex;flex-direction:column;height:100%;min-height:0;background:var(--bg)';

      var body = el('div'); body.style.cssText = 'flex:1;min-height:0;display:flex;gap:14px;padding:14px 16px 0';
      root.appendChild(body);

      // ---------- LEFT: CONFIG COLUMN ----------
      var left = el('div'); left.style.cssText = 'flex:0 0 470px;display:flex;flex-direction:column;gap:12px;min-height:0;overflow:auto';
      body.appendChild(left);

      // --- Computers (TargetManager) for the read-only scan ---
      var compCard = sectionCard('TARGET COMPUTERS (read-only scan)');
      compCard.style.cssText += ';flex:0 0 auto;display:flex;flex-direction:column';
      var targets = C.TargetManager({
        model: ctx.util.targetModel(''),
        hint: 'One host per line - comma/space/semicolon ok; # starts a comment. Used by the read-only Scan (the FIX cards below carry their own imported hosts).',
        placeholder: 'WS-0001\nWS-0002\n# lab row\nWS-0003',
        importLabel: 'Import TXT', importAccept: '.txt',
        countNoun: 'computer',
        onImport: function (n, name) { log.append({ text: '[' + ts() + '] Added ' + n + ' computer(s) from ' + name, level: 'info' }); }
      });
      var tgHolder = el('div'); tgHolder.style.cssText = 'flex:1;min-height:0;display:flex'; tgHolder.appendChild(targets.el);
      compCard.appendChild(tgHolder);
      left.appendChild(compCard);

      // --- IMPORT C2C COMPLIANCE CSV (Tanium export; local parse, no admin gate) ---
      var importCard = sectionCard('IMPORT C2C COMPLIANCE CSV', 'cyan');
      var importIntro = el('div'); importIntro.style.cssText = 'font-size:12px;line-height:1.4;color:var(--muted);margin-bottom:8px';
      importIntro.textContent = 'Import the Tanium "C2C Compliance Status" CSV export. The import builds one FIX card per endpoint-fixable pillar below (each carrying its own affected hosts); RUN ALL fixes every checked card at once.';
      importCard.appendChild(importIntro);
      var importFileInput = el('input'); importFileInput.type = 'file'; importFileInput.accept = '.csv,.txt'; importFileInput.style.display = 'none';
      var importBtn = ui.ctaButton('IMPORT C2C CSV', { title: 'Choose the Tanium C2C Compliance Status CSV export, upload it to the JANET Web host, and parse it (per-host pillar routing).' });
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
      // convenience: load all non-compliant hosts into the scan target list
      var loadScanWrap = el('div'); loadScanWrap.style.cssText = 'margin-top:6px;display:flex;gap:6px;flex-wrap:wrap';
      importCard.appendChild(loadScanWrap);
      importFileInput.addEventListener('change', function () { if (importFileInput.files && importFileInput.files.length) doImport(); });
      importBtn.onclick = function () { if (isRunning()) return; importFileInput.value = ''; importFileInput.click(); };
      left.appendChild(importCard);

      // --- FIX (import-driven cards; destructive; admin session required) ---
      var fixCard = sectionCard('FIX - IMPORTED PILLARS (destructive)', 'cyan');
      var fixIntro = el('div'); fixIntro.style.cssText = 'font-size:12px;line-height:1.4;color:var(--muted);margin-bottom:8px';
      fixIntro.textContent = 'One card per endpoint-fixable pillar the import found. Each card pushes ONLY to the hosts that failed it. Check the cards you want, type FIX once, then Fix a single card or RUN ALL the checked ones. Requires an admin session.';
      fixCard.appendChild(fixIntro);

      // controls row (shown once an import has fixable cards)
      var fixControls = el('div'); fixControls.style.cssText = 'display:none;flex-direction:column;gap:8px;margin-bottom:8px';
      var ctlRow1 = el('div'); ctlRow1.style.cssText = 'display:flex;align-items:center;gap:8px;flex-wrap:wrap';
      var selAllBtn = ui.ghostButton('Select all', { size: 'sm', title: 'Check every fixable card.' });
      var selNoneBtn = ui.ghostButton('Select none', { size: 'sm', title: 'Uncheck every fixable card.' });
      selAllBtn.onclick = function () { setAllChecked(true); };
      selNoneBtn.onclick = function () { setAllChecked(false); };
      var ctlSp = el('div'); ctlSp.style.flex = '1';
      var runAllBtn = ui.button('RUN ALL', { variant: 'danger', size: 'sm', title: 'Fix every CHECKED card - each host gets only its own checked failed pillars, in one pass (destructive).' });
      runAllBtn.onclick = function () { doRunAll(); };
      ctlRow1.appendChild(selAllBtn); ctlRow1.appendChild(selNoneBtn); ctlRow1.appendChild(ctlSp); ctlRow1.appendChild(runAllBtn);
      fixControls.appendChild(ctlRow1);

      var ctlRow2 = el('div'); ctlRow2.style.cssText = 'display:flex;align-items:center;gap:8px;flex-wrap:wrap';
      ctlRow2.appendChild(ui.label('Confirm:'));
      var confirmInput = ui.input({ title: 'Type FIX (exactly) to arm any per-card fix or RUN ALL.' }); confirmInput.placeholder = 'type FIX'; confirmInput.style.width = '110px';
      ctlRow2.appendChild(confirmInput);
      ctlRow2.appendChild(ui.label('Max concurrent:'));
      var fixThreads = ui.number({ value: 8, min: 1, max: 16, title: 'Parallel hosts (1-16).' }); fixThreads.style.width = '68px';
      ctlRow2.appendChild(fixThreads);
      var fixCancelBtn = ui.button('CANCEL RUN', { size: 'sm', title: 'Cancel the in-flight fix run (queued targets skip; in-flight fixes finish).' });
      fixCancelBtn.disabled = true;
      fixCancelBtn.onclick = function () { if (run) { run.cancel(); log.append({ text: '[' + ts() + '] CANCEL requested - queued targets will skip; in-flight fixes finish.', level: 'warn' }); } };
      ctlRow2.appendChild(fixCancelBtn);
      fixControls.appendChild(ctlRow2);

      var fixOffline = ui.checkbox('Attempt even if offline (host unreachable)', { title: 'Try a session even if the TCP 5985/445 probe fails.' });
      fixOffline.style.margin = '0'; fixControls.appendChild(fixOffline);
      fixCard.appendChild(fixControls);

      // fixable-card body + routed-card body (populated on import)
      var fixBody = el('div'); fixBody.style.cssText = 'display:flex;flex-direction:column;gap:8px';
      fixCard.appendChild(fixBody);
      var fixEmpty = el('div', 'muted', 'No fix cards yet - import a C2C Compliance CSV above.');
      fixEmpty.style.cssText = 'padding:14px;text-align:center;font-size:12px;border:1px dashed var(--edge);border-radius:3px';
      fixBody.appendChild(fixEmpty);
      left.appendChild(fixCard);

      // --- What this scans (read-only info) ---
      var infoCard = sectionCard('WHAT THIS SCANS - Comply-to-Connect (rule 3.B.2.B)', 'cyan');
      var intro = el('div'); intro.style.cssText = 'font-size:12.5px;line-height:1.45;color:var(--text);margin-bottom:8px';
      intro.textContent = 'One consolidated READ-ONLY probe per host (changes nothing) over WinRM. '
        + 'Predicts whether each host would be QUARANTINED. 9 checks are scored on the endpoint; '
        + '2 are EXT (external / server-side) - reported but never scored. '
        + 'This tool also IMPORTS the Tanium C2C Compliance report (above) and FIXES the '
        + 'endpoint-fixable pillars - Monitoring, Firewall, Encryption, AntiMalware and Patches - '
        + 'per card or all at once (RUN ALL). '
        + 'PKI roots route to GPO / desk-side, Vuln to ACAS / Reports / KEV, OS Version to Windows Upgrade, STIG to Reports.';
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
        emptyText: 'No results yet - add computers then Scan, or import a CSV then Fix.',
        keyMode: { hostCol: 'Host' }, popOut: true,
        columns: [
          { key: 'Host', label: 'HOST', width: 170 },
          { key: 'Ping', label: 'PING', width: 90, render: function (r) { return { text: r.Ping == null ? '' : String(r.Ping), cls: pingCellCls(r.Ping) }; } },
          { key: 'Status', label: 'STATUS', width: 150, render: function (r) { return { text: r.Status == null ? '' : String(r.Status), cls: statusCellCls(r.Status) }; } },
          { key: 'Detail', label: 'DETAIL', render: function (r) { var t = r.Detail == null ? '' : String(r.Detail); return { text: t, title: t }; } }
        ],
        rowClass: function (r) {
          var s = String(r.Status);
          if (s === 'READY' || s === 'FIXED' || s === 'STARTED') return 'row-ok';
          if (s === 'QUARANTINE RISK' || s === 'OFFLINE' || s === 'FAILED') return 'row-bad';
          if (s === 'CHECK ERRORS' || s === 'Cancelled' || s === 'ERROR' || s === 'DNS MISMATCH' || s === 'PARTIAL' || s === 'SKIPPED') return 'row-warn';
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

      // fixable pillars actually present in this import (>=1 failed host).
      function presentFixable() {
        if (!lastImport) return [];
        var byName = {};
        (lastImport.pillars || []).forEach(function (p) { byName[p.name] = p; });
        return FIXABLE.filter(function (k) { return byName[k] && byName[k].failedCount > 0; });
      }
      function pillarData(name) {
        if (!lastImport) return null;
        var found = (lastImport.pillars || []).filter(function (p) { return p.name === name; })[0];
        return found || null;
      }

      function lockInputs(on) {
        offlineCb._cb.disabled = on; threadsInput.disabled = on; clearBtn.disabled = on;
        importBtn.disabled = on;
        selAllBtn.disabled = on; selNoneBtn.disabled = on; runAllBtn.disabled = on;
        fixThreads.disabled = on; fixOffline._cb.disabled = on; confirmInput.disabled = on;
        if (encEnableCb) encEnableCb._cb.disabled = on;
        // per-card Fix buttons
        Array.prototype.forEach.call(fixBody.querySelectorAll('[data-fixbtn]'), function (b) { b.disabled = on; });
        // the shared cancel button is only usable WHILE a run is active.
        fixCancelBtn.disabled = !on;
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

      // ---- Import C2C Compliance CSV (read-only; no admin session, no confirm) ----
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
        lastImport = null; loadScanWrap.innerHTML = '';
        log.banner('Import C2C Compliance CSV: ' + f.name);
        ctx.uploadFile(f).then(function (p) {
          log.append({ text: 'Uploaded to host: ' + p, level: 'dim' });
          importStatus.textContent = 'Parsing ' + f.name + ' ...'; importStatus.className = 'st-info';
          run = ctx.run('import', { csvPath: p });
          if (unsub) unsub();
          unsub = run.subscribe({
            status: function (t) { importStatus.textContent = t; },
            row: function () {},   // import rows drive the cards/log, not the results grid
            log: function (l) { log.append(l); },
            error: function (e) { importStatus.textContent = 'Import failed'; importStatus.className = 'st-bad'; log.append({ text: '[' + ts() + '] ' + (e && e.text ? e.text : 'error'), level: 'err' }); },
            active: function (a) { importBtn.disabled = a; },
            final: function (res) { renderImportSummary((res && res.summary) || {}); }
          });
        }).catch(function (e) {
          importStatus.textContent = 'Upload failed: ' + (e && e.message); importStatus.className = 'st-bad';
          log.append({ text: 'Upload failed: ' + (e && e.message), level: 'err' });
        });
      }

      function renderImportSummary(s) {
        lastImport = s;
        var fixablePlan = (s.runAllPlan && s.runAllPlan.length) ? s.runAllPlan.length : 0;
        var nonCompliant = s.nonCompliant || 0;
        var routedOnly = Math.max(0, nonCompliant - fixablePlan);
        importTiles.setAll({ total: s.total || 0, noncompliant: nonCompliant, fixable: fixablePlan, routed: routedOnly });
        importStatus.textContent = 'Imported ' + (s.total || 0) + ' host(s): ' + (s.compliant || 0) + ' compliant, ' + nonCompliant + ' non-compliant.';
        importStatus.className = 'st-ok';

        // default every fixable card CHECKED
        fixChecked = {};
        presentFixable().forEach(function (k) { fixChecked[k] = true; });
        renderFixCards();

        // convenience: load ALL non-compliant hosts into the scan target list
        loadScanWrap.innerHTML = '';
        var allHosts = (s.nonCompliantHosts && s.nonCompliantHosts.length) ? s.nonCompliantHosts : [];
        if (allHosts.length) {
          var b = ui.ghostButton('Load ' + allHosts.length + ' non-compliant -> scan targets', { size: 'sm', title: 'Replace the read-only Scan target list with every non-compliant host.' });
          b.onclick = function () { if (isRunning()) return; targets.setText(allHosts.join('\n')); log.append({ text: '[' + ts() + '] Loaded ' + allHosts.length + ' non-compliant host(s) into the scan target list.', level: 'accent' }); };
          loadScanWrap.appendChild(b);
        }
      }

      function setAllChecked(on) {
        presentFixable().forEach(function (k) { fixChecked[k] = on; });
        renderFixCards();
      }

      // ---- render one card per fixable pillar + routed info cards ----
      function renderFixCards() {
        fixBody.innerHTML = ''; encEnableCb = null;
        var fixable = presentFixable();
        if (!lastImport) {
          fixControls.style.display = 'none';
          fixBody.appendChild(fixEmpty);
          return;
        }
        if (fixable.length === 0 && routedPresent().length === 0) {
          fixControls.style.display = 'none';
          var noneHint = el('div', 'muted', 'Import parsed OK but no host has a fixable or routed failing pillar.');
          noneHint.style.cssText = 'padding:12px;text-align:center;font-size:12px;border:1px dashed var(--edge);border-radius:3px';
          fixBody.appendChild(noneHint);
          return;
        }
        fixControls.style.display = fixable.length ? 'flex' : 'none';

        if (fixable.length) {
          fixBody.appendChild(sectionEyebrow('FIXABLE HERE  (' + fixable.length + ')'));
          fixable.forEach(function (k) { fixBody.appendChild(buildFixCard(k, pillarData(k))); });
        }
        var routed = routedPresent();
        if (routed.length) {
          fixBody.appendChild(sectionEyebrow('ROUTED ELSEWHERE  (' + routed.length + ')'));
          routed.forEach(function (r) { fixBody.appendChild(buildRoutedCard(r.meta, r.data)); });
        }
      }

      function routedPresent() {
        if (!lastImport) return [];
        return ROUTED.map(function (m) { return { meta: m, data: pillarData(m.key) }; })
                     .filter(function (x) { return x.data && x.data.failedCount > 0; });
      }

      function sectionEyebrow(t) {
        var h = el('div', 'j-eyebrow', t); h.style.cssText += ';margin:6px 0 2px'; return h;
      }

      function buildFixCard(key, data) {
        var meta = FIX_META[key];
        var count = (data && data.failedCount) || 0;
        var box = el('div', 'j-card'); box.style.cssText += ';padding:10px 12px';
        var r1 = el('div'); r1.style.cssText = 'display:flex;align-items:flex-start;gap:8px';
        var cb = el('input'); cb.type = 'checkbox'; cb.checked = fixChecked[key] !== false; cb.style.marginTop = '3px';
        cb.title = 'Include ' + meta.label + ' in RUN ALL.';
        cb.addEventListener('change', function () { fixChecked[key] = cb.checked; });
        r1.appendChild(cb);

        var txt = el('div'); txt.style.cssText = 'flex:1;min-width:0';
        var nm = el('div'); nm.style.cssText = 'font-weight:700;font-size:12.5px;color:var(--text)'; nm.textContent = meta.label;
        var ds = el('div'); ds.style.cssText = 'font-size:11.5px;line-height:1.35;color:var(--muted)'; ds.textContent = meta.desc;
        txt.appendChild(nm); txt.appendChild(ds);
        r1.appendChild(txt);

        var right = el('div'); right.style.cssText = 'display:flex;flex-direction:column;align-items:flex-end;gap:5px;flex:0 0 auto';
        var hostLbl = el('div'); hostLbl.style.cssText = 'font-family:var(--mono);font-size:11px;color:var(--cyan);cursor:pointer;text-decoration:underline dotted';
        hostLbl.textContent = count + ' host' + (count === 1 ? '' : 's');
        hostLbl.title = 'Click to review the affected host list.';
        hostLbl.onclick = function () { showPillarHosts(key, data); };
        right.appendChild(hostLbl);
        r1.appendChild(right);
        box.appendChild(r1);

        // Encryption card: the ENABLE-BitLocker opt-in toggle
        if (key === 'Encryption') {
          encEnableCb = ui.checkbox('ENABLE BitLocker on FullyDecrypted OS volumes (XtsAes256)', { title: 'Opt-in. On a FullyDecrypted OS volume: add a RecoveryPassword protector and escrow it (Entra-first, AD fallback) FIRST - fail-closed: if escrow fails, the protector is removed and encryption is NEVER started - then add a TPM protector and start XtsAes256 full-disk encryption. Requires a TPM-ready + domain-joined host. Applies to this card and to RUN ALL.' });
          encEnableCb._cb.checked = false;
          encEnableCb.style.margin = '6px 0 2px 22px';
          box.appendChild(encEnableCb);
        }

        var r2 = el('div'); r2.style.cssText = 'display:flex;align-items:center;gap:8px;margin-top:8px';
        var r2sp = el('div'); r2sp.style.flex = '1'; r2.appendChild(r2sp);
        var fixBtn = ui.button('Fix on ' + count, { variant: 'danger', size: 'sm', title: 'Run the ' + meta.label + ' remediation on this pillar\'s ' + count + ' affected host(s) (destructive).' });
        fixBtn.setAttribute('data-fixbtn', key);
        fixBtn.disabled = count === 0;
        fixBtn.onclick = function () { doPillarFix(key, data); };
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

      // review the exact host set a fix card will push to.
      function showPillarHosts(key, data) {
        var hosts = (data && data.hosts) ? data.hosts.slice() : [];
        var b = el('div');
        var d = el('div'); d.style.cssText = 'font-size:11.5px;color:var(--text-dim);margin-bottom:8px';
        d.innerHTML = '<b>' + esc((FIX_META[key] && FIX_META[key].label) || key) + '</b><br>' + hosts.length + ' affected host(s). Fix pushes ONLY to these.';
        b.appendChild(d);
        var listBox = el('div'); listBox.style.cssText = 'max-height:260px;overflow:auto;font-family:var(--mono);font-size:11.5px;border:1px solid var(--edge);border-radius:3px;padding:6px 8px;background:var(--bg)';
        if (hosts.length) hosts.forEach(function (h) { var r = el('div'); r.textContent = h; listBox.appendChild(r); });
        else { var em = el('div', 'muted'); em.textContent = '(no hosts resolved)'; listBox.appendChild(em); }
        b.appendChild(listBox);
        ctx.confirm({ title: 'Affected hosts - ' + ((FIX_META[key] && FIX_META[key].label) || key), body: b, okText: 'Close', cancelText: null });
      }

      // ---- Per-card fix (DESTRUCTIVE; admin session + FIX confirm required) ----
      async function doPillarFix(key, data) {
        if (isRunning()) return;
        var meta = FIX_META[key];
        var hosts = (data && data.hosts) ? data.hosts.slice() : [];
        if (!hosts.length) { alertDialog('No affected hosts', 'No affected hosts resolved for ' + meta.label + '. Re-import the C2C CSV.'); return; }
        if (!ctx.session.state.credSet) { alertDialog('Admin session required', 'Set ADW credentials (top-right) and start an admin session before running a fix - it changes machines.'); return; }
        if (confirmInput.value !== 'FIX') { alertDialog('Type FIX to Confirm', 'Type FIX (exactly, uppercase) in the Confirm box to arm the destructive fix.'); return; }
        var enableEnc = key === 'Encryption' && encEnableCb && encEnableCb._cb.checked;

        var pf = [
          { label: hosts.length + ' affected host(s) queued', ok: hosts.length > 0 },
          { label: 'Admin session (' + (ctx.session.state.user || 'session') + ')', ok: !!ctx.session.state.credSet }
        ];
        if (key === 'Encryption') pf.push({ label: enableEnc ? 'ENABLE BitLocker: WILL start encryption on decrypted OS volumes' : 'Resume-only (ENABLE not ticked)', ok: true });

        var ok = await ctx.arm({
          title: 'Arm Fix ' + meta.label,
          banner: 'DESTRUCTIVE - THIS CHANGES LIVE MACHINES',
          body: 'About to run <b>Fix ' + esc(meta.label) + '</b> on <b>' + hosts.length + '</b> affected host(s).'
            + (enableEnc ? '<br><b>ENABLE BitLocker:</b> this run will START full-disk encryption (XtsAes256) on any of the <b>' + hosts.length + '</b> host(s) whose OS volume is FullyDecrypted - escrow-first, TPM-ready + domain-joined only. Encryption runs for hours in the background.' : ''),
          preflight: pf, okText: 'Run Fix ' + meta.label, cancelText: 'Cancel'
        });
        if (!ok) { log.append({ text: '[' + ts() + '] Fix ' + meta.label + ' cancelled at the arming dialog.', level: 'warn' }); return; }

        grid.clear(); prog.reset(); countLine.textContent = '0 / ' + hosts.length;
        hosts.forEach(function (h) { grid.upsert({ Host: h, Ping: '', Status: 'Queued', Detail: 'Queued' }); });
        log.banner('C2C Fix ' + meta.label + ' on ' + hosts.length + ' host(s)');
        lockInputs(true);
        var params = { targets: hosts.join('\n'), confirm: confirmInput.value, threads: threadsFix(), attemptOffline: fixOffline._cb.checked };
        if (key === 'Encryption') params.enableEncryption = enableEnc;
        run = ctx.run(meta.action, params, { keyOf: keyByHost, destructive: true });
        bindFixRun();
      }

      // ---- RUN ALL: each CHECKED fixable card's hosts, its OWN checked pillars ----
      async function doRunAll() {
        if (isRunning()) return;
        var basePlan = (lastImport && lastImport.runAllPlan && lastImport.runAllPlan.length) ? lastImport.runAllPlan : [];
        if (!basePlan.length) { alertDialog('Nothing to run', 'Import a C2C Compliance CSV first - RUN ALL needs a non-empty plan.'); return; }
        var checkedPillars = presentFixable().filter(function (k) { return fixChecked[k] !== false; });
        if (!checkedPillars.length) { alertDialog('Nothing checked', 'Check at least one fixable card before RUN ALL.'); return; }
        // build the plan: each host keeps only its own CHECKED failed pillars (intersect with the import plan)
        var plan = basePlan.map(function (e) {
          var keep = (e.pillars || []).filter(function (p) { return checkedPillars.indexOf(p) >= 0; });
          return keep.length ? { host: e.host, pillars: keep } : null;
        }).filter(function (x) { return x; });
        if (!plan.length) { alertDialog('Nothing to run', 'No host has a CHECKED fixable pillar.'); return; }
        if (!ctx.session.state.credSet) { alertDialog('Admin session required', 'Set ADW credentials (top-right) and start an admin session before RUN ALL - it changes machines.'); return; }
        if (confirmInput.value !== 'FIX') { alertDialog('Type FIX to Confirm', 'Type FIX (exactly, uppercase) in the Confirm box to arm RUN ALL.'); return; }

        var pcount = {}, totalFixes = 0;
        plan.forEach(function (e) { (e.pillars || []).forEach(function (p) { pcount[p] = (pcount[p] || 0) + 1; totalFixes++; }); });
        var enableEnc = !!(encEnableCb && encEnableCb._cb.checked && checkedPillars.indexOf('Encryption') >= 0);

        var pf = Object.keys(pcount).sort().map(function (p) { return { label: p + ': ' + pcount[p] + ' host(s)', ok: true }; });
        pf.unshift({ label: 'Admin session (' + (ctx.session.state.user || 'session') + ')', ok: !!ctx.session.state.credSet });
        pf.push({ label: enableEnc ? 'ENABLE BitLocker: checked Encryption hosts WILL start encryption' : 'Encryption resume-only (ENABLE not ticked)', ok: true });

        var ok = await ctx.arm({
          title: 'Arm RUN ALL',
          banner: 'DESTRUCTIVE - THIS CHANGES LIVE MACHINES',
          body: 'About to fix <b>' + plan.length + '</b> host(s) - each its OWN checked failed pillars (<b>' + totalFixes + '</b> fix(es) total).'
            + '<br>Per-pillar host counts: <b>' + esc(Object.keys(pcount).sort().map(function (p) { return p + ' ' + pcount[p]; }).join(', ')) + '</b>'
            + (enableEnc ? '<br><b>ENABLE BitLocker:</b> checked Encryption hosts will START encryption on FullyDecrypted OS volumes.' : '<br>Encryption is resume-only (tick ENABLE BitLocker on the Encryption card to start encryption).'),
          preflight: pf, okText: 'RUN ALL', cancelText: 'Cancel'
        });
        if (!ok) { log.append({ text: '[' + ts() + '] RUN ALL cancelled at the arming dialog.', level: 'warn' }); return; }

        var allHosts = plan.map(function (e) { return e.host; });
        grid.clear(); prog.reset(); countLine.textContent = '0 / ' + allHosts.length;
        allHosts.forEach(function (h) { grid.upsert({ Host: h, Ping: '', Status: 'Queued', Detail: 'Queued' }); });
        log.banner('C2C RUN ALL on ' + plan.length + ' host(s) [' + totalFixes + ' fix(es)]');
        lockInputs(true);
        run = ctx.run('run-all', {
          plan: JSON.stringify(plan),
          enableEncryption: enableEnc,
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
      log.append({ text: 'C2C Nemesis ready. Add computers then run the C2C Readiness Scan (read-only), or import the Tanium C2C Compliance CSV to build the FIX cards.', level: 'accent' });
      log.append({ text: '9 scored checks (Monitoring, Firewall, AntiMalware, Patches, Encryption, AppWhitelist, Agents, PkiRoots, Hostname) + 2 EXT (VulnThreshold, Coams). The full per-check report streams here.', level: 'dim' });

      host.appendChild(root);
      this._root = root; this._unsub = function () { if (unsub) unsub(); };
    },
    unmount: function () { try { if (this._unsub) this._unsub(); } catch (e) {} if (this._root) this._root.remove(); }
  });
})();
