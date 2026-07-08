/* ============================================================================
   c2c.view.js  -  C2C Nemesis (tool id: 'c2c')
   Read-only Comply-to-Connect (AFI/MPTO rule 3.B.2.B) quarantine predictor.
   Faithful single-window (non-tabbed) build mirroring the suite idiom
   (winupgrade / wpt): a left config column (TARGET COMPUTERS at the top, a
   short "what this scans" info card, small scan options, then a single Scan
   action bar) beside a colour-coded per-host Results grid, with a sticky footer
   carrying progress + Export CSV + a streaming ActivityLog.

   Read-only "C2C Readiness Scan" (action id 'scan'): the engine fans one worker
   per host, runs ONE consolidated read-only probe (11 C2C checks: 9 scored locally,
   2 EXT/reported), streams the FULL per-check report to the activity log
   ([PASS]/[FAIL]/[EXT]/[ERROR] lines the log colours), and emits one final row per
   host ({ Host, Ping, Status, Detail }). Rows are keyed by Host. The scan CHANGES
   NOTHING and is NOT gated on an admin session (read-only, like the WPT ping /
   bulk-scan and the WinUpgrade Diagnose action).

   Plus the ACTION half (v1.4.0, destructive, admin-session gated): IMPORT the Tanium
   C2C CSV, then either a PER-PILLAR fix (six actions - fix-monitoring / -firewall /
   -antimalware / -patches / -encryption / -pki, each its own Run button in the FIX
   ACTIONS card) or RUN ALL (fix each imported non-compliant host's OWN failed
   endpoint-fixable pillars in one pass). All fix rows share one FIX confirm input.

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
    ['Monitoring', 'Endpoint monitoring installed (Tanium client service running)'],
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

  // Endpoint-fixable pillars (drive the import chips, the per-pillar "Load X hosts"
  // buttons, and the FIX ACTIONS card). Must match the engine's C2cFixablePillars.
  var FIXABLE = ['Monitoring', 'Firewall', 'Encryption', 'AntiMalware', 'PkiRoots', 'Patches'];

  // Per-pillar fix rows: canonical key -> action id, display label, one-line "what changes".
  var FIX_PILLARS = [
    { key: 'Monitoring',  action: 'fix-monitoring',  label: 'Fix Monitoring (Tanium)',    desc: 'Heal the Tanium client service: set Automatic + start it (FAIL if not installed).' },
    { key: 'Firewall',    action: 'fix-firewall',    label: 'Fix Firewall',               desc: 'Enable any disabled Domain / Private / Public firewall profile.' },
    { key: 'AntiMalware', action: 'fix-antimalware', label: 'Fix AntiMalware (Defender)', desc: 'Start WinDefend / Sense (Automatic), enable RTP, update stale signatures.' },
    { key: 'Patches',     action: 'fix-patches',     label: 'Fix Patches (MECM cycle)',   desc: 'Trigger the MECM SUM scan (113) + eval (108); installs run async.' },
    { key: 'Encryption',  action: 'fix-encryption',  label: 'Fix Encryption (BitLocker)', desc: 'Resume suspended protectors; opt-in ENABLE on FullyDecrypted OS volumes.' },
    { key: 'PkiRoots',    action: 'fix-pki',         label: 'Fix PKI Roots',              desc: 'Add DoD roots from an operator .sst to LocalMachine\\Root (additive only).' }
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

      // =================== layout ===================
      var root = el('div'); root.style.cssText = 'display:flex;flex-direction:column;height:100%;min-height:0;background:var(--bg)';

      var body = el('div'); body.style.cssText = 'flex:1;min-height:0;display:flex;gap:14px;padding:14px 16px 0';
      root.appendChild(body);

      // ---------- LEFT: CONFIG COLUMN ----------
      var left = el('div'); left.style.cssText = 'flex:0 0 440px;display:flex;flex-direction:column;gap:12px;min-height:0;overflow:auto';
      body.appendChild(left);

      // --- Computers (TargetManager) --- at the TOP of the config column; bounded
      // height so the info card / options / action bar stay visible below.
      var compCard = sectionCard('TARGET COMPUTERS');
      // Auto height (no cap): the bar/group rows wrap at narrow widths, so a fixed
      // max-height clips them - the left column scrolls instead.
      compCard.style.cssText += ';flex:0 0 auto;display:flex;flex-direction:column';
      var targets = C.TargetManager({
        model: ctx.util.targetModel(''),
        hint: 'One host per line - comma/space/semicolon ok; # starts a comment.',
        placeholder: 'WS-0001\nWS-0002\n# lab row\nWS-0003',
        importLabel: 'Import TXT', importAccept: '.txt',
        countNoun: 'computer',
        onImport: function (n, name) { log.append({ text: '[' + ts() + '] Added ' + n + ' computer(s) from ' + name, level: 'info' }); }
      });
      var tgHolder = el('div'); tgHolder.style.cssText = 'flex:1;min-height:0;display:flex'; tgHolder.appendChild(targets.el);
      compCard.appendChild(tgHolder);
      left.appendChild(compCard);

      // --- IMPORT C2C COMPLIANCE CSV (Tanium export; local parse, no admin gate) ---
      var lastImport = null;             // last import summary (pillars + host lists)
      var importCard = sectionCard('IMPORT C2C COMPLIANCE CSV', 'cyan');
      var importIntro = el('div'); importIntro.style.cssText = 'font-size:12px;line-height:1.4;color:var(--muted);margin-bottom:8px';
      importIntro.textContent = 'Import the Tanium "C2C Compliance Status" CSV export, then RUN ALL (each host, its own failed pillars) or load a pillar\'s failing hosts into the target list above to scan or per-pillar fix.';
      importCard.appendChild(importIntro);
      var importFileInput = el('input'); importFileInput.type = 'file'; importFileInput.accept = '.csv,.txt'; importFileInput.style.display = 'none';
      var importBtn = ui.ctaButton('IMPORT C2C CSV', { title: 'Choose the Tanium C2C Compliance Status CSV export, upload it to the JANET Web host, and parse it (per-host pillar routing).' });
      importBtn.style.maxWidth = '260px';
      var importRow = el('div'); importRow.style.cssText = 'display:flex;gap:8px;align-items:center;flex-wrap:wrap'; importRow.appendChild(importBtn);
      importCard.appendChild(importRow); importCard.appendChild(importFileInput);
      var importStatus = el('div', 'muted', 'Idle.'); importStatus.style.cssText = 'margin-top:8px;font-size:12px';
      importCard.appendChild(importStatus);
      var chipsWrap = el('div'); chipsWrap.style.cssText = 'margin-top:8px;line-height:2';
      importCard.appendChild(chipsWrap);
      var loadBtnsWrap = el('div'); loadBtnsWrap.style.cssText = 'margin-top:6px;display:flex;gap:6px;flex-wrap:wrap';
      importCard.appendChild(loadBtnsWrap);
      // RUN ALL button holder (populated by renderImportSummary when runAllPlan is non-empty).
      var runAllWrap = el('div'); runAllWrap.style.cssText = 'margin-top:8px;display:flex;gap:6px;flex-wrap:wrap';
      importCard.appendChild(runAllWrap);
      var runAllBtn = null;
      importFileInput.addEventListener('change', function () { if (importFileInput.files && importFileInput.files.length) doImport(); });
      importBtn.onclick = function () { if (isRunning()) return; importFileInput.value = ''; importFileInput.click(); };
      left.appendChild(importCard);

      // --- FIX ACTIONS (per pillar; destructive; admin session required) ---
      // Each pillar is its own runnable action (like the ACAS nemesis tool: everything
      // portioned out per finding type). One shared FIX confirm + admin-session gate.
      var sstPath = '';                  // uploaded .sst server path (blank until chosen)
      var pillarRunBtns = [];            // per-row Run buttons (locked while any run is active)
      var fixCard = sectionCard('FIX ACTIONS (per pillar) - run one remediation at a time', 'cyan');
      var fixIntro = el('div'); fixIntro.style.cssText = 'font-size:12px;line-height:1.4;color:var(--muted);margin-bottom:8px';
      fixIntro.textContent = 'DESTRUCTIVE. Each pillar runs on its own against the target list above. Requires an admin session; type FIX once (below) to arm any of them.';
      fixCard.appendChild(fixIntro);

      // The ENABLE-BitLocker opt-in (used by the Encryption row) + the .sst picker (used
      // by the PKI Roots row) are declared here so run-all can read them too.
      var cbEncEnable = ui.checkbox('ENABLE BitLocker on FullyDecrypted OS volumes (XtsAes256)', { title: 'Opt-in. On a FullyDecrypted OS volume: add a RecoveryPassword protector and escrow it (Entra-first, AD fallback) FIRST - fail-closed: if escrow fails, the protector is removed and encryption is NEVER started - then add a TPM protector and start XtsAes256 full-disk encryption. Requires a TPM-ready + domain-joined host. Encryption then runs for hours in the background; protection activates on completion. Applies to the Encryption row and to RUN ALL.' });
      cbEncEnable._cb.checked = false;

      var sstFileInput = el('input'); sstFileInput.type = 'file'; sstFileInput.accept = '.sst,.p7b'; sstFileInput.style.display = 'none';
      var sstBtn = ui.button('Choose .sst', { size: 'sm', title: 'Pick the DoD root bundle (.sst) to push (used by Fix PKI Roots and by RUN ALL when a host plans PkiRoots).' });
      var sstLabel = el('span', 'muted', 'no .sst chosen'); sstLabel.style.fontSize = '11.5px';
      sstBtn.onclick = function () { sstFileInput.value = ''; sstFileInput.click(); };
      sstFileInput.addEventListener('change', function () {
        var f = sstFileInput.files && sstFileInput.files[0]; if (!f) return;
        sstLabel.textContent = 'uploading ' + f.name + ' ...'; sstLabel.className = 'st-info';
        ctx.uploadFile(f, 'c2c-sst').then(function (p) { sstPath = p; sstLabel.textContent = f.name; sstLabel.className = 'st-ok'; log.append({ text: '[' + ts() + '] .sst staged: ' + p, level: 'dim' }); })
          .catch(function (e) { sstPath = ''; sstLabel.textContent = 'upload failed'; sstLabel.className = 'st-bad'; log.append({ text: 'sst upload failed: ' + (e && e.message), level: 'err' }); });
      });

      // one row per pillar: label + description + a small Run button; Encryption gets the
      // indented ENABLE checkbox, PKI Roots gets the .sst picker.
      FIX_PILLARS.forEach(function (row) {
        var rowEl = el('div'); rowEl.style.cssText = 'display:flex;align-items:flex-start;gap:10px;padding:6px 0;border-top:1px solid var(--border)';
        var txt = el('div'); txt.style.cssText = 'flex:1;min-width:0';
        var nm = el('div'); nm.style.cssText = 'font-weight:700;font-size:12.5px;color:var(--text)'; nm.textContent = row.label;
        var ds = el('div'); ds.style.cssText = 'font-size:11.5px;line-height:1.35;color:var(--muted)'; ds.textContent = row.desc;
        txt.appendChild(nm); txt.appendChild(ds);
        var runBtn = ui.button('Run', { size: 'sm', variant: 'danger', title: 'Run the ' + row.label + ' remediation on the target list (destructive).' });
        runBtn.style.flex = '0 0 auto';
        runBtn.onclick = function () { doPillarFix(row); };
        pillarRunBtns.push(runBtn);
        rowEl.appendChild(txt); rowEl.appendChild(runBtn);
        fixCard.appendChild(rowEl);
        if (row.key === 'Encryption') {
          cbEncEnable.style.margin = '2px 0 4px 22px'; fixCard.appendChild(cbEncEnable);
        }
        if (row.key === 'PkiRoots') {
          var sstRow = el('div'); sstRow.style.cssText = 'display:flex;gap:8px;align-items:center;margin:2px 0 4px 22px';
          sstRow.appendChild(sstBtn); sstRow.appendChild(sstLabel); sstRow.appendChild(sstFileInput);
          fixCard.appendChild(sstRow);
        }
      });

      // shared options: threads + attempt-offline + confirm word + a cancel button.
      var fixOptRow = el('div'); fixOptRow.style.cssText = 'display:flex;align-items:center;gap:10px;margin:8px 0 4px;border-top:1px solid var(--border);padding-top:8px';
      fixOptRow.appendChild(ui.label('Max concurrent:'));
      var fixThreads = ui.number({ value: 8, min: 1, max: 16, title: 'Parallel hosts (1-16).' }); fixThreads.style.width = '72px';
      fixOptRow.appendChild(fixThreads);
      fixCard.appendChild(fixOptRow);
      var fixOffline = ui.checkbox('Attempt even if offline (host unreachable)', { title: 'Try a session even if the TCP 5985/445 probe fails.' });
      fixOffline.style.margin = '2px 0'; fixCard.appendChild(fixOffline);
      var confirmRow = el('div'); confirmRow.style.cssText = 'display:flex;align-items:center;gap:8px;margin:8px 0';
      confirmRow.appendChild(ui.label('Confirm:'));
      var confirmInput = ui.input({ title: 'Type FIX (exactly) to arm any per-pillar fix or RUN ALL.' }); confirmInput.placeholder = 'type FIX'; confirmInput.style.width = '120px';
      confirmRow.appendChild(confirmInput);
      var fixCancelBtn = ui.button('CANCEL RUN', { size: 'sm', title: 'Cancel the in-flight fix run (queued targets skip; in-flight fixes finish).' });
      fixCancelBtn.disabled = true;
      fixCancelBtn.onclick = function () { if (run) { run.cancel(); log.append({ text: '[' + ts() + '] CANCEL requested - queued targets will skip; in-flight fixes finish.', level: 'warn' }); } };
      confirmRow.appendChild(fixCancelBtn);
      fixCard.appendChild(confirmRow);
      left.appendChild(fixCard);

      // --- What this scans (read-only info) ---
      var infoCard = sectionCard('WHAT THIS SCANS - Comply-to-Connect (rule 3.B.2.B)', 'cyan');
      var intro = el('div'); intro.style.cssText = 'font-size:12.5px;line-height:1.45;color:var(--text);margin-bottom:8px';
      intro.textContent = 'One consolidated READ-ONLY probe per host (changes nothing) over WinRM. '
        + 'Predicts whether each host would be QUARANTINED. 9 checks are scored on the endpoint; '
        + '2 are EXT (external / server-side) - reported but never scored. '
        + 'This tool also IMPORTS the Tanium C2C Compliance report (above) and can FIX the '
        + 'endpoint-fixable pillars - Monitoring, Firewall, Encryption, AntiMalware, PkiRoots and Patches - '
        + 'one at a time (FIX ACTIONS card) or all imported hosts at once (RUN ALL). '
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
        emptyText: 'No results yet — add computers, then run C2C Readiness Scan.',
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

      function lockInputs(on) {
        offlineCb._cb.disabled = on; threadsInput.disabled = on; clearBtn.disabled = on;
        // lock the import + per-pillar fix controls too, so nothing can be re-fired mid-run.
        importBtn.disabled = on;
        pillarRunBtns.forEach(function (b) { b.disabled = on; });
        if (runAllBtn) { runAllBtn.disabled = on; }
        cbEncEnable._cb.disabled = on;
        sstBtn.disabled = on; fixThreads.disabled = on; fixOffline._cb.disabled = on; confirmInput.disabled = on;
        // the shared cancel button is only usable WHILE a run is active.
        fixCancelBtn.disabled = !on;
      }

      function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }

      function summarize() {
        var ready = 0, risk = 0, offline = 0;
        grid.rows().forEach(function (r) {
          var s = String(r.Status);
          if (s === 'READY') ready++;
          else if (s === 'QUARANTINE RISK') risk++;
          else if (s === 'OFFLINE') offline++;
        });
        var total = grid.rows().length;
        // errors is a catch-all so the buckets always reconcile to total, regardless of the
        // exact failure label a fork emits (CHECK ERRORS / Cancelled / ERROR / DNS MISMATCH).
        var errors = total - ready - risk - offline;
        return { ready: ready, risk: risk, errors: errors, offline: offline, total: total };
      }

      // ---- bind a streaming run handle to the grid/log/progress surfaces ----
      function bindRun(verb) {
        if (unsub) unsub();
        unsub = run.subscribe({
          status: function (t) { prog.setPhase(t); runbar.setStatus(t, 'st-info'); },
          progress: function (p) { prog.setProgress(p.done, p.total); countLine.textContent = p.done + ' / ' + p.total; },
          row: function (r) { grid.upsert(r); },
          // append engine log lines VERBATIM - the full 11-line per-check report,
          // uncut, so the log colours each [PASS]/[FAIL]/[EXT]/[ERROR] line.
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
        // seed a Queued row per host so nothing looks empty before the first stream-back.
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

      function keyByHost(ev) { return ev.Host != null ? String(ev.Host) : (ev.host != null ? String(ev.host) : null); }

      // ---- Import C2C Compliance CSV (read-only; no admin session, no confirm) ----
      function doImport() {
        if (isRunning()) return;
        var files = importFileInput.files ? Array.prototype.slice.call(importFileInput.files) : [];
        if (!files.length) { ctx.confirm({ title: 'No file', body: 'Choose the Tanium C2C Compliance Status CSV export first.', okText: 'OK', cancelText: null }); return; }
        var f = files[0];
        if (/\.(xlsx|xlsm|xlsb|xls)$/i.test(f.name || '')) {
          ctx.confirm({ title: 'Excel workbook - not a CSV', body: esc(f.name) + ' is an Excel workbook. The C2C import must be a CSV - re-export from Tanium (or Save As -> CSV UTF-8), then import that.', okText: 'OK', cancelText: null });
          return;
        }
        importStatus.textContent = 'Uploading ' + f.name + ' ...'; importStatus.className = 'st-info';
        chipsWrap.innerHTML = ''; loadBtnsWrap.innerHTML = ''; lastImport = null;
        log.banner('Import C2C Compliance CSV: ' + f.name);
        ctx.uploadFile(f).then(function (p) {
          log.append({ text: 'Uploaded to host: ' + p, level: 'dim' });
          importStatus.textContent = 'Parsing ' + f.name + ' ...'; importStatus.className = 'st-info';
          run = ctx.run('import', { csvPath: p });
          if (unsub) unsub();
          unsub = run.subscribe({
            status: function (t) { importStatus.textContent = t; },
            // import rows have a different shape (Host/Compliance/Failed/Audit/Fqdn) than the
            // scan/fix grid (Host/Ping/Status/Detail), so they drive chips + the log, not the grid.
            row: function () {},
            log: function (l) { log.append(l); },
            error: function (e) { importStatus.textContent = 'Import failed'; importStatus.className = 'st-bad'; log.append({ text: '[' + ts() + '] ' + (e && e.text ? e.text : 'error'), level: 'err' }); },
            active: function (a) { importBtn.disabled = a; if (!a && !lastImport) { /* no summary => nothing loaded */ } },
            final: function (res) { renderImportSummary((res && res.summary) || {}); }
          });
        }).catch(function (e) {
          importStatus.textContent = 'Upload failed: ' + (e && e.message); importStatus.className = 'st-bad';
          log.append({ text: 'Upload failed: ' + (e && e.message), level: 'err' });
        });
      }

      function renderImportSummary(s) {
        lastImport = s;
        var pillars = s.pillars || [];
        importStatus.textContent = 'Imported ' + (s.total || 0) + ' host(s): ' + (s.compliant || 0) + ' compliant, ' + (s.nonCompliant || 0) + ' non-compliant.';
        importStatus.className = 'st-ok';
        chipsWrap.innerHTML = ''; loadBtnsWrap.innerHTML = '';
        pillars.forEach(function (p) {
          var fix = FIXABLE.indexOf(p.name) >= 0;
          var chip = el('span'); chip.textContent = p.name + ': ' + p.failedCount; chip.title = p.routing;
          chip.style.cssText = 'display:inline-block;margin:2px 6px 2px 0;padding:2px 9px;border-radius:11px;font-size:11.5px;background:var(--panel2);color:var(--text);border:1px solid ' + (fix ? 'var(--accent)' : 'var(--border)');
          chipsWrap.appendChild(chip);
        });
        // Load ALL non-compliant (uses the engine's exact non-compliant host list).
        var allHosts = (s.nonCompliantHosts && s.nonCompliantHosts.length) ? s.nonCompliantHosts : unionPillarHosts(pillars);
        var allBtn = ui.button('Load ALL non-compliant (' + allHosts.length + ') -> targets', { variant: 'gold', size: 'sm', title: 'Replace the target list with every non-compliant host.' });
        allBtn.onclick = function () { loadHosts(allHosts, 'all non-compliant'); };
        loadBtnsWrap.appendChild(allBtn);
        // One small button per FIXABLE pillar with failing hosts.
        pillars.forEach(function (p) {
          if (FIXABLE.indexOf(p.name) < 0 || !p.failedCount) return;
          var b = ui.ghostButton('Load ' + p.name + ' (' + p.failedCount + ')', { size: 'sm', title: p.routing });
          b.onclick = function () { loadHosts(p.hosts || [], p.name + ' hosts'); };
          loadBtnsWrap.appendChild(b);
        });
        // RUN ALL: shown only when the import carried a non-empty runAllPlan.
        runAllWrap.innerHTML = ''; runAllBtn = null;
        var plan = (s.runAllPlan && s.runAllPlan.length) ? s.runAllPlan : [];
        if (plan.length) {
          var fixes = 0; plan.forEach(function (e) { fixes += (e.pillars || []).length; });
          runAllBtn = ui.button('RUN ALL (' + plan.length + ' hosts, ' + fixes + ' fixes)', { variant: 'danger', size: 'sm', title: 'Fix each imported non-compliant host\'s OWN failed endpoint-fixable pillars in one pass (destructive; type FIX + admin session).' });
          runAllBtn.onclick = function () { doRunAll(); };
          runAllWrap.appendChild(runAllBtn);
          var hint = el('span', 'muted', 'each host, its own failed pillars'); hint.style.cssText = 'font-size:11px;align-self:center';
          runAllWrap.appendChild(hint);
        }
      }

      function unionPillarHosts(pillars) {
        var seen = {}, out = [];
        (pillars || []).forEach(function (p) { (p.hosts || []).forEach(function (h) { if (!seen[h]) { seen[h] = 1; out.push(h); } }); });
        return out;
      }

      // Replace the TargetManager contents with a pillar's host list.
      function loadHosts(hosts, label) {
        if (isRunning()) return;
        hosts = hosts || [];
        if (!hosts.length) { ctx.confirm({ title: 'No hosts', body: 'There are no hosts for ' + esc(label) + '.', okText: 'OK', cancelText: null }); return; }
        targets.setText(hosts.join('\n'));
        log.append({ text: '[' + ts() + '] Loaded ' + hosts.length + ' ' + label + ' into the target list.', level: 'accent' });
      }

      function alertDialog(title, body) { ctx.confirm({ title: title, body: body, okText: 'OK', cancelText: null }); }

      // ---- Per-pillar fix (DESTRUCTIVE; admin session + FIX confirm required) ----
      async function doPillarFix(row) {
        if (isRunning()) return;
        var hosts = targets.hosts();
        if (!hosts.length) { alertDialog('No Computers', 'Add at least one computer (or Load a pillar\'s hosts from an import) before running a fix.'); return; }
        if (!ctx.session.state.credSet) { alertDialog('Admin session required', 'Set ADW credentials (top-right) and start an admin session before running a fix - it changes machines.'); return; }
        if (confirmInput.value !== 'FIX') { alertDialog('Type FIX to Confirm', 'Type FIX (exactly, uppercase) in the Confirm box to arm the destructive fix.'); return; }
        if (row.key === 'PkiRoots' && !sstPath) { alertDialog('PKI Roots Need a .sst', 'The PKI Roots fix requires a DoD root bundle (.sst). Choose one first.'); return; }
        var enableEnc = row.key === 'Encryption' && cbEncEnable._cb.checked;

        var pf = [
          { label: hosts.length + ' target host(s) queued', ok: hosts.length > 0 },
          { label: 'Admin session (' + (ctx.session.state.user || 'session') + ')', ok: !!ctx.session.state.credSet }
        ];
        if (row.key === 'Encryption') pf.push({ label: enableEnc ? 'ENABLE BitLocker: WILL start encryption on decrypted OS volumes' : 'Resume-only (ENABLE not ticked)', ok: true });
        if (row.key === 'PkiRoots') pf.push({ label: 'DoD root .sst attached', ok: !!sstPath });

        var ok = await ctx.arm({
          title: 'Arm ' + row.label,
          banner: 'DESTRUCTIVE - THIS CHANGES LIVE MACHINES',
          body: 'About to run <b>' + esc(row.label) + '</b> on <b>' + hosts.length + '</b> host(s).'
            + (row.key === 'PkiRoots' ? '<br>PKI bundle: <b>' + esc(sstPath ? sstPath.split(/[\\/]/).pop() : '(none)') + '</b>' : '')
            + (enableEnc ? '<br><b>ENABLE BitLocker:</b> this run will START full-disk encryption (XtsAes256) on any of the <b>' + hosts.length + '</b> host(s) whose OS volume is FullyDecrypted - escrow-first, TPM-ready + domain-joined only. Encryption runs for hours in the background.' : ''),
          preflight: pf, okText: 'Run ' + row.label, cancelText: 'Cancel'
        });
        if (!ok) { log.append({ text: '[' + ts() + '] ' + row.label + ' cancelled at the arming dialog.', level: 'warn' }); return; }

        grid.clear(); prog.reset(); countLine.textContent = '0 / ' + hosts.length;
        hosts.forEach(function (h) { grid.upsert({ Host: h, Ping: '', Status: 'Queued', Detail: 'Queued' }); });
        log.banner('C2C ' + row.label + ' on ' + hosts.length + ' host(s)');
        lockInputs(true);
        var params = { targets: hosts.join('\n'), confirm: confirmInput.value, threads: threadsFix(), attemptOffline: fixOffline._cb.checked };
        if (row.key === 'Encryption') params.enableEncryption = enableEnc;
        if (row.key === 'PkiRoots') params.sstPath = sstPath || '';
        run = ctx.run(row.action, params, { keyOf: keyByHost, destructive: true });
        bindFixRun();
      }

      // ---- RUN ALL: each imported non-compliant host, its OWN failed pillars only ----
      async function doRunAll() {
        if (isRunning()) return;
        var plan = (lastImport && lastImport.runAllPlan && lastImport.runAllPlan.length) ? lastImport.runAllPlan : [];
        if (!plan.length) { alertDialog('Nothing to run', 'Import a C2C Compliance CSV first - RUN ALL needs a non-empty plan.'); return; }
        if (!ctx.session.state.credSet) { alertDialog('Admin session required', 'Set ADW credentials (top-right) and start an admin session before RUN ALL - it changes machines.'); return; }
        if (confirmInput.value !== 'FIX') { alertDialog('Type FIX to Confirm', 'Type FIX (exactly, uppercase) in the Confirm box (in the FIX ACTIONS card) to arm RUN ALL.'); return; }

        var pcount = {}, totalFixes = 0;
        plan.forEach(function (e) { (e.pillars || []).forEach(function (p) { pcount[p] = (pcount[p] || 0) + 1; totalFixes++; }); });
        var anyPki = !!pcount['PkiRoots'];
        if (anyPki && !sstPath) { alertDialog('PKI Roots Need a .sst', 'One or more planned hosts include PkiRoots. Attach a DoD root .sst (in the FIX ACTIONS card) before RUN ALL, or it will abort server-side.'); return; }
        var enableEnc = cbEncEnable._cb.checked;

        var pf = Object.keys(pcount).sort().map(function (p) { return { label: p + ': ' + pcount[p] + ' host(s)', ok: true }; });
        pf.unshift({ label: 'Admin session (' + (ctx.session.state.user || 'session') + ')', ok: !!ctx.session.state.credSet });
        pf.push({ label: enableEnc ? 'ENABLE BitLocker: planned Encryption hosts WILL start encryption' : 'Encryption resume-only (ENABLE not ticked)', ok: true });
        if (anyPki) pf.push({ label: 'DoD root .sst attached (PkiRoots planned)', ok: !!sstPath });

        var ok = await ctx.arm({
          title: 'Arm RUN ALL',
          banner: 'DESTRUCTIVE - THIS CHANGES LIVE MACHINES',
          body: 'About to fix <b>' + plan.length + '</b> imported non-compliant host(s) - each its OWN failed pillars (<b>' + totalFixes + '</b> fix(es) total).'
            + '<br>Per-pillar host counts: <b>' + esc(Object.keys(pcount).sort().map(function (p) { return p + ' ' + pcount[p]; }).join(', ')) + '</b>'
            + (enableEnc ? '<br><b>ENABLE BitLocker:</b> planned Encryption hosts will START encryption on FullyDecrypted OS volumes.' : '<br>Encryption is resume-only (tick ENABLE BitLocker in the FIX ACTIONS card to start encryption).'),
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
          sstPath: sstPath || '',
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
        if (!rows.length) { ctx.confirm({ title: 'Nothing to export', body: 'Run a scan first - there are no result rows yet.', okText: 'OK', cancelText: null }); return; }
        var csv = ctx.util.toCsv(EXPORT_COLS.map(function (p) { return p[1]; }), rows, EXPORT_COLS.map(function (p) { return p[0]; }));
        ctx.util.downloadBlob('C2CReadiness_results_' + ctx.util.fileStamp() + '.csv', 'text/csv', csv);
        log.append({ text: '[' + ts() + '] Exported ' + rows.length + ' row(s) to CSV.', level: 'info' });
      }

      // =================== init ===================
      log.append({ text: 'C2C Nemesis ready. Add computers, then run the C2C Readiness Scan (read-only - changes nothing, no admin session needed).', level: 'accent' });
      log.append({ text: '9 scored checks (Monitoring, Firewall, AntiMalware, Patches, Encryption, AppWhitelist, Agents, PkiRoots, Hostname) + 2 EXT (VulnThreshold, Coams). The full per-check report streams here.', level: 'dim' });

      host.appendChild(root);
      this._root = root; this._unsub = function () { if (unsub) unsub(); };
    },
    unmount: function () { try { if (this._unsub) this._unsub(); } catch (e) {} if (this._root) this._root.remove(); }
  });
})();
