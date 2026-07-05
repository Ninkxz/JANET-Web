/* ============================================================================
   acas.view.js  -  ACAS Nemesis Tool (tool id: 'acas')
   Faithful web re-build per docs/ui-specs/acas.md of the desktop AFNET
   vulnerability-remediation tool. The desktop tool is a numbered-sidebar
   panel-swap shell (Start / Targets / Updater / Not Updatable / KB Installer /
   Vulnerabilities / Logs / Backbone); here we use the shared TabHost (left rail)
   and reproduce the workflow that actually matters:

       IMPORT  ->  ANALYZE  ->  one CARD PER VULNERABILITY  ->  PATCH / VERIFY
                                                            +   RUN-ALL / BULK

   The signature experience is the Updater tab: one card per rolled-up
   vulnerability (checkbox + affected-host count + a profile-variant picker),
   grouped by category, with smart-dispatch run controls that stream per-host
   colour-coded results into a pop-out-capable ActivityLog while live hero
   StatCards (findings / patchable / patched / failed) recompute from results.

   ALL server I/O goes through ctx.run -> RunController (per-row keyed uniquely);
   the CSV is uploaded via ctx.uploadFile and only its server path is passed to
   the engine. GET /status (localOnly banner) uses ctx.api (read-only, allowed).
   Credentials are universal (shell header) - this view never renders a cred
   control; destructive runs only READ ctx.session.state.credSet.

   Wired engine actions (ids/params/columns from Get-JanetToolManifest + the
   engine switch): import-acas, analyze-remediation, auto-patch, run-vulnerability,
   run-all-sequential, run-all-parallel, preflight-services, plus the engine's
   group-findings (per-card finding drill-down) and list-profiles (Backbone).
   Card runs dispatch against the EXPLICIT affected-host list analyze returns
   (operator can review it): one card -> run-vulnerability(targets=hosts); the
   checked / runnable sets -> run-all-parallel / run-all-sequential(jobs).
   ========================================================================== */
(function () {
  'use strict';

  // category -> display + ordering (Patchable first, like the desktop summary).
  var CAT_ORDER = ['Patchable', 'Experimental', 'Reboot', 'Unpatchable', 'NotUpdatable'];
  var CAT_LABEL = {
    Patchable: 'PATCHABLE', Experimental: 'EXPERIMENTAL', Reboot: 'REBOOT REQUIRED',
    Unpatchable: 'UNPATCHABLE', NotUpdatable: 'NOT UPDATABLE'
  };

  function sevClass(sev) {
    var s = String(sev || '').toLowerCase();
    if (s.indexOf('crit') >= 0) return 'sev-crit';
    if (s.indexOf('high') >= 0) return 'sev-high';
    if (s.indexOf('med') >= 0) return 'sev-med';
    if (s.indexOf('low') >= 0 || s.indexOf('info') >= 0) return 'sev-low';
    return 'sev-low';
  }
  // severity cell renderer shared by the import / vulns / kb-findings grids
  function sevCell(key) {
    return function (r) {
      var v = r[key];
      // Map to the dedicated 4-level severity classes so High (orange) and Medium
      // (amber) are visually distinct, not both amber.
      return { text: v == null ? '' : String(v), cls: 'st-' + (sevClass(v) || 'sev-low') };
    };
  }
  function sevColor(sev) {
    var s = String(sev || '').toLowerCase();
    if (s.indexOf('crit') >= 0) return 'var(--sev-crit)';
    if (s.indexOf('high') >= 0) return 'var(--sev-high)';
    if (s.indexOf('med') >= 0) return 'var(--sev-med)';
    return 'var(--sev-low)';
  }
  function resultCls(v) {
    var s = String(v || '').toUpperCase();
    if (s === 'OK') return 'st-ok';
    if (s === 'FAIL') return 'st-bad';
    if (s === 'SKIP') return 'st-warn';
    return '';
  }
  // run-result rows all carry the same Host across (profile,host) tuples; key by
  // Host+Profile so two profiles on one host do not collapse onto one grid row.
  function keyHostProfile(ev) {
    var h = ev.Host != null ? String(ev.Host) : '';
    var p = ev.Profile != null ? String(ev.Profile) : '';
    if (h === '') return (ev._rk != null ? String(ev._rk) : null);
    return h + '||' + p;
  }
  function keyHost(ev) { return ev.Host != null ? String(ev.Host) : (ev._rk != null ? String(ev._rk) : null); }

  JanetViews.register('acas', {
    mount: function (host, ctx) {
      var ui = ctx.ui, C = ctx.components, el = ctx.util.el;

      // ---- cross-tab state ----
      var csvPath = '';                 // server-side temp path of the uploaded CSV
      var csvName = '';                 // friendly file name
      var cards = [];                   // analyze-remediation group descriptors
      var cardState = {};               // key -> { checked, profile }  (operator picks)
      var importedHosts = [];           // affected short hostnames harvested from import-acas
      var run = null, unsub = null;     // current RunController handle + its unsubscribe
      var hostLookupUnsub = null, groupUnsub = null, backboneUnsub = null, kbScanUnsub = null;  // read-only side-runs
      var stat = { findings: 0, patchable: 0, reboot: 0, patched: 0, failed: 0 };

      var root = el('div'); root.style.cssText = 'display:flex;flex-direction:column;height:100%;min-height:0;background:var(--bg)';

      // local-only logging banner (read-only GET /status is allowed per the contract)
      var localBanner = el('div');
      localBanner.style.cssText = 'display:none;margin:10px 14px 0;padding:7px 12px;border:1px solid var(--gold-dim);background:var(--gold-wash);color:var(--gold);font-size:11.5px;border-radius:3px';
      root.appendChild(localBanner);
      if (ctx.api) {
        ctx.api('GET', '/status').then(function (st) {
          if (st && st.localOnly) {
            localBanner.style.display = 'block';
            localBanner.textContent = 'LOCAL-ONLY LOGGING: the audit log share is unreachable; this session writes to a local log only (' + (st.logRoot || 'local') + ').';
          }
        }).catch(function () {});
      }

      // ====================================================================
      //  ACTIVITY LOG  (shared, pop-out-capable; the ONE streaming console)
      // ====================================================================
      var log = C.ActivityLog({ title: 'UPDATER LOG', defaultName: 'ACAS_UpdaterLog' });

      // refs that cross tabs (assigned lazily as panels build). MUST be declared
      // BEFORE the TabHost: TabHost auto-builds the first tab in its constructor
      // (buildImportTab assigns importTiles/importGrid/importProg/importStatus there),
      // so declaring them "= null" AFTER the TabHost would clobber those refs back
      // to null - the import DOM survives but doImport then hits a null importStatus.
      var importTiles = null, importGrid = null, importProg = null, importStatus = null;
      var updaterBody = null, updaterStats = null, updaterStatus = null, updaterProg = null;
      var resultsGrid = null, cancelBtn = null, runAllBtn = null, bulkBtn = null,
          autoPatchBtn = null, refreshBtn = null, preflightBtn = null, patchSelBtn = null, verifySelBtn = null, expCb = null, scCb = null, toInput = null, log4jInput = null;
      var logHolder = null, logDocked = true, popWin = null;
      var vulnsGrid = null, vulnsStatus = null, vulnsSelect = null, vulnsBtn = null;
      var backboneGrid = null;

      // ====================================================================
      //  TAB HOST
      // ====================================================================
      var tabs = C.TabHost({
        rail: 'left',
        helpId: 'acas',
        tabs: [
          { id: 'import', label: '01  IMPORT', build: buildImportTab },
          { id: 'updater', label: '02  UPDATER', build: buildUpdaterTab },
          { id: 'kb', label: '03  KB INSTALLER', build: buildKbTab },
          { id: 'vulns', label: '04  VULNERABILITIES', build: buildVulnsTab },
          { id: 'backbone', label: '05  BACKBONE', build: buildBackboneTab }
        ]
      });
      var tabsHolder = el('div'); tabsHolder.style.cssText = 'flex:1;min-height:0;display:flex'; tabsHolder.appendChild(tabs.el);
      root.appendChild(tabsHolder);

      // shared activity log: a click-to-open drawer docked full-width across the bottom
      // of the TOOL (visible on every tab), not boxed inside the Updater tab's column.
      var logCard = ui.card({}); logCard.classList.add('j-logdock');
      logHolder = el('div'); logHolder.style.cssText = 'flex:1;min-width:0;min-height:0;display:flex;flex-direction:column'; logHolder.appendChild(log.el);
      logCard.appendChild(logHolder);
      root.appendChild(logCard);

      // footer credit + log path (mirrors the desktop status strip)
      var footer = el('div', 'j-footer');
      footer.appendChild(el('span', 'credit', 'Created by: THOMPSON, BRAXTON - 48 CS'));
      var endBtn = ui.ghostButton('End Session / Notes', { size: 'sm', title: 'Record closing notes (+ optional ASI/RFC) for this session to the ACAS Runs log.' });
      endBtn.onclick = doEndSession;
      footer.appendChild(endBtn);
      var logPath = el('span'); logPath.textContent = 'Log: ' + (ctx.session.state.logRoot || '(local)');
      footer.appendChild(logPath);
      root.appendChild(footer);

      // ====================================================================
      //  helpers
      // ====================================================================
      function secHdr(t) { var h = el('div', 'j-section-h', t); h.style.marginBottom = '8px'; return h; }
      function hint(t) { var d = el('div', 'muted', t); d.style.cssText = 'font-size:11px;margin-bottom:8px'; return d; }
      var esc = Janet.util.esc;
      function runActive() { return run && run.state && run.state.active; }
      function pushStats() { if (updaterStats) updaterStats.setAll(stat); }
      // Per-host run cap (seconds) passed to every patch/update action so one hung
      // host is abandoned on its own clock instead of stalling the wave. Floor 30s.
      function perHostTimeoutVal() { var v = toInput ? parseInt(toInput.value, 10) : 720; return (isFinite(v) && v >= 30) ? v : 720; }
      // Optional Log4j staging-source override (UNC/local folder holding log4j-*.jar);
      // blank = engine default. Threaded into analyze + every patch/run dispatch.
      function log4jSrcVal() { var v = log4jInput && log4jInput.value ? String(log4jInput.value).trim() : ''; return v; }

      // ---- End Session / Notes: record closing notes to the ACAS Runs log ----
      function doEndSession() {
        var body = el('div');
        var p = el('div', 'muted'); p.style.cssText = 'font-size:11.5px;margin-bottom:8px';
        p.textContent = 'Record closing notes for this session (written to the ACAS Runs log so they survive an unclean stop). ASI/RFC optional.';
        body.appendChild(p);
        var asi = ui.input({ placeholder: 'ASI / RFC (optional)' }); asi.style.cssText += ';width:100%;margin-bottom:8px;font-size:11.5px';
        body.appendChild(asi);
        var notes = el('textarea'); notes.rows = 4; notes.placeholder = 'Closing notes - what was patched / deferred / RFC...';
        notes.style.cssText = 'width:100%;box-sizing:border-box;font-family:var(--mono);font-size:11.5px;background:var(--bg);border:1px solid var(--edge);color:var(--text);border-radius:3px;padding:6px 8px;resize:vertical';
        body.appendChild(notes);
        ctx.confirm({ title: 'End Session / Notes', body: body, okText: 'Save Notes', cancelText: 'Cancel' }).then(function (ok) {
          if (!ok) return;
          ctx.api('POST', '/session/end', { notes: notes.value || '', asi: asi.value || '' }).then(function (r) {
            log.append({ text: 'Session notes saved. ' + (r.hostsTouched || 0) + ' host(s) touched, ' + (r.vulnsPatched || 0) + ' patched, ' + (r.failures || 0) + ' failure(s).', level: 'ok' });
          }).catch(function (e) { log.append({ text: 'End Session failed: ' + (e && e.message), level: 'err' }); });
        });
      }

      // ---- Find Host: cross-reference one hostname to all its findings (-> Vulns grid) ----
      function doFindHost(h) {
        h = (h || '').trim();
        if (!csvPath) { ctx.confirm({ title: 'No CSV', body: 'Import an ACAS / Nessus CSV on the Import tab first.', okText: 'OK', cancelText: null }); return; }
        if (!h) { ctx.confirm({ title: 'No host', body: 'Enter a hostname to look up.', okText: 'OK', cancelText: null }); return; }
        if (!vulnsGrid) return;
        vulnsGrid.clear(); vulnsStatus.textContent = 'Looking up ' + h + '...'; vulnsStatus.className = 'st-info';
        var rk = 0;
        var hh = ctx.run('findings-for-host', { csvPaths: csvPath, host: h }, { keyOf: function () { return 'h' + (rk++); } });
        if (hostLookupUnsub) hostLookupUnsub(); hostLookupUnsub = hh.subscribe({
          status: function (t) { vulnsStatus.textContent = t; vulnsStatus.className = 'st-info'; },
          row: function (r) { vulnsGrid.upsert(r); },
          log: function (l) { log.append(l); },
          final: function (res) { var s = (res && res.summary) || {}; vulnsStatus.textContent = (s.total != null ? s.total : vulnsGrid.rows().length) + ' finding(s) for ' + h + '.'; vulnsStatus.className = 'st-ok'; }
        });
      }

      function lockRun(on) {
        [runAllBtn, bulkBtn, autoPatchBtn, refreshBtn, preflightBtn, patchSelBtn, verifySelBtn].forEach(function (b) { if (b) b.disabled = on; });
        if (cancelBtn) cancelBtn.disabled = !on;
        // card checkboxes / profile pickers stay enabled for review but the run
        // controls are the gate (single-run lock, like the desktop).
      }

      // affected-host harvest: import-acas rows are { Host, 'Findings Added', ... }
      function rememberImportRow(r) {
        if (r && r.Host) {
          var h = String(r.Host);
          if (importedHosts.indexOf(h) < 0) importedHosts.push(h);
        }
      }

      // ====================================================================
      //  TAB 1 - IMPORT  (Data Import)
      // ====================================================================
      function buildImportTab(panel) {
        panel.style.cssText = 'flex:1;min-height:0;display:flex;flex-direction:column;gap:12px;padding:14px;box-sizing:border-box;overflow:auto';

        var head = ui.card({});
        head.appendChild(secHdr('DATA IMPORT'));
        head.appendChild(hint('Import a Tenable / ACAS-Nessus CSV export (CSV only - if your report is an Excel workbook, Save As CSV first). Hostnames are normalized + de-duplicated and msek-* server findings are dropped. Findings then feed the Updater + Vulnerabilities tabs.'));

        // hero tiles
        importTiles = C.StatCards({ cards: [
          { key: 'targets', label: 'TARGETS LOADED', color: 'cyan' },
          { key: 'findings', label: 'ACAS FINDINGS', color: 'gold' },
          { key: 'hosts', label: 'UNIQUE HOSTS', color: 'accent' },
          { key: 'skipped', label: 'SERVERS SKIPPED', color: 'bad' }
        ] });
        head.appendChild(importTiles.el);

        // action row - ONE button (desktop parity): the Import button opens the file
        // dialog itself and imports as soon as a CSV is picked.
        var actionRow = el('div'); actionRow.style.cssText = 'display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-top:12px';
        var fileInput = el('input'); fileInput.type = 'file'; fileInput.accept = '.csv,.txt,.tsv'; fileInput.multiple = true; fileInput.style.display = 'none';
        var importBtn = ui.ctaButton('IMPORT ACAS CSV', { title: 'Choose one or more Tenable/ACAS-Nessus CSV exports, upload them to the JANET Web host, and parse them together (desktop Multiselect).' });
        importBtn.style.maxWidth = '260px';
        fileInput.addEventListener('change', function () { if (fileInput.files && fileInput.files.length) doImport(); });
        importBtn.onclick = function () { fileInput.value = ''; fileInput.click(); };  // reset so re-picking the same file still fires change
        actionRow.appendChild(importBtn);
        // Clear All (desktop btnClear parity): reset the imported CSV, affected hosts
        // and analyzed cards so the operator can start over without reloading the tool.
        var clearAllBtn = ui.ghostButton('Clear All', { size: 'sm', title: 'Drop the imported CSV, affected hosts and analyzed cards; reset the Updater + Vulnerabilities tabs. Audit history is unaffected.' });
        clearAllBtn.onclick = doClearAll;
        actionRow.appendChild(clearAllBtn);
        head.appendChild(fileInput); head.appendChild(actionRow);

        importStatus = el('div', 'muted', 'Idle.'); importStatus.style.cssText = 'margin-top:8px;font-size:12px';
        head.appendChild(importStatus);
        importProg = C.ProgressStatusStrip({ showCount: true }); importProg.el.style.marginTop = '6px';
        head.appendChild(importProg.el);
        panel.appendChild(head);

        // per-host import grid
        var gridCard = ui.card({}); gridCard.style.cssText += ';flex:1;min-height:200px;display:flex;flex-direction:column';
        gridCard.appendChild(secHdr('PER-HOST IMPORT SUMMARY'));
        importGrid = C.ResultsGrid({
          title: 'ACAS import', keyMode: { hostCol: 'Host' }, popOut: true,
          // Double-click a host row -> jump to the Vulnerabilities tab and drill into
          // that host's findings (select first so the lazy-built vulns grid exists).
          onRowClick: function (r) { tabs.select('vulns'); doFindHost(r.Host); },
          columns: [
            { key: 'Host', label: 'HOST', width: 180 },
            { key: 'Findings Added', label: 'FINDINGS', width: 110 },
            { key: 'Severity (max)', label: 'MAX SEVERITY', width: 140, render: sevCell('Severity (max)') },
            { key: 'Plugins', label: 'PLUGINS', width: 110 },
            { key: 'Servers Skipped', label: 'SERVERS SKIPPED' }
          ]
        });
        var gh = el('div'); gh.style.cssText = 'flex:1;min-height:0;display:flex'; gh.appendChild(importGrid.el);
        gridCard.appendChild(gh);
        panel.appendChild(gridCard);
      }

      function doImport() {
        // the file input lives in the import panel; find it within our root
        var fi = root.querySelector('input[type=file]');
        var files = (fi && fi.files) ? Array.prototype.slice.call(fi.files) : [];
        if (!files.length) { ctx.confirm({ title: 'No file', body: 'Choose one or more ACAS / Nessus CSV exports first.', okText: 'OK', cancelText: null }); return; }
        // Guard: the engine parses with Import-Csv. A binary Excel workbook fed in
        // (the accept= dialog filter is bypassable via "All Files") decodes into
        // garbage rows that flood the grid + auto-analyze and wedge the tab with no
        // way back ("freezes"). Reject it up front with the fix. ponytail: extension
        // sniff covers the real case (Excel's own .xlsx); add a PK/OLE magic-byte
        // check only if a renamed-binary case ever shows up.
        var notCsv = files.filter(function (f) { return /\.(xlsx|xlsm|xlsb|xls)$/i.test(f.name || ''); });
        if (notCsv.length) {
          ctx.confirm({ title: 'Excel workbook - not a CSV', body: notCsv.map(function (f) { return esc(f.name); }).join(', ') + ' is an Excel workbook. ACAS imports must be CSV - a binary workbook parses as garbage and wedges the tool. In Excel: File -> Save As -> CSV UTF-8; or re-export from Tenable / ACAS as CSV, then import that.', okText: 'OK', cancelText: null });
          return;
        }
        if (runActive()) return;
        var label = files.length > 1 ? (files.length + ' files') : files[0].name;
        importStatus.textContent = 'Uploading ' + label + ' ...'; importStatus.className = 'st-info';
        importGrid.clear(); importProg.reset();
        importedHosts = [];
        log.banner('Import ' + label);
        // upload every selected export, then parse them TOGETHER (engine accumulates
        // newline-joined csvPaths into one finding set) - desktop OpenFileDialog Multiselect loop.
        Promise.all(files.map(function (f) {
          return ctx.uploadFile(f).then(function (p) { log.append({ text: 'Uploaded to host: ' + p, level: 'dim' }); return p; });
        })).then(function (paths) {
          csvPath = paths.join('\n'); csvName = label;
          importStatus.textContent = 'Parsing ' + label + ' ...'; importStatus.className = 'st-info';
          run = ctx.run('import-acas', { csvPaths: csvPath });
          if (unsub) unsub();
          var hostCount = 0;
          unsub = run.subscribe({
            status: function (t) { importStatus.textContent = t; importProg.setPhase(t); },
            progress: function (p) { importProg.setProgress(p.done, p.total); },
            row: function (r) { importGrid.upsert(r); rememberImportRow(r); hostCount++; },
            log: function (l) { log.append(l); },
            final: function (res) {
              var s = (res && res.summary) || {};
              importTiles.setAll({
                targets: importedHosts.length,
                findings: s.findings != null ? s.findings : '',
                hosts: s.total != null ? s.total : hostCount,
                skipped: s.serversSkipped != null ? s.serversSkipped : 0
              });
              stat.findings = s.findings != null ? s.findings : 0; pushStats();
              importStatus.textContent = 'Imported ' + (s.total != null ? s.total : hostCount) + ' host(s), ' + (s.findings != null ? s.findings : '?') + ' finding(s).';
              importStatus.className = 'st-ok';
              log.append({ text: 'Import complete. ' + importedHosts.length + ' affected host(s). Building Updater cards...', level: 'ok' });
              // Auto-analyze so the Updater tab is populated without a manual step.
              // Deferred a tick so the import run settles to inactive first (doAnalyze
              // bails while a run is active). Safe even if the Updater tab is unopened:
              // doAnalyze fills `cards` and the tab paints them when first built.
              if (importedHosts.length) setTimeout(doAnalyze, 0);
            },
            active: function () {}
          });
        }).catch(function (e) {
          importStatus.textContent = 'Upload failed: ' + (e && e.message); importStatus.className = 'st-bad';
          log.append({ text: 'Upload failed: ' + (e && e.message), level: 'err' });
        });
      }

      // Clear All (desktop btnClear): drop CSV + targets + analyzed cards and reset
      // every dependent surface. Findings live only client-side (the engine re-parses
      // from csvPath each action), so this is a pure client reset - no engine call.
      function doClearAll() {
        if (!csvPath && !cards.length && !importedHosts.length) {
          ctx.confirm({ title: 'Nothing to clear', body: 'No ACAS data is loaded yet.', okText: 'OK', cancelText: null });
          return;
        }
        if (runActive()) {
          ctx.confirm({ title: 'Run in progress', body: 'A run is in progress. Cancel it (or wait for it to finish) before clearing.', okText: 'OK', cancelText: null });
          return;
        }
        ctx.confirm({
          title: 'Clear all ACAS data?',
          body: 'Drop the imported CSV, ' + importedHosts.length + ' affected host(s) and ' + cards.length + ' analyzed card(s). The Updater and Vulnerabilities tabs reset to empty. Audit history is unaffected.',
          okText: 'Clear All', cancelText: 'Cancel'
        }).then(function (ok) {
          if (!ok) return;
          csvPath = ''; csvName = ''; importedHosts = [];
          cards = []; cardState = {};
          stat.findings = 0; stat.patchable = 0; stat.reboot = 0; stat.patched = 0; stat.failed = 0;
          if (importGrid) importGrid.clear();
          if (importProg) importProg.reset();
          if (importStatus) { importStatus.textContent = 'Idle.'; importStatus.className = 'muted'; }
          if (importTiles) importTiles.setAll({ targets: '', findings: '', hosts: '', skipped: '' });
          pushStats();
          renderCards();
          refreshVulnSelect();
          if (resultsGrid) resultsGrid.clear();
          if (vulnsGrid) vulnsGrid.clear();
          log.append({ text: 'Cleared all ACAS data (CSV, targets, analyzed cards).', level: 'dim' });
        });
      }

      // ====================================================================
      //  TAB 2 - UPDATER  (the signature surface: one card per vulnerability)
      // ====================================================================
      function buildUpdaterTab(panel) {
        panel.style.cssText = 'flex:1;min-height:0;display:flex;flex-direction:column;gap:10px;padding:14px;box-sizing:border-box';

        // header card: title + hero tiles + action row + status
        var head = ui.card({});
        head.appendChild(secHdr('UPDATER'));
        head.appendChild(hint('One card per vulnerability. Each run pushes ONLY to the hosts that vuln affects. Check the cards you want, pick a profile variant, then Patch / Verify - or run the whole set.'));

        updaterStats = C.StatCards({ cards: [
          { key: 'findings', label: 'FINDINGS', color: 'gold' },
          { key: 'patchable', label: 'PATCHABLE', color: 'cyan' },
          { key: 'reboot', label: 'REBOOT', color: 'accent' },
          { key: 'patched', label: 'PATCHED', color: 'ok' },
          { key: 'failed', label: 'FAILED', color: 'bad' }
        ] });
        head.appendChild(updaterStats.el);

        var actions = el('div'); actions.style.cssText = 'display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-top:12px';
        refreshBtn = ui.ghostButton('Analyze / Refresh Cards', { size: 'sm', title: 'Parse the imported CSV and (re)build one card per vulnerability.' });
        preflightBtn = ui.ghostButton('Pre-Flight Services', { size: 'sm', title: 'Ensure winrm / Winmgmt / RemoteRegistry are Running+Automatic on the affected hosts before a wave.' });
        patchSelBtn = ui.button('Patch Selected', { variant: 'gold', size: 'sm', title: 'Push the chosen profile to every host affected by each CHECKED card.' });
        verifySelBtn = ui.button('Verify Selected', { variant: 'cyan', size: 'sm', title: 'Dry-run / verify the CHECKED cards - check current state, change nothing.' });
        runAllBtn = ui.button('Run All (Sequential)', { variant: 'gold', size: 'sm', title: 'Run every runnable card one profile group at a time, draining each before the next.' });
        bulkBtn = ui.button('Bulk Run (Parallel)', { variant: 'go', size: 'sm', title: 'Auto-patch the whole CSV: every matched (profile,host) in parallel under one drain.' });
        autoPatchBtn = ui.button('Auto-Patch From CSV', { variant: 'go', size: 'sm', title: 'Headline workflow: import->match->push the matched remediation to every affected host.' });
        cancelBtn = ui.button('Cancel Run', { variant: 'danger', size: 'sm', title: 'Stop in-flight jobs.' }); cancelBtn.disabled = true;
        var popOut = ui.ghostButton('Pop Out Log', { size: 'sm', title: 'Float the Updater Log in its own window (it keeps streaming).' });
        // Auto-Patch From CSV steering (the engine accepts these; expose them like the desktop)
        expCb = ui.checkbox('Incl. Experimental', { title: 'Auto-Patch: also match Experimental remediations (MS Store / Defender check).' });
        scCb = ui.checkbox('Prefer Software Center', { title: 'Auto-Patch: prefer the Software Center variant of a profile where one exists.' });
        // Per-host timeout knob: one hung host gets abandoned on its own clock so it
        // can't stall the wave. Keep > 600s when a wave includes the slow M365
        // (SYSTEM-task) update; dial it down for fast app-only waves.
        toInput = el('input'); toInput.type = 'number'; toInput.min = '30'; toInput.step = '30'; toInput.value = '720';
        toInput.title = 'Abandon any single host that runs longer than this many seconds; the rest of the wave keeps going. Keep above 600s if the wave includes the M365 (SYSTEM task) update.';
        toInput.style.cssText = 'width:74px;font-family:var(--mono);font-size:11.5px;padding:3px 6px;background:var(--bg);border:1px solid var(--edge);color:var(--text);border-radius:3px';
        var toWrap = el('div'); toWrap.style.cssText = 'display:flex;align-items:center;gap:6px;font-size:11px;color:var(--muted)';
        toWrap.appendChild(el('span', null, 'Host timeout (s)')); toWrap.appendChild(toInput);
        // Optional Log4j staging-source override (folder of log4j-*.jar replacements);
        // blank = engine default. Sent on analyze + every patch/run dispatch.
        log4jInput = el('input'); log4jInput.type = 'text'; log4jInput.placeholder = 'default';
        log4jInput.title = 'Optional Log4j staging source: a UNC/local folder holding the log4j-*.jar replacements used by Log4j remediations. Blank = engine default staging path.';
        log4jInput.style.cssText = 'width:150px;font-family:var(--mono);font-size:11.5px;padding:3px 6px;background:var(--bg);border:1px solid var(--edge);color:var(--text);border-radius:3px';
        var l4Wrap = el('div'); l4Wrap.style.cssText = 'display:flex;align-items:center;gap:6px;font-size:11px;color:var(--muted)';
        l4Wrap.appendChild(el('span', null, 'Log4j source')); l4Wrap.appendChild(log4jInput);
        // Browse for the Log4j 2.25.4 jars (api + core) on the operator's PC; upload them
        // co-located into ONE host folder (X-Janet-Subdir) and point the Log4j source at
        // it, then re-Analyze so the Log4j card un-greys. Web equivalent of the desktop's
        // folder pick: the host reads the uploaded folder (browsers can't return a path).
        // ponytail: jar names are pinned to 2.25.4 (the remediation + readiness check are);
        // bump all three together if the fleet target moves.
        var l4Browse = ui.ghostButton('Browse jars', { size: 'sm', title: 'Pick log4j-api-2.25.4.jar + log4j-core-2.25.4.jar from your PC; they upload to the host and the Log4j card becomes runnable.' });
        l4Browse.onclick = function () {
          var fi = el('input'); fi.type = 'file'; fi.accept = '.jar'; fi.multiple = true; fi.style.display = 'none';
          document.body.appendChild(fi);
          fi.addEventListener('change', function () {
            var picked = fi.files ? Array.prototype.slice.call(fi.files) : []; document.body.removeChild(fi);
            if (!picked.length) return;
            var jars = picked.filter(function (f) { return /^log4j-(api|core)-2\.25\.4\.jar$/i.test(f.name); });
            var hasApi = jars.some(function (f) { return /^log4j-api-2\.25\.4\.jar$/i.test(f.name); });
            var hasCore = jars.some(function (f) { return /^log4j-core-2\.25\.4\.jar$/i.test(f.name); });
            if (!hasApi || !hasCore) {
              ctx.confirm({ title: 'Need both 2.25.4 jars', body: 'Select BOTH log4j-api-2.25.4.jar and log4j-core-2.25.4.jar (the remediation pins 2.25.4). Found: ' + (jars.length ? jars.map(function (f) { return esc(f.name); }).join(', ') : 'none') + '.', okText: 'OK', cancelText: null });
              return;
            }
            log.append({ text: 'Uploading ' + jars.length + ' Log4j jar(s) to the host...', level: 'mode' });
            Promise.all(jars.map(function (f) { return ctx.uploadFile(f, 'log4j'); })).then(function (paths) {
              var folder = String(paths[0]).replace(/[\\/][^\\/]*$/, '');   // strip the file name -> the shared host folder
              log4jInput.value = folder;
              log.append({ text: 'Log4j source set to uploaded folder: ' + folder, level: 'ok' });
              if (csvPath) { doAnalyze(); }
              else { log.append({ text: 'Import an ACAS CSV, then Analyze - the Log4j card will be runnable.', level: 'dim' }); }
            }).catch(function (e) {
              log.append({ text: 'Log4j jar upload failed: ' + (e && e.message), level: 'err' });
            });
          });
          fi.click();
        };
        l4Wrap.appendChild(l4Browse);

        refreshBtn.onclick = doAnalyze;
        preflightBtn.onclick = doPreflight;
        patchSelBtn.onclick = function () { doPatchSelected(false); };
        verifySelBtn.onclick = function () { doPatchSelected(true); };
        runAllBtn.onclick = doRunAll;
        bulkBtn.onclick = function () { doAutoPatch(true); };
        autoPatchBtn.onclick = doAutoPatch;
        cancelBtn.onclick = function () { if (run) { run.cancel(); log.append({ text: 'CANCEL requested - stopping in-flight jobs...', level: 'warn' }); } };
        popOut.onclick = toggleLogPop;

        [refreshBtn, preflightBtn, patchSelBtn, verifySelBtn, runAllBtn, bulkBtn, autoPatchBtn, cancelBtn, popOut, expCb, scCb, toWrap, l4Wrap].forEach(function (b) { actions.appendChild(b); });
        var spacer = el('div'); spacer.style.flex = '1'; actions.appendChild(spacer);
        updaterStatus = el('span', 'muted', 'Idle'); updaterStatus.style.minWidth = '120px';
        actions.appendChild(updaterStatus);
        head.appendChild(actions);

        updaterProg = C.ProgressStatusStrip({ showCount: true }); updaterProg.el.style.marginTop = '8px';
        head.appendChild(updaterProg.el);
        panel.appendChild(head);

        // two-column body: cards (left, scrollable) | results grid + log (right)
        var body = el('div'); body.style.cssText = 'flex:1;min-height:0;display:flex;gap:10px';

        var cardsCard = ui.card({}); cardsCard.style.cssText += ';flex:1 1 52%;min-width:0;display:flex;flex-direction:column;min-height:0';
        var cardsHdrRow = el('div'); cardsHdrRow.style.cssText = 'display:flex;align-items:center;gap:8px;margin-bottom:6px';
        cardsHdrRow.appendChild(secHdr('REMEDIATION CARDS'));
        var hsp = el('div'); hsp.style.flex = '1'; cardsHdrRow.appendChild(hsp);
        var selAll = ui.ghostButton('Check Runnable', { size: 'sm', title: 'Check every auto-runnable card.' });
        var selNone = ui.ghostButton('Uncheck All', { size: 'sm' });
        selAll.onclick = function () { cards.forEach(function (c) { if (c.runnable && cardState[c.key]) cardState[c.key].checked = true; }); renderCards(); };
        selNone.onclick = function () { Object.keys(cardState).forEach(function (k) { cardState[k].checked = false; }); renderCards(); };
        cardsHdrRow.appendChild(selAll); cardsHdrRow.appendChild(selNone);
        cardsCard.appendChild(cardsHdrRow);
        updaterBody = el('div'); updaterBody.style.cssText = 'flex:1;min-height:0;overflow:auto;display:flex;flex-direction:column;gap:10px;padding-right:4px';
        cardsCard.appendChild(updaterBody);
        body.appendChild(cardsCard);

        var rightCol = el('div'); rightCol.style.cssText = 'flex:1 1 48%;min-width:0;display:flex;flex-direction:column;gap:10px;min-height:0';
        var resCard = ui.card({}); resCard.style.cssText += ';flex:1;min-height:0;display:flex;flex-direction:column';
        resCard.appendChild(secHdr('PER-HOST RESULTS'));
        resultsGrid = C.ResultsGrid({
          title: 'ACAS run results', keyMode: keyHostProfile, popOut: true,
          columns: [
            { key: 'Host', label: 'HOST', width: 150 },
            { key: 'Profile', label: 'PROFILE', width: 170, render: function (r) { return { text: r.Profile == null ? '' : String(r.Profile), cls: 'cell-dim' }; } },
            { key: 'Result', label: 'RESULT', width: 80, render: function (r) { return { text: r.Result == null ? '' : String(r.Result), cls: resultCls(r.Result) }; } },
            { key: 'Version Before', label: 'BEFORE', width: 110 },
            { key: 'Version After', label: 'AFTER', width: 110 },
            { key: 'Detail', label: 'DETAIL' }
          ],
          rowClass: function (r) { var s = String(r.Result || '').toUpperCase(); if (s === 'OK') return 'row-ok'; if (s === 'FAIL') return 'row-bad'; if (s === 'SKIP') return 'row-warn'; return ''; }
        });
        var rgh = el('div'); rgh.style.cssText = 'flex:1;min-height:0;display:flex'; rgh.appendChild(resultsGrid.el);
        resCard.appendChild(rgh);
        rightCol.appendChild(resCard);
        body.appendChild(rightCol);

        panel.appendChild(body);

        renderCards();
        if (cards.length === 0) {
          updaterBody.appendChild(emptyHint('No cards yet. Import a CSV (Import tab), then click "Analyze / Refresh Cards".'));
        }
      }

      function emptyHint(t) { var d = el('div', 'muted', t); d.style.cssText = 'padding:18px;text-align:center;font-size:12px;border:1px dashed var(--edge);border-radius:3px'; return d; }

      // ---- the per-vulnerability CARD ----
      function buildVulnCard(c) {
        var st = cardState[c.key];
        var box = el('div', 'j-card');
        box.style.cssText += ';position:relative;padding:10px 12px 10px 14px';
        // severity top accent
        var accent = el('div'); accent.style.cssText = 'position:absolute;left:0;top:0;bottom:0;width:4px;border-radius:2px 0 0 2px;background:' + sevColor(c.severity);
        box.appendChild(accent);

        // row 1: checkbox + badges + plugin name
        var r1 = el('div'); r1.style.cssText = 'display:flex;align-items:flex-start;gap:8px';
        var cb = el('input'); cb.type = 'checkbox'; cb.checked = !!st.checked; cb.style.marginTop = '3px';
        cb.disabled = !c.runnable;
        cb.title = c.runnable ? 'Include this card in Patch / Verify Selected.' : (c.needsStaging ? 'Needs the Log4j jars staged - set/Browse a Log4j source above, then Analyze.' : 'No auto-runnable profile - cannot be selected for patching.');
        cb.addEventListener('change', function () { st.checked = cb.checked; });
        r1.appendChild(cb);

        var textWrap = el('div'); textWrap.style.cssText = 'flex:1;min-width:0';
        var badges = el('div'); badges.style.cssText = 'display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-bottom:3px';
        var sevPill = ui.pill(String(c.severity || 'n/a').toUpperCase());
        sevPill.style.cssText += ';background:transparent;border:1px solid ' + sevColor(c.severity) + ';color:' + sevColor(c.severity);
        badges.appendChild(sevPill);
        // KEV-first badge at the point of remediation: this group carries a CISA
        // known-exploited CVE (shorter BOD-mandated SLA) — remediate first.
        if (c.inKev) { var kp = ui.pill('KEV'); kp.style.cssText += ';background:var(--sev-crit,#E0505A);color:#0a0a0e;font-weight:700;border:1px solid var(--sev-crit,#E0505A)'; kp.title = 'CISA Known-Exploited Vulnerability — remediate first'; badges.appendChild(kp); }
        var catPill = ui.pill(CAT_LABEL[c.category] || c.category);
        catPill.style.cssText += ';background:var(--panel-light);color:var(--muted)';
        badges.appendChild(catPill);
        if (c.members > 1) { var rp = ui.pill('ROLLUP x' + c.members); rp.style.cssText += ';background:var(--accent-wash);color:var(--accent-2)'; rp.title = (c.memberNames || []).join('\n'); badges.appendChild(rp); }
        if (c.category === 'Experimental') { var ep = ui.pill('EXPERIMENTAL'); ep.style.cssText += ';background:var(--gold-wash);color:var(--gold)'; badges.appendChild(ep); }
        textWrap.appendChild(badges);

        var name = el('div'); name.style.cssText = 'font-family:var(--mono);font-size:13px;color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap';
        name.textContent = c.plugin; name.title = c.plugin + ((c.cves && c.cves.length) ? ('\nCVE: ' + c.cves.join(', ')) : '');
        textWrap.appendChild(name);
        r1.appendChild(textWrap);

        // right column: host count + Run/Verify buttons
        var right = el('div'); right.style.cssText = 'display:flex;flex-direction:column;align-items:flex-end;gap:5px;flex:0 0 auto';
        var hostLbl = el('div'); hostLbl.style.cssText = 'font-family:var(--mono);font-size:11px;color:var(--cyan);cursor:pointer;text-decoration:underline dotted';
        hostLbl.textContent = c.hostCount + ' host' + (c.hostCount === 1 ? '' : 's');
        hostLbl.title = 'Click to review the affected host list.';
        hostLbl.onclick = function () { showCardHosts(c); };
        right.appendChild(hostLbl);
        r1.appendChild(right);
        box.appendChild(r1);

        // row 2 (Reboot-category): editable warning + Reboot Now / Verify Post-Reboot.
        // These vulns have no patch profile - the remediation IS a reboot, so they
        // dispatch schedule-reboot / verify-post-reboot against the card's host set.
        if (c.category === 'Reboot') {
          var rr = el('div'); rr.style.cssText = 'display:flex;align-items:center;gap:8px;margin-top:8px;flex-wrap:wrap';
          var warnInput = ui.input({ value: 'This workstation will reboot in 5 minutes for required security updates. Save your work now.', title: 'Save-your-work message shown to logged-in users before the reboot.' });
          warnInput.style.cssText += ';flex:1;min-width:160px;font-size:11.5px';
          var rebootBtn = ui.button('Reboot Now on ' + c.hostCount, { variant: 'danger', size: 'sm', title: 'Schedule shutdown /r /t 300 on the affected hosts (shows the warning first).' });
          var rvBtn = ui.button('Verify', { variant: 'cyan', size: 'sm', title: 'Confirm the affected hosts came back: reachable / pending-reboot / OS build.' });
          rebootBtn.disabled = rvBtn.disabled = (c.hostCount === 0);
          rebootBtn.onclick = function () { doRebootOne(c, false, warnInput.value); };
          rvBtn.onclick = function () { doRebootOne(c, true, warnInput.value); };
          rr.appendChild(warnInput); rr.appendChild(rebootBtn); rr.appendChild(rvBtn);
          box.appendChild(rr);
          return box;
        }

        // row 2: profile picker + per-card Run / Verify
        var r2 = el('div'); r2.style.cssText = 'display:flex;align-items:center;gap:8px;margin-top:8px;flex-wrap:wrap';
        if (c.profiles && c.profiles.length > 1) {
          var sel = ui.select({ options: c.profiles.map(function (p) { return { value: p, label: p }; }), value: st.profile, onChange: function () { st.profile = sel.value; } });
          sel.style.cssText += ';max-width:280px;font-size:11.5px';
          sel.disabled = !c.runnable;
          r2.appendChild(sel);
        } else {
          var plbl = el('div', 'muted'); plbl.style.cssText = 'font-size:11.5px;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap';
          plbl.textContent = (c.profiles && c.profiles[0]) ? c.profiles[0] : '(no profile)';
          plbl.title = plbl.textContent;
          r2.appendChild(plbl);
        }
        var r2sp = el('div'); r2sp.style.flex = '1'; r2.appendChild(r2sp);

        // Unpatchable / Not-Updatable cards: no remote action, but the desktop "Not
        // Updatable" surface lets the operator Copy Plan (hosts + CVEs + solution) for
        // hand-off. Offer that instead of the (disabled) Run/Verify pair.
        if (c.category === 'Unpatchable' || c.category === 'NotUpdatable') {
          var copyBtn = ui.button('Copy Plan', { variant: 'cyan', size: 'sm', title: 'Copy the affected hosts + CVEs + solution to the clipboard for hand-off.' });
          copyBtn.onclick = function () { copyCardPlan(c); };
          r2.appendChild(copyBtn);
          box.appendChild(r2);
          return box;
        }

        var noRunTitle = c.needsStaging ? 'Needs the Log4j jars staged - set/Browse a Log4j source above, then Analyze.' : 'No profile - nothing to run.';
        var runBtn = ui.button('Run on ' + c.hostCount, { variant: 'gold', size: 'sm', title: c.runnable ? 'Patch the affected hosts now.' : noRunTitle });
        var verBtn = ui.button('Verify', { variant: 'cyan', size: 'sm', title: c.runnable ? 'Dry-run / verify on the affected hosts.' : noRunTitle });
        runBtn.disabled = verBtn.disabled = !c.runnable;
        runBtn.onclick = function () { doPatchOne(c, false); };
        verBtn.onclick = function () { doPatchOne(c, true); };
        r2.appendChild(runBtn); r2.appendChild(verBtn);
        box.appendChild(r2);

        // Greyed staging card (e.g. Log4j): explain HOW to make it runnable instead of
        // leaving it inert. The jars must be readable by the host - drop them under
        // Packages (auto-found) or use "Browse jars" / the Log4j source box, then Analyze.
        if (!c.runnable && c.needsStaging) {
          var sn = el('div'); sn.style.cssText = 'font-size:11px;margin-top:6px;color:var(--amber)';
          sn.textContent = 'Needs the Log4j 2.25.4 jars staged. Drop log4j-api/core-2.25.4.jar under the host Packages folder (auto-found), or click "Browse jars" / set the Log4j source above, then Analyze.';
          box.appendChild(sn);
        }

        return box;
      }

      // Copy an unpatchable card's remediation plan (hosts + CVEs + solution) to the clipboard.
      function copyCardPlan(c) {
        var hosts = hostsOf(c);
        var lines = [
          c.plugin,
          'Severity: ' + (c.severity || 'n/a') + '   Affected hosts: ' + hosts.length,
          (c.cves && c.cves.length) ? ('CVE: ' + c.cves.join(', ')) : '',
          (c.solution ? ('Solution: ' + c.solution) : ''),
          '', 'Hosts:'
        ].filter(function (x) { return x !== ''; }).concat(hosts);
        var text = lines.join('\r\n');
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(function () { log.append({ text: 'Copied plan for [' + c.plugin + '] (' + hosts.length + ' host(s)) to clipboard.', level: 'accent' }); }).catch(function () {});
        }
      }

      function renderCards() {
        if (!updaterBody) return;
        updaterBody.innerHTML = '';
        if (cards.length === 0) { updaterBody.appendChild(emptyHint('No cards yet. Import a CSV, then Analyze.')); return; }
        // group by category, ordered Patchable-first
        var byCat = {};
        cards.forEach(function (c) { (byCat[c.category] = byCat[c.category] || []).push(c); });
        var seen = {};
        CAT_ORDER.concat(Object.keys(byCat)).forEach(function (cat) {
          if (seen[cat] || !byCat[cat]) return; seen[cat] = true;
          var kevN = byCat[cat].filter(function (c) { return c.inKev; }).length;
          var hdr = el('div', 'j-eyebrow', (CAT_LABEL[cat] || cat) + '  (' + byCat[cat].length + (kevN ? (', ' + kevN + ' KEV') : '') + ')');
          hdr.style.cssText += ';margin:4px 0 2px';
          updaterBody.appendChild(hdr);
          // KEV-first within each category: known-exploited groups lead (audit "KEV first").
          byCat[cat].slice().sort(function (a, b) { return (b.inKev ? 1 : 0) - (a.inKev ? 1 : 0); }).forEach(function (c) { updaterBody.appendChild(buildVulnCard(c)); });
        });
      }

      // ---- ANALYZE -> cards ----
      function doAnalyze() {
        if (!csvPath) { ctx.confirm({ title: 'No CSV imported', body: 'Import an ACAS / Nessus CSV on the Import tab first.', okText: 'OK', cancelText: null }); return; }
        if (runActive()) return;
        // The Updater tab builds lazily, so it may not exist yet when import
        // auto-analyzes - guard every Updater-tab ref (cards still populate; the
        // tab paints them on first open via its own renderCards()).
        if (updaterStatus) { updaterStatus.textContent = 'Analyzing...'; updaterStatus.className = 'st-info'; }
        if (updaterProg) updaterProg.reset();
        log.banner('Analyze remediation (' + csvName + ')');
        run = ctx.run('analyze-remediation', { csvPaths: csvPath, log4jSource: log4jSrcVal() });
        if (unsub) unsub();
        unsub = run.subscribe({
          status: function (t) { if (updaterStatus) updaterStatus.textContent = t; if (updaterProg) updaterProg.setPhase(t); },
          progress: function (p) { if (updaterProg) updaterProg.setProgress(p.done, p.total); },
          log: function (l) { log.append(l); },
          final: function (res) {
            cards = (res && res.groups) ? res.groups.slice() : [];
            cardState = {};
            cards.forEach(function (c) { cardState[c.key] = { checked: false, profile: (c.profiles && c.profiles[0]) || '' }; });
            var s = (res && res.summary) || {};
            stat.findings = s.findings != null ? s.findings : stat.findings;
            stat.patchable = s.patchable != null ? s.patchable : cards.filter(function (c) { return c.runnable; }).length;
            stat.reboot = s.reboot != null ? s.reboot : cards.filter(function (c) { return c.category === 'Reboot'; }).length;
            stat.patched = 0; stat.failed = 0;
            pushStats();
            renderCards();
            refreshVulnSelect();
            if (updaterStatus) { updaterStatus.textContent = cards.length + ' card(s): ' + stat.patchable + ' patchable.'; updaterStatus.className = 'st-ok'; }
            log.append({ text: 'Analyze complete: ' + cards.length + ' vuln group(s), ' + stat.patchable + ' patchable.', level: 'ok' });
            // mirror analyze rows into the import tiles' findings count when present
            if (importTiles && s.findings != null) importTiles.set('findings', s.findings);
          },
          active: function () {}
        });
      }

      // ---- shared run binder for the streaming patch/verify/preflight actions ----
      function bindRunResults(opts) {
        // opts: { resetGrid, bannerTxt, onFinal }
        if (opts.resetGrid !== false) resultsGrid.clear();
        updaterProg.reset();
        stat.patched = 0; stat.failed = 0; pushStats();
        if (opts.bannerTxt) log.banner(opts.bannerTxt);
        lockRun(true);
        if (unsub) unsub();
        unsub = run.subscribe({
          status: function (t) { updaterStatus.textContent = t; updaterStatus.className = 'st-info'; updaterProg.setPhase(t); },
          progress: function (p) { updaterProg.setProgress(p.done, p.total); },
          row: function (r) {
            // run-vulnerability rows have no Profile column - stamp the running profile for the grid.
            if (opts.stampProfile && (r.Profile == null || r.Profile === '')) r.Profile = opts.stampProfile;
            resultsGrid.upsert(r);
            var res = String(r.Result || '').toUpperCase();
            if (res === 'OK') { stat.patched++; log.append({ text: '[' + r.Host + '] ' + (r.Profile ? r.Profile + ': ' : '') + 'OK' + (r['Version After'] && r['Version After'] !== 'n/a' ? ' -> ' + r['Version After'] : ''), level: 'ok' }); }
            else if (res === 'FAIL') { stat.failed++; log.append({ text: '[' + r.Host + '] ' + (r.Profile ? r.Profile + ': ' : '') + 'FAIL: ' + (r.Detail || ''), level: 'err' }); }
            else { log.append({ text: '[' + r.Host + '] ' + (r.Profile ? r.Profile + ': ' : '') + (r.Result || '') + ' ' + (r.Detail || ''), level: 'warn' }); }
            pushStats();
          },
          log: function (l) { log.append(l); },
          final: function (res) {
            var s = (res && res.summary) || {};
            var ok = s.ok != null ? s.ok : stat.patched, fail = s.failed != null ? s.failed : stat.failed, tot = s.total != null ? s.total : (ok + fail);
            log.banner('Complete: ' + ok + ' succeeded, ' + fail + ' failed' + (s.gaps ? (' (' + s.gaps + ' coverage gap(s) not run)') : ''));
            updaterStatus.textContent = ok + ' ok, ' + fail + ' failed of ' + tot + '.';
            updaterStatus.className = fail > 0 ? 'st-warn' : 'st-ok';
            if (opts.onFinal) opts.onFinal(res);
          },
          active: function (a) { lockRun(a); }
        });
      }

      function credGuard(actionLabel) {
        if (ctx.session.state.credSet) return true;
        ctx.confirm({ title: 'Admin session required', body: 'Set ADW credentials (top-right) and start an admin session before ' + actionLabel + ' - it changes machines.', okText: 'OK', cancelText: null });
        return false;
      }

      // ---- per-card affected-host helpers (explicit host-list dispatch, desktop parity) ----
      function hostsOf(c) { return (c && c.hosts && c.hosts.length) ? c.hosts.slice() : []; }
      function profOf(c) { return (cardState[c.key] && cardState[c.key].profile) || (c.profiles && c.profiles[0]) || ''; }
      function jobLine(c) { return profOf(c) + ' | ' + hostsOf(c).join(','); }   // run-all-* jobs format: "profile | h1,h2,..."

      // review the exact host set a card will push to (the desktop affected-host list).
      function showCardHosts(c) {
        var hosts = hostsOf(c), prof = profOf(c) || '(no profile)';
        var body = el('div');
        var d = el('div'); d.style.cssText = 'font-size:11.5px;color:var(--text-dim);margin-bottom:8px';
        d.innerHTML = 'Profile: <b>' + esc(prof) + '</b><br>' + hosts.length + ' affected host(s). Run / Verify pushes ONLY to these.';
        body.appendChild(d);
        var listBox = el('div'); listBox.style.cssText = 'max-height:260px;overflow:auto;font-family:var(--mono);font-size:11.5px;border:1px solid var(--edge);border-radius:3px;padding:6px 8px;background:var(--bg)';
        if (hosts.length) hosts.forEach(function (h) { var r = el('div'); r.textContent = h; listBox.appendChild(r); });
        else { var em = el('div', 'muted'); em.textContent = '(no hosts resolved - re-run Analyze / Refresh Cards)'; listBox.appendChild(em); }
        body.appendChild(listBox);
        ctx.confirm({ title: 'Affected hosts - ' + (c.plugin || ''), body: body, okText: 'Close', cancelText: null });
      }

      // ---- per-card Run / Verify (single card) -> run-vulnerability against the EXPLICIT host list ----
      function doPatchOne(c, verifyOnly) {
        if (runActive()) { ctx.confirm({ title: 'Run in progress', body: 'A run is already in progress. Wait for it to finish or Cancel it.', okText: 'OK', cancelText: null }); return; }
        if (!verifyOnly && !credGuard('patching')) return;
        var prof = profOf(c), hosts = hostsOf(c);
        if (!hosts.length) { ctx.confirm({ title: 'No affected hosts', body: 'No affected hosts resolved for this card. Re-run Analyze / Refresh Cards.', okText: 'OK', cancelText: null }); return; }
        ctx.confirm({
          title: (verifyOnly ? 'Verify' : 'Patch') + ' one vulnerability',
          danger: !verifyOnly,
          body: (verifyOnly ? 'Verify' : 'Push') + ' <b>' + esc(prof) + '</b> ' + (verifyOnly ? 'on' : 'to') + ' <b>' + hosts.length + '</b> affected host(s) for:<br><b>' + esc(c.plugin) + '</b>',
          list: hosts.slice(0, 8),
          okText: verifyOnly ? 'Verify' : 'Patch', cancelText: 'Cancel'
        }).then(function (ok) {
          if (!ok) return;
          // explicit host list -> run-vulnerability (operator reviewed + confirmed the exact targets)
          run = ctx.run('run-vulnerability', { profileName: prof, vulnDisplay: c.plugin, targets: hosts.join('\n'), verifyOnly: verifyOnly, threads: 20, perHostTimeout: perHostTimeoutVal(), log4jSource: log4jSrcVal() }, { keyOf: keyHost });
          bindRunResults({ bannerTxt: (verifyOnly ? 'Verify' : 'Patch') + ' [' + c.plugin + '] -> ' + prof + ' on ' + hosts.length + ' host(s)', stampProfile: prof });
        });
      }

      // ---- per-card Reboot / Verify (Reboot-category cards) -> schedule-reboot / verify-post-reboot ----
      function doRebootOne(c, verifyOnly, warningText) {
        if (runActive()) { ctx.confirm({ title: 'Run in progress', body: 'A run is already in progress. Wait for it to finish or Cancel it.', okText: 'OK', cancelText: null }); return; }
        if (!verifyOnly && !credGuard('scheduling reboots')) return;
        var hosts = hostsOf(c);
        if (!hosts.length) { ctx.confirm({ title: 'No affected hosts', body: 'No affected hosts resolved for this card. Re-run Analyze / Refresh Cards.', okText: 'OK', cancelText: null }); return; }
        ctx.confirm({
          title: (verifyOnly ? 'Verify post-reboot' : 'Schedule reboot') + ' - ' + hosts.length + ' host(s)',
          danger: !verifyOnly,
          body: (verifyOnly ? 'Confirm post-reboot state on' : 'Schedule a reboot (shutdown /r /t 300) on') + ' <b>' + hosts.length + '</b> affected host(s) for:<br><b>' + esc(c.plugin) + '</b>' + (verifyOnly ? '' : '<br><br>Users see: <i>' + esc(warningText || '') + '</i>'),
          list: hosts.slice(0, 8),
          okText: verifyOnly ? 'Verify' : 'Schedule Reboot', cancelText: 'Cancel'
        }).then(function (ok) {
          if (!ok) return;
          var action = verifyOnly ? 'verify-post-reboot' : 'schedule-reboot';
          var params = { targets: hosts.join('\n'), vulnDisplay: c.plugin, threads: 20 };
          if (!verifyOnly) params.warningText = warningText || '';
          run = ctx.run(action, params, { keyOf: keyHost });
          bindRebootResults({ verifyOnly: verifyOnly, bannerTxt: (verifyOnly ? 'VERIFY REBOOT' : 'SCHEDULE REBOOT') + ' [' + c.plugin + '] on ' + hosts.length + ' host(s)' });
        });
      }

      // ---- streaming binder for schedule-reboot / verify-post-reboot (folds the
      //      reboot/verify markers into the shared PER-HOST RESULTS grid) ----
      function bindRebootResults(opts) {
        resultsGrid.clear(); updaterProg.reset();
        if (opts.bannerTxt) log.banner(opts.bannerTxt);
        lockRun(true);
        var okC = 0, failC = 0;
        var profLabel = opts.verifyOnly ? 'reboot (verify)' : 'reboot (schedule)';
        if (unsub) unsub();
        unsub = run.subscribe({
          status: function (t) { updaterStatus.textContent = t; updaterStatus.className = 'st-info'; updaterProg.setPhase(t); },
          progress: function (p) { updaterProg.setProgress(p.done, p.total); },
          row: function (r) {
            var detail = r.Detail || '';
            if (opts.verifyOnly) { detail = '[reach=' + (r.Reachable || '?') + ' pending=' + (r.RebootPending || '?') + ' build=' + (r['OS Build'] || '?') + '] ' + detail; }
            else if (r['Exit Code'] != null && r['Exit Code'] !== '') { detail = '[exit ' + r['Exit Code'] + '] ' + detail; }
            resultsGrid.upsert({ Host: r.Host, Profile: profLabel, Result: r.Result, 'Version Before': '', 'Version After': '', Detail: detail });
            var res = String(r.Result || '').toUpperCase();
            if (res === 'FAIL' || res === 'FAILED') { failC++; log.append({ text: '[' + r.Host + '] ' + (opts.verifyOnly ? 'VERIFY FAIL' : 'REBOOT FAIL') + ': ' + detail, level: 'err' }); }
            else { okC++; log.append({ text: '[' + r.Host + '] ' + (r.Result || (opts.verifyOnly ? 'ok' : 'scheduled')) + (detail ? ' - ' + detail : ''), level: 'ok' }); }
          },
          log: function (l) { log.append(l); },
          final: function (res) {
            var s = (res && res.summary) || {};
            var ok = s.ok != null ? s.ok : okC, fail = s.failed != null ? s.failed : failC, tot = s.total != null ? s.total : (ok + fail);
            log.banner((opts.verifyOnly ? 'Verify' : 'Reboot') + ' complete: ' + ok + ' ok, ' + fail + ' failed of ' + tot + '.');
            updaterStatus.textContent = ok + ' ok, ' + fail + ' failed of ' + tot + '.';
            updaterStatus.className = fail > 0 ? 'st-warn' : 'st-ok';
          },
          active: function (a) { lockRun(a); }
        });
      }

      // ---- Patch / Verify the CHECKED cards -> run-all-parallel over each card's explicit host set ----
      function doPatchSelected(verifyOnly) {
        if (runActive()) { ctx.confirm({ title: 'Run in progress', body: 'A run is already in progress.', okText: 'OK', cancelText: null }); return; }
        var chosen = cards.filter(function (c) { return c.runnable && cardState[c.key] && cardState[c.key].checked && hostsOf(c).length; });
        if (chosen.length === 0) { ctx.confirm({ title: 'Nothing selected', body: 'Check at least one runnable card (with affected hosts).', okText: 'OK', cancelText: null }); return; }
        if (!verifyOnly && !credGuard('patching')) return;
        var jobs = chosen.map(jobLine).join('\n');
        ctx.confirm({
          title: (verifyOnly ? 'Verify' : 'Patch') + ' selected (' + chosen.length + ')',
          danger: !verifyOnly,
          body: (verifyOnly ? 'Verify' : 'Patch') + ' <b>' + chosen.length + '</b> selected card(s) against their affected host sets, in parallel?',
          list: chosen.slice(0, 6).map(function (c) { return profOf(c) + '  (' + hostsOf(c).length + ' host(s))'; }),
          okText: verifyOnly ? 'Verify' : 'Patch', cancelText: 'Cancel'
        }).then(function (ok) {
          if (!ok) return;
          run = ctx.run('run-all-parallel', { jobs: jobs, verifyOnly: verifyOnly, threads: 20, perHostTimeout: perHostTimeoutVal(), log4jSource: log4jSrcVal() }, { keyOf: keyHostProfile });
          bindRunResults({ bannerTxt: (verifyOnly ? 'VERIFY' : 'PATCH') + ' SELECTED: ' + chosen.length + ' card(s)' });
        });
      }

      // ---- Run All (Sequential) -> run-all-sequential over every runnable card's explicit host set ----
      function doRunAll() {
        if (runActive()) { ctx.confirm({ title: 'Run in progress', body: 'A run is already in progress.', okText: 'OK', cancelText: null }); return; }
        var chosen = cards.filter(function (c) { return c.runnable && hostsOf(c).length; });
        if (chosen.length === 0) { ctx.confirm({ title: 'Nothing runnable', body: 'No auto-runnable cards. Import + Analyze first.', okText: 'OK', cancelText: null }); return; }
        if (!credGuard('Run All')) return;
        var jobs = chosen.map(jobLine).join('\n');
        ctx.confirm({
          title: 'Run All (Sequential)',
          danger: true,
          body: 'Run all <b>' + chosen.length + '</b> runnable card(s) one profile group at a time (drain before next)?',
          okText: 'Run All', cancelText: 'Cancel'
        }).then(function (ok) {
          if (!ok) return;
          run = ctx.run('run-all-sequential', { jobs: jobs, verifyOnly: false, threads: 20, perHostTimeout: perHostTimeoutVal(), log4jSource: log4jSrcVal() }, { keyOf: keyHostProfile });
          bindRunResults({ bannerTxt: 'RUN ALL (sequential): ' + chosen.length + ' card(s)' });
        });
      }

      // ---- Bulk Run (Parallel) == Auto-Patch the whole CSV in parallel ----
      function doAutoPatch(asBulk) {
        if (!csvPath) { ctx.confirm({ title: 'No CSV imported', body: 'Import an ACAS / Nessus CSV first.', okText: 'OK', cancelText: null }); return; }
        if (runActive()) { ctx.confirm({ title: 'Run in progress', body: 'A run is already in progress.', okText: 'OK', cancelText: null }); return; }
        if (!credGuard('auto-patching')) return;
        ctx.confirm({
          title: asBulk ? 'Bulk Run (Parallel)' : 'Auto-Patch From CSV',
          danger: true,
          body: 'Auto-match the whole CSV and push the matched remediation to <b>every affected host</b> in parallel? Coverage gaps (reboot / unpatchable / staged) are listed but not run.',
          okText: 'Auto-Patch', cancelText: 'Cancel'
        }).then(function (ok) {
          if (!ok) return;
          run = ctx.run('auto-patch', { csvPaths: csvPath, verifyOnly: false, includeExperimental: !!(expCb && expCb._cb.checked), preferSoftwareCenter: !!(scCb && scCb._cb.checked), threads: 20, perHostTimeout: perHostTimeoutVal(), log4jSource: log4jSrcVal() }, { keyOf: keyHostProfile });
          bindRunResults({ bannerTxt: (asBulk ? 'BULK RUN (parallel)' : 'AUTO-PATCH') + ' from ' + csvName });
        });
      }

      // ---- Pre-Flight Services (on imported affected hosts) ----
      function doPreflight() {
        if (runActive()) { ctx.confirm({ title: 'Run in progress', body: 'A run is already in progress.', okText: 'OK', cancelText: null }); return; }
        if (importedHosts.length === 0) { ctx.confirm({ title: 'No hosts', body: 'Import a CSV first - pre-flight runs against the imported affected hosts.', okText: 'OK', cancelText: null }); return; }
        if (!credGuard('pre-flighting services')) return;
        ctx.confirm({
          title: 'Pre-Flight Services',
          danger: true,
          body: 'Ensure <b>winrm / Winmgmt / RemoteRegistry</b> are Running + Automatic on <b>' + importedHosts.length + '</b> imported host(s)? This is a state change on each target.',
          okText: 'Pre-Flight', cancelText: 'Cancel'
        }).then(function (ok) {
          if (!ok) return;
          resultsGrid.clear(); updaterProg.reset();
          log.banner('Pre-Flight Services on ' + importedHosts.length + ' host(s)');
          lockRun(true);
          run = ctx.run('preflight-services', { targets: importedHosts.join('\n'), threads: 20 }, { keyOf: keyHost });
          if (unsub) unsub();
          var okC = 0, failC = 0;
          unsub = run.subscribe({
            status: function (t) { updaterStatus.textContent = t; updaterStatus.className = 'st-info'; updaterProg.setPhase(t); },
            progress: function (p) { updaterProg.setProgress(p.done, p.total); },
            row: function (r) {
              // preflight rows: Host / Changes Made / Result / Timestamp / Detail
              resultsGrid.upsert({ Host: r.Host, Profile: 'pre-flight services', Result: r.Result, 'Version Before': r['Changes Made'], 'Version After': '', Detail: r.Detail });
              if (String(r.Result).toUpperCase() === 'FAIL') { failC++; log.append({ text: '[' + r.Host + '] FAIL: ' + (r.Detail || ''), level: 'err' }); }
              else { okC++; log.append({ text: '[' + r.Host + '] OK - ' + (r['Changes Made'] || 'already correct'), level: 'ok' }); }
            },
            log: function (l) { log.append(l); },
            final: function () { log.banner('Pre-flight complete: ' + okC + ' ok, ' + failC + ' failed'); updaterStatus.textContent = okC + ' ok, ' + failC + ' failed.'; updaterStatus.className = failC ? 'st-warn' : 'st-ok'; },
            active: function (a) { lockRun(a); }
          });
        });
      }

      // ---- pop the Updater Log out / back ----
      function toggleLogPop() {
        if (logDocked) {
          popWin = window.open('', '_blank', 'width=760,height=520');
          if (!popWin) return;
          var d = popWin.document; d.title = 'ACAS Nemesis - Updater Log';
          var link = d.createElement('link'); link.rel = 'stylesheet'; link.href = '/css/janet.css'; d.head.appendChild(link);
          d.body.style.cssText = 'margin:0;background:var(--bg);height:100vh;display:flex';
          var holder = d.createElement('div'); holder.style.cssText = 'flex:1;display:flex;padding:12px;min-height:0';
          d.body.appendChild(holder); holder.appendChild(log.el);
          logDocked = false;
          popWin.addEventListener('beforeunload', function () { if (logHolder) logHolder.appendChild(log.el); logDocked = true; popWin = null; });
        } else if (popWin) { popWin.close(); }
      }

      // ====================================================================
      //  TAB 3 - VULNERABILITIES  (per-finding drill-down via group-findings)
      //  Scaffolded: pick a card, list its raw findings (Host/Severity/Plugin/
      //  CVE/Solution). The desktop per-finding host-exclude grid is deeper -
      //  see report notes.
      // ====================================================================
      function buildVulnsTab(panel) {
        // ponytail: read-only finding drill-down, not the desktop's per-finding
        // exclude-from-run checkbox grid. Run gating already happens at card
        // granularity (card checkboxes + per-card affected-host review), which
        // covers the workflow; add per-finding host exclusion only if operators
        // actually need to drop individual hosts within a single vuln.
        panel.style.cssText = 'flex:1;min-height:0;display:flex;flex-direction:column;gap:10px;padding:14px;box-sizing:border-box';
        var head = ui.card({});
        head.appendChild(secHdr('VULNERABILITIES'));
        head.appendChild(hint('Raw findings behind a remediation card (Host / Severity / Plugin / CVE / Solution). Analyze on the Updater tab first to populate the card list - or use Find Host to list every finding for one hostname.'));
        var row = el('div'); row.style.cssText = 'display:flex;align-items:flex-end;gap:8px;flex-wrap:wrap';
        vulnsSelect = ui.select({ options: [{ value: '', label: '(analyze first)' }], value: '' });
        vulnsSelect.style.maxWidth = '420px';
        vulnsBtn = ui.button('Load Findings', { variant: 'cyan', size: 'sm', title: 'List the raw findings for the chosen card.' });
        vulnsBtn.onclick = loadVulnFindings;
        row.appendChild(ui.field('Remediation card', vulnsSelect));
        row.appendChild(vulnsBtn);
        // Find Host: cross-reference one hostname to all its findings (same grid).
        var hostIn = ui.input({ placeholder: 'hostname' }); hostIn.style.maxWidth = '200px';
        hostIn.addEventListener('keydown', function (e) { if (e.key === 'Enter') doFindHost(hostIn.value); });
        var findBtn = ui.button('Find Host', { variant: 'cyan', size: 'sm', title: 'List every finding for one host (cross-reference).' });
        findBtn.onclick = function () { doFindHost(hostIn.value); };
        row.appendChild(ui.field('Find host', hostIn));
        row.appendChild(findBtn);
        head.appendChild(row);
        vulnsStatus = el('div', 'muted', 'Idle.'); vulnsStatus.style.cssText = 'margin-top:6px;font-size:12px';
        head.appendChild(vulnsStatus);
        panel.appendChild(head);

        var gridCard = ui.card({}); gridCard.style.cssText += ';flex:1;min-height:200px;display:flex;flex-direction:column';
        vulnsGrid = C.ResultsGrid({
          title: 'Findings', keyMode: { rk: true }, popOut: true,
          columns: [
            { key: 'Host', label: 'HOST', width: 150 },
            { key: 'Severity', label: 'SEVERITY', width: 100, render: sevCell('Severity') },
            { key: 'Plugin', label: 'PLUGIN', width: 260 },
            { key: 'CVE', label: 'CVE', width: 140 },
            { key: 'Solution', label: 'SOLUTION' }
          ]
        });
        var gh = el('div'); gh.style.cssText = 'flex:1;min-height:0;display:flex'; gh.appendChild(vulnsGrid.el);
        gridCard.appendChild(gh);
        panel.appendChild(gridCard);

        refreshVulnSelect();
      }
      function refreshVulnSelect() {
        if (!vulnsSelect) return;
        vulnsSelect.innerHTML = '';
        if (cards.length === 0) { var o = el('option', null, '(analyze first)'); o.value = ''; vulnsSelect.appendChild(o); return; }
        cards.forEach(function (c) { var o = el('option', null, c.plugin + '  [' + c.hostCount + ' host(s)]'); o.value = c.key; vulnsSelect.appendChild(o); });
      }
      function loadVulnFindings() {
        if (!csvPath) { ctx.confirm({ title: 'No CSV', body: 'Import + Analyze first.', okText: 'OK', cancelText: null }); return; }
        var key = vulnsSelect.value;
        if (!key) { ctx.confirm({ title: 'No card', body: 'Analyze on the Updater tab, then choose a card.', okText: 'OK', cancelText: null }); return; }
        vulnsGrid.clear(); vulnsStatus.textContent = 'Loading findings...'; vulnsStatus.className = 'st-info';
        var rk = 0;
        var h = ctx.run('group-findings', { csvPaths: csvPath, key: key }, { keyOf: function () { return 'f' + (rk++); } });
        if (groupUnsub) groupUnsub(); groupUnsub = h.subscribe({
          status: function (t) { vulnsStatus.textContent = t; vulnsStatus.className = 'st-info'; },
          row: function (r) { vulnsGrid.upsert(r); },
          log: function (l) { log.append(l); },
          final: function (res) { var s = (res && res.summary) || {}; vulnsStatus.textContent = (s.total != null ? s.total : vulnsGrid.rows().length) + ' finding(s)' + (s.truncated ? ' (truncated)' : '') + '.'; vulnsStatus.className = 'st-ok'; }
        });
      }

      // ====================================================================
      //  TAB 4 - BACKBONE  (profile catalog reference via list-profiles)
      // ====================================================================
      function buildBackboneTab(panel) {
        panel.style.cssText = 'flex:1;min-height:0;display:flex;flex-direction:column;gap:10px;padding:14px;box-sizing:border-box';
        var head = ui.card({});
        head.appendChild(secHdr('BACKBONE - REMEDIATION PROFILE CATALOG'));
        head.appendChild(hint('Every App Update remediation profile, its mechanism, and whether it auto-runs from the JANET Web web host (package / staged profiles need controller-side staging).'));
        var loadBtn = ui.button('Load / Refresh Catalog', { variant: 'cyan', size: 'sm' });
        loadBtn.onclick = loadBackbone;
        head.appendChild(loadBtn);
        panel.appendChild(head);

        var gridCard = ui.card({}); gridCard.style.cssText += ';flex:1;min-height:200px;display:flex;flex-direction:column';
        backboneGrid = C.ResultsGrid({
          title: 'Profiles', keyMode: { hostCol: 'Profile' }, popOut: true,
          columns: [
            { key: 'Profile', label: 'PROFILE', width: 320 },
            { key: 'Kind', label: 'KIND', width: 130 },
            { key: 'Auto-Runnable', label: 'AUTO-RUN', width: 100, render: function (r) { var v = String(r['Auto-Runnable']); return { text: v, cls: v === 'yes' ? 'st-ok' : 'st-warn' }; } },
            { key: 'Mechanism', label: 'MECHANISM' }
          ]
        });
        var gh = el('div'); gh.style.cssText = 'flex:1;min-height:0;display:flex'; gh.appendChild(backboneGrid.el);
        gridCard.appendChild(gh);
        panel.appendChild(gridCard);
        loadBackbone();
      }
      function loadBackbone() {
        if (!backboneGrid) return;
        backboneGrid.clear();
        var h = ctx.run('list-profiles', {}, { keyOf: function (ev) { return ev.Profile != null ? String(ev.Profile) : null; } });
        backboneUnsub = h.subscribe({ row: function (r) { backboneGrid.upsert(r); }, log: function (l) { log.append(l); } });
      }

      // ====================================================================
      //  TAB - KB INSTALLER  (kb-scan-findings -> checkbox grid -> kb-install)
      //  Parses KB rollups from the CSV, the operator checks host x KB rows,
      //  picks MECM / UsoClient (+ optional .msu fallback), groups by host, runs.
      // ====================================================================
      function buildKbTab(panel) {
        panel.style.cssText = 'flex:1;min-height:0;display:flex;flex-direction:column;gap:10px;padding:14px;box-sizing:border-box';
        var msuPath = '';

        var head = ui.card({});
        head.appendChild(secHdr('KB INSTALLER'));
        head.appendChild(hint('Windows KB rollups parsed from the imported CSV. Check the host x KB rows to install, pick a method, then Install. MECM matches each KB in CCM_SoftwareUpdate and InstallUpdates; UsoClient triggers a scan + install; an uploaded .msu is the MECM fallback for any KB not deployed.'));

        var actions = el('div'); actions.style.cssText = 'display:flex;align-items:flex-end;gap:8px;flex-wrap:wrap;margin-top:10px';
        var rescanBtn = ui.ghostButton('Rescan Findings', { size: 'sm', title: 'Re-parse the imported CSV for KB references.' });
        var selAllBtn = ui.ghostButton('Select All', { size: 'sm' });
        var selNoneBtn = ui.ghostButton('Deselect All', { size: 'sm' });
        var selCritBtn = ui.ghostButton('Select Critical/High', { size: 'sm' });
        var methodSel = ui.select({ options: [{ value: 'MECM (CIM targeted)', label: 'MECM (CIM targeted)' }, { value: 'UsoClient Trigger', label: 'UsoClient Trigger' }], value: 'MECM (CIM targeted)' });
        methodSel.style.minWidth = '180px';
        var msuFileInput = el('input'); msuFileInput.type = 'file'; msuFileInput.accept = '.msu'; msuFileInput.style.display = 'none';
        var msuBtn = ui.button('MSU fallback...', { variant: 'cyan', size: 'sm', title: 'Optional .msu used as the MECM fallback for any KB not deployed in MECM.' });
        var msuLabel = el('span', 'muted', 'no MSU'); msuLabel.style.fontSize = '11px';
        var noRebootCb = ui.checkbox('Suppress auto-reboot', { checked: true, color: 'var(--cyan)' });
        var installBtn = ui.button('Install KBs', { variant: 'gold', size: 'sm', title: 'Group the checked rows by host and install per host.' });
        var kbCancelBtn = ui.button('Cancel', { variant: 'danger', size: 'sm' }); kbCancelBtn.disabled = true;
        function methodIsMecm() { return !/uso/i.test(methodSel.value); }
        function syncMsuEnabled() { var on = methodIsMecm(); msuBtn.disabled = !on; msuBtn.style.opacity = on ? '' : '0.5'; }
        methodSel.addEventListener('change', syncMsuEnabled);
        msuBtn.onclick = function () { msuFileInput.value = ''; msuFileInput.click(); };
        msuFileInput.addEventListener('change', async function () {
          var f = msuFileInput.files && msuFileInput.files[0]; if (!f) return;
          msuLabel.textContent = 'uploading ' + f.name + '...'; msuLabel.className = 'muted';
          try { msuPath = await ctx.uploadFile(f); msuLabel.textContent = 'MSU: ' + f.name; msuLabel.className = 'st-info'; }
          catch (e) { msuPath = ''; msuLabel.textContent = 'MSU upload failed'; msuLabel.className = 'st-bad'; }
        });
        [rescanBtn, selAllBtn, selNoneBtn, selCritBtn].forEach(function (b) { actions.appendChild(b); });
        actions.appendChild(ui.field('Method', methodSel));
        actions.appendChild(msuBtn); actions.appendChild(msuLabel);
        actions.appendChild(noRebootCb);
        var asp = el('div'); asp.style.flex = '1'; actions.appendChild(asp);
        actions.appendChild(installBtn); actions.appendChild(kbCancelBtn);
        head.appendChild(actions);
        var countLbl = el('div', 'muted', 'No findings scanned yet.'); countLbl.style.cssText = 'font-size:11.5px;margin-top:6px';
        head.appendChild(countLbl);
        var kbProg = C.ProgressStatusStrip({ showCount: true }); kbProg.el.style.marginTop = '6px'; head.appendChild(kbProg.el);
        panel.appendChild(head);

        var split = el('div'); split.style.cssText = 'flex:1;min-height:0;display:flex;gap:10px';
        var findCard = ui.card({}); findCard.style.cssText += ';flex:1 1 55%;min-width:0;display:flex;flex-direction:column;min-height:0';
        findCard.appendChild(secHdr('KB FINDINGS'));
        var kbGrid = C.ResultsGrid({
          title: 'KB findings', selectable: true, keyMode: { rk: true }, popOut: true,
          columns: [
            { key: 'Host', label: 'HOST', width: 150 },
            { key: 'KB', label: 'KB', width: 110, render: function (r) { return { text: String(r.KB || ''), cls: 'st-info' }; } },
            { key: 'Severity', label: 'SEVERITY', width: 100, render: sevCell('Severity') },
            { key: 'Plugin', label: 'PLUGIN' },
            { key: 'CVE', label: 'CVE', width: 140 }
          ]
        });
        var fgh = el('div'); fgh.style.cssText = 'flex:1;min-height:0;display:flex'; fgh.appendChild(kbGrid.el); findCard.appendChild(fgh);
        split.appendChild(findCard);

        var resCard = ui.card({}); resCard.style.cssText += ';flex:1 1 45%;min-width:0;display:flex;flex-direction:column;min-height:0';
        resCard.appendChild(secHdr('INSTALL RESULTS'));
        var kbResGrid = C.ResultsGrid({
          title: 'KB install results', keyMode: { hostCol: 'Host' }, popOut: true,
          columns: [
            { key: 'Host', label: 'HOST', width: 150 },
            { key: 'KBs', label: 'KBS' },
            { key: 'MECM', label: 'MECM', width: 64, render: function (r) { return { text: String(r.MECM == null ? '' : r.MECM), cls: (parseInt(r.MECM, 10) > 0 ? 'st-ok' : 'cell-dim') }; } },
            { key: 'MSU', label: 'MSU', width: 60, render: function (r) { return { text: String(r.MSU == null ? '' : r.MSU), cls: (parseInt(r.MSU, 10) > 0 ? 'st-ok' : 'cell-dim') }; } },
            { key: 'Result', label: 'RESULT', width: 80, render: function (r) { return { text: String(r.Result || ''), cls: resultCls(r.Result) }; } },
            { key: 'Detail', label: 'DETAIL' }
          ],
          rowClass: function (r) { var s = String(r.Result || '').toUpperCase(); if (s === 'OK') return 'row-ok'; if (s === 'FAIL') return 'row-bad'; if (s === 'SKIP') return 'row-warn'; return ''; }
        });
        var rghh = el('div'); rghh.style.cssText = 'flex:1;min-height:0;display:flex'; rghh.appendChild(kbResGrid.el); resCard.appendChild(rghh);
        split.appendChild(resCard);
        panel.appendChild(split);

        syncMsuEnabled();
        function updateCount() {
          var total = kbGrid.rows().length, checked = kbGrid.getChecked().length;
          countLbl.textContent = total ? (total + ' KB finding(s), ' + checked + ' checked.') : 'No findings scanned. Import a CSV (Import tab) then Rescan Findings.';
        }

        rescanBtn.onclick = function () {
          if (!csvPath) { ctx.confirm({ title: 'No CSV imported', body: 'Import an ACAS / Nessus CSV on the Import tab first.', okText: 'OK', cancelText: null }); return; }
          if (runActive()) { ctx.confirm({ title: 'Run in progress', body: 'A run is already in progress.', okText: 'OK', cancelText: null }); return; }
          kbGrid.clear(); kbResGrid.clear(); kbProg.reset();
          log.banner('Scan KB findings (' + csvName + ')');
          var r2 = ctx.run('kb-scan-findings', { csvPaths: csvPath }, { keyOf: function (ev) { return ev._rk || (ev.Host + '|' + ev.KB); } });
          if (kbScanUnsub) kbScanUnsub(); kbScanUnsub = r2.subscribe({
            row: function (r) { kbGrid.upsert(r); updateCount(); },
            log: function (l) { log.append(l); },
            status: function (t) { kbProg.setPhase(t); },
            final: function () { updateCount(); log.append({ text: 'KB scan: ' + kbGrid.rows().length + ' host x KB pair(s).', level: 'ok' }); }
          });
        };
        selAllBtn.onclick = function () { kbGrid.selectAll(true); updateCount(); };
        selNoneBtn.onclick = function () { kbGrid.selectAll(false); updateCount(); };
        selCritBtn.onclick = function () { kbGrid.selectWhere(function (r) { var c = sevClass(r.Severity); return c === 'sev-crit' || c === 'sev-high'; }); updateCount(); };

        installBtn.onclick = async function () {
          if (runActive()) { ctx.confirm({ title: 'Run in progress', body: 'A run is already in progress.', okText: 'OK', cancelText: null }); return; }
          var checked = kbGrid.getChecked();
          if (!checked.length) { ctx.confirm({ title: 'Nothing checked', body: 'Check at least one KB finding to install.', okText: 'OK', cancelText: null }); return; }
          if (!credGuard('installing KBs')) return;
          var byHost = {};
          checked.forEach(function (r) { var h = r.Host; if (!h) return; (byHost[h] = byHost[h] || []).push(r.KB); });
          var hosts = Object.keys(byHost);
          var pairs = hosts.map(function (h) { return h + ' | ' + byHost[h].filter(function (v, i, a) { return a.indexOf(v) === i; }).join(','); }).join('\n');
          var method = methodSel.value;
          var ok = await ctx.confirm({
            title: 'Install KBs', danger: true,
            body: 'Install <b>' + checked.length + '</b> KB(s) across <b>' + hosts.length + '</b> host(s) via <b>' + esc(method) + '</b>' + (msuPath ? ' (MSU fallback set)' : '') + (noRebootCb._cb.checked ? ' [no auto-reboot]' : '') + '?',
            list: hosts.slice(0, 6), okText: 'Install', cancelText: 'Cancel'
          });
          if (!ok) return;
          kbResGrid.clear(); kbProg.reset();
          log.banner('Install KBs (' + method + ') - ' + hosts.length + ' host(s)');
          installBtn.disabled = true; kbCancelBtn.disabled = false;
          run = ctx.run('kb-install', { pairs: pairs, method: method, msu: msuPath, noreboot: noRebootCb._cb.checked, threads: 12 }, { keyOf: keyHost });
          if (unsub) unsub();
          unsub = run.subscribe({
            status: function (t) { kbProg.setPhase(t); },
            progress: function (p) { kbProg.setProgress(p.done, p.total); },
            row: function (r) { kbResGrid.upsert(r); var res = String(r.Result || '').toUpperCase(); log.append({ text: '[' + r.Host + '] ' + (r.KBs || '') + ': ' + (r.Result || '') + ' ' + (r.Detail || ''), level: res === 'OK' ? 'ok' : res === 'FAIL' ? 'err' : 'warn' }); },
            log: function (l) { log.append(l); },
            error: function (e) { log.append({ text: e.text, level: 'err' }); },
            final: function (res) { var s = (res && res.summary) || {}; log.banner('KB install complete: ' + (s.ok != null ? s.ok : '?') + ' ok, ' + (s.failed != null ? s.failed : '?') + ' failed' + (s.skipped ? ', ' + s.skipped + ' skipped' : '')); },
            active: function (a) { installBtn.disabled = a; kbCancelBtn.disabled = !a; }
          });
        };
        kbCancelBtn.onclick = function () { if (run) { run.cancel(); log.append({ text: 'CANCEL requested - stopping KB install...', level: 'warn' }); } };

        updateCount();
      }

      host.appendChild(root);
      this._root = root;
      this._unsub = function () { if (unsub) unsub(); if (hostLookupUnsub) hostLookupUnsub(); if (groupUnsub) groupUnsub(); if (backboneUnsub) backboneUnsub(); if (kbScanUnsub) kbScanUnsub(); if (popWin) { try { popWin.close(); } catch (e) {} } };
    },
    unmount: function () { try { if (this._unsub) this._unsub(); } catch (e) {} if (this._root) this._root.remove(); }
  });
})();
