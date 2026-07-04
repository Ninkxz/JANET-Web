/* ============================================================================
   upr.view.js  -  Unsupported Product Remediator (tool id: 'upr')
   Faithful single-window re-build per docs/ui-specs/upr.md: a shared GLOBAL
   strip (Report file + Host class + Threads + Plan-only/Dry-run) over a custom
   4-tab nav (TabHost, left rail) mirroring the desktop hidden-header TabControl:
     1. IMPORT & FINDINGS  -> report-findings  (parse-only catalog of findings)
     2. UNINSTALL (core)   -> report-scan then report-uninstall
     3. OS FINDINGS        -> os-findings       (read-only, one row per host)
     4. HISTORY            -> in-session uninstall outcomes
   This is a TWO-STAGE workflow: (1) upload+ingest the report (ctx.uploadFile ->
   server path passed as the `report` param), (2) host-centric Scan -> a colour-
   coded ResultsGrid where each row is one (host x matched product) keyed by the
   engine's unique `_rk`; only PROVEN-EOL rows pre-check, (3) Uninstall the
   CHECKED proven rows (destructive: credSet guard + ArmingDialog; Dry run is the
   DEFAULT). Review / Tanium / unreachable rows are never removable.

   No per-tool credential control (universal in the shell header). All server I/O
   via ctx.run / ctx.uploadFile; the view never fetches/polls. Multi-row-per-host
   grids key by `_rk` (keyOf to ctx.run AND keyMode:{rk:true} to ResultsGrid).
   ========================================================================== */
(function () {
  'use strict';

  var HOSTCLASSES = ['All', 'Workstations (MSEKL/MSEKW)', 'Non-Workstations (servers / other)'];

  // Multi-row-per-host: the engine streams one row per (host x matched install),
  // all sharing Host. Key by the engine's unique _rk or RunController collapses
  // them onto the shared Host. Must match keyMode:{rk:true} on every grid.
  function keyByRk(ev) { return ev._rk != null ? String(ev._rk) : (ev.Host != null ? String(ev.Host) : null); }

  var escHtml = Janet.util.esc;

  // ---- colour rules (HAND-WRITTEN per column, never regex-on-name) ----
  function sevCls(v) {
    switch (String(v)) {
      case 'Critical': return 'st-bad';
      case 'High': return 'st-warn';
      case 'Medium': return 'st-info';
      case 'Low': return 'cell-dim';
      default: return '';
    }
  }
  function findingDecisionCls(v) {
    var s = String(v);
    if (s.indexOf('Uninstall') === 0) return 'st-ok';
    if (s === 'Review') return 'st-warn';
    if (s.indexOf('OS') === 0) return 'cell-dim';
    return 'st-warn';   // No catalog match
  }
  // Scan/uninstall Decision: Uninstall (proven) green, Review cyan, Tanium amber,
  // synthetic Unreachable/Error/No match dim/red.
  function scanDecisionCls(v) {
    var s = String(v);
    if (s === 'Uninstall') return 'st-ok';
    if (s === 'Review') return 'st-info';
    if (s === 'Skipped (Tanium)') return 'st-warn';
    if (s === 'Skipped (protected)') return 'st-warn';
    if (s === 'Unreachable' || s === 'No match') return 'cell-dim';
    if (s === 'Error') return 'st-bad';
    return '';
  }
  // Uninstall Result cell transitions: Uninstalling.../OK/WARN/FAIL/Skipped.
  function resultCls(v) {
    var s = String(v == null ? '' : v);
    if (s === '') return '';
    if (s.indexOf('OK') === 0) return 'st-ok';
    if (s.indexOf('Uninstalling') === 0) return 'st-warn';
    if (s.indexOf('WARN') === 0) return 'st-warn';
    if (s.indexOf('FAIL') === 0) return 'st-bad';
    if (s.indexOf('Skipped') === 0) return 'cell-dim';
    return '';
  }
  // A scan row is a one-click-removable candidate only when proven EOL.
  function isProvenRow(r) { return r && String(r.Decision) === 'Uninstall' && String(r.Host || '') !== ''; }

  JanetViews.register('upr', {
    mount: function (host, ctx) {
      var ui = ctx.ui, C = ctx.components, el = ctx.util.el;

      // ---- shared global state (mirrors the desktop $script: globals) ----
      var reportFile = null;     // the picked File object
      var reportPath = null;     // server-side absolute path after upload (or '(pasted text)' sentinel)
      var reportText = null;     // pasted report text (alternative to a file; no pdftotext needed)
      var uploading = false;
      var scanRun = null, scanUnsub = null;      // active Scan / Uninstall run
      var findRun = null, findUnsub = null;       // findings parse run
      var osRun = null, osUnsub = null;            // OS findings run
      var manRun = null, manUnsub = null;          // Targeted Removal (manual) run
      var historyRows = [];                        // {When,Host,Action,Item,Result}
      var hist = null;                             // ResultsGrid for History tab (lazy)
      var lastScanWasUninstall = false;
      // Declared HERE (not lower) because C.TabHost (below) builds its initial tab
      // synchronously in its constructor; a tab build that derefs these must see them set.
      var selectedFinding = { plugin: '', name: '', decision: '', hosts: 0 };
      var manModel = ctx.util.targetModel('');     // Targeted Removal machine list model

      var root = el('div'); root.style.cssText = 'display:flex;flex-direction:column;height:100%;min-height:0;background:var(--bg)';

      // shared ACTIVITY log (declared before the TabHost - it auto-builds the first
      // tab in its constructor; docked as a root-level click-to-open drawer below).
      var log = C.ActivityLog({ title: 'ACTIVITY', defaultName: 'UPR_ActivityLog' });
      log.append({ text: 'Unsupported Product Remediator ready. Load a report, scan the affected hosts, then uninstall the checked proven-EOL rows.', level: 'accent' });

      // ===================================================================
      //  GLOBAL strip  (Report file + Host class + Threads + Plan-only)
      // ===================================================================
      var strip = ui.card({}); strip.style.cssText += ';margin:12px 14px 0;display:flex;align-items:flex-end;gap:14px;flex-wrap:wrap';
      strip.appendChild(ui.eyebrow('REPORT'));

      // hidden native file input + a themed "Load PDF / CSV" button
      var fileInput = el('input'); fileInput.type = 'file'; fileInput.accept = '.csv,.pdf'; fileInput.style.display = 'none';
      var loadBtn = ui.button('Load PDF / CSV', { variant: 'cyan', size: 'sm', title: 'Pick a Tenable / ACAS Unsupported & SEoL report (.pdf or .csv). It is uploaded to the JANET TWO server, then ingested.' });
      var fileLabel = el('span', 'muted', 'No report loaded'); fileLabel.style.cssText = 'font-family:var(--mono);font-size:12px;max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap';
      var pasteBtn = ui.ghostButton('Paste text', { size: 'sm', title: 'Paste the report text instead of uploading a file (open the PDF, Ctrl+A, Ctrl+C). No pdftotext needed.' });
      var fileWrap = el('div'); fileWrap.style.cssText = 'display:flex;align-items:center;gap:8px';
      fileWrap.appendChild(loadBtn); fileWrap.appendChild(pasteBtn); fileWrap.appendChild(fileInput); fileWrap.appendChild(fileLabel);
      strip.appendChild(fileWrap);

      var hostSel = ui.select({ options: HOSTCLASSES, value: 'All', title: 'Clip every tab to this host class (MSEKL/MSEKW = workstations).' });
      hostSel.style.width = '250px';
      strip.appendChild(ui.field('Host class', hostSel));

      var threadsInput = ui.number({ value: 16, min: 1, max: 64, title: 'Parallel hosts during Scan / Uninstall (1-64).' }); threadsInput.style.width = '80px';
      strip.appendChild(ui.field('Threads', threadsInput));

      var reloadBtn = ui.ghostButton('Reload Catalog', { size: 'sm', title: 'Reload the unsupported/SEoL match catalog from JanetLocal\\UnsupportedProductCatalog.json (falls back to the built-in default if absent/invalid). The catalog is also re-read on every scan.' });
      reloadBtn.onclick = doReloadCatalog;
      strip.appendChild(reloadBtn);

      var dryCb = ui.checkbox('Plan-only (dry run) - enumerate, do NOT uninstall', {
        checked: true, color: 'var(--warn)',
        title: 'CHECKED by default. With dry run on, Uninstall only plans - nothing is removed. Uncheck to actually remove proven-EOL software.'
      });
      var dryWrap = el('div'); dryWrap.style.cssText = 'margin-left:auto;display:flex;align-items:center;gap:8px';
      dryWrap.appendChild(dryCb);
      strip.appendChild(dryWrap);
      root.appendChild(strip);

      // ---- paste-text panel (hidden until "Paste text"; no pdftotext needed) ----
      var pasteCard = ui.card({}); pasteCard.style.cssText += ';margin:8px 14px 0;display:none;flex-direction:column;gap:8px';
      pasteCard.appendChild(ui.eyebrow('PASTE REPORT TEXT'));
      pasteCard.appendChild(hint('Open the report PDF, Select All (Ctrl+A), Copy (Ctrl+C), paste below, then "Use this text". No pdftotext needed. A viewer copy loses the NetBIOS/DNS columns, so the scan connects by IP - keep host class on "All".'));
      var pasteTa = el('textarea');
      pasteTa.placeholder = 'Paste the full report text here...';
      pasteTa.style.cssText = 'width:100%;min-height:150px;box-sizing:border-box;font-family:var(--mono);font-size:12px;background:var(--input);color:var(--text);border:1px solid var(--edge);border-radius:6px;padding:8px;resize:vertical';
      pasteCard.appendChild(pasteTa);
      var pasteBar = el('div'); pasteBar.style.cssText = 'display:flex;align-items:center;gap:8px';
      var pasteUse = ui.button('Use this text', { variant: 'go', size: 'sm' });
      var pasteClear = ui.ghostButton('Clear', { size: 'sm' });
      var pasteMsg = el('span', 'muted'); pasteMsg.style.cssText = 'font-size:11px';
      pasteBar.appendChild(pasteUse); pasteBar.appendChild(pasteClear); pasteBar.appendChild(pasteMsg);
      pasteCard.appendChild(pasteBar);
      root.appendChild(pasteCard);

      pasteBtn.onclick = function () {
        var show = pasteCard.style.display === 'none';
        pasteCard.style.display = show ? 'flex' : 'none';
        if (show) pasteTa.focus();
      };
      pasteClear.onclick = function () { pasteTa.value = ''; pasteMsg.textContent = ''; };
      pasteUse.onclick = function () {
        var t = (pasteTa.value || '').trim();
        if (t.length < 40) { pasteMsg.textContent = 'Paste the report text first (looks empty).'; pasteMsg.className = 'st-bad'; return; }
        reportText = pasteTa.value;
        reportFile = null;
        reportPath = '(pasted text)';   // sentinel: marks "report present"; reportParams() sends reporttext
        fileLabel.textContent = 'Pasted text (' + reportText.length + ' chars)'; fileLabel.className = 'st-ok';
        fileLabel.title = 'Using pasted report text (no file).';
        pasteCard.style.display = 'none';
        if (findApi) findApi.note('Using pasted report text. Parsing findings...', 'ok');
        runFindings();
        if (osApi) runOsFindings();
      };

      // ===================================================================
      //  TABS
      // ===================================================================
      var tabsWrap = el('div'); tabsWrap.style.cssText = 'flex:1;min-height:0;display:flex;padding:12px 14px';
      root.appendChild(tabsWrap);

      // per-tab live handles (built lazily by TabHost; stash here so global
      // controls can drive them and unmount can tear them down)
      var findApi = null, uninstApi = null, osApi = null, manApi = null;

      var tabs = C.TabHost({
        rail: 'left',
        helpId: 'upr',
        tabs: [
          { id: 'findings', label: 'Import & Findings', build: buildFindingsTab },
          { id: 'uninstall', label: 'Uninstall', build: buildUninstallTab },
          { id: 'manual', label: 'Targeted Removal', build: buildManualTab },
          { id: 'os', label: 'OS Findings', build: buildOsTab },
          { id: 'history', label: 'History', build: buildHistoryTab }
        ]
      });
      tabsWrap.appendChild(tabs.el);

      // shared activity log: a click-to-open drawer docked full-width below the tabs
      // (visible on every tab) - the acas root-level dock pattern. log.el is appended
      // directly (no holder div), so the holder-must-be-column gotcha doesn't apply.
      var logCard = ui.card({}); logCard.classList.add('j-logdock'); logCard.style.cssText += ';margin:0 14px 12px';
      logCard.appendChild(log.el);
      root.appendChild(logCard);

      // footer (mirrors the desktop status strip credit + log path)
      var footer = el('div', 'j-footer');
      footer.appendChild(el('span', 'credit', 'Created by: THOMPSON, BRAXTON - 48 CS'));
      var logPath = el('span'); logPath.textContent = 'Log: ' + (ctx.session.state.logRoot || '(local)');
      footer.appendChild(logPath);
      root.appendChild(footer);

      // ===================================================================
      //  shared helpers
      // ===================================================================
      function secHdr(t) { var h = el('div', 'j-section-h', t); h.style.marginBottom = '4px'; return h; }
      function hint(t) { var d = el('div', 'muted', t); d.style.cssText = 'font-size:11px;margin-bottom:8px'; return d; }
      function nowStamp() {
        var d = new Date(), p = function (n) { return String(n).padStart(2, '0'); };
        return d.getFullYear() + '-' + p(d.getMonth() + 1) + p(d.getDate()) + ' ' + p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
      }
      function hostClass() { return hostSel.value || 'All'; }
      // report params: pasted text wins (sends reporttext), else the uploaded file path.
      function reportParams(extra) { var p = extra || {}; if (reportText) { p.reporttext = reportText; } else { p.report = reportPath; } return p; }
      function threadCount() { return Math.max(1, Math.min(64, parseInt(threadsInput.value, 10) || 16)); }
      function isDry() { return dryCb._cb.checked; }
      function anyRunActive() {
        return (scanRun && scanRun.state && scanRun.state.active) ||
               (findRun && findRun.state && findRun.state.active) ||
               (osRun && osRun.state && osRun.state.active) ||
               (manRun && manRun.state && manRun.state.active);
      }
      function needReport(notify) {
        if (reportPath) return true;
        if (notify) ctx.confirm({ title: 'No report loaded', body: 'Load a Tenable / ACAS report (.pdf or .csv) with the Load PDF / CSV button up top first.', okText: 'OK', cancelText: null });
        return false;
      }

      // ---- Reload Catalog (parity with the desktop editable-catalog + Reload button) ----
      function doReloadCatalog() {
        log.banner('Reload Catalog');
        var h = ctx.run('reload-catalog', {});
        h.subscribe({
          row: function (r) { log.append({ text: 'Catalog source: ' + r.Source + '  |  ' + r.Profiles + ' profile(s), ' + r['OS Plugin Patterns'] + ' OS pattern(s).', level: 'ok' }); },
          log: function (l) { log.append(l); },
          error: function (e) { log.append({ text: e.text, level: 'err' }); }
        });
      }

      // ---- Load + upload the report (shared across all tabs) ----
      loadBtn.onclick = function () { fileInput.value = ''; fileInput.click(); };
      fileInput.addEventListener('change', function () {
        var f = fileInput.files && fileInput.files[0];
        if (!f) return;
        doUpload(f);
      });
      function doUpload(f) {
        if (uploading) return;
        uploading = true; reportFile = f; reportPath = null; reportText = null;
        loadBtn.disabled = true;
        fileLabel.textContent = 'Uploading ' + f.name + ' ...'; fileLabel.className = 'st-warn';
        if (findApi) findApi.note('Uploading ' + f.name + ' to the JANET TWO server...', 'accent');
        ctx.uploadFile(f).then(function (path) {
          reportPath = path; uploading = false; loadBtn.disabled = false;
          fileLabel.textContent = f.name; fileLabel.className = 'st-ok';
          fileLabel.title = 'Server path: ' + path;
          if (findApi) findApi.note('Report uploaded: ' + f.name + '. Parsing findings...', 'ok');
          // auto-ingest stage 1: parse findings (+ refresh OS tab if it's built)
          runFindings();
          if (osApi) runOsFindings();
        }).catch(function (e) {
          uploading = false; loadBtn.disabled = false;
          fileLabel.textContent = 'Upload failed - retry'; fileLabel.className = 'st-bad';
          ctx.confirm({ title: 'Upload failed', body: 'Could not upload "' + escHtml(f.name) + '": ' + escHtml(e && e.message || 'unknown error') + '<br><br>Check the JANET TWO console window and retry.', okText: 'OK', cancelText: null });
        });
      }

      // re-run dependent tabs when the global host-class / search filter changes
      hostSel.addEventListener('change', function () {
        if (!reportPath) return;
        if (findApi) runFindings();
        if (osApi) runOsFindings();
      });

      // ===================================================================
      //  TAB 1 - Import & Findings  (report-findings, parse-only)
      // ===================================================================
      function buildFindingsTab(panel) {
        panel.style.cssText = 'display:flex;flex-direction:column;height:100%;min-height:0;gap:8px';
        panel.appendChild(secHdr('FINDINGS'));
        panel.appendChild(hint('Load a report up top. Click a finding row, then switch to the Uninstall tab to scan its hosts. Update-class findings (M365 channel) are hidden - use the App Updater for those.'));

        // filter strip: Search box + live count
        var fstrip = el('div'); fstrip.style.cssText = 'display:flex;align-items:center;gap:10px;flex-wrap:wrap';
        var searchInput = ui.input({ placeholder: 'Search Plugin / Plugin Name / Category', title: 'Live client-side filter over the already-loaded findings (no server round-trip).' });
        searchInput.style.width = '320px';
        var searchBtn = ui.button('Search', { variant: 'go', size: 'sm' });
        var exportBtn = ui.ghostButton('Export CSV', { size: 'sm', title: 'Export the findings catalog (Plugin / Category / Plugin Name / Severity / Hosts / Decision) to XLSX.' });
        var countLbl = el('span', 'muted'); countLbl.style.cssText = 'font-family:var(--mono);font-size:12px';
        fstrip.appendChild(ui.label('Search')); fstrip.appendChild(searchInput); fstrip.appendChild(searchBtn); fstrip.appendChild(exportBtn); fstrip.appendChild(countLbl);
        panel.appendChild(fstrip);
        // Search is CLIENT-SIDE now: filter the loaded grid, never re-parse the report.
        searchBtn.onclick = function () { if (needReport(true)) applyFindingFilter(); };
        searchInput.addEventListener('keydown', function (e) { if (e.key === 'Enter') { e.preventDefault(); if (needReport(true)) applyFindingFilter(); } });
        searchInput.addEventListener('input', function () { if (reportPath) applyFindingFilter(); });

        var grid = C.ResultsGrid({
          title: 'Findings', keyMode: { rk: true }, popOut: true,
          columns: [
            { key: 'Plugin', label: 'PLUGIN', width: 75 },
            { key: 'Category', label: 'CATEGORY', width: 130 },
            { key: 'PluginName', label: 'PLUGIN NAME' },
            { key: 'Severity', label: 'SEVERITY', width: 90, colorRule: sevCls },
            { key: 'Hosts', label: 'HOSTS', width: 70 },
            { key: 'Decision', label: 'CATALOG MATCH', width: 170, colorRule: findingDecisionCls }
          ],
          rowClass: function (r) { return String(r.PluginName) === String(selectedFinding.name) ? 'row-warn' : ''; },
          onRowClick: function (r) { selectFinding(r); }
        });
        var holder = el('div'); holder.style.cssText = 'flex:1;min-height:0;display:flex'; holder.appendChild(grid.el);
        panel.appendChild(holder);

        exportBtn.onclick = function () {
          var rows = currentFindingRows();   // honor the active client-side search filter
          if (!rows.length) { ctx.confirm({ title: 'Nothing to export', body: 'No findings yet - load a report first.', okText: 'OK', cancelText: null }); return; }
          var labels = ['Plugin', 'Category', 'Plugin Name', 'Severity', 'Hosts', 'Decision'];
          var keys = ['Plugin', 'Category', 'PluginName', 'Severity', 'Hosts', 'Decision'];
          var data = rows.map(function (r) { return keys.map(function (k) { return r[k] == null ? '' : r[k]; }); });
          ctx.util.downloadXlsx('UPR_Findings_' + ctx.util.fileStamp() + '.xlsx', labels, data, 'Findings');
        };

        // single-click selection (onRowClick fires on dblclick in the grid, so
        // also wire a single-click handler on the table body for selection)
        grid.el.addEventListener('click', function (e) {
          var tr = e.target && e.target.closest ? e.target.closest('tr[data-key]') : null;
          if (!tr) return;
          var k = tr.dataset.key;
          var row = grid.rows().filter(function (x) { return keyByRk(x) === k; })[0];
          if (row) selectFinding(row);
        });

        var selBanner = el('div', 'muted'); selBanner.style.cssText = 'font-family:var(--mono);font-size:12px;padding:4px 2px';
        selBanner.textContent = 'No finding selected.';
        panel.appendChild(selBanner);

        findApi = {
          grid: grid, countLbl: countLbl, selBanner: selBanner, searchInput: searchInput,
          note: function (text, level) { /* findings tab has no log pane; surface in count line */ countLbl.textContent = text; countLbl.className = level === 'err' ? 'st-bad' : (level === 'ok' ? 'st-ok' : 'muted'); },
          search: function () { return (searchInput.value || '').trim(); }
        };
        // if a report is already loaded (tab opened after upload), populate now
        if (reportPath) runFindings();
        refreshSelBanner();
      }

      function selectFinding(r) {
        selectedFinding = {
          plugin: String(r.Plugin || ''), name: String(r.PluginName || ''),
          decision: String(r.Decision || ''), hosts: r.Hosts || 0
        };
        // re-upsert every row so rowClass re-runs and the new selection highlight paints
        if (findApi && findApi.grid) { findApi.grid.rows().forEach(function (x) { findApi.grid.upsert(x); }); }
        refreshSelBanner();
        if (uninstApi) uninstApi.refreshSel();
      }
      function refreshSelBanner() {
        if (!findApi) return;
        if (!selectedFinding.name) { findApi.selBanner.textContent = 'No finding selected. Click a row, then open the Uninstall tab.'; findApi.selBanner.className = 'muted'; return; }
        findApi.selBanner.innerHTML = 'Selected: <b>[' + escHtml(selectedFinding.plugin) + ']</b> ' + escHtml(selectedFinding.name) +
          '  -  ' + selectedFinding.hosts + ' host(s)  -  ' + escHtml(selectedFinding.decision);
        findApi.selBanner.className = (selectedFinding.decision.indexOf('Uninstall') === 0) ? 'st-ok' : (selectedFinding.decision.indexOf('OS') === 0 ? 'cell-dim' : 'st-warn');
      }

      // ---- client-side findings filter (Search no longer re-parses the report) ----
      function findingMatch(r, q) {
        if (!q) return true;
        var hay = (String(r.Plugin == null ? '' : r.Plugin) + ' ' +
                   String(r.PluginName == null ? '' : r.PluginName) + ' ' +
                   String(r.Category == null ? '' : r.Category)).toLowerCase();
        return hay.indexOf(q.toLowerCase()) !== -1;
      }
      function currentFindingRows() {
        if (!findApi || !findApi.grid) return [];
        var q = findApi.search();
        var rows = findApi.grid.rows();
        return q ? rows.filter(function (r) { return findingMatch(r, q); }) : rows;
      }
      function applyFindingFilter() {
        if (!findApi || !findApi.grid) return;
        var q = findApi.search();
        findApi.grid.setFilter(q ? function (r) { return findingMatch(r, q); } : null);
        var total = findApi.grid.rows().length;
        var shown = q ? currentFindingRows().length : total;
        var hidden = findApi.hiddenUpdate || 0;
        var txt = q ? ('Showing ' + shown + ' of ' + total + ' finding(s) matching "' + q + '"')
                    : ('Showing ' + total + ' finding(s)');
        if (hidden) txt += '  |  ' + hidden + ' update-class hidden';
        txt += '  |  host class: ' + hostClass();
        findApi.countLbl.textContent = txt;
        findApi.countLbl.className = shown ? 'st-ok' : 'st-warn';
      }

      function runFindings() {
        if (!findApi || !reportPath) return;
        if (findRun && findRun.state && findRun.state.active) return;
        findApi.grid.clear();
        findApi.countLbl.textContent = 'Parsing report...'; findApi.countLbl.className = 'muted';
        var n = 0, hidden = 0;
        // Fetch the FULL finding set for this host class; Search filters it client-side.
        findRun = ctx.run('report-findings', reportParams({ hostclass: hostClass() }), { keyOf: keyByRk });
        if (findUnsub) findUnsub();
        findUnsub = findRun.subscribe({
          reset: function () { n = 0; },
          row: function (r) { n++; findApi.grid.upsert(r); },
          status: function (t) { var m = /\((\d+) update-class/.exec(t || ''); if (m) hidden = +m[1]; findApi.countLbl.textContent = t; findApi.countLbl.className = 'st-info'; },
          log: function () { /* findings tab has no console */ },
          error: function (e) { findApi.countLbl.textContent = e.text; findApi.countLbl.className = 'st-bad'; },
          final: function () {
            findApi.hiddenUpdate = hidden;
            applyFindingFilter();   // re-applies any active search + paints the count line
          }
        });
      }

      // ===================================================================
      //  TAB 2 - Uninstall  (the core: report-scan -> report-uninstall)
      // ===================================================================
      function buildUninstallTab(panel) {
        panel.style.cssText = 'display:flex;flex-direction:column;height:100%;min-height:0;gap:8px';
        panel.appendChild(secHdr('BULK UNINSTALL'));
        panel.appendChild(hint('Scan opens one session per affected host, enumerates installed software, and matches the catalog. Only PROVEN-EOL (Uninstall) rows pre-check; Review / Tanium / unreachable rows are never removable. Plan-only (dry run) is set up top.'));

        var selLine = el('div', 'muted'); selLine.style.cssText = 'font-family:var(--mono);font-size:12px;padding:2px';
        panel.appendChild(selLine);

        // action bar: Scan / Uninstall Selected / Export
        var bar = el('div'); bar.style.cssText = 'display:flex;align-items:center;gap:10px;flex-wrap:wrap';
        var scanBtn = ui.button('Scan Hosts', { variant: 'cyan', title: 'Open a session per affected host and match the catalog. Nothing is uninstalled.' });
        var uninstBtn = ui.button('Uninstall Selected', { variant: 'danger', title: 'Uninstall the CHECKED proven-EOL products. Honours Plan-only (dry run).' });
        uninstBtn.disabled = true;
        var cancelBtn = ui.ghostButton('Cancel', { size: 'sm', title: 'Cancel the in-flight scan / uninstall.' }); cancelBtn.disabled = true;
        var exportBtn = ui.ghostButton('Export Results', { size: 'sm', title: 'Export the candidate rows to CSV.' }); exportBtn.disabled = true;
        var statusLbl = el('span', 'muted'); statusLbl.style.cssText = 'font-family:var(--mono);font-size:12px;margin-left:auto';
        bar.appendChild(scanBtn); bar.appendChild(uninstBtn); bar.appendChild(cancelBtn); bar.appendChild(exportBtn); bar.appendChild(statusLbl);
        panel.appendChild(bar);

        var prog = C.ProgressStatusStrip({ showCount: true });
        panel.appendChild(prog.el);

        // results grid (one row per host x matched install, keyed by _rk)
        var grid = C.ResultsGrid({
          title: 'Uninstall candidates', keyMode: { rk: true }, selectable: true, popOut: true,
          columns: [
            { key: 'Host', label: 'HOST', width: 150 },
            { key: 'Plugin', label: 'PLUGIN', width: 70 },
            { key: 'Product', label: 'DISPLAY NAME' },
            { key: 'Publisher', label: 'PUBLISHER', width: 150 },
            { key: 'Type', label: 'TYPE', width: 80 },
            { key: 'Version', label: 'VERSION', width: 95 },
            { key: 'Decision', label: 'DECISION', width: 130, colorRule: scanDecisionCls },
            { key: 'Result', label: 'RESULT', width: 200, render: function (r) {
                // pre-uninstall the engine emits Detail (scan); during/after uninstall it emits Result
                var v = (r.Result != null && r.Result !== '') ? r.Result : (r.Detail != null ? r.Detail : '');
                return { text: v == null ? '' : String(v), cls: (r.Result != null && r.Result !== '') ? resultCls(r.Result) : 'cell-dim', title: v };
              } }
          ],
          rowClass: function (r) {
            var d = String(r.Decision);
            if (d === 'Unreachable' || d === 'No match' || d === 'Skipped (Tanium)') return '';
            if (d === 'Error') return 'row-bad';
            var res = String(r.Result == null ? '' : r.Result);
            if (res.indexOf('OK') === 0) return 'row-ok';
            if (res.indexOf('FAIL') === 0) return 'row-bad';
            if (res.indexOf('WARN') === 0) return 'row-warn';
            return '';
          }
        });
        var holder = el('div'); holder.style.cssText = 'flex:1;min-height:0;display:flex'; holder.appendChild(grid.el);
        panel.appendChild(holder);

        uninstApi = {
          grid: grid, log: log, prog: prog, statusLbl: statusLbl, selLine: selLine,
          scanBtn: scanBtn, uninstBtn: uninstBtn, cancelBtn: cancelBtn, exportBtn: exportBtn,
          refreshSel: refreshUninstSel, refreshButtons: refreshUninstButtons
        };

        scanBtn.onclick = function () { doScan(); };
        uninstBtn.onclick = function () { doUninstall(); };
        cancelBtn.onclick = function () { if (scanRun) { scanRun.cancel(); log.append({ text: 'CANCEL requested - stopping in-flight host jobs...', level: 'warn' }); } };
        exportBtn.onclick = function () { exportScanResults(grid); };

        refreshUninstSel(); refreshUninstButtons();
      }

      function refreshUninstSel() {
        if (!uninstApi) return;
        if (!selectedFinding.name) { uninstApi.selLine.textContent = 'No finding selected. Pick a finding on the Import & Findings tab first.'; uninstApi.selLine.className = 'st-warn'; return; }
        uninstApi.selLine.innerHTML = 'Finding: <b>[' + escHtml(selectedFinding.plugin) + ']</b> ' + escHtml(selectedFinding.name) +
          '  -  ' + selectedFinding.hosts + ' host(s)  -  ' + escHtml(selectedFinding.decision) +
          '  <span class="muted">(Scan fans out across ALL actionable findings in the report)</span>';
        uninstApi.selLine.className = 'st-info';
      }
      function refreshUninstButtons() {
        if (!uninstApi) return;
        var rows = uninstApi.grid.rows();
        var anyProven = rows.some(isProvenRow);
        uninstApi.uninstBtn.disabled = !anyProven || anyRunActive();
        uninstApi.exportBtn.disabled = !rows.length || anyRunActive();
      }

      function lockUninstButtons(on) {
        if (!uninstApi) return;
        uninstApi.scanBtn.disabled = on;
        uninstApi.cancelBtn.disabled = !on;
        loadBtn.disabled = on || uploading;
        hostSel.disabled = on; threadsInput.disabled = on; dryCb._cb.disabled = on;
        if (on) { uninstApi.uninstBtn.disabled = true; uninstApi.exportBtn.disabled = true; }
        else { refreshUninstButtons(); }
      }

      // ---- STAGE 2: Scan hosts (report-scan) ----
      function doScan() {
        if (!needReport(true)) return;
        if (anyRunActive()) return;
        var log = uninstApi.log, grid = uninstApi.grid, prog = uninstApi.prog;
        grid.clear(); prog.reset();
        lastScanWasUninstall = false;
        lockUninstButtons(true);
        uninstApi.statusLbl.textContent = 'Scanning...'; uninstApi.statusLbl.className = 'st-info';
        log.banner('SCAN: actionable findings (host class: ' + hostClass() + ')');
        var counts = { uninstall: 0, review: 0, tanium: 0, unreach: 0, nomatch: 0, error: 0 };
        scanRun = ctx.run('report-scan', reportParams({ hostclass: hostClass(), threads: threadCount() }), { keyOf: keyByRk });
        bindScan(scanRun, counts, false);
      }

      // ---- STAGE 3: Uninstall checked proven rows (report-uninstall) ----
      async function doUninstall() {
        if (!needReport(true)) return;
        if (anyRunActive()) return;
        var grid = uninstApi.grid, log = uninstApi.log;
        var checked = grid.getChecked().filter(isProvenRow);
        if (!checked.length) {
          ctx.confirm({ title: 'Nothing to uninstall', body: 'No PROVEN-EOL (Uninstall) rows are checked. Review / Tanium / unreachable rows are never removable.', okText: 'OK', cancelText: null });
          return;
        }
        var dry = isDry();
        // destructive guard: an admin session is required for a LIVE uninstall
        if (!dry && !ctx.session.state.credSet) {
          ctx.confirm({ title: 'Admin session required', body: 'Set ADW credentials (top-right) and start an admin session before a LIVE uninstall - it permanently removes software. (Dry run needs no admin session.)', okText: 'OK', cancelText: null });
          return;
        }
        var hostsSet = {}; checked.forEach(function (r) { hostsSet[String(r.Host)] = true; });
        var hostCount = Object.keys(hostsSet).length;
        var sample = checked.slice(0, 6).map(function (r) { return r.Host + '  ->  ' + r.Product + (r.Version ? ' (' + r.Version + ')' : ''); });

        // Operator-selection payload: the engine removes EXACTLY these checked
        // host+product pairs (not a re-scan-all). Newline-delimited; per-row key is
        // Host|Product|Version|PSChildName, matching the engine's candidate key.
        var selHosts = Object.keys(hostsSet).join('\n');
        var selKeys = checked.map(function (r) {
          return [String(r.Host || ''), String(r.Product || ''), String(r.Version || ''), String(r.PSChildName || '')].join('|');
        }).join('\n');

        // dry run = a plain confirm; live = the danger ArmingDialog with a typed word
        var ok;
        if (dry) {
          ok = await ctx.confirm({
            title: 'Plan uninstall (DRY RUN)',
            body: 'Plan removal of <b>' + checked.length + '</b> proven-EOL product(s) across <b>' + hostCount + '</b> host(s)?<br><br>Dry run is ON - nothing will be removed. This previews the plan only.',
            list: sample, okText: 'Preview plan', cancelText: 'Cancel'
          });
        } else {
          ok = await ctx.arm({
            title: 'Uninstall proven-EOL software',
            banner: 'IRREVERSIBLE - SOFTWARE WILL BE REMOVED',
            body: 'Uninstall <b>' + checked.length + '</b> proven-EOL product(s) across <b>' + hostCount + '</b> host(s).<br>Dry run: <b>OFF</b>. Review / Tanium matches are never removed. <b>This cannot be undone.</b>',
            preflight: [
              { label: 'Admin session active (ADW credential set)', ok: !!ctx.session.state.credSet },
              { label: 'Only proven-EOL (Uninstall) rows selected', ok: true },
              { label: 'Dry run is OFF - software will be removed', ok: false }
            ],
            confirmWord: 'UNINSTALL', okText: 'Uninstall now', cancelText: 'Cancel'
          });
        }
        if (!ok) { log.append({ text: 'Uninstall cancelled by operator.', level: 'warn' }); return; }

        var prog = uninstApi.prog;
        grid.clear(); prog.reset();
        lastScanWasUninstall = true;
        lockUninstButtons(true);
        uninstApi.statusLbl.textContent = dry ? 'Planning (dry run)...' : 'Uninstalling...'; uninstApi.statusLbl.className = 'st-info';
        log.banner('UNINSTALL (DryRun=' + dry + ', host class: ' + hostClass() + ')');
        // The engine re-scans ONLY the selected hosts, then uninstalls ONLY the
        // checked proven candidates (selecthosts + selectkeys). The proven + non-
        // Tanium gate still runs server-side; unchecked rows are never removed.
        var counts = { ok: 0, warn: 0, fail: 0, skipped: 0, unreach: 0, error: 0 };
        scanRun = ctx.run('report-uninstall', reportParams({ hostclass: hostClass(), threads: threadCount(), dryrun: dry, selecthosts: selHosts, selectkeys: selKeys }), { keyOf: keyByRk });
        bindUninstall(scanRun, counts, dry);
      }

      function bindScan(runHandle, counts) {
        var log = uninstApi.log, grid = uninstApi.grid, prog = uninstApi.prog;
        if (scanUnsub) scanUnsub();
        scanUnsub = runHandle.subscribe({
          status: function (t) { prog.setPhase(t); log.append({ text: t, level: 'gold' }); },
          progress: function (p) { prog.setProgress(p.done, p.total); },
          row: function (r) {
            grid.upsert(r);
            tallyScanRow(r, counts);
            logScanRow(log, r);
          },
          log: function (l) { log.append(l); },
          error: function (e) { log.append({ text: e.text, level: 'err' }); },
          final: function () {
            // pre-check ONLY proven-EOL rows (the one-click-removable set)
            grid.selectWhere(isProvenRow);
            var msg = 'Scan complete: ' + counts.uninstall + ' proven (pre-checked), ' + counts.review + ' review, ' + counts.tanium + ' Tanium, ' + counts.nomatch + ' no-match, ' + counts.unreach + ' unreachable, ' + counts.error + ' error.';
            log.banner(msg);
            uninstApi.statusLbl.textContent = counts.uninstall + ' proven candidate(s) pre-checked'; uninstApi.statusLbl.className = counts.uninstall ? 'st-ok' : 'st-warn';
          },
          active: function (a) {
            lockUninstButtons(a);
            if (!a) { refreshUninstButtons(); }
          }
        });
      }
      function tallyScanRow(r, c) {
        switch (String(r.Decision)) {
          case 'Uninstall': c.uninstall++; break;
          case 'Review': c.review++; break;
          case 'Skipped (Tanium)': c.tanium++; break;
          case 'Unreachable': c.unreach++; break;
          case 'Error': c.error++; break;
          case 'No match': c.nomatch++; break;
        }
      }
      function logScanRow(log, r) {
        var d = String(r.Decision);
        if (d === 'Unreachable') { log.append({ text: '[' + r.Host + '] UNREACHABLE: ' + (r.Detail || ''), level: 'warn' }); return; }
        if (d === 'Error') { log.append({ text: '[' + r.Host + '] ERROR: ' + (r.Detail || ''), level: 'err' }); return; }
        if (d === 'No match') { log.append({ text: '[' + r.Host + '] no flagged install in the registry.', level: 'dim' }); return; }
        var lvl = (d === 'Uninstall') ? 'ok' : (d === 'Review' ? 'info' : (d === 'Skipped (Tanium)' ? 'warn' : 'dim'));
        log.append({ text: '[' + r.Host + '] ' + r.Product + (r.Version ? ' (' + r.Version + ')' : '') + '  ->  ' + d, level: lvl });
      }

      function bindUninstall(runHandle, counts, dry) {
        var log = uninstApi.log, grid = uninstApi.grid, prog = uninstApi.prog;
        if (scanUnsub) scanUnsub();
        scanUnsub = runHandle.subscribe({
          status: function (t) { prog.setPhase(t); log.append({ text: t, level: 'gold' }); },
          progress: function (p) { prog.setProgress(p.done, p.total); },
          row: function (r) {
            grid.upsert(r);
            tallyUninstallRow(r, counts, log);
            recordHistory(r, dry);
          },
          log: function (l) { log.append(l); },
          error: function (e) { log.append({ text: e.text, level: 'err' }); },
          final: function () {
            var msg = (dry ? 'Plan complete' : 'Uninstall complete') + ': ' + counts.ok + ' OK, ' + counts.warn + ' warn, ' + counts.fail + ' fail, ' + counts.skipped + ' skipped, ' + (counts.unreach + counts.error) + ' unreachable/error.';
            log.banner(msg);
            uninstApi.statusLbl.textContent = msg; uninstApi.statusLbl.className = (counts.fail || counts.error) ? 'st-bad' : 'st-ok';
            if (hist) renderHistory();
            ctx.confirm({
              title: dry ? 'Dry run complete' : 'Uninstall complete',
              body: 'OK: <b>' + counts.ok + '</b><br>Warn: <b>' + counts.warn + '</b><br>Fail: <b>' + counts.fail + '</b><br>Skipped: <b>' + counts.skipped + '</b><br>Unreachable / error: <b>' + (counts.unreach + counts.error) + '</b>',
              okText: 'OK', cancelText: null
            });
          },
          active: function (a) { lockUninstButtons(a); if (!a) refreshUninstButtons(); }
        });
      }
      function tallyUninstallRow(r, c, log) {
        var d = String(r.Decision);
        if (d === 'Unreachable') { c.unreach++; log.append({ text: '[' + r.Host + '] UNREACHABLE: ' + (r.Result || ''), level: 'warn' }); return; }
        if (d === 'Error') { c.error++; log.append({ text: '[' + r.Host + '] ERROR: ' + (r.Result || ''), level: 'err' }); return; }
        var res = String(r.Result == null ? '' : r.Result);
        if (res === 'Uninstalling...') { log.append({ text: '[' + r.Host + '] ' + r.Product + ' - uninstalling...', level: 'warn' }); return; }
        var lvl, label;
        if (res.indexOf('OK') === 0) { c.ok++; lvl = 'ok'; label = 'OK'; }
        else if (res.indexOf('WARN') === 0) { c.warn++; lvl = 'warn'; label = 'WARN'; }
        else if (res.indexOf('FAIL') === 0) { c.fail++; lvl = 'err'; label = 'FAIL'; }
        else if (res.indexOf('Skipped') === 0) { c.skipped++; lvl = 'dim'; label = 'SKIP'; }
        else { lvl = 'dim'; label = ''; }
        if (res !== '') log.append({ text: '[' + r.Host + '] ' + r.Product + (r.Version ? ' (' + r.Version + ')' : '') + '  ->  ' + res, level: lvl });
      }

      function recordHistory(r, dry, kind) {
        var res = String(r.Result == null ? '' : r.Result);
        if (res === '' || res === 'Uninstalling...') return;     // only final outcomes
        var act = kind || 'Uninstall';
        historyRows.push({
          When: nowStamp(), Host: String(r.Host || ''), Action: dry ? (act + ' (DryRun)') : act,
          Item: String(r.Product || '') + (r.Version ? ' (' + r.Version + ')' : ''), Result: res
        });
        if (historyRows.length > 200) historyRows = historyRows.slice(historyRows.length - 200);
      }

      function exportScanResults(grid) {
        var rows = grid.rows();
        if (!rows.length) { ctx.confirm({ title: 'Nothing to export', body: 'Scan first - there are no candidate rows.', okText: 'OK', cancelText: null }); return; }
        var cols = ['Host', 'Plugin', 'Product', 'Publisher', 'Type', 'Version', 'Decision', lastScanWasUninstall ? 'Result' : 'Detail'];
        var labelRow = ['Host', 'Plugin', 'Display Name', 'Publisher', 'Type', 'Version', 'Decision', lastScanWasUninstall ? 'Result' : 'Detail'];
        var data = rows.map(function (r) { return cols.map(function (c) { return r[c] == null ? '' : r[c]; }); });
        ctx.util.downloadXlsx('UPR_Candidates_' + ctx.util.fileStamp() + '.xlsx', labelRow, data, 'Candidates');
      }

      // ===================================================================
      //  TAB - Targeted Removal  (manual-scan -> manual-uninstall)
      //  Operator pastes a machine list + a software list; scan finds matches,
      //  check rows, uninstall. No report needed. Protected security agents are
      //  always skipped. Uses the global Threads + Plan-only (dry run).
      // ===================================================================
      function buildManualTab(panel) {
        panel.style.cssText = 'display:flex;flex-direction:column;height:100%;min-height:0;gap:8px';
        panel.appendChild(secHdr('TARGETED REMOVAL'));
        panel.appendChild(hint('Paste machines on the left and the software to find on the right (one per line; * = wildcard, e.g. Adobe*Reader). Scan opens one session per host and lists installs whose name matches (case-insensitive, anywhere in the name). Check rows, then Uninstall Selected. Security agents (Tanium, Trellix, Defender, CrowdStrike, ...) are never removable. Honors Threads + Plan-only (dry run) up top.'));

        // two input columns: Machines (+ Import CSV) | Software
        var io = el('div'); io.style.cssText = 'display:flex;gap:14px;flex-wrap:wrap';
        var mCol = el('div'); mCol.style.cssText = 'flex:1 1 280px;min-width:240px;display:flex;flex-direction:column;gap:6px';
        mCol.appendChild(ui.eyebrow('MACHINES'));
        var hostBox = el('textarea');
        hostBox.placeholder = 'One hostname or IP per line - or Import CSV';
        hostBox.style.cssText = 'width:100%;min-height:120px;box-sizing:border-box;font-family:var(--mono);font-size:12px;background:var(--input);color:var(--text);border:1px solid var(--edge);border-radius:6px;padding:8px;resize:vertical';
        hostBox.addEventListener('input', function () { manModel.set(hostBox.value); });
        // paste a multi-column CSV -> auto-extract the host column (same detect as Reports)
        hostBox.addEventListener('paste', function (e) {
          var cd = e.clipboardData || window.clipboardData; if (!cd) { return; }
          var text = cd.getData('text') || cd.getData('Text'); if (!text || text.indexOf(',') < 0) { return; }
          var hp = ctx.util.parseCsv(text); if (!hp.headers || hp.headers.length <= 1) { return; }
          if (manFindCol(hp.headers, ['Computer Name', 'ComputerName', 'Hostname', 'Host', 'FQDN', 'Name']) < 0) { return; }
          e.preventDefault(); manImportCsvText(text, 'pasted CSV');
        });
        mCol.appendChild(hostBox);
        var mBar = el('div'); mBar.style.cssText = 'display:flex;align-items:center;gap:8px';
        var mImport = ui.button('Import CSV', { variant: 'cyan', size: 'sm', title: 'Load hostnames from a CSV - detects the hostname column and ignores the rest.' });
        var mClear = ui.ghostButton('Clear', { size: 'sm' });
        var mCount = el('span', 'muted'); mCount.style.cssText = 'font-family:var(--mono);font-size:12px;margin-left:auto'; mCount.textContent = '0 machine(s)';
        mBar.appendChild(mImport); mBar.appendChild(mClear); mBar.appendChild(mCount);
        mCol.appendChild(mBar);
        io.appendChild(mCol);

        var sCol = el('div'); sCol.style.cssText = 'flex:1 1 280px;min-width:240px;display:flex;flex-direction:column;gap:6px';
        sCol.appendChild(ui.eyebrow('SOFTWARE TO FIND'));
        var swBox = el('textarea');
        swBox.placeholder = 'One software name per line.\n* = wildcard (e.g. Adobe*Reader)\nMatches anywhere in the name, case-insensitive.';
        swBox.style.cssText = 'width:100%;min-height:120px;box-sizing:border-box;font-family:var(--mono);font-size:12px;background:var(--input);color:var(--text);border:1px solid var(--edge);border-radius:6px;padding:8px;resize:vertical';
        swBox.addEventListener('input', function () { manRefreshCounts(); });
        sCol.appendChild(swBox);
        var sBar = el('div'); sBar.style.cssText = 'display:flex;align-items:center;gap:8px';
        var sClear = ui.ghostButton('Clear', { size: 'sm' });
        var sCount = el('span', 'muted'); sCount.style.cssText = 'font-family:var(--mono);font-size:12px;margin-left:auto'; sCount.textContent = '0 rule(s)';
        sBar.appendChild(sClear); sBar.appendChild(sCount);
        sCol.appendChild(sBar);
        io.appendChild(sCol);
        panel.appendChild(io);

        // action bar
        var bar = el('div'); bar.style.cssText = 'display:flex;align-items:center;gap:10px;flex-wrap:wrap';
        var scanBtn = ui.button('Scan Hosts', { variant: 'cyan', title: 'Open a session per machine and list installs matching your software list. Nothing is uninstalled.' });
        var uninstBtn = ui.button('Uninstall Selected', { variant: 'danger', title: 'Uninstall the CHECKED matches. Honors Plan-only (dry run). Security agents never removed.' });
        uninstBtn.disabled = true;
        var cancelBtn = ui.ghostButton('Cancel', { size: 'sm', title: 'Cancel the in-flight scan / uninstall.' }); cancelBtn.disabled = true;
        var exportBtn = ui.ghostButton('Export Results', { size: 'sm', title: 'Export the rows to XLSX.' }); exportBtn.disabled = true;
        var statusLbl = el('span', 'muted'); statusLbl.style.cssText = 'font-family:var(--mono);font-size:12px;margin-left:auto';
        bar.appendChild(scanBtn); bar.appendChild(uninstBtn); bar.appendChild(cancelBtn); bar.appendChild(exportBtn); bar.appendChild(statusLbl);
        panel.appendChild(bar);

        var prog = C.ProgressStatusStrip({ showCount: true });
        panel.appendChild(prog.el);

        var grid = C.ResultsGrid({
          title: 'Targeted matches', keyMode: { rk: true }, selectable: true, popOut: true,
          columns: [
            { key: 'Host', label: 'HOST', width: 150 },
            { key: 'Product', label: 'DISPLAY NAME' },
            { key: 'Publisher', label: 'PUBLISHER', width: 150 },
            { key: 'Type', label: 'TYPE', width: 80 },
            { key: 'Version', label: 'VERSION', width: 95 },
            { key: 'Decision', label: 'DECISION', width: 150, colorRule: scanDecisionCls },
            { key: 'Result', label: 'RESULT', width: 200, render: function (r) {
                var v = (r.Result != null && r.Result !== '') ? r.Result : (r.Detail != null ? r.Detail : '');
                return { text: v == null ? '' : String(v), cls: (r.Result != null && r.Result !== '') ? resultCls(r.Result) : 'cell-dim', title: v };
              } }
          ],
          rowClass: function (r) {
            var d = String(r.Decision);
            if (d === 'Error') return 'row-bad';
            var res = String(r.Result == null ? '' : r.Result);
            if (res.indexOf('OK') === 0) return 'row-ok';
            if (res.indexOf('FAIL') === 0) return 'row-bad';
            if (res.indexOf('WARN') === 0) return 'row-warn';
            return '';
          }
        });
        var holder = el('div'); holder.style.cssText = 'flex:1;min-height:0;display:flex'; holder.appendChild(grid.el);
        panel.appendChild(holder);

        manApi = {
          grid: grid, prog: prog, statusLbl: statusLbl, hostBox: hostBox, swBox: swBox,
          scanBtn: scanBtn, uninstBtn: uninstBtn, cancelBtn: cancelBtn, exportBtn: exportBtn,
          mCount: mCount, sCount: sCount
        };

        // Import CSV updates manModel -> reflect back into the textarea + counts.
        manModel.onChange(function () { if (hostBox.value !== manModel.raw) hostBox.value = manModel.raw; manRefreshCounts(); });

        function manFindCol(headers, cands) {
          for (var c = 0; c < cands.length; c++) for (var h = 0; h < headers.length; h++)
            if (String(headers[h]).trim().toLowerCase() === cands[c].toLowerCase()) return h;
          return -1;
        }
        function manImportCsvText(text, fileName) {
          var p = ctx.util.parseCsv(text), headers = p.headers || [];
          var hi = manFindCol(headers, ['Computer Name', 'ComputerName', 'Hostname', 'Host', 'FQDN', 'Name']);
          var hosts = [];
          if (hi >= 0) {
            p.rows.forEach(function (r) { var hn = String(r[hi] == null ? '' : r[hi]).trim(); if (hn) hosts.push(hn); });
          } else if (headers.length <= 1) {
            [headers[0]].concat(p.rows.map(function (r) { return r[0]; })).forEach(function (v) { var hn = String(v == null ? '' : v).trim(); if (hn) hosts.push(hn); });
          } else {
            ctx.confirm({ title: 'Unrecognized CSV', body: 'No hostname column found in ' + escHtml(fileName) + '. Expected one of: Computer Name, ComputerName, Hostname, Host, FQDN, Name.', okText: 'OK', cancelText: null });
            return;
          }
          if (!hosts.length) { log.append({ text: 'No hostnames found in ' + fileName + '.', level: 'warn' }); return; }
          var existing = manModel.raw.replace(/\s+$/, '');
          manModel.set((existing ? existing + '\n' : '') + hosts.join('\n'));
          log.append({ text: 'Imported ' + hosts.length + ' machine(s) from ' + fileName + '.', level: 'ok' });
        }
        mImport.onclick = function () {
          var fi = el('input'); fi.type = 'file'; fi.accept = '.csv,.tsv,.txt'; fi.style.display = 'none';
          document.body.appendChild(fi);
          fi.addEventListener('change', function () {
            var f = fi.files && fi.files[0]; document.body.removeChild(fi); if (!f) return;
            var reader = new FileReader();
            reader.onload = function () { manImportCsvText(String(reader.result || ''), f.name); };
            reader.readAsText(f);
          });
          fi.click();
        };
        mClear.onclick = function () { manModel.set(''); };
        sClear.onclick = function () { swBox.value = ''; manRefreshCounts(); };

        scanBtn.onclick = function () { doManualScan(); };
        uninstBtn.onclick = function () { doManualUninstall(); };
        cancelBtn.onclick = function () { if (manRun) { manRun.cancel(); log.append({ text: 'CANCEL requested - stopping in-flight host jobs...', level: 'warn' }); } };
        exportBtn.onclick = function () { manExport(grid); };

        hostBox.value = manModel.raw;
        manRefreshCounts();
      }

      function manSoftwareLines() {
        if (!manApi) return [];
        return String(manApi.swBox.value || '').split(/\r?\n/).map(function (s) { return s.trim(); }).filter(Boolean);
      }
      function manRefreshCounts() {
        if (!manApi) return;
        var hn = manModel.count();
        var seen = {}, rules = 0;
        manSoftwareLines().forEach(function (s) { var k = s.toLowerCase(); if (!seen[k]) { seen[k] = 1; rules++; } });
        manApi.mCount.textContent = hn + ' machine(s)'; manApi.mCount.className = hn ? 'st-ok' : 'muted';
        manApi.sCount.textContent = rules + ' rule(s)'; manApi.sCount.className = rules ? 'st-ok' : 'muted';
      }
      function manParams(extra) {
        var p = extra || {};
        p.hosts = manModel.hosts().join('\n');
        p.software = manSoftwareLines().join('\n');
        return p;
      }
      function manRefreshButtons() {
        if (!manApi) return;
        var rows = manApi.grid.rows();
        var anyRemovable = rows.some(isProvenRow);
        manApi.uninstBtn.disabled = !anyRemovable || anyRunActive();
        manApi.exportBtn.disabled = !rows.length || anyRunActive();
      }
      function lockManualButtons(on) {
        if (!manApi) return;
        manApi.scanBtn.disabled = on;
        manApi.cancelBtn.disabled = !on;
        threadsInput.disabled = on; dryCb._cb.disabled = on;
        if (on) { manApi.uninstBtn.disabled = true; manApi.exportBtn.disabled = true; }
        else { manRefreshButtons(); }
      }

      function doManualScan() {
        if (anyRunActive()) return;
        var hosts = manModel.hosts(), rules = manSoftwareLines();
        if (!hosts.length) { ctx.confirm({ title: 'No machines', body: 'Paste at least one machine (or Import CSV) first.', okText: 'OK', cancelText: null }); return; }
        if (!rules.length) { ctx.confirm({ title: 'No software', body: 'Paste at least one software name to find first.', okText: 'OK', cancelText: null }); return; }
        var grid = manApi.grid, prog = manApi.prog;
        grid.clear(); prog.reset();
        lockManualButtons(true);
        manApi.statusLbl.textContent = 'Scanning...'; manApi.statusLbl.className = 'st-info';
        log.banner('TARGETED SCAN: ' + hosts.length + ' machine(s), ' + rules.length + ' rule(s)');
        var counts = { match: 0, protectedC: 0, nomatch: 0, unreach: 0, error: 0 };
        manRun = ctx.run('manual-scan', manParams({ threads: threadCount() }), { keyOf: keyByRk });
        bindManualScan(manRun, counts);
      }

      async function doManualUninstall() {
        if (anyRunActive()) return;
        var grid = manApi.grid;
        var checked = grid.getChecked().filter(isProvenRow);
        if (!checked.length) {
          ctx.confirm({ title: 'Nothing to uninstall', body: 'No removable (Uninstall) rows are checked. Protected agents / no-match / unreachable rows are never removable.', okText: 'OK', cancelText: null });
          return;
        }
        var dry = isDry();
        if (!dry && !ctx.session.state.credSet) {
          ctx.confirm({ title: 'Admin session required', body: 'Set ADW credentials (top-right) and start an admin session before a LIVE uninstall - it permanently removes software. (Dry run needs no admin session.)', okText: 'OK', cancelText: null });
          return;
        }
        var hostsSet = {}; checked.forEach(function (r) { hostsSet[String(r.Host)] = true; });
        var hostCount = Object.keys(hostsSet).length;
        var sample = checked.slice(0, 6).map(function (r) { return r.Host + '  ->  ' + r.Product + (r.Version ? ' (' + r.Version + ')' : ''); });
        var selHosts = Object.keys(hostsSet).join('\n');
        var selKeys = checked.map(function (r) {
          return [String(r.Host || ''), String(r.Product || ''), String(r.Version || ''), String(r.PSChildName || '')].join('|');
        }).join('\n');

        var ok;
        if (dry) {
          ok = await ctx.confirm({
            title: 'Plan uninstall (DRY RUN)',
            body: 'Plan removal of <b>' + checked.length + '</b> product(s) across <b>' + hostCount + '</b> machine(s)?<br><br>Dry run is ON - nothing will be removed. This previews the plan only.',
            list: sample, okText: 'Preview plan', cancelText: 'Cancel'
          });
        } else {
          ok = await ctx.arm({
            title: 'Uninstall selected software',
            banner: 'IRREVERSIBLE - SOFTWARE WILL BE REMOVED',
            body: 'Uninstall <b>' + checked.length + '</b> product(s) across <b>' + hostCount + '</b> machine(s).<br>Dry run: <b>OFF</b>. Protected security agents are never removed. <b>This cannot be undone.</b>',
            preflight: [
              { label: 'Admin session active (ADW credential set)', ok: !!ctx.session.state.credSet },
              { label: 'Only checked rows will be removed', ok: true },
              { label: 'Dry run is OFF - software will be removed', ok: false }
            ],
            confirmWord: 'UNINSTALL', okText: 'Uninstall now', cancelText: 'Cancel'
          });
        }
        if (!ok) { log.append({ text: 'Targeted uninstall cancelled by operator.', level: 'warn' }); return; }

        var prog = manApi.prog;
        grid.clear(); prog.reset();
        lockManualButtons(true);
        manApi.statusLbl.textContent = dry ? 'Planning (dry run)...' : 'Uninstalling...'; manApi.statusLbl.className = 'st-info';
        log.banner('TARGETED UNINSTALL (DryRun=' + dry + ')');
        var counts = { ok: 0, warn: 0, fail: 0, skipped: 0, unreach: 0, error: 0 };
        manRun = ctx.run('manual-uninstall', manParams({ threads: threadCount(), dryrun: dry, selecthosts: selHosts, selectkeys: selKeys }), { keyOf: keyByRk });
        bindManualUninstall(manRun, counts, dry);
      }

      function bindManualScan(runHandle, counts) {
        var grid = manApi.grid, prog = manApi.prog;
        if (manUnsub) manUnsub();
        manUnsub = runHandle.subscribe({
          status: function (t) { prog.setPhase(t); log.append({ text: t, level: 'gold' }); },
          progress: function (p) { prog.setProgress(p.done, p.total); },
          row: function (r) { grid.upsert(r); manTallyScan(r, counts); logScanRow(log, r); },
          log: function (l) { log.append(l); },
          error: function (e) { log.append({ text: e.text, level: 'err' }); },
          final: function () {
            grid.selectWhere(isProvenRow);
            var msg = 'Targeted scan complete: ' + counts.match + ' match (pre-checked), ' + counts.protectedC + ' protected, ' + counts.nomatch + ' no-match, ' + counts.unreach + ' unreachable, ' + counts.error + ' error.';
            log.banner(msg);
            manApi.statusLbl.textContent = counts.match + ' match(es) pre-checked'; manApi.statusLbl.className = counts.match ? 'st-ok' : 'st-warn';
          },
          active: function (a) { lockManualButtons(a); if (!a) manRefreshButtons(); }
        });
      }
      function manTallyScan(r, c) {
        switch (String(r.Decision)) {
          case 'Uninstall': c.match++; break;
          case 'Skipped (protected)': c.protectedC++; break;
          case 'Skipped (Tanium)': c.protectedC++; break;
          case 'Unreachable': c.unreach++; break;
          case 'Error': c.error++; break;
          case 'No match': c.nomatch++; break;
        }
      }
      function bindManualUninstall(runHandle, counts, dry) {
        var grid = manApi.grid, prog = manApi.prog;
        if (manUnsub) manUnsub();
        manUnsub = runHandle.subscribe({
          status: function (t) { prog.setPhase(t); log.append({ text: t, level: 'gold' }); },
          progress: function (p) { prog.setProgress(p.done, p.total); },
          row: function (r) { grid.upsert(r); tallyUninstallRow(r, counts, log); recordHistory(r, dry, 'Targeted'); },
          log: function (l) { log.append(l); },
          error: function (e) { log.append({ text: e.text, level: 'err' }); },
          final: function () {
            var msg = (dry ? 'Plan complete' : 'Uninstall complete') + ': ' + counts.ok + ' OK, ' + counts.warn + ' warn, ' + counts.fail + ' fail, ' + counts.skipped + ' skipped, ' + (counts.unreach + counts.error) + ' unreachable/error.';
            log.banner(msg);
            manApi.statusLbl.textContent = msg; manApi.statusLbl.className = (counts.fail || counts.error) ? 'st-bad' : 'st-ok';
            if (hist) renderHistory();
            ctx.confirm({
              title: dry ? 'Dry run complete' : 'Uninstall complete',
              body: 'OK: <b>' + counts.ok + '</b><br>Warn: <b>' + counts.warn + '</b><br>Fail: <b>' + counts.fail + '</b><br>Skipped: <b>' + counts.skipped + '</b><br>Unreachable / error: <b>' + (counts.unreach + counts.error) + '</b>',
              okText: 'OK', cancelText: null
            });
          },
          active: function (a) { lockManualButtons(a); if (!a) manRefreshButtons(); }
        });
      }
      function manExport(grid) {
        var rows = grid.rows();
        if (!rows.length) { ctx.confirm({ title: 'Nothing to export', body: 'Scan first - there are no rows.', okText: 'OK', cancelText: null }); return; }
        var cols = ['Host', 'Product', 'Publisher', 'Type', 'Version', 'Decision', 'Result'];
        var labelRow = ['Host', 'Display Name', 'Publisher', 'Type', 'Version', 'Decision', 'Result'];
        var data = rows.map(function (r) {
          return cols.map(function (c) {
            if (c === 'Result') { var v = (r.Result != null && r.Result !== '') ? r.Result : (r.Detail != null ? r.Detail : ''); return v == null ? '' : v; }
            return r[c] == null ? '' : r[c];
          });
        });
        ctx.util.downloadXlsx('UPR_Targeted_' + ctx.util.fileStamp() + '.xlsx', labelRow, data, 'Targeted');
      }

      // ===================================================================
      //  TAB 3 - OS Findings  (os-findings, read-only, one row per host)
      // ===================================================================
      function buildOsTab(panel) {
        panel.style.cssText = 'display:flex;flex-direction:column;height:100%;min-height:0;gap:8px';
        panel.appendChild(secHdr('UNSUPPORTED OPERATING SYSTEMS (read-only)'));
        panel.appendChild(hint('Out of scope for this tool. Export and hand the list to whoever runs OS rebuilds. One row per affected host.'));

        var bar = el('div'); bar.style.cssText = 'display:flex;align-items:center;gap:10px;flex-wrap:wrap';
        var refreshBtn = ui.button('Refresh', { variant: 'cyan', size: 'sm', title: 'Re-parse the loaded report for OS findings.' });
        var exportBtn = ui.ghostButton('Export CSV', { size: 'sm' }); exportBtn.disabled = true;
        var copyBtn = ui.ghostButton('Copy to Clipboard', { size: 'sm' }); copyBtn.disabled = true;
        var osCount = el('span', 'muted'); osCount.style.cssText = 'font-family:var(--mono);font-size:12px;margin-left:auto';
        bar.appendChild(refreshBtn); bar.appendChild(exportBtn); bar.appendChild(copyBtn); bar.appendChild(osCount);
        panel.appendChild(bar);

        var grid = C.ResultsGrid({
          title: 'OS findings', keyMode: { rk: true }, popOut: true,
          columns: [
            { key: 'Plugin', label: 'PLUGIN', width: 75 },
            { key: 'PluginName', label: 'FINDING' },
            { key: 'Severity', label: 'SEVERITY', width: 90, colorRule: sevCls },
            { key: 'IP', label: 'IP', width: 120 },
            { key: 'NetBIOS', label: 'NETBIOS', width: 130 },
            { key: 'DNS', label: 'DNS', width: 170 },
            { key: 'OS CPE', label: 'OS CPE', width: 180 },
            { key: 'MAC', label: 'MAC', width: 130 }
          ]
        });
        var holder = el('div'); holder.style.cssText = 'flex:1;min-height:0;display:flex'; holder.appendChild(grid.el);
        panel.appendChild(holder);

        refreshBtn.onclick = function () { if (needReport(true)) runOsFindings(); };
        exportBtn.onclick = function () {
          var rows = grid.rows();
          if (!rows.length) return;
          var labels = ['Plugin', 'Finding', 'Severity', 'IP', 'NetBIOS', 'DNS', 'OS CPE', 'MAC'];
          var keys = ['Plugin', 'PluginName', 'Severity', 'IP', 'NetBIOS', 'DNS', 'OS CPE', 'MAC'];
          var data = rows.map(function (r) { return keys.map(function (k) { return r[k] == null ? '' : r[k]; }); });
          ctx.util.downloadXlsx('UPR_OS_Findings_' + ctx.util.fileStamp() + '.xlsx', labels, data, 'OS Findings');
        };
        copyBtn.onclick = function () {
          var rows = grid.rows();
          if (!rows.length) return;
          var keys = ['Plugin', 'PluginName', 'Severity', 'IP', 'NetBIOS', 'DNS', 'OS CPE', 'MAC'];
          var text = [keys.join('\t')].concat(rows.map(function (r) { return keys.map(function (k) { return r[k] == null ? '' : String(r[k]); }).join('\t'); })).join('\r\n');
          if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).catch(function () {});
          osCount.textContent = 'Copied ' + rows.length + ' row(s) to clipboard.'; osCount.className = 'st-ok';
        };

        osApi = { grid: grid, osCount: osCount, exportBtn: exportBtn, copyBtn: copyBtn };
        if (reportPath) runOsFindings();
      }

      function runOsFindings() {
        if (!osApi || !reportPath) return;
        if (osRun && osRun.state && osRun.state.active) return;
        osApi.grid.clear();
        osApi.osCount.textContent = 'Parsing OS findings...'; osApi.osCount.className = 'muted';
        osApi.exportBtn.disabled = true; osApi.copyBtn.disabled = true;
        var n = 0;
        osRun = ctx.run('os-findings', reportParams({ hostclass: hostClass() }), { keyOf: keyByRk });
        if (osUnsub) osUnsub();
        osUnsub = osRun.subscribe({
          reset: function () { n = 0; },
          row: function (r) { n++; osApi.grid.upsert(r); },
          error: function (e) { osApi.osCount.textContent = e.text; osApi.osCount.className = 'st-bad'; },
          final: function () {
            osApi.osCount.textContent = n + ' OS host row(s)  |  host class: ' + hostClass();
            osApi.osCount.className = n ? 'st-ok' : 'st-warn';
            osApi.exportBtn.disabled = !n; osApi.copyBtn.disabled = !n;
          }
        });
      }

      // ===================================================================
      //  TAB 4 - History  (in-session uninstall outcomes, last 200)
      // ===================================================================
      function buildHistoryTab(panel) {
        panel.style.cssText = 'display:flex;flex-direction:column;height:100%;min-height:0;gap:8px';
        panel.appendChild(secHdr('SESSION HISTORY (last 200)'));
        panel.appendChild(hint('Every uninstall outcome from this session. Audit log: ' + (ctx.session.state.logRoot || '(local)')));

        var bar = el('div'); bar.style.cssText = 'display:flex;align-items:center;gap:10px;flex-wrap:wrap';
        var clearBtn = ui.ghostButton('Clear Grid', { size: 'sm' });
        var exportBtn = ui.button('Export CSV', { variant: 'cyan', size: 'sm' });
        var hcount = el('span', 'muted'); hcount.style.cssText = 'font-family:var(--mono);font-size:12px;margin-left:auto';
        bar.appendChild(clearBtn); bar.appendChild(exportBtn); bar.appendChild(hcount);
        panel.appendChild(bar);

        var grid = C.ResultsGrid({
          title: 'History', keyMode: function (r) { return r._hk; }, popOut: true,
          columns: [
            { key: 'When', label: 'WHEN', width: 160 },
            { key: 'Host', label: 'HOST', width: 150 },
            { key: 'Action', label: 'ACTION', width: 150 },
            { key: 'Item', label: 'ITEM' },
            { key: 'Result', label: 'RESULT', width: 200, colorRule: resultCls }
          ]
        });
        var holder = el('div'); holder.style.cssText = 'flex:1;min-height:0;display:flex'; holder.appendChild(grid.el);
        panel.appendChild(holder);

        clearBtn.onclick = function () { historyRows = []; grid.clear(); hcount.textContent = '0 row(s)'; };
        exportBtn.onclick = function () {
          if (!historyRows.length) { ctx.confirm({ title: 'Nothing to export', body: 'No history rows yet - run an uninstall first.', okText: 'OK', cancelText: null }); return; }
          var labels = ['When', 'Host', 'Action', 'Item', 'Result'];
          var data = historyRows.map(function (r) { return labels.map(function (k) { return r[k] == null ? '' : r[k]; }); });
          ctx.util.downloadXlsx('UPR_History_' + ctx.util.fileStamp() + '.xlsx', labels, data, 'History');
        };

        hist = { grid: grid, hcount: hcount };
        renderHistory();
      }
      function renderHistory() {
        if (!hist) return;
        hist.grid.clear();
        historyRows.forEach(function (r, i) { var row = {}; Object.keys(r).forEach(function (k) { row[k] = r[k]; }); row._hk = 'h' + i; hist.grid.upsert(row); });
        hist.hcount.textContent = historyRows.length + ' row(s)';
        hist.hcount.className = historyRows.length ? 'st-ok' : 'muted';
      }

      host.appendChild(root);
      this._root = root;
      this._unsub = function () {
        if (scanUnsub) try { scanUnsub(); } catch (e) {}
        if (findUnsub) try { findUnsub(); } catch (e) {}
        if (osUnsub) try { osUnsub(); } catch (e) {}
        if (manUnsub) try { manUnsub(); } catch (e) {}
      };
    },
    unmount: function () { try { if (this._unsub) this._unsub(); } catch (e) {} if (this._root) this._root.remove(); }
  });
})();
