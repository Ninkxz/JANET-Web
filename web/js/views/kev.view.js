/* ============================================================================
   kev.view.js  -  KEV Cross-Check (tool id: 'kev')
   Cross-references a machine's ARAD / ACAS CVE export against the CISA Known
   Exploited Vulnerabilities (KEV) catalog that ships inside JANET
   (JanetLocal\KevCatalog.txt). Two tabs:
     1. Cross-Reference - paste/import the machine export, flag every CVE that is
        ALSO on the KEV list (present AND known-exploited). Double-click any CVE
        to open Google / NVD / CVE.org / CISA KEV / IAVM lookups.
     2. KEV Catalog     - view the current KEV list and add new CVEs (persisted
        to the text file).
   All server I/O via ctx.run -> RunController. No hosts touched, no credentials
   needed (purely local data work).
   ========================================================================== */
(function () {
  'use strict';

  // CVE lookup destinations. Each opens in a new browser tab. Add more here.
  var LOOKUPS = [
    { label: 'Google',      url: function (c) { return 'https://www.google.com/search?q=' + encodeURIComponent(c); } },
    { label: 'NVD',         url: function (c) { return 'https://nvd.nist.gov/vuln/detail/' + encodeURIComponent(c); } },
    { label: 'CVE.org',     url: function (c) { return 'https://www.cve.org/CVERecord?id=' + encodeURIComponent(c); } },
    { label: 'CISA KEV',    url: function (c) { return 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=' + encodeURIComponent(c); } },
    { label: 'IAVM search', url: function (c) { return 'https://www.google.com/search?q=' + encodeURIComponent(c + ' IAVM'); } }
  ];

  var CVE_RE = /^CVE-\d{4}-\d{4,}$/i;

  // Escape operator-typed text before it goes into a confirm dialog's HTML body.
  // audit#25: use the single shared escaper (which also escapes ' -> &#39;) instead
  // of a divergent local copy that missed the apostrophe. One esc, one behavior.
  var esc = Janet.util.esc;

  // Catalog freshness, rendered from the summary the engine now ships (audit
  // 2026-07-24). A months-old snapshot used to be invisible in the UI, so a green
  // "nothing on KEV" result looked authoritative when it was merely old. Age is
  // always shown; past the engine's staleness threshold (summary.stale) it is
  // shown as a warning, because "no overlap" then means "nothing known as of then".
  function catAgeText(s) {
    if (!s || !s.updated) return 'age unknown';
    var d = (s.ageDays == null || s.ageDays < 0) ? null : s.ageDays;
    var when = 'updated ' + s.updated;
    if (d == null) return when;
    if (d === 0) return when + ' (today)';
    return when + ' (' + d + ' day' + (d === 1 ? '' : 's') + ' old)';
  }
  function catAgeCls(s) { return (s && s.stale) ? 'st-warn' : 'muted'; }

  // add-kev streams one { CVE, Status } row per input token; map the status to a log
  // level so the per-CVE outcome is visible instead of collapsing into the counts.
  function addStatusLevel(st) {
    var s = String(st == null ? '' : st).toLowerCase();
    if (s.indexOf('added') === 0) return 'ok';
    if (s.indexOf('invalid') === 0) return 'err';
    return 'warn';
  }

  function sevCls(v) {
    var s = String(v == null ? '' : v).toLowerCase();
    if (s.indexOf('crit') === 0) return 'st-bad';
    if (s.indexOf('high') === 0) return 'st-warn';
    if (s.indexOf('med') === 0) return 'st-info';
    if (s.indexOf('low') === 0) return 'cell-dim';
    return '';
  }

  JanetViews.register('kev', {
    mount: function (host, ctx) {
      var ui = ctx.ui, C = ctx.components, el = ctx.util.el;
      var subs = [];                 // run-handle unsubscribers, torn down on unmount
      function track(u) { if (u) subs.push(u); }

      // ---- shared: CVE lookup dialog (double-click a CVE row) ----------------
      function openLookup(cve) {
        cve = String(cve || '').toUpperCase();
        var body = el('div');
        var info = el('div', 'muted', cve + ' - open this CVE in:'); info.style.marginBottom = '10px';
        body.appendChild(info);
        var bar = el('div'); bar.style.cssText = 'display:flex;flex-wrap:wrap;gap:8px';
        LOOKUPS.forEach(function (L) {
          var url = L.url(cve);
          bar.appendChild(ui.button(L.label, { variant: 'cyan', size: 'sm', title: url, onClick: function () { window.open(url, '_blank', 'noopener'); } }));
        });
        body.appendChild(bar);
        var foot = el('div'); foot.style.cssText = 'margin-top:12px';
        foot.appendChild(ui.ghostButton('Copy CVE', { size: 'sm', onClick: function () { try { navigator.clipboard.writeText(cve); } catch (e) {} } }));
        body.appendChild(foot);
        C.ConfirmDialog({ title: 'Lookup ' + cve, body: body, okText: 'Close', cancelText: null });
      }

      // ---- shared activity log (one dock, both tabs log here) ----------------
      var actlog = C.ActivityLog({ title: 'ACTIVITY LOG', defaultName: 'KevCrossCheck' });

      // =====================================================================
      //  TAB 1 - Cross-Reference
      // =====================================================================
      function buildXrefTab(panel) {
        panel.style.cssText = 'display:flex;gap:14px;height:100%;min-height:0;box-sizing:border-box;padding:12px';

        // LEFT: machine CVE export input
        var left = ui.namedCard('MACHINE CVE EXPORT', 'Paste the ARAD / ACAS export (CSV) - or import a file. The CVE column is auto-detected.');
        left.style.cssText += ';flex:0 0 360px;display:flex;flex-direction:column;min-height:0;gap:10px';
        var aradInput = ui.textarea({ value: '', placeholder: 'Check ID,CVE Year,Severity (CVSS v3),Score (CVSS v3)\nCVE-2019-11634,2019,Critical,9.8\n...\n\n(or just a list of CVE IDs)', rows: 10 });
        aradInput.style.cssText += ';flex:1;min-height:140px;font-family:Consolas,monospace;font-size:12px';
        var aradHolder = el('div'); aradHolder.style.cssText = 'flex:1;min-height:140px;display:flex'; aradHolder.appendChild(aradInput);
        left.appendChild(aradHolder);

        var inBar = el('div'); inBar.style.cssText = 'display:flex;gap:8px;align-items:center;flex-wrap:wrap';
        var importBtn = ui.button('Import CSV', { variant: 'cyan', size: 'sm', title: 'Load the ARAD/ACAS export from a .csv/.txt file.' });
        var clearInBtn = ui.ghostButton('Clear', { size: 'sm', onClick: function () { aradInput.value = ''; updCount(); } });
        var inCount = el('span', 'muted', '0 CVE(s) detected'); inCount.style.fontSize = '11.5px';
        inBar.appendChild(importBtn); inBar.appendChild(clearInBtn); inBar.appendChild(inCount);
        left.appendChild(inBar);

        var kevLine = el('div', 'muted', 'KEV catalog: loading...'); kevLine.style.fontSize = '11.5px';
        left.appendChild(kevLine);

        importBtn.onclick = function () {
          var fi = el('input'); fi.type = 'file'; fi.accept = '.csv,.txt,text/csv,text/plain'; fi.style.display = 'none';
          document.body.appendChild(fi);
          fi.onchange = function () {
            var f = fi.files && fi.files[0]; document.body.removeChild(fi); if (!f) return;
            var reader = new FileReader();
            reader.onload = function () { aradInput.value = String(reader.result || ''); updCount(); actlog.append({ text: 'Imported ' + f.name, level: 'ok' }); };
            reader.readAsText(f);
          };
          fi.click();
        };
        function detectedCves() {
          var m = String(aradInput.value || '').toUpperCase().match(/CVE-\d{4}-\d{4,}/g) || [];
          var seen = {}, out = []; m.forEach(function (c) { if (!seen[c]) { seen[c] = 1; out.push(c); } });
          return out;
        }
        function updCount() { inCount.textContent = detectedCves().length + ' CVE(s) detected'; }
        aradInput.addEventListener('input', updCount);

        panel.appendChild(left);

        // RIGHT column
        var right = el('div'); right.style.cssText = 'flex:1;min-width:0;display:flex;flex-direction:column;gap:12px;min-height:0';

        var stats = C.StatCards({ cards: [
          { key: 'total', label: 'MACHINE CVEs', color: 'cyan' },
          { key: 'kev',   label: 'ON KEV (KNOWN EXPLOITED)', color: 'bad' },
          { key: 'clean', label: 'NOT ON KEV', color: 'accent' }
        ] });
        right.appendChild(stats.el);

        var actionCard = ui.card({}); actionCard.style.cssText += ';display:flex;align-items:center;gap:14px;flex-wrap:wrap';
        var statusLine = el('span', 'muted', 'Ready'); statusLine.style.minWidth = '160px';
        actionCard.appendChild(statusLine);
        var spacer = el('div'); spacer.style.flex = '1'; actionCard.appendChild(spacer);
        var exportBtn = ui.ghostButton('Export CSV', { size: 'sm', title: 'Export the result rows to CSV.' });
        var clearBtn = ui.button('Clear', { variant: 'danger', size: 'sm', title: 'Clear the results grid.' });
        var ctaHolder = el('div'); ctaHolder.style.width = '230px';
        var runbar = C.RunBar({
          label: 'CROSS-REFERENCE', morphToCancel: false,
          title: 'Flag every machine CVE that is also on the CISA KEV catalog.',
          guards: [ function () { return aradInput.value && aradInput.value.trim() ? null : 'Input Required|Paste or import the machine ARAD/ACAS CVE export first.'; } ],
          onGuardFail: function (m) { var p = m.split('|'); ctx.confirm({ title: p[0], body: p[1] || p[0], okText: 'OK', cancelText: null }); },
          onRun: doXref
        });
        ctaHolder.appendChild(runbar.el);
        actionCard.appendChild(exportBtn); actionCard.appendChild(clearBtn); actionCard.appendChild(ctaHolder);
        right.appendChild(actionCard);

        var results = ui.namedCard('RESULTS', 'Rows in red are on the KEV list (known-exploited AND present on this machine). Double-click any CVE for lookup links.');
        results.style.cssText += ';flex:1;min-height:0;display:flex;flex-direction:column';
        var grid = C.ResultsGrid({
          title: 'KEV cross-reference', emptyText: 'No cross-reference yet — paste or import a machine CVE export, then Cross-Reference.', keyMode: { rk: true }, popOut: true,
          onRowClick: function (r) { openLookup(r.CVE); },
          columns: [
            { key: 'CVE', label: 'CVE', width: 150, render: function (r) { return { text: String(r.CVE || ''), cls: 'st-info', title: 'Double-click for lookup links' }; } },
            { key: 'Year', label: 'YEAR', width: 70 },
            { key: 'Severity', label: 'SEVERITY', width: 100, render: function (r) { return { text: String(r.Severity == null ? '' : r.Severity), cls: sevCls(r.Severity) }; } },
            { key: 'Score', label: 'SCORE', width: 75 },
            // audit 2026-07-24: the manifest has always declared IAVA and the engine has
            // always emitted it - the grid just never rendered it, so the IAVA/bulletin
            // badge the operator needs for the ticket was invisible.
            { key: 'IAVA', label: 'IAVA', width: 130, render: function (r) { var v = String(r.IAVA == null ? '' : r.IAVA); return { text: v, cls: v ? 'st-warn' : 'cell-dim' }; } },
            { key: 'InKEV', label: 'ON KEV?', width: 120, render: function (r) { var on = r.InKEV === 'Listed (KEV)'; return { text: String(r.InKEV || ''), cls: on ? 'st-bad' : 'cell-dim' }; } }
          ],
          rowClass: function (r) { return r.InKEV === 'Listed (KEV)' ? 'row-bad' : ''; }
        });
        var gridHolder = el('div'); gridHolder.style.cssText = 'flex:1;min-height:0;display:flex'; gridHolder.appendChild(grid.el);
        results.appendChild(gridHolder);
        right.appendChild(results);
        panel.appendChild(right);

        // behaviour
        function setStatus(t, cls) { statusLine.textContent = t == null ? '' : String(t); statusLine.className = cls || 'muted'; }
        clearBtn.onclick = function () { if (xrefActive) return; grid.clear(); stats.reset(); setStatus('Ready'); };
        exportBtn.onclick = function () {
          var rows = grid.rows();
          if (!rows.length) { ctx.confirm({ title: 'Nothing to export', body: 'Run a cross-reference first.', okText: 'OK', cancelText: null }); return; }
          var cols = [['CVE', 'CVE'], ['Year', 'Year'], ['Severity', 'Severity'], ['Score', 'Score'], ['IAVA', 'IAVA'], ['InKEV', 'On KEV']];
          ctx.util.exportCsv('KEV_CrossRef', cols, rows);
        };

        var xrefActive = false, xrefRun = null, xrefUnsub = null, liveTotal = 0, liveKev = 0;
        // Authoritative O(N) recount (drift-proof) - used once in final(); the row
        // handler keeps O(1) running counters so the stream stays O(N) not O(N^2).
        function recount() {
          var rows = grid.rows(), kev = 0;
          rows.forEach(function (r) { if (r.InKEV === 'Listed (KEV)') kev++; });
          stats.setAll({ total: rows.length, kev: kev, clean: rows.length - kev });
        }
        function doXref() {
          grid.clear(); stats.reset(); liveTotal = 0; liveKev = 0;
          setStatus('Cross-referencing...', 'st-info');
          xrefRun = ctx.run('xref', { arad: aradInput.value }, { keyOf: function (ev) { return ev._rk; } });
          if (xrefUnsub) xrefUnsub();
          xrefUnsub = xrefRun.subscribe({ /* unsub tracked below for unmount teardown */
            status: function (t) { setStatus(t, 'st-info'); },
            row: function (r) { grid.upsert(r); liveTotal++; if (r.InKEV === 'Listed (KEV)') liveKev++; stats.setAll({ total: liveTotal, kev: liveKev, clean: liveTotal - liveKev }); },
            log: function (l) { actlog.append(l); },
            error: function (e) { setStatus(e.text || 'Error', 'st-bad'); actlog.append({ text: e.text, level: 'err' }); },
            active: function (a) { xrefActive = a; runbar.setActive(a); runbar.cta.textContent = a ? 'WORKING...' : 'CROSS-REFERENCE'; },
            final: function (res) {
              recount();
              var s = (res && res.summary) || {};
              kevLine.textContent = 'KEV catalog: ' + (s.kev == null ? '?' : s.kev) + ' CVE(s) - ' + catAgeText(s);
              kevLine.className = catAgeCls(s);
              // audit 2026-07-24: no usable catalog = UNKNOWN, and the engine now sends no
              // rows at all, so the grid/stat cards stay empty rather than reading clean.
              if (s.empty || s.unknown) {
                setStatus('KEV catalog is ' + (s.unreadable ? 'UNREADABLE' : 'EMPTY') + ' - result is UNKNOWN, not clean. Nothing was cross-referenced. Populate/restore it on the KEV Catalog tab, then re-run.', 'st-bad');
                return;
              }
              var ov = s.overlap || 0;
              if (ov === 0 && s.stale) {
                setStatus('No KEV overlap in ' + (s.total || 0) + ' CVE(s) - but the catalog is ' + catAgeText(s) + '. NOT an all-clear.', 'st-warn');
                return;
              }
              setStatus('Done - ' + ov + ' of ' + (s.total || 0) + ' machine CVE(s) on the KEV list.', ov > 0 ? 'st-warn' : 'st-ok');
            }
          });
          track(xrefUnsub);
        }

        // populate the KEV count up-front (silent list-kev)
        var lr = ctx.run('list-kev', {}, { keyOf: function (ev) { return ev._rk; } });
        var n = 0;
        track(lr.subscribe({ row: function () { n++; }, final: function (res) {
          var s = (res && res.summary) || {};
          var c = (s.total != null) ? s.total : n;
          // Age up front, before the operator even runs a cross-reference (audit 2026-07-24).
          kevLine.textContent = 'KEV catalog: ' + c + ' CVE(s), ' + catAgeText(s) + (s.stale ? ' - STALE, refresh it' : '') + ' (JanetLocal\\KevCatalog.txt)';
          kevLine.className = catAgeCls(s);
        } }));

        updCount();
      }

      // =====================================================================
      //  TAB 2 - KEV Catalog (view + add)
      // =====================================================================
      function buildCatalogTab(panel) {
        panel.style.cssText = 'display:flex;gap:14px;height:100%;min-height:0;box-sizing:border-box;padding:12px';

        // LEFT: add CVEs
        var left = ui.namedCard('ADD TO KEV', 'Add CVE(s) the catalog is missing. Saved to JanetLocal\\KevCatalog.txt and shipped in take-to-work.');
        left.style.cssText += ';flex:0 0 360px;display:flex;flex-direction:column;min-height:0;gap:10px';
        var addInput = ui.textarea({ value: '', placeholder: 'CVE-2025-12345\nCVE-2025-23456\n\n(one per line, or comma/space separated)', rows: 8 });
        addInput.style.cssText += ';flex:1;min-height:120px;font-family:Consolas,monospace;font-size:12px';
        var addHolder = el('div'); addHolder.style.cssText = 'flex:1;min-height:120px;display:flex'; addHolder.appendChild(addInput);
        left.appendChild(addHolder);
        var addBar = el('div'); addBar.style.cssText = 'display:flex;gap:8px;align-items:center;flex-wrap:wrap';
        var addBtn = ui.button('Add to KEV', { variant: 'go', size: 'sm', title: 'Validate, de-dupe, and save to the KEV catalog file.' });
        var addStatus = el('span', 'muted', ''); addStatus.style.fontSize = '11.5px';
        addBar.appendChild(addBtn); addBar.appendChild(addStatus);
        left.appendChild(addBar);
        panel.appendChild(left);

        // RIGHT: current catalog
        var right = el('div'); right.style.cssText = 'flex:1;min-width:0;display:flex;flex-direction:column;gap:12px;min-height:0';
        var head = ui.card({}); head.style.cssText += ';display:flex;align-items:center;gap:12px;flex-wrap:wrap';
        var countLine = el('span', 'muted', 'Loading KEV catalog...'); countLine.style.flex = '1';
        var reloadBtn = ui.ghostButton('Reload', { size: 'sm', title: 'Re-read the KEV catalog from disk.' });
        head.appendChild(countLine); head.appendChild(reloadBtn);
        right.appendChild(head);

        var results = ui.namedCard('KEV CATALOG', 'Every CVE on the KEV list. Double-click any CVE for lookup links.');
        results.style.cssText += ';flex:1;min-height:0;display:flex;flex-direction:column';
        var grid = C.ResultsGrid({
          title: 'KEV catalog', emptyText: 'Catalog not loaded — click List KEV, or Add to KEV to create it.', keyMode: { rk: true }, popOut: true, selectable: false,
          onRowClick: function (r) { openLookup(r.CVE); },
          columns: [
            { key: 'CVE', label: 'CVE', width: 170, render: function (r) { return { text: String(r.CVE || ''), cls: 'st-info', title: 'Double-click for lookup links' }; } },
            { key: 'Year', label: 'YEAR', width: 80 }
          ]
        });
        var gridHolder = el('div'); gridHolder.style.cssText = 'flex:1;min-height:0;display:flex'; gridHolder.appendChild(grid.el);
        results.appendChild(gridHolder);
        right.appendChild(results);
        panel.appendChild(right);

        var catUnsub = null, addUnsub = null;
        function loadCatalog() {
          grid.clear(); countLine.textContent = 'Loading KEV catalog...';
          var lr = ctx.run('list-kev', {}, { keyOf: function (ev) { return ev._rk; } });
          var n = 0;
          if (catUnsub) catUnsub();   // replace, don't stack, on Reload / post-add refresh
          catUnsub = lr.subscribe({
            row: function (r) { grid.upsert(r); n++; },
            log: function (l) { actlog.append(l); },
            final: function (res) {
              var s = (res && res.summary) || {};
              var c = (s.total != null) ? s.total : n;
              // audit 2026-07-24: surface the snapshot's vintage next to the count - the
              // count alone says nothing about whether the list is current.
              countLine.textContent = c + ' CVE(s) in the KEV catalog - ' + catAgeText(s) + (s.stale ? ' - STALE, refresh it' : '') + ' - JanetLocal\\KevCatalog.txt';
              countLine.className = catAgeCls(s);
            }
          });
          track(catUnsub);
        }
        reloadBtn.onclick = loadCatalog;

        addBtn.onclick = async function () {
          var raw = String(addInput.value || '');
          var toks = raw.split(/[\r\n,;\t ]+/).map(function (t) { return t.trim(); }).filter(Boolean);
          if (!toks.length) { ctx.confirm({ title: 'Nothing to add', body: 'Enter at least one CVE.', okText: 'OK', cancelText: null }); return; }
          var valid = toks.filter(function (t) { return CVE_RE.test(t); });
          var bad = toks.filter(function (t) { return !CVE_RE.test(t); });
          var msg = 'Add ' + valid.length + ' CVE(s) to the KEV catalog file (JanetLocal\\KevCatalog.txt)?';
          if (bad.length) { msg += '<br><br><span class="st-warn">' + bad.length + ' entr(y/ies) are not valid CVE IDs and will be skipped:</span><br>' + bad.slice(0, 8).map(esc).join(', '); }
          var ok = await ctx.confirm({ title: 'Add to KEV', body: msg, list: valid.slice(0, 12), okText: 'Add', cancelText: 'Cancel' });
          if (!ok) return;
          addStatus.textContent = 'Saving...'; addStatus.className = 'st-info'; addBtn.disabled = true;
          var ar = ctx.run('add-kev', { cves: raw }, { keyOf: function (ev) { return ev._rk; } });
          if (addUnsub) addUnsub();   // replace, don't stack, on repeated adds
          addUnsub = ar.subscribe({
            // audit 2026-07-24: add-kev streams one { CVE, Status } row per token and the
            // view used to drop them all, so "Already in KEV" / "Invalid format" collapsed
            // into a bare count and the operator could not tell WHICH CVE was rejected.
            row: function (r) { actlog.append({ text: String(r.CVE || '') + ' - ' + String(r.Status || ''), level: addStatusLevel(r.Status) }); },
            log: function (l) { actlog.append(l); },
            error: function (e) { addStatus.textContent = e.text || 'Save error'; addStatus.className = 'st-bad'; },
            active: function (a) { addBtn.disabled = a; },
            final: function (res) {
              var s = (res && res.summary) || {};
              if (s.saveError) { addStatus.textContent = 'Save FAILED - catalog unchanged.'; addStatus.className = 'st-bad'; return; }
              // audit 2026-07-25 (fable re-audit follow-up): add-kev reports the catalog's
              // vintage like list-kev / xref do - and it is the PRE-ADD vintage, because
              // writing the file resets its timestamp without refreshing the CISA snapshot.
              addStatus.textContent = 'Added ' + (s.added || 0) + ', skipped ' + (s.duplicate || 0) + ' dup, ' + (s.invalid || 0) + ' invalid'
                + (s.updated ? ' - snapshot before this add: ' + catAgeText(s) + (s.stale ? ' (STALE)' : '') : '') + '.';
              addStatus.className = (s.added > 0) ? 'st-ok' : 'st-warn';
              if (s.added > 0) { addInput.value = ''; loadCatalog(); }
            }
          });
          track(addUnsub);
        };

        loadCatalog();
      }

      // ---- assemble: TabHost + bottom activity dock ----------------------------
      var root = el('div'); root.style.cssText = 'display:flex;flex-direction:column;gap:12px;height:100%;min-height:0;padding:14px;box-sizing:border-box';
      var tabHolder = el('div'); tabHolder.style.cssText = 'flex:1;min-height:0;display:flex';
      var tabs = C.TabHost({
        rail: 'top',
        // audit 2026-07-25: without helpId the per-tab help blurbs never swap into the purple
        // HOW TO USE box (tabhost.js:82) - only the _overview shows. The keys exist in
        // help-content.js keyed to these tab ids.
        helpId: 'kev',
        tabs: [
          { id: 'xref', label: 'Cross-Reference', build: buildXrefTab },
          { id: 'catalog', label: 'KEV Catalog', build: buildCatalogTab }
        ]
      });
      tabHolder.appendChild(tabs.el);
      root.appendChild(tabHolder);

      var logCard = ui.card({}); logCard.classList.add('j-logdock');
      logCard.appendChild(actlog.el);
      root.appendChild(logCard);

      host.appendChild(root);
      this._root = root;
      this._unsub = function () { subs.forEach(function (u) { try { u(); } catch (e) {} }); };
    }
  });
})();
