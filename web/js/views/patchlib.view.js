/* ============================================================================
   patchlib.view.js  -  Patch Content (tool id: 'patchlib')
   Offline patch-content library. Two tabs:
     1. Inventory       - scan the content roots (repo .\Packages, the work share
                          when reachable, plus an optional extra folder) and list
                          every staged item (PSADT / MSI / MSU / CAB / EXE / other)
                          with its parsed KB id, size and date.
     2. Cross-Reference - paste needed KBs / product names and/or import an ACAS
                          CSV, then mark each ON HAND (staged content matches),
                          MISSING, or UNKNOWN (a content root could not be scanned,
                          so absence is UNPROVEN - never read it as MISSING).
                          Stat cards: needed / on hand / missing / unknown / coverage.
   Read-only: no hosts touched, no credentials needed (purely local file work).
   All server I/O via ctx.run -> RunController. The ACAS CSV is uploaded via
   ctx.uploadFile and only its server path is passed to the engine (acas idiom).
   Credentials are UNIVERSAL (shell header) - this view renders NO cred control.
   ========================================================================== */
(function () {
  'use strict';

  // Colour a content-type cell. Installers cyan; PSADT green; the rest dim.
  function typeCls(v) {
    switch (String(v == null ? '' : v)) {
      case 'PSADT': return 'st-ok';
      case 'MSI':
      case 'MSU':
      case 'CAB': return 'st-info';
      case 'EXE': return 'st-warn';
      default: return 'cell-dim';
    }
  }
  function statusCls(v) {
    var s = String(v == null ? '' : v);
    if (s === 'ON HAND') return 'st-ok';
    if (s === 'MISSING') return 'st-bad';
    // audit 2026-07-24: UNKNOWN = a content root was never scanned, so this run
    // proved NOTHING about the item. Amber, deliberately distinct from the red
    // certainty of MISSING - "I did not look there" is not "it is not there".
    if (s === 'UNKNOWN') return 'st-warn';
    return '';
  }
  function locCls(v) {
    var s = String(v == null ? '' : v);
    if (s === 'Local') return 'st-info';
    if (s === 'Share') return 'st-ok';
    if (s === 'Extra') return 'st-warn';
    return 'cell-dim';
  }

  JanetViews.register('patchlib', {
    mount: function (host, ctx) {
      var ui = ctx.ui, C = ctx.components, el = ctx.util.el;
      var subs = [];                 // run-handle unsubscribers, torn down on unmount
      function track(u) { if (u) subs.push(u); }
      function ts() { return ctx.util.clockStr(); }

      // ---- shared activity log (one dock, both tabs log here) ----------------
      var actlog = C.ActivityLog({ title: 'ACTIVITY LOG', defaultName: 'PatchContent' });

      // =====================================================================
      //  TAB 1 - Inventory
      // =====================================================================
      function buildInventoryTab(panel) {
        panel.style.cssText = 'display:flex;gap:14px;height:100%;min-height:0;box-sizing:border-box;padding:12px';

        // LEFT: what-this-scans + extra path + run
        var left = ui.namedCard('CONTENT ROOTS', 'Scans the repo .\\Packages folder, the work share \\\\dm-tn-01\\...\\JANET\\Packages when its host answers on 445, and any extra folder you name below.');
        left.style.cssText += ';flex:0 0 360px;display:flex;flex-direction:column;min-height:0;gap:10px';

        var rootsList = el('div'); rootsList.style.cssText = 'font-size:12px;line-height:1.5;color:var(--text)';
        var b1 = el('div'); b1.innerHTML = '<b>Local</b> - repo .\\Packages (always)';
        var b2 = el('div'); b2.innerHTML = '<b>Share</b> - work share (445-gated)';
        var b3 = el('div'); b3.innerHTML = '<b>Extra</b> - the folder below (optional)';
        rootsList.appendChild(b1); rootsList.appendChild(b2); rootsList.appendChild(b3);
        left.appendChild(rootsList);

        left.appendChild(ui.label('Extra content folder (optional):'));
        var extraInput = ui.input({ type: 'text', placeholder: '\\\\server\\share\\Packages  or  D:\\Staged', title: 'An additional UNC or local folder to include in the scan.' });
        left.appendChild(extraInput);

        var runHolder = el('div'); runHolder.style.cssText = 'margin-top:4px';
        var invStatus = el('span', 'muted', 'Ready'); invStatus.style.cssText = 'display:block;font-size:11.5px;margin-top:8px';
        var runbar = C.RunBar({
          label: 'INVENTORY CONTENT', morphToCancel: false,
          title: 'Scan the content roots and list every staged remediation item.',
          onRun: doInventory
        });
        runHolder.appendChild(runbar.el);
        left.appendChild(runHolder);
        left.appendChild(invStatus);
        panel.appendChild(left);

        // RIGHT: stats + grid
        var right = el('div'); right.style.cssText = 'flex:1;min-width:0;display:flex;flex-direction:column;gap:12px;min-height:0';

        var stats = C.StatCards({ cards: [
          { key: 'total',  label: 'STAGED ITEMS', color: 'cyan' },
          { key: 'psadt',  label: 'PSADT PACKAGES', color: 'ok' },
          { key: 'inst',   label: 'MSI/MSU/CAB/EXE', color: 'accent' },
          { key: 'kbs',    label: 'DISTINCT KB IDs', color: 'gold' }
        ] });
        right.appendChild(stats.el);

        var actionCard = ui.card({}); actionCard.style.cssText += ';display:flex;align-items:center;gap:12px;flex-wrap:wrap';
        var exportBtn = ui.ghostButton('Export CSV', { size: 'sm', title: 'Export the inventory rows to CSV.' });
        var clearBtn = ui.button('Clear', { variant: 'danger', size: 'sm', title: 'Clear the results grid.' });
        var spacer = el('div'); spacer.style.flex = '1';
        actionCard.appendChild(spacer); actionCard.appendChild(exportBtn); actionCard.appendChild(clearBtn);
        right.appendChild(actionCard);

        var results = ui.namedCard('STAGED CONTENT', 'Every item found under the scanned roots, with the KB id parsed from its filename (regex KB nnnnnn+).');
        results.style.cssText += ';flex:1;min-height:0;display:flex;flex-direction:column';
        var grid = C.ResultsGrid({
          title: 'Patch content inventory', keyMode: { rk: true }, popOut: true,
          columns: [
            { key: 'Name', label: 'NAME', width: 250, render: function (r) { var t = String(r.Name || ''); return { text: t, title: t }; } },
            { key: 'ItemType', label: 'TYPE', width: 90, render: function (r) { return { text: String(r.ItemType || ''), cls: typeCls(r.ItemType) }; } },
            { key: 'KB', label: 'KB', width: 120, render: function (r) { var t = String(r.KB || ''); return { text: t, cls: t ? 'st-info' : 'cell-dim', title: t }; } },
            { key: 'Size', label: 'SIZE', width: 90, sortVal: function (r) { return sizeSort(r.Size); } },
            { key: 'Modified', label: 'MODIFIED', width: 130 },
            { key: 'Location', label: 'ROOT', width: 90, render: function (r) { return { text: String(r.Location || ''), cls: locCls(r.Location) }; } }
          ]
        });
        var gridHolder = el('div'); gridHolder.style.cssText = 'flex:1;min-height:0;display:flex'; gridHolder.appendChild(grid.el);
        results.appendChild(gridHolder);
        right.appendChild(results);
        panel.appendChild(right);

        // sort helper: turn "3.2 MB" back into bytes for numeric column sort.
        function sizeSort(s) {
          s = String(s == null ? '' : s).trim().replace(/,/g, '');
          var m = s.match(/^([\d.]+)\s*(B|KB|MB|GB)?$/i);
          if (!m) return -1;
          var n = parseFloat(m[1]) || 0, u = (m[2] || 'B').toUpperCase();
          var mult = u === 'GB' ? 1073741824 : u === 'MB' ? 1048576 : u === 'KB' ? 1024 : 1;
          return n * mult;
        }
        function setStatus(t, cls) { invStatus.textContent = t == null ? '' : String(t); invStatus.className = cls || 'muted'; }

        var invActive = false, invRun = null, invUnsub = null;
        // audit 2026-07-24: every tally is an O(1) counter. cSeen de-dupes by row key
        // so the total stays exact even if a key is ever re-emitted (grid.upsert
        // REPLACES a known key rather than appending, so a naive ++ would drift).
        var cTotal = 0, cInst = 0, cPsadt = 0, cKbCount = 0, cKbSet = null, cSeen = null;
        clearBtn.onclick = function () { if (invActive) return; grid.clear(); stats.reset(); setStatus('Ready'); };
        exportBtn.onclick = function () {
          var rows = grid.rows();
          if (!rows.length) { ctx.confirm({ title: 'Nothing to export', body: 'Run an inventory first.', okText: 'OK', cancelText: null }); return; }
          var cols = [['Name', 'Name'], ['ItemType', 'Type'], ['KB', 'KB'], ['Size', 'Size'], ['Modified', 'Modified'], ['Location', 'Root']];
          ctx.util.exportCsv('PatchContent_Inventory', cols, rows);
        };

        function doInventory() {
          grid.clear(); stats.reset(); cTotal = 0; cInst = 0; cPsadt = 0; cKbCount = 0; cKbSet = {}; cSeen = {};
          setStatus('Scanning content roots...', 'st-info');
          invRun = ctx.run('inventory', { extraPath: extraInput.value || '' }, { keyOf: function (ev) { return ev._rk; } });
          if (invUnsub) invUnsub();
          invUnsub = invRun.subscribe({
            status: function (t) { setStatus(t, 'st-info'); },
            row: function (r) {
              grid.upsert(r);
              // audit 2026-07-24: was grid.rows().length + Object.keys(cKbSet).length
              // PER STREAMED ROW. grid.rows() re-materializes the ENTIRE row array
              // (order.map) and Object.keys walks the whole KB set, so refreshing the
              // stats was O(n) per row - quadratic over an inventory that runs to
              // thousands of staged items on the work share - while cPsadt/cInst sat
              // right beside them already doing it in O(1). Now everything is a counter.
              var k = r._rk == null ? '' : String(r._rk);
              if (Object.prototype.hasOwnProperty.call(cSeen, k)) return;   // already tallied
              cSeen[k] = 1; cTotal++;
              var ty = String(r.ItemType || '');
              if (ty === 'PSADT') cPsadt++;
              if (ty === 'MSI' || ty === 'MSU' || ty === 'CAB' || ty === 'EXE') cInst++;
              // Keys are always 'KB' + digits (the regex guarantees it), so this map
              // can never collide with an Object.prototype name.
              String(r.KB || '').split(/[,\s]+/).forEach(function (t) {
                if (!/^KB\d{6,7}$/i.test(t)) return;
                var u = t.toUpperCase();
                if (cKbSet[u] !== 1) { cKbSet[u] = 1; cKbCount++; }
              });
              stats.setAll({ total: cTotal, psadt: cPsadt, inst: cInst, kbs: cKbCount });
            },
            log: function (l) { actlog.append(l); },
            error: function (e) { setStatus(e.text || 'Error', 'st-bad'); actlog.append({ text: e.text, level: 'err' }); },
            active: function (a) { invActive = a; runbar.setActive(a); runbar.cta.textContent = a ? 'SCANNING...' : 'INVENTORY CONTENT'; },
            final: function (res) {
              var s = (res && res.summary) || {};
              stats.setAll({ total: s.total || cTotal, psadt: s.psadt || cPsadt, inst: (s.msi || 0) + (s.msu || 0) + (s.cab || 0) + (s.exe || 0), kbs: s.distinctKbs == null ? cKbCount : s.distinctKbs });
              setStatus('Done - ' + (s.total || 0) + ' item(s), ' + (s.distinctKbs || 0) + ' KB id(s) on hand.', 'st-ok');
            }
          });
          track(invUnsub);
        }
      }

      // =====================================================================
      //  TAB 2 - Cross-Reference
      // =====================================================================
      function buildCrossrefTab(panel) {
        panel.style.cssText = 'display:flex;gap:14px;height:100%;min-height:0;box-sizing:border-box;padding:12px';

        // LEFT: needed input + CSV import + extra path
        var left = ui.namedCard('NEEDED', 'Paste the KBs / product names you need (one per line), and/or import an ACAS CSV - KB ids are pulled from the plugin / solution / cve columns.');
        left.style.cssText += ';flex:0 0 360px;display:flex;flex-direction:column;min-height:0;gap:10px';
        var neededInput = ui.textarea({ value: '', placeholder: 'KB5034763\n5034441\nGoogle Chrome\nMozilla Firefox\n...', rows: 8 });
        neededInput.style.cssText += ';flex:1;min-height:120px;font-family:Consolas,monospace;font-size:12px';
        var neededHolder = el('div'); neededHolder.style.cssText = 'flex:1;min-height:120px;display:flex'; neededHolder.appendChild(neededInput);
        left.appendChild(neededHolder);

        var csvBar = el('div'); csvBar.style.cssText = 'display:flex;gap:8px;align-items:center;flex-wrap:wrap';
        var importBtn = ui.button('Import ACAS CSV', { variant: 'cyan', size: 'sm', title: 'Upload an ACAS CSV; KB ids are pulled from it and added to the needed list.' });
        var csvClearBtn = ui.ghostButton('Clear CSV', { size: 'sm', onClick: function () { csvPath = ''; csvLine.textContent = 'No CSV imported.'; csvLine.className = 'muted'; } });
        csvBar.appendChild(importBtn); csvBar.appendChild(csvClearBtn);
        left.appendChild(csvBar);
        var csvLine = el('div', 'muted', 'No CSV imported.'); csvLine.style.fontSize = '11.5px';
        left.appendChild(csvLine);

        left.appendChild(ui.label('Extra content folder (optional):'));
        var extraInput = ui.input({ type: 'text', placeholder: '\\\\server\\share\\Packages  or  D:\\Staged', title: 'An additional UNC or local folder to include when checking what is on hand.' });
        left.appendChild(extraInput);

        var xStatus = el('span', 'muted', 'Ready'); xStatus.style.cssText = 'display:block;font-size:11.5px;margin-top:6px';
        var xrunbar = C.RunBar({
          label: 'CROSS-REFERENCE', morphToCancel: false,
          title: 'Mark each needed KB / product ON HAND or MISSING against the staged content.',
          guards: [ function () { return (neededInput.value && neededInput.value.trim()) || csvPath ? null : 'Input Required|Paste at least one needed KB / product name, or import an ACAS CSV.'; } ],
          onGuardFail: function (m) { var p = m.split('|'); ctx.confirm({ title: p[0], body: p[1] || p[0], okText: 'OK', cancelText: null }); },
          onRun: doCrossref
        });
        var xrbHolder = el('div'); xrbHolder.style.cssText = 'margin-top:4px'; xrbHolder.appendChild(xrunbar.el);
        left.appendChild(xrbHolder);
        left.appendChild(xStatus);
        panel.appendChild(left);

        var csvPath = '';
        importBtn.onclick = function () {
          var fi = el('input'); fi.type = 'file'; fi.accept = '.csv,.txt,text/csv,text/plain'; fi.style.display = 'none';
          document.body.appendChild(fi);
          var done = false;
          function cleanup() { if (fi.parentNode) { fi.parentNode.removeChild(fi); } }
          // If the operator cancels the OS file dialog, onchange never fires; remove
          // the orphaned hidden input when focus returns to the window.
          function onFocus() {
            window.removeEventListener('focus', onFocus);
            setTimeout(function () { if (!done) cleanup(); }, 200);
          }
          window.addEventListener('focus', onFocus);
          fi.onchange = function () {
            done = true; window.removeEventListener('focus', onFocus);
            var f = fi.files && fi.files[0]; cleanup(); if (!f) return;
            csvLine.textContent = 'Uploading ' + f.name + '...'; csvLine.className = 'st-info';
            ctx.uploadFile(f).then(function (p) {
              csvPath = p; csvLine.textContent = 'CSV: ' + f.name; csvLine.className = 'st-ok';
              actlog.append({ text: '[' + ts() + '] Uploaded ACAS CSV ' + f.name, level: 'ok' });
            }).catch(function (err) { csvLine.textContent = 'Upload failed'; csvLine.className = 'st-bad'; actlog.append({ text: 'CSV upload failed: ' + (err && err.message ? err.message : err), level: 'err' }); });
          };
          fi.click();
        };

        // RIGHT: stats + grid
        var right = el('div'); right.style.cssText = 'flex:1;min-width:0;display:flex;flex-direction:column;gap:12px;min-height:0';
        // audit 2026-07-24: UNKNOWN gets its OWN tile. Folding unscanned items into
        // MISSING would claim we proved an absence we never looked for; folding them
        // into ON HAND would be worse. It is counted, and excluded from, both.
        var stats = C.StatCards({ cards: [
          { key: 'needed',   label: 'NEEDED', color: 'cyan' },
          { key: 'onhand',   label: 'ON HAND', color: 'ok' },
          { key: 'missing',  label: 'MISSING', color: 'bad' },
          { key: 'unknown',  label: 'UNKNOWN', color: 'accent' },
          { key: 'coverage', label: 'COVERAGE %', color: 'gold' }
        ] });
        right.appendChild(stats.el);

        var actionCard = ui.card({}); actionCard.style.cssText += ';display:flex;align-items:center;gap:12px;flex-wrap:wrap';
        var exportBtn = ui.ghostButton('Export CSV', { size: 'sm', title: 'Export the cross-reference rows to CSV.' });
        var clearBtn = ui.button('Clear', { variant: 'danger', size: 'sm', title: 'Clear the results grid.' });
        var spacer = el('div'); spacer.style.flex = '1';
        actionCard.appendChild(spacer); actionCard.appendChild(exportBtn); actionCard.appendChild(clearBtn);
        right.appendChild(actionCard);

        var results = ui.namedCard('CROSS-REFERENCE', 'Green rows are ON HAND. Red rows are MISSING from staged content (cannot be pushed offline yet). Amber UNKNOWN rows were never checked - a content root could not be scanned, so absence is UNPROVEN; fix the root and re-run before trusting the result.');
        results.style.cssText += ';flex:1;min-height:0;display:flex;flex-direction:column';
        var grid = C.ResultsGrid({
          title: 'Patch content cross-reference', keyMode: { rk: true }, popOut: true,
          columns: [
            { key: 'Needed', label: 'NEEDED', width: 190, render: function (r) { var t = String(r.Needed || ''); return { text: t, title: t }; } },
            { key: 'Kind', label: 'KIND', width: 90, render: function (r) { return { text: String(r.Kind || ''), cls: r.Kind === 'KB' ? 'st-info' : 'cell-dim' }; } },
            { key: 'Status', label: 'STATUS', width: 110, render: function (r) { return { text: String(r.Status || ''), cls: statusCls(r.Status) }; } },
            { key: 'Matches', label: 'ON-HAND CONTENT', render: function (r) { var t = String(r.Matches || ''); return { text: t, title: t }; } }
          ],
          rowClass: function (r) { return r.Status === 'ON HAND' ? 'row-ok' : (r.Status === 'MISSING' ? 'row-bad' : (r.Status === 'UNKNOWN' ? 'row-warn' : '')); }
        });
        var gridHolder = el('div'); gridHolder.style.cssText = 'flex:1;min-height:0;display:flex'; gridHolder.appendChild(grid.el);
        results.appendChild(gridHolder);
        right.appendChild(results);
        panel.appendChild(right);

        function setStatus(t, cls) { xStatus.textContent = t == null ? '' : String(t); xStatus.className = cls || 'muted'; }
        // O(1) tallies, same reason as the Inventory tab (audit 2026-07-24).
        var xActive = false, xRun = null, xUnsub = null;
        var cOn = 0, cMiss = 0, cUnk = 0, cRows = 0, xSeen = null;
        clearBtn.onclick = function () { if (xActive) return; grid.clear(); stats.reset(); setStatus('Ready'); };
        exportBtn.onclick = function () {
          var rows = grid.rows();
          if (!rows.length) { ctx.confirm({ title: 'Nothing to export', body: 'Run a cross-reference first.', okText: 'OK', cancelText: null }); return; }
          var cols = [['Needed', 'Needed'], ['Kind', 'Kind'], ['Status', 'Status'], ['Matches', 'On-Hand Content']];
          ctx.util.exportCsv('PatchContent_CrossRef', cols, rows);
        };

        function doCrossref() {
          grid.clear(); stats.reset(); cOn = 0; cMiss = 0; cUnk = 0; cRows = 0; xSeen = {};
          setStatus('Cross-referencing...', 'st-info');
          xRun = ctx.run('crossref', { needed: neededInput.value || '', csvPaths: csvPath || '', extraPath: extraInput.value || '' }, { keyOf: function (ev) { return ev._rk; } });
          if (xUnsub) xUnsub();
          xUnsub = xRun.subscribe({
            status: function (t) { setStatus(t, 'st-info'); },
            row: function (r) {
              grid.upsert(r);
              // audit 2026-07-24: counters instead of grid.rows().length per row (that
              // call rebuilds the whole row array). UNKNOWN is tallied SEPARATELY - the
              // old 'missing = total - onhand' silently reported every item we could
              // not check as confirmed-absent.
              var k = r._rk == null ? '' : String(r._rk);
              if (Object.prototype.hasOwnProperty.call(xSeen, k)) return;
              xSeen[k] = 1; cRows++;
              var st = String(r.Status || '');
              if (st === 'ON HAND') cOn++; else if (st === 'UNKNOWN') cUnk++; else cMiss++;
              stats.setAll({ needed: cRows, onhand: cOn, missing: cMiss, unknown: cUnk, coverage: cRows ? Math.round((cOn / cRows) * 1000) / 10 : 0 });
            },
            log: function (l) { actlog.append(l); },
            error: function (e) { setStatus(e.text || 'Error', 'st-bad'); actlog.append({ text: e.text, level: 'err' }); },
            active: function (a) { xActive = a; xrunbar.setActive(a); xrunbar.cta.textContent = a ? 'WORKING...' : 'CROSS-REFERENCE'; },
            final: function (res) {
              var s = (res && res.summary) || {};
              var unk = s.unknown == null ? cUnk : s.unknown;
              stats.setAll({ needed: s.needed || cRows, onhand: s.onHand || cOn, missing: s.missing == null ? cMiss : s.missing, unknown: unk, coverage: s.coverage == null ? 0 : s.coverage });
              if (!s.needed) { setStatus('No needed items parsed. Paste a list and/or import an ACAS CSV.', 'st-warn'); return; }
              var miss = s.missing || 0;
              var txt = 'Done - ' + (s.onHand || 0) + ' on hand, ' + miss + ' missing';
              if (unk) { txt += ', ' + unk + ' UNKNOWN (' + (s.rootsSkipped || 0) + ' root(s) NOT scanned)'; }
              txt += ' (' + (s.coverage || 0) + '% coverage).';
              // An UNKNOWN outranks a MISSING in the headline: MISSING is a known gap
              // the operator can go stage, UNKNOWN means the answer itself is not
              // trustworthy yet and the scan has to be repeated (audit 2026-07-24).
              setStatus(txt, unk > 0 ? 'st-bad' : (miss > 0 ? 'st-warn' : 'st-ok'));
            }
          });
          track(xUnsub);
        }
      }

      // ---- assemble: TabHost + bottom activity dock ----------------------------
      var root = el('div'); root.style.cssText = 'display:flex;flex-direction:column;gap:12px;height:100%;min-height:0;padding:14px;box-sizing:border-box';
      var tabHolder = el('div'); tabHolder.style.cssText = 'flex:1;min-height:0;display:flex';
      var tabs = C.TabHost({
        rail: 'top',
        tabs: [
          { id: 'inventory', label: 'Inventory', build: buildInventoryTab },
          { id: 'crossref', label: 'Cross-Reference', build: buildCrossrefTab }
        ]
      });
      tabHolder.appendChild(tabs.el);
      root.appendChild(tabHolder);

      var logCard = ui.card({}); logCard.classList.add('j-logdock');
      logCard.appendChild(actlog.el);
      root.appendChild(logCard);

      actlog.append({ text: 'Patch Content ready. Inventory the staged content, then cross-reference it against what you need (read-only - changes nothing, no admin session needed).', level: 'accent' });

      host.appendChild(root);
      this._root = root;
      this._unsub = function () { subs.forEach(function (u) { try { u(); } catch (e) {} }); };
    }
  });
})();
