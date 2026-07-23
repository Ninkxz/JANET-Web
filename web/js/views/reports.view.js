/* ============================================================================
   reports.view.js  -  J.A.N.E.T. Reports Tool (tool id: 'reports')
   Faithful re-front of the desktop ReportsTool_2.14.x per docs/ui-specs/reports.md:
   a fixed left SIDEBAR of section nav buttons that swap full-screen content
   panels (NOT a WinForms TabControl), with a persistent timestamped ACTIVITY
   LOG below the sections. Rebuilt here with TabHost(rail:'left') for the section
   rail; every section composes the shared kit (ResultsGrid / StatCards /
   ProgressStrip / RunBar / TargetManager) and a SINGLE shared ActivityLog that
   sits under the rail and survives section switches (mirrors the desktop's
   sidebar-docked console + global Log()).

   STATEFUL TOOL: the server keeps ONE persistent runspace (manifest
   statefulRunspace=$true). The view just fires actions in sequence and the
   engine remembers parse/scan/triage state between them - e.g. ACAS Parse File
   -> CORA Build / Remediation Refresh / Host Summary all read the same cached
   findings; Load Baseline -> Load Comparison -> Scan Compare -> Apply Remediated
   is a deliberate sequence. So this view does NOT re-send findings: each action
   stands on the engine's accumulated state.

   ARTIFACTS: report actions (dirty30-render-html, weekly-render-html,
   cora-render-html, dirty30-export-csv, weekly-export-csv, acas-export-findings,
   acas-save-report) return the generated text inline on the final result's
   summary (summary.html / summary.csv / summary.json + summary.bytes). The view
   offers Download (ctx.util.downloadBlob) and, for HTML, Open (a NEW sandboxed
   window: allow-scripts WITHOUT allow-same-origin) buttons once a run finishes.

   CREDENTIALS: reports is read-only / reporting - NO action in the manifest is
   marked destructive, so this view renders NO per-tool cred control and gates on
   nothing. (The shell header owns the single universal Set Credentials.) All
   probes run under the server identity, exactly like the desktop tool.

   ALL server I/O goes through ctx.run -> RunController; imports go through
   ctx.uploadFile(file) -> the returned server path is handed to the parse action.
   ========================================================================== */
(function () {
  'use strict';

  // engine severity ordering / colour - hand-written per the desktop Get-SeverityColor.
  function sevCls(v) {
    switch (String(v)) {
      case 'Critical': return 'st-sev-crit';
      case 'High': return 'st-sev-high';   // dedicated orange - distinct from Medium
      case 'Medium': return 'st-sev-med';  // amber
      case 'Low': return 'st-sev-low';
      case 'Info': return 'cell-dim';
      default: return '';
    }
  }
  // desktop Get-StatusColor: Patched=green, Open=red, NOT OUR PATCH=purple. The grid
  // kit has no purple cell token (only st-ok/st-bad/st-warn/st-info/cell-dim), so NOT
  // OUR PATCH uses st-info (cyan) + a whole-row dim (row-warn), the nearest faithful look.
  function notOurPatchCls(v) { return v === 'NOT OUR PATCH' ? 'st-info' : ''; }
  // triage Status colouring (desktop Get-StatusColor): Patched=green, Open=red,
  // NOT OUR PATCH=purple -> st-info (nearest kit token). Used by the STATUS column (#6).
  function statusCls(v) { v = String(v); if (/Patched/i.test(v)) return 'st-ok'; if (/NOT OUR PATCH/i.test(v)) return 'st-info'; if (/^Open/i.test(v)) return 'st-bad'; return ''; }
  // Dirty 30 / IP-resolve status colouring.
  function d30StatusCls(v) {
    var s = String(v);
    if (/^Active$/i.test(s)) return 'st-ok';
    if (/^Stale$/i.test(s)) return 'st-warn';
    if (/Not Found|NotFound/i.test(s)) return 'st-bad';
    return '';
  }
  function ipStatusCls(v) {
    var s = String(v);
    if (/^Online$/i.test(s)) return 'st-ok';
    if (/^Offline$/i.test(s)) return 'st-bad';
    if (/DNS/i.test(s)) return 'st-warn';
    return '';
  }
  function deltaCls(v) {
    var s = String(v);
    if (/REMEDIATED/i.test(s)) return 'st-ok';
    if (/STILL OPEN/i.test(s)) return 'st-warn';
    if (/NEW/i.test(s)) return 'st-bad';
    return '';
  }
  // Wave closure proof: TouchedByJanet YES = green (attributable), no = dim.
  function touchedCls(v) { return /^yes$/i.test(String(v)) ? 'st-ok' : 'cell-dim'; }
  function patchRateCls(v) {
    var m = /(\d+)/.exec(String(v)); if (!m) return 'cell-dim';
    var n = +m[1];
    return n >= 90 ? 'st-ok' : (n >= 50 ? 'st-warn' : 'st-bad');
  }
  // SLA aging bucket -> pill colour. OVERDUE=red, DUE-SOON=amber, ON-TRACK=green,
  // NEW-UNTRACKED=cyan (no firstSeen yet; not in the persisted SLA ledger).
  function slaBucketCls(v) {
    var s = String(v);
    if (/OVERDUE/i.test(s)) return 'st-bad';
    if (/DUE-SOON/i.test(s)) return 'st-warn';
    if (/ON-TRACK/i.test(s)) return 'st-ok';
    if (/UNTRACKED/i.test(s)) return 'st-info';
    return '';
  }
  // DueIn (days to deadline): negative = past due (red), <=3 = amber, else dim.
  function dueInCls(v) {
    if (v === '' || v == null) return 'cell-dim';
    var n = +v; if (isNaN(n)) return 'cell-dim';
    return n < 0 ? 'st-bad' : (n <= 3 ? 'st-warn' : 'cell-dim');
  }
  var esc = Janet.util.esc;
  // KEV auto-flag (feature): a finding whose CVE is on the CISA Known Exploited
  // Vulnerabilities catalog. Engine sends InKEV as a JSON boolean; be defensive
  // about string forms too. Rendered as a red 'KEV' cell + row highlight, mirroring
  // the sibling KEV Cross-Check tool (st-bad text + row-bad).
  function isKev(r) { var v = r && r.InKEV; return v === true || v === 1 || v === 'True' || v === 'true'; }
  function gt0cls(cls) { return function (v) { return (+v > 0) ? cls : 'cell-dim'; }; }
  function fmtBytes(b) { b = +b || 0; return b < 1024 ? (b + ' B') : (b < 1048576 ? ((b / 1024).toFixed(1) + ' KB') : ((b / 1048576).toFixed(2) + ' MB')); }

  JanetViews.register('reports', {
    mount: function (host, ctx) {
      var ui = ctx.ui, C = ctx.components, el = ctx.util.el;

      // One handle per concurrently-runnable action key; we keep the latest unsub
      // per logical slot so an unmount can detach everything cleanly. RunController
      // keys runs by tool/action, so each action already has its own keep-alive run.
      var unsubs = [];        // every active subscription -> cleaned up on unmount
      function track(unsub) { if (unsub) unsubs.push(unsub); return unsub; }
      // Per-action-key subscription slot: releasing the PREVIOUS live subscription
      // for the same action key before tracking the new one, so a re-run REPLACES
      // its handler instead of stacking it (every stale handler still receives the
      // new run's events -> duplicate log lines / doubled counts). Same idiom as
      // wpt:320 / acas:325; keyed because this view runs many actions concurrently.
      var keyUnsubs = {};     // action key -> live unsub
      function resub(key, unsub) {
        var prev = keyUnsubs[key];
        if (prev) { var i = unsubs.indexOf(prev); if (i >= 0) unsubs.splice(i, 1); prev(); }
        keyUnsubs[key] = track(unsub);
        return keyUnsubs[key];
      }

      // ---------- the SINGLE shared ActivityLog (desktop sidebar console) ----------
      var log = C.ActivityLog({ title: 'ACTIVITY LOG', defaultName: 'ReportsTool_ActivityLog' });

      // ---------- artifact bar factory --------------------------------------------
      // Report actions deliver generated text on the final summary; show Download +
      // (for HTML) Open buttons once a run completes.
      // SECURITY NOTE (loop-1 review, backstop landed loop-3): the popup itself is
      // a plain same-origin window.open, but the /api/report-preview response is
      // served with CSP "sandbox allow-scripts" - the DOCUMENT gets an opaque
      // origin once it loads, so a hostile script smuggled past field escaping
      // cannot read the SPA's sessionStorage token or call /api same-origin.
      // First line of defense is still ConvertTo-HtmlEscaped on every report data
      // field (treat an unescaped field in reports.psm1 as a P1); the sandbox is
      // the backstop. Never add allow-same-origin to that CSP.
      function openHtmlSandboxed(htmlText, titleText) {
        var w = window.open('', '_blank');
        if (!w) {
          ctx.confirm({ title: 'Popup blocked', body: 'Allow popups for this site to open the report in a new window, or use Download instead.', okText: 'OK', cancelText: null });
          return false;
        }
        // The generated report carries an inline <script> (Dirty 30 pill filters /
        // live search). A data: URI would inherit the SPA's strict CSP script-src and
        // that script would be blocked, so stash the HTML server-side and open the
        // one-shot /api/report-preview GET (served with its own relaxed CSP). window.open
        // already fired synchronously above (survives popup blockers); redirect it once
        // the async POST returns the id.
        w.document.open();
        w.document.write('<!doctype html><meta charset="utf-8"><title>' + esc(titleText || 'JANET Report') +
          '</title><body style="margin:0;background:#08080C;color:#8aa;font:14px system-ui;padding:16px">Loading report...</body>');
        w.document.close();
        ctx.api('POST', '/report-preview', { html: htmlText }).then(function (j) {
          if (j && j.ok && j.id) { w.location = '/api/report-preview?id=' + encodeURIComponent(j.id); }
          else { try { w.close(); } catch (e) {} ctx.confirm({ title: 'Preview failed', body: 'The server did not return a preview id. Use Download instead.', okText: 'OK', cancelText: null }); }
        }).catch(function () {
          try { w.close(); } catch (e) {}
          ctx.confirm({ title: 'Preview failed', body: 'Could not open the report preview. Use Download instead.', okText: 'OK', cancelText: null });
        });
        return true;
      }

      // a small toolbar that holds Download/Open buttons for the last artifact of a section
      function ArtifactBar(opts) {
        opts = opts || {};
        var bar = el('div'); bar.style.cssText = 'display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-top:8px';
        var statusSpan = el('span', 'muted'); statusSpan.style.fontSize = '11px';
        var dlBtn = ui.ghostButton(opts.downloadLabel || 'Download', { size: 'sm' });
        var xlsxBtn = ui.ghostButton('Download XLSX', { size: 'sm', title: 'Download the same data as a single-sheet .xlsx workbook (no Excel/ImportExcel needed).' });
        var openBtn = ui.button(opts.openLabel || 'Open in window', { variant: 'gold', size: 'sm' });
        dlBtn.disabled = true; openBtn.disabled = true; xlsxBtn.disabled = true; xlsxBtn.style.display = 'none';
        if (opts.htmlOnly === false) openBtn.style.display = 'none';   // CSV/JSON artifacts: no Open button
        bar.appendChild(statusSpan); bar.appendChild(dlBtn); bar.appendChild(xlsxBtn);
        if (opts.htmlOnly !== false) bar.appendChild(openBtn);

        var cur = null;   // { content, mime, name, kind:'html'|'csv'|'json', sheet }
        dlBtn.onclick = function () { if (cur) ctx.util.downloadBlob(cur.name, cur.mime, cur.content); };
        xlsxBtn.onclick = function () {
          if (!cur || cur.kind !== 'csv') return;
          var p = ctx.util.parseCsv(cur.content);
          if (!p.headers.length) { log.append({ text: 'Nothing to export to XLSX.', level: 'warn' }); return; }
          ctx.util.downloadXlsx(cur.name.replace(/\.csv$/i, '.xlsx'), p.headers, p.rows, (cur.sheet || 'Export').slice(0, 28));
        };
        openBtn.onclick = function () { if (cur && cur.kind === 'html') openHtmlSandboxed(cur.content, cur.name); };

        return {
          el: bar,
          // set from a final summary: pick html|csv|json off it
          set: function (summary, namePrefix) {
            cur = null; dlBtn.disabled = true; openBtn.disabled = true; xlsxBtn.disabled = true; xlsxBtn.style.display = 'none';
            if (!summary) { statusSpan.textContent = ''; return; }
            var stamp = ctx.util.fileStamp();
            if (summary.html != null) {
              cur = { content: summary.html, mime: 'text/html', name: (namePrefix || 'Report') + '_' + stamp + '.html', kind: 'html' };
              openBtn.disabled = false;
            } else if (summary.csv != null) {
              cur = { content: summary.csv, mime: 'text/csv', name: (namePrefix || 'Export') + '_' + stamp + '.csv', kind: 'csv', sheet: (namePrefix || 'Export') };
              xlsxBtn.disabled = false; xlsxBtn.style.display = '';
            } else if (summary.json != null) {
              cur = { content: summary.json, mime: 'application/json', name: (namePrefix || 'Report') + '_' + stamp + '.json', kind: 'json' };
            }
            if (cur) {
              dlBtn.disabled = false;
              statusSpan.textContent = 'Ready: ' + cur.name + (summary.bytes != null ? '  (' + fmtBytes(summary.bytes) + ')' : '');
              statusSpan.className = 'st-ok';
            } else {
              statusSpan.textContent = 'No artifact returned (nothing to export).';
              statusSpan.className = 'muted';
            }
          },
          reset: function () { cur = null; dlBtn.disabled = true; openBtn.disabled = true; xlsxBtn.disabled = true; xlsxBtn.style.display = 'none'; statusSpan.textContent = ''; statusSpan.className = 'muted'; }
        };
      }

      // file-import helper: open the native picker, upload, hand the server path back.
      // (TargetManager imports are client-side text; engine PARSE actions need a server
      // path -> we must round-trip through ctx.uploadFile.)
      function pickAndUpload(accept, onPath, onCancelMsg) {
        var fi = el('input'); fi.type = 'file'; if (accept) fi.accept = accept; fi.style.display = 'none';
        document.body.appendChild(fi);
        fi.addEventListener('change', function () {
          var f = fi.files && fi.files[0];
          document.body.removeChild(fi);
          if (!f) { if (onCancelMsg) log.append({ text: onCancelMsg, level: 'dim' }); return; }
          log.append({ text: 'Uploading ' + f.name + ' (' + fmtBytes(f.size) + ')...', level: 'accent' });
          ctx.uploadFile(f).then(function (path) {
            log.append({ text: 'Uploaded -> ' + path, level: 'ok' });
            onPath(path, f.name);
          }).catch(function (e) {
            log.append({ text: 'Upload failed: ' + (e && e.message), level: 'err' });
            ctx.confirm({ title: 'Upload failed', body: 'Could not upload the file: ' + esc(e && e.message), okText: 'OK', cancelText: null });
          });
        });
        fi.click();
      }

      // ---- best-effort, dependency-free PDF text extraction (Dirty 30 loader) ----
      // Inflate FlateDecode content streams via the browser's DecompressionStream
      // (+ uncompressed streams) and pull PDF literal-string text. Falls back to
      // manual paste when it yields too little (scanned/image-only or unsupported
      // encodings) - no third-party PDF lib, per the zero-dependency constraint.
      function latin1Bytes(bytes) {
        var s = '', CH = 0x8000;
        for (var i = 0; i < bytes.length; i += CH) { s += String.fromCharCode.apply(null, bytes.subarray(i, Math.min(i + CH, bytes.length))); }
        return s;
      }
      function inflateDeflate(bytes) {
        if (typeof DecompressionStream === 'undefined') return Promise.resolve(null);
        // a deflate stream with trailing bytes can make DecompressionStream hang, so
        // race against a timeout - a bad/over-long stream resolves null and is skipped.
        var work = Promise.resolve().then(function () {
          var ds = new DecompressionStream('deflate');
          return new Response(new Blob([bytes]).stream().pipeThrough(ds)).arrayBuffer().then(function (ab) { return new Uint8Array(ab); });
        }).catch(function () { return null; });
        var timeout = new Promise(function (resolve) { setTimeout(function () { resolve(null); }, 4000); });
        return Promise.race([work, timeout]);
      }
      function unescapePdfStr(s) {
        return s.replace(/\\([nrtbf()\\]|[0-7]{1,3})/g, function (m, g) {
          switch (g) { case 'n': return '\n'; case 'r': return '\r'; case 't': return '\t'; case 'b': return '\b'; case 'f': return '\f'; case '(': return '('; case ')': return ')'; case '\\': return '\\'; }
          return String.fromCharCode(parseInt(g, 8) & 0xff);
        });
      }
      function textFromContent(content) {
        var out = [], re = /\((?:\\[\s\S]|\([^()]*\)|[^()\\])*\)|\bT[d*]\b|\bTD\b|\bET\b/g, m;
        while ((m = re.exec(content)) !== null) {
          var tok = m[0];
          if (tok.charAt(0) === '(') out.push(unescapePdfStr(tok.slice(1, -1)));
          else out.push('\n');   // a positioning / end-text op -> line break
        }
        return out.join('');
      }
      function extractPdfText(file) {
        return file.arrayBuffer().then(function (ab) {
          var buf = new Uint8Array(ab), latin = latin1Bytes(buf);
          var slices = [], sIdx = 0, guard = 0;
          while (guard++ < 5000) {
            var sm = latin.indexOf('stream', sIdx); if (sm < 0) break;
            var em = latin.indexOf('endstream', sm); if (em < 0) break;
            var dict = latin.slice(Math.max(0, sm - 400), sm);
            var flate = /\/FlateDecode/.test(dict) || /\/Fl\b/.test(dict);
            var ds = sm + 6;
            if (buf[ds] === 13 && buf[ds + 1] === 10) ds += 2; else if (buf[ds] === 13 || buf[ds] === 10) ds += 1;
            // prefer the dict's direct /Length for exact stream bytes (no trailing EOL,
            // which can hang the inflate); ignore indirect refs (/Length N 0 R).
            var endByte = em;
            var lenM = /\/Length\s+(\d+)(?!\s+\d+\s+R)/.exec(dict);
            if (lenM) { var L = parseInt(lenM[1], 10); if (L > 0 && ds + L <= em + 2) endByte = Math.min(ds + L, em); }
            slices.push({ flate: flate, bytes: buf.subarray(ds, endByte) });
            sIdx = em + 9;
          }
          var texts = [], seq = Promise.resolve();
          slices.forEach(function (sl) {
            seq = seq.then(function () {
              if (sl.flate) return inflateDeflate(sl.bytes).then(function (inf) { if (inf) texts.push(textFromContent(latin1Bytes(inf))); });
              texts.push(textFromContent(latin1Bytes(sl.bytes)));
            });
          });
          return seq.then(function () { return texts.join('\n'); });
        });
      }

      // common "run an action that streams rows into a grid + tails the log" helper.
      // Returns the handle. Pass keyOf for multi-row-per-host grids.
      function runIntoGrid(actionId, params, opts) {
        opts = opts || {};
        var grid = opts.grid, prog = opts.prog, onFinal = opts.onFinal, keyOf = opts.keyOf;
        if (opts.clearGrid && grid) grid.clear();
        if (prog) prog.reset();
        if (grid && grid.setLoading) grid.setLoading(true);   // spinner until first row / terminal
        var handle = ctx.run(actionId, params || {}, keyOf ? { keyOf: keyOf } : {});
        var u = handle.subscribe({
          status: function (t) { if (prog) prog.setPhase(t); log.append({ text: t, level: 'mode' }); },
          progress: function (p) { if (prog) prog.setProgress(p.done, p.total); },
          row: function (r) { if (grid) grid.upsert(r); },
          log: function (l) { log.append(l); },
          error: function (e) { log.append({ text: e.text, level: 'err' }); },
          final: function (res) { if (grid && grid.setLoading) grid.setLoading(false); if (onFinal) onFinal(res); },
          active: function (a) { if (!a && grid && grid.setLoading) grid.setLoading(false); if (opts.onActive) opts.onActive(a); }
        });
        resub(actionId, u);
        return handle;
      }

      // small section helpers
      function sectionTitle(text, gold) { var h = el('div', 'j-section-h', text); h.style.marginBottom = '4px'; if (gold) h.style.color = 'var(--gold)'; return h; }
      function hint(text) { var d = el('div', 'muted', text); d.style.cssText = 'font-size:11px;margin-bottom:10px'; return d; }
      function btnRow() { var r = el('div'); r.style.cssText = 'display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:10px'; return r; }
      function gridHolder(grid, minH) { var h = el('div'); h.style.cssText = 'flex:1;min-height:' + (minH || 160) + 'px;display:flex'; h.appendChild(grid.el); return h; }
      function panelFlex(panel) { panel.style.cssText = 'display:flex;flex-direction:column;height:100%;min-height:0;gap:6px'; }

      // ============================================================================
      //  SECTION BUILDERS  (each = one nav-rail tab; built lazily, kept alive)
      // ============================================================================

      // ---- Start (landing / help) -------------------------------------------------
      function buildStart(panel) {
        panelFlex(panel);
        panel.appendChild(sectionTitle('J.A.N.E.T. REPORTS TOOL', true));
        panel.appendChild(hint('ACAS & Patch Cross-Reference - stateful reporting workspace.'));
        var card = ui.card({}); card.style.cssText += ';max-width:760px';
        var steps = el('div');
        steps.innerHTML =
          '<p style="margin:0 0 10px">This tool keeps a <b>persistent session</b> on the server: each action builds on the last. A typical loop:</p>' +
          '<ol style="margin:0 0 10px 18px;line-height:1.7">' +
          '<li><b>ACAS Import</b> - parse a .nessus / CSV / TSV scan into the working findings set.</li>' +
          '<li>Triage: mark findings <b>Patched</b> / <b>NOT OUR PATCH</b> / <b>Open</b> (undo).</li>' +
          '<li>Review the <b>Dashboard</b> (per-host summary) and <b>Remediation</b> plan.</li>' +
          '<li><b>ACAS Compare</b>: load a baseline + a comparison scan, diff them, apply remediated.</li>' +
          '<li>Generate briefs: <b>CORA</b>, <b>Weekly</b>, <b>Dirty 30</b>; export CSV / JSON / HTML.</li>' +
          '</ol>' +
          '<p class="muted" style="margin:0;font-size:12px">Reporting is read-only - no credentials required. Probes (Dirty 30 last-user, IP resolve) run under the server identity.</p>';
        card.appendChild(steps);
        panel.appendChild(card);
      }

      // ---- ACAS Import (the core triage workspace) --------------------------------
      var acasImport = {};
      function buildAcasImport(panel) {
        panelFlex(panel);
        panel.appendChild(sectionTitle('ACAS SCAN IMPORT', true));
        panel.appendChild(hint('Parse a scan into the working findings set, then triage. Findings whose CVE is on the CISA KEV catalog are flagged KEV (red) - use the KEV only filter to isolate them. Status colours: Patched=green, Open=red, NOT OUR PATCH=purple. Severity coloured per ACAS.'));

        var row1 = btnRow();
        var importBtn = ui.button('Import ACAS (.nessus / .csv / .tsv)', { variant: 'cyan', title: 'Upload a scan file and parse it into findings (replaces the set unless Append is checked).' });
        var appendCb = ui.checkbox('Append to existing findings', { title: 'Add to the current findings instead of replacing them.' });
        var loadJsonBtn = ui.ghostButton('Load Saved Report (JSON)', { size: 'sm', title: 'Restore findings + triage state from an ACAS Save Report JSON.' });
        var saveJsonBtn = ui.ghostButton('Save Report (JSON)', { size: 'sm', title: 'Save findings + triage state to a downloadable JSON.' });
        var countLbl = el('span', 'muted'); countLbl.style.marginLeft = 'auto'; countLbl.textContent = 'No findings loaded';
        row1.appendChild(importBtn); row1.appendChild(appendCb); row1.appendChild(loadJsonBtn); row1.appendChild(saveJsonBtn); row1.appendChild(countLbl);
        panel.appendChild(row1);

        // triage controls (selection-action vs Mark-All-Visible pairing, per the spec)
        var row2 = btnRow();
        var markPatched = ui.button('Mark Selected: Patched', { variant: 'go', size: 'sm', title: 'Mark checked rows Patched (records Patched-By / Date).' });
        var markNop = ui.button('Mark Selected: NOT OUR PATCH', { variant: 'cyan', size: 'sm', title: 'Recategorize checked rows as NOT OUR PATCH.' });
        var markOpen = ui.ghostButton('Undo Selected (-> Open)', { size: 'sm', title: 'Recompute category + clear patch info for checked rows.' });
        var patchedByInput = ui.input({ value: '', placeholder: 'Patched by (blank = you)', title: 'Stamped onto findings marked Patched.' }); patchedByInput.style.width = '180px';
        var patchedDateInput = ui.input({ value: '', placeholder: 'Patched date (blank = today)', title: 'Stamped onto findings marked Patched.' }); patchedDateInput.style.width = '180px';
        row2.appendChild(markPatched); row2.appendChild(markNop); row2.appendChild(markOpen); row2.appendChild(patchedByInput); row2.appendChild(patchedDateInput);
        panel.appendChild(row2);

        // "Mark All Visible" pair (#8): acts on every finding the current filter shows.
        var row2b = btnRow();
        var markAllPatched = ui.button('All Visible: Patched', { variant: 'go', size: 'sm', title: 'Mark every finding currently shown by the filter Patched (records Patched-By / Date).' });
        var markAllNop = ui.button('All Visible: NOT OUR PATCH', { variant: 'cyan', size: 'sm', title: 'Recategorize every finding currently shown by the filter as NOT OUR PATCH.' });
        row2b.appendChild(ui.eyebrow('MARK ALL VISIBLE')); row2b.appendChild(markAllPatched); row2b.appendChild(markAllNop);
        panel.appendChild(row2b);

        // export row + artifact bar
        var row3 = btnRow();
        row3.appendChild(ui.eyebrow('EXPORT FINDINGS (CSV)'));
        var viewSel = ui.select({ options: ['Full (all findings)', 'Open (remaining)', 'NOT OUR PATCH', 'Patched', 'Offline (host down)'], value: 'Full (all findings)', title: 'Which subset to export (Offline needs a Ping Hosts run first).' });
        var exportBtn = ui.ghostButton('Build CSV', { size: 'sm', title: 'Build the findings CSV for the selected view.' });
        row3.appendChild(viewSel); row3.appendChild(exportBtn);
        panel.appendChild(row3);
        var artifact = ArtifactBar({ downloadLabel: 'Download CSV', htmlOnly: false });
        panel.appendChild(artifact.el);

        // IAVM mapping: append/update a CVE -> IAVA/bulletin row in JanetLocal\IavmMap.csv,
        // mirroring the KEV tool's Add to KEV. Freshly parsed/loaded findings then tag IAVA
        // automatically (re-import to apply to the already-loaded set).
        var rowIavm = btnRow();
        rowIavm.appendChild(ui.eyebrow('ADD IAVM MAP'));
        var iavmCveInput = ui.input({ value: '', placeholder: 'CVE-YYYY-NNNN', title: 'CVE to map to an IAVA / bulletin id.' }); iavmCveInput.style.width = '150px';
        var iavmIdInput = ui.input({ value: '', placeholder: 'IAVA (e.g. 2024-A-0100)', title: 'IAVA / bulletin id.' }); iavmIdInput.style.width = '170px';
        var iavmTitleInput = ui.input({ value: '', placeholder: 'Title (optional)', title: 'Short description.' }); iavmTitleInput.style.width = '220px';
        var iavmAddBtn = ui.ghostButton('Add IAVM Mapping', { size: 'sm', title: 'Append/update this CVE -> IAVA mapping in JanetLocal\\IavmMap.csv (re-import findings to apply).' });
        rowIavm.appendChild(iavmCveInput); rowIavm.appendChild(iavmIdInput); rowIavm.appendChild(iavmTitleInput); rowIavm.appendChild(iavmAddBtn);
        panel.appendChild(rowIavm);

        var grid = C.ResultsGrid({
          title: 'ACAS findings', keyMode: { rk: true }, selectable: true, popOut: true,
          columns: [
            { key: 'Hostname', label: 'HOSTNAME', width: 130 },
            { key: 'PluginID', label: 'PLUGIN', width: 80 },
            { key: 'VulnName', label: 'VULN NAME', width: 300 },
            { key: 'Severity', label: 'SEVERITY', width: 90, colorRule: sevCls },
            { key: 'CVE', label: 'CVE', width: 110 },
            // IAVM mapping: the finding's IAVA / bulletin id when its CVE is on the
            // JanetLocal\IavmMap.csv map (blank + dimmed otherwise). sortVal floats
            // mapped rows on sort.
            { key: 'IAVA', label: 'IAVA', width: 110, sortVal: function (r) { return (r.IAVA ? 1 : 0); }, colorRule: function (v) { return v ? '' : 'cell-dim'; } },
            // KEV auto-flag: red 'KEV' when the finding's CVE is known-exploited; the
            // overlapping CVE ids are the hover title. sortVal floats KEV rows on sort.
            { key: 'InKEV', label: 'KEV', width: 60, sortVal: function (r) { return isKev(r) ? 1 : 0; }, render: function (r) { var on = isKev(r); return { text: on ? 'KEV' : '', cls: on ? 'st-bad' : 'cell-dim', title: on ? ('Known-exploited (CISA KEV): ' + (r.KevCves || r.CVE || '')) : '' }; } },
            { key: 'Category', label: 'CATEGORY', width: 130, colorRule: notOurPatchCls },
            { key: 'Status', label: 'STATUS', width: 110, colorRule: statusCls },
            { key: 'Solution', label: 'SOLUTION', width: 280 }
          ],
          // KEV (known-exploited) outranks NOT OUR PATCH for the row highlight - a
          // known-exploited vuln is the higher-priority signal even if it's a vendor patch.
          rowClass: function (r) { return isKev(r) ? 'row-bad' : (r.Category === 'NOT OUR PATCH' ? 'row-warn' : ''); }
        });
        // live triage filter (Severity / Status / Category / free-text + host online-state) - hides rows in place
        var hostOnline = {};            // host(UPPER) -> bool, from acas-ping-hosts (#10)
        var onlineFilterMode = 'all';   // 'all' | 'online' | 'offline' (#10)
        var filterRow = btnRow();
        var sevFilterSel = ui.select({ options: ['All severities', 'Critical', 'High', 'Medium', 'Low', 'Info'], title: 'Show only findings of this severity.' });
        var statusFilterSel = ui.select({ options: ['All statuses', 'Open', 'Patched', 'NOT OUR PATCH'], title: 'Show only findings with this triage status.' });
        var catFilterSel = ui.select({ options: ['All categories'], title: 'Show only findings in this category (populated as findings load).' });
        var kevOnlyCb = ui.checkbox('KEV only', { title: 'Show only findings whose CVE is on the CISA Known Exploited Vulnerabilities catalog (known-exploited).' });
        var findSearch = ui.input({ placeholder: 'Filter: host / plugin / vuln / CVE / category / status / solution', title: 'Case-insensitive substring across the finding fields.' }); findSearch.style.width = '320px';
        var clrFilterBtn = ui.ghostButton('Clear filter', { size: 'sm' });
        filterRow.appendChild(ui.eyebrow('FILTER')); filterRow.appendChild(sevFilterSel); filterRow.appendChild(statusFilterSel); filterRow.appendChild(catFilterSel); filterRow.appendChild(kevOnlyCb); filterRow.appendChild(findSearch); filterRow.appendChild(clrFilterBtn);
        panel.appendChild(filterRow);

        // host reachability bar (#10): ping the findings' hosts, then filter by who is up.
        var pingRow = btnRow();
        var pingBtn = ui.button('Ping Hosts', { variant: 'cyan', size: 'sm', title: 'Ping every distinct host in the loaded findings, then filter the grid by who is reachable now.' });
        var rePingBtn = ui.ghostButton('Re-Ping', { size: 'sm', title: 'Ping the hosts again to refresh the online/offline map.' });
        var onlineToggle = ui.select({ options: ['All hosts', 'Online only', 'Offline only'], title: 'Filter findings by host reachability (run Ping Hosts first).' });
        var pingStat = el('span', 'muted'); pingStat.style.fontSize = '11px'; pingStat.style.marginLeft = '4px'; pingStat.textContent = 'not pinged';
        pingRow.appendChild(ui.eyebrow('HOST PING')); pingRow.appendChild(pingBtn); pingRow.appendChild(rePingBtn); pingRow.appendChild(onlineToggle); pingRow.appendChild(pingStat);
        panel.appendChild(pingRow);

        var gh = gridHolder(grid, 200); panel.appendChild(gh); gh.style.flex = '1';
        var prog = C.ProgressStatusStrip({ showCount: true }); prog.el.style.marginTop = '6px'; panel.appendChild(prog.el);

        // shared predicate so the FILTER row and "Mark All Visible" (#8) agree on what's shown.
        function findingPredicate(r) {
          if (sevFilterSel.value !== 'All severities' && String(r.Severity) !== sevFilterSel.value) return false;
          if (statusFilterSel.value !== 'All statuses' && String(r.Status) !== statusFilterSel.value) return false;
          if (catFilterSel.value !== 'All categories' && String(r.Category) !== catFilterSel.value) return false;
          if (kevOnlyCb._cb.checked && !isKev(r)) return false;
          if (onlineFilterMode !== 'all') {
            var on = hostOnline[String(r.Hostname).toUpperCase()];
            if (onlineFilterMode === 'online' && on !== true) return false;
            if (onlineFilterMode === 'offline' && on !== false) return false;   // unknown (never pinged) is NOT counted offline
          }
          var q = (findSearch.value || '').trim().toLowerCase();
          if (q) {
            var hay = [r.Hostname, r.PluginID, r.VulnName, r.CVE, r.Category, r.Status, r.Solution].map(function (x) { return String(x == null ? '' : x).toLowerCase(); }).join(' ');
            if (hay.indexOf(q) < 0) return false;
          }
          return true;
        }
        function filterIsIdentity() {
          return sevFilterSel.value === 'All severities' && statusFilterSel.value === 'All statuses' &&
                 catFilterSel.value === 'All categories' && !kevOnlyCb._cb.checked && onlineFilterMode === 'all' && !(findSearch.value || '').trim();
        }
        function applyFindingFilter() { grid.setFilter(filterIsIdentity() ? null : findingPredicate); }
        // CATEGORY dropdown is populated from the findings actually loaded (distinct Category).
        function refreshCatOptions() {
          var cats = {}; grid.rows().forEach(function (r) { var c = String(r.Category == null ? '' : r.Category); if (c) cats[c] = true; });
          var want = ['All categories'].concat(Object.keys(cats).sort());
          var cur = catFilterSel.value;
          catFilterSel.innerHTML = '';
          want.forEach(function (o) { var op = document.createElement('option'); op.value = o; op.textContent = o; catFilterSel.appendChild(op); });
          catFilterSel.value = (want.indexOf(cur) >= 0) ? cur : 'All categories';
          applyFindingFilter();   // keep the installed grid filter in lockstep with a possibly-reset dropdown
        }
        sevFilterSel.addEventListener('change', applyFindingFilter);
        statusFilterSel.addEventListener('change', applyFindingFilter);
        catFilterSel.addEventListener('change', applyFindingFilter);
        kevOnlyCb._cb.addEventListener('change', applyFindingFilter);
        findSearch.addEventListener('input', applyFindingFilter);
        clrFilterBtn.onclick = function () { sevFilterSel.value = 'All severities'; statusFilterSel.value = 'All statuses'; catFilterSel.value = 'All categories'; kevOnlyCb._cb.checked = false; findSearch.value = ''; onlineToggle.value = 'All hosts'; onlineFilterMode = 'all'; grid.setFilter(null); };

        // ---- host ping (#10) ----
        function doPing() {
          if (!grid.rows().length) { ctx.confirm({ title: 'No findings', body: 'Parse or load findings first, then ping their hosts.', okText: 'OK', cancelText: null }); return; }
          log.banner('ACAS Ping Hosts');
          pingStat.textContent = 'pinging...'; pingStat.className = 'st-info';
          var h = ctx.run('acas-ping-hosts', { threads: 32, timeoutMs: 1500 }, { keyOf: function (ev) { return ev.Host != null ? String(ev.Host) : null; } });
          resub('acas-ping-hosts', h.subscribe({
            status: function (t) { log.append({ text: t, level: 'mode' }); },
            row: function (r) { hostOnline[String(r.Host).toUpperCase()] = /^Online$/i.test(String(r.Online)); },
            log: function (l) { log.append(l); },
            error: function (e) { log.append({ text: e.text, level: 'err' }); },
            final: function (res) {
              var s = res && res.summary || {};
              pingStat.textContent = (s.online || 0) + ' online / ' + (s.offline || 0) + ' offline of ' + (s.total || 0);
              pingStat.className = 'st-ok';
              log.banner('Ping: ' + (s.online || 0) + ' online, ' + (s.offline || 0) + ' offline of ' + (s.total || 0));
              if (onlineFilterMode !== 'all') applyFindingFilter();   // repaint with the fresh map
            }
          }));
        }
        pingBtn.onclick = doPing;
        rePingBtn.onclick = doPing;
        onlineToggle.addEventListener('change', function () {
          onlineFilterMode = (onlineToggle.value === 'Online only') ? 'online' : (onlineToggle.value === 'Offline only') ? 'offline' : 'all';
          if (onlineFilterMode !== 'all' && !Object.keys(hostOnline).length) log.append({ text: 'No ping data yet - click Ping Hosts first.', level: 'warn' });
          applyFindingFilter();
        });

        // findings parsed by the engine carry no _rk; assign a stable Hostname|PluginID key.
        function findingKey(ev) { return (ev.Hostname != null && ev.PluginID != null) ? (ev.Hostname + '|' + ev.PluginID) : (ev._rk || ev.Hostname || null); }

        function refreshCount(res) {
          var n = grid.rows().length;
          var loaded = (res && res.summary && res.summary.loaded != null) ? res.summary.loaded : n;
          countLbl.textContent = loaded ? ('Showing ' + n + ' finding(s); ' + loaded + ' loaded in session') : 'No findings loaded';
          countLbl.className = loaded ? 'st-ok' : 'muted';
          refreshCatOptions();
        }

        importBtn.onclick = function () {
          pickAndUpload('.nessus,.csv,.tsv', function (path) {
            log.banner('ACAS Parse File');
            // findings rows arrive without _rk -> set a Hostname|PluginID key so a host with many plugins shows many rows.
            grid.clear(); prog.reset();
            var h = ctx.run('acas-parse-file', { FilePath: path, Append: appendCb._cb.checked }, { keyOf: findingKey });
            resub('acas-parse-file', h.subscribe({
              status: function (t) { prog.setPhase(t); log.append({ text: t, level: 'mode' }); },
              progress: function (p) { prog.setProgress(p.done, p.total); },
              row: function (r) { if (!r._rk) r._rk = findingKey(r); grid.upsert(r); },
              log: function (l) { log.append(l); },
              error: function (e) { log.append({ text: e.text, level: 'err' }); },
              final: function (res) {
                var s = res && res.summary || {};
                log.banner('Parsed ' + (s.total || 0) + ' finding(s); ' + (s.loaded || 0) + ' loaded' + (s.duplicatesSkipped ? ', ' + s.duplicatesSkipped + ' dup(s) skipped' : ''));
                refreshCount(res);
              }
            }));
          });
        };

        loadJsonBtn.onclick = function () {
          pickAndUpload('.json', function (path) {
            log.banner('ACAS Load Report (JSON)');
            grid.clear(); prog.reset();
            var h = ctx.run('acas-load-report', { file: path }, { keyOf: findingKey });
            resub('acas-load-report', h.subscribe({
              status: function (t) { prog.setPhase(t); log.append({ text: t, level: 'mode' }); },
              progress: function (p) { prog.setProgress(p.done, p.total); },
              // load-report now streams each loaded finding (same shape as parse-file) -> repaint the grid.
              row: function (r) { if (!r._rk) r._rk = findingKey(r); grid.upsert(r); },
              log: function (l) { log.append(l); },
              error: function (e) { log.append({ text: e.text, level: 'err' }); },
              final: function (res) {
                var s = res && res.summary || {};
                log.banner('Loaded ' + (s.total || 0) + ' finding(s) across ' + (s.hosts || '?') + ' host(s) from ' + (s.file || 'report'));
                refreshCount(res);
              }
            }));
          });
        };

        saveJsonBtn.onclick = function () {
          log.banner('ACAS Save Report (JSON)');
          var h = ctx.run('acas-save-report', {});
          resub('acas-save-report', h.subscribe({
            log: function (l) { log.append(l); },
            error: function (e) { log.append({ text: e.text, level: 'err' }); },
            final: function (res) { artifact.set(res && res.summary, 'ReportsTool_Findings'); }
          }));
        };

        iavmAddBtn.onclick = function () {
          var cve = (iavmCveInput.value || '').trim();
          var iava = (iavmIdInput.value || '').trim();
          if (!cve || !iava) { ctx.confirm({ title: 'Missing input', body: 'Enter both a CVE and an IAVA / bulletin id.', okText: 'OK', cancelText: null }); return; }
          log.banner('Add IAVM Mapping');
          var h = ctx.run('iavm-add-map', { cve: cve, iava: iava, title: (iavmTitleInput.value || '').trim() });
          resub('iavm-add-map', h.subscribe({
            row: function (r) { log.append({ text: r.Status + ' ' + r.CVE + ' -> ' + r.IAVA, level: 'ok' }); },
            log: function (l) { log.append(l); },
            error: function (e) { log.append({ text: e.text, level: 'err' }); },
            final: function (res) {
              var s = res && res.summary || {};
              if (!s.saveError) { iavmCveInput.value = ''; iavmIdInput.value = ''; iavmTitleInput.value = ''; }
              log.banner('IAVM map: ' + (s.total || 0) + ' mapping(s)');
            }
          }));
        };

        function submitMarkStatus(newStatus, keys, count) {
          log.banner('Mark ' + count + ' finding(s): ' + newStatus);
          var params = { keys: keys, newStatus: newStatus };
          if (newStatus === 'Patched') { params.patchedBy = patchedByInput.value || ''; params.patchedDate = patchedDateInput.value || ''; }
          var h = ctx.run('acas-mark-status', params, { keyOf: function (ev) { return (ev.Hostname && ev.PluginID) ? (ev.Hostname + '|' + ev.PluginID) : null; } });
          resub('acas-mark-status', h.subscribe({
            row: function (r) {
              // patch the matching grid row's Status/Category visually. Engine emits the TRUE
              // recomputed Category; only set it when present so Object.assign never clobbers
              // a good cached Category with undefined (was blanking the cell on Patched/Open).
              var k = r.Hostname + '|' + r.PluginID;
              var patch = { _rk: k, Hostname: r.Hostname, PluginID: r.PluginID, Status: (r.Status || r.NewStatus) };
              if (r.Category != null) patch.Category = r.Category;
              grid.upsert(patch);
              log.append({ text: '[' + k + '] ' + r.NewStatus + ' - ' + (r.Outcome || ''), level: 'ok' });
            },
            log: function (l) { log.append(l); },
            error: function (e) { log.append({ text: e.text, level: 'err' }); },
            final: function (res) { var s = res && res.summary || {}; log.banner('Triage: ' + (s.changed || 0) + ' changed, ' + (s.unmatched || 0) + ' unmatched'); refreshCount(); }
          }));
        }
        function markStatus(newStatus) {
          var checked = grid.getChecked();
          if (!checked.length) { ctx.confirm({ title: 'No rows selected', body: 'Check one or more findings first.', okText: 'OK', cancelText: null }); return; }
          submitMarkStatus(newStatus, checked.map(function (r) { return r.Hostname + '|' + r.PluginID; }).join('\n'), checked.length);
        }
        function markAllVisible(newStatus) {
          var vis = grid.rows().filter(findingPredicate);
          if (!vis.length) { ctx.confirm({ title: 'Nothing visible', body: 'No findings match the current filter.', okText: 'OK', cancelText: null }); return; }
          ctx.confirm({ title: 'Mark all visible', body: 'Mark all ' + vis.length + ' finding(s) currently shown by the filter as <b>' + esc(newStatus) + '</b>?', okText: 'Mark ' + vis.length, cancelText: 'Cancel' }).then(function (ok) {
            if (!ok) return;
            submitMarkStatus(newStatus, vis.map(function (r) { return r.Hostname + '|' + r.PluginID; }).join('\n'), vis.length);
          });
        }
        markPatched.onclick = function () { markStatus('Patched'); };
        markNop.onclick = function () { markStatus('NOT OUR PATCH'); };
        markOpen.onclick = function () { markStatus('Open'); };
        markAllPatched.onclick = function () { markAllVisible('Patched'); };
        markAllNop.onclick = function () { markAllVisible('NOT OUR PATCH'); };

        exportBtn.onclick = function () {
          artifact.reset();
          log.banner('Export Findings (CSV): ' + viewSel.value);
          var h = ctx.run('acas-export-findings', { view: viewSel.value });
          resub('acas-export-findings', h.subscribe({
            log: function (l) { log.append(l); },
            error: function (e) { log.append({ text: e.text, level: 'err' }); },
            final: function (res) { artifact.set(res && res.summary, 'ReportsTool_Findings'); }
          }));
        };

        acasImport = { grid: grid, refreshCount: refreshCount };
      }

      // ---- Remediation Plan -------------------------------------------------------
      function buildRemediation(panel) {
        panelFlex(panel);
        panel.appendChild(sectionTitle('REMEDIATION PLAN', true));
        panel.appendChild(hint('Per-app buckets (Chrome / Edge / Office / Defender / KB / Other) of hosts behind the target version, built from the loaded findings. The KEV column counts hosts in the bucket with a known-exploited finding; KEV buckets sort first. Mark a bucket Pushed / Skipped to drop it from the next refresh.'));

        var row = btnRow();
        var netInput = ui.number({ value: 0, min: 0, title: 'Total devices on the network (for % of fleet; 0 = hide).' }); netInput.style.width = '120px';
        var refreshBtn = ui.button('Refresh Plan', { variant: 'cyan', size: 'sm', title: 'Rebuild the remediation plan from current findings.' });
        row.appendChild(ui.label('Network size')); row.appendChild(netInput); row.appendChild(refreshBtn);
        panel.appendChild(row);

        var grid = C.ResultsGrid({
          title: 'Remediation plan', keyMode: { hostCol: 'App' }, popOut: true,
          // KEV rows sort first by default (dir -1 on the KEV host count) so
          // known-exploited buckets lead the plan; ties keep the emitted app order.
          sort: { key: 'KevCount', dir: -1 },
          columns: [
            { key: 'App', label: 'APP / GROUP', width: 200 },
            { key: 'TargetCount', label: 'HOSTS BEHIND', width: 110, colorRule: gt0cls('st-warn') },
            { key: 'TargetVersion', label: 'TARGET VERSION', width: 160 },
            { key: 'CriticalCount', label: 'CRITICAL', width: 90, colorRule: gt0cls('st-bad') },
            { key: 'HighCount', label: 'HIGH', width: 90, colorRule: gt0cls('st-warn') },
            // KEV = distinct hosts in the bucket with a known-exploited finding.
            { key: 'KevCount', label: 'KEV', width: 70, sortVal: function (r) { return +r.KevCount || 0; }, colorRule: gt0cls('st-bad') }
          ],
          rowClass: function (r) { return (+r.KevCount > 0) ? 'row-bad' : ''; }
        });
        var gh = gridHolder(grid, 200); gh.style.flex = '1'; panel.appendChild(gh);
        var prog = C.ProgressStatusStrip({ showCount: false }); prog.el.style.marginTop = '6px'; panel.appendChild(prog.el);

        // Mark Pushed/Skipped/Pending control (desktop per-card Mark Pushed buttons).
        var markRow = btnRow(); markRow.style.marginTop = '10px';
        markRow.appendChild(ui.eyebrow('MARK PUSH STATUS'));
        var appInput = ui.input({ placeholder: 'App bucket or group (e.g. Chrome, Plugin 12345, Other: <name>)', title: 'As shown in the plan grid.' }); appInput.style.width = '340px';
        var statusSel = ui.select({ options: ['Pushed', 'Skipped', 'Pending'], value: 'Pushed' });
        var markBtn = ui.button('Mark', { variant: 'gold', size: 'sm' });
        markRow.appendChild(appInput); markRow.appendChild(statusSel); markRow.appendChild(markBtn);
        panel.appendChild(markRow);

        // per-bucket host actions (#9): pick a plan row, copy or export its affected hosts.
        var hostsRow = btnRow(); hostsRow.style.marginTop = '10px';
        var bucketSel = ui.select({ options: ['(refresh the plan first)'], title: 'Pick an app bucket / group to copy or export its affected hosts.' }); bucketSel.style.minWidth = '300px';
        var copyHostsBtn = ui.ghostButton('Copy Hosts', { size: 'sm', title: 'Copy the affected hosts for the selected bucket, one per line.' });
        var exportHostsBtn = ui.ghostButton('Export CSV', { size: 'sm', title: 'Download App,Host rows for the selected bucket.' });
        hostsRow.appendChild(ui.eyebrow('HOSTS BEHIND')); hostsRow.appendChild(bucketSel); hostsRow.appendChild(copyHostsBtn); hostsRow.appendChild(exportHostsBtn);
        panel.appendChild(hostsRow);

        function refreshBucketOptions() {
          var rows = grid.rows();
          bucketSel.innerHTML = '';
          if (!rows.length) { var op = document.createElement('option'); op.value = ''; op.textContent = '(refresh the plan first)'; bucketSel.appendChild(op); return; }
          rows.forEach(function (r) { var op = document.createElement('option'); op.value = String(r.App); op.textContent = String(r.App) + ' (' + (r.TargetCount || 0) + ' host' + ((+r.TargetCount === 1) ? '' : 's') + ')'; bucketSel.appendChild(op); });
        }
        function selectedBucketHosts() {
          var app = bucketSel.value; if (!app) return { app: app, hosts: [] };
          var match = grid.rows().filter(function (r) { return String(r.App) === app; })[0];
          var raw = (match && match.Hosts != null) ? String(match.Hosts) : '';
          return { app: app, hosts: raw.split('\n').map(function (s) { return s.trim(); }).filter(Boolean) };
        }
        copyHostsBtn.onclick = function () {
          var sel = selectedBucketHosts();
          if (!sel.hosts.length) { ctx.confirm({ title: 'No hosts', body: 'No affected hosts for that bucket - Refresh the plan first.', okText: 'OK', cancelText: null }); return; }
          var txt = sel.hosts.join('\n');
          if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(txt).then(function () { log.append({ text: 'Copied ' + sel.hosts.length + ' host(s) for ' + sel.app + '.', level: 'accent' }); }).catch(function () {});
        };
        exportHostsBtn.onclick = function () {
          var sel = selectedBucketHosts();
          if (!sel.hosts.length) { ctx.confirm({ title: 'No hosts', body: 'No affected hosts for that bucket - Refresh the plan first.', okText: 'OK', cancelText: null }); return; }
          var csv = ctx.util.toCsv(['App', 'Host'], sel.hosts.map(function (hn) { return [sel.app, hn]; }));
          ctx.util.downloadBlob('ReportsTool_RemediationHosts_' + ctx.util.fileStamp() + '.csv', 'text/csv', csv);
        };

        refreshBtn.onclick = function () {
          log.banner('Remediation Refresh');
          grid.clear(); prog.reset();
          runIntoGrid('remediation-refresh', { NetworkDeviceCount: Math.max(0, parseInt(netInput.value, 10) || 0) }, {
            grid: grid, prog: prog, keyOf: function (ev) { return ev.App != null ? String(ev.App) : null; },
            onFinal: function (res) { var s = res && res.summary || {}; log.banner('Plan: ' + (s.total || 0) + ' row(s), ' + (s.otherGroups || 0) + ' other group(s)' + (s.kevBuckets ? ', ' + s.kevBuckets + ' with KEV' : '')); refreshBucketOptions(); }
          });
        };
        markBtn.onclick = function () {
          var app = (appInput.value || '').trim();
          if (!app) { ctx.confirm({ title: 'No app/group', body: 'Type a bucket (Chrome/Edge/Office/Defender/KB/Other) or an Other-vuln group (Plugin <id> / bare id / "Other: <name>").', okText: 'OK', cancelText: null }); return; }
          log.banner('Mark ' + app + ' -> ' + statusSel.value);
          var h = ctx.run('remediation-mark-pushed', { app: app, status: statusSel.value }, { keyOf: function (ev) { return ev.App != null ? String(ev.App) : null; } });
          resub('remediation-mark-pushed', h.subscribe({
            row: function (r) { log.append({ text: r.App + ' -> ' + r.NewStatus + ' (' + (r.RowsChanged || 0) + ' row(s))', level: 'ok' }); },
            log: function (l) { log.append(l); },
            error: function (e) { log.append({ text: e.text, level: 'err' }); },
            final: function () { /* re-run refresh to repaint with the row dropped */ log.append({ text: 'Tip: Refresh Plan to repaint without the pushed/skipped bucket.', level: 'dim' }); }
          }));
        };
      }

      // ---- Remediation Router (scan-to-patch correlation) -------------------------
      //  Groups the loaded OPEN findings by bucket and maps each to a concrete JANET
      //  tool/action/profile (engine action 'remediation-route'). Each routable route
      //  gets a "Send to <tool>" button that loads its hosts into the SHARED target
      //  list (ctx.targets) and hands off to the mapped tool via ctx.openTool.
      function isRoutable(r) { return !!(r && String(r.ToolId || '')); }
      function buildRouter(panel) {
        panelFlex(panel);
        panel.appendChild(sectionTitle('REMEDIATION ROUTER', true));
        panel.appendChild(hint('Scan-to-patch correlation: every OPEN (not-yet-Patched) finding is grouped by bucket and mapped to the JANET remediation that clears it - ACAS Run Vulnerability Update (browser / Office / Defender / unquoted-service-path profiles), WPT Install KBs, or the Unsupported Product Remediator (upr) for EOL / not-our-patch products. Buckets with no safe one-click route (registry / GPO hardening, Apache, Other) need manual review. Use "Send to &lt;tool&gt;" to hand a route\'s hosts to the mapped tool - WPT reads the shared target list; acas/upr get the hosts on your clipboard to paste/import (they scan their own imported host set).'));

        var row = btnRow();
        var routeBtn = ui.button('Route Findings', { variant: 'cyan', size: 'sm', title: 'Correlate the loaded open findings to their JANET remediation routes.' });
        row.appendChild(routeBtn);
        panel.appendChild(row);

        var grid = C.ResultsGrid({
          title: 'Remediation routes', keyMode: { hostCol: 'Bucket' }, popOut: true,
          sort: { key: 'FindingCount', dir: -1 },
          columns: [
            { key: 'Bucket', label: 'BUCKET', width: 150 },
            { key: 'Tool', label: 'TOOL', width: 80, colorRule: function (v) { return (String(v) === '-') ? 'cell-dim' : 'st-ok'; } },
            { key: 'Action', label: 'ACTION', width: 180, colorRule: function (v) { return /manual review/i.test(String(v)) ? 'st-warn' : ''; } },
            { key: 'Profile', label: 'PROFILE', width: 230, render: function (r) { var v = String(r.Profile == null ? '-' : r.Profile); return { text: v, cls: (v === '-') ? 'cell-dim' : '', title: v }; } },
            { key: 'FindingCount', label: 'FINDINGS', width: 90, sortVal: function (r) { return +r.FindingCount || 0; }, colorRule: gt0cls('st-warn') },
            { key: 'HostCount', label: 'HOSTS', width: 80, sortVal: function (r) { return +r.HostCount || 0; }, colorRule: gt0cls('st-info') },
            { key: 'HostsDisplay', label: 'AFFECTED HOSTS', width: 260, render: function (r) { var v = String(r.HostsDisplay == null ? '' : r.HostsDisplay); return { text: v, cls: v ? '' : 'cell-dim', title: v }; } },
            { key: 'SamplePlugins', label: 'SAMPLE PLUGINS', width: 190, render: function (r) { var v = String(r.SamplePlugins == null ? '' : r.SamplePlugins); return { text: v, cls: v ? '' : 'cell-dim', title: v }; } }
          ],
          // manual-review buckets are the attention case - tint them amber.
          rowClass: function (r) { return isRoutable(r) ? '' : 'row-warn'; }
        });
        var gh = gridHolder(grid, 200); gh.style.flex = '1'; panel.appendChild(gh);
        var prog = C.ProgressStatusStrip({ showCount: false }); prog.el.style.marginTop = '6px'; panel.appendChild(prog.el);

        // "SEND TO TOOL" panel: one button per routable route (rebuilt after each run).
        var sendWrap = el('div'); sendWrap.style.cssText = 'margin-top:10px';
        sendWrap.appendChild(ui.eyebrow('SEND TO TOOL'));
        var sendHint = el('div', 'muted', 'Route the findings first, then hand a route\'s hosts to the mapped tool - WPT loads the shared target list; acas/upr copy the hosts to your clipboard to paste/import.');
        sendHint.style.cssText = 'font-size:11px;margin:2px 0 8px';
        sendWrap.appendChild(sendHint);
        var sendPanel = el('div'); sendPanel.style.cssText = 'display:flex;flex-direction:column;gap:6px';
        sendWrap.appendChild(sendPanel);
        panel.appendChild(sendWrap);

        // Tools that consume the SHARED target list (ctx.targets). Today only WPT
        // reads it; acas/upr scan their OWN imported host set, so a bare ctx.targets
        // handoff to them is silently dropped (that was the router bug). For those we
        // put the host list on the clipboard + a transient handoff to paste/import.
        var TARGETS_AWARE = { wpt: true };

        // Copy a route's hosts to the clipboard and stage them on Janet.handoff so the
        // operator can paste/import them into acas/upr (which do not read ctx.targets).
        function stageRouteHosts(hosts, bucket, extra) {
          if (window.Janet && Janet.handoff) { try { Janet.handoff.send(hosts, 'reports route: ' + bucket, extra || null); } catch (e) {} }
          if (navigator.clipboard && navigator.clipboard.writeText) { navigator.clipboard.writeText(hosts.join('\n')).catch(function () {}); }
        }

        // Hand one route's hosts to the mapped tool, then open it. WPT reads the shared
        // target list directly (ctx.targets); acas/upr get the hosts on the clipboard
        // (+ transient handoff) to paste/import, since they scan their own host set.
        // Confirms before overwriting a non-empty shared list (WPT only). Logs BEFORE
        // the handoff (opening the tool unmounts this view).
        function sendRoute(r) {
          var toolId = String(r.ToolId || ''); if (!toolId) return;
          var hosts = String(r.Hosts == null ? '' : r.Hosts).split('\n').map(function (s) { return s.trim(); }).filter(Boolean);
          if (!hosts.length) { ctx.confirm({ title: 'No hosts', body: 'This route has no affected hosts - re-run Route Findings.', okText: 'OK', cancelText: null }); return; }
          var prof = String(r.Profile == null ? '' : r.Profile);
          // A wpt registry-key-apply route carries the reg-catalog KEY in Profile (e.g.
          // 'BHI'); pass it as cvekey via the handoff and deep-link straight to the Reg
          // Key Fixes tab so the fix pre-selects. acas-profile routes are unchanged.
          var isRegKey = (String(r.ActionId || '') === 'registry-key-apply');
          var cvekey = (isRegKey && prof && prof !== '-') ? prof : '';
          var deepTab = isRegKey ? 'regkey' : null;
          var pick = isRegKey ? (cvekey + ' registry fix') : ((prof && prof !== '-') ? (prof + ' profile') : (String(r.Action || '') + ' action'));
          var readsTargets = !!TARGETS_AWARE[toolId];
          var doIt = function () {
            stageRouteHosts(hosts, r.Bucket, cvekey ? { cvekey: cvekey } : null);
            if (readsTargets) {
              ctx.targets.set(hosts.join('\n'));
              log.append({ text: hosts.length + ' host(s) loaded into the shared target list (and copied to clipboard); opened ' + toolId + ' - select the ' + pick + '.', level: 'ok' });
            } else {
              log.append({ text: hosts.length + ' host(s) copied to clipboard; opened ' + toolId + ' - paste/import them there, then select the ' + pick + '. (' + toolId + ' scans its own host set, not the shared target list.)', level: 'ok' });
            }
            if (typeof ctx.openTool === 'function') ctx.openTool(toolId, deepTab);
          };
          if (readsTargets && ctx.targets && ctx.targets.count() > 0) {
            ctx.confirm({
              title: 'Replace shared targets?',
              body: 'The shared target list already has <b>' + ctx.targets.count() + '</b> host(s). Replace it with the <b>' + esc(hosts.length) + '</b> host(s) from the <b>' + esc(r.Bucket) + '</b> route?',
              list: ['Loads: ' + hosts.slice(0, 6).join(', ') + (hosts.length > 6 ? ' ... (+' + (hosts.length - 6) + ' more)' : ''), 'Then opens: ' + toolId],
              okText: 'Replace & Send', cancelText: 'Cancel'
            }).then(function (ok) { if (ok) doIt(); });
          } else { doIt(); }
        }

        function rebuildSendPanel() {
          sendPanel.innerHTML = '';
          var routable = grid.rows().filter(isRoutable);
          if (!routable.length) {
            var none = el('div', 'muted', 'No routable buckets yet - run Route Findings.'); none.style.fontSize = '11px';
            sendPanel.appendChild(none); return;
          }
          routable.forEach(function (r) {
            var line = el('div'); line.style.cssText = 'display:flex;gap:8px;align-items:center;flex-wrap:wrap';
            var prof = String(r.Profile == null ? '' : r.Profile);
            var tail = (prof && prof !== '-') ? (' (' + prof + ')') : (' (' + String(r.Action || '') + ')');
            var b = ui.button('Send to ' + String(r.ToolId), { variant: 'gold', size: 'sm', title: 'Hand ' + (r.HostCount || 0) + ' host(s) to ' + r.ToolId + ' (shared target list for wpt; clipboard for acas/upr) and open it.' });
            b.onclick = (function (row) { return function () { sendRoute(row); }; })(r);
            line.appendChild(b);
            line.appendChild(el('span', 'muted', String(r.Bucket) + ' - ' + (r.HostCount || 0) + ' host(s)' + tail));
            sendPanel.appendChild(line);
          });
        }
        rebuildSendPanel();

        routeBtn.onclick = function () {
          log.banner('Remediation Router');
          grid.clear(); prog.reset(); rebuildSendPanel();
          runIntoGrid('remediation-route', {}, {
            grid: grid, prog: prog, keyOf: function (ev) { return ev.Bucket != null ? String(ev.Bucket) : null; },
            onFinal: function (res) {
              var s = res && res.summary || {};
              log.banner('Routes: ' + (s.total || 0) + ' bucket(s), ' + (s.routableBuckets || 0) + ' routable (' + (s.routablePct || 0) + '% of ' + (s.openFindings || 0) + ' open); ' + (s.manualFindings || 0) + ' need manual review.');
              rebuildSendPanel();
            }
          });
        };
      }

      // ---- Remediation Planner (per-host work queue) ------------------------------
      function buildPlanner(panel) {
        panelFlex(panel);
        panel.appendChild(sectionTitle('REMEDIATION PLANNER (PER-HOST)', true));
        panel.appendChild(hint('Inverts the Remediation Router into a PER-HOST work queue: one row per affected host with the distinct JANET remediations it needs (patch / update / remove), its open-finding count, severity mix (Crit/High/Med/Low), KEV count, and routable-vs-manual split. Worst hosts sort first (KEV, then Critical, then finding count). Read-only planning ONLY - execute each step in the mapped tool (WPT / ACAS / UPR), which keeps its own admin-session + confirm-word + DNS/self guards. Copy a host set to hand off.'));

        var row = btnRow();
        var planBtn = ui.button('Build Plan', { variant: 'cyan', size: 'sm', title: 'Build the per-host remediation work queue from the loaded open findings.' });
        var kevOnly = ui.checkbox('KEV hosts only', { title: 'Filter the grid to hosts with at least one known-exploited (KEV) finding.', onChange: function () { applyKevFilter(); } });
        row.appendChild(planBtn); row.appendChild(kevOnly);
        panel.appendChild(row);

        var grid = C.ResultsGrid({
          title: 'Per-host remediation plan', keyMode: { rk: true }, popOut: true,
          emptyText: 'No plan yet — load findings (ACAS Import) then Build Plan.',
          sort: { key: 'KEV', dir: -1 },
          columns: [
            { key: 'Host', label: 'HOST', width: 220 },
            { key: 'Findings', label: 'OPEN', width: 70, sortVal: function (r) { return +r.Findings || 0; }, colorRule: gt0cls('st-warn') },
            { key: 'Sev', label: 'C/H/M/L', width: 90, title: 'Critical / High / Medium / Low open findings on this host' },
            { key: 'KEV', label: 'KEV', width: 60, sortVal: function (r) { return +r.KEV || 0; }, colorRule: gt0cls('st-bad') },
            { key: 'Routable', label: 'ROUTABLE', width: 90, sortVal: function (r) { return +r.Routable || 0; }, colorRule: gt0cls('st-ok') },
            { key: 'Manual', label: 'MANUAL', width: 80, sortVal: function (r) { return +r.Manual || 0; }, colorRule: gt0cls('st-warn') },
            { key: 'Plan', label: 'WORK QUEUE', width: 380, render: function (r) { var v = String(r.Plan == null ? '' : r.Plan); return { text: v, cls: v ? '' : 'cell-dim', title: v }; } }
          ],
          rowClass: function (r) { return (+r.KEV > 0) ? 'row-bad' : ''; }
        });
        var gh = gridHolder(grid, 220); gh.style.flex = '1'; panel.appendChild(gh);
        var prog = C.ProgressStatusStrip({ showCount: true }); prog.el.style.marginTop = '6px'; panel.appendChild(prog.el);

        // Copy / export the currently-shown host set (respects the KEV filter).
        var actRow = btnRow(); actRow.style.marginTop = '10px';
        var copyBtn = ui.ghostButton('Copy Hosts', { size: 'sm', title: 'Copy the hosts currently shown (one per line) to paste into a tool.' });
        var exportBtn = ui.ghostButton('Export CSV', { size: 'sm', title: 'Download the per-host plan (shown rows) as CSV.' });
        actRow.appendChild(ui.eyebrow('SHOWN HOSTS')); actRow.appendChild(copyBtn); actRow.appendChild(exportBtn);
        panel.appendChild(actRow);

        function kevChecked() { return !!(kevOnly._cb && kevOnly._cb.checked); }
        function shownRows() {
          var rows = grid.rows();
          if (kevChecked()) rows = rows.filter(function (r) { return +r.KEV > 0; });
          return rows;
        }
        function applyKevFilter() { grid.setFilter(kevChecked() ? function (r) { return +r.KEV > 0; } : null); }

        copyBtn.onclick = function () {
          var hosts = shownRows().map(function (r) { return String(r.Host); }).filter(Boolean);
          if (!hosts.length) { ctx.confirm({ title: 'No hosts', body: 'Build the plan first.', okText: 'OK', cancelText: null }); return; }
          if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(hosts.join('\n')).then(function () { log.append({ text: 'Copied ' + hosts.length + ' host(s).', level: 'accent' }); }).catch(function () {});
        };
        exportBtn.onclick = function () {
          var rows = shownRows();
          if (!rows.length) { ctx.confirm({ title: 'No rows', body: 'Build the plan first.', okText: 'OK', cancelText: null }); return; }
          var csv = ctx.util.toCsv(['Host', 'OpenFindings', 'Sev_C_H_M_L', 'KEV', 'Routable', 'Manual', 'WorkQueue'],
            rows.map(function (r) { return [r.Host, r.Findings, r.Sev, r.KEV, r.Routable, r.Manual, r.Plan]; }));
          ctx.util.downloadBlob('ReportsTool_RemediationPlan_' + ctx.util.fileStamp() + '.csv', 'text/csv', csv);
        };

        planBtn.onclick = function () {
          log.banner('Remediation Planner (per-host)');
          grid.clear(); prog.reset();
          runIntoGrid('remediation-plan', {}, {
            grid: grid, prog: prog, keyOf: function (ev) { return ev.Host != null ? String(ev.Host) : null; },
            onFinal: function (res) {
              var s = res && res.summary || {};
              log.banner('Plan: ' + (s.total || 0) + ' host(s), ' + (s.hostsWithRoutes || 0) + ' with a one-click route, over ' + (s.openFindings || 0) + ' open finding(s).');
              applyKevFilter();
            }
          });
        };
      }

      // ---- KBs Needed (from scan) — precise patching -----------------------------
      function buildKbNeeded(panel) {
        panelFlex(panel);
        panel.appendChild(sectionTitle('KBS NEEDED (FROM SCAN)', true));
        panel.appendChild(hint('Extracts the exact KB ids the loaded Tenable/ACAS findings name (plugin + Solution text), so you can push precisely what the scan found. Rolled up by KB with supersedence in mind — one cumulative clears many hosts, so the KB affecting the most hosts leads (KEV first). Findings that name no KB (third-party / version-upgrade) are counted separately — use the Remediation Planner for those. Copy the KB list into Patch Content to check staged-content coverage, or download the per-host Host,KB list to feed the WPT KB Installer.'));

        var row = btnRow();
        var runBtn = ui.button('Extract KBs', { variant: 'cyan', size: 'sm', title: 'Extract the KBs the loaded findings name and roll them up.' });
        var copyKbBtn = ui.ghostButton('Copy KB list', { size: 'sm', title: 'Copy the distinct KB ids (one per line) to paste into Patch Content -> Cross-Reference.' });
        var dlHostBtn = ui.ghostButton('Download Host,KB CSV', { size: 'sm', title: 'Download a per-host Host,KB list to feed the WPT KB Installer.' });
        row.appendChild(runBtn); row.appendChild(copyKbBtn); row.appendChild(dlHostBtn);
        panel.appendChild(row);

        var cards = C.StatCards({ cards: [
          { key: 'total', label: 'DISTINCT KBS', color: 'accent' },
          { key: 'kevKbs', label: 'KEV KBS', color: 'bad' },
          { key: 'hosts', label: 'HOSTS COVERED', color: 'cyan' },
          { key: 'findingsNoKb', label: 'NO-KB FINDINGS', color: 'gold' }
        ] });
        cards.el.style.margin = '8px 0'; panel.appendChild(cards.el);

        var grid = C.ResultsGrid({
          title: 'KBs needed', emptyText: 'No KBs yet — load findings (ACAS Import), then Extract KBs.', keyMode: { rk: true }, popOut: true,
          sort: { key: 'Hosts', dir: -1 },
          columns: [
            { key: 'KB', label: 'KB', width: 120 },
            { key: 'Hosts', label: 'HOSTS', width: 80, sortVal: function (r) { return +r.Hosts || 0; }, colorRule: gt0cls('st-warn') },
            { key: 'Severity', label: 'SEVERITY', width: 90, colorRule: sevCls },
            { key: 'KEV', label: 'KEV', width: 60, sortVal: function (r) { return r.KEV ? 1 : 0; }, colorRule: function (v) { return v ? 'st-bad' : 'cell-dim'; } },
            { key: 'Findings', label: 'FINDINGS', width: 90, sortVal: function (r) { return +r.Findings || 0; } },
            { key: 'SamplePlugins', label: 'SAMPLE PLUGINS', width: 280, render: function (r) { var v = String(r.SamplePlugins == null ? '' : r.SamplePlugins); return { text: v, cls: v ? '' : 'cell-dim', title: v }; } }
          ],
          rowClass: function (r) { return r.KEV ? 'row-bad' : ''; }
        });
        var gh = gridHolder(grid, 200); gh.style.flex = '1'; panel.appendChild(gh);
        var prog = C.ProgressStatusStrip({ showCount: false }); prog.el.style.marginTop = '6px'; panel.appendChild(prog.el);

        var lastSummary = null;
        runBtn.onclick = function () {
          log.banner('KBs Needed (from scan)');
          grid.clear(); cards.reset();
          runIntoGrid('kb-needed', {}, {
            grid: grid, prog: prog, keyOf: function (ev) { return ev.KB != null ? String(ev.KB) : null; },
            onFinal: function (res) {
              var s = res && res.summary || {}; lastSummary = s;
              cards.setAll({ total: s.total || 0, kevKbs: s.kevKbs || 0, hosts: s.hosts || 0, findingsNoKb: s.findingsNoKb || 0 });
              log.banner((s.total || 0) + ' distinct KB(s) (' + (s.kevKbs || 0) + ' KEV) across ' + (s.hosts || 0) + ' host(s); ' + (s.findingsWithKb || 0) + ' finding(s) name a KB, ' + (s.findingsNoKb || 0) + ' have none (use the Planner).');
            }
          });
        };
        copyKbBtn.onclick = function () {
          if (!lastSummary || !lastSummary.kbList) { ctx.confirm({ title: 'No KBs', body: 'Run Extract KBs first.', okText: 'OK', cancelText: null }); return; }
          if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(lastSummary.kbList).then(function () { log.append({ text: 'Copied ' + (lastSummary.total || 0) + ' KB id(s) — paste into Patch Content -> Cross-Reference.', level: 'accent' }); }).catch(function () {});
        };
        dlHostBtn.onclick = function () {
          if (!lastSummary || !lastSummary.perHostCsv) { ctx.confirm({ title: 'No data', body: 'Run Extract KBs first.', okText: 'OK', cancelText: null }); return; }
          ctx.util.downloadBlob('ReportsTool_KBsNeeded_HostKB_' + ctx.util.fileStamp() + '.csv', 'text/csv', lastSummary.perHostCsv);
        };
      }

      // ---- Third-Party Catalog (non-KB product rollup) ----------------------------
      function buildThirdPartyCatalog(panel) {
        panelFlex(panel);
        panel.appendChild(sectionTitle('THIRD-PARTY CATALOG (FROM SCAN)', true));
        panel.appendChild(hint('The flip side of KBs Needed: on a real scan only ~1% of findings name a KB — the rest are third-party / version-upgrade vulns (Chrome, Firefox, Adobe, Java, 7-Zip, Notepad++, VLC, Wireshark, PuTTY, .NET …). This rolls those NON-KB findings up by PRODUCT so the biggest vuln-reduction levers stand out: distinct affected hosts, worst severity, KEV, a representative fixed/target version, the finding count, and the mapped JANET remediation route (same Categorize-Finding + Router mapping the Planner uses). Ranked KEV-first, then most hosts. Read-only — pairs with KBs Needed to cover every open finding.'));

        var row = btnRow();
        var runBtn = ui.button('Build Catalog', { variant: 'cyan', size: 'sm', title: 'Roll the loaded non-KB findings up by third-party product.' });
        row.appendChild(runBtn);
        // "Remediate Selected" HANDOFF: enabled only when exactly one product row is
        // ticked AND that product carries a resolvable route. It NEVER runs a
        // destructive action - it loads that product's affected hosts into the shared
        // target list (wpt) or the clipboard/handoff (acas/upr), then opens the mapped
        // tool so the operator runs the EXISTING gated action there (same ack +
        // credential + DNS/self guards). Mirrors the Remediation Router's sendRoute.
        var remBtn = ui.button('Remediate Selected', { variant: 'gold', size: 'sm', title: 'Tick one product row with a route, then hand its affected hosts to the mapped tool.' });
        remBtn.disabled = true;
        row.appendChild(remBtn);
        panel.appendChild(row);

        var cards = C.StatCards({ cards: [
          { key: 'total', label: 'DISTINCT PRODUCTS', color: 'accent' },
          { key: 'kevProducts', label: 'KEV PRODUCTS', color: 'bad' },
          { key: 'hosts', label: 'HOSTS', color: 'cyan' },
          { key: 'manual', label: 'MANUAL', color: 'gold' }
        ] });
        cards.el.style.margin = '8px 0'; panel.appendChild(cards.el);

        var grid = C.ResultsGrid({
          title: 'Third-party products', emptyText: 'No products yet — load findings (ACAS Import), then Build Catalog.', keyMode: { rk: true }, popOut: true, selectable: true,
          sort: { key: 'Hosts', dir: -1 },
          columns: [
            { key: 'Product', label: 'PRODUCT', width: 180 },
            { key: 'Hosts', label: 'HOSTS', width: 80, sortVal: function (r) { return +r.Hosts || 0; }, colorRule: gt0cls('st-warn') },
            { key: 'Severity', label: 'SEVERITY', width: 90, colorRule: sevCls },
            { key: 'KEV', label: 'KEV', width: 60, sortVal: function (r) { return r.KEV ? 1 : 0; }, colorRule: function (v) { return v ? 'st-bad' : 'cell-dim'; } },
            { key: 'FixedVersion', label: 'FIXED VER', width: 110, render: function (r) { var v = String(r.FixedVersion == null ? '' : r.FixedVersion); return { text: v, cls: (v && v !== '-') ? '' : 'cell-dim' }; } },
            { key: 'Route', label: 'ROUTE', width: 220, render: function (r) { var v = String(r.Route == null ? '' : r.Route); return { text: v, cls: /manual/i.test(v) ? 'cell-dim' : 'st-ok', title: v }; } },
            { key: 'Findings', label: 'FINDINGS', width: 90, sortVal: function (r) { return +r.Findings || 0; } }
          ],
          rowClass: function (r) { return r.KEV ? 'row-bad' : ''; }
        });
        var gh = gridHolder(grid, 200); gh.style.flex = '1'; panel.appendChild(gh);
        var prog = C.ProgressStatusStrip({ showCount: false }); prog.el.style.marginTop = '6px'; panel.appendChild(prog.el);

        // Tools that consume the SHARED target list (ctx.targets) - only WPT reads it;
        // acas/upr scan their OWN imported host set, so they get the hosts on the
        // clipboard + a transient handoff to paste/import (same split as the Router).
        var TP_TARGETS_AWARE = { wpt: true };
        // A product is remediable only if the engine resolved a concrete route
        // (Routable + a RouteTool id). Routeless products (manual / none, e.g. Apache
        // Log4j) are NOT remediable - the button disables with a tooltip for them.
        function isRemediable(r) { return !!(r && r.Routable && String(r.RouteTool || '')); }

        // Re-evaluate the Remediate button after any grid interaction (checkbox / select
        // all). Enabled only when EXACTLY one row is ticked and it is remediable.
        function refreshRemBtn() {
          var sel = grid.getChecked();
          if (sel.length === 0) { remBtn.disabled = true; remBtn.title = 'Tick one product row with a route to remediate.'; return; }
          if (sel.length > 1) { remBtn.disabled = true; remBtn.title = 'Tick exactly one product row to remediate.'; return; }
          var r = sel[0];
          if (!isRemediable(r)) { remBtn.disabled = true; remBtn.title = 'No auto-remediation route — stage an installer or handle manually.'; return; }
          remBtn.disabled = false;
          remBtn.title = 'Load the ' + (r.Hosts || 0) + ' affected host(s) for ' + r.Product + ' into ' + r.RouteTool + ' and open it — review and run the gated action there.';
        }
        // No onSelect hook on ResultsGrid; a delegated click (checkboxes + Select-All all
        // live inside grid.el) covers every selection change. Defer a tick so the grid's
        // own handler mutates its checked-set first.
        grid.el.addEventListener('click', function () { setTimeout(refreshRemBtn, 0); });

        // The HANDOFF itself: prefill targets + navigate. It ENDS here - it never calls
        // ctx.run on a destructive action; the operator runs the gated action in the
        // destination tool. Byte-for-byte the Router's sendRoute behaviour.
        function remediateSelected() {
          var sel = grid.getChecked();
          if (sel.length !== 1) return;
          var r = sel[0];
          if (!isRemediable(r)) return;
          var toolId = String(r.RouteTool || ''); if (!toolId) return;
          var hosts = String(r.HostsList == null ? '' : r.HostsList).split('\n').map(function (s) { return s.trim(); }).filter(Boolean);
          if (!hosts.length) { ctx.confirm({ title: 'No hosts', body: 'This product has no affected hosts — re-run Build Catalog.', okText: 'OK', cancelText: null }); return; }
          var prof = String(r.RouteProfile == null ? '' : r.RouteProfile);
          // wpt registry-key-apply route: Profile carries the reg-catalog KEY (cvekey);
          // pass it via handoff + deep-link to the Reg Key Fixes tab so it pre-selects.
          var isRegKey = (String(r.RouteActionId || '') === 'registry-key-apply');
          var cvekey = (isRegKey && prof) ? prof : '';
          var deepTab = isRegKey ? 'regkey' : null;
          var pick = isRegKey ? (cvekey + ' registry fix') : (prof ? (prof + ' profile') : (String(r.RouteAction || '') + ' action'));
          var readsTargets = !!TP_TARGETS_AWARE[toolId];
          var doIt = function () {
            if (window.Janet && Janet.handoff) { try { Janet.handoff.send(hosts, 'thirdparty: ' + r.Product, cvekey ? { cvekey: cvekey } : null); } catch (e) {} }
            if (navigator.clipboard && navigator.clipboard.writeText) { navigator.clipboard.writeText(hosts.join('\n')).catch(function () {}); }
            if (readsTargets) {
              ctx.targets.set(hosts.join('\n'));
              log.append({ text: 'Loaded ' + hosts.length + ' host(s) for ' + r.Product + ' into ' + toolId + ' (shared target list + clipboard). Review and run the gated ' + pick + ' (admin session required).', level: 'ok' });
            } else {
              log.append({ text: 'Loaded ' + hosts.length + ' host(s) for ' + r.Product + '; copied to clipboard for ' + toolId + '. Paste/import them, then review and run the gated ' + pick + ' (admin session required). ' + toolId + ' scans its own host set, not the shared target list.', level: 'ok' });
            }
            if (typeof ctx.openTool === 'function') ctx.openTool(toolId, deepTab);
          };
          if (readsTargets && ctx.targets && ctx.targets.count() > 0) {
            ctx.confirm({
              title: 'Replace shared targets?',
              body: 'The shared target list already has <b>' + ctx.targets.count() + '</b> host(s). Replace it with the <b>' + esc(hosts.length) + '</b> host(s) affected by <b>' + esc(r.Product) + '</b>?',
              list: ['Loads: ' + hosts.slice(0, 6).join(', ') + (hosts.length > 6 ? ' … (+' + (hosts.length - 6) + ' more)' : ''), 'Then opens: ' + toolId],
              okText: 'Replace & Remediate', cancelText: 'Cancel'
            }).then(function (ok) { if (ok) doIt(); });
          } else { doIt(); }
        }
        remBtn.onclick = remediateSelected;

        runBtn.onclick = function () {
          log.banner('Third-Party Catalog (from scan)');
          grid.clear(); cards.reset(); refreshRemBtn();
          runIntoGrid('thirdparty-catalog', {}, {
            grid: grid, prog: prog, keyOf: function (ev) { return ev.Product != null ? String(ev.Product) : null; },
            onFinal: function (res) {
              var s = res && res.summary || {};
              cards.setAll({ total: s.total || 0, kevProducts: s.kevProducts || 0, hosts: s.hosts || 0, manual: s.manual || 0 });
              log.banner((s.total || 0) + ' third-party product(s) (' + (s.kevProducts || 0) + ' KEV) across ' + (s.hosts || 0) + ' host(s); ' + (s.routable || 0) + ' routable, ' + (s.manual || 0) + ' manual — from ' + (s.thirdPartyFindings || 0) + ' non-KB finding(s).');
              refreshRemBtn();
            }
          });
        };
      }

      // ---- IAVM Board (DoD compliance rollup by bulletin) -------------------------
      function buildIavmBoard(panel) {
        panelFlex(panel);
        panel.appendChild(sectionTitle('IAVM BOARD (COMPLIANCE ROLLUP)', true));
        panel.appendChild(hint('DoD grades technical-vulnerability compliance by IAVA/IAVM bulletin, not by raw CVE. Each loaded finding is IAVA-tagged from the shipped CVE→bulletin map; this rolls the OPEN (not-yet-Patched) findings up BY BULLETIN so you see compliance the way the inspector does: distinct affected hosts, worst severity, KEV, open finding count, a sample of the bulletin\'s CVEs, and sample plugin ids. Ranked KEV-first, then most hosts, then worst severity. Findings that carry no IAVA are counted separately — not every plugin maps to a bulletin (extend JanetLocal\\IavmMap.csv to raise coverage). The parsed scan carries no per-bulletin compliance/due date, so this is a pure counts rollup (no overdue bucketing). Read-only.'));

        var row = btnRow();
        var runBtn = ui.button('Build Board', { variant: 'cyan', size: 'sm', title: 'Roll the loaded OPEN findings up by IAVA/IAVM bulletin.' });
        row.appendChild(runBtn);
        panel.appendChild(row);

        var cards = C.StatCards({ cards: [
          { key: 'total', label: 'IAVA BULLETINS', color: 'accent' },
          { key: 'kevIavas', label: 'KEV IAVAS', color: 'bad' },
          { key: 'hosts', label: 'HOSTS', color: 'cyan' },
          { key: 'findingsNoIava', label: 'NO-IAVA FINDINGS', color: 'gold' }
        ] });
        cards.el.style.margin = '8px 0'; panel.appendChild(cards.el);

        var grid = C.ResultsGrid({
          title: 'IAVM bulletins', emptyText: 'No bulletins yet — load findings (ACAS Import), then Build Board.', keyMode: { rk: true }, popOut: true,
          sort: { key: 'Hosts', dir: -1 },
          columns: [
            { key: 'IAVA', label: 'IAVA', width: 150 },
            { key: 'Hosts', label: 'HOSTS', width: 80, sortVal: function (r) { return +r.Hosts || 0; }, colorRule: gt0cls('st-warn') },
            { key: 'Severity', label: 'SEVERITY', width: 90, colorRule: sevCls },
            { key: 'KEV', label: 'KEV', width: 60, sortVal: function (r) { return r.KEV ? 1 : 0; }, colorRule: function (v) { return v ? 'st-bad' : 'cell-dim'; } },
            { key: 'Findings', label: 'FINDINGS', width: 90, sortVal: function (r) { return +r.Findings || 0; } },
            { key: 'CVEs', label: 'CVES', width: 240, render: function (r) { var v = String(r.CVEs == null ? '' : r.CVEs); return { text: v, cls: v ? '' : 'cell-dim', title: v }; } },
            { key: 'Plugins', label: 'SAMPLE PLUGINS', width: 240, render: function (r) { var v = String(r.Plugins == null ? '' : r.Plugins); return { text: v, cls: v ? '' : 'cell-dim', title: v }; } }
          ],
          rowClass: function (r) { return r.KEV ? 'row-bad' : ''; }
        });
        var gh = gridHolder(grid, 200); gh.style.flex = '1'; panel.appendChild(gh);
        var prog = C.ProgressStatusStrip({ showCount: false }); prog.el.style.marginTop = '6px'; panel.appendChild(prog.el);

        runBtn.onclick = function () {
          log.banner('IAVM Board (compliance rollup)');
          grid.clear(); cards.reset();
          runIntoGrid('iavm-board', {}, {
            grid: grid, prog: prog, keyOf: function (ev) { return ev.IAVA != null ? String(ev.IAVA) : null; },
            onFinal: function (res) {
              var s = res && res.summary || {};
              cards.setAll({ total: s.total || 0, kevIavas: s.kevIavas || 0, hosts: s.hosts || 0, findingsNoIava: s.findingsNoIava || 0 });
              log.banner((s.total || 0) + ' IAVA bulletin(s) (' + (s.kevIavas || 0) + ' KEV) across ' + (s.hosts || 0) + ' host(s); ' + (s.findingsWithIava || 0) + ' open finding(s) map to a bulletin, ' + (s.findingsNoIava || 0) + ' carry no IAVA.');
            }
          });
        };
      }

      // ---- Posture Digest (self-contained posture snapshot to disk) ----
      function buildPostureDigest(panel) {
        panelFlex(panel);
        panel.appendChild(sectionTitle('POSTURE DIGEST (NIGHTLY SNAPSHOT)', true));
        panel.appendChild(hint('Renders the current vuln posture — severity + host totals, SLA aging posture, top KEV exposure, top third-party products, top KBs needed, and IAVA bulletins — to a self-contained HTML file + a CSV on disk. No email/infra needed: point Output Folder at a UNC audit share and the snapshot lands where the whole shop can read it.'));

        var row = btnRow();
        var outInput = ui.input({ type: 'text', placeholder: 'JanetLocal\\digests (blank = default; can be \\\\server\\share\\Digests)', title: 'Folder the HTML + CSV are written to. Can be a UNC share so the snapshot lands where the shop can read it.' });
        outInput.style.cssText = 'flex:1;min-width:260px';
        var titleInput = ui.input({ type: 'text', placeholder: 'Report title (optional)', title: 'Optional title shown on the HTML digest.' });
        titleInput.style.width = '200px';
        var runBtn = ui.button('Generate now', { variant: 'gold', size: 'sm', title: 'Build the digest from the currently loaded findings and write it to Output Folder.' });
        row.appendChild(ui.eyebrow('OUTPUT FOLDER')); row.appendChild(outInput); row.appendChild(titleInput); row.appendChild(runBtn);
        panel.appendChild(row);

        var cards = C.StatCards({ cards: [
          { key: 'total', label: 'OPEN FINDINGS', color: 'accent' },
          { key: 'kev', label: 'KEV', color: 'bad' },
          { key: 'overdue', label: 'SLA OVERDUE', color: 'warn' }
        ] });
        cards.el.style.margin = '8px 0'; panel.appendChild(cards.el);

        var prog = C.ProgressStatusStrip({ showCount: false }); prog.el.style.marginTop = '6px'; panel.appendChild(prog.el);

        var noteBox = el('div', 'muted'); noteBox.style.cssText = 'font-size:12px;margin-top:10px;white-space:pre-wrap;font-family:Consolas,monospace';
        noteBox.textContent = 'Not generated yet.';
        panel.appendChild(noteBox);
        var spacer = el('div'); spacer.style.flex = '1'; panel.appendChild(spacer);

        runBtn.onclick = function () {
          log.banner('Posture Digest');
          cards.reset(); prog.reset();
          noteBox.className = 'muted'; noteBox.textContent = 'Generating...';
          runIntoGrid('posture-digest', { outDir: (outInput.value || '').trim(), title: (titleInput.value || '').trim() }, {
            prog: prog,
            onFinal: function (res) {
              var s = res && res.summary || {};
              cards.setAll({ total: s.totalFindings || 0, kev: s.kev || 0, overdue: s.overdue || 0 });
              if (s.ok) {
                noteBox.className = 'st-ok';
                noteBox.textContent = 'HTML: ' + s.htmlPath + '\nCSV:  ' + s.csvPath;
                log.banner('Posture digest written: ' + (s.totalFindings || 0) + ' open finding(s), ' + (s.hosts || 0) + ' host(s), ' + (s.kev || 0) + ' KEV.');
              } else {
                noteBox.className = 'st-warn';
                noteBox.textContent = s.error ? ('Not written: ' + s.error) : 'Nothing to snapshot — load ACAS findings first (ACAS Import tab).';
                log.append({ text: 'Posture digest not written' + (s.error ? (': ' + s.error) : ' (no findings loaded).'), level: 'warn' });
              }
            }
          });
        };
      }

      // ---- Burndown (persisted vuln-backlog trend) --------------------------------
      // Builds a tiny inline-SVG line/area chart from summary.series (no chart lib):
      // totalOpen as a filled area + line, kev as a thin dashed line, scaled to the
      // series' own min/max. Degrades to a text hint for 0/1 points.
      function buildBurndownSvg(series) {
        var W = 640, H = 170, padTop = 14, padBottom = 22, padLeft = 34, padRight = 10;
        var n = series.length;
        var opens = series.map(function (p) { return +p.totalOpen || 0; });
        var kevs = series.map(function (p) { return +p.kev || 0; });
        var maxV = Math.max.apply(null, opens.concat(kevs, [1]));
        var plotW = W - padLeft - padRight, plotH = H - padTop - padBottom;
        function xAt(i) { return padLeft + (n === 1 ? plotW / 2 : (i / (n - 1)) * plotW); }
        function yAt(v) { return padTop + plotH - (maxV > 0 ? (v / maxV) * plotH : 0); }
        function fmtDate(ts) { try { var d = new Date(ts); if (isNaN(d.getTime())) return String(ts); return (d.getMonth() + 1) + '/' + d.getDate(); } catch (e) { return String(ts); } }

        var svgNS = 'http://www.w3.org/2000/svg';
        var svg = document.createElementNS(svgNS, 'svg');
        svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);
        svg.setAttribute('preserveAspectRatio', 'none');
        svg.style.cssText = 'width:100%;height:170px;display:block';

        function line(x1, y1, x2, y2, cls) {
          var l = document.createElementNS(svgNS, 'line');
          l.setAttribute('x1', x1); l.setAttribute('y1', y1); l.setAttribute('x2', x2); l.setAttribute('y2', y2);
          l.setAttribute('class', cls || ''); l.setAttribute('stroke', 'var(--line-soft)'); l.setAttribute('stroke-width', '1');
          return l;
        }
        function text(x, y, str, anchor, cls) {
          var t = document.createElementNS(svgNS, 'text');
          t.setAttribute('x', x); t.setAttribute('y', y); t.setAttribute('text-anchor', anchor || 'start');
          t.setAttribute('font-size', '9'); t.setAttribute('font-family', 'Consolas,monospace');
          t.setAttribute('fill', 'var(--text-dim)'); if (cls) t.setAttribute('class', cls);
          t.textContent = str; return t;
        }

        // baseline + top gridlines
        svg.appendChild(line(padLeft, padTop + plotH, padLeft + plotW, padTop + plotH));
        svg.appendChild(line(padLeft, padTop, padLeft + plotW, padTop));
        svg.appendChild(text(padLeft - 6, padTop + 3, String(maxV), 'end'));
        svg.appendChild(text(padLeft - 6, padTop + plotH + 3, '0', 'end'));

        var openPts = opens.map(function (v, i) { return xAt(i) + ',' + yAt(v); }).join(' ');
        var areaPts = openPts + ' ' + xAt(n - 1) + ',' + (padTop + plotH) + ' ' + xAt(0) + ',' + (padTop + plotH);
        var area = document.createElementNS(svgNS, 'polygon');
        area.setAttribute('points', areaPts);
        area.setAttribute('fill', 'var(--accent-wash)');
        svg.appendChild(area);

        var openLine = document.createElementNS(svgNS, 'polyline');
        openLine.setAttribute('points', openPts);
        openLine.setAttribute('fill', 'none'); openLine.setAttribute('stroke', 'var(--accent-2)'); openLine.setAttribute('stroke-width', '2');
        svg.appendChild(openLine);

        var kevPts = kevs.map(function (v, i) { return xAt(i) + ',' + yAt(v); }).join(' ');
        var kevLine = document.createElementNS(svgNS, 'polyline');
        kevLine.setAttribute('points', kevPts);
        kevLine.setAttribute('fill', 'none'); kevLine.setAttribute('stroke', 'var(--bad)'); kevLine.setAttribute('stroke-width', '1.5'); kevLine.setAttribute('stroke-dasharray', '4 3');
        svg.appendChild(kevLine);

        // point markers (small dots) so single/sparse series are still visible
        opens.forEach(function (v, i) {
          var dot = document.createElementNS(svgNS, 'circle');
          dot.setAttribute('cx', xAt(i)); dot.setAttribute('cy', yAt(v)); dot.setAttribute('r', i === n - 1 ? 3 : 2);
          dot.setAttribute('fill', 'var(--accent-2)');
          svg.appendChild(dot);
        });

        svg.appendChild(text(xAt(0), H - 6, fmtDate(series[0].ts), 'start'));
        svg.appendChild(text(xAt(n - 1), H - 6, fmtDate(series[n - 1].ts), 'end'));
        svg.appendChild(text(xAt(n - 1), yAt(opens[n - 1]) - 7, String(opens[n - 1]) + ' open', n === 1 ? 'middle' : 'end', 'st-accent'));
        if (kevs[n - 1] > 0) svg.appendChild(text(xAt(n - 1), yAt(kevs[n - 1]) + 12, String(kevs[n - 1]) + ' kev', n === 1 ? 'middle' : 'end', 'st-bad'));

        return svg;
      }

      // A single stat tile matching the StatCards look, but with a colour that
      // flips per-value (down=good/green, up=bad/red) — StatCards' colour is
      // fixed at creation so the delta tile is built by hand instead.
      function deltaTile(label) {
        var tile = el('div', 'j-stat accent');
        var num = el('div', 'j-stat-num', '0');
        tile.appendChild(num);
        tile.appendChild(el('div', 'j-stat-cap', label));
        function setValue(delta) {
          var sign = delta > 0 ? '+' : '';
          num.textContent = sign + delta;
          tile.className = 'j-stat ' + (delta < 0 ? 'ok' : (delta > 0 ? 'bad' : 'cyan'));
        }
        return { el: tile, setValue: setValue };
      }

      function buildBurndown(panel) {
        panelFlex(panel);
        panel.appendChild(sectionTitle('BURNDOWN (VULN-BACKLOG TREND)', true));
        panel.appendChild(hint('Persists a point-in-time snapshot of the current vuln backlog (JanetLocal\\trend\\burndown.jsonl) — total open findings, severity mix, KEV, and host count — reusing the same tallies the Dashboard/CORA and Posture Digest use. Take a snapshot after each scan import or remediation wave, then watch the line trend down. Read-only.'));

        var row = btnRow();
        var labelInput = ui.input({ placeholder: 'Snapshot label (optional)', title: 'Optional free-text label for this point (e.g. "post-wave-3").' });
        labelInput.style.width = '220px';
        var snapBtn = ui.button('Snapshot Now', { variant: 'gold', size: 'sm', title: 'Append one point to the trend from the currently loaded findings.' });
        var refreshBtn = ui.button('Refresh Trend', { variant: 'cyan', size: 'sm', title: 'Reload the persisted trend series.' });
        row.appendChild(ui.eyebrow('SNAPSHOT')); row.appendChild(labelInput); row.appendChild(snapBtn); row.appendChild(refreshBtn);
        panel.appendChild(row);

        var cards = C.StatCards({ cards: [
          { key: 'openNow', label: 'OPEN NOW', color: 'accent' },
          { key: 'kevNow', label: 'KEV NOW', color: 'bad' },
          { key: 'snapshots', label: 'SNAPSHOTS', color: 'cyan' }
        ] });
        var delta = deltaTile('DELTA SINCE FIRST');
        cards.el.appendChild(delta.el);
        cards.el.style.margin = '8px 0'; panel.appendChild(cards.el);

        var chartHolder = el('div'); chartHolder.style.cssText = 'border:1px solid var(--line-soft);border-radius:4px;padding:10px 8px 4px;background:var(--bg-rail2)';
        var chartNote = el('div', 'muted', 'Take snapshots over time to see a trend.');
        chartNote.style.cssText = 'font-size:12px;text-align:center;padding:24px 0';
        chartHolder.appendChild(chartNote);
        panel.appendChild(chartHolder);

        var prog = C.ProgressStatusStrip({ showCount: false }); prog.el.style.marginTop = '6px'; panel.appendChild(prog.el);

        var grid = C.ResultsGrid({
          title: 'Snapshots', emptyText: 'No snapshots yet — click Snapshot Now.', keyMode: { rk: true }, popOut: true,
          sort: { key: 'Date', dir: -1 },
          columns: [
            { key: 'Date', label: 'DATE', width: 150 },
            { key: 'TotalOpen', label: 'OPEN', width: 80, sortVal: function (r) { return +r.TotalOpen || 0; } },
            { key: 'Critical', label: 'CRIT', width: 70, colorRule: gt0cls('st-sev-crit') },
            { key: 'High', label: 'HIGH', width: 70, colorRule: gt0cls('st-sev-high') },
            { key: 'KEV', label: 'KEV', width: 70, sortVal: function (r) { return +r.KEV || 0; }, colorRule: gt0cls('st-bad') },
            { key: 'Hosts', label: 'HOSTS', width: 80, sortVal: function (r) { return +r.Hosts || 0; } }
          ]
        });
        var gh = gridHolder(grid, 160); gh.style.flex = '1'; gh.style.marginTop = '10px'; panel.appendChild(gh);
        panel.appendChild(hint('Tip: take a snapshot after every scan import or remediation wave so the trend fills in over time.'));

        function renderChart(series) {
          chartHolder.innerHTML = '';
          if (!series || series.length < 2) {
            var note = el('div', 'muted', series && series.length === 1 ? 'One snapshot recorded — take another to see a trend.' : 'Take snapshots over time to see a trend.');
            note.style.cssText = 'font-size:12px;text-align:center;padding:24px 0';
            chartHolder.appendChild(note);
            return;
          }
          chartHolder.appendChild(buildBurndownSvg(series));
        }

        function refreshTrend() {
          log.banner('Burndown Trend');
          grid.clear(); cards.reset(); prog.reset();
          runIntoGrid('burndown', {}, {
            grid: grid, prog: prog, keyOf: function (ev) { return ev._rk != null ? String(ev._rk) : null; },
            onFinal: function (res) {
              var s = res && res.summary || {};
              cards.setAll({ openNow: s.lastOpen || 0, kevNow: s.lastKev || 0, snapshots: s.points || 0 });
              delta.setValue(s.deltaOpen || 0);
              renderChart(s.series || []);
              if (s.points > 0) {
                log.banner('Burndown: ' + s.points + ' snapshot(s), open ' + (s.firstOpen || 0) + ' -> ' + (s.lastOpen || 0) + ' (' + (s.pctClosed || 0) + '% closed since first).');
              } else {
                log.append({ text: s.note || 'No snapshots yet — take one with Snapshot Now.', level: 'dim' });
              }
            }
          });
        }

        snapBtn.onclick = function () {
          log.banner('Burndown: Snapshot Now');
          var h = ctx.run('burndown-snapshot', { label: (labelInput.value || '').trim() });
          resub('burndown-snapshot', h.subscribe({
            row: function (r) { log.append({ text: r.Field + ': ' + r.Value, level: 'ok' }); },
            log: function (l) { log.append(l); },
            error: function (e) { log.append({ text: e.text, level: 'err' }); },
            final: function (res) {
              var s = res && res.summary || {};
              if (s.ok) { labelInput.value = ''; refreshTrend(); }
              else { log.append({ text: 'Snapshot not recorded — load ACAS findings first (ACAS Import tab).', level: 'warn' }); }
            }
          }));
        };
        refreshBtn.onclick = refreshTrend;
        refreshTrend();   // load on first mount
      }

      // ---- Remediation Campaigns (persisted closed-loop tracking) -----------------
      function buildCampaigns(panel) {
        panelFlex(panel);
        panel.appendChild(sectionTitle('REMEDIATION CAMPAIGNS', true));
        panel.appendChild(hint('Snapshot the currently loaded OPEN findings into a persisted campaign (JanetLocal\\campaigns) that ties finding → fix → re-verify: it records the finding keys, affected hosts, mapped remediations, and severity/KEV mix. Read-only tracking — run the actual remediation through the gated tools, then re-import the next scan (Patch Cross-Ref) to prove closure. Worst hosts first via the Planner.'));

        var row = btnRow();
        var nameInput = ui.input({ placeholder: 'Campaign name (optional)', title: 'A label for this campaign; blank = auto date-stamp.' }); nameInput.style.width = '260px';
        var createBtn = ui.button('Create from loaded findings', { variant: 'go', size: 'sm', title: 'Snapshot the loaded OPEN findings into a new campaign.' });
        var refreshBtn = ui.button('Refresh List', { variant: 'cyan', size: 'sm', title: 'Reload the saved campaigns.' });
        row.appendChild(ui.label('Name')); row.appendChild(nameInput); row.appendChild(createBtn); row.appendChild(refreshBtn);
        panel.appendChild(row);

        var grid = C.ResultsGrid({
          title: 'Saved campaigns', emptyText: 'No campaigns yet — load findings (ACAS Import), then Create from loaded findings.', keyMode: { rk: true }, popOut: true,
          sort: { key: 'Created', dir: -1 },
          columns: [
            { key: 'Name', label: 'CAMPAIGN', width: 220 },
            { key: 'Created', label: 'CREATED', width: 140 },
            { key: 'Status', label: 'STATUS', width: 90, colorRule: function (v) { return /open/i.test(String(v)) ? 'st-warn' : 'st-ok'; } },
            { key: 'OpenFindings', label: 'OPEN', width: 80, sortVal: function (r) { return +r.OpenFindings || 0; }, colorRule: gt0cls('st-warn') },
            { key: 'KEV', label: 'KEV', width: 60, sortVal: function (r) { return +r.KEV || 0; }, colorRule: gt0cls('st-bad') },
            { key: 'Hosts', label: 'HOSTS', width: 80, sortVal: function (r) { return +r.Hosts || 0; }, colorRule: gt0cls('st-info') }
          ],
          rowClass: function (r) { return (+r.KEV > 0) ? 'row-bad' : ''; },
          onRowClick: function (r) { selectedId = String(r._rk || ''); selName.textContent = selectedId ? ('selected: ' + String(r.Name)) : 'none selected'; verifyBtn.disabled = !selectedId; }
        });
        var gh = gridHolder(grid, 200); gh.style.flex = '1'; panel.appendChild(gh);
        var prog = C.ProgressStatusStrip({ showCount: false }); prog.el.style.marginTop = '6px'; panel.appendChild(prog.el);

        // Close-the-loop: verify a selected campaign against a freshly-loaded scan.
        var selectedId = '';
        var verifyRow = btnRow(); verifyRow.style.marginTop = '10px';
        var verifyBtn = ui.button('Verify Selected (close loop)', { variant: 'gold', size: 'sm', title: 'Click a campaign row, load the NEW scan (ACAS Import), then verify: each snapshotted finding still open = still-open, gone = remediated. Marks VERIFIED-CLOSED at 100%.' });
        verifyBtn.disabled = true;
        var selName = el('span', 'muted', 'none selected'); selName.style.fontSize = '11px';
        verifyRow.appendChild(ui.eyebrow('CLOSE THE LOOP')); verifyRow.appendChild(verifyBtn); verifyRow.appendChild(selName);
        panel.appendChild(verifyRow);
        verifyBtn.onclick = function () {
          if (!selectedId) return;
          log.banner('Verify Campaign (close the loop)');
          var h = ctx.run('campaign-verify', { campaignId: selectedId });
          resub('campaign-verify', h.subscribe({
            log: function (l) { log.append(l); },
            error: function (e) { log.append({ text: e.text, level: 'err' }); },
            final: function (res) {
              var s = res && res.summary || {};
              if (s.notFound) { log.append({ text: 'Campaign not found — refresh the list.', level: 'err' }); return; }
              var lvl = (s.status === 'verified-closed') ? 'ok' : 'mode';
              log.banner('Verify: ' + (s.remediated || 0) + ' remediated, ' + (s.stillOpen || 0) + ' still-open of ' + (s.totalKeys || 0) + ' — ' + (s.closedPct || 0) + '% closed. Status: ' + (s.status || '') + '.');
              log.append({ text: 'Load a NEW scan on ACAS Import before verifying, so "remediated" reflects the latest state.', level: 'dim' });
              refreshList();
            }
          }));
        };

        function refreshList() {
          grid.clear();
          runIntoGrid('campaign-list', {}, {
            grid: grid, prog: prog, keyOf: function (ev) { return ev._rk != null ? String(ev._rk) : null; },
            onFinal: function (res) { var s = res && res.summary || {}; log.append({ text: (s.total || 0) + ' saved campaign(s).', level: 'mode' }); }
          });
        }
        createBtn.onclick = function () {
          log.banner('Create Remediation Campaign');
          var h = ctx.run('campaign-create', { name: (nameInput.value || '').trim() });
          resub('campaign-create', h.subscribe({
            row: function (r) { log.append({ text: r.Field + ': ' + r.Value, level: 'ok' }); },
            log: function (l) { log.append(l); },
            error: function (e) { log.append({ text: e.text, level: 'err' }); },
            final: function (res) { var s = res && res.summary || {}; if (s.id) { log.banner('Campaign saved (' + (s.openFindings || 0) + ' open, ' + (s.kev || 0) + ' KEV, ' + (s.hosts || 0) + ' host(s)).'); nameInput.value = ''; refreshList(); } }
          }));
        };
        refreshBtn.onclick = refreshList;
        refreshList();   // load on first mount
      }

      // ---- Patch Cross-Ref (Compare) ----------------------------------------------
      function buildCompare(panel) {
        panelFlex(panel);
        panel.appendChild(sectionTitle('PATCH CROSS-REF (SCAN COMPARE)', true));
        panel.appendChild(hint('Load a BEFORE (baseline) and AFTER (comparison) scan into separate stores, then diff on Hostname|PluginID: REMEDIATED / STILL OPEN / NEW. Apply Remediated marks the baseline-only keys Patched in the working findings set.'));

        var loadRow = btnRow();
        var baseBtn = ui.button('Load Baseline (BEFORE)', { variant: 'cyan', size: 'sm', title: 'Upload + parse the pre-patch scan into the baseline store.' });
        var baseLbl = el('span', 'muted'); baseLbl.style.fontSize = '11px'; baseLbl.textContent = 'no baseline';
        var compBtn = ui.button('Load Comparison (AFTER)', { variant: 'cyan', size: 'sm', title: 'Upload + parse the post-patch scan into the comparison store.' });
        var compLbl = el('span', 'muted'); compLbl.style.fontSize = '11px'; compLbl.textContent = 'no comparison';
        loadRow.appendChild(baseBtn); loadRow.appendChild(baseLbl); loadRow.appendChild(compBtn); loadRow.appendChild(compLbl);
        panel.appendChild(loadRow);

        var filterRow = btnRow();
        var deltaSel = ui.select({ options: ['All', 'REMEDIATED', 'STILL OPEN', 'NEW'], value: 'All', title: 'Filter the diff rows shown.' });
        var hostFilter = ui.input({ placeholder: 'host filter (substring)', title: 'Substring match on hostname; blank = all.' }); hostFilter.style.width = '180px';
        var sevFilter = ui.select({ options: ['All', 'Critical', 'High', 'Medium', 'Low', 'Info'], value: 'All' });
        var compareBtn = ui.button('Compare Scans', { variant: 'go', size: 'sm', title: 'Diff the baseline against the comparison.' });
        var applyBtn = ui.button('Apply Remediated -> Findings', { variant: 'gold', size: 'sm', title: 'Mark every REMEDIATED key Patched in the working findings set.' });
        var clearBtn = ui.ghostButton('Clear Compare State', { size: 'sm', title: 'Free the baseline/comparison stores + last result.' });
        filterRow.appendChild(ui.label('Delta')); filterRow.appendChild(deltaSel);
        filterRow.appendChild(hostFilter); filterRow.appendChild(ui.label('Sev')); filterRow.appendChild(sevFilter);
        filterRow.appendChild(compareBtn); filterRow.appendChild(applyBtn); filterRow.appendChild(clearBtn);
        panel.appendChild(filterRow);

        // Close-the-loop headline: how the AFTER scan moved vs the BEFORE baseline.
        // % CLOSED = remediated / (remediated + still-open) of the baseline findings.
        var deltaCards = C.StatCards({ cards: [
          { key: 'remediated', label: 'REMEDIATED (FIXED)', color: 'ok' },
          { key: 'stillOpen', label: 'STILL OPEN', color: 'gold' },
          { key: 'newFindings', label: 'NEW', color: 'bad' },
          { key: 'closedPct', label: '% BASELINE CLOSED', color: 'accent' }
        ] });
        deltaCards.el.style.marginBottom = '8px';
        panel.appendChild(deltaCards.el);

        var grid = C.ResultsGrid({
          title: 'Scan compare', keyMode: { rk: true }, popOut: true,
          emptyText: 'No comparison yet — load a Baseline + Comparison scan, then Compare Scans.',
          columns: [
            { key: 'Hostname', label: 'HOSTNAME', width: 130 },
            { key: 'PluginID', label: 'PLUGIN', width: 80 },
            { key: 'VulnName', label: 'VULN NAME', width: 320 },
            { key: 'Severity', label: 'SEVERITY', width: 90, colorRule: sevCls },
            { key: 'Delta', label: 'DELTA', width: 130, colorRule: deltaCls }
          ],
          rowClass: function (r) { var c = deltaCls(r.Delta); return c === 'st-ok' ? 'row-ok' : (c === 'st-bad' ? 'row-bad' : (c === 'st-warn' ? 'row-warn' : '')); }
        });
        var gh = gridHolder(grid, 200); gh.style.flex = '1'; panel.appendChild(gh);
        var prog = C.ProgressStatusStrip({ showCount: true }); prog.el.style.marginTop = '6px'; panel.appendChild(prog.el);

        function cmpKey(ev) { return (ev.Hostname != null && ev.PluginID != null) ? (ev.Hostname + '|' + ev.PluginID + '|' + (ev.Delta || '')) : null; }

        baseBtn.onclick = function () {
          pickAndUpload('.nessus,.csv,.tsv', function (path) {
            log.banner('ACAS Load Baseline');
            var h = ctx.run('acas-load-baseline', { file: path });
            resub('acas-load-baseline', h.subscribe({
              row: function (r) { baseLbl.textContent = r.File + ': ' + (r.Findings || 0) + ' finding(s), ' + (r.Hosts || 0) + ' host(s)'; baseLbl.className = 'st-ok'; },
              log: function (l) { log.append(l); }, error: function (e) { log.append({ text: e.text, level: 'err' }); }
            }));
          });
        };
        compBtn.onclick = function () {
          pickAndUpload('.nessus,.csv,.tsv', function (path) {
            log.banner('ACAS Load Comparison');
            var h = ctx.run('acas-load-comparison', { file: path });
            resub('acas-load-comparison', h.subscribe({
              row: function (r) { compLbl.textContent = r.File + ': ' + (r.Findings || 0) + ' finding(s), ' + (r.Hosts || 0) + ' host(s)'; compLbl.className = 'st-ok'; },
              log: function (l) { log.append(l); }, error: function (e) { log.append({ text: e.text, level: 'err' }); }
            }));
          });
        };
        compareBtn.onclick = function () {
          log.banner('ACAS Scan Compare');
          grid.clear(); prog.reset(); deltaCards.reset();
          runIntoGrid('acas-run-compare', { deltaFilter: deltaSel.value, hostFilter: hostFilter.value || '', severityFilter: sevFilter.value }, {
            grid: grid, prog: prog, keyOf: cmpKey,
            onFinal: function (res) {
              var s = res && res.summary || {};
              var fixed = s.remediated || 0, open = s.stillOpen || 0, added = s.newFindings || 0;
              var baseTotal = fixed + open;
              var pct = baseTotal > 0 ? Math.round(fixed / baseTotal * 100) : 0;
              deltaCards.setAll({ remediated: fixed, stillOpen: open, newFindings: added, closedPct: pct + '%' });
              log.banner('Compare: ' + fixed + ' remediated, ' + open + ' still open, ' + added + ' new — ' + pct + '% of baseline closed (delta ' + (s.deltaTotal || 0) + ')');
            }
          });
        };
        applyBtn.onclick = function () {
          ctx.confirm({ title: 'Apply Remediated', body: 'Mark every REMEDIATED (baseline-only) finding Patched in the working findings set?<br>This mutates session state only - re-parse the file to undo.', okText: 'Apply', cancelText: 'Cancel' }).then(function (ok) {
            if (!ok) return;
            log.banner('ACAS Apply Remediated');
            var h = ctx.run('acas-apply-remediated', {});
            resub('acas-apply-remediated', h.subscribe({
              row: function (r) { log.append({ text: (r.Metric || '') + ': ' + (r.Value != null ? r.Value : ''), level: 'ok' }); },
              log: function (l) { log.append(l); }, error: function (e) { log.append({ text: e.text, level: 'err' }); },
              final: function (res) { var s = res && res.summary || {}; log.banner('Applied: ' + (s.marked || 0) + ' marked Patched (' + (s.remediated || 0) + ' remediated keys)'); }
            }));
          });
        };
        clearBtn.onclick = function () {
          log.banner('Clear Compare State');
          grid.clear(); deltaCards.reset(); baseLbl.textContent = 'no baseline'; baseLbl.className = 'muted'; compLbl.textContent = 'no comparison'; compLbl.className = 'muted';
          var h = ctx.run('acas-clear-state', {});
          resub('acas-clear-state', h.subscribe({ row: function (r) { log.append({ text: (r.Store || '') + ': ' + (r.Cleared != null ? r.Cleared : ''), level: 'dim' }); }, log: function (l) { log.append(l); }, error: function (e) { log.append({ text: e.text, level: 'err' }); } }));
        };

        // ---- Wave closure proof (audit-trail causation join) --------------------
        panel.appendChild(sectionTitle('WAVE CLOSURE PROOF (audit trail)', true));
        panel.appendChild(hint('Prove the wave worked: join every REMEDIATED and STILL OPEN row against the audit trail JANET already writes (TouchedHosts + detail on the log share, local-spool fallback) between the two scan dates. Closed on a host JANET touched = the wave did it; still-open on a touched host = the patch did not take (your next-day worklist).'));

        var proofRow = btnRow();
        var baseDate = ui.input({ placeholder: 'baseline date (YYYY-MM-DD)', title: 'Date of the BEFORE scan = start of the audit window. Blank = 90 days before comparison.' }); baseDate.style.width = '170px';
        var compDate = ui.input({ placeholder: 'comparison date (YYYY-MM-DD)', title: 'Date of the AFTER scan = end of the audit window. Blank = today.' }); compDate.style.width = '170px';
        var proofHost = ui.input({ placeholder: 'host filter (substring)', title: 'Substring match on hostname; blank = all.' }); proofHost.style.width = '160px';
        var proofBtn = ui.button('Prove Closure', { variant: 'go', size: 'sm', title: 'Compare, then attribute each closed / still-open finding to the audit trail.' });
        proofRow.appendChild(ui.label('Baseline')); proofRow.appendChild(baseDate);
        proofRow.appendChild(ui.label('Comparison')); proofRow.appendChild(compDate);
        proofRow.appendChild(proofHost); proofRow.appendChild(proofBtn);
        panel.appendChild(proofRow);

        var proofGrid = C.ResultsGrid({
          title: 'Closure proof', keyMode: { rk: true }, popOut: true,
          columns: [
            { key: 'Hostname', label: 'HOSTNAME', width: 130 },
            { key: 'PluginID', label: 'PLUGIN', width: 80 },
            { key: 'Severity', label: 'SEVERITY', width: 90, colorRule: sevCls },
            { key: 'Delta', label: 'DELTA', width: 120, colorRule: deltaCls },
            { key: 'TouchedByJanet', label: 'JANET?', width: 80, colorRule: touchedCls },
            { key: 'Tool', label: 'TOOL', width: 120 },
            { key: 'Operator', label: 'OPERATOR', width: 180 },
            { key: 'TouchDate', label: 'TOUCH DATE', width: 150 }
          ],
          rowClass: function (r) {
            // STILL OPEN on a touched host = the patch did not take: flag the worklist row.
            if (String(r.Delta) === 'STILL OPEN' && /^yes$/i.test(String(r.TouchedByJanet))) return 'row-bad';
            if (String(r.Delta) === 'REMEDIATED' && /^yes$/i.test(String(r.TouchedByJanet))) return 'row-ok';
            return '';
          }
        });
        var pgh = gridHolder(proofGrid, 180); pgh.style.flex = '1'; panel.appendChild(pgh);
        var proofProg = C.ProgressStatusStrip({ showCount: true }); proofProg.el.style.marginTop = '6px'; panel.appendChild(proofProg.el);

        function proofKey(ev) { return (ev.Hostname != null && ev.PluginID != null) ? (ev.Hostname + '|' + ev.PluginID + '|' + (ev.Delta || '')) : null; }

        proofBtn.onclick = function () {
          log.banner('ACAS Prove Closure');
          proofGrid.clear(); proofProg.reset();
          runIntoGrid('scan-closure-proof', { baselineDate: baseDate.value || '', comparisonDate: compDate.value || '', hostFilter: proofHost.value || '' }, {
            grid: proofGrid, prog: proofProg, keyOf: proofKey,
            onFinal: function (res) {
              var s = res && res.summary || {};
              log.banner('Closure: ' + (s.closedTouched || 0) + ' closed by JANET, ' + (s.closedUntouched || 0) + ' closed by something else, ' + (s.openTouched || 0) + ' still-open on touched hosts (worklist)');
              if (s.windowStart) log.append({ text: 'Window ' + s.windowStart + ' .. ' + s.windowEnd + ' | audit source: ' + (s.source || '') + ' | ' + (s.auditRows || 0) + ' touch row(s) read', level: (s.onShare ? 'info' : 'warn') });
              var wl = (s.worklist || []);
              if (wl.length) {
                log.append({ text: 'NEXT-DAY WORKLIST (' + wl.length + ' still-open on hosts JANET touched):', level: 'warn' });
                for (var i = 0; i < wl.length; i++) {
                  var w = wl[i];
                  log.append({ text: '  ' + (w.Hostname || '') + ' plugin ' + (w.PluginID || '') + ' [' + (w.Severity || '') + '] - ' + (w.Tool || '') + '/' + (w.Operator || '') + ' on ' + (w.TouchDate || ''), level: 'warn' });
                }
              } else {
                log.append({ text: 'No still-open findings on hosts JANET touched - nothing left on the worklist.', level: 'ok' });
              }
            }
          });
        };
      }

      // ---- Weekly Export ----------------------------------------------------------
      function buildWeekly(panel) {
        panelFlex(panel);
        panel.appendChild(sectionTitle('WEEKLY EXPORT', true));
        panel.appendChild(hint('Parse an ACAS_Calculations CSV into per-week, per-enclave (NIPR/SIPR) metrics; then render an HTML brief or export CSV(s).'));

        var row = btnRow();
        var parseBtn = ui.button('Load ACAS_Calculations CSV', { variant: 'cyan', size: 'sm', title: 'Upload + parse the monthly calculations workbook CSV.' });
        var enclaveInput = ui.input({ placeholder: 'Enclave (NIPR / SIPR / blank)', title: 'Filter for HTML / CSV; blank = all (HTML) / first (CSV).' }); enclaveInput.style.width = '180px';
        row.appendChild(parseBtn); row.appendChild(ui.label('Enclave')); row.appendChild(enclaveInput);
        panel.appendChild(row);

        var grid = C.ResultsGrid({
          title: 'Weekly metrics', keyMode: { rk: true }, popOut: true,
          columns: [
            { key: 'Week', label: 'WEEK', width: 180 },
            { key: 'Enclave', label: 'ENCLAVE', width: 90 },
            { key: 'TotalVulns', label: 'TOTAL VULNS', width: 110 },
            { key: 'AR_Percent', label: 'AR %', width: 90 },
            { key: 'MAJCOM_VPH', label: 'MAJCOM VPH', width: 110 }
          ]
        });
        var gh = gridHolder(grid, 180); gh.style.flex = '1'; panel.appendChild(gh);
        var prog = C.ProgressStatusStrip({ showCount: false }); prog.el.style.marginTop = '6px'; panel.appendChild(prog.el);

        var outRow = btnRow(); outRow.style.marginTop = '10px';
        var htmlBtn = ui.button('Render HTML Brief', { variant: 'gold', size: 'sm', title: 'Generate the weekly HTML brief inline.' });
        var weekInput = ui.input({ placeholder: 'Week (DateRange; blank = first)', title: 'Used by CSV export.' }); weekInput.style.width = '210px';
        var allWeeksCb = ui.checkbox('All weeks', { title: 'Export one CSV per non-empty week (inline).' });
        var csvBtn = ui.ghostButton('Export CSV', { size: 'sm', title: 'Export the weekly metrics to CSV.' });
        outRow.appendChild(htmlBtn); outRow.appendChild(weekInput); outRow.appendChild(allWeeksCb); outRow.appendChild(csvBtn);
        panel.appendChild(outRow);
        var htmlArt = ArtifactBar({ downloadLabel: 'Download HTML', openLabel: 'Open brief' });
        var csvArt = ArtifactBar({ downloadLabel: 'Download CSV', htmlOnly: false });
        panel.appendChild(htmlArt.el); panel.appendChild(csvArt.el);

        // one row per (Week, Enclave) - key on both so NIPR + SIPR of the same week stay distinct.
        function weekKey(ev) { return (ev.Week != null ? ev.Week : '') + '|' + (ev.Enclave != null ? ev.Enclave : ''); }

        parseBtn.onclick = function () {
          pickAndUpload('.csv', function (path) {
            log.banner('Weekly Export Parse');
            grid.clear(); prog.reset(); htmlArt.reset(); csvArt.reset();
            runIntoGrid('acas-weekly-parse', { FilePath: path }, {
              grid: grid, prog: prog, keyOf: weekKey,
              onFinal: function (res) { var s = res && res.summary || {}; log.banner('Parsed ' + (s.total || 0) + ' week-block(s)'); }
            });
          });
        };
        htmlBtn.onclick = function () {
          htmlArt.reset();
          log.banner('Weekly Render HTML');
          var h = ctx.run('weekly-render-html', { Enclave: enclaveInput.value || '' });
          resub('weekly-render-html', h.subscribe({ log: function (l) { log.append(l); }, error: function (e) { log.append({ text: e.text, level: 'err' }); }, final: function (res) { htmlArt.set(res && res.summary, 'ReportsTool_Weekly'); } }));
        };
        csvBtn.onclick = function () {
          csvArt.reset();
          log.banner('Weekly Export CSV' + (allWeeksCb._cb.checked ? ' (all weeks)' : ''));
          var h = ctx.run('weekly-export-csv', { Enclave: enclaveInput.value || '', Week: weekInput.value || '', AllWeeks: allWeeksCb._cb.checked });
          resub('weekly-export-csv', h.subscribe({
            log: function (l) { log.append(l); }, error: function (e) { log.append({ text: e.text, level: 'err' }); },
            final: function (res) {
              var s = res && res.summary || {};
              // AllWeeks returns multiple inline CSVs (no single summary.csv) - report counts; single-week returns summary.csv.
              if (s.csv != null) csvArt.set(s, 'ReportsTool_Weekly');
              else { csvArt.reset(); log.append({ text: 'Exported ' + (s.total || 0) + ' week CSV(s)' + (s.written ? ', ' + s.written + ' written server-side' : '') + (s.skippedEmpty ? ', ' + s.skippedEmpty + ' empty skipped' : '') + '. (All-weeks writes per-week files on the server; provide an OutputPath there to keep them.)', level: 'info' }); }
            }
          }));
        };
      }

      // ---- Dirty 30 Triage --------------------------------------------------------
      function buildDirty30(panel) {
        panelFlex(panel);
        panel.appendChild(sectionTitle('DIRTY 30 TRIAGE', true));
        panel.appendChild(hint('Paste / load a Tenable Dirty 30 list, parse + AD lookup, optionally probe last-logged-on user (parallel WMI), then render an HTML report or export CSV.'));

        var inputRow = btnRow();
        var loadBtn = ui.ghostButton('Load File (PDF/CSV/TXT)', { size: 'sm', title: 'Upload a Dirty 30 file - its text is read into the box below.' });
        var sourceInput = ui.input({ placeholder: 'Source label (optional)', title: 'Shown on the report.' }); sourceInput.style.width = '200px';
        var parseBtn = ui.button('Parse + AD Lookup', { variant: 'cyan', size: 'sm', title: 'Parse the input and run a batched LDAP lookup.' });
        inputRow.appendChild(loadBtn); inputRow.appendChild(sourceInput); inputRow.appendChild(parseBtn);
        panel.appendChild(inputRow);

        var inputBox = ui.textarea({ placeholder: 'Paste Dirty 30 PDF text, CSV, or one hostname per line...', rows: 4 });
        inputBox.style.cssText += ';margin-bottom:8px';
        panel.appendChild(inputBox);

        // tiles
        var stats = C.StatCards({ cards: [
          { key: 'parsed', label: 'PARSED', color: 'cyan' },
          { key: 'active', label: 'AD ACTIVE', color: 'ok' },
          { key: 'stale', label: 'AD STALE', color: 'gold' },
          { key: 'notfound', label: 'NOT FOUND', color: 'bad' }
        ] });
        var statCard = ui.card({}); statCard.style.padding = '10px 12px'; statCard.appendChild(stats.el); statCard.style.marginBottom = '8px';
        panel.appendChild(statCard);

        var grid = C.ResultsGrid({
          title: 'Dirty 30', keyMode: { hostCol: 'Hostname' }, popOut: true,
          columns: [
            { key: 'Hostname', label: 'HOSTNAME', width: 140 },
            { key: 'Score', label: 'SCORE', width: 70 },
            { key: 'Vulns', label: 'VULNS (C/H/M/L)', width: 130 },
            { key: 'LastLogon', label: 'LAST AD LOGON', width: 150 },
            { key: 'LastUser', label: 'LAST USER', width: 150 },
            { key: 'Squadron', label: 'SQUADRON', width: 110 },
            { key: 'OUChain', label: 'OU / LOCATION', width: 200 },
            { key: 'Status', label: 'STATUS', width: 100, colorRule: d30StatusCls }
          ],
          rowClass: function (r) { var c = d30StatusCls(r.Status); return c === 'st-ok' ? 'row-ok' : (c === 'st-bad' ? 'row-bad' : (c === 'st-warn' ? 'row-warn' : '')); }
        });
        var gh = gridHolder(grid, 180); gh.style.flex = '1'; panel.appendChild(gh);
        var prog = C.ProgressStatusStrip({ showCount: true }); prog.el.style.marginTop = '6px'; panel.appendChild(prog.el);

        var outRow = btnRow(); outRow.style.marginTop = '10px';
        var probeBtn = ui.button('+ Probe Last User', { variant: 'cyan', size: 'sm', title: 'Parallel WMI StdRegProv probe of LastLoggedOnUser per host.' });
        var timeoutInput = ui.number({ value: 8, min: 1, max: 60, title: 'Per-host timeout (sec).' }); timeoutInput.style.width = '70px';
        var concInput = ui.number({ value: 16, min: 1, max: 64, title: 'Parallel hosts.' }); concInput.style.width = '70px';
        var htmlBtn = ui.button('Render HTML', { variant: 'gold', size: 'sm', title: 'Generate the Dirty 30 HTML report inline.' });
        var csvBtn = ui.ghostButton('Export CSV', { size: 'sm', title: 'Export merged Dirty 30 + AD + probe data to CSV.' });
        outRow.appendChild(probeBtn); outRow.appendChild(ui.label('Timeout')); outRow.appendChild(timeoutInput); outRow.appendChild(ui.label('Parallel')); outRow.appendChild(concInput);
        outRow.appendChild(htmlBtn); outRow.appendChild(csvBtn);
        panel.appendChild(outRow);
        var htmlArt = ArtifactBar({ downloadLabel: 'Download HTML', openLabel: 'Open report' });
        var csvArt = ArtifactBar({ downloadLabel: 'Download CSV', htmlOnly: false });
        panel.appendChild(htmlArt.el); panel.appendChild(csvArt.el);

        loadBtn.onclick = function () {
          // Read the file client-side into the textarea (engine takes the text, not a path, for this action).
          var fi = el('input'); fi.type = 'file'; fi.accept = '.pdf,.csv,.txt'; fi.style.display = 'none';
          document.body.appendChild(fi);
          fi.addEventListener('change', function () {
            var f = fi.files && fi.files[0]; document.body.removeChild(fi); if (!f) return;
            if (/\.pdf$/i.test(f.name)) {
              // best-effort dependency-free text extraction; manual paste if it falls short.
              log.append({ text: 'Reading PDF ' + f.name + ' (' + fmtBytes(f.size) + ') - best-effort text extraction...', level: 'accent' });
              extractPdfText(f).then(function (text) {
                var clean = String(text || '').replace(/[ \t]+\n/g, '\n').replace(/\n{3,}/g, '\n\n').trim();
                if (clean.length >= 30) {
                  inputBox.value = clean;
                  log.append({ text: 'Extracted ~' + clean.length + ' char(s) from the PDF. REVIEW the box, then Parse + AD Lookup. Best-effort - if it looks wrong, paste the PDF text manually.', level: 'ok' });
                } else {
                  ctx.confirm({ title: 'Could not read the PDF text', body: 'This PDF\'s text could not be extracted in the browser (it may be scanned / image-only or use an unsupported encoding). Open the PDF, copy its text, and paste it into the box.', okText: 'OK', cancelText: null });
                }
              }).catch(function (e) {
                ctx.confirm({ title: 'PDF read failed', body: 'Could not read this PDF in the browser (' + esc(e && e.message) + '). Open the PDF, copy its text, and paste it into the box.', okText: 'OK', cancelText: null });
              });
              return;
            }
            var reader = new FileReader();
            reader.onload = function () { inputBox.value = String(reader.result || ''); log.append({ text: 'Loaded ' + f.name + ' (' + fmtBytes(f.size) + ') into the input box.', level: 'ok' }); };
            reader.readAsText(f);
          });
          fi.click();
        };

        parseBtn.onclick = function () {
          if (!inputBox.value.trim()) { ctx.confirm({ title: 'No input', body: 'Paste or load Dirty 30 input first.', okText: 'OK', cancelText: null }); return; }
          log.banner('Dirty 30 Parse + AD Lookup');
          grid.clear(); prog.reset(); stats.reset(); htmlArt.reset(); csvArt.reset();
          runIntoGrid('dirty30-parse-lookup', { InputText: inputBox.value, SourceLabel: sourceInput.value || '' }, {
            grid: grid, prog: prog, keyOf: function (ev) { return ev.Hostname != null ? String(ev.Hostname) : null; },
            onFinal: function (res) {
              var rows = grid.rows(), active = 0, stale = 0, nf = 0;
              rows.forEach(function (r) { var c = d30StatusCls(r.Status); if (c === 'st-ok') active++; else if (c === 'st-warn') stale++; else if (c === 'st-bad') nf++; });
              stats.setAll({ parsed: rows.length, active: active, stale: stale, notfound: nf });
              log.banner('Dirty 30: ' + rows.length + ' parsed, ' + active + ' active, ' + stale + ' stale, ' + nf + ' not found');
            }
          });
        };
        probeBtn.onclick = function () {
          log.banner('Dirty 30 Probe Last User');
          // blank Hostnames -> engine uses the last lookup's host set.
          var h = ctx.run('dirty30-probe-lastuser', { Hostnames: '', TimeoutSec: Math.max(1, parseInt(timeoutInput.value, 10) || 8), MaxConcurrent: Math.max(1, parseInt(concInput.value, 10) || 16) }, { keyOf: function (ev) { return ev.Host != null ? String(ev.Host) : null; } });
          resub('dirty30-probe-lastuser', h.subscribe({
            status: function (t) { prog.setPhase(t); log.append({ text: t, level: 'mode' }); },
            progress: function (p) { prog.setProgress(p.done, p.total); },
            row: function (r) { grid.upsert({ Hostname: r.Host, LastUser: r.LastUser }); log.append({ text: '[' + r.Host + '] last user: ' + (r.LastUser || '--'), level: 'dim' }); },
            log: function (l) { log.append(l); }, error: function (e) { log.append({ text: e.text, level: 'err' }); },
            final: function (res) { var s = res && res.summary || {}; log.banner('Probe: ' + (s.ok || 0) + ' ok, ' + (s.failed || 0) + ' unreachable'); }
          }));
        };
        htmlBtn.onclick = function () {
          htmlArt.reset(); log.banner('Dirty 30 Render HTML');
          var h = ctx.run('dirty30-render-html', { SourceLabel: sourceInput.value || '' });
          resub('dirty30-render-html', h.subscribe({ log: function (l) { log.append(l); }, error: function (e) { log.append({ text: e.text, level: 'err' }); }, final: function (res) { htmlArt.set(res && res.summary, 'ReportsTool_Dirty30'); } }));
        };
        csvBtn.onclick = function () {
          csvArt.reset(); log.banner('Dirty 30 Export CSV');
          var h = ctx.run('dirty30-export-csv', {});
          resub('dirty30-export-csv', h.subscribe({ log: function (l) { log.append(l); }, error: function (e) { log.append({ text: e.text, level: 'err' }); }, final: function (res) { csvArt.set(res && res.summary, 'ReportsTool_Dirty30'); } }));
        };
      }

      // ---- CORA Vulnerabilities ---------------------------------------------------
      function buildCora(panel) {
        panelFlex(panel);
        panel.appendChild(sectionTitle('CORA VULNERABILITIES', true));
        panel.appendChild(hint('Commander brief over the open + actionable findings: headline metrics + an HTML brief. Reads the working findings set (parse a scan in ACAS Import first).'));

        var row = btnRow();
        var netInput = ui.number({ value: 0, min: 0, title: 'Total devices on network (for % of fleet; 0 = hide).' }); netInput.style.width = '120px';
        var buildBtn = ui.button('Build Summary', { variant: 'cyan', size: 'sm', title: 'Compute the CORA metrics from current findings.' });
        var htmlBtn = ui.button('Open HTML Brief', { variant: 'gold', size: 'sm', title: 'Generate the commander-brief HTML inline.' });
        row.appendChild(ui.label('Network size')); row.appendChild(netInput); row.appendChild(buildBtn); row.appendChild(htmlBtn);
        panel.appendChild(row);

        var grid = C.ResultsGrid({
          title: 'CORA summary', keyMode: { hostCol: 'Metric' }, popOut: true,
          columns: [
            { key: 'Metric', label: 'METRIC', width: 240 },
            { key: 'Value', label: 'VALUE', width: 160 }
          ]
        });
        var gh = gridHolder(grid, 200); gh.style.flex = '1'; panel.appendChild(gh);
        var prog = C.ProgressStatusStrip({ showCount: false }); prog.el.style.marginTop = '6px'; panel.appendChild(prog.el);
        var htmlArt = ArtifactBar({ downloadLabel: 'Download HTML', openLabel: 'Open brief' });
        panel.appendChild(htmlArt.el);

        buildBtn.onclick = function () {
          log.banner('CORA Build Summary');
          grid.clear(); prog.reset(); htmlArt.reset();
          runIntoGrid('cora-build-summary', { NetworkDeviceCount: Math.max(0, parseInt(netInput.value, 10) || 0) }, {
            grid: grid, prog: prog, keyOf: function (ev) { return ev.Metric != null ? String(ev.Metric) : null; },
            onFinal: function (res) { var s = res && res.summary || {}; log.banner('CORA: ' + (s.total || 0) + ' metric row(s)'); }
          });
        };
        htmlBtn.onclick = function () {
          htmlArt.reset(); log.banner('CORA Render HTML');
          var h = ctx.run('cora-render-html', { NetworkDeviceCount: Math.max(0, parseInt(netInput.value, 10) || 0) });
          resub('cora-render-html', h.subscribe({ log: function (l) { log.append(l); }, error: function (e) { log.append({ text: e.text, level: 'err' }); }, final: function (res) { htmlArt.set(res && res.summary, 'ReportsTool_CORA'); } }));
        };
      }

      // ---- Future Target IPs ------------------------------------------------------
      // Mirrors the desktop ReportsTool "Future Target IPs" tab: import a hostname CSV
      // (e.g. an AQC pre-target list), parallel DNS-resolve + ping, copy/export the IPs.
      // The desktop btnFImport DETECTS the hostname column (Computer Name / Hostname /
      // Host / FQDN / Name) and an optional ASID column - it never treats raw CSV rows as
      // hostnames. The old TargetManager import did exactly that (every line, header + all
      // columns, dumped as "hostnames"), which is what made imports "messed up". This
      // re-front parses the column like the desktop and carries ASID through to the grid.
      function buildFuture(panel) {
        panelFlex(panel);
        panel.appendChild(sectionTitle('FUTURE TARGET IPs', true));
        panel.appendChild(hint('Import a hostname CSV (e.g. an AQC pre-target list), resolve IPs in parallel (DNS + ping), then copy/export. Detects the hostname column (Computer Name / Hostname / Host / FQDN / Name) + optional ASID, ignoring other columns - or paste a full CSV (host column auto-detected) or one host per line.'));

        var model = ctx.util.targetModel('');
        var asidByHost = {};   // UPPERCASE host -> ASID (the engine upcases hosts; grid keys must match)
        var osByHost = {};     // UPPERCASE host -> Windows OS Version (23H2/24H2/25H2...) from the CSV; surfaced in the row double-click detail

        var tgWrap = el('div'); tgWrap.style.cssText = 'display:flex;gap:14px;flex:1;min-height:0';
        var leftCol = el('div'); leftCol.style.cssText = 'flex:0 0 300px;display:flex;flex-direction:column;min-height:0';

        var box = ui.textarea({ placeholder: 'One target hostname per line - or Import CSV', rows: 8 });
        box.style.cssText += ';flex:1;min-height:140px';
        box.addEventListener('input', function () { model.set(box.value); });
        // Paste a full CSV (e.g. a Quarantine / AQC export) straight into the box and
        // auto-extract the hostname column - same detection as Import CSV. The desktop
        // only ingests via file import; without this a pasted multi-column CSV falls
        // through parseHosts as raw tokens (every cell becomes a "target"). Only hijacks
        // the paste when it is clearly a multi-column CSV WITH a recognized host column;
        // a plain one-per-line list (no commas / single column) pastes normally.
        box.addEventListener('paste', function (e) {
          var cd = e.clipboardData || window.clipboardData; if (!cd) { return; }
          var text = cd.getData('text') || cd.getData('Text'); if (!text || text.indexOf(',') < 0) { return; }
          var hp = ctx.util.parseCsv(text); if (!hp.headers || hp.headers.length <= 1) { return; }
          if (findCol(hp.headers, ['Computer Name', 'ComputerName', 'Hostname', 'Host', 'FQDN', 'Name']) < 0) { return; }
          e.preventDefault();
          importCsvText(text, 'pasted CSV');
        });
        leftCol.appendChild(box);

        var lcBar = btnRow(); lcBar.style.marginTop = '8px';
        var importBtn = ui.button('Import CSV', { variant: 'cyan', size: 'sm', title: 'Load hostnames from a CSV - detects the hostname column (+ ASID) and ignores other columns.' });
        var clearBtn = ui.ghostButton('Clear', { size: 'sm', title: 'Empty the target list, ASID map, and results.' });
        var countLbl = el('span', 'muted'); countLbl.style.marginLeft = 'auto'; countLbl.textContent = '0 target(s)';
        lcBar.appendChild(importBtn); lcBar.appendChild(clearBtn); lcBar.appendChild(countLbl);
        leftCol.appendChild(lcBar);

        var optRow = btnRow(); optRow.style.marginTop = '8px';
        var threadsInput = ui.number({ value: 32, min: 1, max: 32, title: 'Parallel resolvers (1-32).' }); threadsInput.style.width = '70px';
        var timeoutInput = ui.number({ value: 1500, min: 100, max: 10000, step: 100, title: 'Ping timeout (ms).' }); timeoutInput.style.width = '90px';
        optRow.appendChild(ui.label('Threads')); optRow.appendChild(threadsInput); optRow.appendChild(ui.label('Timeout ms')); optRow.appendChild(timeoutInput);
        leftCol.appendChild(optRow);
        var resolveBtn = ui.button('Resolve IPs', { variant: 'go', size: 'sm', title: 'DNS resolve + ping every target in parallel.' });
        resolveBtn.style.marginTop = '8px';
        leftCol.appendChild(resolveBtn);
        tgWrap.appendChild(leftCol);

        var rightCol = el('div'); rightCol.style.cssText = 'flex:1;min-width:0;display:flex;flex-direction:column;min-height:0';
        var grid = C.ResultsGrid({
          title: 'Target IPs', keyMode: { hostCol: 'Host' }, popOut: true,
          columns: [
            { key: 'Host', label: 'HOSTNAME', width: 170 },
            { key: 'ASID', label: 'ASID', width: 80 },
            { key: 'IP', label: 'IP ADDRESS', width: 150 },
            { key: 'Status', label: 'STATUS', width: 110, colorRule: ipStatusCls },
            { key: 'LatencyMs', label: 'LATENCY (ms)', width: 110 }
          ],
          rowClass: function (r) { var c = ipStatusCls(r.Status); return c === 'st-ok' ? 'row-ok' : (c === 'st-bad' ? 'row-bad' : ''); }
        });
        var gh = gridHolder(grid, 200); gh.style.flex = '1'; rightCol.appendChild(gh);
        var prog = C.ProgressStatusStrip({ showCount: true }); prog.el.style.marginTop = '6px'; rightCol.appendChild(prog.el);
        // copy/export helpers (desktop Copy All IPs / Copy Online IPs / Copy Host,IP CSV / Export CSV)
        var copyRow = btnRow(); copyRow.style.marginTop = '8px';
        var copyAll = ui.ghostButton('Copy All IPs', { size: 'sm', title: 'Copy every resolved IP, one per line.' });
        var copyOnline = ui.ghostButton('Copy Online IPs', { size: 'sm', title: 'Copy only IPs that answered a ping.' });
        var copyCsv = ui.ghostButton('Copy Host,IP CSV', { size: 'sm', title: 'Copy Hostname,IP rows (resolved hosts only).' });
        var exportCsv = ui.ghostButton('Export CSV', { size: 'sm', title: 'Download Hostname,ASID,IP,Status,Latency.' });
        copyRow.appendChild(copyAll); copyRow.appendChild(copyOnline); copyRow.appendChild(copyCsv); copyRow.appendChild(exportCsv);
        rightCol.appendChild(copyRow);
        tgWrap.appendChild(rightCol);
        panel.appendChild(tgWrap);

        function refreshCount() { var n = model.count(); countLbl.textContent = n + ' target(s)'; countLbl.className = n > 0 ? 'st-ok' : 'muted'; if (box.value !== model.raw) box.value = model.raw; }
        model.onChange(refreshCount);

        // desktop btnFImport: detect the hostname column (+ optional ASID), pull ONLY those.
        function findCol(headers, cands) {
          for (var c = 0; c < cands.length; c++) for (var h = 0; h < headers.length; h++)
            if (String(headers[h]).trim().toLowerCase() === cands[c].toLowerCase()) return h;
          return -1;
        }
        function importCsvText(text, fileName) {
          var p = ctx.util.parseCsv(text), headers = p.headers || [];
          var hi = findCol(headers, ['Computer Name', 'ComputerName', 'Hostname', 'Host', 'FQDN', 'Name']);
          var ai = findCol(headers, ['ASID Code', 'ASID']);
          var oi = findCol(headers, ['Windows OS Version', 'OS Version', 'Windows Version', 'OSVersion']);
          var hosts = [], withAsid = 0;
          if (hi >= 0) {
            p.rows.forEach(function (r) {
              var hn = String(r[hi] == null ? '' : r[hi]).trim(); if (!hn) return;
              hosts.push(hn);
              if (ai >= 0) { var a = String(r[ai] == null ? '' : r[ai]).trim(); if (a) { asidByHost[hn.toUpperCase()] = a; withAsid++; } }
              if (oi >= 0) { var ov = String(r[oi] == null ? '' : r[oi]).trim(); if (ov) osByHost[hn.toUpperCase()] = ov; }
            });
          } else if (headers.length <= 1) {
            // single-column / headerless list: parseCsv took row 0 as the header, so include it too.
            [headers[0]].concat(p.rows.map(function (r) { return r[0]; })).forEach(function (v) { var hn = String(v == null ? '' : v).trim(); if (hn) hosts.push(hn); });
          } else {
            ctx.confirm({ title: 'Unrecognized CSV', body: 'No hostname column found in ' + esc(fileName) + '. Expected one of: Computer Name, ComputerName, Hostname, Host, FQDN, Name.', okText: 'OK', cancelText: null });
            return;
          }
          if (!hosts.length) { log.append({ text: 'No hostnames found in ' + fileName + '.', level: 'warn' }); return; }
          var existing = model.raw.replace(/\s+$/, '');
          model.set((existing ? existing + '\n' : '') + hosts.join('\n'));
          log.append({ text: 'Imported ' + hosts.length + ' hostname(s)' + (withAsid ? ' (' + withAsid + ' with ASID)' : '') + ' from ' + fileName + '.', level: 'ok' });
        }
        importBtn.onclick = function () {
          var fi = el('input'); fi.type = 'file'; fi.accept = '.csv,.tsv,.txt'; fi.style.display = 'none';
          document.body.appendChild(fi);
          fi.addEventListener('change', function () {
            var f = fi.files && fi.files[0]; document.body.removeChild(fi); if (!f) return;
            var reader = new FileReader();
            reader.onload = function () { importCsvText(String(reader.result || ''), f.name); };
            reader.readAsText(f);
          });
          fi.click();
        };
        clearBtn.onclick = function () { model.set(''); asidByHost = {}; osByHost = {}; grid.clear(); prog.reset(); log.append({ text: 'Cleared Future Target IPs.', level: 'dim' }); };

        function copyText(t, noun) {
          var n = t.split('\n').filter(Boolean).length;
          if (!n) { log.append({ text: 'Nothing to copy - resolve targets first.', level: 'warn' }); return; }
          if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(t).then(function () { log.append({ text: 'Copied ' + n + ' ' + (noun || 'line') + '(s).', level: 'dim' }); }).catch(function () {});
        }
        copyAll.onclick = function () { copyText(grid.rows().map(function (r) { return r.IP; }).filter(Boolean).join('\n'), 'IP'); };
        copyOnline.onclick = function () { copyText(grid.rows().filter(function (r) { return /^Online$/i.test(String(r.Status)); }).map(function (r) { return r.IP; }).filter(Boolean).join('\n'), 'IP'); };
        copyCsv.onclick = function () { var rows = grid.rows().filter(function (r) { return r.IP; }); copyText((rows.length ? 'Hostname,IP\n' : '') + rows.map(function (r) { return r.Host + ',' + r.IP; }).join('\n'), 'row'); };
        exportCsv.onclick = function () {
          var rows = grid.rows(); if (!rows.length) { ctx.confirm({ title: 'Nothing to export', body: 'Resolve targets first.', okText: 'OK', cancelText: null }); return; }
          var csv = ctx.util.toCsv(['Hostname', 'ASID', 'IP', 'Status', 'LatencyMs'], rows.map(function (r) { return [r.Host, r.ASID || '', r.IP || '', r.Status || '', r.LatencyMs != null ? r.LatencyMs : '']; }));
          ctx.util.downloadBlob('ReportsTool_FutureTargetIPs_' + ctx.util.fileStamp() + '.csv', 'text/csv', csv);
        };

        resolveBtn.onclick = function () {
          var hosts = model.hosts();
          if (!hosts.length) { ctx.confirm({ title: 'No targets', body: 'Import a CSV or paste at least one hostname.', okText: 'OK', cancelText: null }); return; }
          log.banner('Resolve Target IPs (' + hosts.length + ')');
          grid.clear(); prog.reset();
          // seed each target now (uppercased to match the engine's host keys) so ASID + OS
          // Version show immediately and survive the resolve upsert (grid.upsert merges by Host).
          hosts.forEach(function (h) { var H = h.toUpperCase(); grid.upsert({ Host: H, ASID: asidByHost[H] || '', 'OS Version': osByHost[H] || '', IP: '', Status: '', LatencyMs: '' }); });
          runIntoGrid('resolve-target-ips', { targets: model.raw, threads: Math.max(1, Math.min(32, parseInt(threadsInput.value, 10) || 32)), timeoutMs: Math.max(100, parseInt(timeoutInput.value, 10) || 1500) }, {
            grid: grid, prog: prog, keyOf: function (ev) { return ev.Host != null ? String(ev.Host) : null; },
            onFinal: function (res) {
              var s = res && res.summary || {};
              log.banner('Resolve: ' + (s.online || 0) + ' online, ' + (s.offline || 0) + ' offline, ' + (s.dnsFailed || 0) + ' DNS-failed' + (s.timedOut ? ', ' + s.timedOut + ' timeout' : '') + (s.cancelled ? ', ' + s.cancelled + ' cancelled' : '') + ' of ' + (s.total || 0));
            }
          });
        };

        refreshCount();
      }

      // ---- Dashboard (per-host summary) -------------------------------------------
      function buildDashboard(panel) {
        panelFlex(panel);
        panel.appendChild(sectionTitle('DASHBOARD - PER-HOST SUMMARY', true));
        panel.appendChild(hint('Per-host severity / triage tallies + patch rate over the loaded findings. Patch rate = Patched of (Patched + Open); colours green >=90 / amber >=50 / red below.'));

        // aggregate metric cards + patch-rate bar (desktop Refresh-Dashboard summary
        // cards). Computed client-side by summing the per-host rows - no engine round-trip.
        var cards = C.StatCards({ cards: [
          { key: 'total', label: 'TOTAL VULNS', color: 'accent' },
          { key: 'crit', label: 'CRITICAL', color: 'bad' },
          { key: 'high', label: 'HIGH', color: 'gold' },
          { key: 'kev', label: 'KEV', color: 'bad' },
          { key: 'patched', label: 'PATCHED', color: 'ok' },
          { key: 'open', label: 'OPEN', color: 'bad' },
          { key: 'notours', label: 'NOT OURS', color: 'cyan' },
          { key: 'rate', label: 'PATCH RATE', color: 'cyan' }
        ] });
        panel.appendChild(cards.el);
        var prTrack = el('div'); prTrack.style.cssText = 'height:8px;border-radius:4px;background:var(--panel-light);margin:8px 0 2px;overflow:hidden';
        var prFill = el('div'); prFill.style.cssText = 'height:100%;width:0;background:var(--ok);transition:width .25s'; prTrack.appendChild(prFill);
        panel.appendChild(prTrack);

        var row = btnRow();
        var refreshBtn = ui.button('Refresh Dashboard', { variant: 'cyan', size: 'sm', title: 'Recompute the per-host summary from current findings.' });
        row.appendChild(refreshBtn);
        panel.appendChild(row);

        var grid = C.ResultsGrid({
          title: 'Host summary', keyMode: { hostCol: 'Host' }, popOut: true,
          columns: [
            { key: 'Host', label: 'HOSTNAME', width: 140 },
            { key: 'TotalVulns', label: 'TOTAL', width: 70 },
            { key: 'Crit', label: 'CRIT', width: 60, colorRule: gt0cls('st-bad') },
            { key: 'High', label: 'HIGH', width: 60, colorRule: gt0cls('st-warn') },
            { key: 'Med', label: 'MED', width: 60, colorRule: gt0cls('st-warn') },
            { key: 'Low', label: 'LOW', width: 60, colorRule: gt0cls('st-info') },
            { key: 'Info', label: 'INFO', width: 60, colorRule: function () { return 'cell-dim'; } },
            { key: 'Kev', label: 'KEV', width: 60, colorRule: gt0cls('st-bad') },
            { key: 'Patched', label: 'PATCHED', width: 80, colorRule: gt0cls('st-ok') },
            { key: 'Open', label: 'OPEN', width: 70, colorRule: gt0cls('st-bad') },
            { key: 'NotOurs', label: 'NOT OURS', width: 90, colorRule: gt0cls('st-info') },
            { key: 'PatchRate', label: 'PATCH RATE', width: 100, colorRule: patchRateCls }
          ]
        });
        var gh = gridHolder(grid, 220); gh.style.flex = '1'; panel.appendChild(gh);
        var prog = C.ProgressStatusStrip({ showCount: true }); prog.el.style.marginTop = '6px'; panel.appendChild(prog.el);

        refreshBtn.onclick = function () {
          log.banner('ACAS Host Summary');
          grid.clear(); prog.reset(); cards.reset(); prFill.style.width = '0';
          runIntoGrid('acas-host-summary', {}, {
            grid: grid, prog: prog, keyOf: function (ev) { return ev.Host != null ? String(ev.Host) : null; },
            onFinal: function (res) {
              var s = res && res.summary || {};
              var agg = { total: 0, crit: 0, high: 0, kev: 0, patched: 0, open: 0, notours: 0 };
              grid.rows().forEach(function (r) { agg.total += (+r.TotalVulns || 0); agg.crit += (+r.Crit || 0); agg.high += (+r.High || 0); agg.kev += (+r.Kev || 0); agg.patched += (+r.Patched || 0); agg.open += (+r.Open || 0); agg.notours += (+r.NotOurs || 0); });
              var denom = agg.patched + agg.open, pct = denom > 0 ? Math.round(agg.patched / denom * 100) : 0;
              cards.setAll({ total: agg.total, crit: agg.crit, high: agg.high, kev: agg.kev, patched: agg.patched, open: agg.open, notours: agg.notours, rate: denom > 0 ? pct + '%' : 'N/A' });
              prFill.style.width = pct + '%'; prFill.style.background = pct >= 90 ? 'var(--ok)' : pct >= 50 ? 'var(--amber)' : 'var(--bad)';
              log.banner('Dashboard: ' + (s.total || 0) + ' host(s) over ' + (s.findings || 0) + ' finding(s)' + (s.kevHosts ? ', ' + s.kevHosts + ' host(s) with KEV' : ''));
            }
          });
        };
      }

      // ---- Remediation SLA / Finding Aging ----------------------------------------
      function buildSla(panel) {
        panelFlex(panel);
        panel.appendChild(sectionTitle('REMEDIATION SLA / FINDING AGING', true));
        panel.appendChild(hint('Ages every OPEN (not Patched) finding against the per-severity remediation windows in JanetLocal\\sla-baseline.json (KEV overrides with the tightest window). Buckets: OVERDUE (red) / DUE-SOON (amber, <=25% of the window or <=3 days left) / ON-TRACK (green) / NEW-UNTRACKED (no firstSeen - not in the ledger yet). The firstSeen clock is persisted in JanetLocal\\sla-ledger.json and auto-carried across fresh re-parses, so the aging survives an import with no operator discipline; Save the report to also embed it. Export the CSV for POA&M.'));

        var cards = C.StatCards({ cards: [
          { key: 'overdue', label: 'OVERDUE', color: 'bad' },
          { key: 'dueSoon', label: 'DUE SOON', color: 'gold' },
          { key: 'onTrack', label: 'ON TRACK', color: 'ok' },
          { key: 'untracked', label: 'UNTRACKED', color: 'cyan' },
          { key: 'hostsOverdue', label: 'HOSTS OVERDUE', color: 'bad' }
        ] });
        panel.appendChild(cards.el);

        var row = btnRow(); row.style.marginTop = '8px';
        var refreshBtn = ui.button('Refresh SLA', { variant: 'cyan', size: 'sm', title: 'Recompute finding aging + SLA buckets from the loaded findings.' });
        var poamBtn = ui.button('Export eMASS POA&M', { variant: 'go', size: 'sm', title: 'Export the OPEN findings as an eMASS POA&M import-template CSV (one row per finding, DISA CAT + SLA-derived scheduled completion). Hand to the ISSM/ISSO.' });
        var bucketSel = ui.select({ options: ['All buckets', 'OVERDUE', 'DUE-SOON', 'ON-TRACK', 'NEW-UNTRACKED'], title: 'Show only findings in this SLA bucket.' });
        var baseLbl = el('span', 'muted'); baseLbl.style.fontSize = '11px'; baseLbl.style.marginLeft = 'auto'; baseLbl.textContent = 'baseline: not loaded';
        row.appendChild(refreshBtn); row.appendChild(poamBtn); row.appendChild(ui.eyebrow('BUCKET')); row.appendChild(bucketSel); row.appendChild(baseLbl);
        panel.appendChild(row);

        var artifact = ArtifactBar({ downloadLabel: 'Download aging CSV', htmlOnly: false });
        panel.appendChild(artifact.el);
        var poamArtifact = ArtifactBar({ downloadLabel: 'Download eMASS POA&M CSV', htmlOnly: false });
        panel.appendChild(poamArtifact.el);

        var grid = C.ResultsGrid({
          title: 'SLA aging', keyMode: { rk: true }, popOut: true,
          // OVERDUE first, then DUE-SOON, by soonest deadline (most-negative DueIn).
          sort: { key: 'DueIn', dir: 1 },
          columns: [
            { key: 'Host', label: 'HOSTNAME', width: 140 },
            { key: 'Plugin', label: 'PLUGIN', width: 80 },
            { key: 'VulnName', label: 'VULN NAME', width: 300 },
            { key: 'Severity', label: 'SEVERITY', width: 90, colorRule: sevCls },
            { key: 'InKEV', label: 'KEV', width: 60, sortVal: function (r) { return isKev(r) ? 1 : 0; }, render: function (r) { var on = isKev(r); return { text: on ? 'KEV' : '', cls: on ? 'st-bad' : 'cell-dim', title: on ? ('Known-exploited (CISA KEV): ' + (r.KevCves || r.CVE || '')) : '' }; } },
            { key: 'IAVA', label: 'IAVA', width: 110, sortVal: function (r) { return (r.IAVA ? 1 : 0); }, colorRule: function (v) { return v ? '' : 'cell-dim'; } },
            { key: 'FirstSeen', label: 'FIRST SEEN', width: 110, colorRule: function (v) { return v ? '' : 'cell-dim'; } },
            { key: 'AgeDays', label: 'AGE (D)', width: 80, sortVal: function (r) { return r.AgeDays === '' ? -1 : (+r.AgeDays || 0); } },
            // +100000 offset keeps OVERDUE (negative DueIn) sortable: ResultsGrid.cmp
            // stringifies sortVals and uses numeric localeCompare, which mis-orders
            // negatives (-30 sorts after -2). Offsetting to a non-negative range fixes
            // the collation so most-overdue lands first under dir:1; '' stays last.
            { key: 'DueIn', label: 'DUE IN (D)', width: 100, colorRule: dueInCls, sortVal: function (r) { return r.DueIn === '' ? 999999 : ((+r.DueIn || 0) + 100000); } },
            { key: 'Bucket', label: 'SLA STATUS', width: 140, colorRule: slaBucketCls }
          ],
          rowClass: function (r) { var c = slaBucketCls(r.Bucket); return c === 'st-bad' ? 'row-bad' : (c === 'st-warn' ? 'row-warn' : ''); }
        });
        var gh = gridHolder(grid, 220); gh.style.flex = '1'; panel.appendChild(gh);
        var prog = C.ProgressStatusStrip({ showCount: true }); prog.el.style.marginTop = '6px'; panel.appendChild(prog.el);

        function applyBucketFilter() {
          var b = bucketSel.value;
          if (b === 'All buckets') { grid.setFilter(null); return; }
          grid.setFilter(function (r) { return String(r.Bucket) === b; });
        }
        bucketSel.addEventListener('change', applyBucketFilter);

        function slaKey(ev) { return (ev.Host != null && ev.Plugin != null) ? (ev.Host + '|' + ev.Plugin) : null; }

        poamBtn.onclick = function () {
          poamArtifact.reset();
          log.banner('Export eMASS POA&M (CSV)');
          var h = ctx.run('export-poam', {});
          resub('export-poam', h.subscribe({
            log: function (l) { log.append(l); },
            error: function (e) { log.append({ text: e.text, level: 'err' }); },
            final: function (res) {
              var s = res && res.summary || {};
              poamArtifact.set(s, 'ReportsTool_eMASS_POAM');
              log.append({ text: (s.total || 0) + ' open finding(s) in the POA&M (' + (s.kev || 0) + ' KEV, ' + (s.overdue || 0) + ' past scheduled completion). Download the CSV and hand to the ISSM/ISSO.', level: (s.total ? 'ok' : 'warn') });
            }
          }));
        };

        refreshBtn.onclick = function () {
          log.banner('SLA / Finding Aging');
          grid.clear(); prog.reset(); cards.reset(); artifact.reset();
          runIntoGrid('sla-aging', {}, {
            grid: grid, prog: prog, keyOf: slaKey,
            onFinal: function (res) {
              var s = res && res.summary || {};
              cards.setAll({ overdue: s.overdue || 0, dueSoon: s.dueSoon || 0, onTrack: s.onTrack || 0, untracked: s.untracked || 0, hostsOverdue: s.hostsOverdue || 0 });
              baseLbl.textContent = 'baseline: ' + (s.baseline || 'defaults');
              baseLbl.className = 'muted';
              artifact.set(s, 'ReportsTool_SLA_POAM');
              applyBucketFilter();   // keep the grid in step with the current bucket dropdown
              log.banner('SLA: ' + (s.overdue || 0) + ' overdue, ' + (s.dueSoon || 0) + ' due-soon, ' + (s.onTrack || 0) + ' on-track, ' + (s.untracked || 0) + ' untracked over ' + (s.hosts || 0) + ' host(s)');
              if (s.hint) log.append({ text: s.hint, level: 'warn' });
            }
          });
        };
      }

      // ---- Squadron Rollup (fleet activity rollup from the log share) -------------
      // Read-only rollup over the CENTRAL JANET log share (the usage rollup +
      // per-tool detail CSVs all operators write to). One row per operator, plus one
      // per squadron when credentials are set and AD can classify the touched hosts.
      // Unlike the other sections this reads the shared log share, not the working
      // findings set - so it stands alone (no ACAS import required).
      function buildRollup(panel) {
        panelFlex(panel);
        panel.appendChild(sectionTitle('SQUADRON ROLLUP', true));
        panel.appendChild(hint('Fleet activity rollup from the central JANET log share (monthly usage rollup + per-tool detail CSVs, across all operators). One row per operator - and one per squadron when credentials are set and AD can classify the touched hostnames (otherwise operator-level only). Read-only; the share is SMB/445-gated, so an unreachable share fails friendly. Big month ranges are parsed with a row cap (noted in the log).'));

        var cards = C.StatCards({ cards: [
          { key: 'operators', label: 'OPERATORS ACTIVE', color: 'cyan' },
          { key: 'hosts', label: 'HOSTS TOUCHED', color: 'accent' },
          { key: 'vulns', label: 'VULNS PATCHED', color: 'ok' },
          { key: 'failPct', label: 'FLEET FAILURE %', color: 'bad' }
        ] });
        panel.appendChild(cards.el);

        var row = btnRow(); row.style.marginTop = '8px';
        var monthsInput = ui.number({ value: 1, min: 1, max: 24, title: 'How many months back to include (1 = current month only).' }); monthsInput.style.width = '80px';
        var runBtn = ui.button('Run Rollup', { variant: 'go', size: 'sm', title: 'Aggregate the log share for the selected months.' });
        var noteLbl = el('span', 'muted'); noteLbl.style.fontSize = '11px'; noteLbl.style.marginLeft = 'auto'; noteLbl.textContent = 'not run';
        row.appendChild(ui.label('Months back')); row.appendChild(monthsInput); row.appendChild(runBtn); row.appendChild(noteLbl);
        panel.appendChild(row);

        var artifact = ArtifactBar({ downloadLabel: 'Download CSV', htmlOnly: false });
        panel.appendChild(artifact.el);

        var grid = C.ResultsGrid({
          title: 'Squadron rollup', keyMode: { rk: true }, popOut: true,
          // busiest first; squadron rows carry no Sessions so they sort naturally by Actions too.
          sort: { key: 'Actions', dir: -1 },
          columns: [
            { key: 'Level', label: 'LEVEL', width: 90, colorRule: function (v) { return v === 'Squadron' ? 'st-info' : 'cell-dim'; } },
            { key: 'Name', label: 'OPERATOR / SQUADRON', width: 210 },
            { key: 'Actions', label: 'ACTIONS', width: 90, sortVal: function (r) { return +r.Actions || 0; } },
            { key: 'Hosts', label: 'HOSTS', width: 80, sortVal: function (r) { return +r.Hosts || 0; } },
            { key: 'TouchOK', label: 'TOUCH OK', width: 90, colorRule: gt0cls('st-ok') },
            { key: 'TouchFail', label: 'TOUCH FAIL', width: 100, colorRule: gt0cls('st-bad') },
            { key: 'Vulns', label: 'VULNS', width: 80, colorRule: gt0cls('st-ok') },
            { key: 'Sessions', label: 'SESSIONS', width: 90 },
            { key: 'TopTools', label: 'TOP TOOLS', width: 240 },
            { key: 'LastActive', label: 'LAST ACTIVE', width: 150 }
          ]
        });
        var gh = gridHolder(grid, 200); gh.style.flex = '1'; panel.appendChild(gh);
        var prog = C.ProgressStatusStrip({ showCount: true }); prog.el.style.marginTop = '6px'; panel.appendChild(prog.el);

        function rowKey(ev) { return (ev.Level != null && ev.Name != null) ? (ev.Level + '|' + ev.Name) : null; }

        runBtn.onclick = function () {
          log.banner('Squadron Rollup');
          grid.clear(); prog.reset(); cards.reset(); artifact.reset();
          noteLbl.textContent = 'running...'; noteLbl.className = 'st-info';
          runIntoGrid('squadron-rollup', { monthsBack: Math.max(1, Math.min(24, parseInt(monthsInput.value, 10) || 1)) }, {
            grid: grid, prog: prog, keyOf: rowKey,
            onFinal: function (res) {
              var s = res && res.summary || {};
              if (s.shareOk === false) {
                noteLbl.textContent = 'log share unreachable'; noteLbl.className = 'st-bad';
                cards.setAll({ operators: 0, hosts: 0, vulns: 0, failPct: 'N/A' });
                log.banner('Rollup: log share unreachable - ' + (s.message || 'try again on-network'));
                return;
              }
              cards.setAll({ operators: s.operators || 0, hosts: s.hosts || 0, vulns: s.vulns || 0, failPct: (s.failPct != null ? s.failPct + '%' : '0%') });
              artifact.set(s, 'ReportsTool_SquadronRollup');
              noteLbl.textContent = (s.months || '') + (s.squadronResolved ? ' - squadrons resolved' : ' - operator-level');
              noteLbl.className = 'muted';
              log.banner('Rollup: ' + (s.operators || 0) + ' operator(s), ' + (s.hosts || 0) + ' host(s) touched, ' + (s.vulns || 0) + ' vuln(s), ' + (s.failPct || 0) + '% fleet failure over ' + (s.months || '?'));
              if (s.squadronNote) log.append({ text: s.squadronNote, level: 'dim' });
              if (s.capped) log.append({ text: 'Detail parsing capped at ' + (s.maxRows || 0) + ' rows (' + (s.rowsParsed || 0) + ' parsed) - lower the month count for a complete pass.', level: 'warn' });
            }
          });
        };
      }

      // ---- Executive Command Brief (rolls up the other sections) -----------------
      // Build LAST: one commander-facing HTML page combining SLA aging, KEV posture,
      // this session's Squadron Rollup, the newest WPT fleet-compliance snapshots, the
      // Remediation Router split, and scan-closure numbers (when a compare has run).
      // Each section degrades to a "run X first" note server-side; the view just fires
      // the action and offers Download/Open on the returned HTML (like CORA/Weekly).
      function buildBrief(panel) {
        panelFlex(panel);
        panel.appendChild(sectionTitle('EXECUTIVE COMMAND BRIEF', true));
        panel.appendChild(hint('One self-contained commander brief that rolls up the other reports: SLA aging buckets, open KEV posture, this session\'s Squadron Rollup, the newest WPT fleet-compliance snapshots, the Remediation Router routable-vs-manual split, and scan-closure numbers (when a Patch Cross-Ref compare has run this session). Sections with no data show a "run X first" note. Run this LAST, after the sections it consumes.'));

        var row = btnRow();
        var buildBtn = ui.button('Build Brief', { variant: 'gold', size: 'sm', title: 'Assemble the executive brief from current session state + local files, and generate the HTML.' });
        var cbSel = ui.select({ options: ['None', 'Protanopia', 'Deuteranopia', 'Tritanopia'], title: 'Colorblind-safe palette for the brief.' });
        var noteLbl = el('span', 'muted'); noteLbl.style.fontSize = '11px'; noteLbl.style.marginLeft = 'auto'; noteLbl.textContent = 'not built';
        row.appendChild(buildBtn); row.appendChild(ui.eyebrow('PALETTE')); row.appendChild(cbSel); row.appendChild(noteLbl);
        panel.appendChild(row);

        var artifact = ArtifactBar({ downloadLabel: 'Download HTML', openLabel: 'Open brief' });
        panel.appendChild(artifact.el);
        var prog = C.ProgressStatusStrip({ showCount: false }); prog.el.style.marginTop = '6px'; panel.appendChild(prog.el);
        var spacer = el('div'); spacer.style.flex = '1'; panel.appendChild(spacer);

        buildBtn.onclick = function () {
          artifact.reset(); prog.reset(); log.banner('Executive Command Brief');
          noteLbl.textContent = 'building...'; noteLbl.className = 'st-info';
          var h = ctx.run('command-brief', { colorblind: cbSel.value || 'None' });
          resub('command-brief', h.subscribe({
            status: function (t) { prog.setPhase(t); log.append({ text: t, level: 'mode' }); },
            log: function (l) { log.append(l); },
            error: function (e) { log.append({ text: e.text, level: 'err' }); },
            final: function (res) {
              var s = res && res.summary || {};
              artifact.set(s, 'ReportsTool_CommandBrief');
              noteLbl.textContent = (s.sections || 0) + '/6 sections populated'; noteLbl.className = 'muted';
              log.banner('Command brief: ' + (s.sections || 0) + '/6 sections populated');
            }
          }));
        };
      }

      // ============================================================================
      //  LAYOUT  -  TabHost(rail:left) for the section nav + a docked ActivityLog
      // ============================================================================
      var root = el('div'); root.style.cssText = 'display:flex;height:100%;min-height:0;background:var(--bg)';

      // left column = nav rail (TabHost) over the persistent ActivityLog (desktop layout)
      var leftWrap = el('div'); leftWrap.style.cssText = 'flex:0 0 188px;display:flex;flex-direction:column;min-height:0;border-right:1px solid var(--line-soft);background:var(--bg-rail)';

      var tabhost = C.TabHost({
        rail: 'left',
        helpId: 'reports',
        tabs: [
          { id: 'start', label: 'Start', build: buildStart },
          { id: 'acas', label: 'ACAS Import', build: buildAcasImport },
          { id: 'remediation', label: 'Remediation Plan', build: buildRemediation },
          { id: 'router', label: 'Remediation Router', build: buildRouter },
          { id: 'planner', label: 'Remediation Planner', build: buildPlanner },
          { id: 'kbneeded', label: 'KBs Needed', build: buildKbNeeded },
          { id: 'thirdparty', label: 'Third-Party Catalog', build: buildThirdPartyCatalog },
          { id: 'iavm', label: 'IAVM Board', build: buildIavmBoard },
          { id: 'digest', label: 'Posture Digest', build: buildPostureDigest },
          { id: 'burndown', label: 'Burndown', build: buildBurndown },
          { id: 'campaigns', label: 'Campaigns', build: buildCampaigns },
          { id: 'compare', label: 'Patch Cross-Ref', build: buildCompare },
          { id: 'weekly', label: 'Weekly Export', build: buildWeekly },
          { id: 'dirty30', label: 'Dirty 30 Triage', build: buildDirty30 },
          { id: 'cora', label: 'CORA Vulns', build: buildCora },
          { id: 'future', label: 'Future Target IPs', build: buildFuture },
          { id: 'dashboard', label: 'Dashboard', build: buildDashboard },
          { id: 'sla', label: 'SLA / Aging', build: buildSla },
          { id: 'rollup', label: 'Squadron Rollup', build: buildRollup },
          { id: 'brief', label: 'Command Brief', build: buildBrief }
        ]
      });
      // The TabHost root is row(rail | panels). To get the desktop layout (nav rail
      // ABOVE a docked console on the left, content panels filling the right) we
      // re-home its rail + panels nodes. Re-homing breaks the descendant CSS rule
      // ".j-tabhost.rail-left .j-tabrail" (sets column/width/padding), so we restate
      // those properties inline on the detached rail node - it then renders identically
      // regardless of parent. (tabhost.el itself is left unused; node refs in its
      // select() closures keep working after re-parenting.)
      var railNode = tabhost.el.querySelector('.j-tabrail');
      var panelsNode = tabhost.el.querySelector('.j-tabpanels');
      railNode.style.cssText = 'display:flex;flex-direction:column;gap:2px;flex:0 0 auto;padding:8px;overflow:auto;background:var(--bg-rail)';
      leftWrap.appendChild(railNode);

      // persistent ActivityLog under the rail (desktop sidebar console)
      var logWrap = el('div'); logWrap.style.cssText = 'flex:1;min-height:120px;display:flex;flex-direction:column;border-top:1px solid var(--line-soft)';
      logWrap.appendChild(log.el);
      leftWrap.appendChild(logWrap);

      root.appendChild(leftWrap);

      // right = the active section panel (TabHost panels), padded content area
      var panelsHolder = el('div'); panelsHolder.style.cssText = 'flex:1;min-width:0;min-height:0;display:flex;flex-direction:column;padding:14px 16px;box-sizing:border-box';
      panelsNode.style.flex = '1'; panelsNode.style.minHeight = '0';
      panelsHolder.appendChild(panelsNode);
      root.appendChild(panelsHolder);

      // initial console banner (mirrors the desktop ready line)
      log.append({ text: 'J.A.N.E.T. Reports Tool ready. Stateful session: actions build on each other.', level: 'accent' });
      log.append({ text: 'Start at ACAS Import: parse a scan, then triage / dashboard / CORA / remediation read the same set.', level: 'dim' });

      host.appendChild(root);
      this._root = root;
      this._unsubAll = function () { unsubs.forEach(function (u) { try { u(); } catch (e) {} }); unsubs = []; };
    },
    unmount: function () { try { if (this._unsubAll) this._unsubAll(); } catch (e) {} if (this._root) this._root.remove(); }
  });
})();
