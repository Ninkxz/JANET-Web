/* ============================================================================
   adto.view.js  -  AD Nemesis (tool id: 'adto')
   Read-only AD Technical-Order compliance scan. No target list - it enumerates
   AD objects under a base DN (or the whole domain), categorises each into
   User / Admin / Service / Computer / Server, and flags COMPLIANT / NON-COMPLIANT
   with the EXACT reason + fix. Headline StatCards + per-category filter chips over
   one results grid. Read-only: runs under the current Kerberos identity (or the
   session credential); no admin session. Fixes + the IAO validation role come next.
   ========================================================================== */
(function () {
  'use strict';

  var CATS = ['User', 'Admin', 'Service', 'Computer', 'Server'];
  var EXPORT_COLS = [['Object', 'Object'], ['Category', 'Category'], ['Status', 'Status'],
    ['Rules', 'Rules'], ['Detail', 'Reason -> Fix'], ['DN', 'DistinguishedName']];

  function statusCellCls(v) {
    var s = String(v == null ? '' : v);
    if (s === 'COMPLIANT') return 'st-ok';
    if (s === 'NON-COMPLIANT') return 'st-bad';
    return '';
  }

  JanetViews.register('adto', {
    mount: function (host, ctx) {
      var ui = ctx.ui, C = ctx.components, el = ctx.util.el;
      var run = null, unsub = null;
      var card = ui.namedCard;

      var allRows = [];                 // every scanned row (grid shows the current filter subset)
      var filterCat = 'All';            // active category chip
      var counts = { total: 0, bad: 0, iao: 0 };
      var catCounts = {};               // cat -> { total, bad }
      CATS.forEach(function (c) { catCounts[c] = { total: 0, bad: 0 }; });

      var root = el('div'); root.style.cssText = 'display:flex;flex-direction:column;gap:14px;height:100%;min-height:0;padding:14px;box-sizing:border-box';
      var workRow = el('div'); workRow.style.cssText = 'display:flex;gap:14px;flex:1;min-height:0';

      // ---------- LEFT: SCAN SCOPE ----------
      var left = card('SCAN SCOPE', 'Read-only. Enumerates AD objects and scores each against the account-management Technical Order. Rule set = editable JanetLocal\\adto-baseline.json (starter defaults - validate against the real TO).');
      left.style.cssText += ';flex:0 0 340px;display:flex;flex-direction:column;gap:12px;min-height:0';

      var baseWrap = el('div');
      baseWrap.appendChild(ui.label('Limit to OU / base-DN (optional)'));
      var baseInput = ui.input({ title: 'A base distinguished name to scope the scan (e.g. OU=Squadron,DC=area52,DC=mil). Leave blank to scan the whole domain - large domains can return thousands of objects.' });
      baseInput.placeholder = 'blank = whole domain';
      baseInput.style.cssText += ';width:100%';
      baseWrap.appendChild(baseInput);
      var baseHint = el('div', 'muted', 'Blank scans the whole domain (can be large).'); baseHint.style.fontSize = '11px'; baseHint.style.marginTop = '4px';
      baseWrap.appendChild(baseHint);
      left.appendChild(baseWrap);

      var catWrap = el('div');
      catWrap.appendChild(ui.label('Categories (optional)'));
      var catInput = ui.input({ title: 'Comma list to restrict the scan to certain categories, e.g. "Admin, Service". Blank = all five.' });
      catInput.placeholder = 'blank = all (User, Admin, Service, Computer, Server)';
      catInput.style.cssText += ';width:100%';
      catWrap.appendChild(catInput);
      left.appendChild(catWrap);

      var onlyBad = ui.checkbox('Only show NON-COMPLIANT objects', { title: 'Skip compliant objects in the results grid (the category counts still reflect the full population).' });
      left.appendChild(onlyBad);

      workRow.appendChild(left);

      // ---------- RIGHT ----------
      var right = el('div'); right.style.cssText = 'flex:1;min-width:0;display:flex;flex-direction:column;gap:12px;min-height:0';

      // headline tiles
      var tiles = C.StatCards({ cards: [
        { key: 'total', label: 'AD OBJECTS', color: 'cyan' },
        { key: 'bad', label: 'NON-COMPLIANT', color: 'bad' },
        { key: 'iao', label: 'NEED IAO VALIDATION', color: 'gold' }
      ] });
      right.appendChild(tiles.el);

      // action bar
      var actionCard = ui.card({}); actionCard.style.cssText += ';display:flex;align-items:center;gap:14px;flex-wrap:wrap';
      var statusLine = el('span', 'muted', 'Ready'); statusLine.style.minWidth = '160px';
      actionCard.appendChild(statusLine);
      var spacer = el('div'); spacer.style.flex = '1'; actionCard.appendChild(spacer);
      var exportBtn = ui.ghostButton('Export CSV', { size: 'sm', title: 'Export the result rows to a CSV file.' });
      var clearBtn = ui.button('Clear', { variant: 'danger', size: 'sm', title: 'Clear the results grid + reset counts.' });
      var ctaHolder = el('div'); ctaHolder.style.width = '240px';
      var runbar = C.RunBar({
        label: 'SCAN AD COMPLIANCE', morphToCancel: true, cancelLabel: 'CANCEL SCAN',
        title: 'Read-only AD Technical-Order compliance scan.',
        guards: [],
        onRun: doRun,
        onCancel: function () { if (run) { run.cancel(); actlog.append({ text: 'CANCEL requested.', level: 'warn' }); } }
      });
      ctaHolder.appendChild(runbar.el);
      actionCard.appendChild(exportBtn); actionCard.appendChild(clearBtn); actionCard.appendChild(ctaHolder);
      right.appendChild(actionCard);

      // category filter chips
      var chipRow = el('div'); chipRow.style.cssText = 'display:flex;gap:6px;flex-wrap:wrap;align-items:center';
      var chips = {};
      ['All'].concat(CATS).forEach(function (c) {
        var b = ui.ghostButton(c, { size: 'sm', title: 'Show only ' + (c === 'All' ? 'all categories' : c + ' objects') + '.' });
        b.onclick = function () { filterCat = c; renderFilter(); };
        chips[c] = b; chipRow.appendChild(b);
      });
      right.appendChild(chipRow);

      // remediation (bulk, on the currently-shown NON-COMPLIANT objects)
      var AUTOFIX = [
        ['inactiveEnabled', 'Disable inactive'], ['staleObject', 'Disable stale'],
        ['passwordNeverExpires', 'Clear never-expire'], ['passwordNotRequired', 'Clear passwd-not-reqd'],
        ['reversibleEncryption', 'Clear reversible-enc'], ['smartcardNotRequired', 'Set smartcard-req']
      ];
      var fixCard = ui.card({}); fixCard.style.cssText += ';display:flex;flex-direction:column;gap:8px';
      fixCard.appendChild(el('div', 'j-section-h', 'REMEDIATE (shown non-compliant)'));
      var fixNote = el('div', 'muted', 'Bulk auto-fix (userAccountControl flips only) across the currently-shown NON-COMPLIANT objects. Description / manager / SPN are never auto-guessed. IAO Validate stamps TO-VALIDATED on objects flagged for recert (IAO-only, gated server-side). Needs an admin session.');
      fixNote.style.cssText = 'font-size:11px;line-height:1.4'; fixCard.appendChild(fixNote);
      var cbRow = el('div'); cbRow.style.cssText = 'display:flex;gap:12px;flex-wrap:wrap';
      var fixCbs = {};
      AUTOFIX.forEach(function (p) { var c = ui.checkbox(p[1], {}); fixCbs[p[0]] = c; cbRow.appendChild(c); });
      fixCard.appendChild(cbRow);
      var fixCtl = el('div'); fixCtl.style.cssText = 'display:flex;gap:8px;align-items:center;flex-wrap:wrap';
      fixCtl.appendChild(ui.label('Confirm:'));
      var fixConfirm = ui.input({ title: 'Type FIX to arm the auto-fix, or VALIDATE to arm IAO validation.' });
      fixConfirm.placeholder = 'FIX or VALIDATE'; fixConfirm.style.width = '140px'; fixCtl.appendChild(fixConfirm);
      var fixBtn = ui.button('FIX SHOWN', { variant: 'danger', size: 'sm', title: 'Apply the checked fixes to every shown non-compliant object that has that finding.' });
      var valBtn = ui.button('IAO VALIDATE SHOWN', { variant: 'gold', size: 'sm', title: 'IAO-only: stamp TO-VALIDATED on every shown object flagged recertifyOverdue. Refused server-side unless you are on the IAO allow-list.' });
      fixCtl.appendChild(fixBtn); fixCtl.appendChild(valBtn);
      fixCard.appendChild(fixCtl);
      right.appendChild(fixCard);

      // results grid
      var results = card('RESULTS');
      results.style.cssText += ';flex:1;min-height:0;display:flex;flex-direction:column';
      var grid = C.ResultsGrid({
        title: 'AD TO compliance results',
        emptyText: 'No results yet - set a scope (or leave blank for the whole domain), then Scan AD Compliance.',
        keyMode: { hostCol: 'DN' }, popOut: true,
        columns: [
          { key: 'Object', label: 'OBJECT', width: 150 },
          { key: 'Category', label: 'CATEGORY', width: 100 },
          { key: 'Status', label: 'STATUS', width: 130, render: function (r) { return { text: r.Status == null ? '' : String(r.Status), cls: statusCellCls(r.Status) }; } },
          { key: 'Rules', label: 'RULES / APPLIED', width: 170, render: function (r) { return { text: r.Applied != null && r.Applied !== '' ? String(r.Applied) : (r.Rules == null ? '' : String(r.Rules)) }; } },
          { key: 'Detail', label: 'REASON -> FIX', render: function (r) { var t = r.Detail == null ? '' : String(r.Detail); return { text: t, title: t }; } },
          { key: 'DN', label: 'DISTINGUISHED NAME', width: 220 }
        ],
        rowClass: function (r) { var s = String(r.Status); if (s === 'COMPLIANT') return 'row-ok'; if (s === 'NON-COMPLIANT') return 'row-bad'; return ''; }
      });
      var gridHolder = el('div'); gridHolder.style.cssText = 'flex:1;min-height:0;display:flex'; gridHolder.appendChild(grid.el);
      results.appendChild(gridHolder);
      var prog = C.ProgressStatusStrip({ showCount: true });
      prog.el.style.marginTop = '8px';
      results.appendChild(prog.el);
      right.appendChild(results);

      workRow.appendChild(right);
      root.appendChild(workRow);

      // activity log dock
      var logCard = ui.card({}); logCard.classList.add('j-logdock');
      var actlog = C.ActivityLog({ title: 'ACTIVITY LOG', defaultName: 'ADNemesis' });
      logCard.appendChild(actlog.el);
      root.appendChild(logCard);

      // ---------- behaviour ----------
      function setStatus(txt, cls) { statusLine.textContent = txt == null ? '' : String(txt); statusLine.className = cls || 'muted'; }
      function isRunning() { return !!(run && run.state && run.state.active); }
      // audit 2026-07-23 deferred pass: S3 lockInputs consolidation (fixCbs is fully
      // populated above, so the flat control list is captured complete here)
      var lockInputs = ctx.util.lockable(
        [baseInput, catInput, onlyBad._cb, clearBtn, fixConfirm, fixBtn, valBtn]
          .concat(Object.keys(fixCbs).map(function (k) { return fixCbs[k]._cb; })));

      // audit 2026-07-24 (P2): the runbar was driven ONLY by the scan run, so during a
      // DESTRUCTIVE fix/validate it sat idle and still read "SCAN AD COMPLIANCE". One click
      // launched a fresh scan whose subscribe() replaced this view's single `unsub`/`run`,
      // detaching the LIVE write run - which kept committing userAccountControl to AD with no
      // rows, no audit surface and no way to cancel it. One owner for the bar's state.
      var RUN_LABEL = 'SCAN AD COMPLIANCE';
      function setRunMode(verb) {
        runbar.setActive(!!verb);
        runbar.cta.textContent = verb ? ('CANCEL ' + String(verb).toUpperCase()) : RUN_LABEL;
      }

      // audit 2026-07-24 (P2): the SERVER's summary is the authority for the headline numbers.
      // The row stream is FILTERED when "Only show NON-COMPLIANT" is ticked, so tallying rows
      // client-side counted only the bad objects and then reported that as the TOTAL - the tiles
      // and the completion dialog read "142 objects / 142 non-compliant" on a 4000-object domain,
      // hiding the true compliance ratio. The engine's summary is computed over the FULL scanned
      // population (see $byCat/$total in the scan), so apply it when it arrives; the row-derived
      // tally stays as the live in-progress display and the fallback for an absent summary.
      function applySummary(s) {
        if (!s) return;
        if (typeof s.total === 'number') counts.total = s.total;
        if (typeof s.nonCompliant === 'number') counts.bad = s.nonCompliant;
        if (typeof s.iaoRequired === 'number') counts.iao = s.iaoRequired;
        var bc = s.byCategory;
        if (!bc) return;
        CATS.forEach(function (c) {
          var e = bc[c]; if (!e) return;
          catCounts[c] = { total: Number(e.total) || 0, bad: Number(e.bad) || 0 };
        });
      }

      function updateTiles() { tiles.setAll({ total: counts.total, bad: counts.bad, iao: counts.iao }); }
      function updateChips() {
        Object.keys(chips).forEach(function (c) {
          var b = chips[c];
          var lbl = c;
          if (c !== 'All') { var cc = catCounts[c]; lbl = c + ' (' + cc.bad + '/' + cc.total + ')'; }
          else { lbl = 'All (' + counts.bad + '/' + counts.total + ')'; }
          b.textContent = lbl;
          b.style.opacity = (filterCat === c) ? '1' : '0.62';
          b.style.fontWeight = (filterCat === c) ? '700' : '400';
        });
      }
      function rowMatches(r) { return filterCat === 'All' || String(r.Category) === filterCat; }
      function renderFilter() {
        grid.clear();
        allRows.forEach(function (r) { if (rowMatches(r)) grid.upsert(r); });
        updateChips();
      }

      function resetState() {
        allRows = []; counts = { total: 0, bad: 0, iao: 0 };
        CATS.forEach(function (c) { catCounts[c] = { total: 0, bad: 0 }; });
        filterCat = 'All'; grid.clear(); prog.reset(); updateTiles(); updateChips();
      }

      clearBtn.onclick = function () { if (isRunning()) return; resetState(); setStatus('Ready'); };
      exportBtn.onclick = function () {
        var rows = allRows.filter(rowMatches);
        if (!rows.length) { ctx.confirm({ title: 'Nothing to export', body: 'Run a scan first - there are no result rows yet.', okText: 'OK', cancelText: null }); return; }
        ctx.util.exportCsv('ADNemesis_' + (filterCat === 'All' ? 'all' : filterCat), EXPORT_COLS, rows);
      };

      function ingestRow(r) {
        allRows.push(r);
        var cat = String(r.Category);
        counts.total++;
        if (catCounts[cat]) catCounts[cat].total++;
        if (String(r.Status) === 'NON-COMPLIANT') {
          counts.bad++;
          if (catCounts[cat]) catCounts[cat].bad++;
          if (r.Rules && String(r.Rules).indexOf('recertifyOverdue') >= 0) counts.iao++;
        }
        if (rowMatches(r)) grid.upsert(r);
      }

      async function doRun() {
        // audit 2026-07-24 (P2): belt-and-braces - the runbar routes a click to onCancel while a
        // run is active, but never let a stray call start a second run over a live (possibly
        // DESTRUCTIVE) one and orphan its stream.
        if (isRunning()) return;
        resetState();
        if (!baseInput.value) {
          var go = await ctx.confirm({ title: 'Whole-domain scan', body: 'No base-DN set - this enumerates EVERY user and computer in the domain, which can be thousands of objects and take a while. Continue?', okText: 'Scan whole domain', cancelText: 'Cancel' });
          if (!go) return;
        }
        setStatus('Scanning AD...', 'st-info');
        lockInputs(true);
        run = ctx.run('scan', {
          SearchBase: String(baseInput.value || '').trim(),
          Categories: String(catInput.value || '').trim(),
          OnlyNonCompliant: onlyBad._cb.checked
        }, { keyOf: function (ev) { return ev.DN != null ? String(ev.DN) : null; }, destructive: false });
        if (unsub) unsub();
        unsub = run.subscribe({
          status: function (t) { setStatus(t, 'st-info'); prog.setPhase(t); },
          progress: function (p) { prog.setProgress(p.done, p.total); setStatus('Scanned ' + p.done + ' object(s)...', 'st-info'); updateTiles(); updateChips(); },
          row: function (r) { ingestRow(r); },
          log: function (l) { actlog.append(l); },
          error: function (e) { setStatus((e && e.text) || 'Scan error', 'st-bad'); if (e && e.text) actlog.append({ text: e.text, level: 'err' }); },
          active: function (a) {
            setRunMode(a ? 'Scan' : null);
            if (!a) { lockInputs(false); updateTiles(); updateChips(); }
          },
          final: function (res) {
            applySummary(res && res.summary);
            updateTiles(); updateChips();
            var anyBad = counts.bad > 0;
            var catLine = CATS.map(function (c) { return c + ': ' + catCounts[c].bad + '/' + catCounts[c].total; }).join('<br>');
            var stopped = !!(res && res.summary && res.summary.cancelled);
            // With "Only show NON-COMPLIANT" ticked the grid holds fewer rows than the totals
            // above - say so, or the numbers look wrong next to the visible row count.
            var shownNote = (allRows.length !== counts.total)
              ? '<br><span class="muted">Grid shows ' + allRows.length + ' row(s) - compliant objects were filtered out of the stream.</span>' : '';
            setStatus((stopped ? 'Cancelled - ' : 'Done - ') + counts.bad + ' non-compliant of ' + counts.total + '.', stopped ? 'st-warn' : (anyBad ? 'st-warn' : 'st-ok'));
            ctx.confirm({
              title: 'AD Nemesis - Scan ' + (stopped ? 'Cancelled' : 'Complete'),
              body: (stopped ? '<b>Cancelled by operator - these counts cover only the objects scanned so far.</b><br><br>' : '')
                + 'Total objects: <b>' + counts.total + '</b><br>Non-compliant: <b>' + counts.bad + '</b><br>Need IAO validation: <b>' + counts.iao + '</b>' + shownNote + '<br><br><b>By category (non-compliant / total):</b><br>' + catLine + '<br><br><span class="muted">Click a category chip to filter.</span>',
              okText: 'OK', cancelText: null
            });
          }
        });
      }

      // shown non-compliant rows (respecting the active category filter)
      function shownNonCompliant() { return allRows.filter(rowMatches).filter(function (r) { return String(r.Status) === 'NON-COMPLIANT'; }); }

      function bindWriteRun(verb) {
        if (unsub) unsub();
        // audit 2026-07-25 (fable re-audit follow-up): remember the ENGINE's own verdict.
        // shell.js reduces the 'final' event inside the poll loop and only dispatches
        // 'active:false' after that loop exits, so this flag is always set by the time
        // the terminal branch below reads it (replay() for a late binder is ordered the
        // same way: final, then active).
        var cancelled = false;
        unsub = run.subscribe({
          status: function (t) { setStatus(t, 'st-info'); prog.setPhase(t); },
          progress: function (p) { prog.setProgress(p.done, p.total); setStatus(verb + '... ' + p.done + ' / ' + p.total, 'st-info'); },
          row: function (r) { grid.upsert(r); },   // keyed by DN -> updates the object's row in place (NON-COMPLIANT -> FIXED/VALIDATED)
          log: function (l) { actlog.append(l); },
          error: function (e) { setStatus((e && e.text) || 'error', 'st-bad'); if (e && e.text) actlog.append({ text: e.text, level: 'err' }); },
          final: function (res) { if (res && res.summary && res.summary.cancelled) cancelled = true; },
          active: function (a) {
            // audit 2026-07-24 (P2): own the runbar for the write run too - it morphs to
            // CANCEL FIX / CANCEL VALIDATE (which now reaches the engine's __job cancel
            // bridge) instead of staying a live SCAN button that would orphan this stream.
            setRunMode(a ? verb : null);
            if (!a) {
              lockInputs(false);
              // audit 2026-07-25 (fable re-audit follow-up): this used to paint '<verb> done'
              // GREEN and pop a '<verb> complete' dialog UNCONDITIONALLY, stomping the
              // server's honest 'Cancelled. X fixed of Y' status - a success headline over
              // a half-finished DESTRUCTIVE AD write, with only the log/grid telling the
              // truth. A hard-killed job never emits 'final', so also honour the run-state's
              // own 'cancelled' status as a second source.
              var stopped = cancelled || !!(run && run.state && String(run.state.status) === 'cancelled');
              if (stopped) {
                setStatus(verb + ' CANCELLED - partial write; only some objects were changed.', 'st-warn');
                ctx.confirm({
                  title: 'AD Nemesis - ' + verb + ' Cancelled',
                  body: '<b>Cancelled by the operator - the ' + verb.toLowerCase() + ' did NOT complete.</b><br><br>Only part of the plan was written to AD. The grid rows and the activity log show exactly which objects were changed. Re-run the scan before deciding what still needs work.',
                  okText: 'OK', cancelText: null
                });
              } else {
                setStatus(verb + ' done - re-scan to refresh compliance counts.', 'st-ok');
                ctx.confirm({ title: 'AD Nemesis - ' + verb + ' complete', body: 'Re-run the scan to confirm the affected objects now read COMPLIANT and refresh the category counts.', okText: 'OK', cancelText: null });
              }
            }
          }
        });
      }

      async function doFix() {
        if (isRunning()) return;
        var selected = AUTOFIX.map(function (p) { return p[0]; }).filter(function (k) { return fixCbs[k]._cb.checked; });
        if (!selected.length) { ctx.confirm({ title: 'No fix selected', body: 'Check at least one auto-fix (userAccountControl flip).', okText: 'OK', cancelText: null }); return; }
        var plan = shownNonCompliant().map(function (r) {
          var rowRules = String(r.Rules == null ? '' : r.Rules).split(',').map(function (s) { return s.trim(); });
          var rules = selected.filter(function (k) { return rowRules.indexOf(k) >= 0; });
          return rules.length ? { dn: r.DN, rules: rules } : null;
        }).filter(Boolean);
        if (!plan.length) { ctx.confirm({ title: 'Nothing to fix', body: 'No shown NON-COMPLIANT object has the checked finding(s). Adjust the category filter or the checks.', okText: 'OK', cancelText: null }); return; }
        if (!ctx.session.state.credSet) { ctx.confirm({ title: 'Admin session required', body: 'Set a credential (top-right) and start an admin session before a fix - it writes to AD.', okText: 'OK', cancelText: null }); return; }
        if (fixConfirm.value !== 'FIX') { ctx.confirm({ title: 'Type FIX', body: 'Type FIX (exactly) in Confirm to arm the fix.', okText: 'OK', cancelText: null }); return; }
        var ok = await ctx.arm({
          title: 'Arm AD Fix', banner: 'DESTRUCTIVE - WRITES userAccountControl TO AD',
          body: 'About to apply <b>' + selected.length + '</b> auto-fix(es) to <b>' + plan.length + '</b> object(s). UAC flips only (disable / clear-flag / set-smartcard); description / manager / SPN are never touched. Verify-first.',
          preflight: [{ label: plan.length + ' object(s)', ok: true }, { label: 'Admin session', ok: !!ctx.session.state.credSet }, { label: 'Fixes: ' + selected.join(', '), ok: true }],
          okText: 'Run Fix', cancelText: 'Cancel'
        });
        if (!ok) { actlog.append({ text: 'Fix cancelled at arming.', level: 'warn' }); return; }
        lockInputs(true); setRunMode('Fix'); setStatus('Fixing ' + plan.length + '...', 'st-info');
        run = ctx.run('fix', { plan: JSON.stringify(plan), confirm: fixConfirm.value }, { keyOf: function (ev) { return ev.DN != null ? String(ev.DN) : null; }, destructive: true });
        bindWriteRun('Fix');
      }

      async function doValidate() {
        if (isRunning()) return;
        var plan = shownNonCompliant().filter(function (r) { return String(r.Rules == null ? '' : r.Rules).indexOf('recertifyOverdue') >= 0; }).map(function (r) { return { dn: r.DN }; });
        if (!plan.length) { ctx.confirm({ title: 'Nothing to validate', body: 'No shown object is flagged recertifyOverdue.', okText: 'OK', cancelText: null }); return; }
        if (!ctx.session.state.credSet) { ctx.confirm({ title: 'Admin session required', body: 'Set your IAO credential (top-right) and start an admin session first.', okText: 'OK', cancelText: null }); return; }
        if (fixConfirm.value !== 'VALIDATE') { ctx.confirm({ title: 'Type VALIDATE', body: 'Type VALIDATE (exactly) in Confirm to arm IAO validation.', okText: 'OK', cancelText: null }); return; }
        var ok = await ctx.arm({
          title: 'Arm IAO Validate', banner: 'IAO EXPRESS PERMISSION - WRITES THE RECERT STAMP',
          body: 'About to stamp <b>TO-VALIDATED</b> on <b>' + plan.length + '</b> object(s). This is refused server-side unless you are on the IAO allow-list. It writes ONLY the recert stamp.',
          preflight: [{ label: plan.length + ' object(s)', ok: true }, { label: 'You must be on the baseline IAO allow-list (checked server-side)', ok: true }],
          okText: 'Validate', cancelText: 'Cancel'
        });
        if (!ok) { actlog.append({ text: 'Validation cancelled at arming.', level: 'warn' }); return; }
        lockInputs(true); setRunMode('Validate'); setStatus('Validating ' + plan.length + '...', 'st-info');
        run = ctx.run('validate-iao', { plan: JSON.stringify(plan), confirm: fixConfirm.value }, { keyOf: function (ev) { return ev.DN != null ? String(ev.DN) : null; }, destructive: true });
        bindWriteRun('Validate');
      }

      fixBtn.onclick = function () { doFix(); };
      valBtn.onclick = function () { doValidate(); };

      resetState();
      host.appendChild(root);
      this._root = root; this._unsub = function () { if (unsub) unsub(); };
    }
  });
})();
