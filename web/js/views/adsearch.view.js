/* ============================================================================
   adsearch.view.js  -  AD Search Tool (tool id: 'adsearch')
   Faithful single-window (non-tabbed) re-build per docs/ui-specs/adsearch.md:
   a horizontal MODE radio bar (9 modes, one per manifest action) that SWAPS the
   visible input fields below it, a left RESULTS card (a ResultsGrid whose columns
   + row colour rules rebuild per mode) and a right EXTENDED INFO console (an
   ActivityLog showing the launch brief, the per-search summary, and the detail of
   a double-clicked row), plus a status strip (KEY :: VALUE phrasing + a progress
   strip). Double-clicking a result row mirrors a long labelled attribute block
   into EXTENDED INFO and opens an OBJECT DETAIL popup.

   AD Search is READ-ONLY: every action is non-destructive, so it runs WITHOUT an
   admin session - it never gates on credSet. Each search is a single-shot async
   run dispatched through ctx.run -> RunController; the view only subscribes.

   The engine stamps a `Host` field on EVERY row (samaccountname or name), and for
   LAST PC `Host` = the Computer - so several last-pc rows (and possibly several
   manager/base rows) can share one `Host`. To stop RunController collapsing them
   onto a shared Host key we pass a per-mode keyOf to ctx.run AND a matching
   keyMode function to the ResultsGrid (Rule 3).
   ========================================================================== */
(function () {
  'use strict';

  // ---- the 9 modes, in desktop order. id = manifest action id. heavy = the
  //      amber/export-class radios in the desktop bar. up = auto-UPPERCASE the
  //      text inputs for this mode (email + manager are NOT uppercased).
  var MODES = [
    { id: 'search-user',          tab: 'USERS',             desc: 'Find user accounts by first / last name and/or EDIPI. Partial matches allowed.' },
    { id: 'search-computer',      tab: 'COMPUTERS',         desc: 'Find computer objects by name (wildcard).' },
    { id: 'search-group',         tab: 'GROUPS',            desc: 'Find security groups / distribution lists by name (wildcard).' },
    { id: 'search-orgbox',        tab: 'ORG BOXES',         desc: 'Find organization / functional mailbox objects by name (wildcard).' },
    { id: 'search-email',         tab: 'BY EMAIL',          desc: 'Find users by email address (mail attribute, wildcard).', noUpper: true },
    { id: 'search-manager',       tab: 'BY MANAGER',        desc: "Find a manager by display name and list all direct reports (manager row highlighted).", noUpper: true },
    { id: 'search-bulk-computer', tab: 'BULK COMPUTERS',    desc: 'Batch-resolve many machine names: Active / Stale (90+d) / Not Found, with squadron/base from the OU chain.', heavy: true },
    { id: 'search-base-users',    tab: 'BASE USERS EXPORT', desc: 'Enumerate all users under a base, classifying each account as Privileged or Standard.', heavy: true },
    { id: 'search-last-pc',       tab: 'BY LAST PC',        desc: 'Discover the workstation a person was last logged into by scanning every DC Security log (4624/4768/4769/4776).', heavy: true }
  ];

  // ---- per-mode ResultsGrid column specs (labels + colour rules are HAND-WRITTEN
  //      per the ui-spec, never regex-on-name). Keys MUST match the engine's
  //      ConvertTo-AdGridRow projection / manifest columns.
  function txt(v) { return v == null ? '' : String(v); }

  function bulkStatusCls(v) {
    var s = String(v || '').toLowerCase();
    if (s.indexOf('active') >= 0) return 'st-ok';
    if (s.indexOf('stale') >= 0) return 'st-warn';
    if (s.indexOf('not found') >= 0 || s.indexOf('error') >= 0) return 'st-bad';
    return '';
  }
  function privCls(v) { return /priv/i.test(String(v || '')) ? 'st-warn' : 'cell-dim'; }

  // Each entry: columns[], rowClass(row)->class, keyOf(ev)->unique row key.
  // keyOf falls back to a per-mode natural unique field; the matching grid keyMode
  // uses the SAME function so grid + RunController agree on row identity.
  var GRIDS = {
    'search-user': {
      columns: [
        { key: 'DisplayName', label: 'DISPLAY NAME', width: 180 },
        { key: 'SamAccountName', label: 'SAMACCOUNT', width: 130 },
        { key: 'Email', label: 'EMAIL', width: 200 },
        { key: 'Title', label: 'TITLE', width: 150 },
        { key: 'Department', label: 'DEPARTMENT', width: 140 },
        { key: 'Company', label: 'COMPANY', width: 120 },
        { key: 'LockedOut', label: 'LOCKED', width: 80, render: function (r) { var lo = /true|yes/i.test(String(r.LockedOut)); return { text: txt(r.LockedOut), cls: lo ? 'st-bad' : 'cell-dim' }; } },
        { key: 'LastLogon', label: 'LAST LOGON', width: 150 },
        { key: 'Manager', label: 'MANAGER', width: 160 }
      ],
      keyOf: function (e) { return e.DistinguishedName || e.SamAccountName || e.Host; }
    },
    'search-computer': {
      columns: [
        { key: 'Name', label: 'COMPUTER', width: 160 },
        { key: 'OperatingSystem', label: 'OPERATING SYSTEM', width: 200 },
        { key: 'OSVersion', label: 'OS VERSION', width: 130 },
        { key: 'LastLogon', label: 'LAST LOGON', width: 150 },
        { key: 'DnsHostName', label: 'DNS NAME', width: 220 },
        { key: 'Location', label: 'LOCATION', width: 160 }
      ],
      keyOf: function (e) { return e.DistinguishedName || e.Name || e.Host; }
    },
    'search-group': {
      columns: [
        { key: 'Name', label: 'GROUP', width: 220 },
        { key: 'MemberCount', label: 'MEMBERS', width: 90, render: function (r) { return { text: txt(r.MemberCount), cls: 'st-info' }; } },
        { key: 'ManagedBy', label: 'MANAGED BY', width: 200 },
        { key: 'WhenCreated', label: 'CREATED', width: 160 },
        { key: 'WhenChanged', label: 'CHANGED', width: 160 }
      ],
      keyOf: function (e) { return e.DistinguishedName || e.Name || e.Host; }
    },
    'search-orgbox': {
      columns: [
        { key: 'Name', label: 'NAME', width: 200 },
        { key: 'DisplayName', label: 'DISPLAY NAME', width: 220 },
        { key: 'Email', label: 'EMAIL', width: 280 }
      ],
      keyOf: function (e) { return e.DistinguishedName || e.Name || e.Host; }
    },
    'search-email': {
      columns: [
        { key: 'DisplayName', label: 'DISPLAY NAME', width: 220 },
        { key: 'SamAccountName', label: 'SAMACCOUNT', width: 140 },
        { key: 'Email', label: 'EMAIL ADDRESS', width: 260 },
        { key: 'Title', label: 'TITLE', width: 160 },
        { key: 'Department', label: 'DEPARTMENT', width: 150 },
        { key: 'Company', label: 'COMPANY', width: 130 }
      ],
      keyOf: function (e) { return e.DistinguishedName || e.SamAccountName || e.Email || e.Host; }
    },
    'search-manager': {
      columns: [
        { key: 'Role', label: 'ROLE', width: 110, render: function (r) { var mgr = /manager/i.test(String(r.Role)); return { text: txt(r.Role), cls: mgr ? 'st-warn' : 'cell-dim' }; } },
        { key: 'DisplayName', label: 'NAME', width: 200 },
        { key: 'SamAccountName', label: 'SAMACCOUNT', width: 140 },
        { key: 'Title', label: 'TITLE', width: 170 },
        { key: 'Department', label: 'DEPARTMENT', width: 150 },
        { key: 'Email', label: 'EMAIL', width: 220 },
        { key: 'DirectReportCount', label: 'REPORTS', width: 90, render: function (r) { return { text: txt(r.DirectReportCount), cls: 'st-info' }; } }
      ],
      // manager row tinted gold (alt-panel in the desktop); reports stay neutral
      rowClass: function (r) { return /manager/i.test(String(r.Role)) ? 'row-warn' : ''; },
      keyOf: function (e) { return (e.Role || '') + '|' + (e.SamAccountName || e.DisplayName || e.Host || ''); }
    },
    'search-bulk-computer': {
      columns: [
        { key: 'Name', label: 'COMPUTER', width: 150 },
        { key: 'Organization', label: 'ORGANIZATION', width: 170 },
        { key: 'Squadron', label: 'SQUADRON / OU', width: 150 },
        { key: 'OUChain', label: 'OU CHAIN', width: 240 },
        { key: 'OperatingSystem', label: 'OPERATING SYSTEM', width: 180 },
        { key: 'LastLogon', label: 'LAST LOGON', width: 150 },
        { key: 'Status', label: 'STATUS', width: 110, render: function (r) { return { text: txt(r.Status), cls: bulkStatusCls(r.Status) }; } }
      ],
      // green=Active, amber=Stale, red=Not Found / Error
      rowClass: function (r) {
        var c = bulkStatusCls(r.Status);
        return c === 'st-ok' ? 'row-ok' : c === 'st-warn' ? 'row-warn' : c === 'st-bad' ? 'row-bad' : '';
      },
      keyOf: function (e) { return e.Name || e.Host; }
    },
    'search-base-users': {
      columns: [
        { key: 'DisplayName', label: 'DISPLAY NAME', width: 190 },
        { key: 'SamAccountName', label: 'ACCOUNT', width: 130 },
        { key: 'Privilege', label: 'PRIVILEGE', width: 110, render: function (r) { return { text: txt(r.Privilege), cls: privCls(r.Privilege) }; } },
        { key: 'Organization', label: 'ORGANIZATION', width: 170 },
        { key: 'ParentOU', label: 'OU', width: 180 },
        { key: 'Title', label: 'TITLE', width: 160 },
        { key: 'Email', label: 'EMAIL', width: 200 },
        { key: 'PrivReason', label: 'REASON', width: 180 }
      ],
      // amber=Privileged, gray=Standard
      rowClass: function (r) { return /priv/i.test(String(r.Privilege)) ? 'row-warn' : ''; },
      keyOf: function (e) { return (e.SamAccountName || e.DisplayName || e.Host || '') + '|' + (e.ParentOU || ''); }
    },
    'search-last-pc': {
      columns: [
        { key: 'User', label: 'USER', width: 180 },
        { key: 'SamAccountName', label: 'ACCOUNT', width: 130 },
        { key: 'Computer', label: 'COMPUTER', width: 150 },
        { key: 'IPAddress', label: 'IP ADDRESS', width: 130 },
        { key: 'LastSeen', label: 'LAST SEEN', width: 170 },
        { key: 'EventId', label: 'EVENT', width: 80, render: function (r) { return { text: txt(r.EventId), cls: 'st-info' }; } },
        { key: 'LogonType', label: 'TYPE', width: 80 },
        { key: 'DC', label: 'DC', width: 150 }
      ],
      // many last-pc rows share Computer (== Host); key on the full event tuple so
      // RunController never collapses distinct logon events onto one row.
      keyOf: function (e) {
        return [e.Computer || e.Host, e.DC, e.LastSeen, e.EventId, e.SamAccountName, e.IPAddress].join('|');
      }
    }
  };

  function modeById(id) { for (var i = 0; i < MODES.length; i++) if (MODES[i].id === id) return MODES[i]; return MODES[0]; }
  function actionFromManifest(ctx, id) {
    var m = ctx.manifest;
    if (!m || !m.actions) return null;
    for (var i = 0; i < m.actions.length; i++) if (m.actions[i].id === id) return m.actions[i];
    return null;
  }
  var esc = Janet.util.esc;

  JanetViews.register('adsearch', {
    mount: function (host, ctx) {
      var ui = ctx.ui, C = ctx.components, el = ctx.util.el;

      // ----- run state -----
      var currentMode = MODES[0].id;
      var run = null, unsub = null;
      var grid = null;                 // rebuilt per mode
      var inputControls = {};          // param-name -> control (text/number)
      var bulkTargets = null;          // TargetManager for the hostlist mode
      var lastResultRows = [];         // cache for SAVE/summary

      // =================== layout ===================
      var root = el('div'); root.style.cssText = 'display:flex;flex-direction:column;height:100%;min-height:0;background:var(--bg)';

      // ---------- MODE bar ----------
      var modeCard = ui.card({}); modeCard.style.cssText += ';margin:12px 14px 0;display:flex;flex-direction:column;gap:8px';
      modeCard.appendChild(ui.eyebrow('MODE'));
      var radioBar = el('div'); radioBar.style.cssText = 'display:flex;flex-wrap:wrap;gap:6px';
      var radioBtns = {};
      MODES.forEach(function (m) {
        var b = ui.button(m.tab, { variant: m.heavy ? 'gold' : 'ghost', size: 'sm', title: m.desc });
        b.style.minWidth = '120px';
        b.onclick = function () { setMode(m.id); };
        radioBtns[m.id] = b;
        radioBar.appendChild(b);
      });
      modeCard.appendChild(radioBar);
      var modeDesc = el('div', 'muted', MODES[0].desc); modeDesc.style.fontSize = '11.5px';
      modeCard.appendChild(modeDesc);
      root.appendChild(modeCard);

      // ---------- INPUT band + action buttons ----------
      var inputCard = ui.card({}); inputCard.style.cssText += ';margin:10px 14px 0;display:flex;flex-direction:column;gap:10px';
      var inputArea = el('div'); inputArea.style.cssText = 'display:flex;flex-wrap:wrap;gap:12px;align-items:flex-end';
      inputCard.appendChild(inputArea);

      var actionRow = el('div'); actionRow.style.cssText = 'display:flex;align-items:center;gap:12px;flex-wrap:wrap';
      var statusLine = el('span'); statusLine.style.cssText = 'font-family:var(--mono);font-size:12px;letter-spacing:.04em'; setStatus('STATUS :: READY', '');
      var liveDot = ui.dot(''); // pulse-dot stand-in (idle / active / error)
      var liveWrap = el('div'); liveWrap.style.cssText = 'display:flex;align-items:center;gap:8px';
      liveWrap.appendChild(liveDot); liveWrap.appendChild(statusLine);
      actionRow.appendChild(liveWrap);
      var actSpacer = el('div'); actSpacer.style.flex = '1'; actionRow.appendChild(actSpacer);

      var saveBtn = ui.ghostButton('Save', { size: 'sm', title: 'Export the current result set (CSV).' });
      var clearBtn = ui.button('Clear', { variant: 'danger', size: 'sm', title: 'Clear the inputs, results, and console.' });
      var aboutBtn = ui.ghostButton('About', { size: 'sm', title: 'About the AD Search Tool.' });
      var ctaHolder = el('div'); ctaHolder.style.width = '220px';
      var runbar = C.RunBar({
        label: 'SEARCH', morphToCancel: true, cancelLabel: 'CANCEL SEARCH',
        title: 'Run the selected search.',
        guards: [function () { return validateInput(); }],
        onGuardFail: function (m) { brief(m, 'warn'); setStatus('STATUS :: INPUT REQUIRED', 'warn'); setDot('error'); },
        onRun: doSearch,
        onCancel: function () { if (run) { run.cancel(); brief('Cancel requested - stopping in-flight search...', 'warn'); } }
      });
      ctaHolder.appendChild(runbar.el);
      actionRow.appendChild(saveBtn); actionRow.appendChild(clearBtn); actionRow.appendChild(aboutBtn); actionRow.appendChild(ctaHolder);
      inputCard.appendChild(actionRow);
      root.appendChild(inputCard);

      // ---------- RESULTS + EXTENDED INFO ----------
      var cols = el('div'); cols.style.cssText = 'flex:1;min-height:0;display:flex;gap:12px;padding:10px 14px 4px';
      root.appendChild(cols);

      // LEFT: RESULTS (grid rebuilt per mode)
      var left = ui.card({}); left.style.cssText += ';flex:1.6;min-width:0;display:flex;flex-direction:column;min-height:0';
      // RESULTS header: title + a client quick-filter over the loaded rows. Base
      // Users Export / Bulk Computer routinely return hundreds-to-thousands of rows,
      // so a case-insensitive substring filter (grid.setFilter) over the visible
      // columns is the only large-fleet affordance the grid was missing.
      var resultsHdr = el('div'); resultsHdr.style.cssText = 'display:flex;align-items:center;gap:10px;margin-bottom:6px';
      var resultsTitle = el('div', 'j-section-h', 'RESULTS');
      var rhSpacer = el('div'); rhSpacer.style.flex = '1';
      var filterInput = ui.input({ value: '', title: 'Quick-filter the loaded results (case-insensitive substring across the visible columns).', placeholder: 'Filter results...' });
      filterInput.style.cssText += ';width:200px';
      filterInput.addEventListener('input', applyFilter);
      resultsHdr.appendChild(resultsTitle); resultsHdr.appendChild(rhSpacer); resultsHdr.appendChild(filterInput);
      left.appendChild(resultsHdr);
      var gridHolder = el('div'); gridHolder.style.cssText = 'flex:1;min-height:0;display:flex';
      left.appendChild(gridHolder);
      var prog = C.ProgressStatusStrip({ showCount: true });
      prog.el.style.marginTop = '8px';
      left.appendChild(prog.el);
      cols.appendChild(left);

      // EXTENDED INFO console - full-width dock across the bottom of the tool
      // (was boxed in the right column of the RESULTS row)
      var right = ui.card({}); right.classList.add('j-logdock'); right.style.cssText += ';margin:0 16px 14px';
      var info = C.ActivityLog({ title: 'EXTENDED INFO', defaultName: 'ADSearch_ExtendedInfo' });
      right.appendChild(info.el);
      root.appendChild(right);

      // ---------- footer ----------
      var footer = el('div', 'j-footer');
      footer.appendChild(el('span', 'credit', 'AD Search Tool // Directory Lookup'));
      footer.appendChild(el('span', null, 'RSAT-free (ADSI/ADSISearcher) - read-only'));
      root.appendChild(footer);

      // =================== helpers ===================
      function secHdr(t) { var h = el('div', 'j-section-h', t); h.style.marginBottom = '6px'; return h; }
      function setStatus(txtv, cls) {
        statusLine.textContent = txtv == null ? '' : String(txtv);
        statusLine.style.color = cls === 'warn' ? 'var(--warn)' : cls === 'err' ? 'var(--danger)' : cls === 'ok' ? 'var(--ok)' : 'var(--muted)';
      }
      // map run-state -> the theme's dot classes: idle = default grey, active =
      // olive-blink (warn + pulse, per the spec), error = red.
      function setDot(state) {
        var cls = 'j-dot';
        if (state === 'active') cls += ' j-dot-warn j-dot-pulse';
        else if (state === 'error') cls += ' j-dot-bad';
        liveDot.className = cls;
      }
      function brief(text, level) { info.append({ text: text, level: level || 'dim' }); }

      // ---- build the per-mode ResultsGrid ----
      function buildGrid(modeId) {
        var spec = GRIDS[modeId];
        if (unsub) { unsub(); unsub = null; }   // detach the old run's grid subscriber
        gridHolder.innerHTML = '';
        grid = C.ResultsGrid({
          title: modeById(modeId).tab,
          columns: spec.columns,
          keyMode: spec.keyOf,                     // SAME function passed to ctx.run as keyOf
          rowClass: spec.rowClass || function () { return ''; },
          popOut: true,
          onRowClick: openDetail
        });
        gridHolder.appendChild(grid.el);
      }

      // ---- client quick-filter over the loaded grid rows (reuses grid.setFilter) ----
      function applyFilter() {
        if (!grid) return;
        var q = String(filterInput.value || '').trim().toLowerCase();
        if (q === '') { grid.setFilter(null); return; }
        var cols = (GRIDS[currentMode] && GRIDS[currentMode].columns) || [];
        grid.setFilter(function (r) {
          for (var i = 0; i < cols.length; i++) {
            var val = r[cols[i].key];
            if (String(val == null ? '' : val).toLowerCase().indexOf(q) >= 0) return true;
          }
          return false;
        });
      }
      function clearFilter() { if (filterInput) filterInput.value = ''; if (grid) grid.setFilter(null); }

      // ---- swap the visible input fields for a mode (the field-swap) ----
      function setMode(modeId) {
        if (run && run.state && run.state.active) return;  // no field-swap mid-run
        currentMode = modeId;
        MODES.forEach(function (m) {
          var b = radioBtns[m.id]; var on = (m.id === modeId);
          b.classList.toggle('is-active', on);
          b.style.outline = on ? '1px solid var(--accent)' : 'none';
          b.style.opacity = on ? '1' : '0.78';
        });
        modeDesc.textContent = modeById(modeId).desc;
        buildInputs(modeId);
        buildGrid(modeId);
        clearFilter();          // drop any quick-filter text when the columns change
        prog.reset();
        setStatus('STATUS :: READY', '');
        setDot('');
      }

      // ---- build inputs from the selected action's manifest inputs ----
      function buildInputs(modeId) {
        inputArea.innerHTML = '';
        inputControls = {}; bulkTargets = null;
        var act = actionFromManifest(ctx, modeId);
        var inputs = (act && act.inputs) ? act.inputs : [];
        var mode = modeById(modeId);

        inputs.forEach(function (inp) {
          if (inp.type === 'hostlist') {
            // BULK: replace the field row with the MACHINE LIST panel
            var holder = el('div'); holder.style.cssText = 'flex:1;min-width:280px;display:flex;flex-direction:column';
            bulkTargets = C.TargetManager({
              model: ctx.util.targetModel(''),
              hint: 'One machine name per line - or Import TXT',
              importLabel: 'Import TXT', importAccept: '.txt,.csv',
              countNoun: 'target',
              onImport: function (n, name) { brief('IMPORTED :: ' + n + ' HOSTNAME(S) from ' + name, 'info'); }
            });
            holder.appendChild(bulkTargets.el);
            inputArea.appendChild(holder);
            inputControls[inp.name] = { _bulk: true };
            return;
          }
          var ctrl;
          if (inp.type === 'int') {
            ctrl = ui.number({ value: (inp.default != null ? inp.default : ''), title: inp.label });
            ctrl.style.width = '120px';
          } else {
            ctrl = ui.input({ value: '', title: inp.label, placeholder: inp.label });
            ctrl.style.width = (inp.name === 'SearchBase' || /name|email|group|orgbox|manager|base/i.test(inp.name)) ? '300px' : '170px';
            if (!mode.noUpper && inp.name !== 'SearchBase') {
              // auto-UPPERCASE (desktop behaviour); SearchBase (a DN) is left as typed
              ctrl.addEventListener('input', function () {
                var p = ctrl.selectionStart; ctrl.value = ctrl.value.toUpperCase();
                try { ctrl.setSelectionRange(p, p); } catch (e) {}
              });
            }
            ctrl.addEventListener('keydown', function (e) { if (e.key === 'Enter') { e.preventDefault(); runbar.cta.click(); } });
          }
          inputControls[inp.name] = ctrl;
          inputArea.appendChild(ui.field(inp.label + (inp.required ? ' *' : ''), ctrl));
        });
      }

      // ---- read params from the live controls ----
      function readParams() {
        var p = {};
        Object.keys(inputControls).forEach(function (name) {
          var c = inputControls[name];
          if (c && c._bulk) { p[name] = bulkTargets ? bulkTargets.getText() : ''; }
          else if (c) { p[name] = c.value; }
        });
        return p;
      }

      // ---- per-mode minimum-input validation (ui-spec ChooseSearchOptions) ----
      function validateInput() {
        var p = readParams();
        var v = function (k) { return String(p[k] || '').trim(); };
        switch (currentMode) {
          case 'search-user':
            // Mirror the engine guard (psm1: reject unless LastName>=2 or EDIPI>=10).
            // First-name-only is refused server-side, so block it here too rather
            // than dispatch a search that returns a confusing "0 results".
            if (!(v('LastName').length >= 2 || v('EDIPI').length >= 10))
              return 'Enter a last name (2+ chars) or a 10-digit EDIPI to search users.';
            return null;
          case 'search-computer':
            return v('ComputerName').length >= 4 ? null : 'Enter at least 4 characters of the computer name.';
          case 'search-group':
            return v('GroupName').length >= 4 ? null : 'Enter at least 4 characters of the group name.';
          case 'search-orgbox':
            return v('OrgBoxName').length >= 4 ? null : 'Enter at least 4 characters of the org box name.';
          case 'search-email':
            return v('EmailAddress').length >= 3 ? null : 'Enter at least 3 characters of the email address.';
          case 'search-manager':
            return v('ManagerName').length >= 3 ? null : "Enter at least 3 characters of the manager's display name.";
          case 'search-base-users':
            return v('BaseName').length >= 3 ? null : 'Enter at least 3 characters of the base / location name.';
          case 'search-bulk-computer':
            return (bulkTargets && bulkTargets.count() >= 1) ? null : 'Add at least one machine name to the list.';
          case 'search-last-pc':
            // Mirror the engine guard (psm1: name>=2 or EDIPI>=10). Last PC is an
            // expensive DC-Security-log fan-out, so reject sub-minimum input up front.
            if (!(v('FirstName').length >= 2 || v('LastName').length >= 2 || v('EDIPI').length >= 10))
              return 'Enter a first or last name (2+ chars), or a 10-digit EDIPI, for the Last PC scan.';
            return null;
          default: return null;
        }
      }

      // ---- the search run (single-shot async) ----
      function doSearch() {
        var spec = GRIDS[currentMode];
        var mode = modeById(currentMode);
        var params = readParams();
        lastResultRows = [];
        grid.clear(); clearFilter(); prog.reset();
        info.banner('SEARCH :: ' + mode.tab);
        // echo criteria
        var crit = Object.keys(params).filter(function (k) { return String(params[k] || '').trim() !== ''; })
          .map(function (k) { return k + '=' + String(params[k]).split(/\r?\n/).slice(0, 3).join(',') + (String(params[k]).split(/\r?\n/).length > 3 ? '...' : ''); });
        brief('Criteria: ' + (crit.length ? crit.join('  ') : '(none)'), 'mode');
        setStatus('SEARCHING :: ' + mode.tab + ' :: please wait', '');
        setDot('active');

        run = ctx.run(currentMode, params, { keyOf: spec.keyOf });
        if (unsub) unsub();
        var rowCount = 0, hadError = false, cancelled = false, refusedMsg = null;
        unsub = run.subscribe({
          status: function (t) { prog.setPhase(t); },
          progress: function (pp) { prog.setProgress(pp.done, pp.total); },
          row: function (r) {
            grid.upsert(r);
            lastResultRows.push(r);
            // an engine soft/hard error is projected into the first column as "(error) ..."
            var first = r[spec.columns[0].key];
            if (typeof first === 'string' && first.indexOf('(error)') === 0) { hadError = true; brief(first, 'err'); }
            else rowCount++;
          },
          log: function (l) { info.append(l); },
          error: function (e) { hadError = true; info.append({ text: e.text, level: 'err' }); },
          final: function (res) {
            if (res && res.summary && res.summary.cancelled) cancelled = true;
            // The engine signals a refused term / soft error (invalid OU, sub-minimum
            // input, no match) via summary.message + 0 rows (not an error event), so
            // capture it to avoid painting a green "OK :: 000 RESULTS".
            if (res && res.summary && res.summary.message) refusedMsg = res.summary.message;
          },
          active: function (a) {
            runbar.setActive(a);
            lockInputs(a);
            if (!a) finishRun();
          }
        });

        function finishRun() {
          var n = grid.rows().length;
          if (cancelled) {
            prog.setProgress(n, n);
            setStatus('STATUS :: CANCELLED :: ' + String(n).padStart(3, '0') + ' PARTIAL', 'warn'); setDot('error');
            return;
          }
          if (hadError && rowCount === 0) {
            setStatus('STATUS :: SEARCH ERROR', 'err'); setDot('error');
            brief('Search failed - see the lines above.', 'err');
            return;
          }
          if (refusedMsg && n === 0) {
            prog.setProgress(0, 0);
            setStatus('STATUS :: NO RESULTS - SEE CONSOLE', 'warn'); setDot('error');
            return;
          }
          prog.setProgress(n, n);
          setStatus('STATUS :: OK :: ' + String(n).padStart(3, '0') + ' RESULTS', 'ok'); setDot('');
          renderSummary(currentMode, grid.rows());
          if (n > 0) brief('Double-click a row to view extended information.', 'mode');
        }
      }

      // ---- EXTENDED INFO summary (per the desktop summary pane) ----
      function renderSummary(modeId, rows) {
        info.append({ text: rows.length + ' result(s).', level: 'ok' });
        if (modeId === 'search-bulk-computer') {
          var a = 0, st = 0, nf = 0;
          rows.forEach(function (r) { var c = bulkStatusCls(r.Status); if (c === 'st-ok') a++; else if (c === 'st-warn') st++; else if (c === 'st-bad') nf++; });
          info.append({ text: 'Active: ' + a + '   Stale (90+d): ' + st + '   Not Found / Error: ' + nf, level: 'mode' });
          var byOrg = {};
          rows.forEach(function (r) { var o = String(r.Organization || '(unknown)'); byOrg[o] = (byOrg[o] || 0) + 1; });
          Object.keys(byOrg).sort().forEach(function (o) { info.append({ text: '  ' + String(byOrg[o]).padStart(3, '0') + '  ' + o, level: 'dim' }); });
        } else if (modeId === 'search-base-users') {
          var priv = rows.filter(function (r) { return /priv/i.test(String(r.Privilege)); });
          info.append({ text: 'Total: ' + rows.length + '   Privileged: ' + priv.length + '   Standard: ' + (rows.length - priv.length), level: 'mode' });
          if (priv.length) {
            info.append({ text: 'Privileged accounts:', level: 'warn' });
            priv.slice(0, 50).forEach(function (r) { info.append({ text: '  ' + (r.SamAccountName || r.DisplayName) + (r.PrivReason ? '  (' + r.PrivReason + ')' : ''), level: 'amber' }); });
          }
          info.append({ text: 'Legend:  Amber = Privileged  |  Gray = Standard', level: 'dim' });
        } else if (modeId === 'search-manager') {
          var mgr = rows.filter(function (r) { return /manager/i.test(String(r.Role)); })[0];
          if (mgr) info.append({ text: 'Manager: ' + (mgr.DisplayName || mgr.SamAccountName) + '   Direct reports: ' + (rows.length - 1), level: 'gold' });
        } else if (modeId === 'search-last-pc') {
          var dcs = {}; rows.forEach(function (r) { if (r.DC) dcs[r.DC] = 1; });
          info.append({ text: 'Logon events: ' + rows.length + '   DCs seen: ' + Object.keys(dcs).length, level: 'mode' });
        }
      }

      // ---- detail text for a result row (one field per line; groups get the OG sectioned layout) ----
      function detailLines(row) {
        // Groups: mirror the OG desktop's clean layout - sectioned, members one per line.
        if (currentMode === 'search-group') {
          var parts = String(row.Members || '').split('; ').filter(Boolean);
          var more  = parts.filter(function (m) { return /^\.\.\.\(\+/.test(m); });   // engine's "...(+N more)" cap sentinel -> keep last
          var names = parts.filter(function (m) { return !/^\.\.\.\(\+/.test(m); })
                           .sort(function (a, b) { return a.toLowerCase().localeCompare(b.toLowerCase()); });
          var fld = function (label, val) { return label.padEnd(15) + txt(val); };
          var L = [
            fld('Group:', row.Name),
            fld('Total Members:', row.MemberCount),
            '',
            fld('OU:', row.DistinguishedName),
            fld('Created:', row.WhenCreated),
            fld('Changed:', row.WhenChanged),
            fld('Manager:', row.ManagedBy),
            '',
            'Members:'
          ];
          return L.concat(names.concat(more).map(function (m) { return '  ' + m; }));
        }
        // default: labelled attribute dump, one field per line
        var lines = [];
        Object.keys(row).forEach(function (k) {
          if (k === 'type' || k === 'Host' || k.charAt(0) === '_') return;
          var v = row[k]; v = (v === true) ? 'yes' : (v === false) ? 'no' : (v == null ? '' : String(v));
          if (v === '') return;
          lines.push(String(k).padEnd(18) + ' : ' + v);
        });
        return lines;
      }

      // ---- double-click: labelled attribute block -> EXTENDED INFO + OBJECT DETAIL popup ----
      function openDetail(row) {
        var lines = detailLines(row);
        // mirror into EXTENDED INFO
        info.banner('OBJECT DETAIL');
        lines.forEach(function (l) { info.append({ text: l, level: 'dim' }); });
        // and open the popup (built from the same detail block)
        var body = el('div');
        var pre = el('pre'); pre.style.cssText = 'font-family:var(--mono);font-size:12px;white-space:pre-wrap;margin:0;color:var(--text)';
        pre.textContent = lines.join('\n');
        body.appendChild(pre);
        var title = row.DisplayName || row.Name || row.User || row.SamAccountName || 'OBJECT DETAIL';
        ctx.confirm({ title: String(title), body: body, okText: 'Close', cancelText: null });
      }

      // ---- lock inputs during a run ----
      function lockInputs(on) {
        Object.keys(inputControls).forEach(function (name) {
          var c = inputControls[name]; if (c && !c._bulk && 'disabled' in c) c.disabled = on;
        });
        MODES.forEach(function (m) { radioBtns[m.id].disabled = on; });
        clearBtn.disabled = on; saveBtn.disabled = on;
      }

      // ---- SAVE / CLEAR / ABOUT ----
      saveBtn.onclick = function () {
        var rows = grid ? grid.rows() : [];
        if (!rows.length) { ctx.confirm({ title: 'No Data', body: 'Run a search first - there are no results to save.', okText: 'OK', cancelText: null }); return; }
        var spec = GRIDS[currentMode];
        var headers = spec.columns.map(function (c) { return c.label; });
        var keys = spec.columns.map(function (c) { return c.key; });
        function toCsv(rs) { return ctx.util.toCsv(headers, rs, keys); }
        var stamp = ctx.util.fileStamp();
        // Base Users: desktop wrote TWO files (privileged vs standard) for review hand-off.
        if (currentMode === 'search-base-users') {
          var priv = rows.filter(function (r) { return /priv/i.test(String(r.Privilege)); });
          var std = rows.filter(function (r) { return !/priv/i.test(String(r.Privilege)); });
          ctx.util.downloadBlob('ADSearch_BaseUsers_PRIVILEGED_' + stamp + '.csv', 'text/csv', toCsv(priv));
          ctx.util.downloadBlob('ADSearch_BaseUsers_STANDARD_' + stamp + '.csv', 'text/csv', toCsv(std));
          brief('Saved ' + priv.length + ' privileged + ' + std.length + ' standard account(s) to 2 CSVs.', 'ok');
          return;
        }
        ctx.util.downloadBlob('ADSearch_' + currentMode + '_' + stamp + '.csv', 'text/csv', toCsv(rows));
        brief('Saved ' + rows.length + ' row(s) to CSV.', 'ok');
      };
      clearBtn.onclick = function () {
        if (run && run.state && run.state.active) return;
        Object.keys(inputControls).forEach(function (name) { var c = inputControls[name]; if (c && !c._bulk && 'value' in c) c.value = ''; });
        if (bulkTargets) bulkTargets.setText('');
        if (grid) grid.clear();
        clearFilter();
        info.clear(); prog.reset();
        setStatus('STATUS :: READY', ''); setDot('');
        printBrief();
      };
      aboutBtn.onclick = function () {
        ctx.confirm({
          title: 'About - AD Search Tool',
          body: 'Read-only Active Directory lookups via ADSI / ADSISearcher - <b>no RSAT required</b>.<br><br>' +
            'Pick a MODE (Users, Computers, Groups, Org Boxes, By Email, By Manager, Bulk Computers, Base Users Export, By Last PC), ' +
            'enter your criteria (partial allowed), and SEARCH. Double-click a result row for full detail.<br><br>' +
            'Every action is non-destructive and runs under your current directory identity.',
          okText: 'Close', cancelText: null
        });
      };

      // ---- launch brief in EXTENDED INFO ----
      function printBrief() {
        info.append({ text: 'AD SEARCH TOOL // DIRECTORY LOOKUP', level: 'accent' });
        info.append({ text: 'Read-only. RSAT-free (ADSI/ADSISearcher). Runs under your current directory identity.', level: 'dim' });
        info.append({ text: 'Flow:  pick MODE  ->  enter criteria (partial allowed)  ->  SEARCH (or Enter)', level: 'mode' });
        info.append({ text: '       ->  double-click a row for full detail  ->  SAVE (CSV)  ->  CLEAR to reset', level: 'mode' });
      }

      // ---- init ----
      setMode(MODES[0].id);
      printBrief();

      host.appendChild(root);
      this._root = root;
      this._unsub = function () { if (unsub) unsub(); };
    },
    unmount: function () { try { if (this._unsub) this._unsub(); } catch (e) {} if (this._root) this._root.remove(); }
  });
})();
