/* ============================================================================
   dhcp.view.js  -  DHCP Scope Options (tool id: 'dhcp')  [BETA]
   Faithful single-window re-build per docs/ui-specs/dhcp.md: a server-connect
   strip over a three-column work area (checkable SCOPES list | SCOPE OPTION
   editor with an ordered, reorderable IP list | colour-coded ACTIVITY LOG),
   plus a BULK APPLY footer. Two workflows: single-scope edit+APPLY, and bulk
   append/prepend/remove across checked scopes. All server calls go through
   ctx.run -> RunController. Credentials are universal (shell header): connect +
   load are read-only; apply + bulk are destructive (need an admin session).
   ========================================================================== */
(function () {
  'use strict';

  var OPTIONS = [
    { id: 6, label: '006 DNS Servers' },
    { id: 3, label: '003 Router' },
    { id: 42, label: '042 NTP Servers' },
    { id: 44, label: '044 WINS / NBNS Servers' },
    { id: 45, label: '045 NetBIOS over TCP/IP NBDD' },
    { id: 0, label: 'Other (specify ID)...' }
  ];
  function isIpv4(s) { return /^(\d{1,3})(\.\d{1,3}){3}$/.test(String(s || '').trim()) && String(s).trim().split('.').every(function (o) { return +o >= 0 && +o <= 255; }); }
  function sameOrder(a, b) { if (a.length !== b.length) return false; for (var i = 0; i < a.length; i++) if (a[i] !== b[i]) return false; return true; }
  // every dhcp row shares Host (the DHCP server), so rows MUST be keyed by ScopeId
  // or RunController's default Host key collapses every scope into one row.
  function keyByScope(ev) { return ev.ScopeId != null ? String(ev.ScopeId) : (ev.Host != null ? String(ev.Host) : null); }

  JanetViews.register('dhcp', {
    mount: function (host, ctx) {
      var ui = ctx.ui, C = ctx.components, el = ctx.util.el;

      // ---- state ----
      // connectedServer: the server Connect actually reached. Every subsequent call
      // targets THIS name, never the live field value (audit 2026-07-24, finding 4).
      var connected = false, connectedServer = '', scopes = [], currentScopeId = null;
      var originalValues = [], workingValues = [], checked = {};
      // loadedOptionId: the option ID whose before-state (originalValues) is actually in the
      // editor - null whenever nothing is loaded. audit 2026-07-25 (fable re-audit follow-up):
      // APPLY is armed against this, not against whatever ID the box currently reads, so a
      // freshly typed custom ID can never be paired with the PREVIOUS option's expectedOld.
      var loadedOptionId = null;
      var readRun = null, readUnsub = null, writeRun = null, writeUnsub = null, writeActive = false, lastResults = [];

      var root = el('div'); root.style.cssText = 'display:flex;flex-direction:column;height:100%;min-height:0;background:var(--bg)';

      // ===== DHCP SERVER connect strip =====
      var connStrip = ui.card({}); connStrip.style.cssText += ';margin:12px 14px 0;display:flex;align-items:center;gap:12px;flex-wrap:wrap';
      connStrip.appendChild(ui.eyebrow('DHCP SERVER'));
      var serverInput = ui.input({ placeholder: 'hostname or FQDN of the authorized DHCP server', title: 'The Microsoft DHCP server to manage (WinRM 5985, HTTPS 5986 fallback).' });
      serverInput.style.width = '300px';
      var connectBtn = ui.button('Connect', { variant: 'go', size: 'sm' });
      var disconnectBtn = ui.ghostButton('Disconnect', { size: 'sm' }); disconnectBtn.disabled = true;
      var connStatus = el('span', 'muted', 'Not connected');
      connStrip.appendChild(serverInput); connStrip.appendChild(connectBtn); connStrip.appendChild(disconnectBtn); connStrip.appendChild(connStatus);
      var credNote = el('span', 'muted'); credNote.style.cssText = 'margin-left:auto;font-size:11px';
      credNote.textContent = 'Runs as the credential set top-right (or your current login if cleared).';
      connStrip.appendChild(credNote);
      root.appendChild(connStrip);

      // ===== three columns =====
      var cols = el('div'); cols.style.cssText = 'flex:1;min-height:0;display:flex;gap:12px;padding:12px 14px';
      root.appendChild(cols);

      // --- LEFT: SCOPES ---
      var left = ui.card({}); left.style.cssText += ';flex:0 0 320px;display:flex;flex-direction:column;min-height:0';
      left.appendChild(secHdr('SCOPES'));
      left.appendChild(hint('Click a row to edit one scope. Check the box to include in BULK APPLY.'));
      var scopeListWrap = el('div'); scopeListWrap.style.cssText = 'flex:1;min-height:0;overflow:auto;border:1px solid var(--line-soft);border-radius:2px;background:var(--panel)';
      var scopeList = el('div'); scopeListWrap.appendChild(scopeList);
      left.appendChild(scopeListWrap);
      var selRow = el('div'); selRow.style.cssText = 'display:flex;gap:6px;margin-top:8px;flex-wrap:wrap';
      ['All', 'None', 'Active', 'Invert'].forEach(function (lbl) {
        var b = ui.ghostButton(lbl, { size: 'sm' });
        b.onclick = function () { bulkToggle(lbl); };
        selRow.appendChild(b);
      });
      left.appendChild(selRow);
      var scopeCount = el('div', 'muted'); scopeCount.style.cssText = 'margin-top:6px;font-family:var(--ui);font-weight:600';
      left.appendChild(scopeCount);
      cols.appendChild(left);

      // --- MIDDLE: SCOPE OPTION editor ---
      var mid = ui.card({}); mid.style.cssText += ';flex:0 0 470px;display:flex;flex-direction:column;min-height:0';
      mid.appendChild(secHdr('SCOPE OPTION'));
      var scopeLabel = el('div', 'muted', 'No scope selected'); scopeLabel.style.marginBottom = '8px';
      mid.appendChild(scopeLabel);
      var optRow = el('div'); optRow.style.cssText = 'display:flex;align-items:flex-end;gap:8px;flex-wrap:wrap';
      var optSelect = ui.select({ options: OPTIONS.map(function (o) { return { value: String(o.id), label: o.label }; }), value: '6', onChange: optChanged });
      optSelect.style.width = '210px';
      var optIdInput = ui.number({ value: 6, min: 1, max: 254, title: 'Custom option ID (1-254).' }); optIdInput.style.width = '80px'; optIdInput.disabled = true;
      var loadBtn = ui.button('Load Values', { variant: 'cyan', size: 'sm' }); loadBtn.disabled = true;
      optRow.appendChild(ui.field('Option', optSelect)); optRow.appendChild(ui.field('ID', optIdInput)); optRow.appendChild(loadBtn);
      mid.appendChild(optRow);

      mid.appendChild((function () { var h = ui.eyebrow('IP ADDRESS LIST  (order matters)'); h.style.marginTop = '10px'; return h; })());
      var ipBody = el('div'); ipBody.style.cssText = 'display:flex;gap:8px;flex:1;min-height:0';
      var ipList = el('div'); ipList.style.cssText = 'flex:1;min-height:80px;overflow:auto;border:1px solid var(--line);border-radius:2px;background:var(--input);font-family:var(--mono);font-size:12.5px';
      ipBody.appendChild(ipList);
      var reorder = el('div'); reorder.style.cssText = 'display:flex;flex-direction:column;gap:4px';
      [['Up', -1], ['Down', 1], ['Top', 'top'], ['Bottom', 'bottom']].forEach(function (p) {
        var b = ui.ghostButton(p[0], { size: 'sm' }); b.onclick = function () { moveSel(p[1]); }; reorder.appendChild(b);
      });
      var removeBtn = ui.button('Remove', { variant: 'danger', size: 'sm' }); removeBtn.onclick = removeSel; reorder.appendChild(removeBtn);
      ipBody.appendChild(reorder);
      mid.appendChild(ipBody);

      var addRow = el('div'); addRow.style.cssText = 'display:flex;gap:6px;margin-top:8px';
      var addInput = ui.input({ placeholder: 'a.b.c.d', title: 'Add an IPv4 address.' });
      addInput.addEventListener('keydown', function (e) { if (e.key === 'Enter') { e.preventDefault(); addIp(false); } });
      var addBtn = ui.button('Add', { variant: 'go', size: 'sm' }); addBtn.onclick = function () { addIp(false); };
      var addBottomBtn = ui.ghostButton('Add to Bottom', { size: 'sm' }); addBottomBtn.onclick = function () { addIp(true); };
      addRow.appendChild(addInput); addRow.appendChild(addBtn); addRow.appendChild(addBottomBtn);
      mid.appendChild(addRow);

      var applyRow = el('div'); applyRow.style.cssText = 'display:flex;gap:8px;margin-top:10px;align-items:center';
      var removeOptCb = ui.checkbox('Remove option', { title: 'Delete the option from the scope (requires an empty list).' });
      var dryCbSingle = ui.checkbox('Dry run', { color: 'var(--warn)' });
      var applyBtn = ui.button('APPLY  ->  COMMIT TO SCOPE', { variant: 'gold' }); applyBtn.disabled = true; applyBtn.onclick = doApply;
      var revertBtn = ui.ghostButton('Revert', { size: 'sm' }); revertBtn.disabled = true; revertBtn.onclick = function () { workingValues = originalValues.slice(); renderIpList(); };
      applyRow.appendChild(applyBtn); applyRow.appendChild(revertBtn); applyRow.appendChild(removeOptCb); applyRow.appendChild(dryCbSingle);
      mid.appendChild(applyRow);
      cols.appendChild(mid);

      // --- ACTIVITY LOG (full-width bottom dock; was boxed in the right column) ---
      var right = ui.card({}); right.classList.add('j-logdock'); right.style.cssText += ';margin:0 14px 12px';
      var log = C.ActivityLog({ title: 'ACTIVITY LOG', defaultName: 'DHCP_ActivityLog' });
      // Run controls for the streaming apply/bulk results: Cancel an in-flight run
      // (engine already supports it) and export the last run's per-scope outcomes to
      // CSV (DHCP was the only destructive view without an export).
      var dhcpTools = el('div'); dhcpTools.style.cssText = 'display:flex;align-items:center;gap:8px;margin-bottom:8px';
      var cancelBtn = ui.button('Cancel Run', { variant: 'danger', size: 'sm', title: 'Stop the in-flight apply / bulk run.' }); cancelBtn.disabled = true;
      cancelBtn.onclick = function () { if (writeRun) { writeRun.cancel(); log.append({ text: 'CANCEL requested - stopping in-flight scope(s)...', level: 'warn' }); } };
      var exportBtn = ui.ghostButton('Export Results CSV', { size: 'sm', title: 'Export the last apply / bulk run results to CSV.' }); exportBtn.disabled = true;
      exportBtn.onclick = doExportResults;
      dhcpTools.appendChild(cancelBtn); dhcpTools.appendChild(exportBtn);
      right.appendChild(dhcpTools);
      right.appendChild(log.el);
      // NOTE: appended to root AFTER the BULK APPLY strip below, so the log is the
      // very bottom element of the tool.

      // ===== BULK APPLY footer =====
      var footer = ui.card({}); footer.style.cssText += ';margin:0 14px 12px;display:flex;align-items:flex-end;gap:12px;flex-wrap:wrap';
      footer.appendChild(secHdr('BULK APPLY'));
      var bulkIps = ui.textarea({ placeholder: 'IPs (one per line) to append/prepend/remove across the CHECKED scopes', rows: 2 });
      bulkIps.style.cssText += ';width:320px;min-height:46px';
      footer.appendChild(ui.field('IP addresses', bulkIps));
      var bulkOptEcho = el('span', 'muted'); bulkOptEcho.style.fontSize = '11px';
      var dryCbBulk = ui.checkbox('Dry run', { color: 'var(--warn)' });
      var appendBtn = ui.button('Append', { variant: 'gold', size: 'sm' }); appendBtn.onclick = function () { doBulk('append'); };
      var prependBtn = ui.button('Prepend', { variant: 'go', size: 'sm' }); prependBtn.onclick = function () { doBulk('prepend'); };
      var removeBulkBtn = ui.button('Remove', { variant: 'danger', size: 'sm' }); removeBulkBtn.onclick = function () { doBulk('remove'); };
      var bulkBtns = el('div'); bulkBtns.style.cssText = 'display:flex;gap:6px;align-items:center';
      bulkBtns.appendChild(bulkOptEcho); bulkBtns.appendChild(appendBtn); bulkBtns.appendChild(prependBtn); bulkBtns.appendChild(removeBulkBtn); bulkBtns.appendChild(dryCbBulk);
      footer.appendChild(bulkBtns);
      root.appendChild(footer);
      root.appendChild(right);   // activity log docks at the very bottom, below the bulk-apply strip

      // ===== helpers =====
      function secHdr(t) { var h = el('div', 'j-section-h', t); h.style.marginBottom = '6px'; return h; }
      function hint(t) { var d = el('div', 'muted', t); d.style.cssText = 'font-size:11px;margin-bottom:6px'; return d; }
      function optChanged() { var v = parseInt(optSelect.value, 10); optIdInput.disabled = (v !== 0); if (v !== 0) optIdInput.value = v; }
      function currentOptionId() { var v = parseInt(optSelect.value, 10); return v === 0 ? Math.max(1, Math.min(254, parseInt(optIdInput.value, 10) || 6)) : v; }
      function setEditorEnabled(on) { loadBtn.disabled = !on; }
      // audit 2026-07-25 (fable re-audit follow-up): the loaded before-state belongs to ONE
      // option ID. Typing a new custom ID used to leave it in place, so APPLY could send the
      // new ID with the OLD option's expectedOld (the divergence guard only catches that when
      // the two options hold different values - two unset options do not). Anything that can
      // change the ID now invalidates the editor, and APPLY is gated on a matching load.
      function optionLoaded() { return loadedOptionId != null && loadedOptionId === currentOptionId(); }
      function invalidateLoadedOption() {
        loadedOptionId = null;
        originalValues = []; workingValues = []; selIdx = -1;
        renderIpList();   // calls updateApplyState() - APPLY drops out with the load
        if (currentScopeId) {
          var ph = el('div'); ph.style.cssText = 'padding:6px 8px;color:var(--warn)';
          ph.textContent = '(option ID changed - click Load Values for option ' + currentOptionId() + ')';
          ipList.appendChild(ph);
        }
      }
      function updateApplyState() {
        var dirty = !sameOrder(workingValues, originalValues) || removeOptCb._cb.checked;
        applyBtn.disabled = writeActive || !optionLoaded() || !(connected && currentScopeId && dirty);
        revertBtn.disabled = !(connected && currentScopeId && !sameOrder(workingValues, originalValues));
      }
      function updateBulk() {
        var n = Object.keys(checked).filter(function (k) { return checked[k]; }).length;
        bulkOptEcho.textContent = 'Option: ' + currentOptionId() + '  |  ' + n + ' checked';
        var en = connected && n > 0 && !writeActive;
        appendBtn.disabled = prependBtn.disabled = removeBulkBtn.disabled = !en;
      }
      // While a destructive write (apply / bulk) is in flight, lock the controls that
      // would start a second overlapping write or reassign the shared read subscription:
      // the write buttons (via updateApplyState / updateBulk), the scope list clicks,
      // and the option selector. Cleared in the write run's active(false) handler.
      function lockWrite(on) {
        writeActive = on;
        optSelect.disabled = on;
        scopeListWrap.style.pointerEvents = on ? 'none' : '';
        updateApplyState(); updateBulk();
      }
      function updateScopeCount() {
        var n = scopes.length, c = Object.keys(checked).filter(function (k) { return checked[k]; }).length;
        scopeCount.textContent = n + ' scopes  |  ' + c + ' checked';
        scopeCount.style.color = c > 0 ? 'var(--gold)' : (n > 0 ? 'var(--ok)' : 'var(--muted)');
        updateBulk();
      }

      function renderScopes() {
        scopeList.innerHTML = '';
        scopes.forEach(function (s) {
          var row = el('div'); row.style.cssText = 'display:flex;align-items:center;gap:8px;padding:5px 8px;border-bottom:1px solid var(--line-faint);cursor:pointer;font-family:var(--mono);font-size:12px';
          if (s.ScopeId === currentScopeId) row.style.background = 'var(--accent-wash)';
          var cb = el('input'); cb.type = 'checkbox'; cb.checked = !!checked[s.ScopeId];
          cb.addEventListener('click', function (e) { e.stopPropagation(); checked[s.ScopeId] = cb.checked; updateScopeCount(); });
          row.appendChild(cb);
          var info = el('div'); info.style.flex = '1';
          var active = /active/i.test(String(s.State));
          info.innerHTML = '<span style="color:' + (active ? 'var(--text)' : 'var(--muted)') + '">' + esc(s.ScopeId) + '</span> <span class="muted">' + esc(s.Name || '') + '</span>';
          var st = el('span'); st.textContent = s.State || ''; st.style.cssText = 'font-size:11px;color:' + (active ? 'var(--ok)' : 'var(--muted)');
          row.appendChild(info); row.appendChild(st);
          row.addEventListener('click', function () { selectScope(s); });
          scopeList.appendChild(row);
        });
        updateScopeCount();
      }
      function bulkToggle(which) {
        scopes.forEach(function (s) {
          var active = /active/i.test(String(s.State));
          if (which === 'All') checked[s.ScopeId] = true;
          else if (which === 'None') checked[s.ScopeId] = false;
          else if (which === 'Active') checked[s.ScopeId] = active;
          else if (which === 'Invert') checked[s.ScopeId] = !checked[s.ScopeId];
        });
        renderScopes();
      }
      function selectScope(s) {
        currentScopeId = s.ScopeId;
        scopeLabel.textContent = 'Scope: ' + s.ScopeId + (s.SubnetMask ? ' / ' + s.SubnetMask : '') + (s.Name ? ' -- ' + s.Name : '') + ' [' + (s.State || '') + ']';
        renderScopes();
        // Clear the prior scope's editor state so its IPs do not linger under the
        // new scope's label, then show a transient loading placeholder until the
        // load row arrives (replaced by renderIpList / the failed-load placeholder).
        originalValues = []; workingValues = []; selIdx = -1; loadedOptionId = null; renderIpList();
        var ph = el('div'); ph.style.cssText = 'padding:6px 8px;color:var(--muted)'; ph.textContent = 'Loading option ' + currentOptionId() + ' on ' + currentScopeId + '...';
        ipList.appendChild(ph);
        doLoad(true);
      }
      function renderIpList() {
        ipList.innerHTML = '';
        workingValues.forEach(function (ip, i) {
          var r = el('div'); r.style.cssText = 'padding:3px 8px;cursor:pointer'; r.dataset.idx = i; r.textContent = ' ' + (i + 1) + '.  ' + ip;
          r.addEventListener('click', function () { selIdx = i; renderIpList(); });
          if (i === selIdx) r.style.background = 'var(--accent-wash)';
          ipList.appendChild(r);
        });
        updateApplyState();
      }
      var selIdx = -1;
      function moveSel(dir) {
        if (selIdx < 0) return;
        var v = workingValues, i = selIdx, ni;
        if (dir === 'top') ni = 0; else if (dir === 'bottom') ni = v.length - 1; else ni = i + dir;
        if (ni < 0 || ni >= v.length) return;
        var x = v.splice(i, 1)[0]; v.splice(ni, 0, x); selIdx = ni; renderIpList();
      }
      function removeSel() { if (selIdx < 0) return; workingValues.splice(selIdx, 1); selIdx = Math.min(selIdx, workingValues.length - 1); renderIpList(); }
      function addIp(bottom) {
        var ip = (addInput.value || '').trim();
        if (!isIpv4(ip)) { ctx.confirm({ title: 'Invalid IP', body: '"' + esc(ip) + '" is not a valid IPv4 address.', okText: 'OK', cancelText: null }); return; }
        if (workingValues.indexOf(ip) >= 0) { log.append({ text: '  ' + ip + ' already in the list - skipped.', level: 'warn' }); addInput.value = ''; return; }
        if (bottom || selIdx < 0) workingValues.push(ip); else workingValues.splice(selIdx + 1, 0, ip);
        addInput.value = ''; renderIpList();
      }

      // ===== runs =====
      function doConnect() {
        var server = (serverInput.value || '').trim();
        if (!server) { ctx.confirm({ title: 'Server required', body: 'Enter the DHCP server hostname or FQDN.', okText: 'OK', cancelText: null }); return; }
        connectBtn.disabled = true; connStatus.textContent = 'Connecting to ' + server + ' ...'; connStatus.className = 'st-warn';
        log.append({ text: 'Connecting to ' + server + ' ...', level: 'accent' });
        scopes = []; checked = {}; var connErr = false;
        readRun = ctx.run('connect', { targets: server }, { keyOf: keyByScope });
        if (readUnsub) readUnsub();
        readUnsub = readRun.subscribe({
          log: function (l) { log.append(l); },
          error: function (e) { connErr = true; log.append({ text: e.text, level: 'err' }); },
          active: function (a) {
            connectBtn.disabled = a;
            if (!a) {
              // rebuild the scope list from RunController's keyed/deduped row set
              var rs = readRun.state;
              scopes = (rs && rs.order) ? rs.order.map(function (k) { return rs.rows[k]; }).filter(function (r) { return r && r.ScopeId; }) : [];
              if (connErr && scopes.length === 0) {
                connStatus.textContent = 'Connect failed - see log'; connStatus.className = 'st-bad';
                return;
              }
              connected = true; connectedServer = server; disconnectBtn.disabled = false; setEditorEnabled(true);
              connStatus.textContent = 'Connected to ' + server + ' - ' + scopes.length + ' scope(s)'; connStatus.className = 'st-ok';
              log.append({ text: 'Connected to ' + server + ' -- ' + scopes.length + ' scope(s) loaded.', level: 'ok' });
              renderScopes();
            }
          }
        });
      }
      function doDisconnect() {
        connected = false; connectedServer = ''; scopes = []; checked = {}; currentScopeId = null; originalValues = []; workingValues = []; selIdx = -1; loadedOptionId = null;
        disconnectBtn.disabled = true; setEditorEnabled(false); applyBtn.disabled = true; revertBtn.disabled = true;
        connStatus.textContent = 'Not connected'; connStatus.className = 'muted';
        scopeLabel.textContent = 'No scope selected';
        renderScopes(); renderIpList(); log.append({ text: 'Disconnected.', level: 'warn' });
      }
      // audit 2026-07-24 (finding 4): load / apply / bulk all read serverInput LIVE, so
      // editing the field after Connect silently RETARGETED them at a different DHCP
      // server while the scope list, the checked set and the editor's before-state still
      // belonged to the connected one -- i.e. an APPLY computed against server A written
      // to server B, and a bulk run aimed at scope IDs that may not even exist there.
      // Every call now goes to the server we actually connected to, and we refuse while
      // the field disagrees (Connect again to retarget). quiet: suppress the modal on the
      // implicit scope-switch load, which still logs and still refuses.
      function activeServer(quiet) {
        if (!connected || !connectedServer) return null;
        var typed = (serverInput.value || '').trim();
        if (typed.toLowerCase() === connectedServer.toLowerCase()) return connectedServer;
        log.append({ text: 'Refused: the DHCP server field says "' + typed + '" but this session is connected to "' + connectedServer + '". Click Connect to retarget.', level: 'err' });
        if (!quiet) {
          ctx.confirm({
            title: 'Server field changed',
            body: 'The DHCP server field reads <b>' + esc(typed) + '</b> but the scope list and editor state belong to <b>' + esc(connectedServer) + '</b>.<br><br>Click <b>Connect</b> to retarget (this reloads the scope list), or restore the connected name.',
            okText: 'OK', cancelText: null
          });
        }
        return null;
      }
      // Keep the connect strip honest the moment the field diverges, so the refusal is
      // never the first sign the operator is looking at another server's scope list.
      function refreshConnStatus() {
        if (!connected) return;
        var typed = (serverInput.value || '').trim();
        if (typed.toLowerCase() === connectedServer.toLowerCase()) {
          connStatus.textContent = 'Connected to ' + connectedServer + ' - ' + scopes.length + ' scope(s)'; connStatus.className = 'st-ok';
        } else {
          connStatus.textContent = 'Connected to ' + connectedServer + ' - field edited, Connect to retarget'; connStatus.className = 'st-warn';
        }
      }
      function doLoad(silent) {
        if (!currentScopeId) return;
        var srv = activeServer(silent);
        if (!srv) {
          // The scope-switch path already dropped a "Loading..." placeholder; replace it
          // so a refused read never sits there pretending a request is in flight.
          if (silent) {
            ipList.innerHTML = '';
            var rph = el('div'); rph.style.cssText = 'padding:6px 8px;color:var(--warn)';
            rph.textContent = '(not loaded - the server field does not match the connected server)';
            ipList.appendChild(rph);
          }
          applyBtn.disabled = true; revertBtn.disabled = true;
          return;
        }
        var opt = currentOptionId();
        var loadErr = false;   // a failed read must NOT masquerade as an empty/unset option
        // Nothing is loaded until THIS read lands: an in-flight (or failed) load must never
        // leave APPLY armed against the previous option/scope (audit 2026-07-25).
        loadedOptionId = null;
        readRun = ctx.run('load', { targets: srv, scopeId: currentScopeId, optionId: opt }, { keyOf: keyByScope });
        if (readUnsub) readUnsub();
        readUnsub = readRun.subscribe({
          error: function (e) { loadErr = true; log.append({ text: e.text, level: 'err' }); },
          row: function (r) {
            if (loadErr) {
              // Read failed: keep the existing working state (do NOT clobber to [])
              // and show a clear placeholder instead of a misleading empty list.
              ipList.innerHTML = '';
              var ph = el('div'); ph.style.cssText = 'padding:6px 8px;color:var(--warn)'; ph.textContent = '(load failed - click Load Values to retry)';
              ipList.appendChild(ph);
              applyBtn.disabled = true; revertBtn.disabled = true;   // gate apply until a clean read
              return;
            }
            var vals = String(r.Values == null ? '' : r.Values).split(/[,;\s]+/).filter(Boolean);
            originalValues = vals.slice(); workingValues = vals.slice(); selIdx = -1;
            loadedOptionId = opt;   // the before-state in the editor is THIS option's (audit 2026-07-25)
            renderIpList();
            if (!silent) log.append({ text: 'Loaded option ' + opt + ' on ' + currentScopeId + ' (' + vals.length + ' value(s)).', level: 'ok' });
          },
          // Always surface read failures, even on a silent (scope-switch) load.
          log: function (l) { if (l && l.level === 'err') { loadErr = true; log.append(l); } else if (!silent) { log.append(l); } }
        });
      }
      function diffText() {
        var added = workingValues.filter(function (v) { return originalValues.indexOf(v) < 0; });
        var removed = originalValues.filter(function (v) { return workingValues.indexOf(v) < 0; });
        if (added.length === 0 && removed.length === 0) return 'REORDER ONLY (same set, new order)';
        var parts = [];
        // esc() each value: added/removed derive from r.Values returned by the REMOTE
        // DHCP server (dhcp.view.js load path, unvalidated) and this string is rendered
        // via ConfirmDialog body -> innerHTML. A free-form option value (015/066/067/012)
        // could otherwise carry a space-free XSS payload into the privileged console (audit P2).
        if (added.length) parts.push('ADD: + ' + added.map(esc).join(', '));
        if (removed.length) parts.push('REMOVE: - ' + removed.map(esc).join(', '));
        return parts.join('<br>');
      }
      async function doApply() {
        if (writeActive) return;   // a write is already in flight - do not fire a second overlapping commit
        if (!ctx.session.state.credSet) { ctx.confirm({ title: 'Admin session required', body: 'Set ADW credentials (top-right) before committing DHCP changes.', okText: 'OK', cancelText: null }); return; }
        var srv = activeServer(false);
        if (!srv) return;   // audit 2026-07-24: never commit to a server other than the connected one
        // audit 2026-07-25 (fable re-audit follow-up): belt-and-braces behind the disabled
        // button - expectedOld below is only meaningful for the option it was READ from, so a
        // commit whose ID no longer matches the loaded one is refused here, not sent.
        if (!optionLoaded()) { ctx.confirm({ title: 'Option not loaded', body: 'The option ID changed since the values were loaded. Click Load Values for option ' + currentOptionId() + ' first - APPLY sends the loaded before-state as its concurrency guard.', okText: 'OK', cancelText: null }); return; }
        var opt = currentOptionId(), removeOpt = removeOptCb._cb.checked, dry = dryCbSingle._cb.checked;
        // audit 2026-07-24 (finding 1): this was ctx.confirm, which silently IGNORES
        // confirmWord - and the run below sent no `confirm` param at all, so the engine's
        // typed-APPLY gate refused every single-scope commit ("type APPLY (exactly)").
        // ctx.arm honours the typed word (pkginstall DEPLOY / secureboot ENABLE idiom):
        // the dialog IS the UI for that server-side gate, so the two must ship together.
        var ok = await ctx.arm({
          title: dry ? 'Confirm APPLY (DRY RUN)' : 'Confirm APPLY',
          banner: dry ? 'DRY RUN - the diff is previewed, nothing is written' : 'DESTRUCTIVE - REPLACES THE LIVE OPTION VALUE ON THIS SCOPE',
          danger: !dry,
          body: 'Server: <b>' + esc(srv) + '</b><br>Scope: <b>' + esc(currentScopeId) + '</b><br>Option: <b>' + opt + '</b><br><br>' + diffText() +
            '<br><br>NEW ORDER (top -> bottom):',
          list: removeOpt ? ['(option will be removed)'] : workingValues.map(function (v, i) { return (i + 1) + '. ' + v; }),
          confirmWord: dry ? null : 'APPLY',
          okText: dry ? 'Preview' : 'Apply', cancelText: 'Cancel'
        });
        if (!ok) { log.append({ text: 'APPLY cancelled by user.', level: 'warn' }); return; }
        log.append({ text: '=== APPLY option ' + opt + ' on ' + currentScopeId + (dry ? ' [DRY RUN]' : '') + ' ===', level: 'banner' });
        // audit 2026-07-24 (finding 3): 'Remove option' posted the loaded IPs in newValues
        // alongside removeOption=true, and the engine refuses exactly that combination
        // ("Clear one or the other") - so the removal the dialog promised was unreachable
        // from this UI. Removal IS the empty new-values list; send it that way.
        // confirm: 'APPLY' on the DRY-RUN path is a deliberate, documented trade-off
        // (audit 2026-07-25, fable re-audit follow-up). The word is sent even though the arm
        // dialog asked for no typing when dry, so the param is NOT operator evidence on a
        // preview - it is a protocol constant satisfying the engine's unconditional
        // -cne 'APPLY' gate. We keep it that way rather than exempting dry runs server-side:
        //   * the gate is the ONE check that cannot be bypassed by any request shape; adding a
        //     dryRun-dependent branch to it would make the fail-closed refusal depend on the
        //     very flag an attacker/typo controls;
        //   * a dry run cannot write anyway - Get-DhcpDryRunSafe (dhcp.psm1) resolves ANY
        //     present-but-unrecognized token to DRY, so 'dryRun' can only fail towards preview;
        //   * arming is still evidenced where it matters: the LIVE path types the word into
        //     ctx.arm (confirmWord 'APPLY') before this line is ever reached, and the preview
        //     still passes through a real arm dialog showing server/scope/option/diff.
        // The residual gap is stated plainly: on a preview, 'confirm' proves nothing.
        writeRun = ctx.run('apply', { targets: srv, scopeId: currentScopeId, optionId: opt, newValues: removeOpt ? '' : workingValues.join('\n'), expectedOld: originalValues.join('\n'), removeOption: removeOpt, dryRun: dry, confirm: 'APPLY' }, { keyOf: keyByScope });
        bindResultLog(function () {
          if (dry) return;
          // audit 2026-07-24: with the Remove path finally reachable (finding 3), a
          // committed removal leaves the option UNSET - so the new before-state is empty,
          // not the working list. Adopting the working list here would post a stale
          // expectedOld on the next apply and have it refused as 'Stale'.
          if (removeOpt) { originalValues = []; workingValues = []; selIdx = -1; removeOptCb._cb.checked = false; renderIpList(); }
          else { originalValues = workingValues.slice(); }
          updateApplyState();
        });
      }
      async function doBulk(mode) {
        if (writeActive) return;   // a write is already in flight - do not fire a second overlapping bulk run
        if (!ctx.session.state.credSet) { ctx.confirm({ title: 'Admin session required', body: 'Set ADW credentials (top-right) before bulk DHCP changes.', okText: 'OK', cancelText: null }); return; }
        var scopeIds = Object.keys(checked).filter(function (k) { return checked[k]; });
        if (!scopeIds.length) { ctx.confirm({ title: 'No scopes checked', body: 'Check at least one scope for bulk apply.', okText: 'OK', cancelText: null }); return; }
        var ips = (bulkIps.value || '').split(/[,;\s\r\n]+/).filter(Boolean);
        var bad = ips.filter(function (i) { return !isIpv4(i); });
        if (!ips.length || bad.length) { ctx.confirm({ title: 'Check IPs', body: ips.length ? ('Not valid IPv4: ' + bad.map(esc).join(', ')) : 'Enter at least one IP.', okText: 'OK', cancelText: null }); return; }
        var srv = activeServer(false);
        if (!srv) return;   // audit 2026-07-24: never bulk-write to a server other than the connected one
        var dry = dryCbBulk._cb.checked, opt = currentOptionId();
        var label = { append: 'APPEND to bottom of', prepend: 'PREPEND to top of', remove: 'REMOVE from' }[mode];
        // audit 2026-07-24 (finding 1): ctx.confirm ignores confirmWord and no `confirm`
        // param was sent, so the engine's typed-APPLY gate refused every bulk run.
        var ok = await ctx.arm({
          title: 'Confirm BULK ' + mode.toUpperCase() + (dry ? ' (DRY RUN)' : ''),
          banner: dry ? 'DRY RUN - per-scope before/after is previewed, nothing is written' : 'DESTRUCTIVE - REWRITES THE LIVE OPTION VALUE ON EVERY CHECKED SCOPE',
          danger: !dry,
          body: 'Server: <b>' + esc(srv) + '</b><br>Action: <b>' + label + ' option ' + opt + '</b><br>Scopes (' + scopeIds.length + '): ' + esc(scopeIds.join(', ')) + '<br>IPs: ' + esc(ips.join(', ')) + (dry ? '<br><br>[DRY RUN]' : '') + '<br><br>Proceed?',
          confirmWord: dry ? null : 'APPLY',
          okText: dry ? 'Preview' : 'Proceed', cancelText: 'Cancel'
        });
        if (!ok) { log.append({ text: 'BULK ' + mode.toUpperCase() + ' cancelled by user.', level: 'warn' }); return; }
        log.append({ text: '=== BULK ' + mode.toUpperCase() + ' option ' + opt + ' on ' + scopeIds.length + ' scope(s)' + (dry ? ' [DRY RUN]' : '') + ' ===', level: 'banner' });
        // confirm: same deliberate trade-off as doApply above (audit 2026-07-25) - on a DRY
        // RUN this word is a protocol constant for the engine's unconditional gate, not
        // operator evidence; the live path types it into ctx.arm first. Keeping the gate
        // dryRun-independent is worth more than making a preview prove arming.
        writeRun = ctx.run('bulk-' + mode, { targets: srv, scopeIds: scopeIds.join('\n'), optionId: opt, ipAddresses: ips.join('\n'), dryRun: dry, confirm: 'APPLY' }, { keyOf: keyByScope });
        bindResultLog(null);
      }
      // Union of the apply (Host,ScopeId,OptionId,Status,OldValues,NewValues,Added,
      // Removed,Reordered,Error) and bulk (Host,ScopeId,Status,BeforeCount,AfterCount,
      // BeforeValues,AfterValues,Error) row shapes, so a CSV of either action keeps
      // every column it produced - the prior list dropped Host, OptionId, OldValues
      // and BeforeValues (server / option / before-state lost from the export).
      var EXPORT_COLS = ['Host', 'ScopeId', 'OptionId', 'Status', 'OldValues', 'NewValues', 'Added', 'Removed', 'Reordered', 'BeforeCount', 'AfterCount', 'BeforeValues', 'AfterValues', 'Error'];
      function doExportResults() {
        if (!lastResults.length) { ctx.confirm({ title: 'Nothing to export', body: 'Run an APPLY or BULK action first.', okText: 'OK', cancelText: null }); return; }
        var csv = ctx.util.toCsv(EXPORT_COLS, lastResults);
        ctx.util.downloadBlob('DHCP_Results_' + ctx.util.fileStamp() + '.csv', 'text/csv', csv);
        log.append({ text: 'Exported ' + lastResults.length + ' result row(s) to CSV.', level: 'accent' });
      }
      function bindResultLog(onDone) {
        if (writeUnsub) writeUnsub();
        lastResults = []; if (exportBtn) exportBtn.disabled = true;
        lockWrite(true);
        var ch = 0, nc = 0, er = 0;
        writeUnsub = writeRun.subscribe({
          active: function (a) { if (cancelBtn) cancelBtn.disabled = !a; if (!a) lockWrite(false); },
          status: function (t) { log.append({ text: t, level: 'gold' }); },
          row: function (r) {
            lastResults.push(r);
            var sid = r.ScopeId || r.Host || '?';
            var st = String(r.Status || '');
            if (st === 'Error') { er++; log.append({ text: '  [' + sid + '] ERROR: ' + (r.Error || ''), level: 'err' }); }
            else if (st === 'Stale') { er++; log.append({ text: '  [' + sid + '] REFUSED: ' + (r.Error || 'the option changed on the server since you loaded it - reload and re-apply.'), level: 'err' }); }
            else if (st === 'Cancelled') { er++; log.append({ text: '  [' + sid + '] cancelled by operator.', level: 'warn' }); }
            else if (/nochange/i.test(st) || st === 'NoChange') { nc++; log.append({ text: '  [' + sid + '] no change (already in desired state).', level: 'dim' }); }
            else if (/removed/i.test(st)) { ch++; log.append({ text: '  [' + sid + '] option removed (list now empty).', level: 'ok' }); }
            else {
              ch++;
              var detail;
              if (r.BeforeCount != null) { detail = r.BeforeCount + ' -> ' + r.AfterCount + ' value(s)' + (r.AfterValues ? ': ' + r.AfterValues : ''); }
              else {  // apply row: surface the server-confirmed committed diff, not just the bare status
                var bits = [];
                if (r.Added) bits.push('+ ' + r.Added);
                if (r.Removed) bits.push('- ' + r.Removed);
                if (r.Reordered === true) bits.push('reordered');
                detail = (st || 'changed') + (bits.length ? ' (' + bits.join('; ') + ')' : '') + (r.NewValues ? ' -> [' + r.NewValues + ']' : '');
              }
              log.append({ text: '  [' + sid + '] ' + detail, level: 'ok' });
            }
          },
          log: function (l) { log.append(l); },
          final: function () { if (exportBtn) exportBtn.disabled = !lastResults.length; log.append({ text: 'Complete: ' + ch + ' changed, ' + nc + ' unchanged, ' + er + ' error(s).', level: er ? 'warn' : 'ok' }); if (onDone && er === 0) onDone(); }
        });
      }
      var esc = Janet.util.esc;

      // wire
      connectBtn.onclick = doConnect;
      disconnectBtn.onclick = doDisconnect;
      serverInput.addEventListener('input', refreshConnStatus);   // audit 2026-07-24: surface a retarget-in-waiting immediately
      loadBtn.onclick = function () { doLoad(false); };
      optSelect.addEventListener('change', function () { optChanged(); updateBulk(); if (currentScopeId) doLoad(true); });
      // audit 2026-07-25 (fable re-audit follow-up): this used to be updateBulk() ALONE, so a
      // custom option ID typed after Load left the previous option's before-state armed under a
      // new ID. Every keystroke invalidates the editor (a partial ID like '6' -> '66' must not
      // stay 'loaded'); the commit edge ('change' - blur/Enter) then reloads for the typed ID,
      // exactly like the dropdown does. No per-keystroke remote read.
      optIdInput.addEventListener('input', function () { updateBulk(); if (!optionLoaded()) invalidateLoadedOption(); });
      optIdInput.addEventListener('change', function () { updateBulk(); if (currentScopeId && !optionLoaded()) doLoad(true); });
      ipList.addEventListener('click', updateApplyState);
      removeOptCb._cb.addEventListener('change', updateApplyState);
      renderScopes(); renderIpList(); updateBulk();
      // initial banner
      log.append({ text: 'DHCP Scope Option Tool ready. Connect to a server to begin.', level: 'accent' });
      log.append({ text: 'Single scope: click a scope, choose an option, edit the IP list, APPLY.', level: 'dim' });
      log.append({ text: 'Bulk: check scopes, type IPs in the footer, Append/Prepend/Remove.', level: 'dim' });

      host.appendChild(root);
      this._root = root; this._unsub = function () { if (readUnsub) readUnsub(); if (writeUnsub) writeUnsub(); };
    }
  });
})();
