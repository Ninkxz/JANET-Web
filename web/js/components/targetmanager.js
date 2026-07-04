/* ============================================================================
   TargetManager  ->  Janet.components.TargetManager
   First-class host-list panel: a big multiline box (paste line/comma/space),
   Import TXT/CSV, Clear, a live count label (green when >0), and an optional
   Ping All pre-flight button. Case-insensitive de-dup via Janet.util.parseHosts.

   Backs a target model: pass ctx.targets for a SHARED list, or a fresh
   Janet.util.targetModel() for a tool-owned bespoke panel (message does this).

   instance = TargetManager({
       model, hint, importLabel, onImport(count,name), onClear,
       pingAll:true, onPingAll(), countNoun:'target'
   })
     .el  .hosts()  .count()  .setText(t)  .getText()  .focus()
     .setPingEnabled(bool)  .model
   ========================================================================== */
(function () {
  'use strict';
  var Janet = window.Janet = window.Janet || {};
  Janet.components = Janet.components || {};
  var el = Janet.ui.el;

  function TargetManager(opts) {
    opts = opts || {};
    var model = opts.model || Janet.util.targetModel('');
    var noun = opts.countNoun || 'target';
    var root = el('div', 'j-targets');

    root.appendChild(el('div', 'j-tg-hint', opts.hint || 'Hostnames, comma or newline separated'));

    var box = Janet.ui.textarea({ placeholder: opts.placeholder || 'One host per line - or use Import', value: model.raw });
    box.classList.add('j-tg-box');
    box.addEventListener('input', function () { model.set(box.value); });
    root.appendChild(box);

    var bar = el('div', 'j-tg-bar');

    // Import (browser-native file picker; appends non-blank lines)
    var fileInput = el('input'); fileInput.type = 'file'; fileInput.accept = opts.importAccept || '.txt,.csv,.tsv'; fileInput.style.display = 'none';
    var importBtn = Janet.ui.ghostButton(opts.importLabel || 'Import TXT', { size: 'sm', title: 'Load hostnames from a TXT/CSV file (non-blank lines are appended).' });
    importBtn.onclick = function () { fileInput.value = ''; fileInput.click(); };
    fileInput.addEventListener('change', function () {
      var f = fileInput.files && fileInput.files[0]; if (!f) return;
      var reader = new FileReader();
      reader.onload = function () {
        var raw = String(reader.result || '');
        var name = (f.name || '');
        // CSV/TSV exports (ACAS/AD/SCCM) carry many columns; pull just the host
        // column so a whole row doesn't land as one "target". TXT stays line-split.
        var text = /\.(csv|tsv)$/i.test(name) ? extractHostColumn(raw) : raw;
        var added = appendText(text);
        if (opts.onImport) opts.onImport(added, f.name);
      };
      reader.readAsText(f);
    });
    bar.appendChild(importBtn);
    bar.appendChild(fileInput);

    var clearBtn = Janet.ui.button('Clear', { variant: 'danger', size: 'sm', title: 'Empty the target list.' });
    clearBtn.onclick = function () { model.set(''); if (opts.onClear) opts.onClear(); };
    bar.appendChild(clearBtn);

    var pingBtn = null;
    if (opts.pingAll) {
      pingBtn = Janet.ui.button('Ping All', { variant: 'cyan', size: 'sm', title: 'Test reachability of every target before you act.' });
      pingBtn.onclick = function () { if (opts.onPingAll) opts.onPingAll(); };
      bar.appendChild(pingBtn);
    }

    // Get Info: read-only Host Info snapshot for a target (PIRS/WPT parity), in any
    // tool. Default-on; pass getInfo:false for non-workstation target lists.
    if (opts.getInfo !== false) {
      var infoBtn = Janet.ui.button('Get Info', { variant: 'cyan', size: 'sm', title: 'Read-only Host Info snapshot (OS, model, serial, IP/MAC, uptime, users, pending reboot) for a target host.' });
      infoBtn.onclick = function () { if (window.Janet && Janet.hostInfoPanel) Janet.hostInfoPanel(effectiveHosts()); };
      bar.appendChild(infoBtn);
    }

    // Negative exclude-filter (PIRS: drop test/kiosk/maintenance-window hosts
    // before a mass action). Case-insensitive substring match; empty = all hosts.
    var excludeInput = el('input', 'j-input j-tg-exclude');
    excludeInput.type = 'text';
    excludeInput.placeholder = 'Exclude (substring, comma-separated)';
    excludeInput.title = 'Drop hosts whose name contains ANY of these comma/space-separated terms (e.g. test, kiosk, maint) before acting. Case-insensitive; plain substring, no wildcards.';
    excludeInput.addEventListener('input', function () { refreshCount(); });
    bar.appendChild(excludeInput);

    var count = el('span', 'j-tg-count none', '0 ' + noun + '(s)');
    bar.appendChild(count);
    root.appendChild(bar);

    // --- saved groups (target library) + cross-tool handoff -------------------
    // Reusable named host lists in Janet.store, loadable into any tool's targets.
    if (opts.groups !== false && Janet.store) {
      var lib = el('div', 'j-tg-bar j-tg-lib');
      var groupSel = el('select', 'j-select j-tg-group');
      groupSel.title = 'Load a saved host group into this list (appends).';
      function refreshGroups() {
        groupSel.innerHTML = '';
        groupSel.appendChild(new Option('Load group...', ''));
        Janet.store.names().forEach(function (n) { groupSel.appendChild(new Option(n, n)); });
      }
      refreshGroups();
      // Groups load synchronously from the localStorage-seeded cache above; when the
      // server hydrate (Janet.store.ready) lands the authoritative set, re-render once
      // so a fresh browser / new port shows the persisted groups without a remount.
      if (Janet.store.ready && Janet.store.ready.then) { Janet.store.ready.then(function () { refreshGroups(); }); }
      groupSel.onchange = function () {
        var n = groupSel.value; groupSel.value = ''; if (!n) return;
        var added = appendText(Janet.store.get(n));
        if (opts.onImport) opts.onImport(added, 'group:' + n);
      };
      // ponytail: window.prompt/confirm for the name - stdlib, fine for a loopback
      // admin tool; swap for a themed text-input modal if it ever needs validation.
      var saveBtn = Janet.ui.ghostButton('Save group', { size: 'sm', title: 'Save the current list as a named, reusable group.' });
      saveBtn.onclick = function () {
        var hosts = effectiveHosts(); if (!hosts.length) return;
        var name = window.prompt('Save ' + hosts.length + ' host(s) as group name:', ''); if (name == null) return;
        name = name.trim(); if (!name) return;
        if (Janet.store.has(name) && !window.confirm('Group "' + name + '" exists. Overwrite?')) return;
        Janet.store.set(name, hosts.join('\n')); refreshGroups();
      };
      var delBtn = Janet.ui.ghostButton('Del', { size: 'sm', title: 'Delete a saved group.' });
      delBtn.onclick = function () {
        var names = Janet.store.names(); if (!names.length) { window.alert('No saved groups.'); return; }
        var name = window.prompt('Delete which group?\n\n' + names.join(', '), ''); if (name == null) return;
        name = name.trim();
        if (name && Janet.store.has(name) && window.confirm('Delete group "' + name + '"?')) { Janet.store.remove(name); refreshGroups(); }
      };
      // canary / ring rollout: keep first N here, save the rest as a group to run next
      var canaryBtn = Janet.ui.ghostButton('Canary', { size: 'sm', title: 'Stage a rollout: keep the first N hosts here, save the rest as a group.' });
      canaryBtn.onclick = function () {
        var hosts = effectiveHosts(); if (hosts.length < 2) { window.alert('Need at least 2 hosts to split a canary.'); return; }
        var nStr = window.prompt('Canary size - keep the first N here, save the rest as a group:', String(Math.min(5, hosts.length - 1))); if (nStr == null) return;
        var n = parseInt(nStr, 10); if (!(n > 0 && n < hosts.length)) { window.alert('Enter a number between 1 and ' + (hosts.length - 1) + '.'); return; }
        var gname = window.prompt('Save the remaining ' + (hosts.length - n) + ' host(s) as group:', 'rest'); if (gname == null) return;
        gname = gname.trim() || 'rest';
        Janet.store.set(gname, hosts.slice(n).join('\n'));
        model.set(hosts.slice(0, n).join('\n')); box.value = model.raw;
        refreshGroups();
      };
      lib.appendChild(groupSel); lib.appendChild(saveBtn); lib.appendChild(delBtn); lib.appendChild(canaryBtn);
      root.appendChild(lib);
    }

    // hosts handed off from another tool (e.g. WPT scan -> Restart)
    var pend = Janet.handoff && Janet.handoff.peek && Janet.handoff.peek();
    if (opts.groups !== false && pend && pend.hosts && pend.hosts.length) {
      var ho = el('div', 'j-tg-handoff');
      ho.appendChild(el('span', null, pend.hosts.length + ' host(s) from ' + (pend.label || 'another tool')));
      var loadHo = Janet.ui.button('Load', { variant: 'cyan', size: 'sm' });
      loadHo.onclick = function () { var p = Janet.handoff.take(); if (p) { var a = appendText(p.hosts.join('\n')); if (opts.onImport) opts.onImport(a, 'handoff'); } ho.remove(); };
      var dis = Janet.ui.ghostButton('Dismiss', { size: 'sm' });
      dis.onclick = function () { Janet.handoff.clear(); ho.remove(); };
      ho.appendChild(loadHo); ho.appendChild(dis);
      root.appendChild(ho);
    }

    // Extract the hostname/IP column from a CSV/TSV blob. Picks the first header
    // matching a known host/ip pattern; falls back to column 0. A single-logical-
    // column file is treated as a plain host list (returned raw for line-splitting).
    function extractHostColumn(raw) {
      var text = raw;
      if (raw.indexOf(',') === -1 && raw.indexOf('\t') !== -1) text = raw.replace(/\t/g, ','); // TSV -> CSV
      var parsed = (Janet.util && Janet.util.parseCsv) ? Janet.util.parseCsv(text) : { headers: [], rows: [] };
      var headers = parsed.headers || [], rows = parsed.rows || [];
      var width = headers.length;
      for (var w = 0; w < rows.length; w++) { if (rows[w].length > width) width = rows[w].length; }
      if (width <= 1) return raw; // really just a host list - let appendText line-split it
      var pats = [/netbios/i, /dns\s*name/i, /computer.?name/i, /host\s*name/i, /^host$/i, /^name$/i, /fqdn/i, /ip\s*address/i, /^ip$/i, /^target$/i];
      var col = -1;
      for (var p = 0; p < pats.length && col === -1; p++) {
        for (var h = 0; h < headers.length; h++) { if (pats[p].test(String(headers[h] || '').trim())) { col = h; break; } }
      }
      var matched = (col !== -1); if (!matched) col = 0;
      var out = [];
      // No recognizable header matched -> row 1 might be data, not a header; keep it.
      if (!matched && headers[col] != null && String(headers[col]).trim()) out.push(String(headers[col]).trim());
      for (var r = 0; r < rows.length; r++) { var v = rows[r][col]; if (v != null && String(v).trim()) out.push(String(v).trim()); }
      return out.join('\n');
    }

    function appendText(text) {
      var before = model.count();
      var existing = model.raw.replace(/\s+$/, '');
      var incoming = String(text || '').split(/\r?\n/).map(function (s) { return s.trim(); }).filter(Boolean);
      var merged = (existing ? (existing + '\n') : '') + incoming.join('\n');
      model.set(merged);
      box.value = model.raw;
      return model.count() - before;
    }

    // Lowercased exclude terms from the field (comma/space separated, de-blanked).
    function excludeTerms() {
      return String(excludeInput.value || '').toLowerCase().split(/[,\s]+/).filter(Boolean);
    }
    // model.hosts() minus any host whose lowercased name contains ANY exclude term.
    // Pure indexOf string match - no RegExp, no injection. Empty field = all hosts.
    function effectiveHosts() {
      var all = model.hosts();
      var terms = excludeTerms();
      if (!terms.length) return all;
      return all.filter(function (h) {
        var lc = String(h).toLowerCase();
        for (var i = 0; i < terms.length; i++) { if (lc.indexOf(terms[i]) !== -1) return false; }
        return true;
      });
    }

    function refreshCount() {
      var total = model.count();
      var n = effectiveHosts().length;
      var excluded = total - n;
      if (opts.max) {
        count.textContent = n + ' / ' + opts.max + (excluded > 0 ? ' (' + excluded + ' excluded)' : '');
        count.className = 'j-tg-count ' + (n > opts.max ? 'over' : (n > 0 ? 'has' : 'none'));
      } else {
        count.textContent = n + ' ' + noun + '(s)' + (excluded > 0 ? ' (' + excluded + ' excluded)' : '');
        count.className = 'j-tg-count ' + (n > 0 ? 'has' : 'none');
      }
      // keep the box in sync if the model was changed externally (shared targets)
      if (box.value !== model.raw) box.value = model.raw;
    }
    var offModelChange = model.onChange(refreshCount);
    refreshCount();

    return {
      el: root, model: model,
      hosts: function () { return effectiveHosts(); },
      count: function () { return effectiveHosts().length; },
      getText: function () { return model.raw; },
      setText: function (t) { model.set(t); box.value = model.raw; },
      focus: function () { box.focus(); },
      setPingEnabled: function (on) { if (pingBtn) pingBtn.disabled = !on; },
      setPingLabel: function (txt) { if (pingBtn) pingBtn.textContent = txt; },
      // Release the shared-model listener. A TargetManager bound to a long-lived
      // model (e.g. WPT -> ctx.targets) otherwise leaks a refreshCount closure (and
      // its DOM) on every mount; bespoke per-view models are GC'd with the view.
      dispose: function () { if (offModelChange) { offModelChange(); offModelChange = null; } }
    };
  }
  Janet.components.TargetManager = TargetManager;
})();
