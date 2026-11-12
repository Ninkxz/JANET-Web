/* Workstation navigation. The shell supplies each original view and context. */
(function () {
  'use strict';
  var Janet = window.Janet;
  var el = Janet.ui.el;
  var groups = [
    { label: 'Targets', pages: [
      ['wpt', 'targets', 'Patching targets'],
      ['c2c', 'targets', 'C2C targets'],
      ['c2c', 'import', 'Import C2C report']
    ] },
    { label: 'Scan & verify', pages: [
      ['wpt', 'bulk', 'Bulk Scan & Patch'],
      ['wpt', 'verifypatch', 'Verify Patch'],
      ['c2c', 'readiness', 'C2C readiness'],
      ['c2c', 'version', 'Version Check'],
      ['c2c', 'escrow', 'BitLocker Escrow Audit']
    ] },
    { label: 'Software & updates', pages: [
      ['wpt', 'software', 'Software Manager'],
      ['wpt', 'sccm', 'Software Center Apps'],
      ['wpt', 'available', 'Available Deployments'],
      ['wpt', 'kb', 'KB Scanner'],
      ['wpt', 'appupd', 'App Updater'],
      ['wpt', 'beta', 'Beta']
    ] },
    { label: 'Fixes', pages: [
      ['c2c', 'fixes', 'C2C pillar fixes'],
      ['wpt', 'cleanup', 'Cleanup'],
      ['wpt', 'cleanapps', 'Clean User Apps'],
      ['wpt', 'regkey', 'Reg Key Fixes'],
      ['wpt', 'unsupported', 'Unsupported Software'],
      ['wpt', 'log4j', 'Log4j Finder'],
      ['wpt', 'vulnfix', 'Vuln Fixes'],
      ['c2c', 'lockscreen', 'Lockscreen & wallpaper'],
      ['c2c', 'java', 'C2C Java cleanup']
    ] },
    { label: 'Support & restart', pages: [
      ['wpt', 'health', 'Health / Healers'],
      ['wpt', 'hostinfo', 'Host Info'],
      ['wpt', 'eventlog', 'Event Logs'],
      ['wpt', 'winrm', 'WinRM Setup'],
      ['wpt', 'reboot', 'Reboot Countdown'],
      ['wpt', 'maint', 'Maintenance'],
      ['wpt', 'message', 'Remote Message']
    ] },
    { label: 'Reports & logs', pages: [
      ['wpt', 'reports', 'Reports'],
      ['wpt', 'trend', 'Compliance Trend'],
      ['wpt', 'usage', 'Usage'],
      ['wpt', 'logs', 'Logs']
    ] }
  ];
  var defaultPages = { wpt: 'targets', c2c: 'targets' };

  function Workstations(opts) {
    var root = el('div', 'j-workstations');
    var head = el('div', 'j-ws-head');
    var title = el('div', 'j-ws-title');
    var heading = el('h1');
    var overview = uiOverview();
    heading.appendChild(overview);
    title.appendChild(heading);
    title.appendChild(el('p', null, 'Comply to Connect'));
    head.appendChild(title);
    var headActions = el('div', 'j-ws-head-actions');
    headActions.appendChild(Janet.ui.ghostButton('Targets', { size: 'sm', onClick: function () { select('c2c', 'targets'); } }));
    headActions.appendChild(Janet.ui.ghostButton('Advanced tools', { size: 'sm', onClick: function () { findTools('c2c'); } }));
    headActions.appendChild(Janet.ui.ghostButton('Help', { size: 'sm', onClick: opts.help }));
    head.appendChild(headActions);
    root.appendChild(head);
    var primary = el('nav', 'j-ws-nav j-ws-primary');
    primary.setAttribute('aria-label', 'Compliance rules');
    root.appendChild(primary);
    var legacyHeader = el('div', 'j-ws-legacy hidden');
    var back = Janet.ui.ghostButton('Back to compliance', { size: 'sm', onClick: function () { showRule(activeRule); } });
    var legacyTitle = el('h2');
    legacyHeader.appendChild(back);
    legacyHeader.appendChild(legacyTitle);
    root.appendChild(legacyHeader);
    var scope = el('div', 'j-ws-scope');
    root.appendChild(scope);
    var runList = el('div', 'j-ws-active-runs hidden');
    runList.setAttribute('aria-label', 'Active workstation runs');
    root.appendChild(runList);
    var content = el('div', 'j-ws-content');
    var status = el('div', 'j-ws-status');
    status.setAttribute('role', 'status');
    content.appendChild(status);
    root.appendChild(content);

    var children = {};
    var activeRule = 'overview';
    var activePage = null;
    var ticket = 0;
    var disposed = false;
    var scopes = { wpt: '', c2c: '' };
    var ruleButtons = {};
    var runRows = {};

    function button(label, parent, action) {
      var b = el('button', 'j-ws-nav-btn', label);
      b.type = 'button';
      b.onclick = action;
      parent.appendChild(b);
      return b;
    }
    function uiOverview() {
      var overviewBtn = el('button', 'j-ws-overview', 'C2C');
      overviewBtn.type = 'button';
      overviewBtn.setAttribute('aria-label', 'C2C overview');
      overviewBtn.onclick = function () { showRule('overview'); };
      return overviewBtn;
    }

    var dashboard = Janet.components.Compliance({
      openTool: select,
      showRule: showRule,
      startScan: async function () {
        var child = await mountChild('c2c', 'targets');
        return !!(child && !disposed && child.view.startAssessment());
      },
      patchingTools: function () { findTools('wpt'); },
      stagePatching: stagePatching
    });
    content.appendChild(dashboard.el);
    Janet.components.Compliance.pages.forEach(function (rule) {
      ruleButtons[rule.id] = rule.id === 'overview' ? overview : button(rule.label, primary, function () { showRule(rule.id); });
    });

    function showScope() {
      var isC2c = activePage && activePage[0] === 'c2c';
      var text = isC2c ? scopes.c2c : scopes.wpt;
      scope.textContent = text;
      scope.classList.toggle('hidden', !activePage || !text);
    }
    function markRuleNav() {
      Object.keys(ruleButtons).forEach(function (id) {
        var active = id === activeRule;
        if (activePage) {
          active = (activePage[0] === 'wpt' && id === 'patching') ||
            (activePage[1] === 'defenderfix' && id === 'defender');
        }
        ruleButtons[id].setAttribute('aria-current', active ? 'page' : 'false');
      });
    }
    function showRule(id) {
      if (disposed || !ruleButtons[id]) return;
      ++ticket;
      activeRule = id;
      activePage = null;
      Object.keys(children).forEach(function (toolId) { children[toolId].node.classList.add('hidden'); });
      status.classList.add('hidden');
      legacyHeader.classList.add('hidden');
      dashboard.el.classList.remove('hidden');
      markRuleNav();
      showScope();
      dashboard.show(id);
      opts.onPage('c2c', 'readiness', id === 'overview' ? 'Overview' : ruleButtons[id].textContent);
    }
    function markPage(page) {
      activePage = page;
      legacyTitle.textContent = page[2];
      legacyHeader.classList.remove('hidden');
      dashboard.el.classList.add('hidden');
      markRuleNav();
      showScope();
      opts.onPage(page[0], page[1], page[2]);
    }

    function findPage(toolId, tab) {
      if (toolId === 'c2c' && tab === 'defenderfix') return ['c2c', 'defenderfix', 'Defender / MDE remediation'];
      for (var i = 0; i < groups.length; i++) {
        var page = groups[i].pages.find(function (item) { return item[0] === toolId && item[1] === tab; });
        if (page) return page;
      }
      return null;
    }

    function getChild(toolId) {
      if (children[toolId]) return children[toolId];
      var node = el('div', 'j-ws-child hidden');
      content.appendChild(node);
      var child = children[toolId] = { node: node, view: null };
      return child;
    }

    async function mountChild(toolId, initialTab) {
      var child = getChild(toolId);
      if (child.view) return child;
      if (child.loading) return child.loading;
      var pending = child.loading = (async function () {
        var loaded = await opts.load(toolId);
        if (disposed) return null;
        var view = Object.create(loaded.view);
        loaded.ctx.workspace = {
          initialTab: initialTab,
          onSelect: function (id) {
            var dest = findPage(toolId, id);
            if (!disposed && activePage && activePage[0] === toolId && dest) markPage(dest);
          },
          setScope: function (value) {
            scopes[toolId] = value;
            if (!disposed) showScope();
          },
          assessment: toolId === 'c2c' ? dashboard : null
        };
        try { view.mount(child.node, loaded.ctx); }
        catch (error) {
          try { if (view.unmount) view.unmount(); } catch (cleanupError) {}
          child.node.textContent = '';
          child.node.classList.add('hidden');
          throw error;
        }
        child.view = view;
        return child;
      })();
      try { return await pending; }
      finally { if (child.loading === pending) child.loading = null; }
    }
    async function select(toolId, tab, navigation) {
      if (disposed || !defaultPages[toolId]) return;
      var page = findPage(toolId, tab) || findPage(toolId, defaultPages[toolId]);
      var generation = ++ticket;
      markPage(page);
      Object.keys(children).forEach(function (id) {
        children[id].node.classList.add('hidden');
      });
      status.classList.remove('hidden');
      status.textContent = 'Loading ' + opts.toolName(toolId) + '…';
      try {
        var child = await mountChild(toolId, page[1]);
        if (!child || disposed || generation !== ticket) return;
        child.view.selectTab(page[1]);
        child.node.classList.remove('hidden');
        status.classList.add('hidden');
        if (navigation && navigation.peanut && child.view.prepareManagedPatch) child.view.prepareManagedPatch();
        if (navigation && navigation.pillar && child.view.focusPillar) child.view.focusPillar(navigation.pillar);
      } catch (error) {
        if (disposed || generation !== ticket) return;
        status.textContent = 'Could not open ' + opts.toolName(toolId) + '. ' + error.message;
        status.appendChild(Janet.ui.ghostButton('Retry', { onClick: function () { select(toolId, page[1], navigation); } }));
      }
    }

    function findTools(toolId) {
      var finder = el('div', 'j-ws-finder');
      var search = Janet.ui.input({ placeholder: 'Search tools' });
      search.setAttribute('aria-label', 'Search workstation tools');
      finder.appendChild(search);
      var links = el('div', 'j-ws-finder-links');
      finder.appendChild(links);
      var choice = null;
      function render() {
        var q = search.value.trim().toLowerCase();
        links.textContent = '';
        groups.forEach(function (group) {
          var pages = group.pages.filter(function (page) {
            return page[0] === toolId && (!q || (page[2] + ' ' + group.label).toLowerCase().indexOf(q) !== -1);
          });
          if (!pages.length) return;
          var block = el('div');
          block.appendChild(el('h3', null, group.label));
          pages.forEach(function (page) {
            button(page[2], block, function () {
              choice = page;
              // The dialog owns focus and closes before routing to the page.
              finder.closest('.j-modal-card').querySelector('.j-modal-actions button:last-child').click();
            });
          });
          links.appendChild(block);
        });
        if (!links.children.length) links.appendChild(el('p', 'muted', 'No matching tools.'));
      }
      search.addEventListener('input', render);
      render();
      Janet.components.ConfirmDialog({ title: toolId === 'wpt' ? 'Patching tools' : 'Advanced C2C tools', body: finder, okText: 'Close', cancelText: null })
        .then(function () { if (choice) select(choice[0], choice[1]); });
    }

    async function stagePatching(hosts) {
      var bulkActions = ['bulk-scan', 'bulk-patch', 'reboot', 'winrm-bootstrap', 'ping-sweep'];
      if (opts.activeRuns().some(function (handle) {
        return handle.state.toolId === 'wpt' && bulkActions.indexOf(handle.state.actionId) !== -1;
      })) {
        Janet.components.ConfirmDialog({ title: 'Bulk run already active',
          body: 'Finish or cancel the active bulk run before staging hosts.', okText: 'Close', cancelText: null });
        return;
      }
      var approved = await Janet.components.ConfirmDialog({
        title: 'Review hosts for managed patching',
        body: 'Stage these ' + hosts.length + ' checked hosts for the patching list. Staging clears the previous bulk results and selects non-invasive app mode. Use Load, review the full patching list, scan, and select rows before patching. Windows updates follow MECM restart policy.',
        list: hosts, okText: 'Stage hosts', cancelText: 'Cancel'
      });
      if (!approved || disposed) return;
      Janet.handoff.send(hosts, 'compliance assessment', null, 'wpt');
      select('wpt', 'bulk', { peanut: true });
    }

    function refreshRuns() {
      var active = opts.activeRuns();
      var keys = active.map(function (handle) {
        var state = handle.state;
        var row = runRows[handle.key];
        if (!row) {
          var node = el('div', 'j-ws-run');
          var title = el('span', null, opts.toolName(state.toolId) + ' · ' + state.actionId.replace(/-/g, ' '));
          var phase = el('span', 'muted');
          var cancel = Janet.ui.button('Cancel run', {
            variant: state.destructive ? 'danger' : 'ghost', size: 'sm',
            onClick: function () { handle.cancel(); }
          });
          cancel.setAttribute('aria-label', 'Cancel ' + title.textContent);
          node.appendChild(title);
          node.appendChild(phase);
          node.appendChild(cancel);
          runList.appendChild(node);
          row = runRows[handle.key] = { node: node, cancel: cancel, phase: phase };
        }
        row.cancel.disabled = !!state.cancelRequested;
        row.phase.textContent = state.cancelRequested ? 'Cancelling…' : 'Running';
        return handle.key;
      });
      Object.keys(runRows).forEach(function (key) {
        if (keys.indexOf(key) !== -1) return;
        runRows[key].node.remove();
        delete runRows[key];
      });
      runList.classList.toggle('hidden', !keys.length);
    }

    return {
      el: root,
      select: select,
      showRule: showRule,
      refreshRuns: refreshRuns,
      unmount: function () {
        disposed = true;
        dashboard.dispose();
        Object.keys(children).forEach(function (id) {
          var view = children[id].view;
          if (view && view.unmount) {
            try { view.unmount(); } catch (error) {}
          }
        });
        root.remove();
      }
    };
  }

  Workstations.groups = groups;
  Janet.components.Workstations = Workstations;
})();
