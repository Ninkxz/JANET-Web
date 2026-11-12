/* Comply to Connect rules and evidence from the existing readiness scan. */
(function () {
  'use strict';
  var Janet = window.Janet;
  var ui = Janet.ui;
  var el = ui.el;
  var pages = [
    { id: 'overview', label: 'Overview' },
    { id: 'defender', label: 'Defender', expectation: 'Signatures are at most 7 days old, protection is on, and the device reports to the expected MDE tenant.' },
    { id: 'vulnerabilities', label: 'Vulnerabilities/AQC', expectation: 'The authoritative AQC score must be below 25. Firefox is prohibited.' },
    { id: 'patching', label: 'Patching', expectation: 'Review Windows updates, MECM readiness and any restart still required.' },
    { id: 'firewall', label: 'Firewall', expectation: 'Domain, Private and Public firewall profiles must be on.', rule: 'Firewall' },
    { id: 'bitlocker', label: 'BitLocker', expectation: 'The Windows system volume must have BitLocker protection on.', rule: 'Encryption' },
    { id: 'tanium', label: 'Tanium monitoring', expectation: 'The Tanium client must be installed and running to attest.', rule: 'Monitoring' },
    { id: 'pki', label: 'PKI certificates', expectation: 'Check the installed trust roots against the configured PKI baseline.', rule: 'PkiRoots' }
  ];

  function key(host) { return String(host || '').trim().toLowerCase(); }
  function shortKey(host) {
    var name = key(host);
    return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(name) ? name : name.split('.')[0];
  }
  function targetIndex(targets) {
    var index = new Map();
    targets.forEach(function (target) {
      var short = shortKey(target);
      index.set(short, index.has(short) ? null : target);
    });
    return index;
  }
  function resolveTarget(host, index) {
    var short = shortKey(host), target = index.get(short);
    if (!target) return null;
    return key(host) === short || key(host) === key(target) ? target : null;
  }
  function findTarget(host, targets) { return resolveTarget(host, targetIndex(targets)); }
  function trustedObservation(row) {
    return row && ['READY', 'QUARANTINE RISK', 'NOT ATTESTING', 'CHECK ERRORS'].indexOf(row.Status) !== -1;
  }
  function field(label, tone) { return { label: label, tone: tone || 'unknown' }; }
  function count(value) { return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null; }
  function signatures(e) {
    var hours = count(e.DefenderSignatureAgeHours);
    if (hours === null) return field('Unknown');
    var age = hours < 24 ? hours.toFixed(1) + ' hr' : (hours / 24).toFixed(1) + ' days';
    return field(age + (hours <= 168 ? ' · Current' : ' · Stale'), hours <= 168 ? 'meets' : 'attention');
  }
  function protection(e) {
    if (e.DefenderEnabled === false) return field('Off', 'attention');
    if (e.DefenderEnabled === true) return field('On', 'meets');
    return field('Unknown');
  }
  function protectionDetails(e) {
    var rtp = e.DefenderRealTimeProtectionEnabled;
    return field((rtp === true ? 'On' : rtp === false ? 'Off' : 'Unknown') +
      (e.DefenderRunningMode ? ' · ' + e.DefenderRunningMode : ''), 'neutral');
  }
  function defenderRule(e) {
    var signature = signatures(e), enabled = protection(e);
    if (signature.tone === 'attention' || enabled.tone === 'attention') return field('Needs attention', 'attention');
    if (signature.tone === 'meets' && enabled.tone === 'meets') return field('Meets local rule', 'meets');
    return field('Unknown');
  }
  function tenant(e) {
    if (e.MdeOrgIdStatus === 'Match') return field('Expected tenant', 'meets');
    if (e.MdeOrgIdStatus === 'Wrong') return field('Wrong tenant', 'attention');
    if (e.MdeOrgIdStatus === 'Missing') return field('Missing', 'attention');
    return field(e.MdeOrgIdStatus === 'Present' ? 'Present · tenant unverified' : 'Unknown');
  }
  function reporting(e) {
    var detail = e.MdeSenseRunning === true ? ' · Sense running' : (e.MdeSenseRunning === false ? ' · Sense stopped' : '');
    return field('Unknown' + detail);
  }
  function intune(e) {
    var detail = e.LocalMdmEnrollmentEvidence;
    return field('Unknown' + (detail === 'Present' ? ' · local MDM evidence found' :
      (detail === 'Absent' ? ' · no local MDM evidence found' : '')));
  }
  function firefox(e) {
    if (e.FirefoxInstalled === true) return field('Prohibited · installed', 'attention');
    if (e.FirefoxInstalled === false) return field('Not found in machine inventory');
    return field('Unknown');
  }
  function ruleResult(row, rule) {
    var check = row && row.Rules && row.Rules[rule];
    if (check && check.Status === 'PASS') return field('Pass', 'meets');
    if (check && check.Status === 'FAIL') return field('Fail', 'attention');
    if (check && check.Status === 'ERROR') return field('Check failed');
    if (check && check.Status === 'EXT') return field('External check');
    return field('Unknown');
  }
  function updates(row, e) {
    var pending = count(e.MecmPendingUpdates), overdue = count(e.MecmOverdueUpdates);
    if (overdue > 0 || ruleResult(row, 'Patches').tone === 'attention') return field('Overdue updates', 'attention');
    if (e.MecmClientRunning === false) return field('MECM client not running', 'attention');
    if (e.RebootPending === true) return field('Restart pending', 'attention');
    if (pending > 0) return overdue === 0 && e.RebootPending === false && e.MecmClientRunning === true
      ? field('Pending · none overdue', 'meets') : field('Updates pending · review');
    if (overdue === 0 && pending === 0 && e.MecmClientRunning === true && e.RebootPending === false) {
      return field('No updates pending', 'meets');
    }
    return field('Unknown');
  }
  function updateDetails(row, e) {
    var details = [];
    var overdue = count(e.MecmOverdueUpdates);
    var pending = count(e.MecmPendingUpdates);
    if (e.MecmClientRunning === false) details.push('MECM client not running');
    if (e.RebootPending === true) details.push('Restart pending');
    if (overdue > 0) details.push(overdue + ' overdue');
    if (details.length) return field(details.join(' · '), 'attention');
    if (pending > 0 && overdue === 0) return field(pending + ' pending · none overdue', 'neutral');
    return updates(row, e);
  }
  function summary(id, row, flagged) {
    var e = row && row.Evidence || {};
    if (id === 'defender') {
      var local = defenderRule(e), org = tenant(e);
      if (local.tone === 'attention' || org.tone === 'attention') return field('Needs attention', 'attention');
      return field(local.tone === 'meets' ? 'Local rule passes · reporting unknown' : 'Needs verification');
    }
    if (id === 'vulnerabilities') {
      if (firefox(e).tone === 'attention') return field('Firefox detected', 'attention');
      return flagged ? field('Reported finding', 'attention') : field('AQC unknown');
    }
    if (id === 'patching') return updates(row, e);
    var page = pages.find(function (p) { return p.id === id; });
    return ruleResult(row, page && page.rule);
  }

  function Compliance(opts) {
    var root = el('section', 'j-c2c-dashboard');
    var toolbar = el('div', 'j-c2c-assess');
    var scope = el('span', null, 'C2C targets · 0 devices');
    var status = el('span', 'muted');
    status.setAttribute('role', 'status');
    var scan = ui.button('Assess C2C targets', { variant: 'go', onClick: start });
    scan.disabled = true;
    toolbar.appendChild(scope);
    toolbar.appendChild(scan);
    toolbar.appendChild(status);
    root.appendChild(toolbar);
    var intro = el('div', 'j-c2c-intro');
    var data = el('div', 'j-c2c-data');
    root.appendChild(intro);
    root.appendChild(data);

    var pageId = 'overview';
    var hosts = [];
    var observations = new Map();
    var reportedHosts = [];
    var reported = new Set();
    var checked = new Set();
    var busy = false, assessed = false, disposed = false;
    var offRun = null, paintTimer = null;
    var actions, stageButton, ticketButton, selectedCount;

    function updateToolbar() {
      scope.textContent = 'C2C targets · ' + hosts.length + (hosts.length === 1 ? ' device' : ' devices');
      scan.disabled = busy || !hosts.length;
      scan.textContent = assessed ? 'Reassess C2C targets' : 'Assess C2C targets';
      if (stageButton) stageButton.disabled = busy || !checked.size;
      if (ticketButton) ticketButton.disabled = busy || checked.size !== 1;
      if (selectedCount) selectedCount.textContent = checked.size + ' selected';
    }
    async function start() {
      if (busy || !hosts.length || disposed) return;
      busy = true;
      observations.clear();
      checked.clear();
      queuePaint();
      status.textContent = 'Preparing assessment…';
      updateToolbar();
      try {
        if (!await opts.startScan()) {
          busy = false;
          status.textContent = 'A C2C action is already running, or there are no targets.';
        }
      } catch (e) {
        busy = false;
        status.textContent = 'Could not start assessment. ' + e.message;
      }
      if (!disposed) updateToolbar();
    }
    function assess(run, snapshot) {
      if (disposed) return;
      if (offRun) offRun();
      observations.clear();
      checked.clear();
      assessed = true;
      busy = true;
      status.textContent = 'Assessing ' + snapshot.length + ' devices…';
      var requested = targetIndex(snapshot);
      var interrupted = false;
      offRun = run.subscribe({
        row: function (row) {
          var target = resolveTarget(row.Host, requested);
          if (target) observations.set(key(target), row);
          queuePaint();
        },
        progress: function (p) {
          if (p.total && !interrupted) status.textContent = 'Assessing · ' + p.done + ' / ' + p.total;
        },
        error: function () {
          interrupted = true;
          status.textContent = 'Assessment interrupted. Review the C2C activity log.';
        },
        active: function (active) {
          busy = active;
          if (!active && !interrupted) {
            status.textContent = run.state && run.state.status === 'cancelled'
              ? 'Assessment cancelled. Review any observations collected.'
              : 'Assessment ended. Review each device’s evidence.';
          }
          updateToolbar();
          queuePaint();
        }
      });
      updateToolbar();
      queuePaint();
    }
    function queuePaint() {
      if (disposed || paintTimer !== null) return;
      paintTimer = setTimeout(function () { paintTimer = null; if (!disposed) paint(); }, 0);
    }
    function link(label, tool, tab, navigation) {
      return ui.ghostButton(label, { size: 'sm', onClick: function () { opts.openTool(tool, tab, navigation); } });
    }
    function show(id) {
      pageId = id;
      checked.clear();
      intro.textContent = '';
      actions = el('div', 'j-c2c-actions');
      stageButton = null;
      ticketButton = null;
      selectedCount = null;
      var page = pages.find(function (item) { return item.id === id; });
      if (page.expectation) {
        intro.appendChild(el('h2', null, page.label));
        intro.appendChild(el('p', null, page.expectation));
      }
      if (id === 'defender') {
        actions.appendChild(link('Review Defender / MDE fix', 'c2c', 'defenderfix'));
        ticketButton = ui.ghostButton('Draft Intune escalation', { size: 'sm', onClick: draftTicket });
        actions.appendChild(ticketButton);
        intro.appendChild(el('p', 'muted', 'The existing fix can update signatures and repair Defender or MDE. Verify cloud reporting and Intune enrollment in the authoritative consoles.'));
      } else if (id === 'vulnerabilities' || id === 'patching') {
        if (id === 'vulnerabilities') {
          actions.appendChild(link('Import C2C report', 'c2c', 'import'));
          actions.appendChild(link('Review installed software', 'wpt', 'software'));
          intro.appendChild(el('p', 'muted', 'The endpoint scan has no numeric AQC score. Firefox inventory checks machine uninstall entries. Per-user and portable copies remain unverified.'));
        } else {
          actions.appendChild(ui.ghostButton('Browse patching tools', { size: 'sm', onClick: opts.patchingTools }));
          actions.appendChild(link('Verify Patch', 'wpt', 'verifypatch'));
          actions.appendChild(link('KB Scanner', 'wpt', 'kb'));
          intro.appendChild(el('p', 'muted', 'Windows Update and BITS can start on demand. A stopped service alone does not confirm an update blocker.'));
        }
        stageButton = ui.ghostButton('Review Peanut butter shot (MECM)', {
          size: 'sm', onClick: function () { if (checked.size && !busy) opts.stagePatching(hosts.filter(function (host) { return checked.has(host); })); }
        });
        actions.appendChild(stageButton);
        actions.appendChild(link('Open Bulk Scan & Patch', 'wpt', 'bulk'));
        intro.appendChild(el('p', 'muted', 'Stage selected devices for eligible MECM apps and updates. Windows updates follow MECM restart policy. Confirm the checked hosts in Bulk Scan & Patch and verify afterward.'));
      } else if (page.rule) {
        actions.appendChild(link('Review ' + page.label + ' fix', 'c2c', 'fixes', { pillar: page.rule }));
        if (id === 'bitlocker') actions.appendChild(link('BitLocker Escrow Audit', 'c2c', 'escrow'));
      }
      if (ticketButton || stageButton) {
        selectedCount = el('span', 'muted');
        actions.appendChild(selectedCount);
      }
      if (actions.children.length) intro.appendChild(actions);
      updateToolbar();
      paint();
    }
    function draftTicket() {
      if (busy || checked.size !== 1) return;
      var host = Array.from(checked)[0];
      var row = observed(host);
      var e = row && row.Evidence || {};
      var editor = el('div', 'j-c2c-draft');
      editor.appendChild(el('p', null, 'Review and edit this draft before copying or downloading.'));
      var draft = ui.textarea({ rows: 12, value: [
        'Subject: Verify Intune enrollment and MDE reporting for ' + host,
        '',
        'Device: ' + host,
        'Observed: ' + (e.ObservedAtUtc || 'No endpoint assessment available'),
        'Defender signatures: ' + signatures(e).label,
        'Defender protection: ' + protection(e).label,
        'MDE organization: ' + tenant(e).label,
        'MDE cloud reporting: ' + reporting(e).label,
        'Intune enrollment: ' + intune(e).label,
        '',
        'Please confirm the authoritative Intune enrollment and MDE reporting state for this device and advise on remediation.'
      ].join('\n') });
      draft.setAttribute('aria-label', 'Editable ticket draft');
      editor.appendChild(draft);
      var feedback = el('span', 'muted');
      feedback.setAttribute('role', 'status');
      var buttons = el('div', 'j-c2c-actions');
      buttons.appendChild(ui.ghostButton('Copy draft', { onClick: async function () {
        try { await navigator.clipboard.writeText(draft.value); feedback.textContent = 'Copied'; }
        catch (e) { draft.select(); feedback.textContent = 'Press Ctrl+C to copy the selected draft.'; }
      } }));
      buttons.appendChild(ui.ghostButton('Download draft', { onClick: function () {
        Janet.util.downloadBlob('intune-escalation-draft.txt', 'text/plain;charset=utf-8', draft.value);
      } }));
      buttons.appendChild(feedback);
      editor.appendChild(buttons);
      Janet.components.ConfirmDialog({ title: 'Intune escalation draft', body: editor, okText: 'Close', cancelText: null });
    }
    function columns() {
      if (pageId === 'defender') return [
        ['Local rule', function (r, e) { return defenderRule(e); }],
        ['Signatures', function (r, e) { return signatures(e); }],
        ['Protection', function (r, e) { return protection(e); }],
        ['Real-time / mode', function (r, e) { return protectionDetails(e); }],
        ['MDE org', function (r, e) { return tenant(e); }],
        ['MDE reporting', function (r, e) { return reporting(e); }],
        ['Intune', function (r, e) { return intune(e); }]
      ];
      if (pageId === 'vulnerabilities') return [
        ['AQC score', function () { return field('Unknown'); }],
        ['Imported report', function (r, e, flagged) { return flagged ? field('Vulnerability flagged', 'attention') : field('No evidence'); }],
        ['System drive free', function (r, e) { var gb = count(e.SystemDriveFreeGB); return field(gb === null ? 'Unknown' : gb + ' GB', gb === null ? 'unknown' : 'neutral'); }],
        ['Update readiness', updateDetails],
        ['Firefox', function (r, e) { return firefox(e); }]
      ];
      if (pageId === 'patching') return [
        ['Update readiness', updateDetails],
        ['MECM pending', function (r, e) { var n = count(e.MecmPendingUpdates); return field(n === null ? 'Unknown' : String(n), n === null ? 'unknown' : 'neutral'); }],
        ['MECM overdue', function (r, e) { var n = count(e.MecmOverdueUpdates); return field(n === null ? 'Unknown' : String(n), n > 0 ? 'attention' : n === 0 ? 'meets' : 'unknown'); }],
        ['Windows Update / BITS', function (r, e) { return field((e.WindowsUpdateServiceStatus || 'Unknown') + ' / ' + (e.BitsServiceStatus || 'Unknown'), 'neutral'); }],
        ['Restart pending', function (r, e) { return field(e.RebootPending === true ? 'Yes' : e.RebootPending === false ? 'No' : 'Unknown', e.RebootPending === true ? 'attention' : 'unknown'); }]
      ];
      var page = pages.find(function (p) { return p.id === pageId; });
      if (page.rule) return [[page.label, function (r) { return ruleResult(r, page.rule); }]];
      return pages.slice(1).map(function (page) {
        return [page.label, function (r, e, flagged) { return summary(page.id, r, flagged); }];
      });
    }
    function paint() {
      data.textContent = '';
      if (pageId === 'overview') {
        var cards = el('div', 'j-c2c-summary');
        pages.slice(1).forEach(function (page) {
          var attention = 0, unknown = 0, meets = 0;
          hosts.forEach(function (host) {
            var v = summary(page.id, observed(host), reported.has(host));
            if (v.tone === 'attention') attention++;
            else if (v.tone === 'meets') meets++;
            else unknown++;
          });
          var card = el('div', 'j-c2c-summary-card');
          card.appendChild(ui.ghostButton(page.label, { onClick: function () { opts.showRule(page.id); } }));
          card.appendChild(el('p', null, hosts.length
            ? attention + ' need attention · ' + unknown + ' unknown' + (meets ? ' · ' + meets + ' meet rule' : '')
            : 'Awaiting targets'));
          cards.appendChild(card);
        });
        data.appendChild(cards);
      }
      if (!hosts.length) {
        var empty = el('div', 'j-c2c-empty');
        empty.appendChild(el('h3', null, 'Add devices to assess'));
        empty.appendChild(el('p', 'muted', 'Paste target names or import a Tanium C2C report to start.'));
        empty.appendChild(link('Edit C2C targets', 'c2c', 'targets'));
        empty.appendChild(link('Import C2C report', 'c2c', 'import'));
        data.appendChild(empty);
        return;
      }
      var cols = columns(), selectable = !!(ticketButton || stageButton);
      var scroller = el('div', 'j-c2c-table-scroll');
      var table = el('table', 'j-c2c-table');
      var head = el('thead'), header = el('tr'), tbody = el('tbody');
      function heading(label) { var th = el('th', null, label); th.scope = 'col'; header.appendChild(th); }
      if (selectable) heading('Select');
      heading('Device');
      cols.forEach(function (col) { heading(col[0]); });
      heading('Observed');
      head.appendChild(header);
      table.appendChild(head);
      hosts.forEach(function (host) {
        var r = observed(host), e = r && r.Evidence || {};
        var tr = el('tr');
        if (selectable) {
          var td = el('td'), cb = el('input');
          cb.type = 'checkbox';
          cb.checked = checked.has(host);
          cb.setAttribute('aria-label', 'Select ' + host);
          cb.onchange = function () { if (cb.checked) checked.add(host); else checked.delete(host); updateToolbar(); };
          td.appendChild(cb);
          tr.appendChild(td);
        }
        var hostCell = el('th', null, host); hostCell.scope = 'row'; tr.appendChild(hostCell);
        var flagged = reported.has(host);
        cols.forEach(function (col) {
          var value = col[1](r, e, flagged);
          tr.appendChild(el('td', 'j-c2c-' + value.tone, value.label));
        });
        var time = new Date(e.ObservedAtUtc || '');
        tr.appendChild(el('td', 'muted', Number.isFinite(time.valueOf()) ? time.toLocaleString() : observationState(host)));
        tbody.appendChild(tr);
      });
      table.appendChild(tbody);
      scroller.appendChild(table);
      data.appendChild(scroller);
    }

    function observed(host) {
      var row = observations.get(key(host));
      return trustedObservation(row) ? row : null;
    }
    function observationState(host) {
      var row = observations.get(key(host));
      var state = row && String(row.Status || '').toUpperCase();
      if (state === 'OFFLINE') return 'Offline';
      if (state === 'CANCELLED') return 'Cancelled';
      if (state === 'DNS MISMATCH' || state === 'IDENTITY UNKNOWN') return 'Identity unverified';
      if (state === 'ERROR') return 'Scan error';
      if (busy) return 'Pending';
      return row ? 'Unavailable' : 'Not assessed';
    }
    function updateReport() {
      var current = targetIndex(hosts);
      reported = new Set(reportedHosts.map(function (host) { return resolveTarget(host, current); }).filter(Boolean));
    }

    return {
      el: root,
      show: show,
      assess: assess,
      setTargets: function (targets) {
        if (targets.length === hosts.length && targets.every(function (host, i) { return host === hosts[i]; })) return;
        hosts = targets.slice();
        updateReport();
        checked.forEach(function (host) { if (hosts.indexOf(host) === -1) checked.delete(host); });
        updateToolbar();
        queuePaint();
      },
      setReport: function (summary) {
        var pillars = summary && Array.isArray(summary.pillars) ? summary.pillars : [];
        var vuln = pillars.find(function (p) { return p.name === 'Vuln'; });
        reportedHosts = vuln && Array.isArray(vuln.hosts) ? vuln.hosts : [];
        updateReport();
        queuePaint();
      },
      dispose: function () { disposed = true; if (offRun) offRun(); if (paintTimer !== null) clearTimeout(paintTimer); }
    };
  }

  Compliance.pages = pages;
  Compliance.evidence = { findTarget: findTarget, signatures: signatures, protection: protection,
    tenant: tenant, reporting: reporting, intune: intune, firefox: firefox, summary: summary,
    defenderRule: defenderRule, trustedObservation: trustedObservation };
  Janet.components.Compliance = Compliance;
})();
