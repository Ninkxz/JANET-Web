// Run with: node --test tests/Workstations.Behavior.test.js
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const { test } = require('node:test');
const { runInNewContext } = require('node:vm');

const source = (path) => readFileSync(join(__dirname, '..', 'web', 'js', path), 'utf8');

function el(tag, className, value) {
  const classes = new Set((className || '').split(' '));
  return {
    children: [], attrs: {}, text: value || '',
    get textContent() { return this.text; },
    set textContent(value) { this.text = value; this.children = []; },
    setAttribute(key, value) { this.attrs[key] = value; },
    appendChild(child) { this.children.push(child); child.parent = this; },
    remove() {
      if (this.parent) this.parent.children = this.parent.children.filter((child) => child !== this);
    },
    classList: {
      add: (name) => classes.add(name),
      remove: (name) => classes.delete(name),
      toggle: (name, on) => on ? classes.add(name) : classes.delete(name),
      contains: (name) => classes.has(name)
    }
  };
}

function components() {
  const button = (label, opts) => Object.assign(el('button', '', label), { onclick: opts.onClick });
  const Janet = { ui: { el, button, ghostButton: button }, components: {} };
  const sandbox = { window: { Janet }, setTimeout, clearTimeout };
  runInNewContext(source('components/compliance.js'), sandbox);
  runInNewContext(source('components/workstations.js'), sandbox);
  return Janet.components;
}
function workstations() { return components().Workstations; }

function deferred() {
  let resolve, reject;
  const promise = new Promise((ok, no) => { resolve = ok; reject = no; });
  return { promise, resolve, reject };
}

function find(node, predicate) {
  if (predicate(node)) return node;
  for (const child of node.children) {
    const match = find(child, predicate);
    if (match) return match;
  }
}

test('every existing WPT tab and C2C workspace section is reachable exactly once', () => {
  const groups = workstations().groups;
  const routes = Array.from(groups).flatMap((group) => Array.from(group.pages));
  assert.equal(new Set(routes.map(([tool, tab]) => tool + '/' + tab)).size, 34);
  const wpt = [...source('views/wpt.view.js').matchAll(/\{ id: '([^']+)', label: '[^']+', build: build\w+ \}/g)].map((m) => m[1]);
  assert.equal(wpt.length, 26);
  assert.deepEqual(routes.filter(([tool]) => tool === 'wpt').map(([, tab]) => tab).sort(), wpt.sort());
  assert.deepEqual(routes.filter(([tool]) => tool === 'c2c').map(([, tab]) => tab).sort(),
    ['escrow', 'fixes', 'import', 'java', 'lockscreen', 'readiness', 'targets', 'version']);
});

test('deep links keep original contexts and retained children, including programmatic selection', async () => {
  const mounted = [], selected = [], unmounted = [];
  const contexts = { wpt: { toolId: 'wpt' }, c2c: { toolId: 'c2c' } };
  const workspace = workstations()({
    toolName: (id) => id, activeRuns: () => [],
    onPage: (tool, page) => selected.push([tool, page]),
    load: async (tool) => ({
      ctx: contexts[tool],
      view: {
        mount(host, ctx) {
          mounted.push([ctx.toolId, ctx.workspace.initialTab]);
          this.selectTab = ctx.workspace.onSelect;
        },
        unmount() { unmounted.push(tool); }
      }
    })
  });
  await workspace.select('wpt', 'cleanup');
  await workspace.select('c2c', 'import');
  await workspace.select('wpt', 'verifypatch');
  contexts.wpt.workspace.onSelect('reboot');
  assert.deepEqual(mounted, [['wpt', 'cleanup'], ['c2c', 'import']]);
  assert.deepEqual(selected.at(-1), ['wpt', 'reboot']);
  assert.ok(find(workspace.el, (node) => node.text === 'Reboot Countdown'));
  assert.equal(find(workspace.el, (node) => node.text === 'Patching').attrs['aria-current'], 'page');
  workspace.showRule('defender');
  assert.equal(find(workspace.el, (node) => node.text === 'Defender' && node.attrs['aria-current'] === 'page').text, 'Defender');
  assert.equal(unmounted.length, 0);
  workspace.unmount();
  assert.deepEqual(unmounted, ['wpt', 'c2c']);
});

test('a late load failure cannot overwrite another page and a partial mount stays inert', async () => {
  const wpt = deferred();
  let cleanup = 0;
  const workspace = workstations()({
    toolName: (id) => id, activeRuns: () => [], onPage() {},
    load: (tool) => tool === 'wpt' ? wpt.promise : Promise.resolve({
      ctx: { toolId: tool },
      view: {
        mount(host) { host.appendChild(el('button', '', 'Partial action')); throw new Error('broken mount'); },
        unmount() { cleanup++; throw new Error('broken cleanup'); }
      }
    })
  });
  const waiting = workspace.select('wpt', 'targets');
  await workspace.select('c2c', 'readiness');
  wpt.reject(new Error('old failure'));
  await waiting;
  assert.equal(cleanup, 1);
  assert.equal(find(workspace.el, (node) => node.text === 'Partial action'), undefined);
  assert.ok(find(workspace.el, (node) => node.text === 'Could not open c2c. broken mount'));
});

test('Defender review opens its own remediation route and retains the Advanced pillar route', async () => {
  const selected = [];
  let mounts = 0;
  const workspace = workstations()({
    toolName: (id) => id, activeRuns: () => [], onPage() {},
    load: async (tool) => ({
      ctx: { toolId: tool },
      view: {
        mount() {
          mounts++;
          this.selectTab = (id) => selected.push(id);
        }
      }
    })
  });
  workspace.showRule('defender');
  find(workspace.el, (node) => node.text === 'Review Defender / MDE fix').onclick();
  await new Promise(setImmediate);
  assert.equal(selected.at(-1), 'defenderfix');
  assert.ok(find(workspace.el, (node) => node.text === 'Defender / MDE remediation'));
  await workspace.select('c2c', 'fixes');
  assert.equal(selected.at(-1), 'fixes');
  assert.equal(mounts, 1);
  workspace.unmount();
});

test('staged hosts only resolve for their destination and refresh retained editors', () => {
  const Janet = {};
  runInNewContext(source('components/store.js'), {
    window: { Janet }, fetch: () => Promise.reject(new Error('isolated fixture'))
  });
  let updates = 0;
  const off = Janet.handoff.onChange(() => updates++);
  Janet.handoff.send(['fixture-host'], 'test handoff', null, 'c2c');
  assert.equal(Janet.handoff.peek('wpt'), null);
  assert.equal(Janet.handoff.peek(), null);
  assert.equal(Janet.handoff.peek('c2c').hosts[0], 'fixture-host');
  assert.equal(Janet.handoff.take().hosts[0], 'fixture-host');
  assert.equal(Janet.handoff.peek('c2c'), null);
  off();
  Janet.handoff.send(['legacy-fixture'], 'legacy');
  assert.equal(Janet.handoff.peek().hosts[0], 'legacy-fixture');
  assert.equal(updates, 2);
});

test('egress cancellation still reaches a pending destructive job after the same key restarts', async () => {
  const shell = source('shell.js');
  const begin = shell.indexOf('var RunController = (function () {');
  const end = shell.indexOf('\n  })();', begin) + '\n  })();'.length;
  const first = deferred(), second = deferred();
  const starts = [first, second];
  const cancel = [];
  const controller = runInNewContext(shell.slice(begin, end) + '\nRunController;', {
    window: { addEventListener() {} },
    current: null,
    api(method, path) {
      if (method === 'GET') return Promise.resolve({ status: 'done' });
      if (path.startsWith('/tool/')) return starts.shift().promise;
      cancel.push(path);
      return Promise.resolve({});
    }
  });
  controller.start('wpt', 'bulk-patch', {}, { destructive: true });
  controller.cancelDestructive('wpt');
  controller.start('wpt', 'bulk-patch', {}, { destructive: true });
  first.resolve({ jobId: 'first-fixture' });
  second.resolve({ jobId: 'second-fixture' });
  await new Promise(setImmediate);
  assert.deepEqual(cancel, ['/job/first-fixture/cancel']);
  assert.equal(controller.get('wpt/bulk-patch').cancelRequested, false);
});

test('seven C2C rules report scoped evidence without promoting unknowns', () => {
  const { Compliance } = components();
  assert.deepEqual(Array.from(Compliance.pages.slice(1), (p) => p.label),
    ['Defender', 'Vulnerabilities/AQC', 'Patching', 'Firewall', 'BitLocker', 'Tanium monitoring', 'PKI certificates']);
  const evidence = Compliance.evidence;
  assert.equal(evidence.signatures({ DefenderSignatureAgeHours: 168 }).tone, 'meets');
  assert.equal(evidence.signatures({ DefenderSignatureAgeHours: 168.01 }).tone, 'attention');
  assert.equal(evidence.signatures({ DefenderSignatureAgeHours: null }).tone, 'unknown');
  assert.equal(evidence.protection({ DefenderEnabled: true, DefenderRealTimeProtectionEnabled: false }).label, 'On');
  assert.equal(evidence.protection({ DefenderEnabled: false }).label, 'Off');
  assert.equal(evidence.defenderRule({ DefenderEnabled: true, DefenderSignatureAgeHours: 168 }).tone, 'meets');
  assert.equal(evidence.defenderRule({ DefenderEnabled: true }).tone, 'unknown');
  assert.equal(evidence.reporting({ MdeSenseRunning: true }).tone, 'unknown');
  assert.equal(evidence.intune({ LocalMdmEnrollmentEvidence: 'Present' }).tone, 'unknown');
  assert.equal(evidence.firefox({ FirefoxInstalled: true }).tone, 'attention');
  assert.equal(evidence.firefox({ FirefoxInstalled: false }).tone, 'unknown');
  assert.equal(evidence.summary('vulnerabilities', { Evidence: { FirefoxInstalled: true } }, false).label, 'Firefox detected');
  assert.equal(evidence.summary('vulnerabilities', null, true).label, 'Reported finding');
  assert.equal(evidence.summary('vulnerabilities', null, false).label, 'AQC unknown');
  assert.equal(evidence.findTarget('NODE', ['node.example.test']), 'node.example.test');
  assert.equal(evidence.findTarget('NODE', ['node.a.test', 'node.b.test']), null);
  assert.equal(evidence.findTarget('node.b.test', ['node.a.test']), null);
});

test('streamed offline rows drop stale pass evidence and terminal errors survive progress', async () => {
  const { Compliance } = components();
  const ui = Compliance({});
  ui.show('defender');
  ui.setTargets(['fixture-online', 'fixture-offline']);
  let handlers;
  ui.assess({ subscribe(h) { handlers = h; return () => {}; } }, ['fixture-online', 'fixture-offline']);
  const e = { DefenderEnabled: true, DefenderSignatureAgeHours: 12, ObservedAtUtc: '2026-11-11T12:00:00Z' };
  handlers.row({ Host: 'fixture-online', Status: 'CHECK ERRORS', Evidence: e });
  handlers.row({ Host: 'fixture-offline', Status: 'OFFLINE', Evidence: e });
  handlers.error();
  handlers.progress({ done: 2, total: 2 });
  handlers.active(false);
  await new Promise((resolve) => setTimeout(resolve, 10));
  const online = find(ui.el, (node) => node.text === 'fixture-online').parent;
  const offline = find(ui.el, (node) => node.text === 'fixture-offline').parent;
  assert.ok(find(online, (node) => node.text === 'On'));
  assert.equal(find(offline, (node) => node.text === 'On'), undefined);
  assert.ok(find(offline, (node) => node.text === 'Offline'));
  assert.ok(find(ui.el, (node) => node.text.startsWith('Assessment interrupted')));
  ui.dispose();
});
