/* ============================================================================
   ConfirmDialog / ArmingDialog  ->  Janet.components.ConfirmDialog / .ArmingDialog
   Themed modals that replace raw window.confirm/alert. Both return a Promise:
   resolve(true) on confirm, resolve(false) on cancel/Esc.

   ConfirmDialog(opts): { title, body, list?, okText, cancelText, danger? }
     - cancelText:null makes it a one-button notice (resolves true on OK/Back).
   ArmingDialog(opts): adds a danger banner, restates host count + consequence +
     dry-run state, an optional pre-flight checklist, and an optional typed-
     confirmation (confirmWord: must type e.g. "APPLY" to enable the go button).
   ========================================================================== */
(function () {
  'use strict';
  var Janet = window.Janet = window.Janet || {};
  Janet.components = Janet.components || {};
  var ui = function () { return Janet.ui; };
  var el = Janet.ui.el;

  function modal(build) {
    return new Promise(function (resolve) {
      var prevFocus = document.activeElement;
      var overlay = el('div', 'j-modal');
      var card = el('div', 'j-modal-card');
      overlay.appendChild(card);
      var done = false;
      function close(val) {
        if (done) return; done = true;
        document.removeEventListener('keydown', onKey, true);
        overlay.remove();
        try { if (prevFocus && prevFocus.focus) prevFocus.focus(); } catch (e) {}
        resolve(val);
      }
      function onKey(e) {
        if (e.key === 'Escape') { e.preventDefault(); close(false); }
      }
      build(card, close);
      document.body.appendChild(overlay);
      document.addEventListener('keydown', onKey, true);
      overlay.addEventListener('mousedown', function (e) { if (e.target === overlay) close(false); });
      card.setAttribute('role', 'dialog'); card.setAttribute('aria-modal', 'true');
      setTimeout(function () { var f = card.querySelector('button, input'); if (f) try { f.focus(); } catch (e) {} }, 0);
    });
  }

  function appendBody(card, opts) {
    if (opts.danger) card.classList.add('danger');
    if (opts.banner) { var ban = el('div', 'j-modal-banner', opts.banner); card.appendChild(ban); }
    var title = el('div', 'j-modal-title' + (opts.danger ? ' danger' : ''), opts.title || 'Confirm');
    card.appendChild(title);
    var body = el('div', 'j-modal-body');
    // audit#25: this is the app's ONLY raw-HTML sink. A string `body` is rendered via
    // innerHTML (legacy: ~40 callers pass esc()-interpolated HTML). Prefer a DOM node
    // (built with el()/textContent) OR the explicit `bodyHtml` field so any raw-HTML
    // usage is greppable. A NON-string, non-node `body` is coerced to text, not HTML.
    if (opts.bodyHtml != null) { var ph = el('div'); ph.innerHTML = String(opts.bodyHtml); body.appendChild(ph); }
    else if (opts.body != null) {
      if (typeof opts.body === 'string') { var p = el('div'); p.innerHTML = String(opts.body); body.appendChild(p); }
      else if (opts.body instanceof Node) { body.appendChild(opts.body); }
      else { body.textContent = String(opts.body); }
    }
    card.appendChild(body);
    if (opts.list && opts.list.length) {
      var list = el('div', 'j-modal-list');
      opts.list.forEach(function (line) { list.appendChild(el('div', null, String(line))); });
      card.appendChild(list);
    }
    return body;
  }

  // Optional target-preflight summary (ADDITIVE). Rendered ONLY when a caller
  // passes opts.preflight = { targets:<array|string>, actionLabel?:string }.
  // Advisory UI: it summarizes what a (usually destructive) wave will actually
  // touch - unique host count, plus how many duplicates/blank lines were dropped -
  // so the operator sees the real target set before clicking through. It does NOT
  // gate, weaken, or alter the confirm's ack/credential flow; the OK button and its
  // behavior are untouched. When opts.preflight is absent this is never called and
  // the dialog renders exactly as before. Numbers come from Janet.util.resolveTargets
  // (pure); labels use textContent (el()) so host names are never treated as HTML.
  function preflightBlock(opts) {
    var pf = opts.preflight || {};
    var u = (window.Janet && Janet.util) || {};
    var r = (typeof u.resolveTargets === 'function')
      ? u.resolveTargets(pf.targets)
      : { total: 0, unique: 0, duplicates: 0, blanks: 0, list: [] };
    var box = el('div', 'j-modal-preflight' + (opts.danger ? ' danger' : ''));
    var label = pf.actionLabel ? String(pf.actionLabel) : '';
    box.appendChild(el('div', 'j-modal-preflight-h',
      'PREFLIGHT' + (label ? ' · ' + label : '') + ' — ' + r.unique + ' unique host(s)'));
    if (r.duplicates > 0) box.appendChild(el('div', 'j-modal-preflight-sub', r.duplicates + ' duplicate(s) removed'));
    if (r.blanks > 0) box.appendChild(el('div', 'j-modal-preflight-sub', r.blanks + ' blank line(s) removed'));
    box.appendChild(el('div', 'j-modal-preflight-note', 'The dispatcher host is auto-excluded from destructive waves server-side.'));
    if (r.list.length) {
      var sample = el('div', 'j-modal-list');
      r.list.slice(0, 6).forEach(function (h) { sample.appendChild(el('div', null, String(h))); });
      if (r.list.length > 6) sample.appendChild(el('div', 'j-modal-preflight-more', '+ ' + (r.list.length - 6) + ' more'));
      box.appendChild(sample);
    }
    return box;
  }

  function ConfirmDialog(opts) {
    opts = opts || {};
    return modal(function (card, close) {
      appendBody(card, opts);
      if (opts.preflight) card.appendChild(preflightBlock(opts));   // additive: absent -> render path unchanged
      var acts = el('div', 'j-modal-actions');
      if (opts.cancelText !== null) {
        var cancel = ui().ghostButton(opts.cancelText || 'Cancel', { onClick: function () { close(false); } });
        acts.appendChild(cancel);
      }
      var ok = ui().button(opts.okText || 'OK', { variant: opts.danger ? 'danger' : 'go', onClick: function () { close(true); } });
      acts.appendChild(ok);
      card.appendChild(acts);
    });
  }

  function ArmingDialog(opts) {
    opts = opts || {};
    return modal(function (card, close) {
      var o = Object.assign({ danger: true, banner: opts.banner || 'IRREVERSIBLE / STATE-CHANGING OPERATION' }, opts);
      appendBody(card, o);

      // pre-flight checklist (elevation / restore-point / DSC-LCM / reboot-pending, etc.)
      if (opts.preflight && opts.preflight.length) {
        var pf = el('div', 'j-modal-list');
        opts.preflight.forEach(function (item) {
          var line = el('div');
          var okItem = item.ok !== false;
          // textContent (not innerHTML): preflight labels are plain data (counts,
          // the admin username, mode text), matching how opts.list renders via
          // el(). innerHTML here would mis-render a label containing & or < (e.g.
          // a future label that interpolates a remote app/host name).
          line.textContent = (okItem ? '[OK] ' : '[!] ') + String(item.label);
          line.className = okItem ? 'st-ok' : 'st-warn';
          pf.appendChild(line);
        });
        card.appendChild(pf);
      }

      var go;
      // typed confirmation (e.g. STIG "APPLY")
      if (opts.confirmWord) {
        var wrap = el('div', 'j-modal-confirm-input');
        wrap.appendChild(ui().label('Type ' + opts.confirmWord + ' to enable:'));
        var inp = ui().input({ placeholder: opts.confirmWord });
        inp.style.fontFamily = 'var(--mono)';
        inp.addEventListener('input', function () { go.disabled = (inp.value.trim() !== opts.confirmWord); });
        wrap.appendChild(inp);
        card.appendChild(wrap);
      }

      var acts = el('div', 'j-modal-actions');
      var cancel = ui().ghostButton(opts.cancelText || 'Cancel', { onClick: function () { close(false); } });
      acts.appendChild(cancel);
      go = ui().button(opts.okText || 'Arm and run', { variant: 'danger', onClick: function () { close(true); } });
      if (opts.confirmWord) go.disabled = true;
      acts.appendChild(go);
      card.appendChild(acts);
    });
  }

  Janet.components.ConfirmDialog = ConfirmDialog;
  Janet.components.ArmingDialog = ArmingDialog;
})();
