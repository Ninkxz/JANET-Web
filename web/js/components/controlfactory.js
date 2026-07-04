/* ============================================================================
   ControlFactory  ->  Janet.ui
   Themed primitives every view + component builds from: flat buttons (gold / go
   / danger / cyan / ghost / striped CTA), mono inputs, labels, cards with the
   corner-bracket header, status dots and pills. No view styles a raw control by
   hand; they all come from here so the JANET look stays consistent.
   ========================================================================== */
(function () {
  'use strict';
  var Janet = window.Janet = window.Janet || {};
  function el(tag, cls, txt) { var e = document.createElement(tag); if (cls) e.className = cls; if (txt != null) e.textContent = txt; return e; }

  var VARIANT = { gold: 'j-btn-gold', go: 'j-btn-go', danger: 'j-btn-danger', cyan: 'j-btn-cyan', ghost: 'j-btn-ghost', plain: '' };

  function button(label, opts) {
    opts = opts || {};
    var b = el('button', 'j-btn' + (VARIANT[opts.variant] ? (' ' + VARIANT[opts.variant]) : ''), label);
    b.type = opts.type || 'button';
    if (opts.size === 'sm') b.classList.add('j-btn-sm');
    if (opts.title) b.title = opts.title;
    if (opts.onClick) b.onclick = opts.onClick;
    if (opts.disabled) b.disabled = true;
    return b;
  }
  function ghostButton(label, opts) { opts = opts || {}; opts.variant = 'ghost'; return button(label, opts); }
  function ctaButton(label, opts) {
    opts = opts || {};
    var b = el('button', 'j-btn-cta', label);
    b.type = opts.type || 'button';
    if (opts.title) b.title = opts.title;
    if (opts.onClick) b.onclick = opts.onClick;
    return b;
  }
  function input(opts) {
    opts = opts || {};
    var i = el('input', 'j-input');
    i.type = opts.type || 'text';
    if (opts.value != null) i.value = opts.value;
    if (opts.placeholder) i.placeholder = opts.placeholder;
    if (opts.title) i.title = opts.title;
    if (opts.mono === false) i.style.fontFamily = "var(--ui-r)";
    if (opts.onInput) i.addEventListener('input', opts.onInput);
    return i;
  }
  function textarea(opts) {
    opts = opts || {};
    var t = el('textarea', 'j-textarea');
    if (opts.value != null) t.value = opts.value;
    if (opts.placeholder) t.placeholder = opts.placeholder;
    if (opts.rows) t.rows = opts.rows;
    if (opts.title) t.title = opts.title;
    if (opts.onInput) t.addEventListener('input', opts.onInput);
    return t;
  }
  function number(opts) {
    opts = opts || {};
    var i = input({ type: 'number', value: opts.value, title: opts.title, onInput: opts.onInput });
    if (opts.min != null) i.min = opts.min;
    if (opts.max != null) i.max = opts.max;
    if (opts.step != null) i.step = opts.step;
    return i;
  }
  function select(opts) {
    opts = opts || {};
    var s = el('select', 'j-select');
    (opts.options || []).forEach(function (o) {
      var label = (typeof o === 'string') ? o : o.label;
      var value = (typeof o === 'string') ? o : o.value;
      var op = el('option', null, label); op.value = value; s.appendChild(op);
    });
    if (opts.value != null) s.value = opts.value;
    if (opts.title) s.title = opts.title;
    if (opts.onChange) s.addEventListener('change', opts.onChange);
    return s;
  }
  function checkbox(labelText, opts) {
    opts = opts || {};
    var lab = el('label'); lab.style.display = 'flex'; lab.style.alignItems = 'center'; lab.style.gap = '7px'; lab.style.cursor = 'pointer';
    lab.style.fontSize = '12.5px';
    var cb = el('input'); cb.type = 'checkbox'; if (opts.checked) cb.checked = true;
    if (opts.onChange) cb.addEventListener('change', opts.onChange);
    var span = el('span', null, labelText); if (opts.color) span.style.color = opts.color;
    lab.appendChild(cb); lab.appendChild(span);
    if (opts.title) lab.title = opts.title;
    lab._cb = cb;
    return lab;
  }
  function label(text) { return el('label', 'j-label', text); }
  function field(labelText, control, hint) {
    var f = el('div', 'j-field');
    if (labelText) f.appendChild(label(labelText));
    f.appendChild(control);
    if (hint) f.appendChild(el('div', 'muted', hint));
    return f;
  }
  function sectionHeader(text) { return el('div', 'j-section-h', text); }
  function eyebrow(text) { return el('div', 'j-eyebrow', text); }
  function card(opts) {
    opts = opts || {};
    var c = el('div', 'j-card');
    c.style.padding = 'var(--s4)';
    if (opts.title) { var h = sectionHeader(opts.title); h.style.marginBottom = 'var(--s3)'; c.appendChild(h); }
    return c;
  }
  function dot(state) { return el('span', 'j-dot' + (state ? (' j-dot-' + state) : '')); }
  function pill(text, cls) { var p = el('span', 'j-pill' + (cls ? (' ' + cls) : ''), text); return p; }
  // Titled card with an optional muted accent note - the helper every per-tool
  // view used to re-declare inline (beta/biosfirmware/pkginstall/secureboot).
  function namedCard(title, accentNote) {
    var box = card({});
    var h = el('div', 'j-section-h', title); h.style.marginBottom = '4px';
    box.insertBefore(h, box.firstChild);
    if (accentNote) { var n = el('div', 'muted', accentNote); n.style.fontSize = '11px'; n.style.marginBottom = '8px'; box.appendChild(n); }
    return box;
  }

  Janet.ui = {
    el: el, button: button, ghostButton: ghostButton, ctaButton: ctaButton,
    input: input, textarea: textarea, number: number, select: select, checkbox: checkbox,
    label: label, field: field, sectionHeader: sectionHeader, eyebrow: eyebrow,
    card: card, namedCard: namedCard, dot: dot, pill: pill
  };
})();
