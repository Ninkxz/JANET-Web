/* ============================================================================
   ActivityLog  ->  Janet.components.ActivityLog
   Colour-coded streaming console: a mono near-black pane, one "[HH:mm:ss] msg"
   line per log event painted in a semantic colour (ok / err / warn / info-mode /
   gold banner / accent / dim diag), auto-tail, and a toolbar + right-click menu
   (Clear / Copy All / Save...). The pane node can be re-parented into a pop-out
   window (it keeps streaming because it is the same DOM).

   instance = ActivityLog({ toolbar:true, defaultName:'JANET_ActivityLog' })
     .el                      root element (toolbar + pane)
     .pane                    the scrolling line container (re-parentable)
     .append({text,level})    add one line
     .banner(text)            add a gold "=== text ===" banner line
     .clear() .copyAll() .save()
   ========================================================================== */
(function () {
  'use strict';
  var Janet = window.Janet = window.Janet || {};
  Janet.components = Janet.components || {};
  var el = Janet.ui.el;

  // engine 'error' level arrives as 'err' here; normalise a few aliases.
  function normLevel(level) {
    if (!level) return '';
    if (level === 'error') return 'err';
    return String(level);
  }

  function ActivityLog(opts) {
    opts = opts || {};
    var root = el('div', 'j-actlog');
    var pane = el('div', 'j-al-pane'); pane.setAttribute('role', 'log'); pane.setAttribute('aria-live', 'polite');
    var lines = [];   // {text, level}  (full in-memory history; Save/Copy export ALL of it)
    var MAX_DOM_LINES = 2000;   // cap LIVE DOM nodes (not `lines`) so a mass run does not grow unbounded DOM + reflow per line
    var peek = el('span', 'j-al-peek');                  // latest-line preview shown when the dock is collapsed
    var toggleBtn = el('span', 'j-al-toggle', '▸'); // right-chevron; flips to a down-chevron when expanded

    // the bottom log dock (.j-logdock) is a click-to-open drawer: a compact bar by
    // default that expands to the full scrollable pane when its header is clicked.
    // No-op when the log isn't inside a dock (a tabbed tool not yet converted, a pop-out).
    function dock() { return root.closest ? root.closest('.j-logdock') : null; }
    function isOpen() { var d = dock(); return !!(d && d.classList.contains('is-open')); }
    function setOpen(on) {
      var d = dock(); if (!d) return;
      d.classList.toggle('is-open', !!on);
      toggleBtn.textContent = on ? '▾' : '▸';
      if (on) pane.scrollTop = pane.scrollHeight;
    }

    function append(l) {
      if (!l) return;
      var level = normLevel(l.level);
      lines.push({ text: l.text, level: level });
      var div = el('div', 'j-al-line' + (level ? (' ' + level) : ''));
      div.appendChild(el('span', 'j-al-ts', '[' + Janet.util.clockStr() + ']'));
      div.appendChild(document.createTextNode(' ' + String(l.text == null ? '' : l.text)));
      pane.appendChild(div);
      // Cap the live DOM only (the `lines` array keeps the full history for Save/Copy):
      // drop the oldest visible nodes past the cap so a several-thousand-host broadcast
      // does not accumulate unbounded DOM nodes with a reflow per line.
      while (pane.childNodes.length > MAX_DOM_LINES) { pane.removeChild(pane.firstChild); }
      pane.scrollTop = pane.scrollHeight;
      peek.textContent = String(l.text == null ? '' : l.text);   // live latest line for the collapsed bar
    }
    function banner(text) { append({ text: '=== ' + text + ' ===', level: 'banner' }); }
    function clear() { lines = []; pane.innerHTML = ''; peek.textContent = ''; }
    function copyAll() {
      var txt = lines.map(function (l) { return l.text; }).join('\n');
      if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(txt).catch(function () {});
    }
    function save() {
      var txt = lines.map(function (l) { return l.text; }).join('\r\n') + '\r\n';
      var name = (opts.defaultName || 'JANET_ActivityLog') + '_' + Janet.util.fileStamp() + '.log';
      Janet.util.downloadBlob(name, 'text/plain', txt);
    }

    // toolbar
    if (opts.toolbar !== false) {
      var tb = el('div', 'j-al-toolbar');
      // clickable header (chevron + title + latest-line peek) toggles the drawer open/closed
      var headWrap = el('div', 'j-al-head');
      var head = el('div', 'j-section-h', opts.title || 'Activity Log');
      headWrap.appendChild(toggleBtn); headWrap.appendChild(head); headWrap.appendChild(peek);
      headWrap.title = 'Show / hide the activity log';
      tb.appendChild(headWrap);
      tb.appendChild(Janet.ui.ghostButton('Clear', { size: 'sm', onClick: clear, title: 'Clear the activity log.' }));
      tb.appendChild(Janet.ui.ghostButton('Copy All', { size: 'sm', onClick: copyAll, title: 'Copy the whole log to the clipboard.' }));
      tb.appendChild(Janet.ui.ghostButton('Save...', { size: 'sm', onClick: save, title: 'Save the log as a .log file.' }));
      // clicking anywhere on the bar toggles the drawer (except the Clear/Copy/Save buttons)
      tb.addEventListener('click', function (e) { if (e.target.closest && e.target.closest('.j-btn')) return; setOpen(!isOpen()); });
      root.appendChild(tb);
    }
    root.appendChild(pane);

    // right-click context menu
    pane.addEventListener('contextmenu', function (e) {
      e.preventDefault();
      var menu = el('div'); menu.style.cssText = 'position:fixed;z-index:80;background:var(--panel);border:1px solid var(--edge2);border-radius:4px;padding:4px;font-size:12px;box-shadow:0 6px 18px rgba(0,0,0,.5)';
      menu.style.left = e.clientX + 'px'; menu.style.top = e.clientY + 'px';
      [['Clear', clear, 'warn'], ['Copy All', copyAll, 'accent'], ['Save...', save, '']].forEach(function (item) {
        var b = Janet.ui.ghostButton(item[0], { size: 'sm', onClick: function () { item[1](); menu.remove(); } });
        b.style.display = 'block'; b.style.width = '100%'; b.style.textAlign = 'left'; b.style.border = '0';
        if (item[2] === 'warn') b.style.color = 'var(--warn)'; if (item[2] === 'accent') b.style.color = 'var(--accent-2)';
        menu.appendChild(b);
      });
      document.body.appendChild(menu);
      var off = function () { menu.remove(); document.removeEventListener('mousedown', off); };
      setTimeout(function () { document.addEventListener('mousedown', off); }, 0);
    });

    return { el: root, pane: pane, append: append, banner: banner, clear: clear, copyAll: copyAll, save: save, lines: function () { return lines.slice(); } };
  }

  Janet.components.ActivityLog = ActivityLog;
})();
