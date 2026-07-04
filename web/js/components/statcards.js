/* ============================================================================
   StatCards  ->  Janet.components.StatCards
   Big-number metric tiles recomputed live from run events (e.g. SENT / FAILED /
   TOTAL). Each tile = a coloured top accent + a mono number + an uppercase
   caption. Colours: ok | bad | gold | cyan | accent.

   instance = StatCards({ cards:[{key:'sent',label:'SENT',color:'ok',value:0}, ...] })
     .el                  the row element
     .set(key, value)     update one tile
     .setAll({sent:3,...}) update several
     .reset()             zero every tile
   ========================================================================== */
(function () {
  'use strict';
  var Janet = window.Janet = window.Janet || {};
  Janet.components = Janet.components || {};
  var el = Janet.ui.el;

  function StatCards(opts) {
    opts = opts || {};
    var row = el('div', 'j-stats');
    var nums = {};
    (opts.cards || []).forEach(function (c) {
      var tile = el('div', 'j-stat' + (c.color ? (' ' + c.color) : ''));
      var num = el('div', 'j-stat-num', String(c.value != null ? c.value : 0));
      tile.appendChild(num);
      tile.appendChild(el('div', 'j-stat-cap', c.label || c.key));
      row.appendChild(tile);
      nums[c.key] = num;
    });
    function set(key, value) { if (nums[key]) nums[key].textContent = String(value); }
    function setAll(obj) { Object.keys(obj || {}).forEach(function (k) { set(k, obj[k]); }); }
    function reset() { Object.keys(nums).forEach(function (k) { nums[k].textContent = '0'; }); }
    return { el: row, set: set, setAll: setAll, reset: reset };
  }
  Janet.components.StatCards = StatCards;
})();
