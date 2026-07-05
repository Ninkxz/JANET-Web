/* ============================================================================
   xlsx.js  ->  Janet.util.buildXlsx / Janet.util.downloadXlsx
   A tiny, dependency-FREE OOXML .xlsx writer (pure JS, STORED-zip + inlineStr
   cells), so JANET Web matches the desktop tools' pure-.NET XLSX exports with
   no third-party software and no build step. Shared kit util - the Remote
   Message tool (Sent / Failed / All) is the first caller; ACAS/WPT/Reports reuse it.

   Janet.util.buildXlsx(headers, rows, sheetName) -> Uint8Array  (a valid .xlsx)
   Janet.util.downloadXlsx(filename, headers, rows, sheetName)   (Blob download)
     headers: ['Col', ...]   rows: [[cell, cell, ...], ...]  (cells stringified)
   ========================================================================== */
(function () {
  'use strict';
  var Janet = window.Janet = window.Janet || {};
  Janet.util = Janet.util || {};

  // CRC32 (standard polynomial 0xEDB88320), table built once.
  var CRC_TABLE = (function () {
    var t = new Uint32Array(256);
    for (var n = 0; n < 256; n++) {
      var c = n;
      for (var k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
      t[n] = c >>> 0;
    }
    return t;
  })();
  function crc32(bytes) {
    var c = 0xFFFFFFFF;
    for (var i = 0; i < bytes.length; i++) c = CRC_TABLE[(c ^ bytes[i]) & 0xFF] ^ (c >>> 8);
    return (c ^ 0xFFFFFFFF) >>> 0;
  }
  var enc = new TextEncoder();
  function utf8(s) { return enc.encode(s); }
  function xmlEsc(s) {
    // Strip XML-1.0-invalid control chars first (all 0x00-0x1F except tab/LF/CR):
    // they cannot be represented in OOXML even as &#x..; refs, so a cell carrying
    // one (e.g. a remote command-output Detail/Diagnostic string) would otherwise
    // make Excel reject the whole .xlsx as corrupt. Then escape the XML specials.
    return String(s == null ? '' : s).replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '').replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' }[c];
    });
  }
  function colRef(i) { // 0 -> A, 25 -> Z, 26 -> AA
    var s = '';
    i = i + 1;
    while (i > 0) { var m = (i - 1) % 26; s = String.fromCharCode(65 + m) + s; i = Math.floor((i - 1) / 26); }
    return s;
  }

  // --- STORED (no-compression) zip writer -----------------------------------
  function zip(files) {
    // files: [{ name, data:Uint8Array }]
    var chunks = [], offset = 0, central = [];
    function u16(n) { return [n & 0xFF, (n >>> 8) & 0xFF]; }
    function u32(n) { return [n & 0xFF, (n >>> 8) & 0xFF, (n >>> 16) & 0xFF, (n >>> 24) & 0xFF]; }
    files.forEach(function (f) {
      var nameBytes = utf8(f.name);
      var crc = crc32(f.data);
      var local = [].concat(u32(0x04034b50), u16(20), u16(0), u16(0), u16(0), u16(0),
        u32(crc), u32(f.data.length), u32(f.data.length), u16(nameBytes.length), u16(0));
      chunks.push(new Uint8Array(local)); chunks.push(nameBytes); chunks.push(f.data);
      var localLen = local.length + nameBytes.length + f.data.length;
      central.push({ name: nameBytes, crc: crc, size: f.data.length, offset: offset });
      offset += localLen;
    });
    var cdStart = offset, cdChunks = [];
    central.forEach(function (c) {
      var hdr = [].concat(u32(0x02014b50), u16(20), u16(20), u16(0), u16(0), u16(0), u16(0),
        u32(c.crc), u32(c.size), u32(c.size), u16(c.name.length), u16(0), u16(0), u16(0), u16(0),
        u32(0), u32(c.offset));
      cdChunks.push(new Uint8Array(hdr)); cdChunks.push(c.name);
      offset += hdr.length + c.name.length;
    });
    var cdSize = offset - cdStart;
    var eocd = new Uint8Array([].concat(u32(0x06054b50), u16(0), u16(0),
      u16(central.length), u16(central.length), u32(cdSize), u32(cdStart), u16(0)));
    var all = chunks.concat(cdChunks); all.push(eocd);
    var total = all.reduce(function (a, b) { return a + b.length; }, 0);
    var out = new Uint8Array(total), p = 0;
    all.forEach(function (b) { out.set(b, p); p += b.length; });
    return out;
  }

  function buildXlsx(headers, rows, sheetName) {
    sheetName = (sheetName || 'Sheet1').slice(0, 31);
    var all = [headers].concat(rows || []);
    var sheetRows = all.map(function (r, ri) {
      var cells = (r || []).map(function (v, ci) {
        return '<c r="' + colRef(ci) + (ri + 1) + '" t="inlineStr"><is><t xml:space="preserve">' + xmlEsc(v) + '</t></is></c>';
      }).join('');
      return '<row r="' + (ri + 1) + '">' + cells + '</row>';
    }).join('');
    var sheetXml = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
      + '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>'
      + sheetRows + '</sheetData></worksheet>';
    var workbook = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
      + '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
      + '<sheets><sheet name="' + xmlEsc(sheetName) + '" sheetId="1" r:id="rId1"/></sheets></workbook>';
    var wbRels = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
      + '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
      + '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>';
    var rootRels = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
      + '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
      + '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>';
    var contentTypes = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
      + '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
      + '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
      + '<Default Extension="xml" ContentType="application/xml"/>'
      + '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
      + '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>';
    return zip([
      { name: '[Content_Types].xml', data: utf8(contentTypes) },
      { name: '_rels/.rels', data: utf8(rootRels) },
      { name: 'xl/workbook.xml', data: utf8(workbook) },
      { name: 'xl/_rels/workbook.xml.rels', data: utf8(wbRels) },
      { name: 'xl/worksheets/sheet1.xml', data: utf8(sheetXml) }
    ]);
  }
  function downloadXlsx(filename, headers, rows, sheetName) {
    var bytes = buildXlsx(headers, rows, sheetName);
    Janet.util.downloadBlob(filename, 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', bytes);
  }
  Janet.util.buildXlsx = buildXlsx;
  Janet.util.downloadXlsx = downloadXlsx;
})();
