// tools/shared/crash-engine.js
// The crash parser's brain. Pure ESM, no dependencies, runs in the browser and in Node.
//
//   extract(inputs)                 → report   (everything we could pull out of the artifacts)
//   match(report, signatures)       → { candidates, best }
//   analyze(inputs, signatures, o)  → { report, finding }     one call does both and emits a v1 finding
//
// inputs: { dialog?: string, log?: string, crashometry?: object|string, dump?: DumpInfo, filename?: string }
// DumpInfo (from the minidump reader): { module, offset, exception, address, violation, build }
//
// Nothing here talks to the network. Redaction of evidence excerpts happens here, via redact.js,
// so a finding is safe to display or share the moment it exists.

import { redactText } from './redact.js';
import { signatureToHash, validateWords, hashMatchesSignature, crashDataKey, symbolicKey } from './crashhash.js';
import { errName, errFamily } from './err-codes.js';

export const ENGINE_VERSION = '0.2.0';
const DOCS_BASE = 'https://docs.blackstonescripts.com/';

// ---- Extraction -----------------------------------------------------------

const RE = {
  signature: /\b([A-Za-z0-9_.\-]+\.(?:exe|dll))\+(?:0x)?([0-9A-Fa-f]{3,8})\b/g,
  hash: /\b([a-z]{2,12})-([a-z]{2,12})-([a-z]{2,12})\b/g,
  hashLabelled: /(?:legacy\s+)?crash\s+hash:?\s*([a-z]{2,12}-[a-z]{2,12}-[a-z]{2,12})/i,
  exception: /\b0x(?:C0000005|C0000409|C00000FD|C0000094|80000003|80000004|E0000008|E06D7363|C0000374|C000001D)\b/i,
  exceptionAny: /\b0x[0-9A-Fa-f]{8}\b/,
  build: /\b(?:b|_b|build\s*)(\d{4})\b/i,
  gtaProcess: /^(?:(?:fivem|redm)_(?:b(\d{4})_)?gtaprocess\.exe|(?:gta5|rdr2|rdr3)_b(\d{4})\.exe)$/i,
  symbolSig: /\b([A-Za-z0-9_.\-]+\.(?:exe|dll))!([A-Za-z0-9_:]+)\s*\(0x([0-9A-Fa-f]{1,6})\)/,
  exitCode: /ExitCode\s*=\s*(\d+)/i,
  address: /(?:at address|address|at)\s+0x([0-9A-Fa-f]{8,16})\b/i,
  violation: /\b(read|write|execute)\b(?:\s+(?:at|of))?\s+(?:null|address|0x)/i,
  logBuild: /\[(?:RedM_)?b(\d{4})_(?:GTAProce|GTA|DumpServ|Dum)\]/,
  logRedM: /\[RedM_b\d{4}_|RedM_b\d{4}_GTAProcess|caused RedM to stop/,
  notable: /error|assert|pool full|pool space|fail|exception|crash|timed out|ExitCode|duplicate archetype|inflate|bad_alloc|physics validation|Invoking CRenderer INIT_CORE|SIGSEGV|Managed Stacktrace|heap limit|early-exit trap|bad tool|no streaming module|cf-error|RAGE error|Vulkan|game ownership|elevation helper|game type|SendNetPacket|connectOK|Obtained error from CPR|overflow|stopped responding|GTA V Enhanced|Enhanced edition|Reference hash|Disk hash|Resource name/i,
  // RAGE errors (gta-core-rdr3/src/ErrorHandler.cpp, built into FiveM too)
  rageNamed: /RAGE error:\s*(ERR_[A-Z0-9_]+|UNKNOWN)\b/,
  rageCodeless: /RAGE error:\s*0x([0-9A-Fa-f]{1,8}):(\d+)/,
  gameErrorAt: /A game error \(at ([0-9A-Fa-f]{8,16})\)/,
  // Error.cpp:296-311: a second error while handling the first. The ORIGINAL error is the real one.
  recursive: /Recursive(?:-recursive)? error:/,
  original: /Original error:\s*([\s\S]+)$/,
  // ResourceCacheDeviceV2.cpp:979, the inflate dialog's resource block
  refHash: /Reference hash:\s*([0-9a-f]{40})/i,
  diskHash: /Disk hash:\s*([0-9a-f]{40})/i,
  resourceName: /Resource name:\s*([^\r\n]+)/,
  // citizen-devtools ResourceTimeWarnings.cpp:197-216, the watchdog
  stoppedResponding: /has stopped responding\s*(?:\((NVIDIA drivers|script deadloop|DirectX query)\))?/i,
  dialogStart: /Process crash captured\. Crash dialog content:/,
  dialogEnd: /Crash report service returned|Error uploading crash|Process crash captured/,
  logPrefix: /^\[\s*\d+\]\s*\[[^\]]*\]\s*[^/]*\/\s?/,
};

function normModule(name) {
  if (!name) return null;
  const n = name.toLowerCase();
  const m = n.match(RE.gtaProcess);
  if (m) return { canon: 'gtaprocess', build: m[1] || m[2], platform: /redm|rdr[23]/.test(n) ? 'redm' : 'fivem' };
  if (n === 'fivem.exe') return { canon: 'gtaprocess', build: null, platform: 'fivem' };
  if (n === 'redm.exe') return { canon: 'gtaprocess', build: null, platform: 'redm' };
  return { canon: n, build: null, platform: /rdr3/.test(n) ? 'redm' : null };
}

function normHex(s) {
  if (!s) return null;
  return String(s).replace(/^0x/i, '').replace(/^0+(?=[0-9a-f])/i, '').toUpperCase();
}

function scanText(text, report, source) {
  if (!text) return;
  let m;
  RE.signature.lastIndex = 0;
  while ((m = RE.signature.exec(text))) {
    if (!report.module) {
      report.module = m[1];
      report.offset = normHex(m[2]);
      const nm = normModule(m[1]);
      report.module_canon = nm.canon;
      if (nm.build && !report.build) report.build = nm.build;
      if (nm.platform && !report.platform) report.platform = nm.platform;
      report.sources.module = source;
    }
  }
  const sy = text.match(RE.symbolSig);
  if (sy && !report.symbol) { report.symbol = sy[2]; report.symbol_offset = normHex(sy[3]); if (!report.module) { const nm = normModule(sy[1]); report.module = sy[1]; report.module_canon = nm.canon; if (nm.build && !report.build) report.build = nm.build; if (nm.platform) report.platform = nm.platform; } }
  const hl = text.match(RE.hashLabelled);
  if (hl && !report.hash) { report.hash = hl[1]; report.sources.hash = source; }
  if (!report.hash) {
    RE.hash.lastIndex = 0;
    while ((m = RE.hash.exec(text))) {
      const cand = m[0];
      // Only accept three words that are all in CitizenFX's crash word list (rejects CSS class names etc.).
      if (!validateWords(cand).ok) continue;
      report.hash = cand; report.sources.hash = source; break;
    }
  }
  const ex = text.match(RE.exception);
  if (ex && !report.exception) { report.exception = ex[0].toUpperCase().replace('0X', '0x'); report.sources.exception = source; }
  const b = text.match(RE.build);
  if (b && !report.build) report.build = b[1];
  const ec = text.match(RE.exitCode);
  if (ec && !report.exit_code) { report.exit_code = Number(ec[1]); report.sources.exit_code = source; }
  const ad = text.match(RE.address);
  if (ad && !report.address) report.address = '0x' + normHex(ad[1]);
  const vi = text.match(RE.violation);
  if (vi && !report.violation) report.violation = vi[1].toLowerCase();
  scanFacts(text, report, source);
}

/** Facts that need no family to be useful: RAGE error code, inflate hash pair, watchdog reason. */
function scanFacts(text, report, source) {
  const rn = text.match(RE.rageNamed);
  if (rn && !report.rage_text) { report.rage_text = rn[1]; report.sources.rage_text = source; }
  const rc = text.match(RE.rageCodeless);
  if (rc && !report.rage_codeless) report.rage_codeless = { file: '0x' + rc[1].toUpperCase(), line: Number(rc[2]) };
  const ga = text.match(RE.gameErrorAt);
  if (ga && !report.game_error_at) report.game_error_at = '0x' + normHex(ga[1]);
  const rh = text.match(RE.refHash), dh = text.match(RE.diskHash);
  if (rh && !report.inflate_ref) report.inflate_ref = rh[1].toLowerCase();
  if (dh && !report.inflate_disk) report.inflate_disk = dh[1].toLowerCase();
  const rs = text.match(RE.resourceName);
  if (rs && !report.inflate_resource) report.inflate_resource = rs[1].trim().slice(0, 80);
  const sr = text.match(RE.stoppedResponding);
  if (sr && !report.hang_reason) report.hang_reason = !sr[1] ? 'unknown' : /nvidia/i.test(sr[1]) ? 'nvidia' : /script/i.test(sr[1]) ? 'script' : 'directx';
}

/** Dialog text lines, searched by 'log' signals alongside the log's notable lines. */
function addDialogLines(text, report, source) {
  for (const line of String(text).split(/\r?\n/)) {
    const t = line.trim();
    if (t && !report.dialog_lines.some((d) => d.text === t)) report.dialog_lines.push({ n: source, text: t });
  }
}

/** "Recursive error: X / Original error: Y": Y is the real error; X is a side effect of crashing. */
function unwrapRecursive(text) {
  if (!text || !RE.recursive.test(text)) return null;
  const parts = text.split(/Original error:/);
  return parts.length > 1 ? parts[parts.length - 1].trim() : null;
}

/** The dialog the player saw, as CitizenFX logged it after the crash ("Process crash captured. Crash dialog content:"). */
function dialogFromLog(lines) {
  const i = lines.findIndex((l) => RE.dialogStart.test(l));
  if (i < 0) return null;
  const out = [];
  for (const l of lines.slice(i + 1, i + 20)) {
    if (RE.dialogEnd.test(l)) break;
    out.push(l.replace(RE.logPrefix, '').trimEnd());
  }
  const t = out.join('\n').trim();
  return t || null;
}

function scanLog(text, report) {
  if (!text) return;
  const lines = text.split(/\r?\n/);
  report.log_lines = lines.length;
  const lb = text.match(RE.logBuild);
  if (lb && !report.build) report.build = lb[1];
  if (!report.platform && RE.logRedM.test(text)) report.platform = 'redm';

  const notable = [];
  const counts = {};
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!RE.notable.test(line)) continue;
    notable.push({ n: i + 1, text: line.trim() });
    const lower = line.toLowerCase();
    for (const k of ['Duplicate archetype', 'Physics validation failed', 'Pool Full', 'ROSLauncher', 'inflate()', 'Timed out', 'Failed to load DLC', 'processed by a bad tool', 'no streaming module', 'SCRIPT ERROR', 'Error parsing script']) {
      if (lower.includes(k.toLowerCase())) counts[k] = (counts[k] || 0) + 1;
    }
  }
  report.notable = notable;
  report.log_counts = counts;
  for (let i = lines.length - 1; i >= Math.max(0, lines.length - 200); i--) {
    const ts = lines[i].match(/^\[\s*(\d{4,})\]/);
    if (ts) { report.session_ms = Number(ts[1]); break; }
  }
  report.log_tail = lines.slice(-80).map((l) => redactText(l).text);
  const dlg = dialogFromLog(lines);
  if (dlg) {
    report.dialog_from_log = redactText(dlg).text.slice(0, 2000);
    const orig = unwrapRecursive(dlg);
    if (orig && !report.original_error) { report.original_error = redactText(orig).text.slice(0, 300); scanText(orig, report, 'log_dialog'); }
    addDialogLines(dlg, report, 'log_dialog');
    scanText(dlg, report, 'log_dialog');
  }
  scanText(notable.map((l) => l.text).join('\n'), report, 'log');
}

function flattenJson(v, out = []) {
  if (v == null) return out;
  if (typeof v === 'object') { for (const k of Object.keys(v)) { out.push(String(k)); flattenJson(v[k], out); } return out; }
  out.push(String(v));
  return out;
}

function scanCrashometry(c, report) {
  if (!c) return;
  let obj = c;
  if (typeof c === 'string') { try { obj = JSON.parse(c); } catch { obj = { raw: c }; } }
  if (!obj || typeof obj !== 'object') return;
  report.crashometry_keys = Object.keys(obj).slice(0, 40);
  // Known keys (observed in real CfxCrashDump zips). crash_hash is "<module>+<offset>" with the canonical
  // module name (fivem.exe for the game process); crash_hash_key is the human-readable legacy hash.
  if (typeof obj.crash_hash === 'string' && !report.module) scanText(`sig ${obj.crash_hash}`, report, 'crashometry');
  if (typeof obj.crash_hash_key === 'string' && !report.hash) { report.hash = obj.crash_hash_key; report.sources.hash = 'crashometry'; }
  if (typeof obj.crashometry_pool_error === 'string') report.pool_error = obj.crashometry_pool_error;
  if (typeof obj.crashometry_gpu_name === 'string') report.gpu = obj.crashometry_gpu_name;
  if (typeof obj.crashometry_last_server_ver === 'string') report.server_ver = obj.crashometry_last_server_ver;
  if (obj.crashometry_onesync_enabled != null) report.onesync = String(obj.crashometry_onesync_enabled) === 'true';
  if (typeof obj.crashometry_gpu_id === 'string') report.gpu_id = obj.crashometry_gpu_id;
  // Only RedM (Vulkan) records the driver version (rage-graphics-rdr3 RenderHooks.cpp:230-239). FiveM never does.
  for (const [k, vendor] of [['crashometry_nvidia_driver', 'NVIDIA'], ['crashometry_intel_driver', 'Intel'], ['crashometry_driver', null]]) {
    if (typeof obj[k] === 'string' && !report.driver) report.driver = vendor ? `${vendor} ${obj[k]}` : obj[k];
  }
  if (typeof obj.crashometry_vulkan_api_version === 'string') report.vulkan_api = obj.crashometry_vulkan_api_version;
  if (typeof obj.crashometry_invalid_pool_size_increase_used === 'string') report.pool_validation_skipped = obj.crashometry_invalid_pool_size_increase_used;
  if (typeof obj.crashometry_init_function === 'string') report.init_function = obj.crashometry_init_function;
  // crashometry_last_server / _url identify the server (address). Deliberately not carried into the report.
  const rest = { ...obj }; delete rest.crashometry_last_server; delete rest.crashometry_last_server_url;
  scanText(flattenJson(rest).join('\n'), report, 'crashometry');
}

function applyDump(d, report) {
  if (!d) return;
  if (d.module) {
    report.module = d.module; report.offset = normHex(d.offset);
    const nm = normModule(d.module); report.module_canon = nm.canon;
    if (nm.build && !report.build) report.build = nm.build;
    if (nm.platform && !report.platform) report.platform = nm.platform;
    report.sources.module = 'minidump';
  }
  if (d.exception) report.exception = d.exception;
  if (d.address) report.address = '0x' + normHex(d.address);
  if (d.violation) report.violation = d.violation;
  if (d.build && !report.build) report.build = String(d.build);
  if (d.os) report.os = d.os;
  if (!report.platform && Array.isArray(d.modules) && d.modules.some((m) => /rdr3|redm/i.test(m.name || ''))) report.platform = 'redm';
  if (d.exception_name) report.exception_name = d.exception_name;
}

/** Pull every recognisable fact out of the artifacts. Order of authority: minidump > dialog > crashometry > log. */
export function extract(inputs = {}) {
  const report = {
    filename: inputs.filename || null,
    module: null, module_canon: null, offset: null, build: null, hash: null,
    exception: null, address: null, violation: null, exit_code: null,
    log_lines: 0, notable: [], log_counts: {}, log_tail: [], crashometry_keys: [],
    pool_error: null, gpu: null, server_ver: null, onesync: null, session_ms: null, os: null, exception_name: null,
    platform: null, symbol: null, symbol_offset: null,
    hash_derived: null, hash_id: null, hash_consistent: null, hash_valid: null,
    crashdata_key: null, symbolic_key: null, dialog_lines: [], dialog_from_log: null, original_error: null,
    write_class: null, rage: null, rage_family: null, rage_text: null, rage_codeless: null, game_error_at: null, five_byte_ok: null,
    inflate_ref: null, inflate_disk: null, inflate_resource: null, inflate_match: null, hang_reason: null,
    gpu_id: null, driver: null, vulkan_api: null, pool_validation_skipped: null, init_function: null,
    server_artifact: null,
    sources: {},
  };
  applyDump(inputs.dump, report);
  if (inputs.dialog) {
    const orig = unwrapRecursive(inputs.dialog);
    if (orig) { report.original_error = redactText(orig).text.slice(0, 300); scanText(orig, report, 'dialog'); }
    addDialogLines(inputs.dialog, report, 'dialog');
  }
  scanText(inputs.dialog, report, 'dialog');
  scanCrashometry(inputs.crashometry, report);
  scanLog(inputs.log, report);

  // Legacy hash is a pure function of the canonical signature, so derive or verify it.
  if (report.module && report.offset) {
    const h = signatureToHash(report.module, report.offset);
    report.hash_derived = h.words;
    report.hash_id = h.id;
    if (!report.hash) { report.hash = h.words; report.sources.hash = 'derived'; }
    else report.hash_consistent = hashMatchesSignature(report.hash, report.module, report.offset);
  }
  if (report.hash) report.hash_valid = validateWords(report.hash).ok;

  // The key CitizenFX's own crash-data.json is looked up by (see crashhash.js crashDataKey).
  if (report.module && report.offset) report.crashdata_key = crashDataKey(report.module, report.offset, report.build)?.words || null;
  const symText = [inputs.dialog, report.dialog_from_log].filter(Boolean).join('\n').match(RE.symbolSig);
  if (symText) report.symbolic_key = symbolicKey(symText[0]).words;

  if (report.inflate_ref && report.inflate_disk) report.inflate_match = report.inflate_ref === report.inflate_disk;
  const av = String(report.server_ver || '').match(/v1\.0\.0\.(\d+)/);
  if (av) report.server_artifact = Number(av[1]);
  classifyWrite(report);
  return report;
}

/**
 * What the crash wrote to, which says what kind of stop it was (verified on real dumps, 2026-11-13):
 *   0x10_<id>  RAGE error: the low 32 bits are the ERR code id (ErrorHandler.cpp:94-118). id 0 = "UNKNOWN".
 *   0xDEED     CitizenFX fatal error (Error.h ERROR_CRASH_MAGIC): classify by the error TEXT, not the module.
 *   0x0        Same, from clients older than 2021-12-08 (FatalError wrote to 0 before commit 9a37a644c);
 *              only trusted when a code-less "RAGE error: 0xFILE:LINE" text backs it up.
 */
function classifyWrite(report) {
  if (report.violation === 'write' && report.address) {
    let a = null;
    try { a = BigInt(report.address); } catch { a = null; }
    if (a != null && (a >> 32n) === 0x10n) {
      const id = Number(a & 0xffffffffn);
      const name = errName(id);
      report.write_class = 'rage_marker';
      report.rage = { id: '0x' + id.toString(16).toUpperCase().padStart(8, '0'), name: name || null, family: errFamily(name), source: 'dump' };
    } else if (a === 0xDEEDn) report.write_class = 'cfx_fatal';
    else if (a === 0n && report.rage_codeless && report.module_canon !== 'gtaprocess') report.write_class = 'cfx_fatal_legacy';
  }
  if (!report.rage && report.rage_text) report.rage = { id: null, name: report.rage_text, family: errFamily(report.rage_text), source: 'text' };
  else if (report.rage && report.rage_text && report.rage.name && report.rage_text !== report.rage.name) report.rage.text_disagrees = report.rage_text;
  report.rage_family = report.rage?.family || null;
  // The dialog prints the return address; the faulting write is one 5-byte CALL before it.
  if (report.game_error_at && report.module_canon === 'gtaprocess' && report.offset) {
    try { report.five_byte_ok = BigInt(report.game_error_at) - 0x140000000n - 5n === BigInt('0x' + report.offset); } catch { /* leave null */ }
  }
}

// ---- Matching --------------------------------------------------------------

function signalHits(sig, report) {
  const hits = [];
  switch (sig.type) {
    case 'log': {
      const needle = sig.pattern.toLowerCase();
      // The dialog (pasted, or as CitizenFX logged it) counts as well as the log's own lines.
      const lines = [...report.notable, ...report.dialog_lines].filter((l) => l.text.toLowerCase().includes(needle));
      if (lines.length) {
        let w = sig.weight;
        if (sig.role === 'precursor' && lines.length > 5) w += 1;
        const ref = typeof lines[0].n === 'number' ? `log:${lines[0].n}` : lines[0].n;
        hits.push({ weight: w, kind: 'log_line', ref, excerpt: lines[0].text, count: lines.length, role: sig.role });
      }
      break;
    }
    case 'module': {
      const re = new RegExp(sig.pattern, 'i');
      if (report.module && (re.test(report.module) || re.test(report.module_canon || ''))) {
        hits.push({ weight: sig.weight, kind: 'crash_field', ref: 'module', excerpt: report.module, role: sig.role });
      }
      break;
    }
    case 'offset': {
      if (!report.offset) break;
      const modOk = sig.module === report.module_canon || (report.module && sig.module === report.module.toLowerCase());
      if (!modOk) break;
      const off = normHex(report.offset);
      if (report.build && sig.offsets[report.build] && normHex(sig.offsets[report.build]) === off) {
        hits.push({ weight: sig.weight, kind: 'crash_field', ref: 'offset', excerpt: `${report.module}+0x${off} (b${report.build})`, role: sig.role });
      } else if (!report.build && Object.values(sig.offsets).some((o) => normHex(o) === off)) {
        hits.push({ weight: Math.max(1, sig.weight - 1), kind: 'crash_field', ref: 'offset', excerpt: `${report.module}+0x${off} (build unknown)`, role: sig.role });
      }
      break;
    }
    case 'hash': {
      const mine = [report.hash, report.hash_derived].filter(Boolean).map((x) => x.toLowerCase());
      const hit = sig.values.find((v) => mine.includes(v.toLowerCase()));
      if (hit) hits.push({ weight: sig.weight, kind: 'crash_field', ref: 'hash', excerpt: hit, role: sig.role });
      break;
    }
    case 'crashdata_key': {
      // Official entries: the display-form key, or (hash-only input) the pasted legacy hash.
      const mine = [report.crashdata_key, report.symbolic_key, report.module ? null : report.hash].filter(Boolean).map((x) => x.toLowerCase());
      const hit = sig.values.find((v) => mine.includes(v.toLowerCase()));
      if (hit) hits.push({ weight: sig.weight, kind: 'crash_field', ref: 'crash_data_key', excerpt: hit, role: sig.role });
      break;
    }
    case 'exception':
      if (report.exception && sig.codes.map((c) => c.toUpperCase()).includes(report.exception.toUpperCase())) hits.push({ weight: sig.weight, kind: 'crash_field', ref: 'exception', excerpt: report.exception, role: sig.role });
      break;
    case 'exitcode':
      if (report.exit_code != null && sig.codes.includes(report.exit_code)) hits.push({ weight: sig.weight, kind: 'crash_field', ref: 'exit_code', excerpt: `ExitCode = ${report.exit_code}`, role: sig.role });
      break;
    case 'address':
      if (report.address && sig.values.some((v) => normHex(v) === normHex(report.address))) hits.push({ weight: sig.weight, kind: 'crash_field', ref: 'address', excerpt: report.address, role: sig.role });
      break;
    case 'crashometry': {
      const v = report[sig.field];
      if (v != null && v !== false && (!sig.pattern || String(v).toLowerCase().includes(sig.pattern.toLowerCase()))) {
        hits.push({ weight: sig.weight, kind: 'crash_field', ref: `crashometry.${sig.field}`, excerpt: String(v), role: sig.role });
      }
      break;
    }
    case 'os':
      if (report.os && new RegExp(sig.pattern, 'i').test(report.os)) hits.push({ weight: sig.weight, kind: 'crash_field', ref: 'os', excerpt: report.os, role: sig.role });
      break;
    case 'log_last': {
      // Pattern must be among the LAST `within` notable lines — i.e. the crash happened right after it.
      // Post-crash dump-server lines don't count as "before the crash".
      const tail = report.notable.filter((x) => !/\[\s*(?:\w+_)?Dump(?:Serv|Server)\s*\]/.test(x.text)).slice(-(sig.within || 3));
      const l = tail.find((x) => x.text.toLowerCase().includes(sig.pattern.toLowerCase()));
      if (l) hits.push({ weight: sig.weight, kind: 'log_line', ref: `log:${l.n}`, excerpt: l.text, role: sig.role });
      break;
    }
    case 'symbol_offset':
      if (report.symbol_offset && sig.values.map(normHex).includes(normHex(report.symbol_offset)) && (!sig.module || sig.module === report.module_canon)) {
        hits.push({ weight: sig.weight, kind: 'crash_field', ref: 'symbol', excerpt: `${report.symbol || '?'} (0x${report.symbol_offset})`, role: sig.role });
      }
      break;
    case 'log_count_min': {
      const c = report.log_counts[sig.key] || 0;
      if (c >= sig.min) hits.push({ weight: sig.weight, kind: 'metric', ref: `log_count:${sig.key}`, excerpt: `${c}× ${sig.key}`, role: sig.role });
      break;
    }
    case 'violation':
      if (report.violation === sig.value) hits.push({ weight: sig.weight, kind: 'crash_field', ref: 'violation', excerpt: `${report.violation} at ${report.address || '?'}`, role: sig.role });
      break;
    case 'trap_offset': {
      // Execute-violation at a tiny offset inside the game process = FiveM's deliberate trap, whatever the build.
      const off = report.offset ? parseInt(report.offset, 16) : NaN;
      if (report.module_canon === 'gtaprocess' && report.violation === 'execute' && off > 0 && off < 0x2000) {
        hits.push({ weight: sig.weight, kind: 'crash_field', ref: 'trap', excerpt: `execute at ${report.module}+0x${report.offset}`, role: sig.role });
      }
      break;
    }
    case 'write_class':
      if (report.write_class === sig.value) hits.push({ weight: sig.weight, kind: 'crash_field', ref: 'write_target', excerpt: `${report.violation} to ${report.address}${report.rage?.name ? ` (${report.rage.name})` : ''}`, role: sig.role });
      break;
    case 'platform':
      if (report.platform === sig.value) hits.push({ weight: sig.weight, kind: 'crash_field', ref: 'platform', excerpt: report.platform, role: sig.role });
      break;
    case 'session_max_min':
      if (report.session_ms != null && report.session_ms <= sig.value * 60000) hits.push({ weight: sig.weight, kind: 'metric', ref: 'session_min', excerpt: `${Math.round(report.session_ms / 60000)} min`, role: sig.role });
      break;
    default: break;
  }
  return hits;
}

export function match(report, signatures) {
  const th = signatures.thresholds || { high: 8, medium: 4 };
  const families = [...signatures.families];
  // Official CitizenFX crash-data.json entries become families on the fly (hash is the only signal, but it's authoritative).
  const known = signatures.official_hashes || {};
  // CitizenFX keys crash-data.json on the DISPLAYED signature (crashDataKey / symbolicKey), not the legacy hash.
  // A pasted legacy hash with no signature is still tried: for DLL crashes it IS the display key.
  const myHashes = [report.crashdata_key, report.symbolic_key].filter(Boolean);
  if (!report.module && report.hash) myHashes.push(report.hash);
  for (const h of [...new Set(myHashes.map((x) => x.toLowerCase()))]) {
    const k = known[h];
    if (!k) continue;
    families.push({
      id: `cfx_${h}`, family: `crash.cfx_known.${h.replace(/-/g, '_')}`, title: `Known to CitizenFX: ${h}`, authoritative: true,
      severity: k.severity || 'MEDIUM', owner: k.owner, owner_detail: k.owner_detail,
      cause: { headline: k.headline, detail: `CitizenFX's own crash dictionary says: "${k.text}"` },
      fix: { steps: k.steps, docs: 'crash/cfx-known' },
      signals: [{ type: 'crashdata_key', values: [h], weight: 8, role: 'definitive' }],
      sources: ['cfx:crash-data.json'],
    });
  }
  let candidates = families.map((fam) => {
    const hits = fam.signals.flatMap((s) => signalHits(s, report));
    const score = hits.reduce((s, h) => s + h.weight, 0);
    const definitive = hits.some((h) => h.role === 'definitive');
    let confidence = 'LOW';
    if (score >= th.high || (definitive && score >= th.medium)) confidence = 'HIGH';
    else if (score >= th.medium) confidence = 'MEDIUM';
    if (fam.require_definitive && !definitive) return { family: fam, hits, score: 0, definitive: false, confidence: 'LOW' };
    const rank = { LOW: 0, MEDIUM: 1, HIGH: 2 };
    if (fam.max_confidence && rank[confidence] > rank[fam.max_confidence]) confidence = fam.max_confidence;
    return { family: fam, hits, score, definitive, confidence };
  }).filter((c) => c.score > 0);

  // Suppression: a generic family steps aside when a specific one explains the same evidence.
  const strong = new Set(candidates.filter((c) => c.score >= th.medium).map((c) => c.family.id));
  candidates = candidates.filter((c) => !(c.family.suppressed_by || []).some((id) => strong.has(id)));

  // CitizenFX's own crash-data.json entry is keyed on this exact build+location: it outranks our generic families.
  candidates.sort((a, b) => (!!b.family.authoritative - !!a.family.authoritative) || b.score - a.score || (b.definitive - a.definitive));
  const best = candidates.length && candidates[0].score >= th.medium ? candidates[0] : null;
  return { candidates, best };
}

// ---- Finding assembly -------------------------------------------------------

function excerpt(s) { return redactText(String(s)).text.slice(0, 200); }

function locationOf(report) {
  const loc = {};
  if (report.module) loc.module = report.module;
  if (report.offset) loc.offset = '0x' + report.offset;
  if (report.build) loc.build = report.build;
  if (report.hash) loc.hash = report.hash;
  if (report.symbol) loc.event = `${report.symbol}+0x${report.symbol_offset}`;
  return Object.keys(loc).length ? loc : undefined;
}

function crashEvidence(report) {
  const ev = [];
  if (report.module) ev.push({ kind: 'crash_field', ref: 'signature', excerpt: `${report.module}+0x${report.offset || '?'}` });
  if (report.exception) ev.push({ kind: 'crash_field', ref: 'exception', excerpt: report.exception + (report.violation ? ` (${report.violation})` : '') });
  if (report.address) ev.push({ kind: 'crash_field', ref: 'address', excerpt: report.address });
  if (report.hash) ev.push({ kind: 'crash_field', ref: report.sources.hash === 'derived' ? 'hash (derived from signature)' : 'hash', excerpt: report.hash });
  if (report.hash_consistent === false) ev.push({ kind: 'crash_field', ref: 'hash_mismatch', excerpt: `pasted hash does not match signature; expected ${report.hash_derived}` });
  if (report.hash_valid === false) ev.push({ kind: 'crash_field', ref: 'hash_invalid', excerpt: 'one or more words are not in the crash word list (typo?)' });
  if (report.exit_code != null) ev.push({ kind: 'crash_field', ref: 'exit_code', excerpt: `ExitCode = ${report.exit_code}` });
  if (report.pool_error) ev.push({ kind: 'crash_field', ref: 'crashometry.pool_error', excerpt: report.pool_error });
  if (report.gpu) ev.push({ kind: 'crash_field', ref: 'gpu', excerpt: report.gpu });
  if (report.os) ev.push({ kind: 'crash_field', ref: 'os', excerpt: report.os });
  if (report.platform === 'redm') ev.push({ kind: 'crash_field', ref: 'platform', excerpt: 'RedM' });
  if (report.rage) ev.push({ kind: 'crash_field', ref: 'rage_error', excerpt: `${report.rage.name || 'code not in table'}${report.rage.id ? ` (${report.rage.id})` : ''}, from the ${report.rage.source === 'dump' ? 'dump write target' : 'error text'}` });
  if (report.rage_codeless) ev.push({ kind: 'crash_field', ref: 'rage_error', excerpt: `RAGE error ${report.rage_codeless.file}:${report.rage_codeless.line} (source-file hash and line; no error code)` });
  if (report.write_class === 'cfx_fatal' || report.write_class === 'cfx_fatal_legacy') ev.push({ kind: 'crash_field', ref: 'write_target', excerpt: `${report.address}: a deliberate CitizenFX stop after a fatal error; the error text is the cause, not the module` });
  if (report.five_byte_ok === false) ev.push({ kind: 'crash_field', ref: 'mismatch', excerpt: `dialog address ${report.game_error_at} does not match the dump's crash location; the files may be from different crashes` });
  if (report.original_error) ev.push({ kind: 'crash_field', ref: 'original_error', excerpt: `Recursive error; the original error was: ${report.original_error}` });
  if (report.inflate_match != null) ev.push({ kind: 'crash_field', ref: 'inflate_hashes', excerpt: report.inflate_match ? 'Reference hash = Disk hash: the file is bad on the server' : 'Reference hash != Disk hash: the player\'s downloaded copy is damaged' });
  if (report.inflate_resource) ev.push({ kind: 'crash_field', ref: 'resource', excerpt: report.inflate_resource });
  if (report.driver) ev.push({ kind: 'crash_field', ref: 'driver', excerpt: report.driver });
  if (report.pool_validation_skipped) ev.push({ kind: 'crash_field', ref: 'unsupported_setup', excerpt: `pool size validation skipped ('moo 31337'): ${report.pool_validation_skipped}` });
  return ev;
}

/** The server's artifact (crashometry last_server_ver) against the known-bad builds list in signatures.json. */
function artifactEvidence(report, signatures) {
  const n = report.server_artifact;
  if (!n) return [];
  const ev = [{ kind: 'crash_field', ref: 'server_artifact', excerpt: `server artifact ${n}` }];
  for (const k of signatures.known_bad_artifacts || []) {
    if (n >= k.from && (k.to == null || n <= k.to)) {
      ev.push({ kind: 'crash_field', ref: 'server_artifact_known_issue', excerpt: `artifact ${n} has a known issue: ${k.issue}${k.fixed_in ? ` (fixed in ${k.fixed_in})` : ' (not fixed yet)'}` });
    }
  }
  return ev;
}

/** A family can carry variants: when a report field has a given value, owner/cause/fix change (e.g. inflate hashes). */
function pickVariant(fam, report) {
  for (const v of fam.variants || []) {
    if (v.when && report[v.when.field] === v.when.equals) return v;
  }
  return null;
}

/** Full pipeline: artifacts in, v1 finding out. `now` is injectable for tests. */
export function analyze(inputs, signatures, { now = Date.now() } = {}) {
  const report = extract(inputs);
  const { candidates, best } = match(report, signatures);
  const producer = { tool: 'crash-parser', version: ENGINE_VERSION, module: `signatures@${signatures.version}` };
  const base = {
    schema: 1,
    producer,
    tenant: null,
    location: locationOf(report),
    privacy: { redacted: true, classes: ['A'] },
    contract_version: '1.0',
    detected_at: now,
    status: 'open',
  };

  if (!best) {
    const ev = [...crashEvidence(report), ...artifactEvidence(report, signatures)].map((e) => ({ ...e, excerpt: excerpt(e.excerpt) }));
    for (const l of report.notable.slice(-5)) ev.push({ kind: 'log_line', ref: `log:${l.n}`, excerpt: excerpt(l.text) });
    const where = report.module ? `${report.module}+0x${report.offset || '?'}` : (report.hash || 'no signature found');
    const finding = {
      ...base,
      key: `unknown.crash:${report.build || '?'}:${report.module || report.hash || '?'}+${report.offset || '?'}`,
      family: 'unknown.crash',
      severity: 'MEDIUM',
      confidence: 'LOW',
      summary: `No matching signature for ${where}`.slice(0, 160),
      cause: {
        headline: 'No matching signature',
        detail: 'The crash location and log lines were extracted, but no known family explains them yet.' +
          precursorNote(report) +
          ' Submitting it as an unknown case adds it to the research queue; it becomes a named family once a cause is confirmed.',
      },
      owner: 'nobody',
      owner_detail: 'Not yet known. Submit as an unknown case; if several players hit the same signature, tell the server owner.',
      fix: { steps: ['Use "Submit as unknown" so this signature can be researched.', 'Note the server, game build, and whether other players crashed at the same time.'], automated: false },
      evidence: ev.slice(0, 20),
      alternatives: candidates.slice(0, 3).map(alt),
      metrics: { score: candidates[0]?.score || 0, log_lines: report.log_lines, notable_lines: report.notable.length },
      count: 1,
    };
    return { report, finding, candidates };
  }

  const v = pickVariant(best.family, report);
  const fam = v ? {
    ...best.family,
    owner: v.owner || best.family.owner,
    owner_detail: v.owner_detail || best.family.owner_detail,
    cause: { headline: v.headline || best.family.cause.headline, detail: v.detail || best.family.cause.detail },
    fix: { ...best.family.fix, steps: v.steps || best.family.fix.steps },
  } : best.family;
  const P = (t) => platformize(t, report.platform);
  const evidence = [];
  for (const h of best.hits) evidence.push({ kind: h.kind, ref: h.ref, excerpt: excerpt(h.excerpt) });
  for (const e of [...crashEvidence(report), ...artifactEvidence(report, signatures)]) if (!evidence.some((x) => x.ref === e.ref && x.excerpt === excerpt(e.excerpt))) evidence.push({ ...e, excerpt: excerpt(e.excerpt) });

  const finding = {
    ...base,
    key: `${fam.family}:${report.build || '?'}:${report.module_canon || report.module || '?'}+${report.offset || '?'}`,
    family: fam.family,
    severity: fam.severity,
    confidence: best.confidence,
    summary: P(`${fam.title}: ${fam.cause.headline}`).slice(0, 160),
    cause: { headline: P(fam.cause.headline), detail: P(fam.cause.detail), refs: fam.fix?.docs ? [DOCS_BASE + fam.fix.docs] : undefined },
    owner: fam.owner,
    owner_detail: P(fam.owner_detail),
    fix: { steps: fam.fix.steps.slice(0, 10).map(P), automated: false, docs_url: fam.fix.docs ? DOCS_BASE + fam.fix.docs : undefined },
    evidence: evidence.slice(0, 20),
    alternatives: candidates.slice(1, 4).map(alt),
    metrics: {
      score: best.score,
      log_lines: report.log_lines,
      notable_lines: report.notable.length,
      ...(report.session_ms ? { session_min: Math.round(report.session_ms / 60000) } : {}),
      ...Object.fromEntries(Object.entries(report.log_counts).map(([k, v]) => [k.toLowerCase().replace(/[^a-z0-9]+/g, '_'), v])),
    },
    signature: { db_id: fam.id, version: Number(signatures.version.split('.')[1]) || 0, ...(v ? { variant: v.id } : {}) },
    count: 1,
  };
  return { report, finding, candidates };
}

function precursorNote(report) {
  const c = report.log_counts || {};
  const bits = [];
  if (c['Duplicate archetype']) bits.push(`${c['Duplicate archetype']} duplicate-archetype warnings`);
  if (c['Physics validation failed']) bits.push(`${c['Physics validation failed']} broken-collision warnings`);
  if (c['processed by a bad tool']) bits.push(`${c['processed by a bad tool']} "processed by a bad tool" warnings`);
  if (c['no streaming module']) bits.push(`${c['no streaming module']} non-streamable files in stream/`);
  if (c['SCRIPT ERROR']) bits.push(`${c['SCRIPT ERROR']} script errors`);
  return bits.length ? ` The log does show server-content problems (${bits.join(', ')}), which is where a server owner should look first.` : '';
}

// Family text is written for FiveM; RedM dumps get the RedM names in every human-facing string.
const REDM_WORDS = [[/\bFiveM\.app\b/g, 'RedM.app'], [/\bFiveM\b/g, 'RedM'], [/\bGTA V\b/g, 'RDR2'], [/\bGTA5\b/g, 'RDR2'], [/%localappdata%\\FiveM/g, '%localappdata%\\RedM']];
function platformize(text, platform) {
  if (platform !== 'redm' || typeof text !== 'string') return text;
  return REDM_WORDS.reduce((t, [re, to]) => t.replace(re, to), text);
}

function alt(c) {
  return { kind: c.family.id, detail: `${c.family.title} (score ${c.score})`, confidence: c.confidence, magnitude: c.score };
}