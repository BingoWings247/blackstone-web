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
import { signatureToHash, validateWords, hashMatchesSignature } from './crashhash.js';

export const ENGINE_VERSION = '0.1.0';
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
  notable: /error|assert|pool full|pool space|fail|exception|crash|timed out|ExitCode|duplicate archetype|inflate|bad_alloc|physics validation|Invoking CRenderer INIT_CORE|SIGSEGV|Managed Stacktrace|heap limit|early-exit trap|bad tool|no streaming module|cf-error|RAGE error|Vulkan|game ownership|elevation helper|game type|SendNetPacket|connectOK|Obtained error from CPR/i,
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
    sources: {},
  };
  applyDump(inputs.dump, report);
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
  return report;
}

// ---- Matching --------------------------------------------------------------

function signalHits(sig, report) {
  const hits = [];
  switch (sig.type) {
    case 'log': {
      const needle = sig.pattern.toLowerCase();
      const lines = report.notable.filter((l) => l.text.toLowerCase().includes(needle));
      if (lines.length) {
        let w = sig.weight;
        if (sig.role === 'precursor' && lines.length > 5) w += 1;
        hits.push({ weight: w, kind: 'log_line', ref: `log:${lines[0].n}`, excerpt: lines[0].text, count: lines.length, role: sig.role });
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
  const myHashes = [report.hash, report.hash_derived].filter(Boolean).map((x) => x.toLowerCase());
  for (const h of myHashes) {
    const k = known[h];
    if (!k) continue;
    families.push({
      id: `cfx_${h}`, family: `crash.cfx_known.${h.replace(/-/g, '_')}`, title: `Known to CitizenFX: ${h}`,
      severity: k.severity || 'MEDIUM', owner: k.owner, owner_detail: k.owner_detail,
      cause: { headline: k.headline, detail: `CitizenFX's own crash dictionary says: "${k.text}"` },
      fix: { steps: k.steps, docs: 'crash/cfx-known' },
      signals: [{ type: 'hash', values: [h], weight: 8, role: 'definitive' }],
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

  candidates.sort((a, b) => b.score - a.score || (b.definitive - a.definitive));
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
  return ev;
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
    const ev = crashEvidence(report).map((e) => ({ ...e, excerpt: excerpt(e.excerpt) }));
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

  const fam = best.family;
  const P = (t) => platformize(t, report.platform);
  const evidence = [];
  for (const h of best.hits) evidence.push({ kind: h.kind, ref: h.ref, excerpt: excerpt(h.excerpt) });
  for (const e of crashEvidence(report)) if (!evidence.some((x) => x.ref === e.ref)) evidence.push({ ...e, excerpt: excerpt(e.excerpt) });

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
    signature: { db_id: fam.id, version: Number(signatures.version.split('.')[1]) || 0 },
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