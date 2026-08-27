// tools/crash/app.js — page logic for the Crash Parser (kept external so the site's CSP can stay strict: script-src 'self')
import { analyze } from '../shared/crash-engine.js';
import { checkFinding } from '../shared/finding-check.js';
import { ingestFiles, mergeText } from '../shared/pipeline.js';
import { redactText } from '../shared/redact.js';

const $ = (id) => document.getElementById(id);
let signatures = null;
let pendingFiles = [];
let last = null;

async function loadSignatures() {
  const res = await fetch('../shared/signatures.json', { cache: 'no-cache' });
  signatures = await res.json();
  $('sigver').textContent = `v${signatures.version} · ${signatures.families.length} families`;
}
loadSignatures().catch(() => { $('sigver').textContent = 'failed to load'; });

const drop = $('drop');
drop.addEventListener('dragover', (e) => { e.preventDefault(); drop.classList.add('over'); });
drop.addEventListener('dragleave', () => drop.classList.remove('over'));
drop.addEventListener('drop', (e) => { e.preventDefault(); drop.classList.remove('over'); queue([...e.dataTransfer.files]); });
$('file').addEventListener('change', (e) => queue([...e.target.files]));
function queue(files) {
  pendingFiles = files;
  drop.querySelector('strong').textContent = files.map((f) => f.name).join(', ') || 'Drop CfxCrashDump_….zip here';
  $('status').textContent = `${files.length} file(s) ready`;
  if (files.length) run();               // dropping a crash file IS the request
}
// Pasted text analyzes on its own once typing stops.
let pasteTimer = null;
$('paste').addEventListener('input', () => { clearTimeout(pasteTimer); pasteTimer = setTimeout(() => { if ($('paste').value.trim().length > 20) run(); }, 700); });
$('paste').addEventListener('paste', () => { clearTimeout(pasteTimer); pasteTimer = setTimeout(run, 150); });

$('clear').addEventListener('click', () => {
  pendingFiles = []; $('paste').value = ''; $('file').value = ''; last = null;
  drop.querySelector('strong').textContent = 'Drop CfxCrashDump_….zip here';
  $('status').textContent = ''; $('notes').textContent = ''; $('result').classList.remove('show');
});

$('run').addEventListener('click', run);
let running = false;
async function run() {
  if (running) return;
  if (!signatures) { $('status').textContent = 'signature database still loading…'; setTimeout(run, 400); return; }
  running = true;
  try { await runInner(); } catch (e) { $('status').textContent = `error: ${e.message}`; console.error(e); } finally { running = false; }
}
async function runInner() {
  const inputs = {}; const notes = [];
  $('status').textContent = 'reading…';
  try {
    if (pendingFiles.length) await ingestFiles(pendingFiles, inputs, notes);
    if ($('paste').value.trim()) mergeText($('paste').value, inputs, notes);
  } catch (e) { notes.push(`error: ${e.message}`); }
  $('notes').textContent = notes.join('\n');
  if (!inputs.dump && !inputs.log && !inputs.dialog && !inputs.crashometry) { $('status').textContent = 'nothing to analyze yet'; return; }
  const { report, finding } = analyze(inputs, signatures);
  const chk = checkFinding(finding);
  if (!chk.ok) { $('status').textContent = `finding rejected by privacy gate: ${chk.error.field} (${chk.error.detail})`; return; }
  last = { report, finding };
  render(report, finding);
  $('status').textContent = 'done';
}

const OWNER_LABEL = { player: 'The player', server_owner: 'The server owner', script_developer: 'The script author', platform: 'FiveM / Rockstar', nobody: 'Not yet known' };

function render(report, f) {
  $('badges').innerHTML = '';
  for (const [cls, txt] of [[f.severity, `severity ${f.severity}`], ['conf', `confidence ${f.confidence}`], ['', f.family]]) {
    const b = document.createElement('span'); b.className = `badge ${cls}`; b.textContent = txt; $('badges').appendChild(b);
  }
  $('title').textContent = f.cause.headline;
  $('why').textContent = f.cause.detail || f.summary;
  $('ownerName').textContent = OWNER_LABEL[f.owner] || f.owner;
  $('ownerDetail').textContent = f.owner_detail || '';
  $('fix').innerHTML = ''; for (const s of f.fix?.steps || []) { const li = document.createElement('li'); li.textContent = s; $('fix').appendChild(li); }
  $('alts').textContent = f.alternatives?.length ? 'Also considered: ' + f.alternatives.map((a) => `${a.detail}`).join(' · ') : '';

  const dl = (el, rows) => { el.innerHTML = ''; for (const [k, v] of rows) { if (v == null || v === '') continue; const dt = document.createElement('dt'); dt.textContent = k; const dd = document.createElement('dd'); dd.textContent = v; el.append(dt, dd); } };
  dl($('crash'), [
    ['signature', report.module ? `${report.module}+0x${report.offset || '?'}` : null],
    ['hash', report.hash], ['build', report.build ? `b${report.build}` : null],
    ['exception', report.exception ? `${report.exception}${report.exception_name ? ' ' + report.exception_name : ''}` : null],
    ['violation', report.violation], ['address', report.address], ['exit code', report.exit_code],
    ['pool', report.pool_error], ['session', report.session_ms ? `${Math.round(report.session_ms / 60000)} min` : null],
  ]);
  dl($('system'), [['OS', report.os], ['GPU', report.gpu], ['server build', report.server_ver], ['OneSync', report.onesync == null ? null : String(report.onesync)], ['file', report.filename]]);
  $('evidence').innerHTML = '';
  for (const e of f.evidence) { const li = document.createElement('li'); li.innerHTML = `<span></span> <em></em>`; li.querySelector('span').textContent = e.excerpt || ''; li.querySelector('em').textContent = e.ref; $('evidence').appendChild(li); }
  $('tail').textContent = report.log_tail.join('\n'); $('tailWrap').style.display = report.log_tail.length ? '' : 'none';
  $('json').textContent = JSON.stringify(f, null, 2);
  $('result').classList.add('show');
  $('result').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function reportText(f, r) {
  return [
    `Crash Parser — blackstonescripts.com/tools/crash`,
    `${f.family} · severity ${f.severity} · confidence ${f.confidence}`,
    `Cause: ${f.cause.headline}`,
    `Who fixes it: ${OWNER_LABEL[f.owner] || f.owner} — ${f.owner_detail || ''}`,
    r.module ? `Signature: ${r.module}+0x${r.offset || '?'}${r.build ? ` (b${r.build})` : ''}` : null,
    r.hash ? `Hash: ${r.hash}` : null,
    r.exception ? `Exception: ${r.exception}${r.violation ? ` (${r.violation})` : ''}` : null,
    'Steps:', ...(f.fix?.steps || []).map((s, i) => `  ${i + 1}. ${s}`),
  ].filter(Boolean).join('\n');
}
$('copy').addEventListener('click', async () => { if (!last) return; await navigator.clipboard.writeText(redactText(reportText(last.finding, last.report)).text); $('status').textContent = 'copied'; });
$('download').addEventListener('click', () => {
  if (!last) return;
  const blob = new Blob([JSON.stringify(last.finding, null, 2)], { type: 'application/json' });
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `finding-${last.finding.family}.json`; a.click();
});
