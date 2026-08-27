// tools/shared/pipeline.js
// Artifact intake: files and pasted text → { inputs, notes } for crash-engine.analyze().
// Browser-only for File objects, but the buffer/text functions also run in Node.

import { openZip } from './zip.js';
import { readMinidump } from './minidump.js';

const MAX_LOG_BYTES = 8 * 1024 * 1024;

function isLog(name) { return /citizenfx_log.*\.log$/i.test(name) || /\.log$/i.test(name); }

/** Classify pasted text: crash dialog, log lines, crashometry JSON, or a mix. */
export function classifyText(text) {
  const t = text.trim();
  if (!t) return 'empty';
  if (t.startsWith('{') && /crash_hash|crashometry_/.test(t)) return 'crashometry';
  if (/^\[\s*\d+\]\s*\[/m.test(t)) return 'log';
  if (/crash signature|legacy crash hash|caused FiveM to stop working/i.test(t)) return 'dialog';
  return 'text';
}

/** Add one artifact (by name + bytes) into `inputs`. Returns a note string for the UI. */
export async function ingestBuffer(name, buffer, inputs, notes = []) {
  const lower = name.toLowerCase();
  const u8 = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  const ab = u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength);

  // Minidump by magic, regardless of extension (misnamed .zip dumps exist)
  if (u8.length > 4 && new DataView(ab).getUint32(0, true) === 0x504D444D) {
    const d = readMinidump(ab);
    if (d.ok) { inputs.dump = d; notes.push(`${name}: minidump, ${d.modules.length} modules, ${d.module || 'no faulting module'}+0x${d.offset || '?'}`); }
    else notes.push(`${name}: minidump unreadable (${d.error})`);
    return notes;
  }
  if (lower.endsWith('.zip') || (u8.length > 4 && u8[0] === 0x50 && u8[1] === 0x4b)) {
    let z;
    try { z = await openZip(ab); } catch (e) { notes.push(`${name}: not a readable zip (${e.message})`); return notes; }
    inputs.filename = inputs.filename || name;
    inputs.zip_entries = z.entries.map((e) => e.name);
    for (const e of z.entries) {
      const n = e.name.toLowerCase();
      if (n.endsWith('.dmp')) {
        const bytes = await z.read(e.name);
        await ingestBuffer(e.name, bytes, inputs, notes);
      } else if (n === 'crashometry.json') {
        inputs.crashometry = new TextDecoder().decode(await z.read(e.name));
        notes.push('crashometry.json: read');
      } else if (/^citizenfx_log.*\.log$/.test(n)) {
        if (e.size > MAX_LOG_BYTES) { notes.push(`${e.name}: skipped (>${MAX_LOG_BYTES / 1048576} MB)`); continue; }
        inputs.log = new TextDecoder().decode(await z.read(e.name));
        notes.push(`${e.name}: ${inputs.log.split('\n').length} lines`);
      }
      // launcher.log / socialclub*.log are deliberately not read: they add nothing to diagnosis and carry account details.
    }
    return notes;
  }
  if (lower === 'crashometry.json' || lower.endsWith('.json')) {
    inputs.crashometry = new TextDecoder().decode(ab);
    notes.push(`${name}: read`);
    return notes;
  }
  if (isLog(lower) || lower.endsWith('.txt')) {
    if (u8.length > MAX_LOG_BYTES) { notes.push(`${name}: too large`); return notes; }
    const text = new TextDecoder().decode(ab);
    mergeText(text, inputs, notes, name);
    return notes;
  }
  notes.push(`${name}: unrecognised file type, ignored`);
  return notes;
}

/** Route pasted text into the right input slot. */
export function mergeText(text, inputs, notes = [], label = 'pasted text') {
  const kind = classifyText(text);
  if (kind === 'crashometry') { inputs.crashometry = text; notes.push(`${label}: crashometry`); }
  else if (kind === 'log') { inputs.log = inputs.log ? inputs.log + '\n' + text : text; notes.push(`${label}: log lines`); }
  else if (kind === 'dialog' || kind === 'text') { inputs.dialog = inputs.dialog ? inputs.dialog + '\n' + text : text; notes.push(`${label}: crash dialog`); }
  return notes;
}

/** Browser: File objects → inputs. */
export async function ingestFiles(files, inputs = {}, notes = []) {
  for (const f of files) {
    const buf = await f.arrayBuffer();
    await ingestBuffer(f.name, buf, inputs, notes);
  }
  return { inputs, notes };
}
