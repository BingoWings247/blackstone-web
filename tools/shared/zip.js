// tools/shared/zip.js
// Minimal ZIP reader for the browser: lists entries and extracts one at a time.
// Supports method 0 (stored) and 8 (deflate) via DecompressionStream('deflate-raw').
// Bounded: refuses entries whose declared size exceeds `maxEntryBytes` (zip-bomb guard).
//
//   const z = await openZip(arrayBuffer);   → { entries: [{ name, size, method }], read(name) → Uint8Array }

const EOCD = 0x06054b50, CDFH = 0x02014b50, LFH = 0x04034b50;

export async function openZip(buffer, { maxEntryBytes = 64 * 1024 * 1024, maxEntries = 200 } = {}) {
  const dv = new DataView(buffer);
  const u8 = new Uint8Array(buffer);
  // Find end-of-central-directory (scan back at most 64K + 22 bytes)
  let eocd = -1;
  for (let i = dv.byteLength - 22; i >= Math.max(0, dv.byteLength - 65557); i--) {
    if (dv.getUint32(i, true) === EOCD) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error('not_a_zip');
  const count = dv.getUint16(eocd + 10, true);
  let cd = dv.getUint32(eocd + 16, true);
  if (count > maxEntries) throw new Error('too_many_entries');

  const entries = [];
  for (let i = 0; i < count; i++) {
    if (dv.getUint32(cd, true) !== CDFH) throw new Error('bad_central_directory');
    const method = dv.getUint16(cd + 10, true);
    const csize = dv.getUint32(cd + 20, true);
    const usize = dv.getUint32(cd + 24, true);
    const nlen = dv.getUint16(cd + 28, true), elen = dv.getUint16(cd + 30, true), clen = dv.getUint16(cd + 32, true);
    const lho = dv.getUint32(cd + 42, true);
    const name = new TextDecoder().decode(u8.subarray(cd + 46, cd + 46 + nlen));
    entries.push({ name, size: usize, csize, method, lho });
    cd += 46 + nlen + elen + clen;
  }

  async function read(name) {
    const e = entries.find((x) => x.name === name);
    if (!e) throw new Error('no_such_entry');
    if (e.size > maxEntryBytes) throw new Error('entry_too_large');
    if (dv.getUint32(e.lho, true) !== LFH) throw new Error('bad_local_header');
    const nlen = dv.getUint16(e.lho + 26, true), elen = dv.getUint16(e.lho + 28, true);
    const start = e.lho + 30 + nlen + elen;
    const raw = u8.subarray(start, start + e.csize);
    if (e.method === 0) return raw.slice();
    if (e.method !== 8) throw new Error('unsupported_method');
    if (typeof DecompressionStream === 'undefined') throw new Error('no_decompression_stream');
    const ds = new DecompressionStream('deflate-raw');
    const out = new Response(new Blob([raw]).stream().pipeThrough(ds));
    const buf = new Uint8Array(await out.arrayBuffer());
    if (buf.length > maxEntryBytes) throw new Error('entry_too_large');
    return buf;
  }

  return { entries: entries.map(({ name, size, method }) => ({ name, size, method })), read };
}
