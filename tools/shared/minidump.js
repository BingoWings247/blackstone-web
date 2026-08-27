// tools/shared/minidump.js
// Minimal Windows minidump reader: enough to answer "which module, what offset, what exception".
// Works on an ArrayBuffer (browser File.arrayBuffer() or Node fs.readFileSync().buffer).
// Reads only: header, stream directory, ModuleListStream (4), ExceptionStream (6), SystemInfoStream (7).
// Never touches memory-region streams, so nothing from the process's memory is ever read or surfaced.
//
//   readMinidump(buffer) → {
//     ok, error?,
//     module, offset, base, exception, address, violation, build, os, arch,
//     modules: [{ name, base, size }] (basenames only),
//     timestamp
//   }

const STREAM = { MODULE_LIST: 4, EXCEPTION: 6, SYSTEM_INFO: 7 };
const EXC = {
  0xC0000005: 'ACCESS_VIOLATION', 0x80000003: 'BREAKPOINT', 0x80000004: 'SINGLE_STEP',
  0xC00000FD: 'STACK_OVERFLOW', 0xC0000094: 'INTEGER_DIVIDE_BY_ZERO', 0xC0000409: 'STACK_BUFFER_OVERRUN',
  0xE06D7363: 'CPP_EXCEPTION', 0xC0000374: 'HEAP_CORRUPTION', 0xC000001D: 'ILLEGAL_INSTRUCTION',
  0xE0000008: 'FIVEM_FATAL', 0x40000015: 'FATAL_APP_EXIT',
};

function u32(dv, o) { return dv.getUint32(o, true); }
function u64(dv, o) { return dv.getBigUint64(o, true); }
function hex(n, pad = 0) { return n.toString(16).toUpperCase().padStart(pad, '0'); }

function readString(dv, rva) {
  if (rva === 0 || rva + 4 > dv.byteLength) return '';
  const len = u32(dv, rva); // bytes, UTF-16LE
  if (rva + 4 + len > dv.byteLength) return '';
  const chars = new Uint16Array(len / 2);
  for (let i = 0; i < chars.length; i++) chars[i] = dv.getUint16(rva + 4 + i * 2, true);
  return String.fromCharCode(...chars);
}

function basename(p) { return p.split(/[\\/]/).pop(); }

export function readMinidump(buffer) {
  const dv = new DataView(buffer instanceof ArrayBuffer ? buffer : buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength));
  if (dv.byteLength < 32 || u32(dv, 0) !== 0x504D444D) return { ok: false, error: 'not_a_minidump' };

  const streamCount = u32(dv, 8);
  const dirRva = u32(dv, 12);
  const timestamp = u32(dv, 20) * 1000;
  const streams = {};
  for (let i = 0; i < streamCount; i++) {
    const e = dirRva + i * 12;
    if (e + 12 > dv.byteLength) break;
    streams[u32(dv, e)] = { size: u32(dv, e + 4), rva: u32(dv, e + 8) };
  }

  const out = { ok: true, timestamp, modules: [], module: null, offset: null, base: null, exception: null, exception_name: null, address: null, violation: null, build: null, os: null, arch: null };

  // ---- Modules ----------------------------------------------------------
  const ml = streams[STREAM.MODULE_LIST];
  if (ml) {
    const n = u32(dv, ml.rva);
    for (let i = 0; i < n; i++) {
      const m = ml.rva + 4 + i * 108;
      if (m + 108 > dv.byteLength) break;
      const base = u64(dv, m);
      const size = u32(dv, m + 8);
      const name = basename(readString(dv, u32(dv, m + 20)));
      out.modules.push({ name, base, size });
      const b = name.match(/^(?:FiveM_b(\d{4})_GTAProcess\.exe|GTA5_b(\d{4})\.exe)$/i);
      if (b) out.build = b[1] || b[2];
    }
  }

  // ---- System info --------------------------------------------------------
  const si = streams[STREAM.SYSTEM_INFO];
  if (si) {
    const archId = dv.getUint16(si.rva, true);
    out.arch = archId === 9 ? 'x64' : archId === 0 ? 'x86' : archId === 12 ? 'arm64' : `arch_${archId}`;
    const major = u32(dv, si.rva + 8), minor = u32(dv, si.rva + 12), buildNo = u32(dv, si.rva + 16);
    out.os = `Windows ${major}.${minor} (Build ${buildNo})`;
    if (major === 10 && buildNo >= 22000) out.os = `Windows 11 (Build ${buildNo})`;
    else if (major === 10) out.os = `Windows 10 (Build ${buildNo})`;
  }

  // ---- Exception ----------------------------------------------------------
  const ex = streams[STREAM.EXCEPTION];
  if (ex) {
    const r = ex.rva + 8; // skip ThreadId + alignment
    const code = u32(dv, r);
    const addr = u64(dv, r + 16);
    const nparams = u32(dv, r + 24);
    out.exception = '0x' + hex(code, 8);
    out.exception_name = EXC[code] || null;
    const crashAddr = addr;
    if (code === 0xC0000005 && nparams >= 2) {
      const kind = Number(u64(dv, r + 32));
      out.violation = kind === 1 ? 'write' : kind === 8 ? 'execute' : 'read';
      out.address = '0x' + hex(u64(dv, r + 40), 16);
    }
    // Which module owns the faulting instruction?
    for (const m of out.modules) {
      if (crashAddr >= m.base && crashAddr < m.base + BigInt(m.size)) {
        out.module = m.name;
        out.base = '0x' + hex(m.base, 16);
        out.offset = hex(crashAddr - m.base);
        break;
      }
    }
    if (!out.module) out.offset = hex(crashAddr);
  }

  return out;
}
