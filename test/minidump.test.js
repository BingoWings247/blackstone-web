// test/minidump.test.js — synthetic minidump so the reader is tested without shipping anyone's real dump.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readMinidump } from '../tools/shared/minidump.js';

function buildDump({ moduleName = 'FiveM_b3570_GTAProcess.exe', base = 0x140000000n, size = 0x2000000, code = 0xC0000005, crashOffset = 0x64C24Fn, write = true, addr = 0x10n }) {
  const enc = (s) => { const b = new Uint8Array(4 + s.length * 2); new DataView(b.buffer).setUint32(0, s.length * 2, true); for (let i = 0; i < s.length; i++) new DataView(b.buffer).setUint16(4 + i * 2, s.charCodeAt(i), true); return b; };
  const name = enc(moduleName);
  const HDR = 32, DIR = HDR, MODS = DIR + 3 * 12, NAME = MODS + 4 + 108, EXC = NAME + name.length, SYS = EXC + 8 + 152, END = SYS + 56;
  const buf = new ArrayBuffer(END); const dv = new DataView(buf); const u8 = new Uint8Array(buf);
  dv.setUint32(0, 0x504D444D, true); dv.setUint32(4, 0xA793, true); dv.setUint32(8, 3, true); dv.setUint32(12, DIR, true); dv.setUint32(20, 1756200000, true);
  const dir = (i, t, sz, rva) => { dv.setUint32(DIR + i * 12, t, true); dv.setUint32(DIR + i * 12 + 4, sz, true); dv.setUint32(DIR + i * 12 + 8, rva, true); };
  dir(0, 4, 4 + 108, MODS); dir(1, 6, 8 + 152, EXC); dir(2, 7, 56, SYS);
  dv.setUint32(MODS, 1, true); dv.setBigUint64(MODS + 4, base, true); dv.setUint32(MODS + 12, size, true); dv.setUint32(MODS + 24, NAME, true);
  u8.set(name, NAME);
  const r = EXC + 8; dv.setUint32(r, code, true); dv.setBigUint64(r + 16, base + crashOffset, true); dv.setUint32(r + 24, 2, true);
  dv.setBigUint64(r + 32, write ? 1n : 0n, true); dv.setBigUint64(r + 40, addr, true);
  dv.setUint16(SYS, 9, true); dv.setUint32(SYS + 8, 10, true); dv.setUint32(SYS + 12, 0, true); dv.setUint32(SYS + 16, 22631, true);
  return buf;
}

test('reads module, offset, exception, violation, address, build and OS from a minidump', () => {
  const r = readMinidump(buildDump({}));
  assert.equal(r.ok, true);
  assert.equal(r.module, 'FiveM_b3570_GTAProcess.exe');
  assert.equal(r.offset, '64C24F');
  assert.equal(r.exception, '0xC0000005');
  assert.equal(r.exception_name, 'ACCESS_VIOLATION');
  assert.equal(r.violation, 'write');
  assert.equal(r.address, '0x0000000000000010');
  assert.equal(r.build, '3570');
  assert.equal(r.os, 'Windows 11 (Build 22631)');
});

test('single-step exception has no violation/address', () => {
  const r = readMinidump(buildDump({ moduleName: 'gta-core-five.dll', base: 0x7FF800000000n, code: 0x80000004, crashOffset: 0x1B840n }));
  assert.equal(r.exception_name, 'SINGLE_STEP');
  assert.equal(r.module, 'gta-core-five.dll');
  assert.equal(r.offset, '1B840');
  assert.equal(r.violation, null);
});

test('rejects non-minidump input', () => {
  assert.equal(readMinidump(new ArrayBuffer(64)).ok, false);
});
