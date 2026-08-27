// test/crashhash.test.js — the legacy hash algorithm against three real crashometry files.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { joaat, signatureToHash, validateWords, hashMatchesSignature, WORDS } from '../tools/shared/crashhash.js';
import { analyze } from '../tools/shared/crash-engine.js';
const signatures = JSON.parse(await readFile(new URL('../tools/shared/signatures.json', import.meta.url), 'utf8'));

test('word list is exactly 256 words', () => assert.equal(WORDS.length, 256));

test('reproduces real crash_hash_id and crash_hash_key values', () => {
  assert.deepEqual(signatureToHash('fivem.exe', '64C24F'), { signature: 'fivem.exe+64C24F', id: 2816774214, words: 'fish-mockingbird-two' });
  assert.deepEqual(signatureToHash('gta-core-five.dll', '1B840'), { signature: 'gta-core-five.dll+1B840', id: 1069235659, words: 'snake-eleven-robin' });
  assert.deepEqual(signatureToHash('fivem.exe', '7252AB'), { signature: 'fivem.exe+7252AB', id: 3412107760, words: 'virginia-october-hydrogen' });
});

test('per-build module names canonicalise to fivem.exe before hashing', () => {
  assert.equal(signatureToHash('GTA5_b3258.exe', '7252AB').words, 'virginia-october-hydrogen');
  assert.equal(signatureToHash('FiveM_b3095_GTAProcess.exe', '0x64C24F').words, 'fish-mockingbird-two');
  assert.equal(joaat('FIVEM.EXE+64c24f'), joaat('fivem.exe+64C24F'));
});

test('validateWords catches typos', () => {
  assert.equal(validateWords('fish-mockingbird-two').ok, true);
  assert.deepEqual(validateWords('fish-mockingbrid-two').bad, ['mockingbrid']);
  assert.equal(hashMatchesSignature('snake-eleven-robin', 'gta-core-five.dll', '1B840'), true);
  assert.equal(hashMatchesSignature('fish-mockingbird-two', 'gta-core-five.dll', '1B840'), false);
});

test('engine derives the hash from a dump with no dialog, and matches hash-only families', () => {
  const { report, finding } = analyze({ dump: { module: 'FiveM_b3258_GTAProcess.exe', offset: '7252AB', exception: '0xC0000005' } }, signatures, { now: 1 });
  assert.equal(report.hash, 'virginia-october-hydrogen');
  assert.equal(report.sources.hash, 'derived');
  assert.equal(finding.family, 'crash.ped_spawn_components');
});

test('a pasted hash that disagrees with the signature is flagged as evidence', () => {
  const { finding } = analyze({ dialog: 'Crash signature: gta-core-five.dll+1B840\nLegacy crash hash: fish-mockingbird-two' }, signatures, { now: 1 });
  assert.ok(finding.evidence.some((e) => e.ref === 'hash_mismatch'));
});

test('an official CitizenFX hash becomes a cfx_known family with the official text as cause', () => {
  const { finding } = analyze({ dialog: 'Legacy crash hash: sweet-sad-july' }, signatures, { now: 1 });
  assert.equal(finding.family, 'crash.cfx_known.sweet_sad_july');
  assert.equal(finding.owner, 'script_developer');
  assert.equal(finding.confidence, 'HIGH');
  assert.ok(finding.cause.detail.includes('invalid TXD reference'));
});

test('RedM hashes canonicalise the game process to redm.exe (verified: king-mountain-alaska)', () => {
  assert.equal(signatureToHash('RedM_b1491_GTAProcess.exe', '8006460').words, 'king-mountain-alaska');
  assert.equal(signatureToHash('RDR2_b1491.exe', '8006460').words, 'king-mountain-alaska');
  assert.equal(signatureToHash('redm.exe', '8006460').id, 2600703090);
});
