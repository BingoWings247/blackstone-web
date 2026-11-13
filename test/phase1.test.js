// test/phase1.test.js
// Parser phase 1: write-target classifier, ERR codes, crash-data.json key, and the new text rules.
// The marker fixtures are seven real forum dumps (redacted fields only), read on 2026-11-13.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { analyze, extract } from '../tools/shared/crash-engine.js';
import { checkFinding } from '../tools/shared/finding-check.js';
import { crashDataKey, signatureToHash, symbolicKey, joaat } from '../tools/shared/crashhash.js';
import { errName, ERR_NAMES, ERR_UI_STRINGS } from '../tools/shared/err-codes.js';

const signatures = JSON.parse(await readFile(new URL('../tools/shared/signatures.json', import.meta.url), 'utf8'));
const markers = JSON.parse(await readFile(new URL('./fixtures/marker-dumps.json', import.meta.url), 'utf8'));
const legacy = JSON.parse(await readFile(new URL('./fixtures/real-dumps.json', import.meta.url), 'utf8'));
const NOW = 1_763_000_000_000;
const fx = (name) => markers.find((f) => f.name === name);
const run = (inputs, sigs = signatures) => analyze(inputs, sigs, { now: NOW });

// ---- ERR code table ---------------------------------------------------------

test('ERR table: names hash to the ids seen in CitizenFX source and real dumps', () => {
  assert.equal(errName(0x15559348), 'ERR_GEN_ZLIB_2'); // UnkStuff.cpp
  assert.equal(errName(0xC6F4EC84), 'ERR_MEM_POOLALLOC_ALLOC_2'); // FiveM hook pattern B9 84 EC F4 C6
  assert.equal(errName(0x9CF7BD06), 'ERR_GFX_D3D_INIT'); // RenderHooks.cpp pattern B9 06 BD F7 9C
  assert.equal(errName(0), 'UNKNOWN');
  assert.equal(errName(0x12345678), null);
  assert.equal(ERR_NAMES.length, 220);
  assert.ok(!ERR_NAMES.some((n) => ERR_UI_STRINGS.includes(n)), 'dialog strings are kept out of the error list');
  assert.equal(new Set(ERR_NAMES.map(joaat)).size, ERR_NAMES.length, 'no two names share an id');
});

// ---- Write-target classifier, on the real marker dumps ----------------------

for (const [name, want] of [
  ['forum-2022-06-20-err-embeddedalloc', { family: 'crash.rage_error', write: 'rage_marker', err: 'ERR_MEM_EMBEDDEDALLOC_ALLOC', id: '0xBAFD530B' }],
  ['forum-2022-12-11-rage-unknown', { family: 'crash.rage_error', write: 'rage_marker', err: 'UNKNOWN', id: '0x00000000' }],
  ['forum-2022-03-19-rage-unknown', { family: 'crash.rage_error', write: 'rage_marker', err: 'UNKNOWN', id: '0x00000000' }],
  ['forum-2024-02-13-redm-err-gfx-state', { family: 'crash.rage_error', write: 'rage_marker', err: 'ERR_GFX_STATE', id: '0x40CDFD74', owner: 'player', variant: 'graphics' }],
  ['forum-2026-07-13-redm-vulkan-oom', { family: 'crash.redm_vulkan_device_memory', write: 'cfx_fatal', owner: 'player' }],
  ['forum-2023-05-27-redm-codeless-16634bf9', { family: 'crash.rage_error', write: 'cfx_fatal', codeless: '0x16634BF9:435' }],
  ['forum-2025-04-12-redm-codeless-4757f5b0', { family: 'crash.rage_error', write: 'cfx_fatal', codeless: '0x4757F5B0:436' }],
]) {
  test(`marker dump ${name} → ${want.family} (${want.write})`, () => {
    const { report, finding } = run(fx(name));
    assert.equal(finding.family, want.family);
    assert.equal(report.write_class, want.write);
    if (want.err) assert.equal(report.rage.name, want.err);
    if (want.id) assert.equal(report.rage.id, want.id);
    if (want.owner) assert.equal(finding.owner, want.owner);
    if (want.variant) assert.equal(finding.signature.variant, want.variant);
    if (want.codeless) assert.equal(`${report.rage_codeless.file}:${report.rage_codeless.line}`, want.codeless);
    assert.equal(checkFinding(finding).ok, true, JSON.stringify(checkFinding(finding).error));
  });
}

test('the dump alone is enough: no log, no crashometry, the write target still names the RAGE error', () => {
  const { report, finding } = run({ dump: fx('forum-2022-06-20-err-embeddedalloc').dump });
  assert.equal(finding.family, 'crash.rage_error');
  assert.equal(report.rage.source, 'dump');
  assert.ok(finding.evidence.some((e) => e.excerpt.includes('ERR_MEM_EMBEDDEDALLOC_ALLOC')));
});

test('dialog address minus 5 is the crash address on all four marker dumps; a mismatch is flagged', () => {
  for (const n of ['forum-2022-06-20-err-embeddedalloc', 'forum-2022-12-11-rage-unknown', 'forum-2022-03-19-rage-unknown', 'forum-2024-02-13-redm-err-gfx-state']) {
    assert.equal(extract(fx(n)).five_byte_ok, true, n);
  }
  const f = fx('forum-2022-06-20-err-embeddedalloc');
  const { finding } = run({ ...f, dump: { ...f.dump, offset: '12CE000' } });
  assert.ok(finding.evidence.some((e) => e.ref === 'mismatch'));
});

test('pre-Dec-2021 clients: a NULL write is a CFX fatal error only when a code-less RAGE text backs it', () => {
  const old = legacy.find((f) => f.name.startsWith('batch-8-'));
  assert.equal(extract(old).write_class, 'cfx_fatal_legacy');
  const plain = extract({ dump: { module: 'gta-core-five.dll', offset: '1234', address: '0x0', violation: 'write' } });
  assert.equal(plain.write_class, null);
});

// ---- crash-data.json key (CitizenFX's own lookup) ---------------------------

test('crashometry crash_hash_key is the LEGACY hash of crash_hash (6 real dumps)', () => {
  for (const f of markers.filter((m) => m.crashometry)) {
    const [mod, off] = f.crashometry.crash_hash.split('+');
    assert.equal(signatureToHash(mod, off).words, f.crashometry.crash_hash_key, f.name);
    assert.equal(signatureToHash(mod, off).id, f.crashometry.crash_hash_id, f.name);
  }
});

test('crash-data key: game crashes use the GTA5_b/RDR2_b display form, DLL crashes the legacy form', () => {
  assert.equal(crashDataKey('FiveM_b2545_GTAProcess.exe', '12CE418', '2545').signature, 'GTA5_b2545.exe+12CE418');
  assert.equal(crashDataKey('redm.exe', '2599AA3', '1491').signature, 'RDR2_b1491.exe+2599AA3');
  assert.equal(crashDataKey('fivem.exe', '12CE418', null), null, 'no build, no key');
  assert.equal(crashDataKey('glue.dll', '937C2').words, signatureToHash('glue.dll', '937C2').words);
  assert.equal(symbolicKey('RDR2_b1491.exe!sub_142599A9C (0x7)').signature, 'RDR2_b1491.exe!sub_142599A9C (0x7)');
});

test('official hashes match on the crash-data key, not on the legacy hash of a game crash', () => {
  const entry = { text: 'test entry', owner: 'player', owner_detail: 'x', headline: 'Test entry', steps: ['x'], severity: 'MEDIUM' };
  const f = fx('forum-2022-06-20-err-embeddedalloc');
  const byDisplay = { ...signatures, official_hashes: { 'east-georgia-skylark': entry } };
  assert.equal(run(f, byDisplay).finding.family, 'crash.cfx_known.east_georgia_skylark');
  const byLegacy = { ...signatures, official_hashes: { 'carpet-nevada-west': entry } };
  assert.notEqual(run(f, byLegacy).finding.family, 'crash.cfx_known.carpet_nevada_west');
});

// ---- Text rules ---------------------------------------------------------------

test('Recursive error: the ORIGINAL error decides the family', () => {
  const dialog = 'Recursive error: Something failed while handling the crash\nOriginal error: <<unknown pool>> Pool Full, Size == 200';
  const { report, finding } = run({ dialog });
  assert.equal(finding.family, 'crash.pool_full');
  assert.ok(report.original_error.includes('Pool Full'));
  assert.ok(finding.evidence.some((e) => e.ref === 'original_error'));
});

const inflateDialog = (ref, disk) => [
  'Failed to call inflate() for streaming file clothing_01.ydd. invalid distance too far back',
  'RSC version: 7', 'Resource name: eup-pack', `Reference hash: ${ref}`, `Disk hash: ${disk}`, 'File size: 12345',
].join('\n');
const H1 = 'a'.repeat(40), H2 = 'b'.repeat(40);

test('inflate: differing hashes = the player\'s cached copy; matching = the server file', () => {
  const mine = run({ dialog: inflateDialog(H1, H2) });
  assert.equal(mine.finding.family, 'crash.streaming_corrupt_asset');
  assert.equal(mine.finding.owner, 'player');
  assert.equal(mine.finding.signature.variant, 'player_cache');
  assert.ok(mine.finding.fix.steps.some((s) => s.includes('server-cache')));
  const theirs = run({ dialog: inflateDialog(H1, H1) });
  assert.equal(theirs.finding.owner, 'server_owner');
  assert.equal(theirs.finding.signature.variant, 'server_file');
  assert.ok(theirs.finding.evidence.some((e) => e.ref === 'resource' && e.excerpt === 'eup-pack'));
  const none = run({ dialog: 'Failed to call inflate() for streaming file x.ydd' });
  assert.equal(none.finding.owner, 'server_owner');
  assert.equal(none.finding.signature.variant, undefined);
});

test('server rate-limit drops name the server owner', () => {
  for (const msg of ['Reliable network event overflow.', 'Reliable state bag packet overflow.', 'Reliable server command overflow.', 'Reliable netGameEvent overflow.', 'Unreliable network event overflow.', 'latent event ACK overflow.']) {
    const { finding } = run({ dialog: msg });
    assert.equal(finding.family, 'drop.rate_limit', msg);
    assert.equal(finding.owner, 'server_owner');
    assert.equal(checkFinding(finding).ok, true);
  }
});

test('watchdog: the bracketed reason picks the owner', () => {
  const msg = (r) => `FiveM has stopped responding ${r}\nThe game stopped responding for too long and needs to be restarted.`;
  assert.equal(run({ dialog: msg('(script deadloop)') }).finding.owner, 'server_owner');
  assert.equal(run({ dialog: msg('(NVIDIA drivers)') }).finding.signature.variant, 'nvidia');
  assert.equal(run({ dialog: msg('(DirectX query)') }).finding.signature.variant, 'directx');
  const plain = run({ dialog: msg('') }).finding;
  assert.equal(plain.family, 'hang.watchdog');
  assert.equal(plain.signature.variant, undefined);
});

test('GTA V Enhanced is a wrong-install case', () => {
  const { finding } = run({ dialog: 'Your selected game installation folder points to the Enhanced edition of GTA V, which is currently not supported by FiveM.' });
  assert.equal(finding.family, 'launch.enhanced_unsupported');
  assert.equal(finding.owner, 'player');
});

test('a libcef.dll crash is the in-game browser, capped at MEDIUM', () => {
  const { finding } = run({ dump: { module: 'libcef.dll', offset: '1A2B3C', exception: '0xC0000005' } });
  assert.equal(finding.family, 'crash.nui_process');
  assert.equal(finding.confidence, 'MEDIUM');
});

// ---- Crashometry extras ------------------------------------------------------

test('RedM driver version and a known-bad server artifact reach the evidence', () => {
  const v = run(fx('forum-2026-07-13-redm-vulkan-oom')).finding;
  assert.ok(v.evidence.some((e) => e.ref === 'driver' && e.excerpt === 'NVIDIA v610.62.0.0'));
  const f = fx('forum-2022-12-11-rage-unknown');
  const bad = run({ ...f, crashometry: { ...f.crashometry, crashometry_last_server_ver: 'master v1.0.0.38435' } }).finding;
  assert.ok(bad.evidence.some((e) => e.ref === 'server_artifact_known_issue' && e.excerpt.includes('#4384')));
  assert.ok(bad.evidence.some((e) => e.excerpt.includes('#4394')), 'open-ended range (38004+) applies too');
  const ok = run(f).finding;
  assert.ok(!ok.evidence.some((e) => e.ref === 'server_artifact_known_issue'));
});

test('the server address in crashometry never reaches the finding', () => {
  const f = fx('forum-2022-12-11-rage-unknown');
  const { finding } = run({ ...f, crashometry: { ...f.crashometry, crashometry_last_server: '203.0.113.7:30120', crashometry_last_server_url: 'cfx.re/join/abc123' } });
  const s = JSON.stringify(finding);
  assert.ok(!s.includes('203.0.113.7') && !s.includes('abc123'));
  assert.equal(checkFinding(finding).ok, true);
});
