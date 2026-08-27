// test/crash-engine.test.js
// Run: npm test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { analyze, extract } from '../tools/shared/crash-engine.js';
import { checkFinding } from '../tools/shared/finding-check.js';
import { redactText, pseudonymizeText, newShareKey, containsSecret } from '../tools/shared/redact.js';

const signatures = JSON.parse(await readFile(new URL('../tools/shared/signatures.json', import.meta.url), 'utf8'));
const NOW = 1_756_200_000_000;

// ---- Fixtures: the three dumps run through 1of1 on 2026-08-26 ---------------

const POOL_FULL = {
  filename: 'CfxCrashDump_2025_05_05_21_12_55.zip',
  dump: { module: 'FiveM_b3095_GTAProcess.exe', offset: '64C24F', exception: '0xC0000005', address: '0x10', violation: 'write' },
  log: [
    '[   9270001] [b3095_GTAProce]             MainThrd/ Warning: Duplicate archetype prop_test_01',
    '[   9270002] [b3095_GTAProce]             MainThrd/ Warning: Duplicate archetype prop_test_02',
    '[   9270003] [b3095_GTAProce]             MainThrd/ Warning: Duplicate archetype prop_test_03',
    '[   9270004] [b3095_GTAProce]             MainThrd/ Warning: Duplicate archetype prop_test_04',
    '[   9270005] [b3095_GTAProce]             MainThrd/ Warning: Duplicate archetype prop_test_05',
    '[   9270006] [b3095_GTAProce]             MainThrd/ Warning: Duplicate archetype prop_test_06',
    '[   9270100] [b3095_GTAProce]             MainThrd/ Error: Physics validation failed for bound: broken_ybn',
    '[   9278968] [b3095_GTAProce]             MainThrd/ Error: <<unknown pool>> Pool Full, Size == 200',
  ].join('\n'),
};

const PATTERN_ASSERT = {
  filename: 'CfxCrashDump_2025_07_25_11_19_16.zip',
  dump: { module: 'gta-core-five.dll', offset: '1B840', exception: '0x80000004' },
  log: '[     12328] [b3570_GTAProce]             MainThrd/ Error: Assertion failure: m_matches.size() == expected',
};

const ROS_506 = {
  filename: 'CfxCrashDump_2026_08_07_21_03_20.zip',
  dump: { module: 'legitimacy.dll', offset: '7AF632', exception: '0xC0000005', address: '0xDEED', violation: 'write' },
  log: '[     93093] [       ROSLauncher]             MainThrd/ Error: 506. Failure connecting to the Rockstar Games Launcher! (ExitCode = 506)',
};

// ---- Engine ----------------------------------------------------------------

test('pool-full dump: HIGH confidence, server_owner owns the fix, 1of1 called this a null pointer', () => {
  const { finding } = analyze(POOL_FULL, signatures, { now: NOW });
  assert.equal(finding.family, 'crash.pool_full');
  assert.equal(finding.confidence, 'HIGH');
  assert.equal(finding.owner, 'server_owner');
  assert.equal(finding.location.build, '3095');
  assert.equal(finding.location.offset, '0x64C24F');
  assert.ok(finding.metrics.duplicate_archetype >= 6);
  assert.ok(finding.evidence.some((e) => e.excerpt.includes('Pool Full')));
  assert.equal(checkFinding(finding).ok, true);
});

test('pattern-scan assertion: 1of1 said Unknown, we name the family and hand it to the player', () => {
  const { finding } = analyze(PATTERN_ASSERT, signatures, { now: NOW });
  assert.equal(finding.family, 'crash.pattern_scan_assert');
  assert.equal(finding.confidence, 'HIGH');
  assert.equal(finding.owner, 'player');
  assert.equal(finding.location.build, '3570');
  assert.equal(checkFinding(finding).ok, true);
});

test('ROS 506 in legitimacy.dll: ros_handshake wins and the generic protection-layer family is suppressed', () => {
  const { finding, candidates } = analyze(ROS_506, signatures, { now: NOW });
  assert.equal(finding.family, 'crash.ros_handshake');
  assert.equal(finding.confidence, 'HIGH');
  assert.equal(finding.owner, 'player');
  assert.ok(!candidates.some((c) => c.family.id === 'protection_layer_generic'), 'generic family must be suppressed');
  assert.ok(finding.fix.steps.some((s) => /not.*mod-menu|Do not treat/i.test(s)));
  assert.equal(checkFinding(finding).ok, true);
});

test('legitimacy.dll with no launcher error falls back to the generic protection-layer family at MEDIUM', () => {
  const { finding } = analyze({ dump: ROS_506.dump }, signatures, { now: NOW });
  assert.equal(finding.family, 'crash.protection_layer');
  assert.equal(finding.confidence, 'MEDIUM');
  assert.ok(finding.cause.detail.includes('NOT evidence of cheating'));
});

test('paste-the-dialog mode: signature and hash from text alone', () => {
  const dialog = [
    'FiveM has encountered an error',
    'Crash signature: gta-core-five.dll+1B840',
    'Report ID: si-abc123 (use Ctrl+C to copy)',
    'Legacy crash hash: snake-eleven-robin',
    'Exception: 0x80000004',
  ].join('\n');
  const r = extract({ dialog });
  assert.equal(r.module, 'gta-core-five.dll');
  assert.equal(r.offset, '1B840');
  assert.equal(r.hash, 'snake-eleven-robin');
  const { finding } = analyze({ dialog }, signatures, { now: NOW });
  assert.equal(finding.family, 'crash.pattern_scan_assert');
});

test('nothing recognisable → unknown.crash, LOW, owner nobody, evidence still extracted', () => {
  const { finding } = analyze({
    dialog: 'Crash signature: something-else.dll+ABC123\nLegacy crash hash: november-table-ink',
  }, signatures, { now: NOW });
  assert.equal(finding.family, 'unknown.crash');
  assert.equal(finding.confidence, 'LOW');
  assert.equal(finding.owner, 'nobody');
  assert.equal(finding.location.hash, 'november-table-ink');
  assert.equal(checkFinding(finding).ok, true);
});

test('evidence excerpts are redacted: a webhook and a license id in the log never reach the finding', () => {
  const log = [
    '[1] [b3570_GTAProce] MainThrd/ Error: <<unknown pool>> Pool Full, Size == 200 https://discord.com/api/webhooks/123456789/AbCdEf_ghIJ',
    '[2] [b3570_GTAProce] MainThrd/ Error: player license:0a1b2c3d4e5f6a7b dropped, ip 203.0.113.9:30120',
  ].join('\n');
  const { finding } = analyze({ log }, signatures, { now: NOW });
  const dumped = JSON.stringify(finding);
  assert.ok(!dumped.includes('AbCdEf_ghIJ'));
  assert.ok(!dumped.includes('0a1b2c3d4e5f6a7b'));
  assert.ok(!dumped.includes('203.0.113.9'));
  assert.equal(checkFinding(finding).ok, true);
});

// ---- Redaction --------------------------------------------------------------

test('redactText strips every Class S family and keeps the label', () => {
  const { text, hits } = redactText([
    'sv_licenseKey "cfxk_abcdefghijklmnop_ABC123"',
    'set mysql_connection_string "mysql://root:hunter2@127.0.0.1/qbcore"',
    'webhook https://discord.com/api/webhooks/1122334455/Zz_yyXXwwVVuu',
    'C:\\Users\\Baillie\\AppData\\Local\\FiveM\\FiveM.app',
    'Authorization: Bearer abcdefghijklmnopqrstuvwxyz',
  ].join('\n'));
  assert.ok(text.includes('sv_licenseKey "[REDACTED:sv_licenseKey]'));
  assert.ok(!text.includes('hunter2'));
  assert.ok(!text.includes('Zz_yyXXwwVVuu'));
  assert.ok(text.includes('C:\\Users\\[REDACTED:windows_user_path]'));
  assert.ok(!text.includes('abcdefghijklmnopqrstuvwxyz'));
  assert.ok(hits.sv_licenseKey === 1 && hits.discord_webhook === 1 && hits.windows_user_path === 1);
  assert.equal(containsSecret(text), null);
});

test('pseudonymizeText gives stable per-key pseudonyms and different ones under a different key', async () => {
  const k1 = newShareKey(); const k2 = newShareKey();
  const src = 'join license:0a1b2c3d4e5f6a7b discord:123456789012345678 again license:0a1b2c3d4e5f6a7b';
  const a = await pseudonymizeText(src, k1);
  const b = await pseudonymizeText(src, k1);
  const c = await pseudonymizeText(src, k2);
  assert.equal(a.text, b.text);
  assert.notEqual(a.text, c.text);
  const ids = a.text.match(/\[license#[0-9a-f]{16}\]/g);
  assert.equal(ids.length, 2);
  assert.equal(ids[0], ids[1]);
  assert.ok(!a.text.includes('0a1b2c3d4e5f6a7b'));
  assert.equal(containsSecret(a.text), null);
});

test('redactText leaves version numbers alone and only redacts plausible IPv4', () => {
  const { text } = redactText('FiveM 1.0.0.9999 build 3570 from 10.0.0.5');
  assert.ok(text.includes('1.0.0.9999'));
  assert.ok(text.includes('[ip#redacted]'));
});

test('Rockstar account ids and MTL machine hashes are redacted', () => {
  const { text } = redactText('Account id 169462029\nCaught machine hash details from MTL. 68mPP+A3p7D+yq3eLC/X470x9Stv1qbDVj35F/5t5L4=');
  assert.ok(!text.includes('169462029'));
  assert.ok(!text.includes('68mPP+A3p7D'));
  assert.equal(containsSecret(text), null);
});
