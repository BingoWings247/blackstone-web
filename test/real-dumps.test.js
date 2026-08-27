// test/real-dumps.test.js
// Seven real crashes (dump-reader output + crashometry + notable log lines, redacted) through the full engine.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { analyze } from '../tools/shared/crash-engine.js';
import { checkFinding } from '../tools/shared/finding-check.js';

const signatures = JSON.parse(await readFile(new URL('../tools/shared/signatures.json', import.meta.url), 'utf8'));
const fixtures = JSON.parse(await readFile(new URL('./fixtures/real-dumps.json', import.meta.url), 'utf8'));

for (const fx of fixtures) {
  test(`${fx.name} → ${fx.expect}`, () => {
    const { finding } = analyze({ filename: fx.filename, dump: fx.dump, crashometry: fx.crashometry, log: fx.log }, signatures, { now: 1_756_200_000_000 });
    assert.equal(finding.family, fx.expect);
    const chk = checkFinding(finding);
    assert.equal(chk.ok, true, JSON.stringify(chk.error));
    if (fx.expect !== 'unknown.crash') assert.notEqual(finding.confidence, 'LOW');
    assert.notEqual(finding.owner, undefined);
  });
}

test('pool-full logs carry the duplicate-archetype precursor count', () => {
  const fx = fixtures.find((f) => f.name === 'CfxCrashDump_2025_05_04_23_28_09');
  const { finding } = analyze({ dump: fx.dump, crashometry: fx.crashometry, log: fx.log }, signatures, { now: 1 });
  assert.ok(finding.metrics.duplicate_archetype > 5, JSON.stringify(finding.metrics));
  assert.ok(finding.evidence.some((e) => e.ref === 'crashometry.pool_error'));
});
