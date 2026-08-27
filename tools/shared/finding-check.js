// tools/shared/finding-check.js
// A dependency-free check that a finding has the v1 shape and carries no Class S / raw Class I data.
// The authoritative validator (Zod) runs server-side at ingest; this one keeps the browser honest.

import { containsSecret } from './redact.js';

const SEVERITY = new Set(['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);
const CONFIDENCE = new Set(['LOW', 'MEDIUM', 'HIGH']);
const OWNER = new Set(['player', 'server_owner', 'script_developer', 'platform', 'nobody']);

function* strings(v, path = '') {
  if (typeof v === 'string') { yield [path, v]; return; }
  if (Array.isArray(v)) { for (let i = 0; i < v.length; i++) yield* strings(v[i], `${path}[${i}]`); return; }
  if (v && typeof v === 'object') for (const k of Object.keys(v)) yield* strings(v[k], path ? `${path}.${k}` : k);
}

export function checkFinding(f) {
  const fail = (field, detail) => ({ ok: false, error: { code: 'invalid_finding', field, detail } });
  if (!f || typeof f !== 'object') return fail('', 'not an object');
  if (f.schema !== 1) return fail('schema', 'must be 1');
  if (typeof f.key !== 'string' || !f.key) return fail('key', 'required');
  if (!/^[a-z]+(\.[a-z0-9_]+)+$/.test(f.family || '')) return fail('family', 'dotted lowercase (digits/underscore allowed after the first segment)');
  if (!SEVERITY.has(f.severity)) return fail('severity', 'enum');
  if (!CONFIDENCE.has(f.confidence)) return fail('confidence', 'enum');
  if (typeof f.summary !== 'string' || !f.summary || f.summary.length > 160) return fail('summary', '1-160 chars');
  if (!f.cause || typeof f.cause.headline !== 'string') return fail('cause.headline', 'required');
  if (!OWNER.has(f.owner)) return fail('owner', 'enum');
  if (!f.privacy || f.privacy.redacted !== true) return fail('privacy.redacted', 'must be true');
  if (typeof f.detected_at !== 'number') return fail('detected_at', 'ms epoch');
  if (f.evidence && f.evidence.length > 20) return fail('evidence', 'max 20');
  for (const e of f.evidence || []) if (e.excerpt && e.excerpt.length > 200) return fail('evidence.excerpt', 'max 200');
  for (const [path, s] of strings(f)) {
    const hit = containsSecret(s);
    if (hit) return { ok: false, error: { code: 'privacy_violation', field: path, detail: `value matched ${hit} pattern` } };
  }
  return { ok: true, finding: f };
}
