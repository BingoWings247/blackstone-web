// tools/shared/redact.js
// Class S (secrets) and Class I (player identifiers) handling for every browser tool.
// Runs BEFORE anything leaves the browser. Pure ESM, no dependencies, works in Node for tests.
// See docs/data-contract.md §1–2 in the Sentinel repo.
//
//   redactText(text)            → { text, hits: { <patternName>: count } }   sync, placeholders only
//   pseudonymizeText(text, key) → Promise<{ text, hits }>                     Class I → HMAC pseudonyms
//   newShareKey()               → Uint8Array(32)                              random per-share key, never stored
//   containsSecret(text)        → pattern name | null                          gate used by the share step

// ---- Class S: secrets. Replaced with [REDACTED:<name>], never anything derived from the value.
export const SECRET_PATTERNS = [
  // Labelled values first, generic URI/token shapes after. Every value group refuses to re-match a placeholder.
  ['sv_licenseKey',      /(sv_licenseKey\s*["']?\s*)(?!\[REDACTED)[A-Za-z0-9_\-]{8,}/gi],
  ['steam_webApiKey',    /(steam_webApiKey\s*["']?\s*)(?!\[REDACTED)[A-Fa-f0-9]{16,}/gi],
  ['rcon_password',      /(rcon_password\s*["']?\s*)(?!\[REDACTED)\S{4,}/gi],
  ['mysql_connection',   /(mysql_connection_string\s*["']?\s*)(?!\[REDACTED)[^\s"']+/gi],
  ['db_uri',             /\b(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?):\/\/[^\s"'\]]+/gi],
  ['discord_webhook',    /https?:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_\-]+/gi],
  ['discord_bot_token',  /\b[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}\b/g],
  ['bearer',             /(\bBearer\s+)(?!\[REDACTED)[A-Za-z0-9\-._~+/]{16,}=*/gi],
  ['authorization',      /(\bAuthorization:\s*)(?!\[REDACTED|Bearer)\S+/gi],
  ['generic_assignment', /(\b(?:api[_-]?key|apikey|token|secret|password|passwd)\s*[:=]\s*["']?)(?!\[REDACTED)[^\s"']{8,}/gi],
  ['ip_port',            /\b(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}\b/g],
  ['rockstar_account_id', /(\bAccount id\s+)(?!\[REDACTED)\d{6,}/gi],
  ['mtl_machine_hash',    /(machine hash details from MTL\.\s*)(?!\[REDACTED)[A-Za-z0-9+/=]{20,}/gi],
  ['windows_user_path',  /([A-Za-z]:\\Users\\)(?!\[REDACTED)[^\\\s]+/g],
];

// ---- Class I: player identifiers. Replaced with [<kind>#<pseudonym>] (HMAC) or [<kind>#redacted] (sync).
// The '#' separator is deliberate: a placeholder must never itself look like an identifier.
export const IDENTIFIER_PATTERN = /\b(license2?|discord|steam|fivem|xbl|live|ip):([A-Za-z0-9.]{4,})\b/gi;

// Bare IPv4 (no port) — treated as Class I because it's usually a player address in FiveM logs.
const BARE_IPV4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;

function applySecrets(text, hits) {
  let out = text;
  for (const [name, re] of SECRET_PATTERNS) {
    out = out.replace(re, (m, keep) => {
      hits[name] = (hits[name] || 0) + 1;
      // Patterns with a capture group keep the label (e.g. "sv_licenseKey ") and replace only the value.
      return typeof keep === 'string' && m.startsWith(keep) ? `${keep}[REDACTED:${name}]` : `[REDACTED:${name}]`;
    });
  }
  return out;
}

/** Synchronous redaction: secrets → placeholders, identifiers → [kind:redacted]. Used for on-screen display. */
export function redactText(text) {
  const hits = {};
  if (typeof text !== 'string' || !text) return { text: text ?? '', hits };
  let out = applySecrets(text, hits);
  out = out.replace(IDENTIFIER_PATTERN, (m, kind) => {
    hits[`id_${kind.toLowerCase()}`] = (hits[`id_${kind.toLowerCase()}`] || 0) + 1;
    return `[${kind.toLowerCase()}#redacted]`;
  });
  out = out.replace(BARE_IPV4, (m) => {
    // Don't touch version-looking numbers like 1.0.0.0 that aren't plausible addresses.
    if (m.split('.').some((o) => Number(o) > 255)) return m;
    hits.ipv4 = (hits.ipv4 || 0) + 1;
    return '[ip#redacted]';
  });
  return { text: out, hits };
}

/** Random 32-byte key for one share. Never persisted, never sent. */
export function newShareKey() {
  const k = new Uint8Array(32);
  globalThis.crypto.getRandomValues(k);
  return k;
}

async function hmacHex(key, message) {
  const subtle = globalThis.crypto.subtle;
  const cryptoKey = await subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await subtle.sign('HMAC', cryptoKey, new TextEncoder().encode(message));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, '0')).join('').slice(0, 16);
}

/** Async redaction for the share step: secrets → placeholders, identifiers → stable HMAC pseudonyms under `key`. */
export async function pseudonymizeText(text, key) {
  const hits = {};
  if (typeof text !== 'string' || !text) return { text: text ?? '', hits };
  let out = applySecrets(text, hits);

  // Collect identifiers first so we can await HMACs, then substitute.
  const found = new Map();
  for (const m of out.matchAll(IDENTIFIER_PATTERN)) {
    const kind = m[1].toLowerCase();
    found.set(m[0], { kind, value: m[2] });
  }
  for (const m of out.matchAll(BARE_IPV4)) {
    if (m[0].split('.').some((o) => Number(o) > 255)) continue;
    found.set(m[0], { kind: 'ip', value: m[0] });
  }
  for (const [raw, { kind, value }] of found) {
    const p = await hmacHex(key, `${kind}:${value}`);
    hits[`id_${kind}`] = (hits[`id_${kind}`] || 0) + 1;
    out = out.split(raw).join(`[${kind}#${p}]`);
  }
  return { text: out, hits };
}

/** Gate: returns the first secret pattern name that still matches, or null. Used right before upload. */
export function containsSecret(text) {
  if (typeof text !== 'string' || !text) return null;
  for (const [name, re] of SECRET_PATTERNS) {
    re.lastIndex = 0;
    if (re.test(text)) { re.lastIndex = 0; return name; }
  }
  IDENTIFIER_PATTERN.lastIndex = 0;
  if (IDENTIFIER_PATTERN.test(text)) { IDENTIFIER_PATTERN.lastIndex = 0; return 'identifier'; }
  return null;
}
