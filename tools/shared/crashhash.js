// tools/shared/crashhash.js
// How FiveM turns a crash signature into a "legacy crash hash", reproduced exactly.
//
//   id    = joaat(lowercase("<canonical module>+<offset>"))        // Jenkins one-at-a-time, as GTA's HashString
//   words = WORDS[id & 0xFF] - WORDS[(id >> 8) & 0xFF] - WORDS[(id >> 16) & 0xFF]
//
// Verified against real crashometry.json files (crash_hash / crash_hash_id / crash_hash_key):
//   fivem.exe+64C24F        → 2816774214 → fish-mockingbird-two
//   gta-core-five.dll+1B840 → 1069235659 → snake-eleven-robin
//   fivem.exe+7252AB        → 3412107760 → virginia-october-hydrogen
//
// The canonical module for the game process is "fivem.exe" (RedM: "redm.exe", verified: redm.exe+8006460 → king-mountain-alaska)
// even though the dialog shows GTA5_bXXXX.exe / FiveM_bXXXX_GTAProcess.exe / RDR2_b1491.exe. Offsets are per build, so the same bug has a different hash on each build.
// Word list: code/client/launcher/CrashWordList.h in citizenfx/fivem (from zacharyvoase/humanhash).

export const WORDS = [
  'ack','alabama','alanine','alaska','alpha','angel','apart','april','arizona','arkansas','artist','asparagus','aspen','august','autumn','avocado',
  'bacon','bakerloo','batman','beer','berlin','beryllium','black','blossom','blue','bluebird','bravo','bulldog','burger','butter','california','carbon',
  'cardinal','carolina','carpet','cat','ceiling','charlie','chicken','coffee','cola','cold','colorado','comet','connecticut','crazy','cup','dakota',
  'december','delaware','delta','diet','don','double','early','earth','east','echo','edward','eight','eighteen','eleven','emma','enemy',
  'equal','failed','fanta','fifteen','fillet','finch','fish','five','fix','floor','florida','football','four','fourteen','foxtrot','freddie',
  'friend','fruit','gee','georgia','glucose','golf','green','grey','hamper','happy','harry','hawaii','helium','high','hot','hotel',
  'hydrogen','idaho','illinois','india','indigo','ink','iowa','island','item','jersey','jig','johnny','juliet','july','jupiter','kansas',
  'kentucky','kilo','king','kitten','lactose','lake','lamp','lemon','leopard','lima','lion','lithium','london','louisiana','low','magazine',
  'magnesium','maine','mango','march','mars','maryland','massachusetts','may','mexico','michigan','mike','minnesota','mirror','mississippi','missouri','mobile',
  'mockingbird','monkey','montana','moon','mountain','muppet','music','nebraska','neptune','network','nevada','nine','nineteen','nitrogen','north','november',
  'nuts','october','ohio','oklahoma','one','orange','oranges','oregon','oscar','oven','oxygen','papa','paris','pasta','pennsylvania','pip',
  'pizza','pluto','potato','princess','purple','quebec','queen','quiet','red','river','robert','robin','romeo','rugby','sad','salami',
  'saturn','september','seven','seventeen','shade','sierra','single','sink','six','sixteen','skylark','snake','social','sodium','solar','south',
  'spaghetti','speaker','spring','stairway','steak','stream','summer','sweet','table','tango','ten','tennessee','tennis','texas','thirteen','three',
  'timing','triple','twelve','twenty','two','uncle','undress','uniform','uranus','utah','vegan','venus','vermont','victor','video','violet',
  'virginia','washington','west','whiskey','white','william','winner','winter','wisconsin','wolfram','wyoming','xray','yankee','yellow','zebra','zulu',
];
const INDEX = new Map(WORDS.map((w, i) => [w, i]));

/** Jenkins one-at-a-time over the lowercased string, as GTA's HashString. */
export function joaat(str) {
  let h = 0;
  const s = str.toLowerCase();
  for (let i = 0; i < s.length; i++) {
    h = (h + s.charCodeAt(i)) >>> 0;
    h = (h + (h << 10)) >>> 0;
    h = (h ^ (h >>> 6)) >>> 0;
  }
  h = (h + (h << 3)) >>> 0;
  h = (h ^ (h >>> 11)) >>> 0;
  h = (h + (h << 15)) >>> 0;
  return h >>> 0;
}

export function idToWords(id) {
  return `${WORDS[id & 0xff]}-${WORDS[(id >>> 8) & 0xff]}-${WORDS[(id >>> 16) & 0xff]}`;
}

/** Canonical signature string: dialog/dump module names for the game process become "fivem.exe". */
export function canonicalSignature(module, offset) {
  if (!module || !offset) return null;
  let m = module;
  if (/^(?:fivem_(?:b\d{4}_)?gtaprocess\.exe|gta5(?:_b\d{4})?\.exe)$/i.test(module)) m = 'fivem.exe';
  else if (/^(?:redm_(?:b\d{4}_)?gtaprocess\.exe|rdr2(?:_b\d{4})?\.exe)$/i.test(module)) m = 'redm.exe';
  return `${m}+${String(offset).replace(/^0x/i, '').toUpperCase()}`;
}

export function signatureToHash(module, offset) {
  const sig = canonicalSignature(module, offset);
  if (!sig) return null;
  const id = joaat(sig);
  return { signature: sig, id, words: idToWords(id) };
}

/** Are all three words real? Catches typos in pasted hashes. Returns { ok, bad: [word] }. */
export function validateWords(hash) {
  const parts = String(hash || '').toLowerCase().split('-');
  if (parts.length !== 3) return { ok: false, bad: parts };
  const bad = parts.filter((w) => !INDEX.has(w));
  return { ok: bad.length === 0, bad };
}

/** Does the pasted hash agree with the signature? null when either side is missing. */
export function hashMatchesSignature(hash, module, offset) {
  const h = signatureToHash(module, offset);
  if (!h || !hash) return null;
  return h.words === String(hash).toLowerCase();
}
