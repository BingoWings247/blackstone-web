# blackstone-web

Public site for blackstonescripts.com and the free browser-side diagnostic tools.
Deployed as a static site (Cloudflare Pages). No server, no uploads by default: every tool parses in the browser.

```
index.html                 landing page
tools/shared/redact.js     Class S secret strip + Class I pseudonymization (runs before anything leaves the browser)
tools/shared/signatures.json   crash family database — data, not code
tools/shared/crash-engine.js   artifact → v1 finding
tools/shared/finding-check.js  browser-side structural + privacy check for findings
tools/shared/minidump.js       reads module/offset/exception from a minidump (no memory regions)
tools/shared/zip.js            in-browser zip reader (DecompressionStream), zip-bomb guarded
tools/shared/pipeline.js       files/paste → engine inputs
tools/shared/crashhash.js      legacy crash hash algorithm (joaat + 256-word list), verified on real dumps
tools/crash/index.html         the Crash Parser page
data/index.html                the data contract, rendered
_headers                       Cloudflare Pages security headers + CSP
test/                      node --test
```

Rules that apply to every file here are in the Sentinel repo: `docs/data-contract.md` and `docs/finding-schema-v1.md`.

Run tests: `npm test` (Node 22+, no dependencies).
