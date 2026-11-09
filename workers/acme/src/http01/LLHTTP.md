# llhttp WASM provenance

`npm run build:llhttp` extracts the unmodified, non-SIMD WASM module from the
official `undici@8.12.4` npm release (llhttp 9.3.1). Undici is a build dependency;
its client and dynamic WASM loader are not bundled into the Worker.

Upstream: https://github.com/nodejs/undici/tree/v8.12.4/lib/llhttp

Both Undici and llhttp are MIT licensed. The llhttp MIT notice is retained in `LLHTTP-LICENSE.txt`; the build includes
that notice and Undici's license alongside the WASM. Generated artifacts
are ignored under `cas/`; `llhttp-provenance.json` records their SHA-256 and source.

The TypeScript adapter uses the upstream WASM callback ABI and public llhttp
accessors. Lenient parsing is never enabled. Upgrades require reviewing that ABI
and rerunning the parser corpus and workerd smoke tests with the same binary.

A generated TypeScript shim imports `./llhttp.wasm` beside the binary. This
keeps the module specifier valid with Wrangler `preserve_file_names`, whose
bundler otherwise retains source-relative paths in the single Worker entry.
