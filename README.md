# testatum v0.1 (prototype)

Single-file, zero-runtime-dependency supply-chain checker for DSH plugin artifacts.
Built from `artifacts/supply-chain-baseline.md` (v0.1.0-draft, 2026-11-14).

npm status: **staged** (`testatum@0.0.0-stage` placeholder) pending 2FA approval; use the GitHub source until `0.1.0` is live.

**Experimental. Not a security gate.** v0.1 performs static inspection and digest
matching only; it does **not** verify cryptographic signatures or provenance, and
it does **not** fetch revocation lists. Unverifiable evidence is always `UNKNOWN`,
never `PASS`.

## Quick start

```sh
node testatum.mjs policy
node testatum.mjs scan .
node testatum.mjs scan dsh-auto-review@0.15.1
node testatum.mjs verify dsh-permission-rules@0.8.0
```

`scan` and `verify` write JSON (`schema: "testatum/1"`) to stdout and a human
summary to stderr. Add `--json` to suppress the stderr summary.

Exit codes: `0` pass, `1` fail, `2` unknown (including usage errors).

## Commands

| Command | What it checks |
|---|---|
| `scan <pkg\|dir>` | tarball/local manifest, `scripts` (`preinstall`/`install`/`postinstall`/`prepare`), `files`, `dsh.capabilities`, `binding.gyp`, lockfile integrity (dir) or `dist.integrity` + tarball SHA-512 (npm) |
| `verify <pkg>` | `dist.integrity`/`shasum` and tarball digest, presence of npm provenance and registry signatures, self-declared `dsh.attestation`/`dsh.signature` — all signature/provenance checks are `UNKNOWN` in v0.1 |
| `policy` | the 10 baseline requirements, modes and the `0/1/2` exit-code contract |

## Safety

- Package code and lifecycle scripts are never executed.
- Tarballs are gunzipped and parsed in memory; nothing is extracted to disk.
- `test/run.mjs` contains a malicious `postinstall` fixture and asserts its marker
  file is never created.

## Tests

```sh
npm test
```

Requires network for the two pinned npm packages. Tested with Node v24.22.1
(Linux/WSL). `engines` declares Node >= 20.

## Files

- `testatum.mjs` — the single-file CLI
- `test/run.mjs` — 8 end-to-end tests
- `fixtures/clean-minimal/` — negative control
- `fixtures/malicious-postinstall/` — positive control (never executed)
- `/mnt/d/Projects/dsh/deepseek-community-hub/artifacts/testatum-v0.1.md` — report
