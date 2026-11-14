# testatum v0.2 (local prototype)

Single-file, zero-runtime-dependency supply-chain checker for DSH plugin artifacts.
Built from `artifacts/supply-chain-baseline.md` (v0.1.0-draft, 2026-11-14).

npm: **`testatum@0.1.0` is live** — `npx testatum ...`. **v0.2.0 is local only**:
this prototype has **not** been published, and no git tag was created.

**Experimental. Not a security gate.** testatum performs static inspection, local
SBOM generation and an unsigned OSV advisory lookup. It does **not** verify
cryptographic signatures, Sigstore bundles or SLSA provenance, and it does **not**
consume a signed revocation list. Unverifiable evidence is always `UNKNOWN`,
never `PASS`.

## Quick start

```sh
node testatum.mjs policy
node testatum.mjs scan .
node testatum.mjs verify dsh-auto-review@0.15.1
node testatum.mjs sbom dsh-auto-review@0.15.1          # report with embedded CycloneDX
node testatum.mjs sbom . --cdx > sbom.cdx.json         # raw CycloneDX 1.5
node testatum.mjs revocation dsh-auto-review@0.15.1    # fresh OSV query
node testatum.mjs revocation lodash@4.17.19            # known-vulnerable example
```

`scan`, `verify`, `sbom` and `revocation` write JSON (`schema: "testatum/1"`) to
stdout and a human summary to stderr. Add `--json` to suppress the summary.

Exit codes: `0` pass, `1` fail, `2` unknown (including usage errors and network
failures).

## Commands

| Command | What it checks |
|---|---|
| `scan <pkg\|dir>` | tarball/local manifest, `scripts` (`preinstall`/`install`/`postinstall`/`prepare`), `files`, `dsh.capabilities`, `binding.gyp`, lockfile integrity (dir) or `dist.integrity` + tarball SHA-512/SHA-1 (npm) |
| `verify <pkg>` | `dist.integrity`/`shasum` and tarball digest, registry-signature **presence**, npm-attestation **presence**. Every signature/provenance check stays `UNKNOWN`; presence is never promoted to `PASS` |
| `sbom <pkg\|dir>` | emits a local **CycloneDX 1.5** document: root component name/version/purl/hashes, dependency components (version/hash/license where resolvable), SHA-256 file-inventory digest and file count. `--cdx` prints only the document |
| `revocation <pkg@version>` | POSTs an exact package+version to the public **OSV** `/v1/query` API. No active advisories → `PASS`; advisories → `FAIL`; network/API failure → `UNKNOWN`. Results are never cached |
| `policy` | the 10 baseline requirements, v0.2 status, modes and the `0/1/2` exit-code contract |

### SBOM coverage

- Hash contents are lowercase hex, as required by the CycloneDX 1.5 schema.
- `metadata.component.hashes` binds the npm tarball bytes (SHA-512 + SHA-256) or
  the local source-tree digest.
- `testatum:filesDigest` (`sha256:<hex>`) is a deterministic digest over the
  sorted file inventory (`path`, size, per-file SHA-256). The same bytes produce
  the same serial number, components and digest.
- Local-directory inventories exclude `node_modules`, `.git`, `.cache` and
  `coverage`; symlinks are not followed, and individual files above 16 MiB are
  skipped (reported as a coverage gap) to bound memory use.
- A tarball has no lockfile, so dependency versions are declared semver ranges.
  When runtime/peer components remain unresolved (or lack hashes/licenses),
  `SC-02` is `UNKNOWN` and the report exits `2` even though a valid CycloneDX
  document is still emitted. Lockfile-backed local directories can reach `PASS`.
- The SBOM is unsigned and unattested. `testatum:sbomSigned=false` and
  `testatum:sbomAttested=false` make that explicit.

### Revocation semantics

- Exact versions only (`name@1.2.3`, scoped names supported); ranges and tags are
  rejected with exit `2`.
- One fresh request per invocation (default endpoint is HTTPS). There is no
  in-memory or on-disk cache, so a stale result cannot be replayed; a failed
  query is never treated as clear.
- `revocation.status` is `clear`, `advisories-found` or `unknown`. Advisories
  carry id, aliases (e.g. CVE), severity, fixed versions and modified time.
- OSV advisories are **unsigned, point-in-time data**, not the signed
  `revocations.json` list required by baseline SC-06. A `PASS` here means "OSV
  returned no active advisories for this exact version", not "safe".

### Provenance presence

`verify` records whether the npm version metadata contains `dist.attestations`
(and tries to count the bundles). `report.provenance.present=true` means the
field exists; `verified=false` always means testatum did not verify it. The
`provenance` check remains `UNKNOWN` in both the present and absent cases.

## JSON schema `testatum/1`

v0.2 is additive and backward compatible. Every `scan`/`verify`/`sbom`/`revocation`
report keeps the v0.1 keys and adds three keys that are always present (`null`
when not applicable):

| Field | Type | Meaning |
|---|---|---|
| `sbom` | object\|null | CycloneDX 1.5 document for `sbom` reports |
| `revocation` | object\|null | OSV query result for `revocation` reports |
| `provenance` | object\|null | `{present, verified, status, source, url, predicateTypes, bundleCount, declaredInManifest, reason}` for `verify` |

Existing fields (`schema`, `tool`, `command`, `target`, `generatedAt`, `verdict`,
`exitCode`, `summary`, `checks[]`, `evidence`, `limitations[]`) are unchanged.
`sbom` evidence includes `format`, `specVersion`, `source`, `fileCount`,
`filesDigest`, `coverage` (`full`/`partial`), `gaps`, `signed` and `attested`.

## Safety

- Package code and lifecycle scripts are never executed.
- Tarballs are gunzipped and parsed in memory; nothing is extracted to disk.
- `sbom` only reads bytes and hashes them; `verify` only reads registry metadata,
  tarballs and the attestation endpoint.
- `revocation` sends only `{package:{name,ecosystem:"npm"},version}` to OSV.
- `test/run.mjs` contains a malicious `postinstall` fixture and asserts its marker
  file is never created by `scan` or `sbom`.

## Tests

```sh
npm test
```

20 end-to-end tests, including clean/malicious/locked local fixtures and the real
`dsh-auto-review@0.15.1` package. Requires network for npm tarballs and OSV.
Tested with Node v24.22.1 (Linux/WSL). `engines` declares Node >= 20.

## Limitations

- No cryptographic verification: npm signatures, Sigstore/Fulcio/Rekor, DSSE,
  SLSA provenance and project Ed25519 signatures are all unverified.
- No signed revocation list, TTL or fail-closed feed; OSV is an unsigned
  advisory lookup and can change between invocations.
- SBOMs are local and unsigned; npm-tarball dependency graphs are not resolved
  transitively, so coverage is often `partial`.
- Capability checks are declaration-level only (no AST/runtime observation).
- No reproducible-build check, no install audit log, no host/CLI integration.

## Files

- `testatum.mjs` — the single-file CLI
- `test/run.mjs` — 20 end-to-end tests
- `fixtures/clean-minimal/` — negative control
- `fixtures/malicious-postinstall/` — positive control (never executed)
- `fixtures/locked-deps/` — SBOM fixture with a pinned `left-pad@1.3.0` integrity hash
- `/mnt/d/Projects/dsh/deepseek-community-hub/artifacts/testatum-v0.1.md` — v0.1 report
- `/mnt/d/Projects/dsh/deepseek-community-hub/artifacts/testatum-v0.2.md` — v0.2 report
