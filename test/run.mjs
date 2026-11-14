#!/usr/bin/env node
/**
 * End-to-end tests for the testatum v0.2 prototype.
 *
 * Network is required for the pinned npm targets and for the live OSV checks.
 * The tests never install packages and never execute fixture lifecycle scripts.
 */

import { spawnSync } from 'node:child_process'
import { existsSync, rmSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const TEST_DIR = dirname(fileURLToPath(import.meta.url))
const ROOT = dirname(TEST_DIR)
const CLI = join(ROOT, 'testatum.mjs')
const MALICIOUS_DIR = join(ROOT, 'fixtures', 'malicious-postinstall')
const MARKER = join(MALICIOUS_DIR, 'PWNED-BY-POSTINSTALL')

const results = []
let failed = 0

function run(args, extraEnv = {}) {
  return spawnSync(process.execPath, [CLI, ...args], {
    cwd: ROOT,
    encoding: 'utf8',
    timeout: 180_000,
    env: { ...process.env, ...extraEnv },
  })
}

function assert(condition, message) {
  if (!condition) throw new Error(message)
}

function parseReport(result, expectedExit) {
  assert(result.status === expectedExit, `expected exit ${expectedExit}, got ${result.status}; stderr=${result.stderr}`)
  let report
  try {
    report = JSON.parse(result.stdout)
  } catch (error) {
    throw new Error(`stdout is not JSON: ${error.message}\n${result.stdout.slice(0, 500)}`)
  }
  assert(report.schema === 'testatum/1', `schema is ${report.schema}`)
  assert(report.exitCode === result.status, `report.exitCode ${report.exitCode} != process exit ${result.status}`)
  assert(['pass', 'fail', 'unknown'].includes(report.verdict), `bad verdict ${report.verdict}`)
  assert(Array.isArray(report.checks) && report.checks.length > 0, 'checks are empty')
  const counts = { pass: 0, fail: 0, unknown: 0 }
  for (const check of report.checks) counts[check.status.toLowerCase()] += 1
  assert(counts.pass === report.summary.pass, 'summary.pass mismatch')
  assert(counts.fail === report.summary.fail, 'summary.fail mismatch')
  assert(counts.unknown === report.summary.unknown, 'summary.unknown mismatch')
  assert(report.verdict === (counts.fail ? 'fail' : counts.unknown ? 'unknown' : 'pass'), 'verdict does not follow fail > unknown > pass')
  return report
}

function check(id, status, report) {
  return report.checks.find((item) => item.id === id && (!status || item.status === status))
}

function property(document, name) {
  return document.properties?.find((item) => item.name === name)?.value
}

function assertCycloneDx(document) {
  assert(document && document.bomFormat === 'CycloneDX', 'bomFormat is not CycloneDX')
  assert(document.specVersion === '1.5', `specVersion is ${document.specVersion}`)
  assert(document.version === 1, `document.version is ${document.version}`)
  assert(/^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(document.serialNumber || ''), 'serialNumber is not a UUID urn')
  const root = document.metadata?.component
  assert(root && root.type === 'library' && root.name && root.version, 'metadata.component is incomplete')
  assert(/^pkg:npm\//.test(root.purl || ''), `root purl is ${root.purl}`)
  assert(Array.isArray(root.hashes) && root.hashes.length > 0, 'root hashes are empty')
  for (const hash of root.hashes) {
    assert(hash.alg === 'SHA-256' || hash.alg === 'SHA-512', `unexpected root hash alg ${hash.alg}`)
    assert(/^[a-f0-9]+$/.test(hash.content || ''), `root hash ${hash.alg} is not lowercase hex`)
  }
  assert(typeof property(document, 'testatum:filesDigest') === 'string', 'filesDigest property missing')
  assert(typeof property(document, 'testatum:fileCount') === 'string', 'fileCount property missing')
  for (const component of document.components || []) {
    assert(component.type === 'library', `component ${component.name} is not a library`)
    assert(typeof component.name === 'string' && component.name, 'component name missing')
    assert(typeof component['bom-ref'] === 'string' && component['bom-ref'], `component ${component.name} has no bom-ref`)
    for (const hash of component.hashes || []) {
      assert(/^[a-f0-9]+$/.test(hash.content || ''), `component ${component.name} hash is not hex`)
    }
  }
  const refs = new Set((document.components || []).map((item) => item['bom-ref']))
  for (const dependency of document.dependencies || []) {
    assert(dependency.ref === root.purl, `dependency root ${dependency.ref} != root purl`)
    for (const ref of dependency.dependsOn || []) assert(refs.has(ref), `unknown dependency ref ${ref}`)
  }
}

function test(name, fn) {
  try {
    const detail = fn()
    results.push({ name, ok: true, detail: detail || '' })
  } catch (error) {
    failed += 1
    results.push({ name, ok: false, detail: error.message })
  }
}

// ---------------------------------------------------------------------------

test('policy --json: 10 requirements, v0.2 fields and exit codes', () => {
  const result = run(['policy', '--json'])
  assert(result.status === 0, `exit ${result.status}`)
  const policy = JSON.parse(result.stdout)
  assert(policy.schema === 'testatum/1', 'schema mismatch')
  assert(policy.requirements.length === 10, `got ${policy.requirements.length} requirements`)
  assert(policy.tool.version === '0.2.0', `tool version ${policy.tool.version}`)
  assert(policy.exitCodes['0'] === 'pass' && policy.exitCodes['1'] === 'fail' && String(policy.exitCodes['2']).startsWith('unknown'), 'exit code contract incomplete')
  assert(policy.requirements.some((item) => item.id === 'SC-03'), 'SC-03 missing')
  assert(/CycloneDX/.test(policy.requirements.find((item) => item.id === 'SC-02').v02), 'SC-02 v0.2 status does not mention CycloneDX')
  assert(/OSV/.test(policy.requirements.find((item) => item.id === 'SC-06').v02), 'SC-06 v0.2 status does not mention OSV')
  assert(policy.commands?.sbom && policy.commands?.revocation, 'commands map missing sbom/revocation')
  assert(policy.schemaExtensions?.sbom && policy.schemaExtensions?.revocation && policy.schemaExtensions?.provenance, 'schema extension map incomplete')
  return '10 requirements; SC-02/SC-06 v0.2; exit 0/1/2'
})

test('scan fixtures/clean-minimal: exit 0 / pass; additive fields are null', () => {
  const result = run(['scan', 'fixtures/clean-minimal', '--json'])
  const report = parseReport(result, 0)
  assert(report.verdict === 'pass', `verdict ${report.verdict}`)
  assert(check('SC-03', 'PASS', report), 'SC-03 is not PASS')
  assert(check('SC-04', 'PASS', report), 'SC-04 is not PASS')
  assert(check('SC-07', 'PASS', report), 'SC-07 is not PASS')
  assert('sbom' in report && report.sbom === null, 'sbom field missing/not null on scan')
  assert('revocation' in report && report.revocation === null, 'revocation field missing/not null on scan')
  assert('provenance' in report && report.provenance === null, 'provenance field missing/not null on scan')
  return '3/3 PASS; sbom/revocation/provenance null'
})

test('scan fixtures/malicious-postinstall: exit 1 / SC-03 FAIL; script not executed', () => {
  rmSync(MARKER, { force: true })
  const result = run(['scan', 'fixtures/malicious-postinstall', '--json'])
  const report = parseReport(result, 1)
  assert(report.verdict === 'fail', `verdict ${report.verdict}`)
  const sc03 = check('SC-03', 'FAIL', report)
  assert(sc03, 'SC-03 is not FAIL')
  assert(/postinstall/.test(sc03.reason), 'postinstall not named in reason')
  assert(!existsSync(MARKER), 'postinstall command was executed (marker exists)')
  return 'FAIL SC-03; marker absent'
})

test('scan dsh-permission-rules@0.8.0: exit 1 / prepare + missing capabilities', () => {
  const result = run(['scan', 'dsh-permission-rules@0.8.0', '--json'])
  const report = parseReport(result, 1)
  const sc03 = check('SC-03', 'FAIL', report)
  assert(sc03 && /prepare/.test(sc03.reason), 'SC-03 does not report prepare')
  assert(sc03.evidence.source === 'tarball', 'manifest was not read from the tarball')
  assert(check('SC-04', 'UNKNOWN', report), 'SC-04 is not UNKNOWN')
  assert(check('SC-07', 'PASS', report), 'SC-07 is not PASS')
  return 'FAIL prepare; UNKNOWN capabilities; PASS sha512'
})

test('scan dsh-auto-review@0.15.1: exit 1 / prepare + declared capabilities', () => {
  const result = run(['scan', 'dsh-auto-review@0.15.1', '--json'])
  const report = parseReport(result, 1)
  const sc03 = check('SC-03', 'FAIL', report)
  assert(sc03 && /prepare/.test(sc03.reason), 'SC-03 does not report prepare')
  assert(check('SC-04', 'PASS', report), 'SC-04 is not PASS')
  assert(check('SC-07', 'PASS', report), 'SC-07 is not PASS')
  return 'FAIL prepare; PASS capabilities; PASS sha512'
})

test('verify dsh-permission-rules@0.8.0: digest PASS, signature/provenance UNKNOWN and present', () => {
  const result = run(['verify', 'dsh-permission-rules@0.8.0', '--json'])
  const report = parseReport(result, 2)
  assert(report.verdict === 'unknown', `verdict ${report.verdict}`)
  assert(check('SC-07', 'PASS', report), 'artifact digest is not PASS')
  const signature = check('SC-01', 'UNKNOWN', report)
  assert(signature && /does not verify/.test(signature.reason), 'signature not UNKNOWN/unverified')
  const provenance = report.checks.find((item) => item.id === 'SC-07' && item.title === 'provenance')
  assert(provenance && provenance.status === 'UNKNOWN', 'provenance is not UNKNOWN')
  assert(/does not verify/.test(provenance.reason), 'provenance reason does not state the limitation')
  assert(report.provenance?.present === true, 'top-level provenance.present is not true')
  assert(report.provenance?.verified === false, 'top-level provenance.verified is not false')
  assert(report.provenance?.status === 'present-unverified', `provenance status is ${report.provenance?.status}`)
  assert(report.provenance?.verification === 'not-implemented', 'provenance.verification is not not-implemented')
  assert(report.provenance?.bundleCount >= 1, 'provenance bundle count is missing')
  assert(report.provenance?.source === 'npm-attestations', 'provenance source is not npm-attestations')
  return 'digest PASS; 2 UNKNOWN; provenance present/unverified'
})

test('verify dsh-auto-review@0.15.1: provenance present is never promoted to PASS', () => {
  const result = run(['verify', 'dsh-auto-review@0.15.1', '--json'])
  const report = parseReport(result, 2)
  assert(report.verdict === 'unknown', `verdict ${report.verdict}`)
  assert(report.provenance?.present === true, 'provenance is not present')
  assert(report.provenance?.verified === false, 'provenance was claimed verified')
  assert(report.summary.pass >= 1 && report.summary.unknown >= 2, 'unexpected summary')
  const provenanceChecks = report.checks.filter((item) => item.title === 'provenance')
  assert(provenanceChecks.length === 1 && provenanceChecks[0].status === 'UNKNOWN', 'provenance check is not UNKNOWN')
  return 'exit 2; provenance present but UNKNOWN'
})

test('verify left-pad@1.3.0: absent provenance is UNKNOWN, not PASS', () => {
  const result = run(['verify', 'left-pad@1.3.0', '--json'])
  const report = parseReport(result, 2)
  assert(report.provenance?.present === false, 'provenance.present is not false')
  assert(report.provenance?.status === 'absent', `provenance status is ${report.provenance?.status}`)
  assert(report.provenance?.verified === false, 'provenance was claimed verified')
  const provenance = report.checks.find((item) => item.id === 'SC-07' && item.title === 'provenance')
  assert(provenance && provenance.status === 'UNKNOWN', 'provenance check is not UNKNOWN')
  assert(/no npm provenance/.test(provenance.reason), 'reason does not say provenance is absent')
  return 'present=false; status=absent; UNKNOWN'
})

test('sbom fixtures/clean-minimal: valid CycloneDX 1.5, files digest, deterministic', () => {
  const result = run(['sbom', 'fixtures/clean-minimal', '--json'])
  const report = parseReport(result, 0)
  assert(report.verdict === 'pass', `verdict ${report.verdict}`)
  assertCycloneDx(report.sbom)
  assert(check('SC-02', 'PASS', report), 'SC-02 is not PASS')
  assert(report.evidence.sbom.fileCount === 3, `fileCount ${report.evidence.sbom.fileCount}`)
  assert(/^sha256:[0-9a-f]{64}$/.test(report.evidence.sbom.filesDigest), `filesDigest ${report.evidence.sbom.filesDigest}`)
  assert(report.sbom.components.length === 0, 'clean fixture unexpectedly has components')
  assert(report.sbom.metadata.component.name === 'testatum-fixture-clean', 'root component name mismatch')
  assert(report.sbom.metadata.component.version === '1.0.0', 'root component version mismatch')
  assert(property(report.sbom, 'testatum:sbomSigned') === 'false', 'SBOM must be marked unsigned')
  assert(property(report.sbom, 'testatum:coverage') === 'full', 'coverage is not full')
  const again = parseReport(run(['sbom', 'fixtures/clean-minimal', '--json']), 0)
  assert(JSON.stringify(again.sbom) === JSON.stringify(report.sbom), 'CycloneDX output is not deterministic')
  return '3 files; 1 component (root); deterministic serial/hashes'
})

test('sbom fixtures/locked-deps: pinned dependency version + SHA-512 hash + license', () => {
  const result = run(['sbom', 'fixtures/locked-deps', '--json'])
  const report = parseReport(result, 0)
  assertCycloneDx(report.sbom)
  assert(check('SC-02', 'PASS', report), 'SC-02 is not PASS')
  assert(report.sbom.components.length === 1, `component count ${report.sbom.components.length}`)
  const component = report.sbom.components[0]
  assert(component.name === 'left-pad', `component name ${component.name}`)
  assert(component.version === '1.3.0', `component version ${component.version}`)
  assert(component.purl === 'pkg:npm/left-pad@1.3.0', `component purl ${component.purl}`)
  assert(component.hashes?.length === 1 && component.hashes[0].alg === 'SHA-512', 'component hash missing')
  assert(/^[a-f0-9]{128}$/.test(component.hashes[0].content), 'component SHA-512 is not 128 hex chars')
  assert(component.licenses?.[0]?.license?.id === 'MIT', 'component license is not MIT')
  assert(report.sbom.dependencies[0].dependsOn.includes('pkg:npm/left-pad@1.3.0'), 'root dependency edge missing')
  assert(report.evidence.sbom.coverage === 'full', 'coverage is not full')
  return 'left-pad@1.3.0; SHA-512; MIT; dependency edge'
})

test('sbom fixtures/malicious-postinstall: SBOM generation does not execute scripts', () => {
  rmSync(MARKER, { force: true })
  const result = run(['sbom', 'fixtures/malicious-postinstall', '--json'])
  const report = parseReport(result, 0)
  assertCycloneDx(report.sbom)
  assert(check('SC-02', 'PASS', report), 'SC-02 is not PASS')
  assert(!existsSync(MARKER), 'postinstall command was executed while generating the SBOM (marker exists)')
  return 'SBOM PASS; marker absent'
})

test('sbom dsh-auto-review@0.15.1: valid CycloneDX with partial dependency coverage', () => {
  const result = run(['sbom', 'dsh-auto-review@0.15.1', '--json'])
  const report = parseReport(result, 2)
  assert(report.verdict === 'unknown', `verdict ${report.verdict}`)
  assertCycloneDx(report.sbom)
  const sc02 = check('SC-02', 'UNKNOWN', report)
  assert(sc02 && /partial/.test(sc02.reason), 'SC-02 does not report partial coverage')
  assert(report.evidence.sbom.coverage === 'partial', 'coverage is not partial')
  assert(report.evidence.sbom.unresolvedRuntime >= 1, 'no unresolved runtime components recorded')
  assert(report.evidence.sbom.fileCount === 211, `fileCount ${report.evidence.sbom.fileCount}`)
  assert(report.evidence.source.integrityMatches === true, 'tarball digest does not match dist.integrity')
  assert(report.sbom.components.some((item) => item.name === 'zod'), 'zod component missing')
  const zod = report.sbom.components.find((item) => item.name === 'zod')
  assert(!zod.version, 'zod version should be unresolved for a tarball without a lockfile')
  assert(property({ properties: zod.properties }, 'testatum:versionSpec') === '^4.4.3', 'zod versionSpec property missing')
  return '211 files; partial coverage; zod/yaml ranges recorded'
})

test('sbom --cdx prints a bare CycloneDX document', () => {
  const result = run(['sbom', 'fixtures/clean-minimal', '--cdx'])
  assert(result.status === 0, `exit ${result.status}`)
  const document = JSON.parse(result.stdout)
  assert(document.bomFormat === 'CycloneDX', 'raw output is not CycloneDX')
  assert(document.schema === undefined, 'raw output unexpectedly carries the testatum report schema')
  assertCycloneDx(document)
  return 'bare CycloneDX 1.5 on stdout'
})

test('revocation left-pad@1.3.0: OSV clear => PASS / exit 0', () => {
  const result = run(['revocation', 'left-pad@1.3.0', '--json'])
  const report = parseReport(result, 0)
  assert(report.verdict === 'pass', `verdict ${report.verdict}`)
  assert(report.revocation?.status === 'clear', `status ${report.revocation?.status}`)
  assert(report.revocation?.advisoryCount === 0, 'advisory count is not zero')
  assert(report.revocation?.cache === 'disabled', 'revocation result is cached')
  assert(report.revocation?.signed === false, 'OSV result was claimed signed')
  assert(check('SC-06', 'PASS', report), 'SC-06 is not PASS')
  assert(/api\.osv\.dev/.test(report.revocation?.endpoint || ''), 'endpoint is not the public OSV API')
  return 'clear; 0 advisories; cache disabled'
})

test('revocation lodash@4.17.19: OSV advisories => FAIL / exit 1', () => {
  const result = run(['revocation', 'lodash@4.17.19', '--json'])
  const report = parseReport(result, 1)
  assert(report.verdict === 'fail', `verdict ${report.verdict}`)
  assert(report.revocation?.status === 'advisories-found', `status ${report.revocation?.status}`)
  assert(report.revocation?.advisoryCount >= 1, 'no advisories recorded')
  assert(report.revocation?.advisories.some((item) => /^GHSA-/.test(item.id || '')), 'no GHSA advisory id')
  assert(check('SC-06', 'FAIL', report), 'SC-06 is not FAIL')
  assert(/advisory|advisories/.test(check('SC-06', 'FAIL', report).reason), 'FAIL reason does not mention advisories')
  return `${report.revocation.advisoryCount} advisories; FAIL`
})

test('revocation dsh-auto-review@0.15.1: live OSV query for the pinned real package', () => {
  const result = run(['revocation', 'dsh-auto-review@0.15.1', '--json'])
  const report = parseReport(result, 0)
  assert(report.verdict === 'pass', `verdict ${report.verdict}`)
  assert(report.revocation?.status === 'clear', `status ${report.revocation?.status}`)
  assert(report.revocation?.package === 'dsh-auto-review', 'package name mismatch')
  assert(report.revocation?.version === '0.15.1', 'version mismatch')
  assert(report.revocation?.cache === 'disabled', 'revocation result is cached')
  return 'clear; package/version pinned; no cache'
})

test('revocation network failure => UNKNOWN / exit 2; no cached retry', () => {
  const env = { TESTATUM_OSV_API: 'http://127.0.0.1:1/v1/query' }
  const first = run(['revocation', 'left-pad@1.3.0', '--json'], env)
  const report = parseReport(first, 2)
  assert(report.verdict === 'unknown', `verdict ${report.verdict}`)
  assert(report.revocation?.status === 'unknown', `status ${report.revocation?.status}`)
  assert(Boolean(report.revocation?.error), 'network error was not recorded')
  assert(report.revocation?.cache === 'disabled', 'failed result was cached')
  assert(check('SC-06', 'UNKNOWN', report), 'SC-06 is not UNKNOWN')
  assert(/no cached result/.test(check('SC-06', 'UNKNOWN', report).reason), 'reason does not state that no cache was used')
  const second = parseReport(run(['revocation', 'left-pad@1.3.0', '--json'], env), 2)
  assert(second.revocation?.status === 'unknown', 'second offline run did not stay UNKNOWN')
  return 'UNKNOWN twice; cache disabled'
})

test('revocation rejects missing/ranged versions as usage errors', () => {
  const missing = run(['revocation', 'left-pad', '--json'])
  const missingReport = parseReport(missing, 2)
  assert(/exact version/.test(missingReport.error || ''), 'missing-version error is unclear')
  assert(missingReport.checks[0].id === 'SC-00', 'usage error did not produce SC-00')
  const ranged = run(['revocation', 'lodash@^4.17.19', '--json'])
  const rangedReport = parseReport(ranged, 2)
  assert(/exact semver/.test(rangedReport.error || ''), 'ranged-version error is unclear')
  return 'missing and ranged versions rejected with exit 2'
})

test('help lists sbom/revocation, --cdx and the exit-code contract', () => {
  const result = run(['help'])
  assert(result.status === 0, `exit ${result.status}`)
  assert(result.stdout.includes('testatum sbom'), 'sbom command missing from help')
  assert(result.stdout.includes('testatum revocation'), 'revocation command missing from help')
  assert(result.stdout.includes('--cdx'), '--cdx missing from help')
  assert(result.stdout.includes('0 pass / 1 fail / 2 unknown'), 'exit-code line missing')
  assert(result.stdout.includes('never cached'), 'no-cache note missing')
  return 'sbom/revocation/--cdx/exit codes documented'
})

test('policy human output mentions CycloneDX, OSV and the 0/1/2 contract', () => {
  const result = run(['policy'])
  assert(result.status === 0, `exit ${result.status}`)
  assert(result.stdout.includes('0 = pass; 1 = fail; 2 = unknown'), 'exit-code line missing')
  assert(result.stdout.includes('SC-10'), 'SC-10 missing')
  assert(result.stdout.includes('CycloneDX'), 'CycloneDX status missing')
  assert(result.stdout.includes('OSV'), 'OSV status missing')
  return 'human-readable policy with v0.2 statuses'
})

// ---------------------------------------------------------------------------

const width = Math.max(...results.map((item) => item.name.length), 5)
console.log(`\ntestatum v0.2 end-to-end tests (node ${process.version})\n`)
console.log(`${'RESULT'.padEnd(7)} ${'TEST'.padEnd(width)}  DETAIL`)
console.log(`${'-'.repeat(7)} ${'-'.repeat(width)}  ${'-'.repeat(40)}`)
for (const item of results) {
  console.log(`${(item.ok ? 'PASS' : 'FAIL').padEnd(7)} ${item.name.padEnd(width)}  ${item.detail.replace(/\n/g, '\n' + ' '.repeat(width + 10))}`)
}
console.log(`\n${results.length - failed} passed, ${failed} failed`)

if (failed > 0) process.exitCode = 1
