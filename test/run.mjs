#!/usr/bin/env node
/**
 * End-to-end tests for the testatum v0.1 prototype.
 *
 * Network is required for the npm targets (pinned versions). The tests never
 * install packages and never execute fixture lifecycle scripts.
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

function run(args) {
  return spawnSync(process.execPath, [CLI, ...args], {
    cwd: ROOT,
    encoding: 'utf8',
    timeout: 120_000,
    env: { ...process.env },
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

test('policy --json: 10 requirements + exit codes', () => {
  const result = run(['policy', '--json'])
  assert(result.status === 0, `exit ${result.status}`)
  const policy = JSON.parse(result.stdout)
  assert(policy.schema === 'testatum/1', 'schema mismatch')
  assert(policy.requirements.length === 10, `got ${policy.requirements.length} requirements`)
  assert(policy.exitCodes['0'] === 'pass' && policy.exitCodes['1'] === 'fail', 'exit code contract incomplete')
  assert(policy.requirements.some((item) => item.id === 'SC-03'), 'SC-03 missing')
  return '10 requirements, 0/1/2 contract'
})

test('scan fixtures/clean-minimal: exit 0 / pass', () => {
  const result = run(['scan', 'fixtures/clean-minimal', '--json'])
  const report = parseReport(result, 0)
  assert(report.verdict === 'pass', `verdict ${report.verdict}`)
  assert(check('SC-03', 'PASS', report), 'SC-03 is not PASS')
  assert(check('SC-04', 'PASS', report), 'SC-04 is not PASS')
  assert(check('SC-07', 'PASS', report), 'SC-07 is not PASS')
  return '3/3 PASS'
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

test('verify dsh-permission-rules@0.8.0: exit 2 / digest PASS, signature+provenance UNKNOWN', () => {
  const result = run(['verify', 'dsh-permission-rules@0.8.0', '--json'])
  const report = parseReport(result, 2)
  assert(report.verdict === 'unknown', `verdict ${report.verdict}`)
  assert(check('SC-07', 'PASS', report), 'artifact digest is not PASS')
  const signature = check('SC-01', 'UNKNOWN', report)
  assert(signature && /does not verify/.test(signature.reason), 'signature not UNKNOWN/unverified')
  const provenance = report.checks.find((item) => item.id === 'SC-07' && item.title === 'provenance')
  assert(provenance && provenance.status === 'UNKNOWN', 'provenance is not UNKNOWN')
  assert(/does not verify/.test(provenance.reason), 'provenance reason does not state the limitation')
  return 'digest PASS; 2 UNKNOWN; exit 2'
})

test('verify dsh-auto-review@0.15.1: exit 2 / never promotes provenance to PASS', () => {
  const result = run(['verify', 'dsh-auto-review@0.15.1', '--json'])
  const report = parseReport(result, 2)
  assert(report.verdict === 'unknown', `verdict ${report.verdict}`)
  assert(report.summary.pass >= 1 && report.summary.unknown >= 2, 'unexpected summary')
  return 'exit 2; provenance/signature UNKNOWN'
})

test('policy human output contains the 0/1/2 contract', () => {
  const result = run(['policy'])
  assert(result.status === 0, `exit ${result.status}`)
  assert(result.stdout.includes('0 = pass; 1 = fail; 2 = unknown'), 'exit-code line missing')
  assert(result.stdout.includes('SC-10'), 'SC-10 missing')
  return 'human-readable policy'
})

// ---------------------------------------------------------------------------

const width = Math.max(...results.map((item) => item.name.length), 5)
console.log(`\ntestatum v0.1 end-to-end tests (node ${process.version})\n`)
console.log(`${'RESULT'.padEnd(7)} ${'TEST'.padEnd(width)}  DETAIL`)
console.log(`${'-'.repeat(7)} ${'-'.repeat(width)}  ${'-'.repeat(40)}`)
for (const item of results) {
  console.log(`${(item.ok ? 'PASS' : 'FAIL').padEnd(7)} ${item.name.padEnd(width)}  ${item.detail.replace(/\n/g, '\n' + ' '.repeat(width + 10))}`)
}
console.log(`\n${results.length - failed} passed, ${failed} failed`)

if (failed > 0) process.exitCode = 1
