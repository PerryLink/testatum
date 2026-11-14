#!/usr/bin/env node
/**
 * testatum v0.1 — a single-file, zero-dependency supply-chain checker prototype.
 *
 * Scope (deliberately small):
 *   - static inspection only; package code and lifecycle scripts are NEVER executed
 *   - no cryptographic signature or provenance verification
 *   - no revocation-feed fetching or verification
 *
 * Exit codes (also printed by `testatum policy`):
 *   0 = pass, 1 = fail, 2 = unknown (including "evidence could not be verified")
 *
 * JSON output uses schema `testatum/1`.
 */

import { createHash } from 'node:crypto'
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs'
import { basename, join, resolve, sep } from 'node:path'
import { gunzipSync } from 'node:zlib'

const VERSION = '0.1.0'
const SCHEMA = 'testatum/1'
const REGISTRY = (process.env.TESTATUM_REGISTRY || 'https://registry.npmjs.org').replace(/\/+$/, '')
const MAX_TARBALL_BYTES = 32 * 1024 * 1024
const MAX_JSON_BYTES = 8 * 1024 * 1024
const FETCH_TIMEOUT_MS = 30_000

const LIFECYCLE = ['preinstall', 'install', 'postinstall', 'prepare']
const LOCKFILES = ['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lockb']

// Partial closed set. Unknown-but-well-formed IDs are reported as UNKNOWN rather
// than silently promoted to PASS; v0.1 does not claim the set is authoritative.
const KNOWN_CAPABILITIES = new Set([
  'tools:register',
  'tools:unregister',
  'network:egress',
  'network:ingress',
  'fs:read',
  'fs:write',
  'sessions:read',
  'sessions:write',
  'subprocess',
  'shell',
  'exec',
  'listen',
  'process',
  'plugin:install',
  'remote:expose',
])

const HIGH_RISK_CAPABILITIES = new Set([
  'subprocess',
  'shell',
  'exec',
  'fs:write',
  'network:egress',
  'network:ingress',
  'listen',
  'process',
  'plugin:install',
  'remote:expose',
])

const LIMITATIONS = [
  'Static inspection only: package code and lifecycle scripts are never executed.',
  'v0.1 does not cryptographically verify signatures or provenance; presence is UNKNOWN, never PASS.',
  'Revocation feeds are not fetched or verified in v0.1; absence is UNKNOWN, not PASS.',
  'Capability checks cover declaration shape and dangerous literals, not AST or runtime behavior.',
  'pnpm/yarn lockfile integrity coverage is heuristic; package-lock parsing is structural.',
  'Registry metadata and tarballs are point-in-time evidence; pin the verified digest before install.',
]

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function hasOwn(object, key) {
  return Object.prototype.hasOwnProperty.call(object, key)
}

function sha512Base64(buffer) {
  return createHash('sha512').update(buffer).digest('base64')
}

function sha1Hex(buffer) {
  return createHash('sha1').update(buffer).digest('hex')
}

function extractSha512(integrity) {
  if (typeof integrity !== 'string') return null
  for (const token of integrity.trim().split(/\s+/)) {
    if (token.startsWith('sha512-') && token.length > 'sha512-'.length) return token.slice('sha512-'.length)
  }
  return null
}

function short(value, limit = 160) {
  const text = String(value ?? '')
  return text.length > limit ? `${text.slice(0, limit - 1)}…` : text
}

function makeCheck(id, title, status, reason, evidence) {
  const check = { id, title, status, reason }
  if (evidence !== undefined) check.evidence = evidence
  return check
}

function summarize(dsh) {
  if (!isObject(dsh)) return null
  return {
    manifestVersion: dsh.manifestVersion ?? null,
    capabilities: Array.isArray(dsh.capabilities) ? dsh.capabilities : null,
    hasCapabilities: hasOwn(dsh, 'capabilities'),
    hasAttestation: isObject(dsh.attestation) || hasOwn(dsh, 'attestation'),
    hasSignature: hasOwn(dsh, 'signature'),
    hasSbom: isObject(dsh.sbom) || hasOwn(dsh, 'sbom'),
    hasRevocationFeed: typeof dsh.revocationFeed === 'string',
    installScripts: Array.isArray(dsh.installScripts) ? dsh.installScripts : null,
    keys: Object.keys(dsh).sort(),
  }
}

// ---------------------------------------------------------------------------
// JSON / network
// ---------------------------------------------------------------------------

async function fetchJson(url, timeoutMs = FETCH_TIMEOUT_MS) {
  const response = await fetch(url, {
    headers: {
      accept: 'application/json',
      'user-agent': `testatum/${VERSION}`,
    },
    signal: AbortSignal.timeout(timeoutMs),
  })
  if (!response.ok) throw new Error(`HTTP ${response.status} for ${url}`)
  const text = await response.text()
  if (text.length > MAX_JSON_BYTES) throw new Error(`response too large (${text.length} bytes) for ${url}`)
  try {
    return JSON.parse(text)
  } catch (error) {
    throw new Error(`invalid JSON from ${url}: ${error.message}`)
  }
}

async function fetchBuffer(url, timeoutMs = FETCH_TIMEOUT_MS) {
  const response = await fetch(url, {
    headers: { 'user-agent': `testatum/${VERSION}` },
    redirect: 'follow',
    signal: AbortSignal.timeout(timeoutMs),
  })
  if (!response.ok) throw new Error(`HTTP ${response.status} for ${url}`)
  const declared = Number(response.headers.get('content-length') || 0)
  if (declared > MAX_TARBALL_BYTES) throw new Error(`tarball too large (${declared} bytes)`)
  const arrayBuffer = await response.arrayBuffer()
  if (arrayBuffer.byteLength > MAX_TARBALL_BYTES) {
    throw new Error(`tarball too large (${arrayBuffer.byteLength} bytes)`)
  }
  return Buffer.from(arrayBuffer)
}

function encodePackageName(name) {
  return name.startsWith('@') ? name.replace('/', '%2F') : encodeURIComponent(name)
}

function parseSpec(input) {
  if (input.startsWith('@')) {
    const at = input.lastIndexOf('@')
    if (at > 0) return { name: input.slice(0, at), version: input.slice(at + 1) || null }
    return { name: input, version: null }
  }
  const at = input.indexOf('@')
  if (at > 0) return { name: input.slice(0, at), version: input.slice(at + 1) || null }
  return { name: input, version: null }
}

async function fetchVersion(name, version) {
  const encoded = encodePackageName(name)
  const url = version
    ? `${REGISTRY}/${encoded}/${encodeURIComponent(version)}`
    : `${REGISTRY}/${encoded}/latest`
  const meta = await fetchJson(url)
  if (!isObject(meta) || typeof meta.version !== 'string') {
    throw new Error(`registry returned no version metadata for ${name}${version ? `@${version}` : ''}`)
  }
  return { ...meta, name: meta.name || name }
}

// ---------------------------------------------------------------------------
// tarball inspection (in memory; never extracted to disk)
// ---------------------------------------------------------------------------

function align512(value) {
  return Math.ceil(value / 512) * 512
}

function readCString(buffer, offset, length) {
  const slice = buffer.subarray(offset, offset + length)
  const zero = slice.indexOf(0)
  return slice.subarray(0, zero === -1 ? slice.length : zero).toString('utf8')
}

function parseOctal(buffer, offset, length) {
  const text = readCString(buffer, offset, length).trim()
  if (!text) return 0
  const value = Number.parseInt(text, 8)
  return Number.isFinite(value) && value >= 0 ? value : 0
}

function parsePaxRecords(buffer) {
  const records = {}
  let offset = 0
  while (offset < buffer.length) {
    const space = buffer.indexOf(0x20, offset)
    if (space === -1) break
    const length = Number.parseInt(buffer.subarray(offset, space).toString('ascii'), 10)
    if (!Number.isFinite(length) || length <= 0 || offset + length > buffer.length) break
    const record = buffer.subarray(space + 1, offset + length - 1).toString('utf8')
    const equals = record.indexOf('=')
    if (equals > 0) records[record.slice(0, equals)] = record.slice(equals + 1)
    offset += length
  }
  return records
}

function parseTar(gzipped) {
  const buffer = gunzipSync(gzipped)
  const entries = []
  let offset = 0
  let longName = null
  let paxPath = null

  while (offset + 512 <= buffer.length) {
    const header = buffer.subarray(offset, offset + 512)
    if (header.every((byte) => byte === 0)) break

    const size = parseOctal(header, 124, 12)
    const type = String.fromCharCode(header[156] || 0x30)
    let name = readCString(header, 0, 100)
    const prefix = readCString(header, 345, 155)
    if (prefix) name = `${prefix}/${name}`

    const dataStart = offset + 512
    if (type === 'x' || type === 'g') {
      const pax = parsePaxRecords(buffer.subarray(dataStart, Math.min(dataStart + size, buffer.length)))
      if (pax.path) paxPath = pax.path
      offset = dataStart + align512(size)
      continue
    }
    if (type === 'L') {
      longName = readCString(buffer, dataStart, size).replace(/\0.*$/s, '')
      offset = dataStart + align512(size)
      continue
    }

    const finalName = paxPath || longName || name
    paxPath = null
    longName = null
    entries.push({
      name: finalName,
      size,
      type,
      dataStart,
    })
    offset = dataStart + align512(size)
  }

  return { buffer, entries }
}

function readTarManifest(tar) {
  const candidates = tar.entries.filter((entry) => {
    if (!/(^|\/)package\.json$/.test(entry.name)) return false
    return entry.type !== '5'
  })
  if (!candidates.length) return null
  candidates.sort((a, b) => a.name.split('/').length - b.name.split('/').length)
  const entry = candidates[0]
  const text = tar.buffer.subarray(entry.dataStart, Math.min(entry.dataStart + entry.size, tar.buffer.length)).toString('utf8')
  return { manifest: JSON.parse(text), path: entry.name }
}

function tarballStats(tar) {
  const files = tar.entries.filter((entry) => entry.type !== '5' && !entry.name.endsWith('/'))
  const names = files.map((entry) => entry.name)
  return {
    fileCount: files.length,
    bindingGyp: names.some((name) => basename(name) === 'binding.gyp'),
    npmrc: names.some((name) => basename(name) === '.npmrc'),
    hasInstallJs: names.some((name) => /(^|\/)(install|preinstall|postinstall)\.(js|cjs|mjs)$/.test(name)),
    topLevel: [...new Set(names.map((name) => name.split('/')[1]).filter(Boolean))].sort().slice(0, 40),
  }
}

async function loadTarball(meta) {
  const url = meta?.dist?.tarball
  if (typeof url !== 'string' || !url) return { buffer: null, error: 'dist.tarball missing' }
  try {
    const buffer = await fetchBuffer(url)
    try {
      const tar = parseTar(buffer)
      const parsed = readTarManifest(tar)
      return {
        buffer,
        manifest: parsed?.manifest || null,
        manifestPath: parsed?.path || null,
        stats: tarballStats(tar),
        error: null,
      }
    } catch (error) {
      return { buffer, manifest: null, stats: null, error: `tarball parse failed: ${error.message}` }
    }
  } catch (error) {
    return { buffer: null, manifest: null, stats: null, error: error.message }
  }
}

// ---------------------------------------------------------------------------
// local filesystem inspection
// ---------------------------------------------------------------------------

function loadLocalPackage(dir) {
  const file = join(dir, 'package.json')
  if (!existsSync(file)) throw new Error(`no package.json in ${dir}`)
  let manifest
  try {
    manifest = JSON.parse(readFileSync(file, 'utf8'))
  } catch (error) {
    throw new Error(`invalid package.json in ${dir}: ${error.message}`)
  }
  if (!isObject(manifest)) throw new Error(`package.json in ${dir} is not an object`)
  return { manifest, file: resolve(file) }
}

function walkFiles(root, maxFiles = 20_000) {
  const skip = new Set(['node_modules', '.git', '.cache', 'coverage'])
  const files = []
  let truncated = false
  const stack = ['']
  while (stack.length) {
    const relativeDir = stack.pop()
    const absoluteDir = relativeDir ? join(root, relativeDir) : root
    let entries
    try {
      entries = readdirSync(absoluteDir, { withFileTypes: true })
    } catch {
      continue
    }
    for (const entry of entries) {
      const relative = relativeDir ? join(relativeDir, entry.name) : entry.name
      if (entry.isDirectory()) {
        if (!skip.has(entry.name)) stack.push(relative)
      } else if (entry.isFile()) {
        files.push(relative.split(sep).join('/'))
        if (files.length >= maxFiles) {
          truncated = true
          return { files, truncated }
        }
      }
    }
  }
  files.sort()
  return { files, truncated }
}

// ---------------------------------------------------------------------------
// checks
// ---------------------------------------------------------------------------

function checkLifecycle(manifest, { source, bindingGyp = false }) {
  const scripts = isObject(manifest.scripts) ? manifest.scripts : {}
  const present = LIFECYCLE.filter((key) => hasOwn(scripts, key) && String(scripts[key] ?? '').trim() !== '')
  const emptyKeys = LIFECYCLE.filter((key) => hasOwn(scripts, key) && String(scripts[key] ?? '').trim() === '')
  const declared = Array.isArray(manifest?.dsh?.installScripts) ? manifest.dsh.installScripts : null
  const scriptsOfInterest = {}
  for (const key of LIFECYCLE) {
    if (hasOwn(scripts, key)) scriptsOfInterest[key] = short(scripts[key], 240)
  }

  let status
  let reason
  if (present.length) {
    status = 'FAIL'
    reason = `lifecycle script(s) present: ${present.join(', ')}`
    if (present.includes('prepare')) {
      reason += source === 'tarball'
        ? '; prepare must not ship in a published artifact'
        : '; dev-only prepare must still be gated on any git install'
    }
    if (bindingGyp) reason += '; binding.gyp also present'
  } else if (bindingGyp) {
    status = 'UNKNOWN'
    reason = 'binding.gyp present: implicit node-gyp install path requires review'
  } else {
    status = 'PASS'
    reason = 'no preinstall/install/postinstall/prepare; no binding.gyp'
  }

  return makeCheck('SC-03', 'lifecycle scripts', status, reason, {
    source,
    scripts: scriptsOfInterest,
    lifecycle: present,
    emptyLifecycleKeys: emptyKeys,
    declaredInstallScripts: declared,
    bindingGyp: Boolean(bindingGyp),
  })
}

function collectDangerousStrings(value, path, out, depth = 0) {
  if (depth > 8 || out.length >= 10) return
  if (typeof value === 'string') {
    if (/danger[-_ ]?full[-_ ]?access/i.test(value) || /(^|[\\/])\.credentials\.ya?ml$/i.test(value)) {
      out.push({ path, value: short(value, 120) })
    }
    return
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => collectDangerousStrings(item, `${path}[${index}]`, out, depth + 1))
    return
  }
  if (isObject(value)) {
    for (const [key, item] of Object.entries(value)) {
      collectDangerousStrings(item, path ? `${path}.${key}` : key, out, depth + 1)
    }
  }
}

function isKnownCapability(capability) {
  if (KNOWN_CAPABILITIES.has(capability)) return true
  if (/^client:[a-z0-9-]+$/.test(capability)) return true
  if (/^credentials:[a-z0-9-]+$/.test(capability)) return true
  if (/^tools:[a-z0-9-]+$/.test(capability)) return true
  return false
}

function checkCapabilities(manifest) {
  const dsh = manifest.dsh
  if (!isObject(dsh)) {
    return makeCheck('SC-04', 'capability declaration', 'UNKNOWN', 'no dsh block; capabilities cannot be checked', {
      hasDsh: false,
    })
  }
  if (!hasOwn(dsh, 'capabilities')) {
    return makeCheck('SC-04', 'capability declaration', 'UNKNOWN', 'dsh.capabilities missing', {
      dshKeys: Object.keys(dsh).sort(),
    })
  }
  const capabilities = dsh.capabilities
  if (!Array.isArray(capabilities)) {
    return makeCheck('SC-04', 'capability declaration', 'FAIL', 'dsh.capabilities is not an array', {
      type: typeof capabilities,
    })
  }
  const nonStrings = capabilities.filter((item) => typeof item !== 'string' || item.trim() === '')
  if (nonStrings.length) {
    return makeCheck('SC-04', 'capability declaration', 'FAIL', 'dsh.capabilities contains non-string/empty entries', {
      capabilities,
    })
  }

  const dangerous = []
  collectDangerousStrings(dsh, 'dsh', dangerous)
  if (dangerous.length) {
    return makeCheck('SC-04', 'capability declaration', 'FAIL',
      `dangerous literal(s) present: ${dangerous.map((item) => item.path).join(', ')}`, { dangerous })
  }

  const unrecognized = capabilities.filter((capability) => !isKnownCapability(capability))
  const highRisk = capabilities.filter((capability) => HIGH_RISK_CAPABILITIES.has(capability))
  if (unrecognized.length) {
    return makeCheck('SC-04', 'capability declaration', 'UNKNOWN',
      `unrecognized capability id(s): ${unrecognized.join(', ')}`, { capabilities, unrecognized, highRisk })
  }

  const suffix = highRisk.length ? `; high-risk declared: ${highRisk.join(', ')}` : ''
  const label = capabilities.length === 1 ? '1 capability' : `${capabilities.length} capabilities`
  return makeCheck('SC-04', 'capability declaration', 'PASS',
    `${label} declared${suffix}`, { capabilities, highRisk })
}

function checkNpmLockfile(dir, name, text, evidence) {
  const lock = JSON.parse(text)
  evidence.lockfileVersion = lock.lockfileVersion ?? null
  const missing = []
  let entries = 0
  let skipped = 0

  if (isObject(lock.packages)) {
    for (const [key, value] of Object.entries(lock.packages)) {
      if (!key) continue
      const localLink = value?.link === true ||
        (typeof value?.resolved === 'string' && value.resolved.startsWith('file:'))
      if (localLink) {
        skipped += 1
        continue
      }
      entries += 1
      if (typeof value?.integrity !== 'string' || !value.integrity) missing.push(key)
    }
  } else if (isObject(lock.dependencies)) {
    const visit = (dependencies) => {
      for (const [key, value] of Object.entries(dependencies || {})) {
        entries += 1
        if (typeof value?.integrity !== 'string' || !value.integrity) missing.push(key)
        if (isObject(value?.dependencies)) visit(value.dependencies)
      }
    }
    visit(lock.dependencies)
  } else {
    return makeCheck('SC-07', 'dependency lockfile integrity', 'UNKNOWN',
      `${name} has neither packages nor dependencies; nothing to check`, { ...evidence, file: name })
  }

  Object.assign(evidence, {
    file: name,
    entries,
    covered: entries - missing.length,
    missing: missing.length,
    skippedLocalLinks: skipped,
    missingSample: missing.slice(0, 5),
  })
  if (entries === 0) {
    return makeCheck('SC-07', 'dependency lockfile integrity', 'PASS',
      `${name} present; no external dependency entries to check`, evidence)
  }
  if (missing.length) {
    return makeCheck('SC-07', 'dependency lockfile integrity', 'FAIL',
      `${missing.length}/${entries} dependency entries lack integrity (e.g. ${missing.slice(0, 3).join(', ')})`, evidence)
  }
  return makeCheck('SC-07', 'dependency lockfile integrity', 'PASS',
    `all ${entries} dependency entries carry integrity`, evidence)
}

function checkPnpmLockfile(dir, name, text, evidence) {
  const version = (text.match(/^lockfileVersion:\s*'?([^'\n]+)'?/m) || [])[1] || null
  let section = text
  const packagesIndex = text.search(/^packages:\s*$/m)
  if (packagesIndex >= 0) {
    section = text.slice(packagesIndex)
    const snapshotsIndex = section.search(/^snapshots:\s*$/m)
    if (snapshotsIndex >= 0) section = section.slice(0, snapshotsIndex)
  }
  const entries = [...section.matchAll(/^ {2}([^ \t].*):\s*$/gm)].map((match) => match[1])
  const integrityFields = (section.match(/\bintegrity:\s*\S+/g) || []).length
  Object.assign(evidence, {
    file: name,
    lockfileVersion: version,
    entries: entries.length,
    integrityFields,
    heuristic: true,
  })
  if (entries.length === 0) {
    return makeCheck('SC-07', 'dependency lockfile integrity', 'PASS',
      `${name} present; no package entries parsed`, evidence)
  }
  if (integrityFields === 0) {
    return makeCheck('SC-07', 'dependency lockfile integrity', 'FAIL',
      `${name}: ${entries.length} package entries but no integrity fields`, evidence)
  }
  if (integrityFields < entries.length) {
    return makeCheck('SC-07', 'dependency lockfile integrity', 'FAIL',
      `${entries.length - integrityFields}/${entries.length} pnpm package entries lack integrity`, evidence)
  }
  return makeCheck('SC-07', 'dependency lockfile integrity', 'PASS',
    `pnpm lockfile: ${integrityFields} integrity fields cover ${entries.length} entries`, evidence)
}

function checkYarnLockfile(dir, name, text, evidence) {
  const entries = (text.match(/^[^\s#].*:\s*$/gm) || []).length
  const integrityFields = (text.match(/^\s+integrity\s+\S+/gm) || []).length
  Object.assign(evidence, { file: name, entries, integrityFields, heuristic: true })
  if (entries === 0) {
    return makeCheck('SC-07', 'dependency lockfile integrity', 'PASS',
      `${name} present; no entries parsed`, evidence)
  }
  if (integrityFields === 0) {
    return makeCheck('SC-07', 'dependency lockfile integrity', 'UNKNOWN',
      `${name}: no integrity fields found (yarn may omit them for git/file deps)`, evidence)
  }
  if (integrityFields < entries) {
    return makeCheck('SC-07', 'dependency lockfile integrity', 'UNKNOWN',
      `${name}: ${integrityFields}/${entries} entries have integrity (heuristic)`, evidence)
  }
  return makeCheck('SC-07', 'dependency lockfile integrity', 'PASS',
    `${name}: ${integrityFields} integrity fields for ${entries} entries`, evidence)
}

function checkLocalIntegrity(dir) {
  const found = LOCKFILES.filter((name) => existsSync(join(dir, name)))
  const evidence = { found }
  if (found.length === 0) {
    return makeCheck('SC-07', 'dependency lockfile integrity', 'UNKNOWN', 'no lockfile found', evidence)
  }
  if (found.length > 1) {
    return makeCheck('SC-07', 'dependency lockfile integrity', 'UNKNOWN',
      `multiple lockfiles present: ${found.join(', ')}`, evidence)
  }
  const name = found[0]
  evidence.file = name
  try {
    if (name === 'package-lock.json' || name === 'npm-shrinkwrap.json') {
      return checkNpmLockfile(dir, name, readFileSync(join(dir, name), 'utf8'), evidence)
    }
    if (name === 'pnpm-lock.yaml') {
      return checkPnpmLockfile(dir, name, readFileSync(join(dir, name), 'utf8'), evidence)
    }
    if (name === 'yarn.lock') {
      return checkYarnLockfile(dir, name, readFileSync(join(dir, name), 'utf8'), evidence)
    }
    return makeCheck('SC-07', 'dependency lockfile integrity', 'UNKNOWN',
      `${name} is a binary lockfile; v0.1 does not parse it`, evidence)
  } catch (error) {
    return makeCheck('SC-07', 'dependency lockfile integrity', 'FAIL',
      `cannot parse ${name}: ${error.message}`, evidence)
  }
}

function checkRemoteIntegrity(meta, artifact) {
  const dist = isObject(meta.dist) ? meta.dist : {}
  const evidence = {
    integrity: dist.integrity ?? null,
    shasum: dist.shasum ?? null,
    tarball: dist.tarball ?? null,
    declaredFileCount: dist.fileCount ?? null,
  }
  if (artifact.stats) Object.assign(evidence, { tarballFiles: artifact.stats.fileCount, bindingGyp: artifact.stats.bindingGyp })
  if (typeof dist.integrity !== 'string' || !dist.integrity) {
    return makeCheck('SC-07', 'artifact digest', 'FAIL', 'dist.integrity missing; artifact bytes are not pinned', evidence)
  }
  const expected = extractSha512(dist.integrity)
  if (!expected) {
    return makeCheck('SC-07', 'artifact digest', 'FAIL', 'dist.integrity has no sha512 token', evidence)
  }
  if (!artifact.buffer) {
    return makeCheck('SC-07', 'artifact digest', 'UNKNOWN',
      `dist.integrity present but tarball unavailable (${artifact.error || 'unknown error'})`, evidence)
  }
  const actual = sha512Base64(artifact.buffer)
  evidence.actualSha512 = `sha512-${actual}`
  if (actual !== expected) {
    return makeCheck('SC-07', 'artifact digest', 'FAIL',
      'sha512 mismatch: tarball bytes do not match dist.integrity', evidence)
  }
  if (artifact.manifest) {
    evidence.manifest = { name: artifact.manifest.name ?? null, version: artifact.manifest.version ?? null }
    if (artifact.manifest.name !== meta.name || artifact.manifest.version !== meta.version) {
      return makeCheck('SC-07', 'artifact digest', 'FAIL',
        `tarball package.json is ${artifact.manifest.name}@${artifact.manifest.version}, expected ${meta.name}@${meta.version}`,
        evidence)
    }
  }
  if (typeof dist.shasum === 'string' && dist.shasum) {
    const actualSha1 = sha1Hex(artifact.buffer)
    evidence.actualSha1 = actualSha1
    if (actualSha1 !== dist.shasum) {
      return makeCheck('SC-07', 'artifact digest', 'FAIL', 'sha1 shasum mismatch', evidence)
    }
  }
  return makeCheck('SC-07', 'artifact digest', 'PASS', 'sha512 matches tarball', evidence)
}

async function checkProvenance(meta, artifact) {
  const dist = isObject(meta.dist) ? meta.dist : {}
  const declared = artifact.manifest?.dsh?.attestation
  const evidence = {
    npmAttestations: dist.attestations ?? null,
    declaredInManifest: declared ? true : false,
  }
  if (!dist.attestations) {
    const suffix = declared ? '; self-declared dsh.attestation is unverified' : ''
    return makeCheck('SC-07', 'provenance', 'UNKNOWN',
      `no npm provenance; source/commit/builder cannot be bound${suffix}`, evidence)
  }
  if (!isObject(dist.attestations) || typeof dist.attestations.url !== 'string') {
    return makeCheck('SC-07', 'provenance', 'UNKNOWN',
      'dist.attestations declared but has no attestation URL', evidence)
  }
  try {
    const bundle = await fetchJson(dist.attestations.url)
    const list = Array.isArray(bundle.attestations) ? bundle.attestations : []
    evidence.fetched = {
      count: list.length,
      predicateTypes: [...new Set(list.map((item) => item?.predicateType).filter(Boolean))],
      mediaTypes: [...new Set(list.map((item) => item?.bundle?.mediaType).filter(Boolean))],
    }
    if (!list.length) {
      return makeCheck('SC-07', 'provenance', 'UNKNOWN',
        'attestation endpoint returned no attestations', evidence)
    }
    return makeCheck('SC-07', 'provenance', 'UNKNOWN',
      `npm attestation present (${list.length} bundle(s)) but v0.1 does not verify the bundle`, evidence)
  } catch (error) {
    return makeCheck('SC-07', 'provenance', 'UNKNOWN',
      `npm attestation declared but unreachable: ${short(error.message, 100)}`, evidence)
  }
}

function checkSignature(meta, artifact) {
  const dist = isObject(meta.dist) ? meta.dist : {}
  const npmSignatures = Array.isArray(dist.signatures) ? dist.signatures : []
  const declared = artifact.manifest?.dsh?.signature ?? artifact.manifest?.dsh?.attestation
  const evidence = {
    npmSignatureCount: npmSignatures.length,
    npmKeyids: [...new Set(npmSignatures.map((item) => item?.keyid).filter(Boolean))],
    declaredInManifest: declared ? true : false,
  }
  if (npmSignatures.length) {
    return makeCheck('SC-01', 'publisher signature', 'UNKNOWN',
      `${npmSignatures.length} npm registry signature(s) present; v0.1 does not verify them`, evidence)
  }
  if (declared) {
    return makeCheck('SC-01', 'publisher signature', 'UNKNOWN',
      'self-declared signature/attestation field present; unverified', evidence)
  }
  return makeCheck('SC-01', 'publisher signature', 'UNKNOWN',
    'no signature declared; cannot bind publisher identity to the artifact', evidence)
}

// ---------------------------------------------------------------------------
// report assembly
// ---------------------------------------------------------------------------

function buildReport({ command, target, checks, evidence = {}, error = null }) {
  const summary = {
    pass: checks.filter((check) => check.status === 'PASS').length,
    fail: checks.filter((check) => check.status === 'FAIL').length,
    unknown: checks.filter((check) => check.status === 'UNKNOWN').length,
    total: checks.length,
  }
  const verdict = summary.fail > 0 ? 'fail' : summary.unknown > 0 ? 'unknown' : 'pass'
  const exitCode = verdict === 'fail' ? 1 : verdict === 'unknown' ? 2 : 0
  const report = {
    schema: SCHEMA,
    tool: {
      name: 'testatum',
      version: VERSION,
      node: process.version,
      mode: 'static-only',
    },
    command,
    target,
    generatedAt: new Date().toISOString(),
    verdict,
    exitCode,
    summary,
    checks,
    evidence,
    limitations: LIMITATIONS,
  }
  if (error) report.error = short(error, 500)
  return report
}

function errorReport(command, target, error) {
  const check = makeCheck('SC-00', 'target resolution', 'UNKNOWN', short(error?.message || error, 200), null)
  return buildReport({ command, target, checks: [check], error: error?.message || String(error) })
}

function targetLabel(target) {
  if (!target) return 'unknown'
  if (target.type === 'dir') return `${target.name || '?'}@${target.version || '?'} (dir: ${target.path})`
  return `${target.name || '?'}@${target.version || '?'} (npm: ${target.registry || REGISTRY})`
}

function renderSummary(report) {
  const lines = []
  lines.push(`testatum ${VERSION} · ${report.command} · ${targetLabel(report.target)}`)
  lines.push(`verdict ${report.verdict.toUpperCase()} (exit ${report.exitCode}) — ` +
    `pass ${report.summary.pass} / fail ${report.summary.fail} / unknown ${report.summary.unknown}`)
  for (const check of report.checks) {
    lines.push(`  ${check.status.padEnd(7)} ${check.id.padEnd(9)} ${check.title}: ${check.reason}`)
  }
  if (report.error) lines.push(`  error: ${report.error}`)
  lines.push('  note: static checks only; no cryptographic signature/provenance verification in v0.1')
  return lines.join('\n')
}

// ---------------------------------------------------------------------------
// commands
// ---------------------------------------------------------------------------

async function scanDir(input) {
  const dir = resolve(input)
  const { manifest, file } = loadLocalPackage(dir)
  const walk = walkFiles(dir)
  const bindingGyp = existsSync(join(dir, 'binding.gyp')) || walk.files.some((name) => basename(name) === 'binding.gyp')
  const checks = [
    checkLifecycle(manifest, { source: 'dir', bindingGyp }),
    checkCapabilities(manifest),
    checkLocalIntegrity(dir),
  ]
  const files = isObject(manifest) && Array.isArray(manifest.files) ? manifest.files : null
  return buildReport({
    command: 'scan',
    target: {
      input,
      type: 'dir',
      name: manifest.name ?? null,
      version: manifest.version ?? null,
      path: dir,
      manifestPath: file,
    },
    checks,
    evidence: {
      package: {
        name: manifest.name ?? null,
        version: manifest.version ?? null,
        private: manifest.private === true,
        files,
        scripts: isObject(manifest.scripts) ? manifest.scripts : null,
        dsh: summarize(manifest.dsh),
        repository: manifest.repository ?? null,
      },
      tree: {
        fileCount: walk.files.length,
        truncated: walk.truncated,
        sample: walk.files.slice(0, 25),
        bindingGyp,
      },
    },
  })
}

async function scanNpm(input) {
  const spec = parseSpec(input)
  if (!spec.name) throw new Error(`invalid package spec: ${input}`)
  const meta = await fetchVersion(spec.name, spec.version)
  const artifact = await loadTarball(meta)
  const manifest = artifact.manifest || meta
  const source = artifact.manifest ? 'tarball' : 'registry-metadata'
  const checks = [
    checkLifecycle(manifest, { source, bindingGyp: artifact.stats?.bindingGyp || false }),
    checkCapabilities(manifest),
    checkRemoteIntegrity(meta, artifact),
  ]
  const files = Array.isArray(manifest.files) ? manifest.files : null
  return buildReport({
    command: 'scan',
    target: {
      input,
      type: 'npm',
      name: meta.name,
      version: meta.version,
      registry: REGISTRY,
      tarball: meta?.dist?.tarball ?? null,
    },
    checks,
    evidence: {
      package: {
        name: manifest.name ?? meta.name,
        version: manifest.version ?? meta.version,
        files,
        scripts: isObject(manifest.scripts) ? manifest.scripts : null,
        dsh: summarize(manifest.dsh),
        repository: manifest.repository ?? null,
        manifestSource: artifact.manifest ? `tarball:${artifact.manifestPath}` : 'registry metadata',
      },
      artifact: {
        integrity: meta?.dist?.integrity ?? null,
        shasum: meta?.dist?.shasum ?? null,
        fileCountDeclared: meta?.dist?.fileCount ?? null,
        fileCountInTarball: artifact.stats?.fileCount ?? null,
        bindingGyp: artifact.stats?.bindingGyp ?? null,
        npmrc: artifact.stats?.npmrc ?? null,
        tarballError: artifact.error,
      },
    },
  })
}

async function verifyNpm(input) {
  const spec = parseSpec(input)
  if (!spec.name) throw new Error(`invalid package spec: ${input}`)
  const meta = await fetchVersion(spec.name, spec.version)
  const artifact = await loadTarball(meta)
  const checks = [
    checkRemoteIntegrity(meta, artifact),
    checkSignature(meta, artifact),
    await checkProvenance(meta, artifact),
  ]
  return buildReport({
    command: 'verify',
    target: {
      input,
      type: 'npm',
      name: meta.name,
      version: meta.version,
      registry: REGISTRY,
      tarball: meta?.dist?.tarball ?? null,
    },
    checks,
    evidence: {
      dist: {
        integrity: meta?.dist?.integrity ?? null,
        shasum: meta?.dist?.shasum ?? null,
        attestations: meta?.dist?.attestations ?? null,
        signatureCount: Array.isArray(meta?.dist?.signatures) ? meta.dist.signatures.length : 0,
      },
      package: {
        name: artifact.manifest?.name ?? meta.name,
        version: artifact.manifest?.version ?? meta.version,
        repository: artifact.manifest?.repository ?? null,
        dsh: summarize(artifact.manifest?.dsh),
      },
      tarball: {
        fetched: Boolean(artifact.buffer),
        error: artifact.error,
        fileCount: artifact.stats?.fileCount ?? null,
      },
    },
  })
}

function policyRequirements() {
  return [
    { id: 'SC-01', title: 'artifact signature and verification', level: 'MUST', v01: 'presence only; verify reports UNKNOWN', default: 'strict missing evidence => DENY' },
    { id: 'SC-02', title: 'SBOM and dependency inventory', level: 'MUST', v01: 'not implemented (fields reported only)', default: 'strict new release without SBOM => DENY' },
    { id: 'SC-03', title: 'install scripts denied by default', level: 'MUST', v01: 'implemented for pre/install/postinstall/prepare', default: 'DENY in all modes' },
    { id: 'SC-04', title: 'capability declaration and consistency', level: 'MUST', v01: 'declaration shape + dangerous literals only', default: 'undeclared high risk => DENY/WARN' },
    { id: 'SC-05', title: 'CVE and vulnerability response', level: 'MUST', v01: 'not implemented', default: 'KEV/CVSS>=9 => DENY' },
    { id: 'SC-06', title: 'signed revocation list', level: 'MUST', v01: 'not implemented (policy only)', default: 'revoked/unreachable => DENY/WARN' },
    { id: 'SC-07', title: 'provenance and commit pinning', level: 'MUST', v01: 'digest verified; provenance presence only => UNKNOWN', default: 'strict missing provenance => DENY' },
    { id: 'SC-08', title: 'reproducible builds', level: 'MUST', v01: 'not implemented', default: 'strict missing evidence => DENY' },
    { id: 'SC-09', title: 'least privilege', level: 'MUST', v01: 'danger-full-access / credentials literal scan only', default: 'dangerous grant => DENY' },
    { id: 'SC-10', title: 'install audit log', level: 'MUST', v01: 'not implemented', default: 'strict without audit => DENY' },
  ]
}

function policyHuman() {
  const lines = []
  lines.push(`testatum ${VERSION} — DSH supply-chain policy (baseline v0.1, 2026-11-14)`)
  lines.push('')
  for (const item of policyRequirements()) {
    lines.push(`${item.id}  ${item.title}`)
    lines.push(`      v0.1: ${item.v01}`)
    lines.push(`      default: ${item.default}`)
  }
  lines.push('')
  lines.push('Modes: strict (CI/first-party) / balanced (community) / permissive (local experiments).')
  lines.push('Non-negotiable: install scripts DENY in every mode; revoked/KEV DENY in every mode;')
  lines.push('missing, expired or unreachable evidence is never reported as PASS.')
  lines.push('')
  lines.push('Exit codes: 0 = pass; 1 = fail; 2 = unknown (unverifiable evidence or usage error).')
  lines.push('v0.1 does not perform cryptographic verification and must not be used as a security gate.')
  return lines.join('\n')
}

function policyJson() {
  return {
    schema: SCHEMA,
    tool: { name: 'testatum', version: VERSION, node: process.version, mode: 'static-only' },
    command: 'policy',
    generatedAt: new Date().toISOString(),
    baseline: { name: 'DSH Plugin Supply-Chain Baseline', version: '0.1.0-draft', date: '2026-11-14' },
    requirements: policyRequirements(),
    modes: {
      strict: 'missing evidence => DENY; install scripts => DENY; revoked/KEV => DENY',
      balanced: 'missing evidence => WARN + explicit approval; install scripts => DENY; revoked/KEV => DENY',
      permissive: 'missing evidence => WARN; install scripts => DENY unless explicit audited override; revoked/KEV => DENY',
    },
    exitCodes: {
      0: 'pass',
      1: 'fail',
      2: 'unknown (including unverifiable evidence and usage errors)',
    },
    limitations: LIMITATIONS,
  }
}

function helpText() {
  return [
    `testatum ${VERSION} — static supply-chain checker prototype (schema ${SCHEMA})`,
    '',
    'Usage:',
    '  testatum scan <pkg|dir>   inspect manifest, lifecycle scripts, files and lockfile/digest',
    '  testatum verify <pkg>     inspect registry integrity, provenance and signature presence',
    '  testatum policy           print the 10 baseline requirements and exit-code contract',
    '  testatum version          print version',
    '  testatum help             print this help',
    '',
    'Options:',
    '  --json    JSON only (scan/verify already write JSON to stdout; suppress the stderr summary)',
    '',
    'Examples:',
    '  node testatum.mjs scan .',
    '  node testatum.mjs scan dsh-auto-review@0.15.1',
    '  node testatum.mjs verify dsh-permission-rules@0.8.0',
    '  node testatum.mjs policy --json',
    '',
    'Exit codes: 0 pass / 1 fail / 2 unknown. v0.1 never executes package code or lifecycle scripts.',
  ].join('\n')
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

async function main(argv) {
  const jsonOnly = argv.includes('--json')
  const args = argv.filter((arg) => arg !== '--json')
  const [command, ...rest] = args

  if (!command || command === 'help' || command === '--help' || command === '-h') {
    console.log(helpText())
    return 0
  }
  if (command === 'version' || command === '--version' || command === '-v') {
    console.log(VERSION)
    return 0
  }

  if (command === 'policy') {
    if (jsonOnly) {
      console.log(JSON.stringify(policyJson(), null, 2))
    } else {
      console.log(policyHuman())
    }
    return 0
  }

  if (command === 'scan') {
    const input = rest[0]
    if (!input) {
      console.error('testatum: scan requires <pkg|dir>')
      return 2
    }
    let report
    try {
      const targetPath = resolve(input)
      if (existsSync(targetPath) && statSync(targetPath).isDirectory()) {
        report = await scanDir(input)
      } else {
        report = await scanNpm(input)
      }
    } catch (error) {
      report = errorReport('scan', { input, type: input.startsWith('.') || input.includes('/') ? 'dir' : 'npm' }, error)
    }
    console.log(JSON.stringify(report, null, 2))
    if (!jsonOnly) console.error(renderSummary(report))
    return report.exitCode
  }

  if (command === 'verify') {
    const input = rest[0]
    if (!input) {
      console.error('testatum: verify requires <pkg>')
      return 2
    }
    let report
    try {
      const targetPath = resolve(input)
      if (existsSync(targetPath) && statSync(targetPath).isDirectory()) {
        throw new Error('verify expects an npm package spec, not a directory')
      }
      report = await verifyNpm(input)
    } catch (error) {
      report = errorReport('verify', { input, type: 'npm' }, error)
    }
    console.log(JSON.stringify(report, null, 2))
    if (!jsonOnly) console.error(renderSummary(report))
    return report.exitCode
  }

  console.error(`testatum: unknown command "${command}" (try: testatum help)`)
  return 2
}

main(process.argv.slice(2))
  .then((code) => {
    process.exitCode = code
  })
  .catch((error) => {
    console.error(`testatum: ${error?.stack || error}`)
    process.exitCode = 2
  })
