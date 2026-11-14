#!/usr/bin/env node
/**
 * testatum v0.2 — a single-file, zero-dependency supply-chain checker prototype.
 *
 * Scope (deliberately small):
 *   - static inspection only; package code and lifecycle scripts are NEVER executed
 *   - SBOM generation (CycloneDX 1.5) from a tarball or local source tree
 *   - on-demand OSV advisory lookup via the public API (never cached)
 *   - provenance/attestation PRESENCE only; no cryptographic verification
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

const VERSION = '0.2.0'
const SCHEMA = 'testatum/1'
const REGISTRY = (process.env.TESTATUM_REGISTRY || 'https://registry.npmjs.org').replace(/\/+$/, '')
const OSV_API = process.env.TESTATUM_OSV_API || 'https://api.osv.dev/v1/query'
const CDX_SPEC_VERSION = '1.5'
const CDX_SCHEMA = 'http://cyclonedx.org/schema/bom-1.5.schema.json'
const MAX_TARBALL_BYTES = 32 * 1024 * 1024
const MAX_JSON_BYTES = 8 * 1024 * 1024
const FETCH_TIMEOUT_MS = 30_000
const MAX_SBOM_FILES = 20_000
const MAX_SBOM_FILE_BYTES = 16 * 1024 * 1024
const MAX_SBOM_COMPONENTS = 2_000

const LIFECYCLE = ['preinstall', 'install', 'postinstall', 'prepare']
const LOCKFILES = ['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lockb']

// Partial closed set. Unknown-but-well-formed IDs are reported as UNKNOWN rather
// than silently promoted to PASS; v0.2 does not claim the set is authoritative.
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
  'v0.2 does not cryptographically verify signatures or provenance; attestation presence is evidence only, and the provenance check is always UNKNOWN.',
  'Revocation comes from the unsigned public OSV API. It is not a signed revocation list, and a PASS is only a point-in-time advisory query, never a proof that a version is safe.',
  'OSV results are never cached: every revocation invocation performs a fresh query. Network failure is UNKNOWN, not PASS.',
  'SBOMs are generated locally and are unsigned/not attested. For npm tarballs, dependency versions are declared semver ranges unless the tarball ships a lockfile; runtime dependency coverage is then partial.',
  'Local-directory file inventories exclude node_modules/.git/.cache/coverage and never hash symlinks; npm-tarball inventories cover the package payload only.',
  'Capability checks cover declaration shape and dangerous literals, not AST or runtime behavior.',
  'pnpm/yarn lockfile integrity coverage is heuristic; package-lock parsing is structural.',
  'Registry metadata, tarballs and OSV responses are point-in-time evidence; pin the verified digest before install.',
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

function sha256Hex(buffer) {
  return createHash('sha256').update(buffer).digest('hex')
}

function sha512Hex(buffer) {
  return createHash('sha512').update(buffer).digest('hex')
}

function deterministicUrn(seed) {
  const bytes = createHash('sha256').update(seed).digest().subarray(0, 16)
  bytes[6] = (bytes[6] & 0x0f) | 0x50
  bytes[8] = (bytes[8] & 0x3f) | 0x80
  const hex = bytes.toString('hex')
  return `urn:uuid:${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
}

function purlFor(name, version) {
  if (typeof name !== 'string' || !name) return null
  let encoded
  if (name.startsWith('@')) {
    const body = name.slice(1)
    const slash = body.indexOf('/')
    encoded = slash < 0
      ? `%40${encodeURIComponent(body)}`
      : `%40${encodeURIComponent(body.slice(0, slash))}/${encodeURIComponent(body.slice(slash + 1))}`
  } else {
    encoded = encodeURIComponent(name)
  }
  return `pkg:npm/${encoded}${version ? `@${encodeURIComponent(version)}` : ''}`
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

function describeError(error) {
  const message = error?.message || String(error)
  const cause = error?.cause
  if (typeof cause?.code === 'string' && cause.code) return `${message} (${cause.code})`
  return message
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

async function postJson(url, payload, timeoutMs = FETCH_TIMEOUT_MS) {
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      accept: 'application/json',
      'content-type': 'application/json',
      'user-agent': `testatum/${VERSION}`,
    },
    body: JSON.stringify(payload),
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

function normalizeTarPath(name) {
  return String(name || '').replace(/^\.\//, '').replace(/^package\//, '')
}

function readTarText(tar, exactPath) {
  const entry = tar.entries.find((item) => item.type !== '5' && normalizeTarPath(item.name) === exactPath)
  if (!entry) return null
  return tar.buffer.subarray(entry.dataStart, Math.min(entry.dataStart + entry.size, tar.buffer.length)).toString('utf8')
}

function tarFileInventory(tar, maxFiles = MAX_SBOM_FILES) {
  const files = new Map()
  for (const entry of tar.entries) {
    if (entry.type !== '0' && entry.type !== '7') continue
    const relative = normalizeTarPath(entry.name)
    if (!relative) continue
    const data = tar.buffer.subarray(entry.dataStart, Math.min(entry.dataStart + entry.size, tar.buffer.length))
    files.set(relative, { path: relative, size: data.length, sha256: sha256Hex(data) })
    if (files.size >= maxFiles) {
      return { files: [...files.values()].sort((a, b) => a.path.localeCompare(b.path)), truncated: true }
    }
  }
  return { files: [...files.values()].sort((a, b) => a.path.localeCompare(b.path)), truncated: false }
}

function filesDigest(files) {
  const hash = createHash('sha256')
  for (const file of files) hash.update(`${file.path}\0${file.size}\0${file.sha256}\n`)
  return hash.digest('hex')
}

async function loadTarball(meta) {
  const url = meta?.dist?.tarball
  if (typeof url !== 'string' || !url) return { buffer: null, tar: null, error: 'dist.tarball missing' }
  try {
    const buffer = await fetchBuffer(url)
    try {
      const tar = parseTar(buffer)
      const parsed = readTarManifest(tar)
      return {
        buffer,
        tar,
        manifest: parsed?.manifest || null,
        manifestPath: parsed?.path || null,
        stats: tarballStats(tar),
        error: null,
      }
    } catch (error) {
      return { buffer, tar: null, manifest: null, stats: null, error: `tarball parse failed: ${error.message}` }
    }
  } catch (error) {
    return { buffer: null, tar: null, manifest: null, stats: null, error: error.message }
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

function localFileInventory(dir, maxFiles = MAX_SBOM_FILES) {
  const walk = walkFiles(dir, maxFiles)
  const files = []
  let unreadable = 0
  let oversized = 0
  for (const relative of walk.files) {
    const absolute = join(dir, relative)
    try {
      if (statSync(absolute).size > MAX_SBOM_FILE_BYTES) {
        oversized += 1
        continue
      }
      const data = readFileSync(absolute)
      files.push({ path: relative, size: data.length, sha256: sha256Hex(data) })
    } catch {
      unreadable += 1
    }
  }
  return { files, truncated: walk.truncated, unreadable, oversized, scope: 'source-tree' }
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
      `${name} is a binary lockfile; testatum does not parse it`, evidence)
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
  const hasAttestations = hasOwn(dist, 'attestations') && dist.attestations !== null && dist.attestations !== false
  const url = isObject(dist.attestations) && typeof dist.attestations.url === 'string'
    ? dist.attestations.url
    : null
  const declaredPredicate = isObject(dist.attestations?.provenance)
    ? dist.attestations.provenance.predicateType ?? null
    : null
  const evidence = {
    present: Boolean(hasAttestations),
    verified: false,
    verification: 'not-implemented',
    status: hasAttestations ? 'present-unverified' : 'absent',
    npmAttestations: dist.attestations ?? null,
    url,
    declaredPredicateType: declaredPredicate,
    declaredInManifest: Boolean(declared),
    fetched: null,
    failure: null,
  }
  if (!hasAttestations) {
    const suffix = declared ? '; self-declared dsh.attestation is unverified' : ''
    return makeCheck('SC-07', 'provenance', 'UNKNOWN',
      `no npm provenance; source/commit/builder cannot be bound${suffix}; testatum does not verify provenance (UNKNOWN)`,
      evidence)
  }
  if (!url) {
    return makeCheck('SC-07', 'provenance', 'UNKNOWN',
      'npm attestations field present but has no attestation URL; presence recorded, testatum does not verify provenance (UNKNOWN)',
      evidence)
  }
  try {
    const bundle = await fetchJson(url)
    const list = Array.isArray(bundle.attestations) ? bundle.attestations : []
    const predicateTypes = [...new Set(list.map((item) => item?.predicateType).filter(Boolean))]
    evidence.fetched = {
      count: list.length,
      predicateTypes,
      mediaTypes: [...new Set(list.map((item) => item?.bundle?.mediaType).filter(Boolean))],
    }
    if (!list.length) {
      evidence.status = 'present-empty'
      return makeCheck('SC-07', 'provenance', 'UNKNOWN',
        'npm attestations field present but the endpoint returned no attestations; testatum does not verify provenance (UNKNOWN)',
        evidence)
    }
    evidence.status = 'present-unverified'
    return makeCheck('SC-07', 'provenance', 'UNKNOWN',
      `npm attestation present (${list.length} bundle(s)); testatum does not verify the bundle (presence only, UNKNOWN)`,
      evidence)
  } catch (error) {
    evidence.status = 'present-unreachable'
    evidence.failure = short(describeError(error), 160)
    return makeCheck('SC-07', 'provenance', 'UNKNOWN',
      `npm attestation present but unreachable (${short(describeError(error), 100)}); testatum does not verify the bundle (UNKNOWN)`,
      evidence)
  }
}

function provenanceSummary(check) {
  const evidence = isObject(check.evidence) ? check.evidence : {}
  return {
    present: Boolean(evidence.present),
    verified: false,
    verification: 'not-implemented',
    status: evidence.status || (evidence.present ? 'present-unverified' : 'absent'),
    source: evidence.present ? 'npm-attestations' : 'none',
    url: evidence.url ?? null,
    declaredPredicateType: evidence.declaredPredicateType ?? null,
    bundleCount: evidence.fetched?.count ?? null,
    predicateTypes: evidence.fetched?.predicateTypes ?? [],
    declaredInManifest: Boolean(evidence.declaredInManifest),
    reason: check.reason,
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
    verified: false,
  }
  if (npmSignatures.length) {
    return makeCheck('SC-01', 'publisher signature', 'UNKNOWN',
      `${npmSignatures.length} npm registry signature(s) present; testatum does not verify them (UNKNOWN)`, evidence)
  }
  if (declared) {
    return makeCheck('SC-01', 'publisher signature', 'UNKNOWN',
      'self-declared signature/attestation field present; testatum does not verify it (UNKNOWN)', evidence)
  }
  return makeCheck('SC-01', 'publisher signature', 'UNKNOWN',
    'no signature declared; cannot bind publisher identity to the artifact', evidence)
}

// ---------------------------------------------------------------------------
// report assembly
// ---------------------------------------------------------------------------

function buildReport({ command, target, checks, evidence = {}, error = null, sbom = null, revocation = null, provenance = null }) {
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
    // v0.2 additive fields. They are always present (null when not applicable)
    // so consumers of testatum/1 can rely on a stable key set.
    sbom,
    revocation,
    provenance,
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
  if (report.sbom) {
    const sbomEvidence = report.evidence?.sbom || {}
    lines.push(`  sbom: CycloneDX ${report.sbom.specVersion} · ${sbomEvidence.componentCount ?? '?'} component(s) · ` +
      `${sbomEvidence.fileCount ?? '?'} file(s) · ${sbomEvidence.filesDigest ?? 'no digest'} · coverage ${sbomEvidence.coverage ?? '?'} · unsigned`)
  }
  if (report.revocation) {
    lines.push(`  revocation: ${report.revocation.status} · ${report.revocation.advisoryCount ?? 0} active advisory(ies) · ` +
      `source ${report.revocation.source} (${report.revocation.cache})`)
  }
  if (report.provenance) {
    lines.push(`  provenance: ${report.provenance.present ? 'present' : 'absent'} · verified ${report.provenance.verified} · ` +
      `${report.provenance.status} · ${report.provenance.bundleCount ?? '?'} bundle(s)`)
  }
  if (report.error) lines.push(`  error: ${report.error}`)
  lines.push('  note: no cryptographic signature/provenance verification in v0.2; OSV advisories are unsigned and never cached')
  return lines.join('\n')
}

// ---------------------------------------------------------------------------
// SBOM (CycloneDX 1.5) generation
// ---------------------------------------------------------------------------

function licenseEntries(value) {
  if (typeof value === 'string' && value.trim()) {
    const text = value.trim()
    if (/^[A-Za-z0-9.+-]+$/.test(text) && !/^SEE LICENSE IN/i.test(text)) {
      return [{ license: { id: text } }]
    }
    return [{ license: { name: text } }]
  }
  if (isObject(value) && typeof value.type === 'string' && value.type.trim()) {
    return licenseEntries(value.type)
  }
  if (Array.isArray(value)) {
    const entries = value.flatMap((item) => licenseEntries(item) || [])
    return entries.length ? entries : null
  }
  return null
}

function integrityToHashes(integrity) {
  if (typeof integrity !== 'string' || !integrity.trim()) return []
  const algorithms = {
    sha1: ['SHA-1', 40],
    sha256: ['SHA-256', 64],
    sha384: ['SHA-384', 96],
    sha512: ['SHA-512', 128],
  }
  const hashes = []
  for (const token of integrity.trim().split(/\s+/)) {
    const clean = token.split('?')[0]
    const dash = clean.indexOf('-')
    if (dash <= 0) continue
    const algorithm = algorithms[clean.slice(0, dash).toLowerCase()]
    if (!algorithm) continue
    const content = clean.slice(dash + 1)
    const hex = Buffer.from(content, 'base64').toString('hex')
    if (!new RegExp(`^[a-f0-9]{${algorithm[1]}}$`).test(hex)) continue
    hashes.push({ alg: algorithm[0], content: hex })
  }
  return hashes
}

function packageNameFromLockPath(key) {
  const marker = 'node_modules/'
  const index = key.lastIndexOf(marker)
  if (index < 0) return null
  const rest = key.slice(index + marker.length)
  if (rest.startsWith('@')) {
    const parts = rest.split('/')
    return parts.length >= 2 ? `${parts[0]}/${parts[1]}` : null
  }
  return rest.split('/')[0] || null
}

function lockDependencyType(value) {
  if (value?.dev === true) return 'dev'
  if (value?.optional === true) return 'optional'
  if (value?.peer === true) return 'peer'
  return 'runtime'
}

function componentsFromNpmLock(lock, source) {
  const components = []
  const seen = new Set()
  const push = (name, value, fallbackVersion = null) => {
    if (!name) return
    if (value?.link === true) return
    if (typeof value?.resolved === 'string' && value.resolved.startsWith('file:')) return
    const version = typeof value?.version === 'string' && value.version ? value.version : fallbackVersion
    const dependencyType = lockDependencyType(value)
    const key = `${name}@${version || ''}`
    if (seen.has(key)) return
    seen.add(key)
    components.push({
      name,
      version: version || null,
      versionSpec: typeof value?.version === 'string' ? value.version : null,
      resolved: Boolean(version),
      hashes: integrityToHashes(value?.integrity),
      license: licenseEntries(value?.license),
      integrity: value?.integrity ?? null,
      dependencyType,
      scope: dependencyType === 'dev' ? 'excluded' : dependencyType === 'optional' || dependencyType === 'peer' ? 'optional' : 'required',
      source,
    })
  }

  if (isObject(lock.packages)) {
    for (const [key, value] of Object.entries(lock.packages)) {
      if (!key || !key.includes('node_modules/')) continue
      push(packageNameFromLockPath(key) || value?.name, value)
    }
  } else if (isObject(lock.dependencies)) {
    const visit = (dependencies) => {
      for (const [name, value] of Object.entries(dependencies || {})) {
        push(name, value)
        if (isObject(value?.dependencies)) visit(value.dependencies)
      }
    }
    visit(lock.dependencies)
  }
  components.sort((a, b) => `${a.name}@${a.version}`.localeCompare(`${b.name}@${b.version}`))
  return components.slice(0, MAX_SBOM_COMPONENTS)
}

function componentsFromManifest(manifest, source) {
  const groups = [
    ['dependencies', 'runtime', 'required'],
    ['optionalDependencies', 'optional', 'optional'],
    ['peerDependencies', 'peer', 'optional'],
  ]
  if (source === 'dir') groups.push(['devDependencies', 'dev', 'excluded'])
  const components = []
  const seen = new Map()
  for (const [field, dependencyType, scope] of groups) {
    if (!isObject(manifest[field])) continue
    for (const [name, spec] of Object.entries(manifest[field])) {
      if (typeof spec !== 'string' || !spec.trim()) continue
      const existing = seen.get(name)
      if (existing) {
        // Runtime declarations win over optional/peer/dev duplicates.
        const priority = { runtime: 0, optional: 1, peer: 2, dev: 3 }
        if (priority[dependencyType] < priority[existing.dependencyType]) {
          existing.versionSpec = spec
          existing.dependencyType = dependencyType
          existing.scope = scope
        }
        continue
      }
      const component = {
        name,
        version: null,
        versionSpec: spec,
        resolved: false,
        hashes: [],
        license: null,
        integrity: null,
        dependencyType,
        scope,
        source: 'package.json-range',
      }
      seen.set(name, component)
      components.push(component)
    }
  }
  components.sort((a, b) => a.name.localeCompare(b.name))
  return components.slice(0, MAX_SBOM_COMPONENTS)
}

function loadLocalSbomComponents(dir, manifest) {
  const found = LOCKFILES.filter((name) => existsSync(join(dir, name)))
  if (found.length === 1 && (found[0] === 'package-lock.json' || found[0] === 'npm-shrinkwrap.json')) {
    try {
      const lock = JSON.parse(readFileSync(join(dir, found[0]), 'utf8'))
      return {
        components: componentsFromNpmLock(lock, found[0]),
        resolution: 'lockfile',
        lockfile: found[0],
        warning: null,
      }
    } catch (error) {
      return {
        components: componentsFromManifest(manifest, 'dir'),
        resolution: 'declared-ranges',
        lockfile: found[0],
        warning: `cannot parse ${found[0]}: ${error.message}`,
      }
    }
  }
  const warning = found.length > 1
    ? `multiple lockfiles present: ${found.join(', ')}`
    : found.length === 1
      ? `${found[0]} is not resolved by v0.2; dependency versions are declared ranges`
      : 'no lockfile; dependency versions are declared ranges'
  return {
    components: componentsFromManifest(manifest, 'dir'),
    resolution: 'declared-ranges',
    lockfile: found[0] ?? null,
    warning,
  }
}

function evaluateSbomCoverage({ components, inventory, rootLicense, componentsTruncated = false }) {
  const gaps = []
  if (inventory.truncated) gaps.push(`file inventory truncated at ${inventory.files.length} files`)
  if (inventory.unreadable) gaps.push(`${inventory.unreadable} file(s) unreadable`)
  if (inventory.oversized) gaps.push(`${inventory.oversized} file(s) exceed ${MAX_SBOM_FILE_BYTES} bytes and were not hashed`)
  if (!rootLicense) gaps.push('root component has no license')
  if (componentsTruncated) gaps.push(`component list truncated at ${MAX_SBOM_COMPONENTS}`)
  const runtime = components.filter((component) => component.dependencyType !== 'dev')
  const unresolved = runtime.filter((component) => !component.version)
  const missingHashes = runtime.filter((component) => component.version && component.hashes.length === 0)
  const missingLicenses = runtime.filter((component) => component.version && !component.license)
  if (unresolved.length) {
    gaps.push(`${unresolved.length} runtime component(s) have unresolved versions (${unresolved.slice(0, 3).map((item) => item.name).join(', ')}${unresolved.length > 3 ? ', …' : ''})`)
  }
  if (missingHashes.length) {
    gaps.push(`${missingHashes.length} resolved runtime component(s) have no hash`)
  }
  if (missingLicenses.length) {
    gaps.push(`${missingLicenses.length} resolved runtime component(s) have no license`)
  }
  return {
    coverage: gaps.length ? 'partial' : 'full',
    gaps,
    runtimeComponents: runtime.length,
    unresolvedRuntime: unresolved.length,
    missingHashComponents: missingHashes.length,
    missingLicenseComponents: missingLicenses.length,
  }
}

function buildCycloneDx({ name, version, source, rootHashes, rootLicense, components, inventory, coverage, distributionUrl, repositoryUrl, extraProperties = [] }) {
  const rootPurl = purlFor(name, version)
  const digest = filesDigest(inventory.files)
  const usedRefs = new Set(rootPurl ? [rootPurl] : [])
  const cdxComponents = components.map((component, index) => {
    const purl = purlFor(component.name, component.version)
    let ref = purl || `component:${index}`
    if (usedRefs.has(ref)) ref = `${ref}#${index}`
    usedRefs.add(ref)
    const properties = [
      { name: 'testatum:dependencyType', value: component.dependencyType },
      { name: 'testatum:resolved', value: String(Boolean(component.version)) },
    ]
    if (component.versionSpec) properties.push({ name: 'testatum:versionSpec', value: component.versionSpec })
    return {
      type: 'library',
      'bom-ref': ref,
      name: component.name,
      ...(component.version ? { version: component.version } : {}),
      ...(purl ? { purl } : {}),
      scope: component.scope,
      ...(component.hashes.length ? { hashes: component.hashes } : {}),
      ...(component.license ? { licenses: component.license } : {}),
      properties,
    }
  })
  const rootReferences = []
  if (distributionUrl) rootReferences.push({ type: 'distribution', url: distributionUrl })
  if (repositoryUrl) rootReferences.push({ type: 'vcs', url: repositoryUrl })
  const rootProperties = [
    { name: 'testatum:fileInventoryScope', value: source === 'npm' ? 'tarball-payload' : 'source-tree' },
    { name: 'testatum:filesDigest', value: `sha256:${digest}` },
    { name: 'testatum:hashMeaning', value: source === 'npm' ? 'tarball-bytes' : 'source-tree-sha256' },
  ]
  const rootComponent = {
    type: 'library',
    'bom-ref': rootPurl,
    name,
    version,
    purl: rootPurl,
    hashes: rootHashes,
    ...(rootLicense ? { licenses: rootLicense } : {}),
    ...(rootReferences.length ? { externalReferences: rootReferences } : {}),
    properties: rootProperties,
  }
  const document = {
    $schema: CDX_SCHEMA,
    bomFormat: 'CycloneDX',
    specVersion: CDX_SPEC_VERSION,
    serialNumber: deterministicUrn(`${name}@${version}|${source}|${digest}`),
    version: 1,
    metadata: {
      tools: {
        components: [{ type: 'application', name: 'testatum', version: VERSION }],
      },
      component: rootComponent,
    },
    components: cdxComponents,
    dependencies: [{
      ref: rootPurl,
      dependsOn: cdxComponents.map((component) => component['bom-ref']),
    }],
    properties: [
      { name: 'testatum:source', value: source },
      { name: 'testatum:fileCount', value: String(inventory.files.length) },
      { name: 'testatum:filesDigest', value: `sha256:${digest}` },
      { name: 'testatum:filesTruncated', value: String(Boolean(inventory.truncated)) },
      { name: 'testatum:coverage', value: coverage.coverage },
      { name: 'testatum:sbomSigned', value: 'false' },
      { name: 'testatum:sbomAttested', value: 'false' },
      ...extraProperties,
    ],
  }
  return { document, digest }
}

function validateCycloneDx(document) {
  const issues = []
  const hashPattern = {
    'SHA-1': /^[a-f0-9]{40}$/,
    'SHA-256': /^[a-f0-9]{64}$/,
    'SHA-384': /^[a-f0-9]{96}$/,
    'SHA-512': /^[a-f0-9]{128}$/,
  }
  if (document?.bomFormat !== 'CycloneDX') issues.push('bomFormat must be CycloneDX')
  if (document?.specVersion !== CDX_SPEC_VERSION) issues.push(`specVersion must be ${CDX_SPEC_VERSION}`)
  if (document?.version !== 1) issues.push('version must be 1')
  if (typeof document?.serialNumber !== 'string' || !/^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(document.serialNumber)) {
    issues.push('serialNumber is not a lowercase RFC-4122 urn:uuid')
  }
  const root = document?.metadata?.component
  if (!isObject(root) || typeof root.name !== 'string' || !root.name || typeof root.version !== 'string' || !root.version) {
    issues.push('metadata.component must carry name and version')
  } else {
    if (!Array.isArray(root.hashes) || !root.hashes.length) issues.push('metadata.component.hashes is empty')
    if (!Array.isArray(root.properties)) issues.push('metadata.component.properties must be an array')
  }
  const refs = new Set()
  for (const [index, component] of (document?.components || []).entries()) {
    if (!isObject(component) || typeof component.name !== 'string' || !component.name) {
      issues.push(`components[${index}].name missing`)
    }
    if (!component || component.type !== 'library') issues.push(`components[${index}].type must be library`)
    if (component?.['bom-ref']) {
      if (refs.has(component['bom-ref'])) issues.push(`duplicate bom-ref ${component['bom-ref']}`)
      refs.add(component['bom-ref'])
    }
    for (const hash of component?.hashes || []) {
      const pattern = hashPattern[hash.alg]
      if (!pattern || !pattern.test(String(hash.content || ''))) issues.push(`components[${index}] has an invalid ${hash.alg} hash`)
    }
  }
  for (const [index, hash] of (root?.hashes || []).entries()) {
    const pattern = hashPattern[hash.alg]
    if (!pattern || !pattern.test(String(hash.content || ''))) issues.push(`metadata.component.hashes[${index}] is invalid (${hash.alg})`)
  }
  for (const dependency of document?.dependencies || []) {
    if (dependency.ref !== root?.purl) issues.push(`dependencies ref ${dependency.ref} is not the root purl`)
    for (const ref of dependency.dependsOn || []) {
      if (!refs.has(ref)) issues.push(`dependencies dependsOn unknown ref ${ref}`)
    }
  }
  for (const [index, property] of (document?.properties || []).entries()) {
    if (!isObject(property) || typeof property.name !== 'string' || typeof property.value !== 'string') {
      issues.push(`properties[${index}] is not a name/value pair`)
    }
  }
  return issues
}

function checkSbomGeneration({ issues, coverage, digest, fileCount, componentCount, source, extraFailures = [] }) {
  const evidence = {
    format: 'CycloneDX',
    specVersion: CDX_SPEC_VERSION,
    source,
    fileCount,
    filesDigest: `sha256:${digest}`,
    componentCount,
    componentCountIncludesRoot: true,
    coverage: coverage.coverage,
    gaps: coverage.gaps,
    runtimeComponents: coverage.runtimeComponents,
    unresolvedRuntime: coverage.unresolvedRuntime,
    signed: false,
    attested: false,
    validation: issues.length ? issues : 'ok',
  }
  if (extraFailures.length) {
    return makeCheck('SC-02', 'SBOM generation (CycloneDX 1.5)', 'FAIL', extraFailures.join('; '), evidence)
  }
  if (issues.length) {
    return makeCheck('SC-02', 'SBOM generation (CycloneDX 1.5)', 'FAIL',
      `generated CycloneDX document failed structural validation: ${issues.slice(0, 3).join('; ')}`, evidence)
  }
  if (coverage.coverage !== 'full') {
    return makeCheck('SC-02', 'SBOM generation (CycloneDX 1.5)', 'UNKNOWN',
      `CycloneDX 1.5 generated but coverage is partial: ${coverage.gaps.join('; ')}; local SBOM is unsigned`, evidence)
  }
  return makeCheck('SC-02', 'SBOM generation (CycloneDX 1.5)', 'PASS',
    `CycloneDX 1.5 generated: ${componentCount} component(s), ${fileCount} file(s), files digest sha256:${digest.slice(0, 16)}…; local SBOM is unsigned/not attested`,
    evidence)
}

// ---------------------------------------------------------------------------
// revocation lookup (OSV)
// ---------------------------------------------------------------------------

function osvAdvisorySummary(vuln) {
  const fixed = []
  for (const affected of Array.isArray(vuln?.affected) ? vuln.affected : []) {
    for (const range of Array.isArray(affected?.ranges) ? affected.ranges : []) {
      for (const event of Array.isArray(range?.events) ? range.events : []) {
        if (typeof event?.fixed === 'string' && event.fixed) fixed.push(event.fixed)
      }
    }
  }
  return {
    id: vuln?.id ?? null,
    aliases: Array.isArray(vuln?.aliases) ? vuln.aliases : [],
    modified: vuln?.modified ?? null,
    published: vuln?.published ?? null,
    withdrawn: vuln?.withdrawn ?? null,
    summary: short(vuln?.summary || '', 200),
    severity: Array.isArray(vuln?.severity)
      ? vuln.severity.map((item) => ({ type: item?.type ?? null, score: item?.score ?? null })).slice(0, 5)
      : [],
    fixed: [...new Set(fixed)].slice(0, 10),
  }
}

async function queryOsv(name, version) {
  const payload = {
    package: { name, ecosystem: 'npm' },
    version,
  }
  const response = await postJson(OSV_API, payload)
  if (!isObject(response)) throw new Error('OSV response is not a JSON object')
  if (response.vulns !== undefined && !Array.isArray(response.vulns)) {
    throw new Error('OSV response has a non-array vulns field')
  }
  return {
    payload,
    vulns: response.vulns || [],
    nextPageToken: response.next_page_token || null,
  }
}

function checkRevocation({ name, version, result = null, error = null, queriedAt }) {
  const evidence = {
    source: 'osv',
    endpoint: OSV_API,
    ecosystem: 'npm',
    package: name,
    version,
    queriedAt,
    cache: 'disabled',
    signed: false,
    advisoryCount: 0,
    withdrawnCount: 0,
    advisories: [],
    nextPageToken: null,
    error: error ? short(error, 300) : null,
  }
  if (error) {
    return {
      check: makeCheck('SC-06', 'revocation query (OSV)', 'UNKNOWN',
        `OSV query failed (${short(error, 120)}); absence of advisories cannot be established and no cached result is used`,
        evidence),
      field: {
        ...evidence,
        status: 'unknown',
        reason: 'OSV query failed; UNKNOWN, not PASS',
      },
    }
  }
  const objects = result.vulns.filter((vuln) => isObject(vuln))
  const malformed = result.vulns.length - objects.length
  const active = objects.filter((vuln) => !vuln.withdrawn)
  const withdrawn = objects.length - active.length
  evidence.advisoryCount = active.length
  evidence.withdrawnCount = withdrawn
  evidence.advisories = active.slice(0, 20).map(osvAdvisorySummary)
  evidence.nextPageToken = result.nextPageToken
  if (malformed > 0 && active.length === 0) {
    return {
      check: makeCheck('SC-06', 'revocation query (OSV)', 'UNKNOWN',
        `OSV returned ${malformed} malformed advisory record(s); the result cannot be treated as clear`, evidence),
      field: { ...evidence, status: 'unknown', reason: 'malformed OSV result; UNKNOWN, not PASS' },
    }
  }
  if (result.nextPageToken && active.length === 0) {
    return {
      check: makeCheck('SC-06', 'revocation query (OSV)', 'UNKNOWN',
        'OSV returned a pagination token with no advisories; pagination is not implemented, so the result is UNKNOWN', evidence),
      field: { ...evidence, status: 'unknown', reason: 'OSV pagination not implemented; UNKNOWN, not PASS' },
    }
  }
  if (active.length > 0) {
    const ids = active.slice(0, 5).map((vuln) => vuln.id || 'unknown').join(', ')
    return {
      check: makeCheck('SC-06', 'revocation query (OSV)', 'FAIL',
        `OSV reports ${active.length} active advisory(ies) affecting ${name}@${version}: ${ids}${active.length > 5 ? ', …' : ''}`,
        evidence),
      field: {
        ...evidence,
        status: 'advisories-found',
        reason: 'OSV advisory affects this exact version; treat as revoked until reviewed',
      },
    }
  }
  const withdrawnSuffix = withdrawn ? ` (${withdrawn} withdrawn advisory record(s) ignored)` : ''
  return {
    check: makeCheck('SC-06', 'revocation query (OSV)', 'PASS',
      `OSV reports no active advisories for ${name}@${version}${withdrawnSuffix}; point-in-time unsigned advisory query, not a signed revocation list`,
      evidence),
    field: {
      ...evidence,
      status: 'clear',
      reason: 'OSV returned no active advisories; unsigned point-in-time result',
    },
  }
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
  const provenanceCheck = await checkProvenance(meta, artifact)
  const checks = [
    checkRemoteIntegrity(meta, artifact),
    checkSignature(meta, artifact),
    provenanceCheck,
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
    provenance: provenanceSummary(provenanceCheck),
  })
}

function repositoryUrl(manifest) {
  const repository = manifest?.repository
  if (typeof repository === 'string') return repository
  if (isObject(repository) && typeof repository.url === 'string') return repository.url
  if (typeof manifest?.homepage === 'string') return manifest.homepage
  return null
}

async function sbomDir(input) {
  const dir = resolve(input)
  const { manifest, file } = loadLocalPackage(dir)
  const name = typeof manifest.name === 'string' ? manifest.name : ''
  const version = typeof manifest.version === 'string' ? manifest.version : ''
  if (!name || !version) throw new Error('package.json must declare name and version to build an SBOM')
  const inventory = localFileInventory(dir)
  const rootLicense = licenseEntries(manifest.license)
  const lock = loadLocalSbomComponents(dir, manifest)
  const components = lock.components
  const coverage = evaluateSbomCoverage({
    components,
    inventory,
    rootLicense,
    componentsTruncated: components.length >= MAX_SBOM_COMPONENTS,
  })
  const digest = filesDigest(inventory.files)
  const rootHashes = [{ alg: 'SHA-256', content: digest }]
  const { document } = buildCycloneDx({
    name,
    version,
    source: 'dir',
    rootHashes,
    rootLicense,
    components,
    inventory,
    coverage,
    distributionUrl: null,
    repositoryUrl: repositoryUrl(manifest),
    extraProperties: [
      { name: 'testatum:lockfile', value: lock.lockfile || 'none' },
      { name: 'testatum:dependencyResolution', value: lock.resolution },
      ...(lock.warning ? [{ name: 'testatum:resolutionWarning', value: lock.warning }] : []),
    ],
  })
  const issues = validateCycloneDx(document)
  const check = checkSbomGeneration({
    issues,
    coverage,
    digest,
    fileCount: inventory.files.length,
    componentCount: 1 + components.length,
    source: 'local-dir',
  })
  return buildReport({
    command: 'sbom',
    target: {
      input,
      type: 'dir',
      name,
      version,
      path: dir,
      manifestPath: file,
    },
    checks: [check],
    evidence: {
      sbom: check.evidence,
      source: {
        type: 'dir',
        path: dir,
        manifestPath: file,
        lockfile: lock.lockfile,
        dependencyResolution: lock.resolution,
        warning: lock.warning,
      },
      files: {
        count: inventory.files.length,
        digest: `sha256:${digest}`,
        truncated: inventory.truncated,
        unreadable: inventory.unreadable,
        oversized: inventory.oversized,
        sample: inventory.files.slice(0, 10),
      },
      components: {
        count: components.length,
        runtime: components.filter((item) => item.dependencyType !== 'dev').length,
        unresolved: components.filter((item) => !item.version).map((item) => item.name),
        sample: components.slice(0, 10).map((item) => ({
          name: item.name,
          version: item.version,
          dependencyType: item.dependencyType,
          hashes: item.hashes.length,
        })),
      },
    },
    sbom: document,
  })
}

async function sbomNpm(input) {
  const spec = parseSpec(input)
  if (!spec.name) throw new Error(`invalid package spec: ${input}`)
  const meta = await fetchVersion(spec.name, spec.version)
  const artifact = await loadTarball(meta)
  if (!artifact.buffer || !artifact.tar) {
    throw new Error(`tarball unavailable: ${artifact.error || 'unknown error'}`)
  }
  const manifest = artifact.manifest
  if (!manifest) throw new Error('tarball package.json could not be parsed')
  const name = typeof manifest.name === 'string' ? manifest.name : meta.name
  const version = typeof manifest.version === 'string' ? manifest.version : meta.version
  if (!name || !version) throw new Error('package manifest must declare name and version to build an SBOM')

  const inventory = tarFileInventory(artifact.tar)
  const rootLicense = licenseEntries(manifest.license)
  let components
  let resolution
  let lockfile = null
  const embeddedLock = artifact.tar ? (readTarText(artifact.tar, 'package-lock.json') || readTarText(artifact.tar, 'npm-shrinkwrap.json')) : null
  if (embeddedLock) {
    try {
      components = componentsFromNpmLock(JSON.parse(embeddedLock), 'tarball-lockfile')
      resolution = 'tarball-lockfile'
      lockfile = 'package-lock.json'
    } catch {
      components = componentsFromManifest(manifest, 'npm')
      resolution = 'declared-ranges'
    }
  } else {
    components = componentsFromManifest(manifest, 'npm')
    resolution = 'declared-ranges'
  }
  const coverage = evaluateSbomCoverage({
    components,
    inventory,
    rootLicense,
    componentsTruncated: components.length >= MAX_SBOM_COMPONENTS,
  })
  const digest = filesDigest(inventory.files)
  const rootHashes = [
    { alg: 'SHA-512', content: sha512Hex(artifact.buffer) },
    { alg: 'SHA-256', content: sha256Hex(artifact.buffer) },
  ]
  const expectedSha512 = extractSha512(meta?.dist?.integrity)
  const digestMatches = expectedSha512 ? createHash('sha512').update(artifact.buffer).digest('base64') === expectedSha512 : null
  const { document } = buildCycloneDx({
    name,
    version,
    source: 'npm',
    rootHashes,
    rootLicense,
    components,
    inventory,
    coverage,
    distributionUrl: meta?.dist?.tarball ?? null,
    repositoryUrl: repositoryUrl(manifest),
    extraProperties: [
      { name: 'testatum:registryIntegrity', value: meta?.dist?.integrity ?? 'none' },
      { name: 'testatum:registryIntegrityMatches', value: String(digestMatches) },
      { name: 'testatum:dependencyResolution', value: resolution },
      ...(lockfile ? [{ name: 'testatum:embeddedLockfile', value: lockfile }] : []),
    ],
  })
  const issues = validateCycloneDx(document)
  const extraFailures = []
  if (digestMatches === false) extraFailures.push('tarball bytes do not match dist.integrity; SBOM hashes are computed from the fetched bytes, not the registry declaration')
  if (manifest.name !== meta.name || manifest.version !== meta.version) {
    extraFailures.push(`tarball package.json is ${manifest.name}@${manifest.version}, expected ${meta.name}@${meta.version}`)
  }
  const check = checkSbomGeneration({
    issues,
    coverage,
    digest,
    fileCount: inventory.files.length,
    componentCount: 1 + components.length,
    source: 'npm-tarball',
    extraFailures,
  })
  return buildReport({
    command: 'sbom',
    target: {
      input,
      type: 'npm',
      name,
      version,
      registry: REGISTRY,
      tarball: meta?.dist?.tarball ?? null,
    },
    checks: [check],
    evidence: {
      sbom: check.evidence,
      source: {
        type: 'npm-tarball',
        registry: REGISTRY,
        tarball: meta?.dist?.tarball ?? null,
        integrity: meta?.dist?.integrity ?? null,
        integrityMatches: digestMatches,
        dependencyResolution: resolution,
        embeddedLockfile: lockfile,
        tarballFiles: artifact.stats?.fileCount ?? null,
      },
      files: {
        count: inventory.files.length,
        digest: `sha256:${digest}`,
        truncated: inventory.truncated,
        sample: inventory.files.slice(0, 10),
      },
      components: {
        count: components.length,
        runtime: components.filter((item) => item.dependencyType !== 'dev').length,
        unresolved: components.filter((item) => !item.version).map((item) => item.name),
        sample: components.slice(0, 10).map((item) => ({
          name: item.name,
          version: item.version,
          dependencyType: item.dependencyType,
          hashes: item.hashes.length,
        })),
      },
    },
    sbom: document,
  })
}

async function revocationNpm(input) {
  const targetPath = resolve(input)
  if (existsSync(targetPath) && statSync(targetPath).isDirectory()) {
    throw new Error('revocation expects an npm package spec, not a directory')
  }
  const spec = parseSpec(input)
  if (!spec.name) throw new Error(`invalid package spec: ${input}`)
  if (!spec.version) throw new Error(`revocation requires an exact version: ${input} (use <pkg>@<version>)`)
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(spec.version)) {
    throw new Error(`revocation requires an exact semver version, got "${spec.version}"`)
  }
  const queriedAt = new Date().toISOString()
  let result = null
  let error = null
  try {
    result = await queryOsv(spec.name, spec.version)
  } catch (caught) {
    error = describeError(caught)
  }
  const { check, field } = checkRevocation({ name: spec.name, version: spec.version, result, error, queriedAt })
  return buildReport({
    command: 'revocation',
    target: {
      input,
      type: 'npm',
      name: spec.name,
      version: spec.version,
      registry: REGISTRY,
      osvEndpoint: OSV_API,
    },
    checks: [check],
    evidence: {
      revocation: field,
    },
    revocation: field,
  })
}

function policyRequirements() {
  return [
    { id: 'SC-01', title: 'artifact signature and verification', level: 'MUST', v01: 'presence only; verify reports UNKNOWN', v02: 'presence only; registry signatures never verified (UNKNOWN)', default: 'strict missing evidence => DENY' },
    { id: 'SC-02', title: 'SBOM and dependency inventory', level: 'MUST', v01: 'not implemented (fields reported only)', v02: 'local CycloneDX 1.5 via `sbom`; unsigned, no attestation; tarball dependency ranges may stay unresolved', default: 'strict new release without SBOM => DENY' },
    { id: 'SC-03', title: 'install scripts denied by default', level: 'MUST', v01: 'implemented for pre/install/postinstall/prepare', v02: 'implemented for pre/install/postinstall/prepare; still static only', default: 'DENY in all modes' },
    { id: 'SC-04', title: 'capability declaration and consistency', level: 'MUST', v01: 'declaration shape + dangerous literals only', v02: 'declaration shape + dangerous literals only; no AST/runtime observation', default: 'undeclared high risk => DENY/WARN' },
    { id: 'SC-05', title: 'CVE and vulnerability response', level: 'MUST', v01: 'not implemented', v02: 'on-demand OSV query via `revocation`; no continuous monitoring or KEV feed', default: 'KEV/CVSS>=9 => DENY' },
    { id: 'SC-06', title: 'signed revocation list', level: 'MUST', v01: 'not implemented (policy only)', v02: 'on-demand unsigned OSV advisory query; signed revocation list/TTL not implemented', default: 'revoked/unreachable => DENY/WARN' },
    { id: 'SC-07', title: 'provenance and commit pinning', level: 'MUST', v01: 'digest verified; provenance presence only => UNKNOWN', v02: 'digest verified; npm attestation presence recorded; always UNKNOWN, never PASS', default: 'strict missing provenance => DENY' },
    { id: 'SC-08', title: 'reproducible builds', level: 'MUST', v01: 'not implemented', v02: 'not implemented', default: 'strict missing evidence => DENY' },
    { id: 'SC-09', title: 'least privilege', level: 'MUST', v01: 'danger-full-access / credentials literal scan only', v02: 'danger-full-access / credentials literal scan only', default: 'dangerous grant => DENY' },
    { id: 'SC-10', title: 'install audit log', level: 'MUST', v01: 'not implemented', v02: 'not implemented', default: 'strict without audit => DENY' },
  ]
}

function policyHuman() {
  const lines = []
  lines.push(`testatum ${VERSION} — DSH supply-chain policy (baseline v0.1.0-draft, 2026-11-14)`)
  lines.push('')
  for (const item of policyRequirements()) {
    lines.push(`${item.id}  ${item.title}`)
    lines.push(`      v0.2: ${item.v02}`)
    lines.push(`      default: ${item.default}`)
  }
  lines.push('')
  lines.push('Modes: strict (CI/first-party) / balanced (community) / permissive (local experiments).')
  lines.push('Non-negotiable: install scripts DENY in every mode; revoked/KEV DENY in every mode;')
  lines.push('missing, expired or unreachable evidence is never reported as PASS.')
  lines.push('')
  lines.push('Exit codes: 0 = pass; 1 = fail; 2 = unknown (unverifiable evidence or usage error).')
  lines.push('v0.2 does not perform cryptographic verification and must not be used as a security gate.')
  lines.push('OSV advisories are unsigned, point-in-time data and are never cached.')
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
    commands: {
      scan: 'static manifest, lifecycle-script, capability and integrity checks',
      verify: 'registry digest + signature/provenance presence (never PASS on provenance)',
      sbom: 'generate a local CycloneDX 1.5 SBOM (unsigned; no attestation)',
      revocation: 'fresh OSV advisory query for one exact version (no cache; network failure = UNKNOWN)',
      policy: 'print the 10 baseline requirements and exit-code contract',
    },
    schemaExtensions: {
      sbom: 'CycloneDX 1.5 JSON object when command=sbom, otherwise null',
      revocation: 'OSV query result when command=revocation, otherwise null',
      provenance: 'presence summary when command=verify, otherwise null',
    },
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
    '  testatum scan <pkg|dir>           inspect manifest, lifecycle scripts, files and lockfile/digest',
    '  testatum verify <pkg>             inspect registry integrity, signature and provenance PRESENCE',
    '  testatum sbom <pkg|dir>           generate a local CycloneDX 1.5 SBOM (unsigned)',
    '  testatum revocation <pkg@ver>     query OSV for advisories affecting one exact version',
    '  testatum policy                   print the 10 baseline requirements and exit-code contract',
    '  testatum version                  print version',
    '  testatum help                     print this help',
    '',
    'Options:',
    '  --json    JSON only (scan/verify/sbom/revocation already write JSON to stdout; suppress the stderr summary)',
    '  --cdx     with sbom: print only the CycloneDX 1.5 document',
    '',
    'Examples:',
    '  node testatum.mjs scan .',
    '  node testatum.mjs scan dsh-auto-review@0.15.1',
    '  node testatum.mjs verify dsh-permission-rules@0.8.0',
    '  node testatum.mjs sbom dsh-auto-review@0.15.1',
    '  node testatum.mjs sbom . --cdx > sbom.cdx.json',
    '  node testatum.mjs revocation lodash@4.17.19',
    '  node testatum.mjs policy --json',
    '',
    'Exit codes: 0 pass / 1 fail / 2 unknown. v0.2 never executes package code or lifecycle scripts.',
    'OSV results are never cached; network failure is UNKNOWN, never PASS.',
  ].join('\n')
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

async function main(argv) {
  const jsonOnly = argv.includes('--json')
  const cdxOnly = argv.includes('--cdx')
  const args = argv.filter((arg) => arg !== '--json' && arg !== '--cdx')
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

  if (command === 'sbom') {
    const input = rest[0]
    if (!input) {
      console.error('testatum: sbom requires <pkg|dir>')
      return 2
    }
    let report
    try {
      const targetPath = resolve(input)
      if (existsSync(targetPath) && statSync(targetPath).isDirectory()) {
        report = await sbomDir(input)
      } else {
        report = await sbomNpm(input)
      }
    } catch (error) {
      report = errorReport('sbom', { input, type: input.startsWith('.') || input.includes('/') ? 'dir' : 'npm' }, error)
    }
    if (cdxOnly && report.sbom) {
      console.log(JSON.stringify(report.sbom, null, 2))
      return report.exitCode
    }
    console.log(JSON.stringify(report, null, 2))
    if (!jsonOnly && !cdxOnly) console.error(renderSummary(report))
    return report.exitCode
  }

  if (command === 'revocation') {
    const input = rest[0]
    if (!input) {
      console.error('testatum: revocation requires <pkg@version>')
      return 2
    }
    let report
    try {
      report = await revocationNpm(input)
    } catch (error) {
      report = errorReport('revocation', { input, type: 'npm' }, error)
    }
    console.log(JSON.stringify(report, null, 2))
    if (!jsonOnly) console.error(renderSummary(report))
    return report.exitCode
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
