import assert from 'node:assert/strict'
import { createHash, createHmac, randomBytes } from 'node:crypto'
import http from 'node:http'
import { test } from 'node:test'

import {
  apply,
  decodeToken,
  parseCookies,
  requestAudience,
  resolveOptions,
  serializeDeletion,
} from '../index.js'

const SECRET = randomBytes(32)
const AUTHORITY = '127.0.0.1:51302'
const OTHER_AUTHORITY = '127.0.0.1:50969'
const DAY = 24 * 60 * 60 * 1000

const cookieName = (authority) => `dsh-auth-${createHash('sha256').update(authority).digest('base64url')}`
const CURRENT = cookieName(AUTHORITY)
const OTHER = cookieName(OTHER_AUTHORITY)

function token(authority, options = {}) {
  const issuedAt = options.issuedAt ?? Date.now()
  const expiresAt = options.expiresAt ?? issuedAt + 30 * DAY
  const version = options.version ?? 1
  const payload = { version, authority, issuedAt, expiresAt }
  if (options.id !== undefined) payload.id = options.id
  const body = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url')
  const signature = createHmac('sha256', options.secret ?? SECRET).update(body).digest('base64url')
  return `v${version}.${body}.${signature}`
}

function fakeContext(server, logs = []) {
  let dispose
  const ctx = {
    webServer: { server, protocol: 'http:' },
    connection: { browserAuth: { secret: SECRET } },
    logger: {
      info: (message) => logs.push(['info', message]),
      warn: (message) => logs.push(['warn', message]),
    },
    effect(callback) {
      const result = callback()
      if (typeof result === 'function') dispose = result
      return result
    },
  }
  return { ctx, logs, dispose: () => dispose?.() }
}

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject)
      resolve(server.address().port)
    })
  })
}

function close(server) {
  return new Promise((resolve) => server.close(resolve))
}

function request(port, cookie, options = {}) {
  return new Promise((resolve, reject) => {
    const headers = { host: AUTHORITY }
    if (cookie !== undefined) headers.cookie = cookie
    const req = http.request(
      { host: '127.0.0.1', port, path: options.path ?? '/', method: options.method ?? 'GET', headers },
      (res) => {
        let body = ''
        res.setEncoding('utf8')
        res.on('data', (chunk) => { body += chunk })
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }))
      },
    )
    req.on('error', reject)
    req.end()
  })
}

function setCookies(response) {
  const value = response.headers['set-cookie']
  if (value === undefined) return []
  return Array.isArray(value) ? value : [value]
}

test('resolveOptions clamps invalid values and keeps valid ones', () => {
  assert.deepEqual(resolveOptions(undefined), {
    maxHeaderBytes: 262144,
    cookieBudgetBytes: 4096,
    keepOtherCookies: 3,
  })
  assert.deepEqual(resolveOptions({ maxHeaderBytes: 1024, cookieBudgetBytes: 'x', keepOtherCookies: 99 }), {
    maxHeaderBytes: 262144,
    cookieBudgetBytes: 4096,
    keepOtherCookies: 3,
  })
  assert.deepEqual(resolveOptions({ maxHeaderBytes: 65536, cookieBudgetBytes: 2048, keepOtherCookies: 0 }), {
    maxHeaderBytes: 65536,
    cookieBudgetBytes: 2048,
    keepOtherCookies: 0,
  })
})

test('parseCookies handles spaces, empty pairs, and = inside values', () => {
  assert.deepEqual(parseCookies(' a=1 ; b=2=3;; c= ; d'), [
    { name: 'a', value: '1', raw: 'a=1' },
    { name: 'b', value: '2=3', raw: 'b=2=3' },
    { name: 'c', value: '', raw: 'c=' },
  ])
  assert.deepEqual(parseCookies(''), [])
})

test('requestAudience matches the Host header spelling used by DSH', () => {
  assert.equal(requestAudience({ host: '127.0.0.1:51302' }, false), '127.0.0.1:51302')
  assert.equal(requestAudience({ host: '127.0.0.1:443' }, true), 'https://127.0.0.1')
  assert.equal(requestAudience({ host: '[::1]:51302' }, false), '[::1]:51302')
  assert.equal(requestAudience({}, false), undefined)
  assert.equal(requestAudience({ host: 'bad host' }, false), undefined)
})

test('decodeToken verifies the HMAC and payload shape', () => {
  const value = token(AUTHORITY)
  const payload = decodeToken(value, SECRET)
  assert.equal(payload.authority, AUTHORITY)
  assert.equal(payload.version, 1)

  assert.equal(decodeToken(value, randomBytes(32)), undefined)
  assert.equal(decodeToken(`${value}x`, SECRET), undefined)
  assert.equal(decodeToken('v1.not-json.sig', SECRET), undefined)
})

test('serializeDeletion expires the cookie on the same host/path', () => {
  assert.match(serializeDeletion('dsh-auth-x', false), /^dsh-auth-x=; Path=\/; Max-Age=0;/)
  assert.doesNotMatch(serializeDeletion('dsh-auth-x', false), /Secure/)
  assert.match(serializeDeletion('dsh-auth-x', true), /; Secure$/)
})

test('raises maxHeaderSize before accepting requests and restores it on dispose', async () => {
  const server = http.createServer((_req, res) => res.end('ok'))
  const { ctx, dispose } = fakeContext(server)
  apply(ctx, { maxHeaderBytes: 65536 })
  assert.equal(server.maxHeaderSize, 65536)

  const port = await listen(server)
  const big = `x=${'a'.repeat(20_000)}`
  const response = await request(port, big)
  assert.equal(response.status, 200)

  dispose()
  assert.equal(server.maxHeaderSize, 16 * 1024)
  await close(server)
})

test('applies to a server that is already listening', async () => {
  const server = http.createServer((_req, res) => res.end('ok'))
  const port = await listen(server)
  const { ctx, dispose } = fakeContext(server)
  apply(ctx, { maxHeaderBytes: 65536 })
  assert.equal(server.maxHeaderSize, 65536)

  const response = await request(port, `x=${'a'.repeat(20_000)}`)
  assert.equal(response.status, 200)

  dispose()
  await close(server)
})

test('strips stale auth cookies and sends deletions while keeping the current one', async () => {
  const seen = []
  const server = http.createServer((req, res) => {
    seen.push(req.headers.cookie)
    res.end('ok')
  })
  const { ctx, dispose } = fakeContext(server)
  apply(ctx, { maxHeaderBytes: 65536, keepOtherCookies: 0 })
  const port = await listen(server)

  const current = token(AUTHORITY)
  const old = token(OTHER_AUTHORITY, { issuedAt: Date.now() - 60_000 })
  const response = await request(port, `${CURRENT}=${current}; app=1; ${OTHER}=${old}`)

  assert.equal(response.status, 200)
  assert.equal(seen[0], `${CURRENT}=${current}; app=1`)
  const cookies = setCookies(response)
  assert.equal(cookies.length, 1)
  assert.match(cookies[0], new RegExp(`^${OTHER}=;`))
  assert.doesNotMatch(cookies[0], new RegExp(`^${CURRENT}=`))

  dispose()
  await close(server)
})

test('caps a bloated header to current + keepOther newest cookies and deletes the rest', async () => {
  const seen = []
  const server = http.createServer((req, res) => {
    seen.push(req.headers.cookie)
    res.end('ok')
  })
  const { ctx, dispose } = fakeContext(server)
  apply(ctx, { maxHeaderBytes: 262144, keepOtherCookies: 3, cookieBudgetBytes: 4096 })
  const port = await listen(server)

  const values = []
  const names = []
  const now = Date.now()
  for (let i = 0; i < 100; i += 1) {
    const authority = `127.0.0.1:${50000 + i}`
    const name = cookieName(authority)
    names.push(name)
    values.push(`${name}=${token(authority, { issuedAt: now - i * 1000 })}`)
  }
  const current = token(AUTHORITY)
  const header = `${CURRENT}=${current}; ${values.join('; ')}`
  assert.ok(header.length > 15_000)

  const response = await request(port, header)
  assert.equal(response.status, 200)
  assert.ok(seen[0].length < 4096)
  assert.ok(seen[0].startsWith(`${CURRENT}=${current}`))
  assert.equal(seen[0].split('; ').length, 4)

  const deletions = setCookies(response)
  assert.equal(deletions.length, 100 - 3)
  for (const name of names.slice(3)) {
    assert.ok(deletions.some((cookie) => cookie.startsWith(`${name}=;`)), `missing deletion for ${name}`)
  }

  dispose()
  await close(server)
})

test('deletes expired, invalid, and tampered auth cookies', async () => {
  const seen = []
  const server = http.createServer((req, res) => {
    seen.push(req.headers.cookie)
    res.end('ok')
  })
  const { ctx, dispose } = fakeContext(server)
  apply(ctx, { maxHeaderBytes: 65536 })
  const port = await listen(server)

  const current = token(AUTHORITY)
  const expiredName = cookieName('127.0.0.1:49001')
  const expired = token('127.0.0.1:49001', { issuedAt: Date.now() - 31 * DAY, expiresAt: Date.now() - 1000 })
  const invalidName = cookieName('127.0.0.1:49002')
  const invalid = 'v1.not-json.invalid'
  const shortName = 'dsh-auth-short'
  const shortValue = 'keep-me'

  const response = await request(
    port,
    `${CURRENT}=${current}; ${expiredName}=${expired}; ${invalidName}=${invalid}; ${shortName}=${shortValue}`,
  )
  assert.equal(response.status, 200)
  assert.equal(seen[0], `${CURRENT}=${current}; ${shortName}=${shortValue}`)
  const deletions = setCookies(response)
  assert.equal(deletions.length, 2)
  assert.ok(deletions.some((cookie) => cookie.startsWith(`${expiredName}=;`)))
  assert.ok(deletions.some((cookie) => cookie.startsWith(`${invalidName}=;`)))

  dispose()
  await close(server)
})

test('respects the cookie budget when choosing other authorities', async () => {
  const seen = []
  const server = http.createServer((req, res) => {
    seen.push(req.headers.cookie)
    res.end('ok')
  })
  const { ctx, dispose } = fakeContext(server)
  apply(ctx, { maxHeaderBytes: 65536, keepOtherCookies: 3, cookieBudgetBytes: 512 })
  const port = await listen(server)

  const current = token(AUTHORITY)
  const values = []
  const names = []
  for (let i = 0; i < 5; i += 1) {
    const authority = `127.0.0.1:${51000 + i}`
    const name = cookieName(authority)
    names.push(name)
    values.push(`${name}=${token(authority, { issuedAt: Date.now() - i * 1000 })}`)
  }
  const response = await request(port, `${CURRENT}=${current}; ${values.join('; ')}`)
  assert.equal(response.status, 200)
  assert.equal(seen[0].split('; ').length, 2)
  const deletions = setCookies(response)
  assert.equal(deletions.length, 4)

  dispose()
  await close(server)
})

test('keeps recent other-instance cookies when there is no current cookie yet', async () => {
  const seen = []
  const server = http.createServer((req, res) => {
    seen.push(req.headers.cookie)
    res.end('ok')
  })
  const { ctx, dispose } = fakeContext(server)
  apply(ctx, { maxHeaderBytes: 65536, keepOtherCookies: 2 })
  const port = await listen(server)

  const values = []
  const names = []
  for (let i = 0; i < 4; i += 1) {
    const authority = `127.0.0.1:${52000 + i}`
    const name = cookieName(authority)
    names.push(name)
    values.push(`${name}=${token(authority, { issuedAt: Date.now() - i * 1000 })}`)
  }
  const response = await request(port, values.join('; '))
  assert.equal(response.status, 200)
  assert.equal(seen[0].split('; ').length, 2)
  assert.equal(setCookies(response).length, 2)

  dispose()
  await close(server)
})

test('does nothing when the only auth cookie belongs to the current authority', async () => {
  let calls = 0
  const server = http.createServer((_req, res) => {
    calls += 1
    res.end('ok')
  })
  const { ctx, dispose } = fakeContext(server)
  apply(ctx, { maxHeaderBytes: 65536 })
  const port = await listen(server)

  const response = await request(port, `${CURRENT}=${token(AUTHORITY)}; theme=dark`)
  assert.equal(response.status, 200)
  assert.equal(calls, 1)
  assert.deepEqual(setCookies(response), [])

  dispose()
  await close(server)
})

test('preserves a minted dsh-auth cookie while adding stale deletions', async () => {
  const minted = token(AUTHORITY, { issuedAt: Date.now() + 1 })
  const mintValue = `${CURRENT}=${minted}; Max-Age=2592000; Path=/; HttpOnly; SameSite=Strict`
  const server = http.createServer((_req, res) => {
    res.writeHead(303, { location: './', 'set-cookie': mintValue })
    res.end()
  })
  const { ctx, dispose } = fakeContext(server)
  apply(ctx, { maxHeaderBytes: 65536, keepOtherCookies: 0 })
  const port = await listen(server)

  const old = token(OTHER_AUTHORITY)
  const response = await request(port, `${CURRENT}=${token(AUTHORITY)}; ${OTHER}=${old}`)
  assert.equal(response.status, 303)
  const cookies = setCookies(response)
  assert.equal(cookies.length, 2)
  assert.equal(cookies[0], mintValue)
  assert.ok(cookies[1].startsWith(`${OTHER}=;`))

  dispose()
  await close(server)
})

test('cleans up stale cookies on an unauthorized response too', async () => {
  const server = http.createServer((_req, res) => {
    res.writeHead(401, { 'content-type': 'text/plain; charset=utf-8' })
    res.end('auth required')
  })
  const { ctx, dispose } = fakeContext(server)
  apply(ctx, { maxHeaderBytes: 65536, keepOtherCookies: 0 })
  const port = await listen(server)

  const old = token(OTHER_AUTHORITY)
  const response = await request(port, `${OTHER}=${old}`)
  assert.equal(response.status, 401)
  assert.ok(setCookies(response).some((cookie) => cookie.startsWith(`${OTHER}=;`)))

  dispose()
  await close(server)
})

test('preserves an existing Set-Cookie value set with setHeader', async () => {
  const server = http.createServer((_req, res) => {
    res.setHeader('set-cookie', ['app=1; Path=/'])
    res.end('ok')
  })
  const { ctx, dispose } = fakeContext(server)
  apply(ctx, { maxHeaderBytes: 65536, keepOtherCookies: 0 })
  const port = await listen(server)

  const old = token(OTHER_AUTHORITY)
  const response = await request(port, `${CURRENT}=${token(AUTHORITY)}; ${OTHER}=${old}`)
  const cookies = setCookies(response)
  assert.equal(cookies.length, 2)
  assert.ok(cookies.includes('app=1; Path=/'))
  assert.ok(cookies.some((cookie) => cookie.startsWith(`${OTHER}=;`)))

  dispose()
  await close(server)
})

test('preserves the writeHead statusMessage overload and its headers', async () => {
  const server = http.createServer((_req, res) => {
    res.writeHead(201, 'Created', { 'content-type': 'text/plain', 'x-app': 'yes' })
    res.end('ok')
  })
  const { ctx, dispose } = fakeContext(server)
  apply(ctx, { maxHeaderBytes: 65536, keepOtherCookies: 0 })
  const port = await listen(server)

  const old = token(OTHER_AUTHORITY)
  const response = await request(port, `${CURRENT}=${token(AUTHORITY)}; ${OTHER}=${old}`)
  assert.equal(response.status, 201)
  assert.equal(response.headers['x-app'], 'yes')
  assert.ok(setCookies(response).some((cookie) => cookie.startsWith(`${OTHER}=;`)))

  dispose()
  await close(server)
})

test('handles raw-array writeHead headers', async () => {
  const server = http.createServer((_req, res) => {
    res.writeHead(200, ['content-type', 'text/plain', 'x-app', 'yes'])
    res.end('ok')
  })
  const { ctx, dispose } = fakeContext(server)
  apply(ctx, { maxHeaderBytes: 65536, keepOtherCookies: 0 })
  const port = await listen(server)

  const old = token(OTHER_AUTHORITY)
  const response = await request(port, `${CURRENT}=${token(AUTHORITY)}; ${OTHER}=${old}`)
  assert.equal(response.status, 200)
  assert.equal(response.headers['x-app'], 'yes')
  assert.ok(setCookies(response).some((cookie) => cookie.startsWith(`${OTHER}=;`)))

  dispose()
  await close(server)
})

test('adds deletions when a handler writes before end', async () => {
  const server = http.createServer((_req, res) => {
    res.write('a')
    res.end('b')
  })
  const { ctx, dispose } = fakeContext(server)
  apply(ctx, { maxHeaderBytes: 65536, keepOtherCookies: 0 })
  const port = await listen(server)

  const old = token(OTHER_AUTHORITY)
  const response = await request(port, `${CURRENT}=${token(AUTHORITY)}; ${OTHER}=${old}`)
  assert.equal(response.status, 200)
  assert.equal(response.body, 'ab')
  const deletions = setCookies(response)
  assert.equal(deletions.length, 1)
  assert.ok(deletions[0].startsWith(`${OTHER}=;`))

  dispose()
  await close(server)
})

test('adds deletions when the handler uses implicit headers', async () => {
  const server = http.createServer((_req, res) => {
    res.end('ok')
  })
  const { ctx, dispose } = fakeContext(server)
  apply(ctx, { maxHeaderBytes: 65536, keepOtherCookies: 0 })
  const port = await listen(server)

  const old = token(OTHER_AUTHORITY)
  const response = await request(port, `${CURRENT}=${token(AUTHORITY)}; ${OTHER}=${old}`)
  assert.equal(response.status, 200)
  assert.ok(setCookies(response).some((cookie) => cookie.startsWith(`${OTHER}=;`)))

  dispose()
  await close(server)
})

test('survives a missing webServer.server and reports it', () => {
  const logs = []
  const ctx = {
    webServer: { server: undefined, protocol: 'http:' },
    connection: { browserAuth: { secret: SECRET } },
    logger: { info: (m) => logs.push(m), warn: (m) => logs.push(m) },
    effect() { throw new Error('must not run') },
  }
  assert.doesNotThrow(() => apply(ctx, {}))
  assert.ok(logs.some((message) => message.includes('unavailable')))
})

// ---------------------------------------------------------------------------
// A tiny browser-like jar: process Set-Cookie deletions and prove the next
// request no longer carries the stale names.  This mirrors what a browser does
// with the response headers produced above.
// ---------------------------------------------------------------------------

test('a simulated cookie jar is clean on the next request', async () => {
  const jar = new Map()
  const server = http.createServer((req, res) => {
    for (const cookie of setCookiesFromRequest(req)) jar.set(cookie.name, cookie.value)
    res.end('ok')
  })
  const { ctx, dispose } = fakeContext(server)
  apply(ctx, { maxHeaderBytes: 65536 })
  const port = await listen(server)

  jar.set(CURRENT, token(AUTHORITY))
  for (let i = 0; i < 40; i += 1) {
    const authority = `127.0.0.1:${53000 + i}`
    jar.set(cookieName(authority), token(authority, { issuedAt: Date.now() - (i + 1) * 1000 }))
  }

  const firstHeader = [...jar].map(([name, value]) => `${name}=${value}`).join('; ')
  const first = await request(port, firstHeader)
  assert.ok(firstHeader.length > 9000)
  assert.equal(first.status, 200)
  for (const cookie of setCookies(first)) {
    const at = cookie.indexOf('=')
    const name = cookie.slice(0, at)
    if (/Max-Age=0/.test(cookie)) jar.delete(name)
  }
  assert.equal(jar.size, 4)

  const secondHeader = [...jar].map(([name, value]) => `${name}=${value}`).join('; ')
  const second = await request(port, secondHeader)
  assert.equal(second.status, 200)
  assert.deepEqual(setCookies(second), [])

  dispose()
  await close(server)
})

function setCookiesFromRequest(req) {
  return parseCookies(req.headers.cookie ?? '')
}
