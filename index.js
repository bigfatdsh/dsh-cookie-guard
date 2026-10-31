/**
 * dsh-cookie-guard — stop DSH browser-auth cookies from growing without bound.
 *
 * DSH mints one `dsh-auth-<hash(host:port)>` cookie per listener authority and
 * never expires the cookies minted by earlier launches.  A desktop app that
 * picks a fresh port on every start therefore leaves one more cookie in the
 * browser on every start; browsers eventually refuse the request once the
 * Cookie header reaches their header limit.
 *
 * This host plugin fixes the failure at the HTTP boundary:
 *
 * 1. raises the listener's `maxHeaderSize` so an already-bloated request can
 *    still reach the handler (Node's default is 16 KiB and rejects with 431);
 * 2. drops stale `dsh-auth-*` cookies from `req.headers.cookie` before DSH's
 *    auth code sees them, so authentication only ever inspects the current
 *    authority's cookie;
 * 3. expires stale cookies in the browser with `Set-Cookie` deletion headers;
 * 4. keeps a small, budgeted number of other live authorities' cookies so two
 *    concurrently running DSH instances do not evict each other.
 *
 * The plugin is deliberately dependency-free and does not modify DSH files.
 */

import { createHash, createHmac, timingSafeEqual } from 'node:crypto'

export const name = 'cookie-guard'
export const inject = ['webServer', 'connection']

const AUTH_PREFIX = 'dsh-auth-'
/** A generated cookie name is the prefix plus one base64url SHA-256 digest. */
const AUTH_NAME_PATTERN = /^dsh-auth-[A-Za-z0-9_-]{43}$/
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]*$/

const DEFAULT_MAX_HEADER_BYTES = 256 * 1024
const MIN_MAX_HEADER_BYTES = 16 * 1024
const MAX_MAX_HEADER_BYTES = 1024 * 1024
const DEFAULT_COOKIE_BUDGET_BYTES = 4096
const MIN_COOKIE_BUDGET_BYTES = 256
const MAX_COOKIE_BUDGET_BYTES = 16 * 1024
const DEFAULT_KEEP_OTHER_COOKIES = 3
const MAX_KEEP_OTHER_COOKIES = 8
const DEFAULT_MAX_HEADER_SIZE = 16 * 1024
const CLOCK_SKEW_MS = 5 * 60 * 1000
const LOG_INTERVAL_MS = 5000
const EXPIRED_COOKIE_DATE = 'Thu, 01 Jan 1970 00:00:00 GMT'

/** Resolve and clamp the row config; an invalid value always falls back. */
export function resolveOptions(config) {
  const source = config !== null && typeof config === 'object' ? config : {}
  return {
    maxHeaderBytes: readInteger(
      source.maxHeaderBytes,
      DEFAULT_MAX_HEADER_BYTES,
      MIN_MAX_HEADER_BYTES,
      MAX_MAX_HEADER_BYTES,
    ),
    cookieBudgetBytes: readInteger(
      source.cookieBudgetBytes,
      DEFAULT_COOKIE_BUDGET_BYTES,
      MIN_COOKIE_BUDGET_BYTES,
      MAX_COOKIE_BUDGET_BYTES,
    ),
    keepOtherCookies: readInteger(
      source.keepOtherCookies,
      DEFAULT_KEEP_OTHER_COOKIES,
      0,
      MAX_KEEP_OTHER_COOKIES,
    ),
  }
}

/**
 * Host plugin entry point.
 *
 * @param {import('@deepseek-ai/cordis').Context} ctx - owning plugin context.
 * @param {unknown} config - row config from `cordis.patch.yml`.
 */
export function apply(ctx, config) {
  const options = resolveOptions(config)
  const webServer = ctx.webServer
  const server = webServer?.server
  if (server === undefined || server === null) {
    log(ctx, 'warn', 'cookie-guard: webServer.server is unavailable; cookie cleanup was not installed')
    return
  }

  const secure = webServer.protocol === 'https:'
  const state = { lastLogAt: 0, cleaned: 0, reportedError: false }
  let disposed = false

  ctx.effect(() => {
    const previousMaxHeaderSize = server.maxHeaderSize
    try {
      server.maxHeaderSize = options.maxHeaderBytes
    } catch (error) {
      log(ctx, 'warn', `cookie-guard: cannot raise maxHeaderSize: ${errorMessage(error)}`)
    }

    /**
     * Runs before DSH's own request listener.  Keeping this handler small and
     * exception-safe is important: a failure here must never take down the UI.
     */
    const onRequest = (req, res) => {
      if (disposed) return
      try {
        cleanupRequest(req, res, options, secure, ctx, state)
      } catch (error) {
        if (!state.reportedError) {
          state.reportedError = true
          log(ctx, 'warn', `cookie-guard: cleanup skipped after an internal error: ${errorMessage(error)}`)
        }
      }
    }

    server.prependListener('request', onRequest)
    log(
      ctx,
      'info',
      `cookie-guard: active (maxHeaderSize=${options.maxHeaderBytes}B, budget=${options.cookieBudgetBytes}B, keepOther=${options.keepOtherCookies})`,
    )

    return () => {
      disposed = true
      server.removeListener('request', onRequest)
      // Restore the previous value only when nobody else has changed it since.
      if (server.maxHeaderSize === options.maxHeaderBytes) {
        server.maxHeaderSize = previousMaxHeaderSize ?? DEFAULT_MAX_HEADER_SIZE
      }
    }
  })
}

/**
 * Clean one request: strip stale auth cookies from the header and schedule
 * their deletion on the response.
 *
 * @param {import('node:http').IncomingMessage} req - incoming request.
 * @param {import('node:http').ServerResponse} res - response being prepared.
 * @param {ReturnType<typeof resolveOptions>} options - effective config.
 * @param {boolean} secure - whether this listener serves TLS.
 * @param {import('@deepseek-ai/cordis').Context} ctx - plugin context.
 * @param {{ lastLogAt: number, cleaned: number, requests: number }} state - local counters.
 */
function cleanupRequest(req, res, options, secure, ctx, state) {
  const raw = req.headers.cookie
  if (typeof raw !== 'string' || raw.length === 0 || raw.indexOf(AUTH_PREFIX) === -1) return

  const authority = requestAudience(req.headers, secure)
  const currentName = authority === undefined
    ? undefined
    : AUTH_PREFIX + createHash('sha256').update(authority).digest('base64url')

  const entries = parseCookies(raw)
  if (entries.length === 0) return

  /** @type {Map<string, Array<{ name: string, value: string, raw: string }>>} */
  const groups = new Map()
  for (const entry of entries) {
    if (!AUTH_NAME_PATTERN.test(entry.name)) continue
    const group = groups.get(entry.name)
    if (group === undefined) groups.set(entry.name, [entry])
    else group.push(entry)
  }
  if (groups.size === 0) return

  // Fast path: exactly the current authority's one cookie, nothing stale.
  if (groups.size === 1 && currentName !== undefined) {
    const only = groups.get(currentName)
    if (only !== undefined && only.length === 1) return
  }

  const secret = ctx.connection?.browserAuth?.secret
  const now = Date.now()
  const stale = new Set()
  const current = currentName === undefined ? undefined : groups.get(currentName)
  let keptBytes = 0
  if (current !== undefined) {
    for (const entry of current) keptBytes += entry.raw.length + 2
  }

  /** @type {Array<{ name: string, list: Array<{ raw: string }>, issuedAt: number, bytes: number }>} */
  const candidates = []
  for (const [cookieName, list] of groups) {
    if (cookieName === currentName) continue
    const token = decodeToken(list[0].value, secret)
    if (!isUsable(token, now)) {
      stale.add(cookieName)
      continue
    }
    let bytes = 0
    for (const entry of list) bytes += entry.raw.length + 2
    candidates.push({ name: cookieName, list, issuedAt: token.issuedAt, bytes })
  }

  // Newest first; the name tie-break keeps the choice deterministic.
  candidates.sort((a, b) => b.issuedAt - a.issuedAt || a.name.localeCompare(b.name))

  let keptOther = 0
  for (const candidate of candidates) {
    if (keptOther >= options.keepOtherCookies || keptBytes + candidate.bytes > options.cookieBudgetBytes) {
      stale.add(candidate.name)
      continue
    }
    keptBytes += candidate.bytes
    keptOther += 1
  }

  if (stale.size === 0) return

  // DSH only needs the current authority's cookie.  Removing the rest here
  // also keeps the header small for every downstream consumer.
  const keptEntries = entries.filter((entry) => !stale.has(entry.name))
  if (keptEntries.length === 0) delete req.headers.cookie
  else req.headers.cookie = keptEntries.map((entry) => entry.raw).join('; ')

  const deletions = []
  for (const cookieName of stale) deletions.push(serializeDeletion(cookieName, secure))
  addResponseCookies(res, deletions)

  state.cleaned += stale.size
  const after = typeof req.headers.cookie === 'string' ? req.headers.cookie.length : 0
  const level = raw.length >= 8192 ? 'warn' : 'info'
  const nowForLog = Date.now()
  if (nowForLog - state.lastLogAt >= LOG_INTERVAL_MS) {
    state.lastLogAt = nowForLog
    log(
      ctx,
      level,
      `cookie-guard: removed ${stale.size} stale auth cookie(s), Cookie ${raw.length}->${after} bytes, kept ${keptOther} other authority cookie(s)`,
    )
  }
}

/**
 * Parse a Cookie header without decoding values.  Values are base64url in
 * DSH's format, but the parser also tolerates `=` inside a value.
 *
 * @param {string} header - raw Cookie header.
 * @returns {Array<{ name: string, value: string, raw: string }>} parsed pairs.
 */
export function parseCookies(header) {
  const entries = []
  let start = 0
  while (start < header.length) {
    let end = header.indexOf(';', start)
    if (end === -1) end = header.length
    const raw = header.slice(start, end).trim()
    if (raw.length > 0) {
      const separator = raw.indexOf('=')
      if (separator > 0) {
        entries.push({
          name: raw.slice(0, separator).trim(),
          value: raw.slice(separator + 1).trim(),
          raw,
        })
      }
    }
    start = end + 1
  }
  return entries
}

/**
 * Verify and decode one DSH cookie token.  The signature uses the same
 * persistent secret and HMAC construction as `dsh-client-connection`.
 *
 * @param {string} value - cookie value (`v1.<body>.<signature>`).
 * @param {Buffer | Uint8Array | undefined} secret - auth signing secret.
 * @returns {Record<string, unknown> | undefined} verified payload.
 */
export function decodeToken(value, secret) {
  if (typeof value !== 'string' || value.length === 0) return undefined
  if (typeof secret !== 'string' && !(secret instanceof Uint8Array)) return undefined

  const parts = value.split('.')
  if (parts.length !== 3) return undefined
  const [version, body, encodedSignature] = parts
  if ((version !== 'v1' && version !== 'v2') || body.length === 0 || encodedSignature.length === 0) {
    return undefined
  }

  const actualSignature = decodeBase64Url(encodedSignature)
  if (actualSignature === undefined) return undefined
  const expectedSignature = createHmac('sha256', secret).update(body).digest()
  if (actualSignature.length !== expectedSignature.length) return undefined
  if (!timingSafeEqual(actualSignature, expectedSignature)) return undefined

  const decoded = decodeBase64Url(body)
  if (decoded === undefined) return undefined
  let payload
  try {
    payload = JSON.parse(decoded.toString('utf8'))
  } catch {
    return undefined
  }
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) return undefined
  if (typeof payload.authority !== 'string') return undefined
  if (!Number.isSafeInteger(payload.issuedAt) || !Number.isSafeInteger(payload.expiresAt)) return undefined
  return payload
}

/**
 * Whether a verified token could still authenticate a live DSH instance.
 *
 * @param {Record<string, unknown> | undefined} token - decoded token.
 * @param {number} now - current epoch milliseconds.
 * @returns {boolean} true when the token is unexpired and plausible.
 */
function isUsable(token, now) {
  if (token === undefined) return false
  return token.issuedAt <= now + CLOCK_SKEW_MS
    && token.expiresAt > now
    && token.expiresAt > token.issuedAt
}

/**
 * Compute the exact authority spelling `dsh-client-connection` uses.
 *
 * @param {import('node:http').IncomingHttpHeaders} headers - request headers.
 * @param {boolean} secure - whether the listener serves TLS.
 * @returns {string | undefined} cookie audience.
 */
export function requestAudience(headers, secure) {
  const host = headers.host
  if (typeof host !== 'string' || host.length === 0) return undefined
  try {
    const url = new URL(`${secure ? 'https:' : 'http:'}//${host}`)
    return secure ? url.origin : url.host
  } catch {
    return undefined
  }
}

/**
 * Serialize a cookie deletion that matches DSH's `Path=/`, host-only cookie.
 *
 * @param {string} name - cookie name to expire.
 * @param {boolean} secure - whether the listener serves TLS.
 * @returns {string} Set-Cookie value.
 */
export function serializeDeletion(name, secure) {
  const base = `${name}=; Path=/; Max-Age=0; Expires=${EXPIRED_COOKIE_DATE}; HttpOnly; SameSite=Strict`
  return secure ? `${base}; Secure` : base
}

/**
 * Append deletion cookies to every response shape Node's ServerResponse can
 * produce: explicit `writeHead`, a `set-cookie` set earlier, or implicit
 * headers sent by `write`/`flushHeaders`/`end`.
 *
 * @param {import('node:http').ServerResponse} res - target response.
 * @param {string[]} cookies - Set-Cookie values to append.
 */
function addResponseCookies(res, cookies) {
  if (cookies.length === 0 || res.headersSent) return
  const pending = cookies.slice()
  let added = false
  const originalWriteHead = res.writeHead
  const originalWrite = res.write
  const originalEnd = res.end
  const originalFlushHeaders = res.flushHeaders

  const addImplicit = () => {
    if (added || res.headersSent) return
    added = true
    try {
      const existing = normalizeSetCookie(res.getHeader('set-cookie'))
      res.setHeader('set-cookie', existing.concat(pending))
    } catch {
      // A response that is already gone must not turn cleanup into a crash.
    }
  }

  res.writeHead = function writeHead(statusCode, statusMessage, headers) {
    let message
    let outgoing
    if (arguments.length >= 3) {
      message = statusMessage
      outgoing = headers
    } else {
      message = undefined
      outgoing = statusMessage
    }
    let merged
    try {
      merged = mergeResponseCookies(res, outgoing, added ? [] : pending)
    } catch {
      merged = outgoing ?? {}
    }
    added = true
    if (message === undefined) return originalWriteHead.call(this, statusCode, merged)
    return originalWriteHead.call(this, statusCode, message, merged)
  }

  res.write = function write(...args) {
    addImplicit()
    return originalWrite.apply(this, args)
  }
  res.end = function end(...args) {
    addImplicit()
    return originalEnd.apply(this, args)
  }
  if (typeof originalFlushHeaders === 'function') {
    res.flushHeaders = function flushHeaders(...args) {
      addImplicit()
      return originalFlushHeaders.apply(this, args)
    }
  }
}

/**
 * Merge the response's existing Set-Cookie values with the pending deletions.
 *
 * @param {import('node:http').ServerResponse} res - target response.
 * @param {Record<string, unknown> | unknown[] | undefined} headers - writeHead headers.
 * @param {string[]} pending - deletions to append.
 * @returns {Record<string, unknown> | unknown[]} headers ready for writeHead.
 */
function mergeResponseCookies(res, headers, pending) {
  if (Array.isArray(headers)) {
    const merged = headers.slice()
    for (const cookie of pending) merged.push('set-cookie', cookie)
    return merged
  }

  const source = headers !== null && typeof headers === 'object' ? headers : {}
  const merged = {}
  let existing
  for (const key of Object.keys(source)) {
    if (key.toLowerCase() === 'set-cookie') {
      existing = (existing ?? []).concat(normalizeSetCookie(source[key]))
    } else {
      merged[key] = source[key]
    }
  }
  if (existing === undefined) {
    existing = normalizeSetCookie(res.getHeader('set-cookie'))
  }
  merged['set-cookie'] = existing.concat(pending)
  return merged
}

/** Normalize a header value to an array of strings. */
function normalizeSetCookie(value) {
  if (Array.isArray(value)) return value.filter((item) => typeof item === 'string')
  if (typeof value === 'string') return [value]
  return []
}

/** Strict base64url decoder matching DSH's canonical round-trip check. */
function decodeBase64Url(value) {
  if (!BASE64URL_PATTERN.test(value) || value.length % 4 === 1) return undefined
  const padding = '='.repeat((4 - (value.length % 4)) % 4)
  const decoded = Buffer.from(value.replaceAll('-', '+').replaceAll('_', '/') + padding, 'base64')
  return decoded.toString('base64url') === value ? decoded : undefined
}

/** Clamp an integer config value. */
function readInteger(value, fallback, min, max) {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < min || value > max) return fallback
  return value
}

/** Safe, prefixed logging: a logger failure must not break request handling. */
function log(ctx, level, message) {
  try {
    ctx.logger?.[level]?.(message)
  } catch {
    // Logging is best effort.
  }
}

function errorMessage(error) {
  return error instanceof Error ? error.message : String(error)
}
