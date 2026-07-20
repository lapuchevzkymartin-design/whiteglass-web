import { createHash, timingSafeEqual } from 'node:crypto';

const WINDOW_MS = 15 * 60 * 1000;
const MAX_ATTEMPTS = 5;
const MAX_ACCOUNT_ATTEMPTS = 20;
const attempts = globalThis.__whiteglassAdminAttempts ?? new Map();
globalThis.__whiteglassAdminAttempts = attempts;

function clientKey(req) {
  const forwarded = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  const address = forwarded || req.socket?.remoteAddress || 'unknown';
  return createHash('sha256').update(address).digest('hex').slice(0, 20);
}

function secureEqual(received, expected) {
  const receivedHash = createHash('sha256').update(received).digest();
  const expectedHash = createHash('sha256').update(expected).digest();
  return timingSafeEqual(receivedHash, expectedHash);
}

function getAttemptState(key, now) {
  const current = attempts.get(key);
  if (!current || now >= current.resetAt) {
    const fresh = { count: 0, resetAt: now + WINDOW_MS };
    attempts.set(key, fresh);
    return fresh;
  }
  return current;
}

function sameOriginRequest(req) {
  const fetchSite = String(req.headers['sec-fetch-site'] || '').toLowerCase();
  if (fetchSite && !['same-origin', 'none'].includes(fetchSite)) return false;

  const origin = req.headers.origin;
  const host = req.headers['x-forwarded-host'] || req.headers.host;
  if (!origin || !host) return true;
  return origin === `https://${host}` || origin === `http://${host}`;
}

const wait = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  res.setHeader('Content-Type', 'application/json; charset=utf-8');

  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ ok: false });
  }

  if (!sameOriginRequest(req)) return res.status(403).json({ ok: false });
  if (!String(req.headers['content-type'] || '').toLowerCase().startsWith('application/json')) {
    return res.status(415).json({ ok: false });
  }

  const contentLength = Number(req.headers['content-length'] || 0);
  if (contentLength > 512) return res.status(413).json({ ok: false });

  const adminPass = process.env.ADMIN_PASS;
  if (!adminPass) return res.status(500).json({ ok: false });

  let pass = null;
  try {
    pass = typeof req.body === 'string'
      ? JSON.parse(req.body || '{}').pass
      : req.body?.pass;
  } catch {
    pass = null;
  }

  const key = clientKey(req);
  const now = Date.now();
  const state = getAttemptState(key, now);
  const accountState = getAttemptState('account', now);
  if (state.count >= MAX_ATTEMPTS || accountState.count >= MAX_ACCOUNT_ATTEMPTS) {
    res.setHeader('Retry-After', '900');
    return res.status(429).json({ ok: false });
  }

  const validInput = typeof pass === 'string' && pass.length > 0 && pass.length <= 128;
  const validPassword = validInput && secureEqual(pass, adminPass);
  if (validPassword) {
    attempts.delete(key);
    attempts.delete('account');
    console.info('admin_auth_success', { client: key });
    return res.status(200).json({ ok: true });
  }

  state.count += 1;
  accountState.count += 1;
  attempts.set(key, state);
  attempts.set('account', accountState);
  console.warn('admin_auth_failure', { client: key, attempts: state.count });
  await wait(250);
  return res.status(401).json({ ok: false });
}
