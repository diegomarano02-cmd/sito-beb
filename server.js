const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const readline = require('node:readline/promises');
const { DatabaseSync } = require('node:sqlite');
const { randomBytes, createHash, createHmac, scryptSync, timingSafeEqual } = require('node:crypto');

const ROOT_DIR = __dirname;
const DATA_DIR = path.join(ROOT_DIR, 'data');
const DB_PATH = path.join(DATA_DIR, 'reviews.sqlite');
const SETTINGS_PATH = path.join(DATA_DIR, 'settings.json');
const PORT = Number(process.env.PORT) || 3000;
const SESSION_TTL = 12 * 60 * 60 * 1000;
const COOKIE_NAME = 'dds_admin';

fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });

const db = new DatabaseSync(DB_PATH);
db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;
  CREATE TABLE IF NOT EXISTS reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    author TEXT NOT NULL,
    rating INTEGER NOT NULL CHECK (rating BETWEEN 1 AND 5),
    content TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'approved' CHECK (status IN ('pending', 'approved', 'rejected')),
    created_at TEXT NOT NULL,
    published_at TEXT,
    moderated_at TEXT,
    ip_hash TEXT NOT NULL,
    user_agent TEXT NOT NULL DEFAULT ''
  );
  CREATE INDEX IF NOT EXISTS idx_reviews_status_published
    ON reviews (status, published_at DESC, id DESC);
`);

db.prepare(`
  UPDATE reviews
  SET status = 'approved',
      published_at = COALESCE(published_at, created_at),
      moderated_at = ?
  WHERE status = 'pending'
`).run(new Date().toISOString());

function hashPassword(password, salt) {
  return scryptSync(String(password), salt, 64).toString('hex');
}

function setPassword(settings, password) {
  settings.passwordSalt = randomBytes(16).toString('hex');
  settings.passwordHash = hashPassword(password, settings.passwordSalt);
}

function persistSettings(settings) {
  fs.writeFileSync(
    SETTINGS_PATH,
    JSON.stringify(settings, null, 2),
    { mode: 0o600 }
  );
  try {
    fs.chmodSync(SETTINGS_PATH, 0o600);
  } catch {}
}

function loadSettings() {
  let settings;

  try {
    settings = JSON.parse(fs.readFileSync(SETTINGS_PATH, 'utf8'));
  } catch {
    settings = {};
  }

  const generatedNow = !settings.passwordHash;

  if (!settings.passwordSalt) settings.passwordSalt = randomBytes(16).toString('hex');
  if (!settings.sessionSecret) settings.sessionSecret = randomBytes(32).toString('hex');

  let generatedPassword = null;
  if (!settings.passwordHash) {
    generatedPassword = randomBytes(18).toString('base64url');
    setPassword(settings, generatedPassword);
  }

  if (process.env.ADMIN_PASSWORD) {
    setPassword(settings, process.env.ADMIN_PASSWORD);
    generatedPassword = null;
  }

  persistSettings(settings);

  if (generatedPassword) {
    console.log('Password amministratore generata (verrà mostrata solo ora):');
    console.log(`  ${generatedPassword}`);
    console.log('Salvala in un luogo sicuro oppure imposta ADMIN_PASSWORD prima di avviare il server.');
  }

  return settings;
}

const settings = loadSettings();

function verifyPassword(password) {
  const candidate = Buffer.from(hashPassword(password, settings.passwordSalt), 'hex');
  const stored = Buffer.from(settings.passwordHash, 'hex');
  return candidate.length === stored.length && timingSafeEqual(candidate, stored);
}

function signSession(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = createHmac('sha256', Buffer.from(settings.sessionSecret, 'hex'))
    .update(body)
    .digest('base64url');
  return `${body}.${signature}`;
}

function readSession(token) {
  if (!token || typeof token !== 'string') return null;
  const [body, signature] = token.split('.');
  if (!body || !signature) return null;

  const expected = createHmac('sha256', Buffer.from(settings.sessionSecret, 'hex'))
    .update(body)
    .digest('base64url');

  if (
    signature.length !== expected.length ||
    !timingSafeEqual(Buffer.from(signature), Buffer.from(expected))
  ) {
    return null;
  }

  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (payload.sub !== 'admin' || !payload.exp || payload.exp < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const result = {};
  for (const part of header.split(';')) {
    const index = part.indexOf('=');
    if (index === -1) continue;
    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    try {
      result[key] = decodeURIComponent(value);
    } catch {
      result[key] = value;
    }
  }
  return result;
}

function getSession(req) {
  return readSession(parseCookies(req)[COOKIE_NAME]);
}

function buildCookie(req, token, maxAgeSeconds) {
  const secure = req.socket.encrypted || req.headers['x-forwarded-proto'] === 'https';
  return `${COOKIE_NAME}=${token}; HttpOnly; ${secure ? 'Secure; ' : ''}SameSite=Strict; Path=/; Max-Age=${maxAgeSeconds}`;
}

function sendJson(res, statusCode, data, extraHeaders = {}) {
  const body = JSON.stringify(data);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    ...extraHeaders
  });
  res.end(body);
}

function readJson(req, limit = 8192) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let tooLarge = false;

    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > limit) {
        tooLarge = true;
        return;
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      if (tooLarge) {
        reject(new Error('Payload troppo grande.'));
        return;
      }
      try {
        const raw = Buffer.concat(chunks).toString('utf8');
        resolve(raw ? JSON.parse(raw) : {});
      } catch {
        reject(new Error('JSON non valido.'));
      }
    });

    req.on('error', reject);
  });
}

const submissionLog = new Map();
const loginLog = new Map();

function pruneLog(log, key, windowMs) {
  const now = Date.now();
  const entries = (log.get(key) || []).filter((time) => now - time < windowMs);
  if (entries.length) log.set(key, entries);
  else log.delete(key);
  return entries;
}

function clientIp(req) {
  return String(req.socket.remoteAddress || 'unknown').slice(0, 64);
}

function checkSubmissionLimit(req) {
  const ip = clientIp(req);
  const windowMs = 60 * 60 * 1000;
  const entries = pruneLog(submissionLog, ip, windowMs);
  const last = entries[entries.length - 1];

  if (last && Date.now() - last < 60 * 1000) {
    return 'Attendi un minuto prima di inviare un\'altra recensione.';
  }

  if (entries.length >= 3) {
    return 'Hai inviato troppe recensioni in poco tempo. Riprova più tardi.';
  }

  entries.push(Date.now());
  submissionLog.set(ip, entries);
  return null;
}

function checkLoginLimit(req) {
  const ip = clientIp(req);
  const windowMs = 15 * 60 * 1000;
  const entries = pruneLog(loginLog, ip, windowMs);

  if (entries.length >= 10) {
    return 'Troppi tentativi di accesso. Riprova tra qualche minuto.';
  }

  entries.push(Date.now());
  loginLog.set(ip, entries);
  return null;
}

setInterval(() => {
  const now = Date.now();
  for (const [key, entries] of submissionLog) {
    const fresh = entries.filter((time) => now - time < 60 * 60 * 1000);
    if (fresh.length) submissionLog.set(key, fresh);
    else submissionLog.delete(key);
  }
  for (const [key, entries] of loginLog) {
    const fresh = entries.filter((time) => now - time < 15 * 60 * 1000);
    if (fresh.length) loginLog.set(key, fresh);
    else loginLog.delete(key);
  }
}, 10 * 60 * 1000).unref();

function validateReview(body) {
  const name = String(body.name ?? '').replace(/\s+/g, ' ').trim();
  const rating = Number(body.rating);
  const content = String(body.content ?? '').trim().replace(/\n{3,}/g, '\n\n');
  const website = String(body.website ?? '').trim();

  if (website) {
    return { error: 'Invio non consentito.' };
  }

  if (name.length < 2 || name.length > 80 || !/\p{L}/u.test(name)) {
    return { error: 'Inserisci nome e cognome (da 2 a 80 caratteri).' };
  }

  if (!Number.isInteger(rating) || rating < 1 || rating > 5) {
    return { error: 'Seleziona una valutazione da 1 a 5 stelle.' };
  }

  if (content.length < 20 || content.length > 1000) {
    return { error: 'La recensione deve contenere tra 20 e 1000 caratteri.' };
  }

  if (/(https?:\/\/|www\.)/i.test(content) || /[\w.+-]+@[\w-]+\.[\w.]+/i.test(content)) {
    return { error: 'Non inserire link o indirizzi email nella recensione.' };
  }

  if (/(.)\1{9,}/su.test(content)) {
    return { error: 'La recensione contiene ripetizioni non valide.' };
  }

  const nonSpace = content.replace(/\s/g, '');
  if (nonSpace.length < 15) {
    return { error: 'La recensione è troppo breve.' };
  }

  return { name, rating, content };
}

function findRecentDuplicate(content, ipHash) {
  const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
  return db.prepare(`
    SELECT id FROM reviews
    WHERE (content = ? OR ip_hash = ?)
      AND created_at > ?
    LIMIT 1
  `).get(content, ipHash, since);
}

function getPublicReviews() {
  const rows = db.prepare(`
    SELECT
      id,
      author,
      rating,
      content,
      COALESCE(published_at, created_at) AS published_at
    FROM reviews
    WHERE status = 'approved'
    ORDER BY COALESCE(published_at, created_at) DESC, id DESC
  `).all();

  const total = rows.length;
  const average = total
    ? Math.round((rows.reduce((sum, row) => sum + row.rating, 0) / total) * 10) / 10
    : null;

  return {
    reviews: rows,
    stats: { total, average }
  };
}

function getAdminReviews() {
  return db.prepare(`
    SELECT
      id,
      author,
      rating,
      content,
      status,
      created_at,
      published_at,
      moderated_at
    FROM reviews
    ORDER BY
      CASE status WHEN 'pending' THEN 0 WHEN 'approved' THEN 1 ELSE 2 END,
      COALESCE(published_at, created_at) DESC,
      id DESC
  `).all();
}

function requireAdmin(req, res) {
  const session = getSession(req);
  if (!session) {
    sendJson(res, 401, { ok: false, error: 'Accesso non autorizzato.' });
    return null;
  }
  return session;
}

function requireCsrf(req, res, session) {
  const token = String(req.headers['x-csrf-token'] || '');
  if (!session.csrf || token !== session.csrf) {
    sendJson(res, 403, { ok: false, error: 'Richiesta non valida.' });
    return false;
  }
  return true;
}

async function handleApi(req, res, pathname) {
  if (pathname === '/api/reviews' && req.method === 'GET') {
    sendJson(res, 200, { ok: true, ...getPublicReviews() });
    return;
  }

  if (pathname === '/api/reviews' && req.method === 'POST') {
    let body;
    try {
      body = await readJson(req);
    } catch (error) {
      sendJson(res, 400, { ok: false, error: error.message });
      return;
    }

    const validated = validateReview(body);
    if (validated.error) {
      sendJson(res, 400, { ok: false, error: validated.error });
      return;
    }

    const limitError = checkSubmissionLimit(req);
    if (limitError) {
      sendJson(res, 429, { ok: false, error: limitError });
      return;
    }

    const ipHash = createHash('sha256')
      .update(clientIp(req))
      .update(settings.sessionSecret)
      .digest('hex')
      .slice(0, 32);

    if (findRecentDuplicate(validated.content, ipHash)) {
      sendJson(res, 409, { ok: false, error: 'Questa recensione è già stata inviata di recente.' });
      return;
    }

    const createdAt = new Date().toISOString();
    db.prepare(`
      INSERT INTO reviews (author, rating, content, status, created_at, published_at, moderated_at, ip_hash, user_agent)
      VALUES (?, ?, ?, 'approved', ?, ?, ?, ?, ?)
    `).run(
      validated.name,
      validated.rating,
      validated.content,
      createdAt,
      createdAt,
      createdAt,
      ipHash,
      String(req.headers['user-agent'] || '').slice(0, 240)
    );

    sendJson(res, 201, {
      ok: true,
      message: 'Grazie! La tua recensione è stata pubblicata ed è ora visibile a tutti.'
    });
    return;
  }

  if (pathname === '/api/admin/session' && req.method === 'GET') {
    const session = getSession(req);
    sendJson(res, 200, {
      ok: true,
      authenticated: Boolean(session),
      csrf: session ? session.csrf : null
    });
    return;
  }

  if (pathname === '/api/admin/login' && req.method === 'POST') {
    const limitError = checkLoginLimit(req);
    if (limitError) {
      sendJson(res, 429, { ok: false, error: limitError });
      return;
    }

    let body;
    try {
      body = await readJson(req, 2048);
    } catch (error) {
      sendJson(res, 400, { ok: false, error: error.message });
      return;
    }

    if (!verifyPassword(String(body.password ?? ''))) {
      sendJson(res, 401, { ok: false, error: 'Password non corretta.' });
      return;
    }

    loginLog.delete(clientIp(req));

    const csrf = randomBytes(16).toString('base64url');
    const token = signSession({
      sub: 'admin',
      iat: Date.now(),
      exp: Date.now() + SESSION_TTL,
      csrf
    });

    sendJson(res, 200, { ok: true, csrf }, {
      'Set-Cookie': buildCookie(req, token, Math.floor(SESSION_TTL / 1000))
    });
    return;
  }

  if (pathname === '/api/admin/logout' && req.method === 'POST') {
    sendJson(res, 200, { ok: true }, {
      'Set-Cookie': buildCookie(req, '', 0)
    });
    return;
  }

  if (pathname === '/api/admin/reviews' && req.method === 'GET') {
    const session = requireAdmin(req, res);
    if (!session) return;
    sendJson(res, 200, { ok: true, reviews: getAdminReviews() });
    return;
  }

  const moderateMatch = pathname.match(/^\/api\/admin\/reviews\/(\d+)\/(approve|reject)$/);
  if (moderateMatch && req.method === 'POST') {
    const session = requireAdmin(req, res);
    if (!session) return;
    if (!requireCsrf(req, res, session)) return;

    const id = Number(moderateMatch[1]);
    const action = moderateMatch[2];
    const now = new Date().toISOString();

    const result = action === 'approve'
      ? db.prepare(`
          UPDATE reviews
          SET status = 'approved', published_at = ?, moderated_at = ?
          WHERE id = ?
        `).run(now, now, id)
      : db.prepare(`
          UPDATE reviews
          SET status = 'rejected', published_at = NULL, moderated_at = ?
          WHERE id = ?
        `).run(now, id);

    if (!result.changes) {
      sendJson(res, 404, { ok: false, error: 'Recensione non trovata.' });
      return;
    }

    sendJson(res, 200, { ok: true, message: action === 'approve' ? 'Recensione approvata.' : 'Recensione rifiutata.' });
    return;
  }

  const deleteMatch = pathname.match(/^\/api\/admin\/reviews\/(\d+)$/);
  if (deleteMatch && req.method === 'DELETE') {
    const session = requireAdmin(req, res);
    if (!session) return;
    if (!requireCsrf(req, res, session)) return;

    const result = db.prepare('DELETE FROM reviews WHERE id = ?').run(Number(deleteMatch[1]));
    if (!result.changes) {
      sendJson(res, 404, { ok: false, error: 'Recensione non trovata.' });
      return;
    }

    sendJson(res, 200, { ok: true, message: 'Recensione eliminata.' });
    return;
  }

  sendJson(res, 404, { ok: false, error: 'Endpoint non trovato.' });
}

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.jfif': 'image/jpeg',
  '.png': 'image/png',
  '.gif': 'image/gif',
  '.webp': 'image/webp',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.txt': 'text/plain; charset=utf-8'
};

const BLOCKED_NAMES = new Set(['data', 'node_modules', '.git', '.env', 'server.js', 'package.json', 'package-lock.json']);

function serveStatic(req, res, pathname) {
  let relativePath;

  try {
    relativePath = decodeURIComponent(pathname);
  } catch {
    sendJson(res, 400, { ok: false, error: 'Percorso non valido.' });
    return;
  }

  if (relativePath === '/' || relativePath === '/index.html') relativePath = '/index.html';
  if (relativePath === '/admin') relativePath = '/admin.html';

  const resolved = path.resolve(ROOT_DIR, `.${relativePath}`);
  const relativeToRoot = path.relative(ROOT_DIR, resolved);
  const firstSegment = relativeToRoot.split(path.sep)[0];

  if (
    relativeToRoot.startsWith('..') ||
    path.isAbsolute(relativeToRoot) ||
    BLOCKED_NAMES.has(firstSegment) ||
    firstSegment.startsWith('.')
  ) {
    sendJson(res, 403, { ok: false, error: 'Accesso negato.' });
    return;
  }

  const extension = path.extname(resolved).toLowerCase();
  if (!MIME_TYPES[extension]) {
    sendJson(res, 403, { ok: false, error: 'Tipo di file non consentito.' });
    return;
  }

  fs.stat(resolved, (error, stats) => {
    if (error || !stats.isFile()) {
      sendJson(res, 404, { ok: false, error: 'File non trovato.' });
      return;
    }

    const cacheControl = extension === '.html'
      ? 'no-cache'
      : /\.(jpe?g|png|gif|webp)$/.test(extension)
        ? 'public, max-age=86400'
        : 'no-cache';

    res.writeHead(200, {
      'Content-Type': MIME_TYPES[extension],
      'Content-Length': stats.size,
      'Cache-Control': cacheControl,
      'X-Content-Type-Options': 'nosniff'
    });

    if (req.method === 'HEAD') {
      res.end();
      return;
    }

    const stream = fs.createReadStream(resolved);
    stream.on('error', () => res.destroy());
    stream.pipe(res);
  });
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const pathname = url.pathname;

    if (pathname.startsWith('/api/')) {
      await handleApi(req, res, pathname);
      return;
    }

    if (req.method === 'GET' || req.method === 'HEAD') {
      serveStatic(req, res, pathname);
      return;
    }

    sendJson(res, 405, { ok: false, error: 'Metodo non consentito.' });
  } catch (error) {
    console.error(error);
    if (!res.headersSent) {
      sendJson(res, 500, { ok: false, error: 'Errore interno del server.' });
    } else {
      res.destroy();
    }
  }
});

async function setPasswordInteractive() {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const password = await rl.question('Nuova password amministratore (minimo 10 caratteri): ');
  rl.close();

  if (String(password).length < 10) {
    console.error('La password deve contenere almeno 10 caratteri.');
    process.exit(1);
  }

  setPassword(settings, password);
  persistSettings(settings);
  console.log('Password amministratore aggiornata.');
  process.exit(0);
}

if (process.argv.includes('--set-password')) {
  setPasswordInteractive();
} else {
  server.listen(PORT, '0.0.0.0', () => {
    const addresses = Object.values(os.networkInterfaces())
      .flat()
      .filter((item) => item && item.family === 'IPv4' && !item.internal)
      .map((item) => item.address);

    console.log(`Dimora del Sole in ascolto su http://localhost:${PORT}`);
    for (const address of addresses) {
      console.log(`Rete locale: http://${address}:${PORT}`);
    }
    console.log(`Area amministrazione: http://localhost:${PORT}/admin`);
  });

  process.on('SIGINT', () => {
    server.close(() => {
      db.close();
      process.exit(0);
    });
  });
}
