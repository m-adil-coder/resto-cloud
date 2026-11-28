require('dotenv').config()
const express = require('express')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const crypto = require('crypto')
const path = require('path')
const fs = require('fs')
const zlib = require('zlib')
const { pool, init } = require('./db')

const SECRET = process.env.JWT_SECRET || ''
const GRACE = Number(process.env.GRACE_DAYS) || 5
const PORT = Number(process.env.PORT) || 4000

if (SECRET.length < 32 && require.main === module) {
  console.error('JWT_SECRET in .env must be at least 32 characters long.')
  process.exit(1)
}

const app = express()
app.set('trust proxy', 1)
app.disable('x-powered-by')
app.use(express.json({ limit: '25mb' }))

// Lightweight gzip compression for JSON/HTML/JS/CSS responses > 1KB
app.use((req, res, next) => {
  const ae = String(req.headers['accept-encoding'] || '')
  if (!ae.includes('gzip') || req.method === 'HEAD') return next()
  const origWrite = res.write.bind(res)
  const origEnd = res.end.bind(res)
  const chunks = []
  let buffered = false
  let decided = false

  function shouldCompress() {
    if (decided) return buffered
    decided = true
    const ct = String(res.getHeader('Content-Type') || '')
    const ce = res.getHeader('Content-Encoding')
    if (ce || !/(json|text\/html|javascript|text\/css|csv|svg|xml)/i.test(ct)) {
      buffered = false
      return false
    }
    buffered = true
    return true
  }

  res.write = (chunk, enc, cb) => {
    if (shouldCompress()) {
      const encStr = typeof enc === 'string' ? enc : undefined
      const done = typeof enc === 'function' ? enc : cb
      if (chunk) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encStr))
      if (typeof done === 'function') done()
      return true
    }
    return origWrite(chunk, enc, cb)
  }

  res.end = (chunk, enc, cb) => {
    if (!shouldCompress()) return origEnd(chunk, enc, cb)
    const encStr = typeof enc === 'string' ? enc : undefined
    const done = typeof enc === 'function' ? enc : cb
    if (chunk && typeof chunk !== 'function') chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encStr))
    const raw = Buffer.concat(chunks)
    if (raw.length < 1024) {
      return origEnd(raw, done)
    }
    res.setHeader('Content-Encoding', 'gzip')
    res.setHeader('Vary', 'Accept-Encoding')
    res.removeHeader('Content-Length')
    zlib.gzip(raw, (err, zipped) => {
      if (err) {
        res.removeHeader('Content-Encoding')
        return origEnd(raw, done)
      }
      origEnd(zipped, done)
    })
  }
  next()
})

// Block direct HTTP access to server/source/config files even with static fallback
app.use((req, res, next) => {
  const p = req.path.toLowerCase()
  if (
    p === '/server.js' ||
    p === '/db.js' ||
    p === '/package.json' ||
    p === '/package-lock.json' ||
    p.startsWith('/.env') ||
    p.startsWith('/.git') ||
    p.startsWith('/android') ||
    p.startsWith('/node_modules')
  ) {
    return res.status(404).end()
  }
  next()
})

const staticOpts = {
  dotfiles: 'allow',
  setHeaders: (res, filePath) => {
    const base = path.basename(filePath).toLowerCase()
    if (base === 'sw.js' || base.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate')
    } else if (base.endsWith('.png') || base.endsWith('.json')) {
      res.setHeader('Cache-Control', 'public, max-age=3600')
    }
  }
}
app.use(express.static(path.join(__dirname, 'public'), staticOpts))
app.use(express.static(__dirname, staticOpts))

app.get('/api/health', (req, res) => {
  res.json({ ok: true, ts: Date.now() })
})

app.get('/.well-known/assetlinks.json', (req, res) => {
  const p1 = path.join(__dirname, 'public', '.well-known', 'assetlinks.json')
  const p2 = path.join(__dirname, '.well-known', 'assetlinks.json')
  const p3 = path.join(__dirname, 'assetlinks.json')
  if (fs.existsSync(p1)) return res.sendFile(p1)
  if (fs.existsSync(p2)) return res.sendFile(p2)
  if (fs.existsSync(p3)) return res.sendFile(p3)
  res.status(404).json({ error: 'assetlinks.json not yet uploaded' })
})

app.get('/download', (req, res) => {
  const url = process.env.DESKTOP_DOWNLOAD_URL || 'https://github.com/m-adil-coder/resto-cloud/releases/download/v1.0.0/resto-pos-1.0.0-setup.exe'
  res.redirect(url)
})

// ---------- helpers ----------
const today = () => new Date(Date.now() + 5 * 3600e3).toISOString().slice(0, 10) // Pakistan date
const nowPkt = () => new Date(Date.now() + 5 * 3600e3).toISOString().replace('T', ' ').slice(0, 19)
const addDays = (d, n) => {
  const x = new Date(d + 'T00:00:00Z')
  x.setUTCDate(x.getUTCDate() + n)
  return x.toISOString().slice(0, 10)
}
const diffDays = (a, b) => Math.round((Date.parse(a + 'T00:00:00Z') - Date.parse(b + 'T00:00:00Z')) / 864e5)
const wrap = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch((e) => {
    console.error(e)
    res.status(500).json({ ok: false, message: 'Server error' })
  })
const isUuid = (s) =>
  typeof s === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s)
const isEmail = (s) => typeof s === 'string' && s.length <= 120 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s)
const clean = (s, max = 120) => String(s ?? '').trim().slice(0, max)
const num = (v) => (Number.isFinite(Number(v)) ? Number(v) : 0)
const isDate = (s) => typeof s === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(s)
const isImage = (s) => s === '' || (typeof s === 'string' && s.startsWith('data:image/') && s.length <= 400000)
const bad = (res, message, code = 400) => res.status(code).json({ ok: false, message })

function signImg(rid, pid) {
  return crypto.createHmac('sha256', SECRET).update(`${rid}:${pid}`).digest('hex').slice(0, 16)
}
function verifyImgSig(rid, pid, sig) {
  if (typeof sig !== 'string' || sig.length !== 16) return false
  const expected = signImg(rid, pid)
  try {
    return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))
  } catch {
    return false
  }
}

function naturalSortByName(rows) {
  return [...rows].sort((a, b) =>
    String(a.name || '').localeCompare(String(b.name || ''), undefined, { numeric: true, sensitivity: 'base' })
  )
}

async function seedDefaultTablesIfNeeded(rid) {
  const existing = await pool.query('SELECT 1 FROM tables WHERE restaurant_id = $1 LIMIT 1', [rid])
  if (existing.rowCount > 0) return
  const client = await pool.connect()
  try {
    await client.query('BEGIN')
    const check = await client.query('SELECT 1 FROM tables WHERE restaurant_id = $1 LIMIT 1', [rid])
    if (check.rowCount === 0) {
      for (let t = 1; t <= 10; t++) {
        await client.query(
          'INSERT INTO tables (restaurant_id, id, name, is_active) VALUES ($1,$2,$3,TRUE)',
          [rid, crypto.randomUUID(), `Table ${t}`]
        )
      }
    }
    await client.query('COMMIT')
  } catch (e) {
    await client.query('ROLLBACK')
    throw e
  } finally {
    client.release()
  }
}

// simple protection against password guessing
const fails = new Map()
const limited = (k) => {
  const e = fails.get(k)
  return !!e && e.count >= 15 && Date.now() - e.t < 2 * 60e3
}
const addFail = (k) => {
  const e = fails.get(k)
  if (!e || Date.now() - e.t > 2 * 60e3) fails.set(k, { count: 1, t: Date.now() })
  else e.count++
}

function auth(role) {
  return wrap(async (req, res, next) => {
    const h = req.headers.authorization || ''
    const token = h.startsWith('Bearer ') ? h.slice(7) : ''
    let p
    try {
      p = jwt.verify(token, SECRET)
      if (p.role !== role) throw new Error('wrong role')
    } catch {
      return res.status(401).json({ ok: false, message: 'Please log in again' })
    }
    req.auth = p
    if (role === 'restaurant') {
      if (p.uid) {
        const uRes = await pool.query(
          'SELECT id, name, username, role, is_active FROM users WHERE restaurant_id = $1 AND id = $2',
          [p.rid, p.uid]
        )
        const u = uRes.rows[0]
        if (!u || !u.is_active) {
          return res.status(401).json({ ok: false, message: 'Your staff account has been blocked or removed. Contact administrator.' })
        }
        req.staff = { id: u.id, name: u.name, username: u.username, role: u.role || 'cashier' }
      } else {
        req.staff = { id: null, name: p.uname || '', username: p.uuser || '', role: 'admin' }
      }
    }
    next()
  })
}

function needRole(...roles) {
  return (req, res, next) => {
    const r = (req.staff && req.staff.role) || 'cashier'
    if (!roles.includes(r)) {
      return bad(res, 'You do not have permission for this section', 403)
    }
    next()
  }
}

const RCOLS = `id, name, owner_name, email, phone, city, status, plan,
  monthly_fee::float AS monthly_fee, paid_until::text AS paid_until, notes, last_seen, created_at`

async function getRestaurant(id) {
  const { rows } = await pool.query(`SELECT ${RCOLS} FROM restaurants WHERE id = $1`, [id])
  return rows[0]
}

// What the desktop app and the web panel are allowed to do
function licenseOf(r) {
  const daysLeft = r.paid_until ? diffDays(r.paid_until, today()) : null
  let state = r.status
  if (state === 'active' && daysLeft !== null && daysLeft < -GRACE) state = 'expired'

  let message = ''
  if (state === 'active' && daysLeft !== null) {
    if (daysLeft < 0) message = `Subscription expired. The app will lock in ${GRACE + daysLeft + 1} day(s).`
    else if (daysLeft <= 5) message = `Subscription ends in ${daysLeft} day(s).`
  }
  if (state === 'paused') message = 'Your account is paused. Please contact support.'
  if (state === 'expired') message = 'Your subscription has expired. Please contact support.'

  return { state, paid_until: r.paid_until, days_left: daysLeft, grace_days: GRACE, message }
}

// Editing is allowed only while the subscription is active (admin "open system" can always edit)
const needActive = wrap(async (req, res, next) => {
  if (req.auth.imp) return next()
  const r = await getRestaurant(req.auth.rid)
  if (!r) return bad(res, 'Please log in again', 401)
  const lic = licenseOf(r)
  if (lic.state !== 'active') return bad(res, lic.message || 'Account is not active', 403)
  next()
})

async function reportFor(rid, from, to, withBills) {
  const where = `restaurant_id = $1 AND created_at::date BETWEEN $2 AND $3`
  const args = [rid, from, to]
  const [sum, sold, pay, day, items] = await Promise.all([
    pool.query(
      `SELECT COUNT(*)::int AS bills, COALESCE(SUM(total),0)::float AS sales,
              COALESCE(SUM(guests),0)::int AS guests FROM bills WHERE ${where}`,
      args
    ),
    pool.query(
      `SELECT COALESCE(SUM((i->>'qty')::int),0)::int AS qty
       FROM bills b, jsonb_array_elements(b.items) i
       WHERE b.restaurant_id = $1 AND b.created_at::date BETWEEN $2 AND $3`,
      args
    ),
    pool.query(
      `SELECT COALESCE(payment_method,'Cash') AS method, SUM(total)::float AS total
       FROM bills WHERE ${where} GROUP BY 1`,
      args
    ),
    pool.query(
      `SELECT created_at::date::text AS day, SUM(total)::float AS total
       FROM bills WHERE ${where} GROUP BY 1 ORDER BY 1`,
      args
    ),
    pool.query(
      `SELECT i->>'name' AS name, SUM((i->>'qty')::int)::int AS qty,
              SUM((i->>'qty')::int * (i->>'price')::float)::float AS amount
       FROM bills b, jsonb_array_elements(b.items) i
       WHERE b.restaurant_id = $1 AND b.created_at::date BETWEEN $2 AND $3
       GROUP BY 1 ORDER BY qty DESC, 1 LIMIT 300`,
      args
    )
  ])

  let bills = []
  if (withBills) {
    const b = await pool.query(
      `SELECT id, bill_no, to_char(created_at, 'YYYY-MM-DD HH24:MI:SS') AS created_at, order_type,
              table_name, COALESCE(waiter_name, '') AS waiter_name, guests, subtotal::float AS subtotal, discount::float AS discount,
              tax::float AS tax, total::float AS total, COALESCE(payment_method,'Cash') AS payment_method, items
       FROM bills WHERE ${where} ORDER BY created_at DESC, bill_no DESC LIMIT 1000`,
      args
    )
    bills = b.rows
  }

  return {
    summary: { ...sum.rows[0], items_sold: sold.rows[0].qty },
    payments: pay.rows,
    days: day.rows,
    items: items.rows,
    bills
  }
}

const rangeOf = (q) => {
  const from = isDate(q.from) ? q.from : today()
  const to = isDate(q.to) ? q.to : from
  return from <= to ? { from, to } : null
}

// ---------- restaurant: sign up and login ----------
app.post(
  '/api/signup',
  wrap(async (req, res) => {
    const b = req.body || {}
    const name = clean(b.restaurant_name)
    const owner = clean(b.owner_name)
    const email = clean(b.email).toLowerCase()
    const phone = clean(b.phone, 30)
    const city = clean(b.city, 60)
    const password = String(b.password || '')

    if (!name || !owner) return bad(res, 'Enter the restaurant name and your name')
    if (!isEmail(email)) return bad(res, 'Enter a valid email')
    if (password.length < 8) return bad(res, 'Password must be at least 8 characters')

    const exists = await pool.query('SELECT 1 FROM restaurants WHERE email = $1', [email])
    if (exists.rowCount) return bad(res, 'This email is already registered', 409)

    const trialUntil = addDays(today(), 15)
    await pool.query(
      `INSERT INTO restaurants (id, name, owner_name, email, phone, city, password_hash, status, paid_until)
       VALUES ($1,$2,$3,$4,$5,$6,$7,'active',$8::date)`,
      [crypto.randomUUID(), name, owner, email, phone, city, bcrypt.hashSync(password, 10), trialUntil]
    )
    res.json({ ok: true, message: 'Account created! Your 15-day free trial is active. You can log in now.' })
  })
)

app.post(
  '/api/login',
  wrap(async (req, res) => {
    const emailOrUser = clean(req.body?.email).toLowerCase()
    const restEmail = clean(req.body?.restaurant_email).toLowerCase()
    const password = String(req.body?.password || '')
    const key = `${req.ip}|${restEmail}|${emailOrUser}`
    if (limited(key)) return bad(res, 'Too many attempts. Try again in 15 minutes.', 429)

    let targetRestaurant = null
    let staffUser = null

    // 1. Desktop link / Owner email login check (when no explicit restaurant_email or email === restEmail)
    if (!restEmail || restEmail === emailOrUser) {
      const { rows } = await pool.query('SELECT id, password_hash, status, owner_name, name, email FROM restaurants WHERE email = $1', [emailOrUser])
      const r = rows[0]
      if (r && bcrypt.compareSync(password, r.password_hash)) {
        targetRestaurant = r
      }
    }

    // 2. Staff login (Cashier / Manager / Admin created in users table) - never used for desktop device=true link
    if (!targetRestaurant && !req.body?.device) {
      let uRows = []
      if (restEmail) {
        const q = await pool.query(
          `SELECT u.id, u.name, u.username, u.password_hash, u.role, u.is_active,
                  r.id AS rid, r.status AS rstatus, r.name AS rname, r.owner_name, r.email AS remail, r.password_hash AS rhash
           FROM users u JOIN restaurants r ON r.id = u.restaurant_id
           WHERE lower(r.email) = $1 AND lower(u.username) = $2`,
          [restEmail, emailOrUser]
        )
        uRows = q.rows
      } else {
        const q = await pool.query(
          `SELECT u.id, u.name, u.username, u.password_hash, u.role, u.is_active,
                  r.id AS rid, r.status AS rstatus, r.name AS rname, r.owner_name, r.email AS remail, r.password_hash AS rhash
           FROM users u JOIN restaurants r ON r.id = u.restaurant_id
           WHERE lower(u.username) = $1`,
          [emailOrUser]
        )
        uRows = q.rows
      }

      const validPwMatches = uRows.filter((u) => u.password_hash && bcrypt.compareSync(password, u.password_hash))
      const activeMatches = validPwMatches.filter((u) => u.is_active)

      if (activeMatches.length > 1 && !restEmail) {
        return res.status(409).json({
          ok: false,
          need_restaurant_email: true,
          message: 'Multiple restaurants use this username. Please also enter your Restaurant Email.'
        })
      }
      if (activeMatches.length === 1) {
        const m = activeMatches[0]
        targetRestaurant = { id: m.rid, status: m.rstatus, password_hash: m.rhash, name: m.rname, owner_name: m.owner_name, email: m.remail }
        staffUser = { id: m.id, name: m.name, username: m.username, role: m.role || 'cashier' }
      } else if (validPwMatches.length > 0 && activeMatches.length === 0) {
        fails.delete(key)
        return bad(res, 'Your staff account has been blocked/deactivated. Please contact administrator.', 403)
      }
    }

    if (!targetRestaurant) {
      addFail(key)
      return bad(res, 'Wrong email/username or password', 401)
    }
    fails.delete(key)

    const r = targetRestaurant
    if (r.status === 'pending') {
      const trialUntil = addDays(today(), 15)
      await pool.query("UPDATE restaurants SET status = 'active', paid_until = COALESCE(paid_until, $1::date) WHERE id = $2", [trialUntil, r.id])
      r.status = 'active'
    }
    if (r.status === 'rejected') return bad(res, 'Your request was not approved. Please contact support.', 403)

    await pool.query('UPDATE restaurants SET last_seen = now() WHERE id = $1', [r.id])
    let full = await getRestaurant(r.id)
    const daysLeft = full.paid_until ? diffDays(full.paid_until, today()) : null
    if (full.status === 'active' && (daysLeft === null || daysLeft <= 0)) {
      const trialUntil = addDays(today(), 15)
      await pool.query("UPDATE restaurants SET paid_until = $1::date WHERE id = $2", [trialUntil, full.id])
      full.paid_until = trialUntil
    }

    const tokenPayload = staffUser
      ? { role: 'restaurant', rid: r.id, uid: staffUser.id, urole: staffUser.role, uname: staffUser.name, uuser: staffUser.username }
      : { role: 'restaurant', rid: r.id, uname: full.owner_name || full.name, uuser: full.email }

    // the desktop app asks for a long-lived token so it keeps working offline
    const token = jwt.sign(tokenPayload, SECRET, { expiresIn: req.body?.device ? '365d' : '30d' })
    res.json({
      ok: true,
      token,
      restaurant: { id: full.id, name: full.name, email: full.email },
      user: staffUser || { id: null, name: full.owner_name || full.name, username: full.email, role: 'admin' },
      owner: req.body?.device ? { email: full.email, name: full.owner_name, password_hash: r.password_hash } : undefined,
      license: licenseOf(full)
    })
  })
)

// ---------- restaurant: identity, license, bootstrap, password, sync ----------
app.get(
  '/api/me',
  auth('restaurant'),
  wrap(async (req, res) => {
    let r = await getRestaurant(req.auth.rid)
    if (!r) return bad(res, 'Please log in again', 401)
    if (!req.auth.imp) await pool.query('UPDATE restaurants SET last_seen = now() WHERE id = $1', [r.id])
    const daysLeft = r.paid_until ? diffDays(r.paid_until, today()) : null
    if (r.status === 'active' && (daysLeft === null || daysLeft <= 0)) {
      const trialUntil = addDays(today(), 15)
      await pool.query("UPDATE restaurants SET paid_until = $1::date WHERE id = $2", [trialUntil, r.id])
      r.paid_until = trialUntil
    }
    res.json({
      ok: true,
      restaurant: { id: r.id, name: r.name, email: r.email },
      user: {
        id: req.staff?.id || null,
        name: req.staff?.name || r.owner_name || r.name,
        username: req.staff?.username || r.email,
        role: req.staff?.role || 'admin'
      },
      license: licenseOf(r),
      imp: !!req.auth.imp
    })
  })
)

app.post(
  '/api/account/password',
  auth('restaurant'),
  needActive,
  wrap(async (req, res) => {
    const oldPw = String(req.body?.old_password || '')
    const newPw = String(req.body?.new_password || '')
    if (req.staff && req.staff.id) {
      if (newPw.length < 6) return bad(res, 'New password must be at least 6 characters')
      if (newPw === 'admin123') return bad(res, 'Choose a different password, not the default one')
      const { rows } = await pool.query('SELECT password_hash FROM users WHERE restaurant_id = $1 AND id = $2', [req.auth.rid, req.staff.id])
      const u = rows[0]
      if (!u || !bcrypt.compareSync(oldPw, u.password_hash)) return bad(res, 'Current password is wrong', 400)
      await pool.query('UPDATE users SET password_hash = $1 WHERE restaurant_id = $2 AND id = $3', [
        bcrypt.hashSync(newPw, 10),
        req.auth.rid,
        req.staff.id
      ])
      return res.json({ ok: true, message: 'Password updated successfully' })
    }
    if (newPw.length < 8) return bad(res, 'Owner password must be at least 8 characters')
    const { rows } = await pool.query('SELECT password_hash FROM restaurants WHERE id = $1', [req.auth.rid])
    const r = rows[0]
    if (!r || !bcrypt.compareSync(oldPw, r.password_hash)) return bad(res, 'Current password is wrong', 400)
    await pool.query('UPDATE restaurants SET password_hash = $1 WHERE id = $2', [bcrypt.hashSync(newPw, 10), req.auth.rid])
    res.json({ ok: true, message: 'Owner password updated successfully' })
  })
)

app.get(
  '/api/bootstrap',
  auth('restaurant'),
  wrap(async (req, res) => {
    const rid = req.auth.rid
    const r = await getRestaurant(rid)
    if (!r) return bad(res, 'Please log in again', 401)
    if (!req.auth.imp) pool.query('UPDATE restaurants SET last_seen = now() WHERE id = $1', [rid]).catch(() => {})
    const daysLeft = r.paid_until ? diffDays(r.paid_until, today()) : null
    if (r.status === 'active' && (daysLeft === null || daysLeft <= 0)) {
      const trialUntil = addDays(today(), 15)
      await pool.query("UPDATE restaurants SET paid_until = $1::date WHERE id = $2", [trialUntil, rid])
      r.paid_until = trialUntil
    }

    await seedDefaultTablesIfNeeded(rid)

    const [catR, prodR, varR, waitR, tblR, setR, actR] = await Promise.all([
      pool.query('SELECT id, name FROM categories WHERE restaurant_id = $1 AND is_active ORDER BY lower(name)', [rid]),
      pool.query(
        `SELECT id, category_id, name, (image <> '') AS has_image,
                CASE WHEN image <> '' THEN left(md5(image), 8) ELSE '' END AS img_v,
                track_stock, stock, min_stock
         FROM products WHERE restaurant_id = $1 AND is_active ORDER BY lower(name)`,
        [rid]
      ),
      pool.query(
        `SELECT id, product_id, name, price::float AS price, pos, stock, min_stock
         FROM variants WHERE restaurant_id = $1 AND is_active ORDER BY pos`,
        [rid]
      ),
      pool.query('SELECT id, name, is_active FROM waiters WHERE restaurant_id = $1 AND is_active ORDER BY lower(name)', [rid]),
      pool.query('SELECT id, name, is_active FROM tables WHERE restaurant_id = $1 AND is_active', [rid]),
      pool.query('SELECT key, value FROM settings WHERE restaurant_id = $1', [rid]),
      pool.query(
        `SELECT table_name, order_type, waiter_id, waiter_name, guests, discount::float AS discount,
                tax_percent::float AS tax_percent, cart, printed_cart, kot_seq, token_no, created_at, updated_at
         FROM active_orders WHERE restaurant_id = $1 ORDER BY created_at ASC`,
        [rid]
      )
    ])

    const byProduct = {}
    for (const v of varR.rows) (byProduct[v.product_id] = byProduct[v.product_id] || []).push(v)

    const products = prodR.rows.map((x) => {
      const image_url = x.has_image ? `/api/product-image/${rid}/${x.id}?v=${x.img_v}&sig=${signImg(rid, x.id)}` : ''
      return {
        id: x.id,
        category_id: x.category_id,
        name: x.name,
        has_image: x.has_image,
        image: image_url,
        image_url,
        track_stock: x.track_stock,
        stock: x.stock,
        min_stock: x.min_stock,
        variants: byProduct[x.id] || []
      }
    })

    const settings = {
      restaurant_name: r.name,
      address: '',
      phone: r.phone || '',
      tax_percent: '0',
      footer: 'Thank you! Visit again.'
    }
    for (const x of setR.rows) if (SETTING_KEYS.includes(x.key)) settings[x.key] = x.value

    const active_orders = actR.rows.map((ao) => {
      const cart = Array.isArray(ao.cart) ? ao.cart : []
      const subtotal = cart.reduce((s, c) => s + Number(c.price || 0) * Math.max(0, Number(c.qty) || 0), 0)
      const disc = Math.min(Math.max(Number(ao.discount) || 0, 0), subtotal)
      const tp = Math.max(Number(ao.tax_percent ?? settings.tax_percent) || 0, 0)
      const tax = Math.round((subtotal - disc) * tp) / 100
      const total = Math.round((subtotal - disc + tax) * 100) / 100
      return { ...ao, cart, printed_cart: Array.isArray(ao.printed_cart) ? ao.printed_cart : [], subtotal, total }
    })

    res.json({
      ok: true,
      restaurant: { id: r.id, name: r.name, email: r.email },
      user: {
        id: req.staff?.id || null,
        name: req.staff?.name || r.owner_name || r.name,
        username: req.staff?.username || r.email,
        role: req.staff?.role || 'admin'
      },
      license: licenseOf(r),
      imp: !!req.auth.imp,
      categories: catR.rows,
      products,
      waiters: waitR.rows,
      tables: naturalSortByName(tblR.rows),
      settings,
      active_orders
    })
  })
)

app.get(
  '/api/product-image/:rid/:id',
  wrap(async (req, res) => {
    const { rid, id } = req.params
    const sig = String(req.query.sig || '')
    if (!isUuid(rid) || !isUuid(id) || !verifyImgSig(rid, id, sig)) {
      return res.status(403).end()
    }
    const { rows } = await pool.query(
      'SELECT image FROM products WHERE restaurant_id = $1 AND id = $2 AND is_active = TRUE',
      [rid, id]
    )
    const raw = rows[0] && rows[0].image
    if (!raw) return res.status(404).end()
    const m = /^data:(image\/[a-zA-Z0-9.+-]+);base64,(.+)$/.exec(raw)
    if (!m) return res.status(404).end()
    const buf = Buffer.from(m[2], 'base64')
    res.setHeader('Content-Type', m[1])
    res.setHeader('Cache-Control', 'public, max-age=31536000, immutable')
    res.send(buf)
  })
)

app.get(
  '/api/license',
  auth('restaurant'),
  wrap(async (req, res) => {
    await pool.query('UPDATE restaurants SET last_seen = now() WHERE id = $1', [req.auth.rid])
    const { rows } = await pool.query(`SELECT ${RCOLS}, password_hash FROM restaurants WHERE id = $1`, [req.auth.rid])
    const r = rows[0]
    if (!r) return bad(res, 'Please log in again', 401)
    res.json({
      ok: true,
      restaurant: { id: r.id, name: r.name },
      owner: { email: r.email, name: r.owner_name, password_hash: r.password_hash },
      license: licenseOf(r)
    })
  })
)

app.post(
  '/api/sync/bills',
  auth('restaurant'),
  wrap(async (req, res) => {
    const r = await getRestaurant(req.auth.rid)
    if (!r) return bad(res, 'Please log in again', 401)
    const lic = licenseOf(r)
    if (lic.state !== 'active') {
      return res.status(403).json({ ok: false, license: lic, message: lic.message || 'Account is not active' })
    }

    const list = Array.isArray(req.body?.bills) ? req.body.bills.slice(0, 200) : []
    const accepted = []
    const rejected = []
    const voidedList = Array.isArray(req.body?.voided) ? req.body.voided.filter(isUuid) : []

    const client = await pool.connect()
    try {
      await client.query('BEGIN')
      if (voidedList.length > 0) {
        await client.query('DELETE FROM bills WHERE restaurant_id = $1 AND id = ANY($2::uuid[])', [r.id, voidedList])
      }
      for (const b of list) {
        const okShape =
          b &&
          isUuid(b.id) &&
          typeof b.created_at === 'string' &&
          /^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}/.test(b.created_at)
        if (!okShape) {
          rejected.push(b && b.id)
          continue
        }
        const items = (Array.isArray(b.items) ? b.items : []).slice(0, 200).map((i) => ({
          name: clean(i.name, 120),
          qty: Math.max(0, Math.floor(num(i.qty))),
          price: num(i.price)
        }))

        await client.query(
          `INSERT INTO bills (restaurant_id, id, bill_no, created_at, order_type, table_name, waiter_name, guests,
             subtotal, discount, tax, total, payment_method, items)
           VALUES ($1,$2,$3,$4::timestamp,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb)
           ON CONFLICT (restaurant_id, id) DO NOTHING`,
          [
            r.id,
            b.id,
            Math.floor(num(b.bill_no)),
            b.created_at.replace('T', ' ').slice(0, 19),
            clean(b.order_type, 30),
            clean(b.table_name, 30),
            clean(b.waiter_name, 60),
            Math.max(1, Math.floor(num(b.guests))),
            num(b.subtotal),
            num(b.discount),
            num(b.tax),
            num(b.total),
            clean(b.payment_method, 60) || 'Cash',
            JSON.stringify(items)
          ]
        )
        accepted.push(b.id)
      }
      await client.query('COMMIT')
    } catch (e) {
      await client.query('ROLLBACK')
      throw e
    } finally {
      client.release()
    }

    await pool.query('UPDATE restaurants SET last_seen = now() WHERE id = $1', [r.id])
    res.json({ ok: true, accepted, rejected, voided: voidedList, license: lic })
  })
)

// ---------- online / mobile POS billing order creation & active table orders ----------
app.get(
  '/api/active-orders',
  auth('restaurant'),
  wrap(async (req, res) => {
    const rid = req.auth.rid
    const [actR, setR] = await Promise.all([
      pool.query(
        `SELECT table_name, order_type, waiter_id, waiter_name, guests, discount::float AS discount,
                tax_percent::float AS tax_percent, cart, printed_cart, kot_seq, token_no, created_at, updated_at
         FROM active_orders WHERE restaurant_id = $1 ORDER BY created_at ASC`,
        [rid]
      ),
      pool.query("SELECT value FROM settings WHERE restaurant_id = $1 AND key = 'tax_percent'", [rid])
    ])
    const defaultTax = setR.rows[0] ? Math.max(Number(setR.rows[0].value) || 0, 0) : 0
    const active_orders = actR.rows.map((ao) => {
      const cart = Array.isArray(ao.cart) ? ao.cart : []
      const subtotal = cart.reduce((s, c) => s + Number(c.price || 0) * Math.max(0, Number(c.qty) || 0), 0)
      const disc = Math.min(Math.max(Number(ao.discount) || 0, 0), subtotal)
      const tp = Math.max(Number(ao.tax_percent ?? defaultTax) || 0, 0)
      const tax = Math.round((subtotal - disc) * tp) / 100
      const total = Math.round((subtotal - disc + tax) * 100) / 100
      return { ...ao, cart, printed_cart: Array.isArray(ao.printed_cart) ? ao.printed_cart : [], subtotal, total }
    })
    res.json({ ok: true, active_orders })
  })
)

app.post(
  '/api/active-orders',
  auth('restaurant'),
  needActive,
  wrap(async (req, res) => {
    const rid = req.auth.rid
    const b = req.body || {}
    const tableName = clean(b.table_name, 40)
    if (!tableName) return bad(res, 'Select a table first')
    const cart = (Array.isArray(b.cart) ? b.cart : []).slice(0, 200).map((i) => ({
      uid: clean(i.uid, 80),
      product_id: isUuid(i.product_id) ? i.product_id : null,
      variant_id: isUuid(i.variant_id) ? i.variant_id : null,
      name: clean(i.name, 120),
      price: Math.max(0, num(i.price)),
      qty: Math.max(1, Math.floor(num(i.qty))),
      note: clean(i.note, 250)
    }))
    if (!cart.length) return bad(res, 'Add at least one item to hold the table')

    const printedCart = Array.isArray(b.printed_cart)
      ? b.printed_cart.slice(0, 200).map((i) => ({
          uid: clean(i.uid, 80),
          product_id: isUuid(i.product_id) ? i.product_id : null,
          variant_id: isUuid(i.variant_id) ? i.variant_id : null,
          name: clean(i.name, 120),
          price: Math.max(0, num(i.price)),
          qty: Math.max(1, Math.floor(num(i.qty))),
          note: clean(i.note, 250)
        }))
      : null

    const client = await pool.connect()
    let tokenNo = Number(b.token_no) || null
    let kotSeq = Number(b.kot_seq)
    try {
      await client.query('BEGIN')
      await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [rid])
      const existingRes = await client.query(
        'SELECT token_no, kot_seq, printed_cart FROM active_orders WHERE restaurant_id = $1 AND table_name = $2',
        [rid, tableName]
      )
      const ex = existingRes.rows[0]
      if (!tokenNo) tokenNo = ex && ex.token_no ? Number(ex.token_no) : null
      if (!tokenNo) {
        const nxt = await client.query(
          `SELECT GREATEST(
             COALESCE((SELECT MAX(bill_no) FROM bills WHERE restaurant_id = $1), 0),
             COALESCE((SELECT MAX(token_no) FROM active_orders WHERE restaurant_id = $1), 0)
           ) + 1 AS n`,
          [rid]
        )
        tokenNo = Number(nxt.rows[0].n) || 1
      }
      if (!Number.isFinite(kotSeq)) kotSeq = ex ? Number(ex.kot_seq) || 0 : 0
      const finalPrinted = printedCart !== null ? printedCart : ex && Array.isArray(ex.printed_cart) ? ex.printed_cart : []

      await client.query(
        `INSERT INTO active_orders (restaurant_id, table_name, order_type, waiter_id, waiter_name, guests, discount, tax_percent, cart, printed_cart, kot_seq, token_no, created_at, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10::jsonb,$11,$12,now(),now())
         ON CONFLICT (restaurant_id, table_name) DO UPDATE SET
           waiter_id = EXCLUDED.waiter_id,
           waiter_name = EXCLUDED.waiter_name,
           guests = EXCLUDED.guests,
           discount = EXCLUDED.discount,
           tax_percent = EXCLUDED.tax_percent,
           cart = EXCLUDED.cart,
           printed_cart = EXCLUDED.printed_cart,
           kot_seq = EXCLUDED.kot_seq,
           token_no = EXCLUDED.token_no,
           updated_at = now()`,
        [
          rid,
          tableName,
          clean(b.order_type, 30) || 'Dine-in',
          clean(b.waiter_id, 60),
          clean(b.waiter_name, 60),
          Math.max(1, Math.floor(num(b.guests))),
          Math.max(0, num(b.discount)),
          Math.max(0, num(b.tax_percent)),
          JSON.stringify(cart),
          JSON.stringify(finalPrinted),
          kotSeq,
          tokenNo
        ]
      )
      await client.query('COMMIT')
    } catch (e) {
      await client.query('ROLLBACK')
      throw e
    } finally {
      client.release()
    }
    res.json({ ok: true, table_name: tableName, token_no: tokenNo, kot_seq: kotSeq })
  })
)

app.post(
  '/api/active-orders/move',
  auth('restaurant'),
  needActive,
  wrap(async (req, res) => {
    const rid = req.auth.rid
    const fromTable = clean(req.body?.from_table, 40)
    const toTable = clean(req.body?.to_table, 40)
    if (!fromTable || !toTable) return bad(res, 'Select both source and target tables')
    if (fromTable === toTable) return bad(res, 'Source and target table cannot be the same')

    const client = await pool.connect()
    try {
      await client.query('BEGIN')
      const src = await client.query('SELECT 1 FROM active_orders WHERE restaurant_id = $1 AND table_name = $2', [rid, fromTable])
      if (!src.rowCount) {
        await client.query('ROLLBACK')
        return bad(res, `No active order found on ${fromTable}`, 404)
      }
      const dst = await client.query('SELECT 1 FROM active_orders WHERE restaurant_id = $1 AND table_name = $2', [rid, toTable])
      if (dst.rowCount) {
        await client.query('ROLLBACK')
        return bad(res, `${toTable} is already occupied! Choose an available table.`, 409)
      }
      await client.query(
        'UPDATE active_orders SET table_name = $1, updated_at = now() WHERE restaurant_id = $2 AND table_name = $3',
        [toTable, rid, fromTable]
      )
      await client.query('COMMIT')
    } catch (e) {
      await client.query('ROLLBACK')
      throw e
    } finally {
      client.release()
    }
    res.json({ ok: true, table_name: toTable })
  })
)

app.delete(
  '/api/active-orders/:tableName',
  auth('restaurant'),
  needActive,
  wrap(async (req, res) => {
    const tableName = clean(req.params.tableName, 40)
    if (!tableName) return bad(res, 'Missing table name')
    await pool.query('DELETE FROM active_orders WHERE restaurant_id = $1 AND table_name = $2', [req.auth.rid, tableName])
    res.json({ ok: true })
  })
)

app.post(
  '/api/orders',
  auth('restaurant'),
  wrap(async (req, res) => {
    const r = await getRestaurant(req.auth.rid)
    if (!r) return bad(res, 'Please log in again', 401)
    const lic = licenseOf(r)
    if (lic.state !== 'active') {
      return res.status(403).json({ ok: false, license: lic, message: lic.message || 'Account is not active' })
    }

    const b = req.body || {}
    const rawItems = Array.isArray(b.items) ? b.items.slice(0, 200) : []
    const parsedItems = rawItems
      .map((i) => ({
        name: clean(i.name, 120),
        qty: Math.max(0, Math.floor(num(i.qty))),
        price: Math.max(0, num(i.price)),
        note: clean(i.note, 250) || '',
        product_id: isUuid(i.product_id) ? i.product_id : null,
        variant_id: isUuid(i.variant_id) ? i.variant_id : null
      }))
      .filter((i) => i.qty > 0 && i.name)
    if (!parsedItems.length) return bad(res, 'Order must contain at least one item')

    const billId = isUuid(b.id) ? b.id : crypto.randomUUID()
    const orderType = clean(b.order_type, 30) || 'Dine-in'
    const tableName = clean(b.table_name, 40) || ''
    const waiterName = clean(b.waiter_name, 60) || ''
    const guests = Math.max(1, Math.floor(num(b.guests)))
    let paymentMethod = clean(b.payment_method, 60) || 'Cash'

    const client = await pool.connect()
    try {
      await client.query('BEGIN')
      await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [r.id])

      // Idempotency guard: if this bill UUID was already committed, return it cleanly without duplicating or re-deducting stock
      const existingBill = await client.query(
        `SELECT id, bill_no, to_char(created_at, 'YYYY-MM-DD HH24:MI:SS') AS created_at, order_type, table_name,
                COALESCE(waiter_name,'') AS waiter_name, guests, subtotal::float AS subtotal, discount::float AS discount,
                tax::float AS tax, total::float AS total, payment_method, items
         FROM bills WHERE restaurant_id = $1 AND id = $2`,
        [r.id, billId]
      )
      if (existingBill.rowCount > 0) {
        await client.query('COMMIT')
        return res.json({ ok: true, duplicate: true, bill: existingBill.rows[0] })
      }

      // Resolve authoritative variant prices & track_stock info from DB where available
      const varIds = [...new Set(parsedItems.map((i) => i.variant_id).filter(Boolean))]
      const prodIds = [...new Set(parsedItems.map((i) => i.product_id).filter(Boolean))]
      const varMap = new Map()
      const singleVarByProd = new Map()
      if (varIds.length) {
        const vr = await client.query(
          `SELECT v.id, v.product_id, v.name AS vname, v.price::float AS price, p.name AS pname, p.track_stock
           FROM variants v JOIN products p ON p.id = v.product_id
           WHERE v.restaurant_id = $1 AND v.id = ANY($2::uuid[])`,
          [r.id, varIds]
        )
        for (const row of vr.rows) varMap.set(row.id, row)
      }
      if (prodIds.length) {
        const pr = await client.query(
          `SELECT v.id, v.product_id, v.name AS vname, v.price::float AS price, p.name AS pname, p.track_stock
           FROM variants v JOIN products p ON p.id = v.product_id
           WHERE v.restaurant_id = $1 AND v.product_id = ANY($2::uuid[]) AND v.is_active = TRUE
           ORDER BY v.pos ASC`,
          [r.id, prodIds]
        )
        for (const row of pr.rows) {
          if (!singleVarByProd.has(row.product_id)) singleVarByProd.set(row.product_id, row)
        }
      }

      const items = parsedItems.map((i) => {
        const dbVar = (i.variant_id && varMap.get(i.variant_id)) || (!i.variant_id && i.product_id && singleVarByProd.get(i.product_id)) || null
        return {
          name: i.name || (dbVar ? (dbVar.vname ? `${dbVar.pname} (${dbVar.vname})` : dbVar.pname) : 'Item'),
          qty: i.qty,
          price: dbVar ? Number(dbVar.price) : i.price,
          note: i.note,
          product_id: (dbVar && dbVar.product_id) || i.product_id,
          variant_id: (dbVar && dbVar.id) || i.variant_id,
          track_stock: !!(dbVar && dbVar.track_stock)
        }
      })

      const taxSetRes = await client.query(
        "SELECT value FROM settings WHERE restaurant_id = $1 AND key = 'tax_percent'",
        [r.id]
      )
      const settingsTaxPct = taxSetRes.rows[0] ? Math.max(num(taxSetRes.rows[0].value), 0) : Math.max(num(b.tax_percent), 0)

      // Exact Desktop POS math (matches resto-pos db.js lines 908-913)
      const subtotal = items.reduce((s, i) => s + i.qty * i.price, 0)
      const discount = Math.min(Math.max(num(b.discount), 0), subtotal)
      const tax = Math.round((subtotal - discount) * settingsTaxPct) / 100
      const total = Math.round((subtotal - discount + tax) * 100) / 100

      if (paymentMethod === 'Split' && (b.cash_amount !== undefined || b.online_amount !== undefined)) {
        const cashPart = Math.max(0, num(b.cash_amount))
        const onlinePart = Math.max(0, b.online_amount !== undefined ? num(b.online_amount) : Math.max(0, total - cashPart))
        paymentMethod = clean(`Split (Cash: Rs ${cashPart.toLocaleString()} | Online: Rs ${onlinePart.toLocaleString()})`, 60)
      }

      // Bill numbering: reuse table's held token_no if provided and not yet used in bills
      let billNo = null
      const reqToken = Math.floor(num(b.token_no))
      if (reqToken > 0) {
        const taken = await client.query('SELECT 1 FROM bills WHERE restaurant_id = $1 AND bill_no = $2', [r.id, reqToken])
        if (!taken.rowCount) billNo = reqToken
      }
      if (!billNo && tableName) {
        const act = await client.query('SELECT token_no FROM active_orders WHERE restaurant_id = $1 AND table_name = $2', [r.id, tableName])
        if (act.rowCount && act.rows[0].token_no) {
          const taken = await client.query('SELECT 1 FROM bills WHERE restaurant_id = $1 AND bill_no = $2', [r.id, act.rows[0].token_no])
          if (!taken.rowCount) billNo = Number(act.rows[0].token_no)
        }
      }
      if (!billNo) {
        const maxRes = await client.query('SELECT COALESCE(MAX(bill_no), 0) + 1 AS next_bill_no FROM bills WHERE restaurant_id = $1', [r.id])
        billNo = Number(maxRes.rows[0].next_bill_no) || 1
      }

      const createdAt = nowPkt()
      const storedItems = items.map(({ track_stock, ...rest }) => rest)

      await client.query(
        `INSERT INTO bills (restaurant_id, id, bill_no, created_at, order_type, table_name, waiter_name, guests,
           subtotal, discount, tax, total, payment_method, items)
         VALUES ($1, $2, $3, $4::timestamp, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14::jsonb)`,
        [
          r.id,
          billId,
          billNo,
          createdAt,
          orderType,
          tableName,
          waiterName,
          guests,
          subtotal,
          discount,
          tax,
          total,
          paymentMethod,
          JSON.stringify(storedItems)
        ]
      )

      // Deduct stock ONLY for tracked items (note: variants table does not have updated_at; trigger updates synced_at)
      const touchedProds = new Set()
      for (const item of items) {
        if (item.track_stock && item.variant_id) {
          await client.query(
            `UPDATE variants SET stock = GREATEST(0, stock - $1)
             WHERE restaurant_id = $2 AND id = $3`,
            [item.qty, r.id, item.variant_id]
          )
          if (item.product_id) touchedProds.add(item.product_id)
        }
      }
      for (const pid of touchedProds) {
        await client.query(
          `UPDATE products
           SET stock = COALESCE((SELECT SUM(stock) FROM variants WHERE restaurant_id = $1 AND product_id = $2 AND is_active = TRUE), 0),
               updated_at = now()
           WHERE restaurant_id = $1 AND id = $2 AND track_stock = TRUE`,
          [r.id, pid]
        )
      }

      if (tableName) {
        await client.query('DELETE FROM active_orders WHERE restaurant_id = $1 AND table_name = $2', [r.id, tableName])
      }

      await client.query('UPDATE restaurants SET last_seen = now() WHERE id = $1', [r.id])
      await client.query('COMMIT')

      res.json({
        ok: true,
        bill: {
          id: billId,
          bill_no: billNo,
          created_at: createdAt,
          order_type: orderType,
          table_name: tableName,
          waiter_name: waiterName,
          guests,
          subtotal,
          discount,
          tax,
          total,
          payment_method: paymentMethod,
          items: storedItems
        }
      })
    } catch (e) {
      await client.query('ROLLBACK')
      throw e
    } finally {
      client.release()
    }
  })
)

app.get(
  '/api/orders/:id',
  auth('restaurant'),
  wrap(async (req, res) => {
    const id = req.params.id
    let q
    if (isUuid(id)) {
      q = await pool.query(
        `SELECT id, bill_no, to_char(created_at, 'YYYY-MM-DD HH24:MI:SS') AS created_at, order_type, table_name,
                COALESCE(waiter_name,'') AS waiter_name, guests, subtotal::float AS subtotal, discount::float AS discount,
                tax::float AS tax, total::float AS total, COALESCE(payment_method,'Cash') AS payment_method, items
         FROM bills WHERE restaurant_id = $1 AND id = $2`,
        [req.auth.rid, id]
      )
    } else {
      const bno = parseInt(id, 10)
      if (isNaN(bno)) return bad(res, 'Invalid bill id', 400)
      q = await pool.query(
        `SELECT id, bill_no, to_char(created_at, 'YYYY-MM-DD HH24:MI:SS') AS created_at, order_type, table_name,
                COALESCE(waiter_name,'') AS waiter_name, guests, subtotal::float AS subtotal, discount::float AS discount,
                tax::float AS tax, total::float AS total, COALESCE(payment_method,'Cash') AS payment_method, items
         FROM bills WHERE restaurant_id = $1 AND bill_no = $2 ORDER BY created_at DESC LIMIT 1`,
        [req.auth.rid, bno]
      )
    }
    if (!q.rowCount) return bad(res, 'Bill not found', 404)
    res.json({ ok: true, bill: q.rows[0] })
  })
)

async function voidBillHandler(req, res) {
  const rid = req.auth.rid
  const id = req.params.id
  const client = await pool.connect()
  try {
    await client.query('BEGIN')
    let delRes
    if (isUuid(id)) {
      delRes = await client.query('DELETE FROM bills WHERE restaurant_id = $1 AND id = $2 RETURNING id, bill_no, items', [rid, id])
    } else {
      const bno = parseInt(id, 10)
      if (isNaN(bno)) {
        await client.query('ROLLBACK')
        return bad(res, 'Invalid bill id')
      }
      delRes = await client.query('DELETE FROM bills WHERE restaurant_id = $1 AND bill_no = $2 RETURNING id, bill_no, items', [rid, bno])
    }
    if (!delRes.rowCount) {
      await client.query('ROLLBACK')
      return bad(res, 'Bill not found', 404)
    }

    const bill = delRes.rows[0]
    const items = Array.isArray(bill.items) ? bill.items : []
    const touchedProds = new Set()
    for (const item of items) {
      const qty = Math.max(0, Math.floor(num(item.qty)))
      if (!qty) continue
      if (isUuid(item.variant_id)) {
        const up = await client.query(
          `UPDATE variants SET stock = stock + $1
           WHERE restaurant_id = $2 AND id = $3
             AND product_id IN (SELECT id FROM products WHERE restaurant_id = $2 AND track_stock = TRUE)
           RETURNING product_id`,
          [qty, rid, item.variant_id]
        )
        if (up.rowCount) touchedProds.add(up.rows[0].product_id)
      } else if (isUuid(item.product_id)) {
        const firstV = await client.query(
          'SELECT id FROM variants WHERE restaurant_id = $1 AND product_id = $2 AND is_active = TRUE ORDER BY pos LIMIT 1',
          [rid, item.product_id]
        )
        if (firstV.rowCount) {
          const up = await client.query(
            `UPDATE variants SET stock = stock + $1
             WHERE restaurant_id = $2 AND id = $3
               AND product_id IN (SELECT id FROM products WHERE restaurant_id = $2 AND track_stock = TRUE)
             RETURNING product_id`,
            [qty, rid, firstV.rows[0].id]
          )
          if (up.rowCount) touchedProds.add(up.rows[0].product_id)
        }
      }
    }
    for (const pid of touchedProds) {
      await client.query(
        `UPDATE products
         SET stock = COALESCE((SELECT SUM(stock) FROM variants WHERE restaurant_id = $1 AND product_id = $2 AND is_active = TRUE), 0),
             updated_at = now()
         WHERE restaurant_id = $1 AND id = $2 AND track_stock = TRUE`,
        [rid, pid]
      )
    }
    await client.query('COMMIT')
    res.json({ ok: true, bill_no: bill.bill_no })
  } catch (e) {
    await client.query('ROLLBACK')
    throw e
  } finally {
    client.release()
  }
}

app.delete('/api/orders/:id', auth('restaurant'), needRole('admin', 'manager'), needActive, wrap(voidBillHandler))
app.post('/api/orders/:id/void', auth('restaurant'), needRole('admin', 'manager'), needActive, wrap(voidBillHandler))

// ---------- desktop app: products and settings sync (both directions) ----------
app.post(
  '/api/sync/catalog',
  auth('restaurant'),
  wrap(async (req, res) => {
    const r = await getRestaurant(req.auth.rid)
    if (!r) return bad(res, 'Please log in again', 401)
    const lic = licenseOf(r)
    if (lic.state !== 'active') {
      return res.status(403).json({ ok: false, license: lic, message: lic.message || 'Account is not active' })
    }

    const rid = r.id
    const b = req.body || {}
    const arr = (x, n) => (Array.isArray(x) ? x.slice(0, n) : [])
    const on = (v) => !(v === 0 || v === false || v === '0')

    const client = await pool.connect()
    try {
      await client.query('BEGIN')

      for (const c of arr(b.categories, 2000)) {
        const name = clean(c && c.name, 60)
        if (!isUuid(c && c.id) || !name) continue
        await client.query(
          `INSERT INTO categories (restaurant_id, id, name, is_active) VALUES ($1,$2,$3,$4)
           ON CONFLICT (restaurant_id, id) DO UPDATE SET name = EXCLUDED.name, is_active = EXCLUDED.is_active`,
          [rid, c.id, name, on(c.is_active)]
        )
      }

      for (const p of arr(b.products, 5000)) {
        const name = clean(p && p.name)
        if (!isUuid(p && p.id) || !name) continue
        const image = typeof p.image === 'string' && isImage(p.image) ? p.image : ''
        const track_stock = !!(p.track_stock && p.track_stock !== '0')
        const stock = Math.max(0, Math.floor(num(p.stock)))
        const min_stock = Math.max(0, Math.floor(num(p.min_stock)) || 5)
        await client.query(
          `INSERT INTO products (restaurant_id, id, category_id, name, image, track_stock, stock, min_stock, is_active)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
           ON CONFLICT (restaurant_id, id) DO UPDATE
           SET category_id = EXCLUDED.category_id, name = EXCLUDED.name, image = EXCLUDED.image,
               track_stock = EXCLUDED.track_stock, stock = EXCLUDED.stock, min_stock = EXCLUDED.min_stock,
               is_active = EXCLUDED.is_active, updated_at = now()`,
          [rid, p.id, isUuid(p.category_id) ? p.category_id : null, name, image, track_stock, stock, min_stock, on(p.is_active)]
        )
      }

      for (const v of arr(b.variants, 20000)) {
        if (!isUuid(v && v.id) || !isUuid(v.product_id)) continue
        const price = num(v.price)
        if (price < 0) continue
        const stock = Math.max(0, Math.floor(num(v.stock)))
        const min_stock = Math.max(0, Math.floor(num(v.min_stock)) || 5)
        await client.query(
          `INSERT INTO variants (restaurant_id, id, product_id, name, price, pos, is_active, stock, min_stock)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
           ON CONFLICT (restaurant_id, id) DO UPDATE
           SET product_id = EXCLUDED.product_id, name = EXCLUDED.name, price = EXCLUDED.price,
               pos = EXCLUDED.pos, is_active = EXCLUDED.is_active,
               stock = EXCLUDED.stock, min_stock = EXCLUDED.min_stock`,
          [rid, v.id, v.product_id, clean(v.name, 40), price, Math.max(0, Math.floor(num(v.pos))), on(v.is_active), stock, min_stock]
        )
      }

      for (const u of arr(b.users, 200)) {
        if (!isUuid(u && u.id)) continue
        const name = clean(u.name, 60)
        const username = clean(u.username, 60).toLowerCase()
        if (!name || !username) continue
        await client.query(
          `INSERT INTO users (restaurant_id, id, name, username, password_hash, role, is_active)
           VALUES ($1,$2,$3,$4,$5,$6,$7)
           ON CONFLICT (restaurant_id, id) DO UPDATE
           SET name = EXCLUDED.name, username = EXCLUDED.username,
               password_hash = CASE WHEN EXCLUDED.password_hash <> '' THEN EXCLUDED.password_hash ELSE users.password_hash END,
               role = EXCLUDED.role, is_active = EXCLUDED.is_active`,
          [rid, u.id, name, username, u.password_hash || '', clean(u.role || 'cashier', 20), on(u.is_active)]
        )
      }

      for (const w of arr(b.waiters, 200)) {
        if (!isUuid(w && w.id)) continue
        const name = clean(w.name, 60)
        if (!name) continue
        await client.query(
          `INSERT INTO waiters (restaurant_id, id, name, is_active)
           VALUES ($1,$2,$3,$4)
           ON CONFLICT (restaurant_id, id) DO UPDATE
           SET name = EXCLUDED.name, is_active = EXCLUDED.is_active`,
          [rid, w.id, name, on(w.is_active)]
        )
      }

      if (b.settings && typeof b.settings === 'object') {
        for (const k of SETTING_KEYS) {
          if (b.settings[k] === undefined) continue
          if (k === 'tax_percent') {
            const t = Number(b.settings[k])
            if (!(Number.isFinite(t) && t >= 0 && t <= 100)) continue
          }
          await client.query(
            `INSERT INTO settings (restaurant_id, key, value) VALUES ($1,$2,$3)
             ON CONFLICT (restaurant_id, key) DO UPDATE SET value = EXCLUDED.value`,
            [rid, k, clean(b.settings[k], 200)]
          )
        }
      }

      await client.query('COMMIT')
    } catch (e) {
      await client.query('ROLLBACK')
      throw e
    } finally {
      client.release()
    }

    // everything that changed on the server since the desktop last asked
    const since = b.since && !Number.isNaN(Date.parse(b.since)) ? new Date(b.since).toISOString() : '1970-01-01T00:00:00Z'
    const t = (await pool.query('SELECT clock_timestamp() AS t')).rows[0].t
    const [c, p, v, s, u, w, bi] = await Promise.all([
      pool.query('SELECT id, name, is_active FROM categories WHERE restaurant_id = $1 AND synced_at > $2::timestamptz', [rid, since]),
      pool.query(
        'SELECT id, category_id, name, image, track_stock, stock, min_stock, is_active FROM products WHERE restaurant_id = $1 AND synced_at > $2::timestamptz',
        [rid, since]
      ),
      pool.query(
        `SELECT id, product_id, name, price::float AS price, pos, is_active, stock, min_stock FROM variants
         WHERE restaurant_id = $1 AND synced_at > $2::timestamptz`,
        [rid, since]
      ),
      pool.query('SELECT key, value FROM settings WHERE restaurant_id = $1 AND synced_at > $2::timestamptz', [rid, since]),
      pool.query('SELECT id, name, username, password_hash, role, is_active FROM users WHERE restaurant_id = $1 AND synced_at > $2::timestamptz', [rid, since]),
      pool.query('SELECT id, name, is_active FROM waiters WHERE restaurant_id = $1 AND synced_at > $2::timestamptz', [rid, since]),
      pool.query(
        `SELECT id, bill_no, created_at, order_type, table_name, waiter_name, guests, subtotal, discount, tax, total, payment_method, items
         FROM bills WHERE restaurant_id = $1 AND received_at > $2::timestamptz`,
        [rid, since]
      )
    ])
    const settings = {}
    for (const x of s.rows) if (SETTING_KEYS.includes(x.key)) settings[x.key] = x.value

    await pool.query('UPDATE restaurants SET last_seen = now() WHERE id = $1', [rid])
    res.json({
      ok: true,
      server_time: new Date(t).toISOString(),
      categories: c.rows,
      products: p.rows,
      variants: v.rows,
      settings,
      users: u.rows,
      waiters: w.rows,
      bills: bi.rows,
      license: lic
    })
  })
)

// ---------- restaurant panel: reports ----------
app.get(
  '/api/report',
  auth('restaurant'),
  needRole('admin', 'manager'),
  wrap(async (req, res) => {
    const range = rangeOf(req.query)
    if (!range) return bad(res, 'Invalid date range')
    res.json({ ok: true, ...(await reportFor(req.auth.rid, range.from, range.to, req.query.bills === '1')) })
  })
)

// ---------- restaurant panel: products ----------
app.get(
  '/api/catalog',
  auth('restaurant'),
  wrap(async (req, res) => {
    const rid = req.auth.rid
    const isLite = req.query.lite === '1'
    const [c, p, v] = await Promise.all([
      pool.query('SELECT id, name FROM categories WHERE restaurant_id = $1 AND is_active ORDER BY lower(name)', [rid]),
      pool.query(
        isLite
          ? `SELECT id, category_id, name, (image <> '') AS has_image,
                    CASE WHEN image <> '' THEN left(md5(image), 8) ELSE '' END AS img_v,
                    track_stock, stock, min_stock
             FROM products WHERE restaurant_id = $1 AND is_active ORDER BY lower(name)`
          : `SELECT id, category_id, name, image, track_stock, stock, min_stock FROM products
             WHERE restaurant_id = $1 AND is_active ORDER BY lower(name)`,
        [rid]
      ),
      pool.query(
        `SELECT id, product_id, name, price::float AS price, pos, stock, min_stock FROM variants
         WHERE restaurant_id = $1 AND is_active ORDER BY pos`,
        [rid]
      )
    ])
    const byProduct = {}
    for (const x of v.rows) (byProduct[x.product_id] = byProduct[x.product_id] || []).push(x)
    res.json({
      ok: true,
      categories: c.rows,
      products: p.rows.map((x) => {
        if (isLite) {
          const image_url = x.has_image ? `/api/product-image/${rid}/${x.id}?v=${x.img_v}&sig=${signImg(rid, x.id)}` : ''
          return {
            id: x.id,
            category_id: x.category_id,
            name: x.name,
            has_image: x.has_image,
            image: image_url,
            image_url,
            track_stock: x.track_stock,
            stock: x.stock,
            min_stock: x.min_stock,
            variants: byProduct[x.id] || []
          }
        }
        return { ...x, variants: byProduct[x.id] || [] }
      })
    })
  })
)

app.post(
  '/api/categories',
  auth('restaurant'),
  needRole('admin', 'manager'),
  needActive,
  wrap(async (req, res) => {
    const name = clean(req.body?.name, 60)
    if (!name) return bad(res, 'Enter a category name')
    const dup = await pool.query('SELECT 1 FROM categories WHERE restaurant_id = $1 AND lower(name) = lower($2) AND is_active', [
      req.auth.rid,
      name
    ])
    if (dup.rowCount) return bad(res, 'This category already exists')
    const id = crypto.randomUUID()
    await pool.query('INSERT INTO categories (restaurant_id, id, name) VALUES ($1,$2,$3)', [
      req.auth.rid,
      id,
      name
    ])
    res.json({ ok: true, id })
  })
)

app.put(
  '/api/categories/:id',
  auth('restaurant'),
  needRole('admin', 'manager'),
  needActive,
  wrap(async (req, res) => {
    if (!isUuid(req.params.id)) return bad(res, 'Invalid id')
    const name = clean(req.body?.name, 60)
    if (!name) return bad(res, 'Enter a category name')
    const dup = await pool.query(
      'SELECT 1 FROM categories WHERE restaurant_id = $1 AND lower(name) = lower($2) AND id <> $3 AND is_active',
      [req.auth.rid, name, req.params.id]
    )
    if (dup.rowCount) return bad(res, 'This category already exists')
    await pool.query('UPDATE categories SET name = $1 WHERE restaurant_id = $2 AND id = $3', [
      name,
      req.auth.rid,
      req.params.id
    ])
    res.json({ ok: true })
  })
)

app.delete(
  '/api/categories/:id',
  auth('restaurant'),
  needRole('admin', 'manager'),
  needActive,
  wrap(async (req, res) => {
    if (!isUuid(req.params.id)) return bad(res, 'Invalid id')
    const used = await pool.query(
      'SELECT COUNT(*)::int AS c FROM products WHERE restaurant_id = $1 AND category_id = $2 AND is_active',
      [req.auth.rid, req.params.id]
    )
    if (used.rows[0].c) {
      return bad(res, `This category has ${used.rows[0].c} product(s). Move or delete them first.`)
    }
    await pool.query('UPDATE categories SET is_active = FALSE WHERE restaurant_id = $1 AND id = $2', [req.auth.rid, req.params.id])
    res.json({ ok: true })
  })
)

app.post(
  '/api/products',
  auth('restaurant'),
  needRole('admin', 'manager'),
  needActive,
  wrap(async (req, res) => {
    const rid = req.auth.rid
    const b = req.body || {}
    const name = clean(b.name)
    if (!name) return bad(res, 'Product name is required')
    if (!isUuid(b.category_id)) return bad(res, 'Select a category first')
    let keepExistingImage = b.keep_existing_image === true || b.image === '__KEEP__'
    const rawImg = typeof b.image === 'string' ? b.image : ''
    if (rawImg.startsWith('/api/product-image/')) keepExistingImage = true
    const image = keepExistingImage ? '' : rawImg
    if (!keepExistingImage && !isImage(image)) return bad(res, 'The photo is too large. Choose a smaller photo.')

    const variants = (Array.isArray(b.variants) ? b.variants : [])
      .slice(0, 20)
      .map((v) => ({
        id: isUuid(v && v.id) ? v.id : '',
        name: clean(v && v.name, 40),
        price: num(v && v.price),
        stock: Math.max(0, Math.floor(num(v && v.stock))),
        min_stock: Math.max(0, Math.floor(num(v && v.min_stock)) || 5)
      }))
      .filter((v) => v.name || v.price)

    if (!variants.length) return bad(res, 'Add at least one price')
    if (variants.some((v) => !(v.price > 0))) return bad(res, 'Every option needs a valid price')
    if (variants.length > 1 && variants.some((v) => !v.name)) return bad(res, 'Give every option a name')

    const cat = await pool.query('SELECT 1 FROM categories WHERE restaurant_id = $1 AND id = $2 AND is_active', [rid, b.category_id])
    if (!cat.rowCount) return bad(res, 'Category not found')

    const track_stock = !!b.track_stock
    const stock = track_stock ? variants.reduce((sum, v) => sum + (v.stock || 0), 0) : 0
    const min_stock = Math.max(0, Math.floor(num(b.min_stock)) || 5)

    let notFound = false
    const client = await pool.connect()
    try {
      await client.query('BEGIN')
      let id = isUuid(b.id) ? b.id : null
      if (id) {
        const up = keepExistingImage
          ? await client.query(
              `UPDATE products SET name = $1, category_id = $2, track_stock = $3, stock = $4, min_stock = $5, updated_at = now(), is_active = TRUE
               WHERE restaurant_id = $6 AND id = $7`,
              [name, b.category_id, track_stock, stock, min_stock, rid, id]
            )
          : await client.query(
              `UPDATE products SET name = $1, category_id = $2, image = $3, track_stock = $4, stock = $5, min_stock = $6, updated_at = now(), is_active = TRUE
               WHERE restaurant_id = $7 AND id = $8`,
              [name, b.category_id, image, track_stock, stock, min_stock, rid, id]
            )
        if (!up.rowCount) notFound = true
      } else {
        id = crypto.randomUUID()
        await client.query(
          'INSERT INTO products (restaurant_id, id, category_id, name, image, track_stock, stock, min_stock) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
          [rid, id, b.category_id, name, image, track_stock, stock, min_stock]
        )
      }

      if (!notFound) {
        const keep = []
        for (let i = 0; i < variants.length; i++) {
          const v = variants[i]
          let vid = v.id
          let updated = 0
          if (vid) {
            const u = await client.query(
              `UPDATE variants SET name = $1, price = $2, pos = $3, stock = $4, min_stock = $5, is_active = TRUE
               WHERE restaurant_id = $6 AND id = $7 AND product_id = $8`,
              [v.name, v.price, i, v.stock, v.min_stock, rid, vid, id]
            )
            updated = u.rowCount
          }
          if (!updated) {
            vid = crypto.randomUUID()
            await client.query(
              'INSERT INTO variants (restaurant_id, id, product_id, name, price, pos, stock, min_stock) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
              [rid, vid, id, v.name, v.price, i, v.stock, v.min_stock]
            )
          }
          keep.push(vid)
        }
        await client.query(
          `UPDATE variants SET is_active = FALSE
           WHERE restaurant_id = $1 AND product_id = $2 AND NOT (id = ANY($3::uuid[]))`,
          [rid, id, keep]
        )
      }
      await client.query(notFound ? 'ROLLBACK' : 'COMMIT')
    } catch (e) {
      await client.query('ROLLBACK')
      throw e
    } finally {
      client.release()
    }

    if (notFound) return bad(res, 'Product not found', 404)
    res.json({ ok: true })
  })
)

app.delete(
  '/api/products/:id',
  auth('restaurant'),
  needRole('admin', 'manager'),
  needActive,
  wrap(async (req, res) => {
    if (!isUuid(req.params.id)) return bad(res, 'Invalid id')
    await pool.query('UPDATE products SET is_active = FALSE, updated_at = now() WHERE restaurant_id = $1 AND id = $2', [
      req.auth.rid,
      req.params.id
    ])
    await pool.query('UPDATE variants SET is_active = FALSE WHERE restaurant_id = $1 AND product_id = $2', [
      req.auth.rid,
      req.params.id
    ])
    res.json({ ok: true })
  })
)

app.patch(
  '/api/products/:id/stock',
  auth('restaurant'),
  needRole('admin', 'manager'),
  needActive,
  wrap(async (req, res) => {
    if (!isUuid(req.params.id)) return bad(res, 'Invalid id')
    const stock = Math.max(0, Math.floor(num(req.body && req.body.stock)))
    const up = await pool.query(
      'UPDATE products SET stock = $1, updated_at = now() WHERE restaurant_id = $2 AND id = $3 AND is_active = TRUE',
      [stock, req.auth.rid, req.params.id]
    )
    if (!up.rowCount) return bad(res, 'Product not found', 404)
    res.json({ ok: true, stock })
  })
)

app.patch(
  '/api/variants/:id/stock',
  auth('restaurant'),
  needRole('admin', 'manager'),
  needActive,
  wrap(async (req, res) => {
    if (!isUuid(req.params.id)) return bad(res, 'Invalid id')
    const stock = Math.max(0, Math.floor(num(req.body && req.body.stock)))
    const up = await pool.query(
      `UPDATE variants SET stock = $1 WHERE restaurant_id = $2 AND id = $3 AND is_active = TRUE RETURNING product_id`,
      [stock, req.auth.rid, req.params.id]
    )
    if (!up.rowCount) return bad(res, 'Variant not found', 404)
    const pid = up.rows[0].product_id
    await pool.query(
      `UPDATE products SET stock = COALESCE((SELECT SUM(stock) FROM variants WHERE restaurant_id = $1 AND product_id = $2 AND is_active = TRUE), 0), updated_at = now() WHERE restaurant_id = $1 AND id = $2`,
      [req.auth.rid, pid]
    )
    res.json({ ok: true, stock })
  })
)

// ---------- restaurant panel: settings ----------
const SETTING_KEYS = ['restaurant_name', 'address', 'phone', 'tax_percent', 'footer']

app.get(
  '/api/settings',
  auth('restaurant'),
  wrap(async (req, res) => {
    const r = await getRestaurant(req.auth.rid)
    if (!r) return bad(res, 'Please log in again', 401)
    const s = {
      restaurant_name: r.name,
      address: '',
      phone: r.phone || '',
      tax_percent: '0',
      footer: 'Thank you! Visit again.'
    }
    const { rows } = await pool.query('SELECT key, value FROM settings WHERE restaurant_id = $1', [req.auth.rid])
    for (const x of rows) if (SETTING_KEYS.includes(x.key)) s[x.key] = x.value
    res.json({ ok: true, settings: s })
  })
)

app.post(
  '/api/settings',
  auth('restaurant'),
  needRole('admin'),
  needActive,
  wrap(async (req, res) => {
    const b = req.body || {}
    const tax = Number(b.tax_percent)
    if (b.tax_percent !== undefined && !(Number.isFinite(tax) && tax >= 0 && tax <= 100)) {
      return bad(res, 'Tax must be a number between 0 and 100')
    }
    for (const k of SETTING_KEYS) {
      if (b[k] === undefined) continue
      await pool.query(
        `INSERT INTO settings (restaurant_id, key, value) VALUES ($1,$2,$3)
         ON CONFLICT (restaurant_id, key) DO UPDATE SET value = EXCLUDED.value`,
        [req.auth.rid, k, clean(b[k], 200)]
      )
    }
    res.json({ ok: true })
  })
)

// ---------- restaurant panel: users & cashiers ----------
app.get(
  '/api/users',
  auth('restaurant'),
  needRole('admin'),
  wrap(async (req, res) => {
    const { rows } = await pool.query(
      'SELECT id, name, username, role, is_active FROM users WHERE restaurant_id = $1 ORDER BY role, lower(name)',
      [req.auth.rid]
    )
    res.json({ ok: true, users: rows })
  })
)

app.post(
  '/api/users',
  auth('restaurant'),
  needRole('admin'),
  needActive,
  wrap(async (req, res) => {
    const rid = req.auth.rid
    const b = req.body || {}
    const name = clean(b.name, 60)
    const username = clean(b.username, 60).toLowerCase()
    const password = String(b.password || '')
    const role = ['manager', 'admin', 'cashier'].includes(b.role) ? b.role : 'cashier'

    if (!name) return bad(res, "Enter the person's name")
    if (!/^[a-z0-9._-]{3,}$/.test(username)) {
      return bad(res, 'Username needs at least 3 letters or numbers, with no spaces')
    }
    if (password.length < 6) return bad(res, 'Password must be at least 6 characters')

    const dup = await pool.query('SELECT 1 FROM users WHERE restaurant_id = $1 AND lower(username) = $2', [
      rid,
      username
    ])
    if (dup.rowCount) return bad(res, 'This username is already taken')

    const id = crypto.randomUUID()
    const hash = bcrypt.hashSync(password, 10)
    await pool.query(
      'INSERT INTO users (restaurant_id, id, name, username, password_hash, role, is_active) VALUES ($1,$2,$3,$4,$5,$6,TRUE)',
      [rid, id, name, username, hash, role]
    )
    res.json({ ok: true, id })
  })
)

app.put(
  '/api/users/:id',
  auth('restaurant'),
  needRole('admin'),
  needActive,
  wrap(async (req, res) => {
    if (!isUuid(req.params.id)) return bad(res, 'Invalid user id')
    const rid = req.auth.rid
    const b = req.body || {}
    const name = clean(b.name, 60)
    const username = clean(b.username, 60).toLowerCase()
    const role = ['manager', 'admin', 'cashier'].includes(b.role) ? b.role : 'cashier'

    if (!name) return bad(res, "Enter the person's name")
    if (!/^[a-z0-9._-]{3,}$/.test(username)) {
      return bad(res, 'Username needs at least 3 letters or numbers, with no spaces')
    }

    const cur = await pool.query('SELECT role FROM users WHERE restaurant_id = $1 AND id = $2', [rid, req.params.id])
    if (!cur.rowCount) return bad(res, 'User not found', 404)
    if (cur.rows[0].role === 'admin' && role !== 'admin') {
      const admins = await pool.query(
        "SELECT COUNT(*)::int AS c FROM users WHERE restaurant_id = $1 AND role = 'admin' AND is_active = TRUE",
        [rid]
      )
      if (admins.rows[0].c <= 1) return bad(res, 'At least one active admin is required')
    }

    const dup = await pool.query(
      'SELECT 1 FROM users WHERE restaurant_id = $1 AND lower(username) = $2 AND id <> $3',
      [rid, username, req.params.id]
    )
    if (dup.rowCount) return bad(res, 'This username is already taken')

    await pool.query(
      'UPDATE users SET name = $1, username = $2, role = $3 WHERE restaurant_id = $4 AND id = $5',
      [name, username, role, rid, req.params.id]
    )
    res.json({ ok: true })
  })
)

app.put(
  '/api/users/:id/status',
  auth('restaurant'),
  needRole('admin'),
  needActive,
  wrap(async (req, res) => {
    if (!isUuid(req.params.id)) return bad(res, 'Invalid user id')
    const isActive = req.body?.is_active !== false
    if (req.staff?.id === req.params.id && !isActive) {
      return bad(res, 'You cannot deactivate your own account')
    }
    const target = await pool.query('SELECT role FROM users WHERE restaurant_id = $1 AND id = $2', [
      req.auth.rid,
      req.params.id
    ])
    if (!target.rowCount) return bad(res, 'User not found', 404)
    if (!isActive && target.rows[0].role === 'admin') {
      const admins = await pool.query(
        "SELECT COUNT(*)::int AS c FROM users WHERE restaurant_id = $1 AND role = 'admin' AND is_active = TRUE",
        [req.auth.rid]
      )
      if (admins.rows[0].c <= 1) return bad(res, 'At least one active admin is required')
    }
    await pool.query('UPDATE users SET is_active = $1 WHERE restaurant_id = $2 AND id = $3', [
      isActive,
      req.auth.rid,
      req.params.id
    ])
    res.json({ ok: true, is_active: isActive })
  })
)

app.put(
  '/api/users/:id/password',
  auth('restaurant'),
  needRole('admin'),
  needActive,
  wrap(async (req, res) => {
    if (!isUuid(req.params.id)) return bad(res, 'Invalid user id')
    const password = String(req.body?.password || '')
    if (password.length < 6) return bad(res, 'Password must be at least 6 characters')
    const hash = bcrypt.hashSync(password, 10)
    await pool.query('UPDATE users SET password_hash = $1 WHERE restaurant_id = $2 AND id = $3', [
      hash,
      req.auth.rid,
      req.params.id
    ])
    res.json({ ok: true })
  })
)

app.delete(
  '/api/users/:id',
  auth('restaurant'),
  needRole('admin'),
  needActive,
  wrap(async (req, res) => {
    if (!isUuid(req.params.id)) return bad(res, 'Invalid user id')
    if (req.staff?.id === req.params.id) return bad(res, 'You cannot delete your own account')
    const target = await pool.query('SELECT role FROM users WHERE restaurant_id = $1 AND id = $2', [
      req.auth.rid,
      req.params.id
    ])
    if (!target.rowCount) return bad(res, 'User not found', 404)
    if (target.rows[0].role === 'admin') return bad(res, 'Admin accounts cannot be deleted')
    await pool.query('DELETE FROM users WHERE restaurant_id = $1 AND id = $2', [req.auth.rid, req.params.id])
    res.json({ ok: true })
  })
)

// ---------- restaurant panel: waiters ----------
app.get(
  '/api/waiters',
  auth('restaurant'),
  wrap(async (req, res) => {
    const { rows } = await pool.query(
      'SELECT id, name, is_active FROM waiters WHERE restaurant_id = $1 AND is_active ORDER BY lower(name)',
      [req.auth.rid]
    )
    res.json({ ok: true, waiters: rows })
  })
)

app.post(
  '/api/waiters',
  auth('restaurant'),
  needRole('admin'),
  needActive,
  wrap(async (req, res) => {
    const rid = req.auth.rid
    const name = clean(req.body?.name, 60)
    if (!name) return bad(res, 'Enter a waiter name')
    const dup = await pool.query(
      'SELECT 1 FROM waiters WHERE restaurant_id = $1 AND lower(name) = lower($2) AND is_active',
      [rid, name]
    )
    if (dup.rowCount) return bad(res, 'This waiter already exists')
    const id = crypto.randomUUID()
    await pool.query('INSERT INTO waiters (restaurant_id, id, name, is_active) VALUES ($1,$2,$3,TRUE)', [
      rid,
      id,
      name
    ])
    res.json({ ok: true, id, name })
  })
)

app.put(
  '/api/waiters/:id',
  auth('restaurant'),
  needRole('admin'),
  needActive,
  wrap(async (req, res) => {
    if (!isUuid(req.params.id)) return bad(res, 'Invalid id')
    const name = clean(req.body?.name, 60)
    if (!name) return bad(res, 'Enter a waiter name')
    const dup = await pool.query(
      'SELECT 1 FROM waiters WHERE restaurant_id = $1 AND lower(name) = lower($2) AND id <> $3 AND is_active',
      [req.auth.rid, name, req.params.id]
    )
    if (dup.rowCount) return bad(res, 'This waiter already exists')
    await pool.query('UPDATE waiters SET name = $1 WHERE restaurant_id = $2 AND id = $3', [
      name,
      req.auth.rid,
      req.params.id
    ])
    res.json({ ok: true, id: req.params.id, name })
  })
)

app.delete(
  '/api/waiters/:id',
  auth('restaurant'),
  needRole('admin'),
  needActive,
  wrap(async (req, res) => {
    if (!isUuid(req.params.id)) return bad(res, 'Invalid id')
    await pool.query('UPDATE waiters SET is_active = FALSE WHERE restaurant_id = $1 AND id = $2', [
      req.auth.rid,
      req.params.id
    ])
    res.json({ ok: true })
  })
)

// ---------- restaurant panel: tables ----------
app.get(
  '/api/tables',
  auth('restaurant'),
  wrap(async (req, res) => {
    await seedDefaultTablesIfNeeded(req.auth.rid)
    const { rows } = await pool.query(
      'SELECT id, name, is_active FROM tables WHERE restaurant_id = $1 AND is_active',
      [req.auth.rid]
    )
    res.json({ ok: true, tables: naturalSortByName(rows) })
  })
)

app.post(
  '/api/tables',
  auth('restaurant'),
  needRole('admin'),
  needActive,
  wrap(async (req, res) => {
    const rid = req.auth.rid
    const name = clean(req.body?.name, 60)
    if (!name) return bad(res, 'Enter a table name')
    const dup = await pool.query(
      'SELECT 1 FROM tables WHERE restaurant_id = $1 AND lower(name) = lower($2) AND is_active',
      [rid, name]
    )
    if (dup.rowCount) return bad(res, 'This table already exists')
    const id = crypto.randomUUID()
    await pool.query('INSERT INTO tables (restaurant_id, id, name, is_active) VALUES ($1,$2,$3,TRUE)', [
      rid,
      id,
      name
    ])
    res.json({ ok: true, id, name })
  })
)

app.put(
  '/api/tables/:id',
  auth('restaurant'),
  needRole('admin'),
  needActive,
  wrap(async (req, res) => {
    if (!isUuid(req.params.id)) return bad(res, 'Invalid id')
    const name = clean(req.body?.name, 60)
    if (!name) return bad(res, 'Enter a table name')
    const dup = await pool.query(
      'SELECT 1 FROM tables WHERE restaurant_id = $1 AND lower(name) = lower($2) AND id <> $3 AND is_active',
      [req.auth.rid, name, req.params.id]
    )
    if (dup.rowCount) return bad(res, 'This table already exists')
    await pool.query('UPDATE tables SET name = $1 WHERE restaurant_id = $2 AND id = $3', [
      name,
      req.auth.rid,
      req.params.id
    ])
    res.json({ ok: true, id: req.params.id, name })
  })
)

app.delete(
  '/api/tables/:id',
  auth('restaurant'),
  needRole('admin'),
  needActive,
  wrap(async (req, res) => {
    if (!isUuid(req.params.id)) return bad(res, 'Invalid id')
    await pool.query('UPDATE tables SET is_active = FALSE WHERE restaurant_id = $1 AND id = $2', [
      req.auth.rid,
      req.params.id
    ])
    res.json({ ok: true })
  })
)

// ---------- admin (you) ----------
app.post(
  '/api/admin/login',
  wrap(async (req, res) => {
    const email = clean(req.body?.email).toLowerCase()
    const password = String(req.body?.password || '')
    const key = `admin|${req.ip}`
    if (limited(key)) return bad(res, 'Too many attempts. Try again later.', 429)

    const { rows } = await pool.query('SELECT id, password_hash FROM admins WHERE email = $1', [email])
    const a = rows[0]
    if (!a || !bcrypt.compareSync(password, a.password_hash)) {
      addFail(key)
      return bad(res, 'Wrong email or password', 401)
    }
    fails.delete(key)
    res.json({ ok: true, token: jwt.sign({ role: 'admin', aid: a.id }, SECRET, { expiresIn: '12h' }) })
  })
)

app.get(
  '/api/admin/restaurants',
  auth('admin'),
  wrap(async (req, res) => {
    const { rows } = await pool.query(`
      SELECT r.id, r.name, r.owner_name, r.email, r.phone, r.city, r.status, r.plan,
             r.monthly_fee::float AS monthly_fee, r.paid_until::text AS paid_until,
             r.notes, r.last_seen, r.created_at,
             COALESCE(b.bills,0)::int AS bills, COALESCE(b.sales,0)::float AS sales,
             COALESCE(p.paid,0)::float AS total_paid
      FROM restaurants r
      LEFT JOIN (SELECT restaurant_id, COUNT(*) AS bills, SUM(total) AS sales
                 FROM bills GROUP BY restaurant_id) b ON b.restaurant_id = r.id
      LEFT JOIN (SELECT restaurant_id, SUM(amount) AS paid
                 FROM payments GROUP BY restaurant_id) p ON p.restaurant_id = r.id
      ORDER BY r.created_at DESC`)
    res.json({ ok: true, restaurants: rows.map((r) => ({ ...r, license: licenseOf(r) })) })
  })
)

const needId = (req, res, next) => (isUuid(req.params.id) ? next() : bad(res, 'Invalid id'))

app.post(
  '/api/admin/restaurants/:id/status',
  auth('admin'),
  needId,
  wrap(async (req, res) => {
    const status = String(req.body?.status || '')
    if (!['pending', 'active', 'paused', 'rejected'].includes(status)) return bad(res, 'Invalid status')
    // First approval gives a 14 day free trial
    await pool.query(
      `UPDATE restaurants
       SET status = $1::text,
           paid_until = CASE WHEN $1::text = 'active' THEN COALESCE(paid_until, $3::date) ELSE paid_until END
       WHERE id = $2`,
      [status, req.params.id, addDays(today(), 14)]
    )
    res.json({ ok: true })
  })
)

app.post(
  '/api/admin/restaurants/:id/plan',
  auth('admin'),
  needId,
  wrap(async (req, res) => {
    const fee = Math.max(0, num(req.body?.monthly_fee))
    await pool.query('UPDATE restaurants SET plan = $1, monthly_fee = $2, notes = $3 WHERE id = $4', [
      clean(req.body?.plan, 40) || 'Monthly',
      fee,
      clean(req.body?.notes, 500),
      req.params.id
    ])
    res.json({ ok: true })
  })
)

app.post(
  '/api/admin/restaurants/:id/payment',
  auth('admin'),
  needId,
  wrap(async (req, res) => {
    const amount = num(req.body?.amount)
    const days = Math.min(Math.max(Math.floor(num(req.body?.days)) || 30, 1), 400)
    if (!(amount > 0)) return bad(res, 'Enter the amount received')

    const r = await getRestaurant(req.params.id)
    if (!r) return bad(res, 'Restaurant not found', 404)

    const t = today()
    const base = r.paid_until && r.paid_until > t ? r.paid_until : t
    await pool.query(
      'INSERT INTO payments (id, restaurant_id, amount, days_added, note) VALUES ($1,$2,$3,$4,$5)',
      [crypto.randomUUID(), r.id, amount, days, clean(req.body?.note, 200)]
    )
    await pool.query('UPDATE restaurants SET paid_until = $1::date WHERE id = $2', [addDays(base, days), r.id])
    res.json({ ok: true, paid_until: addDays(base, days) })
  })
)

app.post(
  '/api/admin/restaurants/:id/password',
  auth('admin'),
  needId,
  wrap(async (req, res) => {
    const pw = String(req.body?.password || '')
    if (pw.length < 8) return bad(res, 'Password must be at least 8 characters')
    const u = await pool.query('UPDATE restaurants SET password_hash = $1 WHERE id = $2', [
      bcrypt.hashSync(pw, 10),
      req.params.id
    ])
    if (!u.rowCount) return bad(res, 'Restaurant not found', 404)
    res.json({ ok: true })
  })
)

// Admin opens the restaurant's own panel (same screens the owner sees)
app.post(
  '/api/admin/restaurants/:id/impersonate',
  auth('admin'),
  needId,
  wrap(async (req, res) => {
    const r = await getRestaurant(req.params.id)
    if (!r) return bad(res, 'Restaurant not found', 404)
    const token = jwt.sign({ role: 'restaurant', rid: r.id, imp: true }, SECRET, { expiresIn: '4h' })
    res.json({ ok: true, token, restaurant: { id: r.id, name: r.name } })
  })
)

app.delete(
  '/api/admin/restaurants/:id',
  auth('admin'),
  needId,
  wrap(async (req, res) => {
    const { rowCount } = await pool.query('DELETE FROM restaurants WHERE id = $1', [req.params.id])
    if (!rowCount) return bad(res, 'Restaurant not found', 404)
    res.json({ ok: true })
  })
)

// ---------- start ----------
async function start() {
  await init()

  const has = await pool.query('SELECT 1 FROM admins LIMIT 1')
  if (!has.rowCount) {
    const email = clean(process.env.ADMIN_EMAIL).toLowerCase()
    const pw = String(process.env.ADMIN_PASSWORD || '')
    if (!isEmail(email) || pw.length < 10) {
      console.error('Set ADMIN_EMAIL and ADMIN_PASSWORD (at least 10 characters) in .env')
      process.exit(1)
    }
    await pool.query('INSERT INTO admins (id, email, password_hash) VALUES ($1,$2,$3)', [
      crypto.randomUUID(),
      email,
      bcrypt.hashSync(pw, 10)
    ])
    console.log('Admin account created for', email)
  }

  return app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`))
}

if (require.main === module) {
  start().catch((e) => {
    console.error('Could not start the server:', e.message)
    process.exit(1)
  })
}

module.exports = { app, start }
