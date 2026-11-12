require('dotenv').config()
const express = require('express')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const crypto = require('crypto')
const path = require('path')
const { pool, init } = require('./db')

const SECRET = process.env.JWT_SECRET || ''
const GRACE = Number(process.env.GRACE_DAYS) || 5
const PORT = Number(process.env.PORT) || 4000

if (SECRET.length < 32) {
  console.error('JWT_SECRET in .env must be at least 32 characters long.')
  process.exit(1)
}

const app = express()
app.disable('x-powered-by')
app.use(express.json({ limit: '25mb' }))
app.use(express.static(path.join(__dirname, 'public')))
app.use(express.static(__dirname))

// ---------- helpers ----------
const today = () => new Date(Date.now() + 5 * 3600e3).toISOString().slice(0, 10) // Pakistan date
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

// simple protection against password guessing
const fails = new Map()
const limited = (k) => {
  const e = fails.get(k)
  return !!e && e.count >= 8 && Date.now() - e.t < 15 * 60e3
}
const addFail = (k) => {
  const e = fails.get(k)
  if (!e || Date.now() - e.t > 15 * 60e3) fails.set(k, { count: 1, t: Date.now() })
  else e.count++
}

function auth(role) {
  return (req, res, next) => {
    const h = req.headers.authorization || ''
    const token = h.startsWith('Bearer ') ? h.slice(7) : ''
    try {
      const p = jwt.verify(token, SECRET)
      if (p.role !== role) throw new Error('wrong role')
      req.auth = p
      next()
    } catch {
      res.status(401).json({ ok: false, message: 'Please log in again' })
    }
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
              table_name, guests, subtotal::float AS subtotal, discount::float AS discount,
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

    await pool.query(
      `INSERT INTO restaurants (id, name, owner_name, email, phone, city, password_hash)
       VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [crypto.randomUUID(), name, owner, email, phone, city, bcrypt.hashSync(password, 10)]
    )
    res.json({ ok: true, message: 'Request received. You can log in after we approve your account.' })
  })
)

app.post(
  '/api/login',
  wrap(async (req, res) => {
    const email = clean(req.body?.email).toLowerCase()
    const password = String(req.body?.password || '')
    const key = `${req.ip}|${email}`
    if (limited(key)) return bad(res, 'Too many attempts. Try again in 15 minutes.', 429)

    const { rows } = await pool.query('SELECT id, password_hash, status FROM restaurants WHERE email = $1', [email])
    const r = rows[0]
    if (!r || !bcrypt.compareSync(password, r.password_hash)) {
      addFail(key)
      return bad(res, 'Wrong email or password', 401)
    }
    fails.delete(key)

    if (r.status === 'pending') return bad(res, 'Your account is waiting for approval.', 403)
    if (r.status === 'rejected') return bad(res, 'Your request was not approved. Please contact support.', 403)

    await pool.query('UPDATE restaurants SET last_seen = now() WHERE id = $1', [r.id])
    const full = await getRestaurant(r.id)
    // the desktop app asks for a long-lived token so it keeps working offline
    const token = jwt.sign({ role: 'restaurant', rid: r.id }, SECRET, { expiresIn: req.body?.device ? '365d' : '30d' })
    res.json({ ok: true, token, restaurant: { id: full.id, name: full.name }, license: licenseOf(full) })
  })
)

// ---------- restaurant: identity, license, sync ----------
app.get(
  '/api/me',
  auth('restaurant'),
  wrap(async (req, res) => {
    const r = await getRestaurant(req.auth.rid)
    if (!r) return bad(res, 'Please log in again', 401)
    if (!req.auth.imp) await pool.query('UPDATE restaurants SET last_seen = now() WHERE id = $1', [r.id])
    res.json({
      ok: true,
      restaurant: { id: r.id, name: r.name, email: r.email },
      license: licenseOf(r),
      imp: !!req.auth.imp
    })
  })
)

app.get(
  '/api/license',
  auth('restaurant'),
  wrap(async (req, res) => {
    await pool.query('UPDATE restaurants SET last_seen = now() WHERE id = $1', [req.auth.rid])
    const r = await getRestaurant(req.auth.rid)
    if (!r) return bad(res, 'Please log in again', 401)
    res.json({ ok: true, restaurant: { id: r.id, name: r.name }, license: licenseOf(r) })
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

    const client = await pool.connect()
    try {
      await client.query('BEGIN')
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
          `INSERT INTO bills (restaurant_id, id, bill_no, created_at, order_type, table_name, guests,
             subtotal, discount, tax, total, payment_method, items)
           VALUES ($1,$2,$3,$4::timestamp,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb)
           ON CONFLICT (restaurant_id, id) DO NOTHING`,
          [
            r.id,
            b.id,
            Math.floor(num(b.bill_no)),
            b.created_at.replace('T', ' ').slice(0, 19),
            clean(b.order_type, 30),
            clean(b.table_name, 30),
            Math.max(1, Math.floor(num(b.guests))),
            num(b.subtotal),
            num(b.discount),
            num(b.tax),
            num(b.total),
            clean(b.payment_method, 30) || 'Cash',
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
    res.json({ ok: true, accepted, rejected, license: lic })
  })
)

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
        await client.query(
          `INSERT INTO products (restaurant_id, id, category_id, name, image, is_active) VALUES ($1,$2,$3,$4,$5,$6)
           ON CONFLICT (restaurant_id, id) DO UPDATE
           SET category_id = EXCLUDED.category_id, name = EXCLUDED.name, image = EXCLUDED.image,
               is_active = EXCLUDED.is_active, updated_at = now()`,
          [rid, p.id, isUuid(p.category_id) ? p.category_id : null, name, image, on(p.is_active)]
        )
      }

      for (const v of arr(b.variants, 20000)) {
        if (!isUuid(v && v.id) || !isUuid(v.product_id)) continue
        const price = num(v.price)
        if (price < 0) continue
        await client.query(
          `INSERT INTO variants (restaurant_id, id, product_id, name, price, pos, is_active) VALUES ($1,$2,$3,$4,$5,$6,$7)
           ON CONFLICT (restaurant_id, id) DO UPDATE
           SET product_id = EXCLUDED.product_id, name = EXCLUDED.name, price = EXCLUDED.price,
               pos = EXCLUDED.pos, is_active = EXCLUDED.is_active`,
          [rid, v.id, v.product_id, clean(v.name, 40), price, Math.max(0, Math.floor(num(v.pos))), on(v.is_active)]
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
    const [c, p, v, s] = await Promise.all([
      pool.query('SELECT id, name, is_active FROM categories WHERE restaurant_id = $1 AND synced_at > $2::timestamptz', [rid, since]),
      pool.query(
        'SELECT id, category_id, name, image, is_active FROM products WHERE restaurant_id = $1 AND synced_at > $2::timestamptz',
        [rid, since]
      ),
      pool.query(
        `SELECT id, product_id, name, price::float AS price, pos, is_active FROM variants
         WHERE restaurant_id = $1 AND synced_at > $2::timestamptz`,
        [rid, since]
      ),
      pool.query('SELECT key, value FROM settings WHERE restaurant_id = $1 AND synced_at > $2::timestamptz', [rid, since])
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
      license: lic
    })
  })
)

// ---------- restaurant panel: reports ----------
app.get(
  '/api/report',
  auth('restaurant'),
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
    const [c, p, v] = await Promise.all([
      pool.query('SELECT id, name FROM categories WHERE restaurant_id = $1 AND is_active ORDER BY lower(name)', [rid]),
      pool.query(
        `SELECT id, category_id, name, image FROM products
         WHERE restaurant_id = $1 AND is_active ORDER BY lower(name)`,
        [rid]
      ),
      pool.query(
        `SELECT id, product_id, name, price::float AS price FROM variants
         WHERE restaurant_id = $1 AND is_active ORDER BY pos`,
        [rid]
      )
    ])
    const byProduct = {}
    for (const x of v.rows) (byProduct[x.product_id] = byProduct[x.product_id] || []).push(x)
    res.json({
      ok: true,
      categories: c.rows,
      products: p.rows.map((x) => ({ ...x, variants: byProduct[x.id] || [] }))
    })
  })
)

app.post(
  '/api/categories',
  auth('restaurant'),
  needActive,
  wrap(async (req, res) => {
    const name = clean(req.body?.name, 60)
    if (!name) return bad(res, 'Enter a category name')
    const dup = await pool.query('SELECT 1 FROM categories WHERE restaurant_id = $1 AND lower(name) = lower($2) AND is_active', [
      req.auth.rid,
      name
    ])
    if (dup.rowCount) return bad(res, 'This category already exists')
    await pool.query('INSERT INTO categories (restaurant_id, id, name) VALUES ($1,$2,$3)', [
      req.auth.rid,
      crypto.randomUUID(),
      name
    ])
    res.json({ ok: true })
  })
)

app.put(
  '/api/categories/:id',
  auth('restaurant'),
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
  needActive,
  wrap(async (req, res) => {
    const rid = req.auth.rid
    const b = req.body || {}
    const name = clean(b.name)
    if (!name) return bad(res, 'Product name is required')
    if (!isUuid(b.category_id)) return bad(res, 'Select a category first')
    const image = typeof b.image === 'string' ? b.image : ''
    if (!isImage(image)) return bad(res, 'The photo is too large. Choose a smaller photo.')

    const variants = (Array.isArray(b.variants) ? b.variants : [])
      .slice(0, 20)
      .map((v) => ({ id: isUuid(v && v.id) ? v.id : '', name: clean(v && v.name, 40), price: num(v && v.price) }))
      .filter((v) => v.name || v.price)

    if (!variants.length) return bad(res, 'Add at least one price')
    if (variants.some((v) => !(v.price > 0))) return bad(res, 'Every option needs a valid price')
    if (variants.length > 1 && variants.some((v) => !v.name)) return bad(res, 'Give every option a name')

    const cat = await pool.query('SELECT 1 FROM categories WHERE restaurant_id = $1 AND id = $2 AND is_active', [rid, b.category_id])
    if (!cat.rowCount) return bad(res, 'Category not found')

    let notFound = false
    const client = await pool.connect()
    try {
      await client.query('BEGIN')
      let id = isUuid(b.id) ? b.id : null
      if (id) {
        const up = await client.query(
          `UPDATE products SET name = $1, category_id = $2, image = $3, updated_at = now(), is_active = TRUE
           WHERE restaurant_id = $4 AND id = $5`,
          [name, b.category_id, image, rid, id]
        )
        if (!up.rowCount) notFound = true
      } else {
        id = crypto.randomUUID()
        await client.query(
          'INSERT INTO products (restaurant_id, id, category_id, name, image) VALUES ($1,$2,$3,$4,$5)',
          [rid, id, b.category_id, name, image]
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
              `UPDATE variants SET name = $1, price = $2, pos = $3, is_active = TRUE
               WHERE restaurant_id = $4 AND id = $5 AND product_id = $6`,
              [v.name, v.price, i, rid, vid, id]
            )
            updated = u.rowCount
          }
          if (!updated) {
            vid = crypto.randomUUID()
            await client.query(
              'INSERT INTO variants (restaurant_id, id, product_id, name, price, pos) VALUES ($1,$2,$3,$4,$5,$6)',
              [rid, vid, id, v.name, v.price, i]
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

  app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`))
}

start().catch((e) => {
  console.error('Could not start the server:', e.message)
  process.exit(1)
})
