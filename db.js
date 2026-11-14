require('dotenv').config()
const { Pool } = require('pg')

const poolConfig = process.env.DATABASE_URL
  ? {
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false }
    }
  : {
      host: process.env.DB_HOST || 'localhost',
      port: Number(process.env.DB_PORT) || 5432,
      user: process.env.DB_USER || 'postgres',
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME || 'restopos_cloud'
    }

const pool = new Pool(poolConfig)

async function init() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS restaurants (
      id UUID PRIMARY KEY,
      name TEXT NOT NULL,
      owner_name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      phone TEXT,
      city TEXT,
      password_hash TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      plan TEXT NOT NULL DEFAULT 'Monthly',
      monthly_fee NUMERIC(12,2) NOT NULL DEFAULT 0,
      paid_until DATE,
      notes TEXT,
      last_seen TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS admins (
      id UUID PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS payments (
      id UUID PRIMARY KEY,
      restaurant_id UUID NOT NULL REFERENCES restaurants(id) ON DELETE CASCADE,
      amount NUMERIC(12,2) NOT NULL,
      days_added INT NOT NULL DEFAULT 30,
      note TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS bills (
      restaurant_id UUID NOT NULL REFERENCES restaurants(id) ON DELETE CASCADE,
      id UUID NOT NULL,
      bill_no INT,
      created_at TIMESTAMP NOT NULL,
      order_type TEXT,
      table_name TEXT,
      guests INT NOT NULL DEFAULT 1,
      subtotal NUMERIC(12,2) NOT NULL DEFAULT 0,
      discount NUMERIC(12,2) NOT NULL DEFAULT 0,
      tax NUMERIC(12,2) NOT NULL DEFAULT 0,
      total NUMERIC(12,2) NOT NULL DEFAULT 0,
      payment_method TEXT,
      items JSONB NOT NULL DEFAULT '[]',
      received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY (restaurant_id, id)
    );

    CREATE INDEX IF NOT EXISTS bills_date_idx ON bills (restaurant_id, created_at);

    CREATE TABLE IF NOT EXISTS categories (
      restaurant_id UUID NOT NULL REFERENCES restaurants(id) ON DELETE CASCADE,
      id UUID NOT NULL,
      name TEXT NOT NULL,
      PRIMARY KEY (restaurant_id, id)
    );

    CREATE TABLE IF NOT EXISTS products (
      restaurant_id UUID NOT NULL REFERENCES restaurants(id) ON DELETE CASCADE,
      id UUID NOT NULL,
      category_id UUID,
      name TEXT NOT NULL,
      image TEXT NOT NULL DEFAULT '',
      is_active BOOLEAN NOT NULL DEFAULT TRUE,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY (restaurant_id, id)
    );

    CREATE TABLE IF NOT EXISTS variants (
      restaurant_id UUID NOT NULL REFERENCES restaurants(id) ON DELETE CASCADE,
      id UUID NOT NULL,
      product_id UUID NOT NULL,
      name TEXT NOT NULL DEFAULT '',
      price NUMERIC(12,2) NOT NULL,
      pos INT NOT NULL DEFAULT 0,
      is_active BOOLEAN NOT NULL DEFAULT TRUE,
      PRIMARY KEY (restaurant_id, id)
    );

    CREATE TABLE IF NOT EXISTS settings (
      restaurant_id UUID NOT NULL REFERENCES restaurants(id) ON DELETE CASCADE,
      key TEXT NOT NULL,
      value TEXT NOT NULL DEFAULT '',
      PRIMARY KEY (restaurant_id, key)
    );

    -- columns and triggers used by the desktop sync
    ALTER TABLE categories ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE;
    ALTER TABLE categories ADD COLUMN IF NOT EXISTS synced_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp();
    ALTER TABLE products   ADD COLUMN IF NOT EXISTS synced_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp();
    ALTER TABLE products   ADD COLUMN IF NOT EXISTS track_stock BOOLEAN NOT NULL DEFAULT FALSE;
    ALTER TABLE products   ADD COLUMN IF NOT EXISTS stock INT NOT NULL DEFAULT 0;
    ALTER TABLE products   ADD COLUMN IF NOT EXISTS min_stock INT NOT NULL DEFAULT 5;
    ALTER TABLE variants   ADD COLUMN IF NOT EXISTS stock INT NOT NULL DEFAULT 0;
    ALTER TABLE variants   ADD COLUMN IF NOT EXISTS min_stock INT NOT NULL DEFAULT 5;
    ALTER TABLE variants   ADD COLUMN IF NOT EXISTS synced_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp();
    ALTER TABLE bills      ADD COLUMN IF NOT EXISTS waiter_name TEXT;
    ALTER TABLE settings   ADD COLUMN IF NOT EXISTS synced_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp();

    CREATE OR REPLACE FUNCTION touch_synced_at() RETURNS trigger AS $$
    BEGIN
      NEW.synced_at = clock_timestamp();
      RETURN NEW;
    END;
    $$ LANGUAGE plpgsql;

    DROP TRIGGER IF EXISTS t_categories_sync ON categories;
    CREATE TRIGGER t_categories_sync BEFORE INSERT OR UPDATE ON categories FOR EACH ROW EXECUTE FUNCTION touch_synced_at();
    DROP TRIGGER IF EXISTS t_products_sync ON products;
    CREATE TRIGGER t_products_sync BEFORE INSERT OR UPDATE ON products FOR EACH ROW EXECUTE FUNCTION touch_synced_at();
    DROP TRIGGER IF EXISTS t_variants_sync ON variants;
    CREATE TRIGGER t_variants_sync BEFORE INSERT OR UPDATE ON variants FOR EACH ROW EXECUTE FUNCTION touch_synced_at();
    DROP TRIGGER IF EXISTS t_settings_sync ON settings;
    CREATE TRIGGER t_settings_sync BEFORE INSERT OR UPDATE ON settings FOR EACH ROW EXECUTE FUNCTION touch_synced_at();
  `)
}

module.exports = { pool, init }
