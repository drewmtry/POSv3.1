const express = require('express');
const path = require('path');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;
let JWT_SECRET = process.env.JWT_SECRET || null;
const DB_PATH = path.join(__dirname, 'pos.db');
const db = new Database(DB_PATH);
const ALLOWED_ORIGINS = (process.env.CORS_ORIGIN || 'http://localhost:3000,http://127.0.0.1:3000')
  .split(',')
  .map(origin => origin.trim())
  .filter(Boolean);

db.pragma('journal_mode = WAL');
app.use(cors({
  origin(origin, callback) {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error('Origin not allowed by CORS.'));
  }
}));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const globalRateLimiter = rateLimit({
  windowMs: 60_000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Please try again shortly.' }
});
const authRateLimiter = rateLimit({
  windowMs: 60_000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Please try again later.' }
});
app.use(globalRateLimiter);

function now() {
  return new Date().toISOString();
}

function money(value) {
  return Number(Number(value || 0).toFixed(2));
}

function recalcEndingStock(record) {
  return money(Number(record.beginning_stock || 0) + Number(record.stock_in || 0) - Number(record.stock_out || 0));
}

function initDb() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('manager','waiter','cashier','developer')),
      enabled INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS categories (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL,
      display_system TEXT NOT NULL CHECK (display_system IN ('bar','kitchen','both')) DEFAULT 'kitchen',
      enabled INTEGER NOT NULL DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS food_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      price REAL NOT NULL,
      discount_percent REAL NOT NULL DEFAULT 0,
      category_id INTEGER,
      display_system TEXT NOT NULL CHECK (display_system IN ('bar','kitchen','both')) DEFAULT 'kitchen',
      enabled INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL,
      FOREIGN KEY (category_id) REFERENCES categories(id)
    );

    CREATE TABLE IF NOT EXISTS inventory (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      food_item_id INTEGER NOT NULL,
      beginning_stock REAL NOT NULL DEFAULT 0,
      stock_in REAL NOT NULL DEFAULT 0,
      stock_out REAL NOT NULL DEFAULT 0,
      ending_stock REAL NOT NULL DEFAULT 0,
      date TEXT NOT NULL,
      FOREIGN KEY (food_item_id) REFERENCES food_items(id)
    );

    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      table_number TEXT,
      waiter_id INTEGER,
      status TEXT NOT NULL DEFAULT 'paid',
      subtotal REAL NOT NULL DEFAULT 0,
      discount REAL NOT NULL DEFAULT 0,
      tax REAL NOT NULL DEFAULT 0,
      tips REAL NOT NULL DEFAULT 0,
      total REAL NOT NULL DEFAULT 0,
      payment_method TEXT NOT NULL DEFAULT 'cash',
      amount_paid REAL NOT NULL DEFAULT 0,
      change_given REAL NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL,
      FOREIGN KEY (waiter_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS order_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      order_id INTEGER NOT NULL,
      food_item_id INTEGER NOT NULL,
      quantity REAL NOT NULL,
      price REAL NOT NULL,
      discount_percent REAL NOT NULL DEFAULT 0,
      FOREIGN KEY (order_id) REFERENCES orders(id),
      FOREIGN KEY (food_item_id) REFERENCES food_items(id)
    );

    CREATE TABLE IF NOT EXISTS split_bills (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      order_id INTEGER NOT NULL,
      split_number INTEGER NOT NULL,
      amount REAL NOT NULL,
      paid INTEGER NOT NULL DEFAULT 0,
      FOREIGN KEY (order_id) REFERENCES orders(id)
    );

    CREATE TABLE IF NOT EXISTS subscription (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      expiry_date TEXT NOT NULL,
      plan_name TEXT NOT NULL,
      created_by INTEGER,
      created_at TEXT NOT NULL,
      FOREIGN KEY (created_by) REFERENCES users(id)
    );

    CREATE INDEX IF NOT EXISTS idx_inventory_food_date ON inventory(food_item_id, date);
    CREATE INDEX IF NOT EXISTS idx_order_items_order_id ON order_items(order_id);
    CREATE INDEX IF NOT EXISTS idx_orders_created_at ON orders(created_at);
  `);

  const settingStmt = db.prepare('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)');
  settingStmt.run('restaurant_name', 'Copilot Bistro');
  settingStmt.run('currency', 'USD');
  if (!JWT_SECRET) {
    const storedSecret = db.prepare("SELECT value FROM settings WHERE key = 'jwt_secret'").get();
    JWT_SECRET = storedSecret ? storedSecret.value : crypto.randomBytes(32).toString('hex');
    settingStmt.run('jwt_secret', JWT_SECRET);
    if (!storedSecret) {
      console.warn('JWT_SECRET not set. Generated and stored a database-backed secret; set JWT_SECRET to override it explicitly.');
    }
  }

  if (db.prepare('SELECT COUNT(*) AS count FROM users').get().count === 0) {
    const insertUser = db.prepare('INSERT INTO users (username, password_hash, role, enabled, created_at) VALUES (?, ?, ?, 1, ?)');
    function resolvePassword(envVar, username) {
      if (process.env[envVar]) return process.env[envVar];
      // Generate a random password on first run and store it for display
      const generated = crypto.randomBytes(10).toString('base64url');
      console.log(`[SEED] Auto-generated password for '${username}': ${generated}  (set ${envVar} to override)`);
      return generated;
    }
    const seededUsers = [
      { username: 'admin', password: resolvePassword('POS_ADMIN_PASSWORD', 'admin'), role: 'manager' },
      { username: 'developer', password: resolvePassword('POS_DEVELOPER_PASSWORD', 'developer'), role: 'developer' },
      { username: 'waiter', password: resolvePassword('POS_WAITER_PASSWORD', 'waiter'), role: 'waiter' },
      { username: 'cashier', password: resolvePassword('POS_CASHIER_PASSWORD', 'cashier'), role: 'cashier' }
    ];
    for (const user of seededUsers) {
      insertUser.run(user.username, bcrypt.hashSync(user.password, 10), user.role, now());
    }
  }

  if (db.prepare('SELECT COUNT(*) AS count FROM categories').get().count === 0) {
    const insertCategory = db.prepare('INSERT INTO categories (name, display_system, enabled) VALUES (?, ?, 1)');
    insertCategory.run('Main Course', 'kitchen');
    insertCategory.run('Drinks', 'bar');
    insertCategory.run('Desserts', 'kitchen');
  }

  if (db.prepare('SELECT COUNT(*) AS count FROM food_items').get().count === 0) {
    const categoryMap = Object.fromEntries(db.prepare('SELECT id, name FROM categories').all().map(row => [row.name, row.id]));
    const insertFood = db.prepare(`
      INSERT INTO food_items (name, price, discount_percent, category_id, display_system, enabled, created_at)
      VALUES (?, ?, ?, ?, ?, 1, ?)
    `);
    const createdAt = now();
    insertFood.run('Grilled Chicken', 14.5, 0, categoryMap['Main Course'], 'kitchen', createdAt);
    insertFood.run('Pasta Alfredo', 12.0, 5, categoryMap['Main Course'], 'kitchen', createdAt);
    insertFood.run('Fresh Lemonade', 4.5, 0, categoryMap['Drinks'], 'bar', createdAt);
    insertFood.run('Chocolate Cake', 6.25, 10, categoryMap['Desserts'], 'kitchen', createdAt);
  }

  if (db.prepare('SELECT COUNT(*) AS count FROM subscription').get().count === 0) {
    const developer = db.prepare("SELECT id FROM users WHERE role = 'developer' ORDER BY id LIMIT 1").get();
    const expiry = new Date();
    expiry.setMonth(expiry.getMonth() + 1);
    db.prepare('INSERT INTO subscription (expiry_date, plan_name, created_by, created_at) VALUES (?, ?, ?, ?)')
      .run(expiry.toISOString(), 'Starter', developer ? developer.id : null, now());
  }

  seedInventory();
}

function seedInventory() {
  const today = new Date().toISOString().slice(0, 10);
  const foodItems = db.prepare('SELECT id FROM food_items').all();
  const existing = db.prepare('SELECT COUNT(*) AS count FROM inventory WHERE date = ?').get(today).count;
  if (existing > 0) return;
  const insert = db.prepare(`
    INSERT INTO inventory (food_item_id, beginning_stock, stock_in, stock_out, ending_stock, date)
    VALUES (?, ?, ?, ?, ?, ?)
  `);
  const tx = db.transaction(() => {
    for (const item of foodItems) {
      insert.run(item.id, 50, 0, 0, 50, today);
    }
  });
  tx();
}

function getSettingsObject() {
  const rows = db.prepare('SELECT key, value FROM settings').all();
  return rows.reduce((acc, row) => {
    acc[row.key] = row.value;
    return acc;
  }, {});
}

function getCurrentSubscription() {
  return db.prepare(`
    SELECT s.*, u.username AS created_by_username
    FROM subscription s
    LEFT JOIN users u ON u.id = s.created_by
    ORDER BY s.id DESC LIMIT 1
  `).get() || null;
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) {
    return res.status(401).json({ error: 'Authentication required.' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = db.prepare('SELECT id, username, role, enabled, created_at FROM users WHERE id = ?').get(decoded.id);
    if (!user || !user.enabled) {
      return res.status(401).json({ error: 'User is disabled or missing.' });
    }
    req.user = user;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid or expired token.' });
  }
}

function requireRoles(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions.' });
    }
    next();
  };
}

function mapFoodItem(row) {
  return {
    ...row,
    enabled: Boolean(row.enabled)
  };
}

function getOrderDetails(orderId) {
  const order = db.prepare(`
    SELECT o.*, u.username AS waiter_username
    FROM orders o
    LEFT JOIN users u ON u.id = o.waiter_id
    WHERE o.id = ?
  `).get(orderId);
  if (!order) return null;

  const items = db.prepare(`
    SELECT oi.*, fi.name AS food_name, fi.display_system, c.name AS category_name
    FROM order_items oi
    JOIN food_items fi ON fi.id = oi.food_item_id
    LEFT JOIN categories c ON c.id = fi.category_id
    WHERE oi.order_id = ?
    ORDER BY oi.id ASC
  `).all(orderId);

  const splitBills = db.prepare('SELECT * FROM split_bills WHERE order_id = ? ORDER BY split_number ASC').all(orderId);
  return { ...order, items, splitBills };
}

function getEnabledManagerCount() {
  return db.prepare("SELECT COUNT(*) AS count FROM users WHERE role = 'manager' AND enabled = 1").get().count;
}

function ensureInventoryRow(foodItemId, date) {
  let row = db.prepare('SELECT * FROM inventory WHERE food_item_id = ? AND date = ? ORDER BY id DESC LIMIT 1').get(foodItemId, date);
  if (row) return row;

  const previous = db.prepare('SELECT ending_stock FROM inventory WHERE food_item_id = ? ORDER BY date DESC, id DESC LIMIT 1').get(foodItemId);
  const beginning = previous ? Number(previous.ending_stock) : 0;
  const info = db.prepare(`
    INSERT INTO inventory (food_item_id, beginning_stock, stock_in, stock_out, ending_stock, date)
    VALUES (?, ?, 0, 0, ?, ?)
  `).run(foodItemId, beginning, beginning, date);
  return db.prepare('SELECT * FROM inventory WHERE id = ?').get(info.lastInsertRowid);
}

function adjustInventory(items, direction) {
  const today = new Date().toISOString().slice(0, 10);
  const update = db.prepare(`
    UPDATE inventory
    SET stock_out = ?, ending_stock = ?
    WHERE id = ?
  `);
  for (const item of items) {
    const row = ensureInventoryRow(item.food_item_id || item.foodItemId, today);
    const nextStockOut = Number(row.stock_out) + direction * Number(item.quantity);
    const safeStockOut = nextStockOut < 0 ? 0 : nextStockOut;
    const updated = {
      beginning_stock: row.beginning_stock,
      stock_in: row.stock_in,
      stock_out: safeStockOut
    };
    update.run(safeStockOut, recalcEndingStock(updated), row.id);
  }
}

function buildReport(startDate, endDate) {
  const summary = db.prepare(`
    SELECT COUNT(*) AS orders_count,
           COALESCE(SUM(subtotal), 0) AS subtotal,
           COALESCE(SUM(discount), 0) AS discount,
           COALESCE(SUM(tips), 0) AS tips,
           COALESCE(SUM(total), 0) AS total
    FROM orders
    WHERE substr(created_at, 1, 10) BETWEEN ? AND ?
  `).get(startDate, endDate);

  const topItems = db.prepare(`
    SELECT fi.name,
           COALESCE(SUM(oi.quantity), 0) AS qty,
           COALESCE(SUM((oi.price - (oi.price * oi.discount_percent / 100.0)) * oi.quantity), 0) AS sales
    FROM order_items oi
    JOIN orders o ON o.id = oi.order_id
    JOIN food_items fi ON fi.id = oi.food_item_id
    WHERE substr(o.created_at, 1, 10) BETWEEN ? AND ?
    GROUP BY fi.id
    ORDER BY qty DESC, sales DESC
    LIMIT 10
  `).all(startDate, endDate);

  const payments = db.prepare(`
    SELECT payment_method, COUNT(*) AS count, COALESCE(SUM(total), 0) AS total
    FROM orders
    WHERE substr(created_at, 1, 10) BETWEEN ? AND ?
    GROUP BY payment_method
    ORDER BY total DESC
  `).all(startDate, endDate);

  return { range: { startDate, endDate }, summary, topItems, payments };
}

initDb();

app.post('/api/auth/login', authRateLimiter, (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(String(username).trim());
  if (!user || !user.enabled || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Invalid credentials or disabled account.' });
  }

  const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '12h' });
  return res.json({
    token,
    user: { id: user.id, username: user.username, role: user.role, enabled: Boolean(user.enabled) },
    settings: getSettingsObject(),
    subscription: getCurrentSubscription()
  });
});

app.get('/api/me', authMiddleware, (req, res) => {
  res.json({ user: req.user, settings: getSettingsObject(), subscription: getCurrentSubscription() });
});

app.get('/api/users', authMiddleware, requireRoles('manager'), (req, res) => {
  const users = db.prepare('SELECT id, username, role, enabled, created_at FROM users ORDER BY created_at DESC').all();
  res.json(users.map(user => ({ ...user, enabled: Boolean(user.enabled) })));
});

app.post('/api/users', authMiddleware, requireRoles('manager'), (req, res) => {
  const { username, password, role, enabled = true } = req.body || {};
  if (!username || !password || !role) {
    return res.status(400).json({ error: 'Username, password, and role are required.' });
  }
  if (!['manager', 'waiter', 'cashier', 'developer'].includes(role)) {
    return res.status(400).json({ error: 'Invalid role.' });
  }

  try {
    const info = db.prepare(`
      INSERT INTO users (username, password_hash, role, enabled, created_at)
      VALUES (?, ?, ?, ?, ?)
    `).run(String(username).trim(), bcrypt.hashSync(password, 10), role, enabled ? 1 : 0, now());
    const created = db.prepare('SELECT id, username, role, enabled, created_at FROM users WHERE id = ?').get(info.lastInsertRowid);
    res.status(201).json({ ...created, enabled: Boolean(created.enabled) });
  } catch (error) {
    res.status(400).json({ error: 'Could not create user. Username may already exist.' });
  }
});

app.put('/api/users/:id', authMiddleware, requireRoles('manager'), (req, res) => {
  const { username, password, role, enabled } = req.body || {};
  const existing = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!existing) {
    return res.status(404).json({ error: 'User not found.' });
  }
  if (role && !['manager', 'waiter', 'cashier', 'developer'].includes(role)) {
    return res.status(400).json({ error: 'Invalid role.' });
  }
  const nextRole = role || existing.role;
  const nextEnabled = typeof enabled === 'undefined' ? Boolean(existing.enabled) : Boolean(enabled);
  if (existing.role === 'manager' && existing.enabled && (!nextEnabled || nextRole !== 'manager') && getEnabledManagerCount() <= 1) {
    return res.status(400).json({ error: 'At least one enabled manager account must remain.' });
  }
  if (existing.role === 'manager' && existing.id === req.user.id && (!nextEnabled || nextRole !== 'manager')) {
    return res.status(400).json({ error: 'You cannot remove your own active manager access.' });
  }

  try {
    db.prepare(`
      UPDATE users
      SET username = ?,
          role = ?,
          enabled = ?,
          password_hash = ?
      WHERE id = ?
    `).run(
      String(username || existing.username).trim(),
      nextRole,
      nextEnabled ? 1 : 0,
      password ? bcrypt.hashSync(password, 10) : existing.password_hash,
      req.params.id
    );
    const updated = db.prepare('SELECT id, username, role, enabled, created_at FROM users WHERE id = ?').get(req.params.id);
    res.json({ ...updated, enabled: Boolean(updated.enabled) });
  } catch (error) {
    res.status(400).json({ error: 'Could not update user.' });
  }
});

app.delete('/api/users/:id', authMiddleware, requireRoles('manager'), (req, res) => {
  const existing = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!existing) {
    return res.status(404).json({ error: 'User not found.' });
  }
  if (existing.id === req.user.id) {
    return res.status(400).json({ error: 'You cannot delete your own account.' });
  }
  if (existing.role === 'manager' && existing.enabled && getEnabledManagerCount() <= 1) {
    return res.status(400).json({ error: 'At least one enabled manager account must remain.' });
  }
  db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

app.get('/api/settings', authMiddleware, (req, res) => {
  res.json(getSettingsObject());
});

app.put('/api/settings', authMiddleware, requireRoles('manager'), (req, res) => {
  const { restaurant_name, currency } = req.body || {};
  const stmt = db.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value');
  if (restaurant_name) stmt.run('restaurant_name', String(restaurant_name).trim());
  if (currency) stmt.run('currency', String(currency).trim().toUpperCase());
  res.json(getSettingsObject());
});

app.get('/api/categories', authMiddleware, (req, res) => {
  const { q = '', enabled } = req.query;
  let query = 'SELECT * FROM categories WHERE name LIKE ?';
  const params = [`%${q}%`];
  if (typeof enabled !== 'undefined') {
    query += ' AND enabled = ?';
    params.push(enabled === 'true' ? 1 : 0);
  }
  query += ' ORDER BY name ASC';
  const rows = db.prepare(query).all(...params);
  res.json(rows.map(row => ({ ...row, enabled: Boolean(row.enabled) })));
});

app.post('/api/categories', authMiddleware, requireRoles('manager'), (req, res) => {
  const { name, display_system = 'kitchen', enabled = true } = req.body || {};
  if (!name) return res.status(400).json({ error: 'Category name is required.' });
  if (!['bar', 'kitchen', 'both'].includes(display_system)) return res.status(400).json({ error: 'Invalid display system.' });
  try {
    const info = db.prepare('INSERT INTO categories (name, display_system, enabled) VALUES (?, ?, ?)').run(String(name).trim(), display_system, enabled ? 1 : 0);
    res.status(201).json({ ...db.prepare('SELECT * FROM categories WHERE id = ?').get(info.lastInsertRowid), enabled: Boolean(enabled) });
  } catch (error) {
    res.status(400).json({ error: 'Could not create category.' });
  }
});

app.put('/api/categories/:id', authMiddleware, requireRoles('manager'), (req, res) => {
  const existing = db.prepare('SELECT * FROM categories WHERE id = ?').get(req.params.id);
  if (!existing) return res.status(404).json({ error: 'Category not found.' });
  const { name, display_system, enabled } = req.body || {};
  if (display_system && !['bar', 'kitchen', 'both'].includes(display_system)) {
    return res.status(400).json({ error: 'Invalid display system.' });
  }
  try {
    db.prepare(`
      UPDATE categories
      SET name = ?, display_system = ?, enabled = ?
      WHERE id = ?
    `).run(
      String(name || existing.name).trim(),
      display_system || existing.display_system,
      typeof enabled === 'undefined' ? existing.enabled : enabled ? 1 : 0,
      req.params.id
    );
    const updated = db.prepare('SELECT * FROM categories WHERE id = ?').get(req.params.id);
    res.json({ ...updated, enabled: Boolean(updated.enabled) });
  } catch (error) {
    res.status(400).json({ error: 'Could not update category.' });
  }
});

app.delete('/api/categories/:id', authMiddleware, requireRoles('manager'), (req, res) => {
  db.transaction(() => {
    db.prepare('UPDATE food_items SET category_id = NULL WHERE category_id = ?').run(req.params.id);
    db.prepare('DELETE FROM categories WHERE id = ?').run(req.params.id);
  })();
  res.json({ success: true });
});

app.get('/api/food-items', authMiddleware, (req, res) => {
  const { q = '', categoryId, enabled } = req.query;
  let query = `
    SELECT fi.*, c.name AS category_name, c.display_system AS category_display_system
    FROM food_items fi
    LEFT JOIN categories c ON c.id = fi.category_id
    WHERE fi.name LIKE ?
  `;
  const params = [`%${q}%`];
  if (categoryId) {
    query += ' AND fi.category_id = ?';
    params.push(categoryId);
  }
  if (typeof enabled !== 'undefined') {
    query += ' AND fi.enabled = ?';
    params.push(enabled === 'true' ? 1 : 0);
  }
  query += ' ORDER BY fi.name ASC';
  const rows = db.prepare(query).all(...params);
  res.json(rows.map(mapFoodItem));
});

app.post('/api/food-items', authMiddleware, requireRoles('manager'), (req, res) => {
  const { name, price, discount_percent = 0, category_id = null, display_system = 'kitchen', enabled = true } = req.body || {};
  if (!name || typeof price === 'undefined') {
    return res.status(400).json({ error: 'Food item name and price are required.' });
  }
  if (!['bar', 'kitchen', 'both'].includes(display_system)) {
    return res.status(400).json({ error: 'Invalid display system.' });
  }
  const info = db.prepare(`
    INSERT INTO food_items (name, price, discount_percent, category_id, display_system, enabled, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(String(name).trim(), Number(price), Number(discount_percent || 0), category_id || null, display_system, enabled ? 1 : 0, now());
  const row = db.prepare(`
    SELECT fi.*, c.name AS category_name, c.display_system AS category_display_system
    FROM food_items fi
    LEFT JOIN categories c ON c.id = fi.category_id
    WHERE fi.id = ?
  `).get(info.lastInsertRowid);
  const today = new Date().toISOString().slice(0, 10);
  ensureInventoryRow(info.lastInsertRowid, today);
  res.status(201).json(mapFoodItem(row));
});

app.put('/api/food-items/:id', authMiddleware, requireRoles('manager'), (req, res) => {
  const existing = db.prepare('SELECT * FROM food_items WHERE id = ?').get(req.params.id);
  if (!existing) return res.status(404).json({ error: 'Food item not found.' });
  const { name, price, discount_percent, category_id, display_system, enabled } = req.body || {};
  if (display_system && !['bar', 'kitchen', 'both'].includes(display_system)) {
    return res.status(400).json({ error: 'Invalid display system.' });
  }
  db.prepare(`
    UPDATE food_items
    SET name = ?, price = ?, discount_percent = ?, category_id = ?, display_system = ?, enabled = ?
    WHERE id = ?
  `).run(
    String(name || existing.name).trim(),
    typeof price === 'undefined' ? existing.price : Number(price),
    typeof discount_percent === 'undefined' ? existing.discount_percent : Number(discount_percent),
    typeof category_id === 'undefined' ? existing.category_id : category_id || null,
    display_system || existing.display_system,
    typeof enabled === 'undefined' ? existing.enabled : enabled ? 1 : 0,
    req.params.id
  );
  const row = db.prepare(`
    SELECT fi.*, c.name AS category_name, c.display_system AS category_display_system
    FROM food_items fi
    LEFT JOIN categories c ON c.id = fi.category_id
    WHERE fi.id = ?
  `).get(req.params.id);
  res.json(mapFoodItem(row));
});

app.delete('/api/food-items/:id', authMiddleware, requireRoles('manager'), (req, res) => {
  const existing = db.prepare('SELECT * FROM food_items WHERE id = ?').get(req.params.id);
  if (!existing) {
    return res.status(404).json({ error: 'Food item not found.' });
  }
  const hasOrders = db.prepare('SELECT COUNT(*) AS count FROM order_items WHERE food_item_id = ?').get(req.params.id).count;
  if (hasOrders > 0) {
    return res.status(400).json({ error: 'Food item has order history. Disable it instead of deleting.' });
  }
  const tx = db.transaction(() => {
    db.prepare('DELETE FROM inventory WHERE food_item_id = ?').run(req.params.id);
    db.prepare('DELETE FROM food_items WHERE id = ?').run(req.params.id);
  });
  tx();
  res.json({ success: true });
});

app.get('/api/inventory', authMiddleware, requireRoles('manager'), (req, res) => {
  const { q = '', date } = req.query;
  const reportDate = date || new Date().toISOString().slice(0, 10);
  const rows = db.prepare(`
    SELECT i.*, fi.name AS food_name
    FROM inventory i
    JOIN food_items fi ON fi.id = i.food_item_id
    WHERE i.date = ? AND fi.name LIKE ?
    ORDER BY fi.name ASC
  `).all(reportDate, `%${q}%`);
  res.json(rows);
});

app.post('/api/inventory', authMiddleware, requireRoles('manager'), (req, res) => {
  const { food_item_id, beginning_stock = 0, stock_in = 0, stock_out = 0, date } = req.body || {};
  if (!food_item_id || !date) {
    return res.status(400).json({ error: 'food_item_id and date are required.' });
  }
  const payload = {
    food_item_id: Number(food_item_id),
    beginning_stock: Number(beginning_stock),
    stock_in: Number(stock_in),
    stock_out: Number(stock_out),
    date: String(date)
  };
  payload.ending_stock = recalcEndingStock(payload);
  const info = db.prepare(`
    INSERT INTO inventory (food_item_id, beginning_stock, stock_in, stock_out, ending_stock, date)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(payload.food_item_id, payload.beginning_stock, payload.stock_in, payload.stock_out, payload.ending_stock, payload.date);
  res.status(201).json(db.prepare('SELECT * FROM inventory WHERE id = ?').get(info.lastInsertRowid));
});

app.put('/api/inventory/:id', authMiddleware, requireRoles('manager'), (req, res) => {
  const existing = db.prepare('SELECT * FROM inventory WHERE id = ?').get(req.params.id);
  if (!existing) return res.status(404).json({ error: 'Inventory entry not found.' });
  const next = {
    food_item_id: typeof req.body.food_item_id === 'undefined' ? existing.food_item_id : Number(req.body.food_item_id),
    beginning_stock: typeof req.body.beginning_stock === 'undefined' ? Number(existing.beginning_stock) : Number(req.body.beginning_stock),
    stock_in: typeof req.body.stock_in === 'undefined' ? Number(existing.stock_in) : Number(req.body.stock_in),
    stock_out: typeof req.body.stock_out === 'undefined' ? Number(existing.stock_out) : Number(req.body.stock_out),
    date: req.body.date || existing.date
  };
  next.ending_stock = recalcEndingStock(next);
  db.prepare(`
    UPDATE inventory
    SET food_item_id = ?, beginning_stock = ?, stock_in = ?, stock_out = ?, ending_stock = ?, date = ?
    WHERE id = ?
  `).run(next.food_item_id, next.beginning_stock, next.stock_in, next.stock_out, next.ending_stock, next.date, req.params.id);
  res.json(db.prepare('SELECT * FROM inventory WHERE id = ?').get(req.params.id));
});

app.delete('/api/inventory/:id', authMiddleware, requireRoles('manager'), (req, res) => {
  db.prepare('DELETE FROM inventory WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

app.get('/api/orders', authMiddleware, requireRoles('manager', 'waiter', 'cashier'), (req, res) => {
  const rows = db.prepare(`
    SELECT o.*, u.username AS waiter_username
    FROM orders o
    LEFT JOIN users u ON u.id = o.waiter_id
    ORDER BY o.created_at DESC
    LIMIT 100
  `).all();
  if (!rows.length) {
    return res.json([]);
  }
  const placeholders = rows.map(() => '?').join(',');
  const orderIds = rows.map(order => order.id);
  const items = db.prepare(`
    SELECT oi.*, fi.name AS food_name
    FROM order_items oi
    JOIN food_items fi ON fi.id = oi.food_item_id
    WHERE oi.order_id IN (${placeholders})
    ORDER BY oi.order_id ASC, oi.id ASC
  `).all(...orderIds);
  const splitBills = db.prepare(`
    SELECT *
    FROM split_bills
    WHERE order_id IN (${placeholders})
    ORDER BY order_id ASC, split_number ASC
  `).all(...orderIds);
  const itemsByOrder = items.reduce((acc, item) => {
    if (!acc[item.order_id]) acc[item.order_id] = [];
    acc[item.order_id].push(item);
    return acc;
  }, {});
  const splitsByOrder = splitBills.reduce((acc, bill) => {
    if (!acc[bill.order_id]) acc[bill.order_id] = [];
    acc[bill.order_id].push(bill);
    return acc;
  }, {});
  res.json(rows.map(order => ({ ...order, items: itemsByOrder[order.id] || [], splitBills: splitsByOrder[order.id] || [] })));
});

app.get('/api/orders/:id', authMiddleware, requireRoles('manager', 'waiter', 'cashier'), (req, res) => {
  const order = getOrderDetails(req.params.id);
  if (!order) return res.status(404).json({ error: 'Order not found.' });
  res.json(order);
});

app.post('/api/orders', authMiddleware, requireRoles('manager', 'waiter', 'cashier'), (req, res) => {
  const {
    table_number = '',
    items = [],
    payment_method = 'cash',
    amount_paid = 0,
    tips = 0,
    tax = 0,
    split_count = 1,
    split_bills = null
  } = req.body || {};

  if (!Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'At least one order item is required.' });
  }

  const foodStmt = db.prepare('SELECT * FROM food_items WHERE id = ? AND enabled = 1');
  const insertOrder = db.prepare(`
    INSERT INTO orders (table_number, waiter_id, status, subtotal, discount, tax, tips, total, payment_method, amount_paid, change_given, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  const insertItem = db.prepare(`
    INSERT INTO order_items (order_id, food_item_id, quantity, price, discount_percent)
    VALUES (?, ?, ?, ?, ?)
  `);
  const insertSplit = db.prepare(`
    INSERT INTO split_bills (order_id, split_number, amount, paid)
    VALUES (?, ?, ?, ?)
  `);

  try {
    const result = db.transaction(() => {
      const orderItems = items.map(entry => {
        const food = foodStmt.get(entry.food_item_id || entry.foodItemId);
        if (!food) {
          throw new Error('One or more food items are unavailable.');
        }
        const quantity = Number(entry.quantity || 0);
        if (quantity <= 0) throw new Error('Quantity must be greater than zero.');
        return { food, quantity };
      });

      const subtotal = money(orderItems.reduce((sum, entry) => sum + (Number(entry.food.price) * entry.quantity), 0));
      const discount = money(orderItems.reduce((sum, entry) => sum + (Number(entry.food.price) * (Number(entry.food.discount_percent) / 100) * entry.quantity), 0));
      const taxAmount = money(Number(tax || 0));
      const tipAmount = money(Number(tips || 0));
      const total = money(subtotal - discount + taxAmount + tipAmount);
      const paidAmount = money(Number(amount_paid || 0));
      const changeGiven = money(Math.max(0, paidAmount - total));
      const status = paidAmount >= total ? 'paid' : 'pending';

      const orderInfo = insertOrder.run(
        String(table_number || '').trim(),
        req.user.id,
        status,
        subtotal,
        discount,
        taxAmount,
        tipAmount,
        total,
        payment_method,
        paidAmount,
        changeGiven,
        now()
      );

      const normalizedItems = [];
      for (const entry of orderItems) {
        insertItem.run(orderInfo.lastInsertRowid, entry.food.id, entry.quantity, entry.food.price, entry.food.discount_percent || 0);
        normalizedItems.push({ food_item_id: entry.food.id, quantity: entry.quantity });
      }

      const splitCountNumber = Math.max(1, Number(split_count || 1));
      if (Array.isArray(split_bills) && split_bills.length) {
        split_bills.forEach((bill, index) => {
          insertSplit.run(orderInfo.lastInsertRowid, index + 1, money(Number(bill.amount || 0)), bill.paid ? 1 : 0);
        });
      } else {
        const baseAmount = money(total / splitCountNumber);
        let remainder = money(total - baseAmount * splitCountNumber);
        let remainingPaid = paidAmount;
        for (let i = 1; i <= splitCountNumber; i += 1) {
          const addition = remainder > 0 ? 0.01 : 0;
          const amount = money(baseAmount + addition);
          if (remainder > 0) remainder = money(remainder - 0.01);
          const isPaid = remainingPaid >= amount;
          if (isPaid) remainingPaid = money(remainingPaid - amount);
          insertSplit.run(orderInfo.lastInsertRowid, i, amount, isPaid ? 1 : 0);
        }
      }

      adjustInventory(normalizedItems, 1);
      return getOrderDetails(orderInfo.lastInsertRowid);
    })();

    res.status(201).json(result);
  } catch (error) {
    res.status(400).json({ error: error.message || 'Could not create order.' });
  }
});

app.put('/api/orders/:id', authMiddleware, requireRoles('manager', 'waiter', 'cashier'), (req, res) => {
  const existing = db.prepare('SELECT * FROM orders WHERE id = ?').get(req.params.id);
  if (!existing) return res.status(404).json({ error: 'Order not found.' });
  if (req.user.role !== 'manager' && existing.waiter_id !== req.user.id) {
    return res.status(403).json({ error: 'You can only update your own orders.' });
  }
  const next = {
    table_number: typeof req.body.table_number === 'undefined' ? existing.table_number : String(req.body.table_number),
    status: req.body.status || existing.status,
    tips: typeof req.body.tips === 'undefined' ? Number(existing.tips) : Number(req.body.tips),
    payment_method: req.body.payment_method || existing.payment_method,
    amount_paid: typeof req.body.amount_paid === 'undefined' ? Number(existing.amount_paid) : Number(req.body.amount_paid)
  };
  next.total = money(Number(existing.subtotal) - Number(existing.discount) + Number(existing.tax) + next.tips);
  next.change_given = money(Math.max(0, next.amount_paid - next.total));
  if (next.amount_paid >= next.total) next.status = 'paid';
  db.prepare(`
    UPDATE orders
    SET table_number = ?, status = ?, tips = ?, total = ?, payment_method = ?, amount_paid = ?, change_given = ?
    WHERE id = ?
  `).run(next.table_number, next.status, next.tips, next.total, next.payment_method, next.amount_paid, next.change_given, req.params.id);

  if (Array.isArray(req.body.split_bills)) {
    db.prepare('DELETE FROM split_bills WHERE order_id = ?').run(req.params.id);
    const insertSplit = db.prepare('INSERT INTO split_bills (order_id, split_number, amount, paid) VALUES (?, ?, ?, ?)');
    req.body.split_bills.forEach((bill, index) => {
      insertSplit.run(req.params.id, index + 1, money(Number(bill.amount || 0)), bill.paid ? 1 : 0);
    });
  }

  res.json(getOrderDetails(req.params.id));
});

app.delete('/api/orders/:id', authMiddleware, requireRoles('manager'), (req, res) => {
  const order = getOrderDetails(req.params.id);
  if (!order) return res.status(404).json({ error: 'Order not found.' });
  const tx = db.transaction(() => {
    adjustInventory(order.items.map(item => ({ food_item_id: item.food_item_id, quantity: item.quantity })), -1);
    db.prepare('DELETE FROM split_bills WHERE order_id = ?').run(req.params.id);
    db.prepare('DELETE FROM order_items WHERE order_id = ?').run(req.params.id);
    db.prepare('DELETE FROM orders WHERE id = ?').run(req.params.id);
  });
  tx();
  res.json({ success: true });
});

app.get('/api/reports/daily', authMiddleware, requireRoles('manager'), (req, res) => {
  const date = req.query.date || new Date().toISOString().slice(0, 10);
  res.json(buildReport(date, date));
});

app.get('/api/reports/weekly', authMiddleware, requireRoles('manager'), (req, res) => {
  const end = req.query.endDate ? new Date(req.query.endDate) : new Date();
  const start = new Date(end);
  start.setDate(end.getDate() - 6);
  res.json(buildReport(start.toISOString().slice(0, 10), end.toISOString().slice(0, 10)));
});

app.get('/api/reports/monthly', authMiddleware, requireRoles('manager'), (req, res) => {
  const target = req.query.month ? new Date(`${req.query.month}-01T00:00:00`) : new Date();
  const start = new Date(target.getFullYear(), target.getMonth(), 1);
  const end = new Date(target.getFullYear(), target.getMonth() + 1, 0);
  res.json(buildReport(start.toISOString().slice(0, 10), end.toISOString().slice(0, 10)));
});

app.get('/api/subscription', authMiddleware, (req, res) => {
  res.json(getCurrentSubscription());
});

app.post('/api/subscription', authMiddleware, requireRoles('developer'), (req, res) => {
  const { expiry_date, plan_name } = req.body || {};
  if (!expiry_date || !plan_name) {
    return res.status(400).json({ error: 'expiry_date and plan_name are required.' });
  }
  const info = db.prepare(`
    INSERT INTO subscription (expiry_date, plan_name, created_by, created_at)
    VALUES (?, ?, ?, ?)
  `).run(expiry_date, String(plan_name).trim(), req.user.id, now());
  res.status(201).json(db.prepare('SELECT * FROM subscription WHERE id = ?').get(info.lastInsertRowid));
});

app.put('/api/subscription', authMiddleware, requireRoles('developer'), (req, res) => {
  const current = getCurrentSubscription();
  if (!current) return res.status(404).json({ error: 'Subscription not found.' });
  const expiryDate = req.body.expiry_date || current.expiry_date;
  const planName = req.body.plan_name || current.plan_name;
  db.prepare('UPDATE subscription SET expiry_date = ?, plan_name = ?, created_by = ? WHERE id = ?')
    .run(expiryDate, planName, req.user.id, current.id);
  res.json(getCurrentSubscription());
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Restaurant POS server running on http://localhost:${PORT}`);
  });
}

module.exports = app;
