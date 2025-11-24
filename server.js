// index.js
require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');

const app = express();
const PORT = process.env.PORT || 3000;
const path = require('path');

// Serve all static files from root folder
app.use(express.static(path.join(__dirname)));

// Root route → serve login page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});


// Security middleware
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false
});
app.use(limiter);

// Database pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Utility: cleanup expired keys
const cleanupExpiredKeys = async () => {
  try {
    const result = await pool.query(`
      UPDATE keys
      SET status = 'expired'
      WHERE expires_at < CURRENT_TIMESTAMP
        AND status = 'active'
      RETURNING id
    `);
    if (result.rows.length > 0) {
      console.log(`🔄 Auto-expired ${result.rows.length} keys`);
    }
  } catch (err) {
    console.error('Auto-cleanup error:', err);
  }
};

// Run cleanup every hour and on startup
setInterval(cleanupExpiredKeys, 60 * 60 * 1000);
cleanupExpiredKeys().catch(() => {});

// Key generator
const generateKey = () => {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let key = '';
  for (let i = 0; i < 25; i++) {
    if (i > 0 && i % 5 === 0) key += '-';
    key += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return key;
};

// Log key activity
const logKeyActivity = async (keyId, action, req) => {
  try {
    await pool.query(
      `INSERT INTO key_logs (key_id, action, ip_address, user_agent)
       VALUES ($1, $2, $3, $4)`,
      [keyId, action, req.ip, req.get('User-Agent') || 'unknown']
    );
  } catch (err) {
    console.error('Log activity error:', err);
  }
};

// Admin authentication middleware (async/await version)
const authenticateAdmin = async (req, res, next) => {
  try {
    const adminSecret = req.headers['admin-secret'] || req.body?.admin_secret;
    console.log('🔐 Admin auth attempt');
    console.log('Secret provided:', adminSecret ? 'Yes' : 'No');

    if (!adminSecret) {
      console.log('❌ No admin secret provided');
      return res.status(401).json({ success: false, error: 'Admin secret required' });
    }
    if (!process.env.ADMIN_SECRET_HASH) {
      console.error('❌ ADMIN_SECRET_HASH environment variable is not set');
      return res.status(500).json({ success: false, error: 'Server configuration error' });
    }

    try {
      const match = await bcrypt.compare(adminSecret, process.env.ADMIN_SECRET_HASH);
      if (match) {
        console.log('✅ Admin authentication successful');
        return next();
      } else {
        console.log('❌ Admin authentication failed - Invalid secret');
        return res.status(401).json({ success: false, error: 'Invalid admin secret' });
      }
    } catch (bcryptErr) {
      console.error('💥 Bcrypt comparison error:', bcryptErr);
      return res.status(500).json({
        success: false,
        error: 'Authentication error',
        details: process.env.NODE_ENV === 'development' ? bcryptErr.message : undefined
      });
    }
  } catch (err) {
    console.error('💥 Auth middleware error:', err);
    res.status(500).json({
      success: false,
      error: 'Authentication server error',
      details: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
};

// Initialize database (create keys, key_activations, key_logs)
const initDatabase = async () => {
  try {
    // Clean start (drop if exist)
    await pool.query('DROP TABLE IF EXISTS key_logs CASCADE');
    await pool.query('DROP TABLE IF EXISTS key_activations CASCADE');
    await pool.query('DROP TABLE IF EXISTS keys CASCADE');

    // Create keys table
    await pool.query(`
      CREATE TABLE keys (
        id SERIAL PRIMARY KEY,
        key_string VARCHAR(255) UNIQUE NOT NULL,
        duration_hours INTEGER NOT NULL,
        max_devices INTEGER DEFAULT 1,
        used_devices INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP,
        status VARCHAR(20) DEFAULT 'active'
      )
    `);

    // Create key_activations table
    await pool.query(`
      CREATE TABLE key_activations (
        id SERIAL PRIMARY KEY,
        key_id INTEGER NOT NULL REFERENCES keys(id) ON DELETE CASCADE,
        device_id VARCHAR(255) NOT NULL,
        ip_address VARCHAR(100),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (key_id, device_id)
      )
    `);

    // Create key_logs table
    await pool.query(`
      CREATE TABLE key_logs (
        id SERIAL PRIMARY KEY,
        key_id INTEGER REFERENCES keys(id) ON DELETE CASCADE,
        action VARCHAR(100),
        ip_address VARCHAR(100),
        user_agent TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    console.log('✅ Database tables created with clean schema');
  } catch (err) {
    console.error('Database initialization error:', err);
    throw err;
  }
};

// Update schema if needed (keeps for future compatibility)
const updateDatabaseSchema = async () => {
  try {
    // Ensure columns exist in keys table (idempotent)
    const needsMax = await pool.query(`
      SELECT column_name FROM information_schema.columns
      WHERE table_name = 'keys' AND column_name = 'max_devices'
    `);
    if (needsMax.rows.length === 0) {
      console.log('🔄 Adding max_devices column to keys...');
      await pool.query(`ALTER TABLE keys ADD COLUMN max_devices INTEGER DEFAULT 1`);
    }

    const needsUsed = await pool.query(`
      SELECT column_name FROM information_schema.columns
      WHERE table_name = 'keys' AND column_name = 'used_devices'
    `);
    if (needsUsed.rows.length === 0) {
      console.log('🔄 Adding used_devices column to keys...');
      await pool.query(`ALTER TABLE keys ADD COLUMN used_devices INTEGER DEFAULT 0`);
    }
    console.log('✅ Schema update checked');
  } catch (err) {
    console.error('Database schema update error:', err);
  }
};

// Routes

app.post('/admin/login', async (req, res) => {
  const adminSecret = req.body?.admin_secret;
  if (!adminSecret) return res.status(400).json({ success: false, error: 'Admin secret required' });

  try {
    const match = await bcrypt.compare(adminSecret, process.env.ADMIN_SECRET_HASH);
    if (match) {
      res.json({ success: true });
    } else {
      res.status(401).json({ success: false, error: 'Invalid admin secret' });
    }
  } catch {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});


app.get('/', (req, res) => {
  res.json({ message: 'Team KMZ Gfx System API is running!', version: '1.0.0' });
});

app.get('/admin', (req, res) => res.sendFile(__dirname + '/admin.html'));
app.get('/login', (req, res) => res.sendFile(__dirname + '/login.html'));
app.get('/style.css', (req, res) => res.sendFile(__dirname + '/style.css'));

// Admin-only generate key
app.post('/generateKey', authenticateAdmin, async (req, res) => {
  try {
    const { duration_hours = 720, max_devices = 10, status = 'active' } = req.body;

    if (!duration_hours || duration_hours <= 0) {
      return res.status(400).json({ success: false, error: 'Valid duration_hours is required' });
    }

    // Generate unique key (retry on collision)
    let keyString;
    for (let i = 0; i < 5; i++) {
      keyString = generateKey();
      try {
        const expiresAt = new Date(Date.now() + duration_hours * 60 * 60 * 1000);
        const result = await pool.query(
          `INSERT INTO keys (key_string, duration_hours, max_devices, expires_at, status)
           VALUES ($1, $2, $3, $4, $5) RETURNING *`,
          [keyString, duration_hours, max_devices, expiresAt, status]
        );
        return res.json({
          success: true,
          key: result.rows[0].key_string,
          expires_at: result.rows[0].expires_at,
          duration_hours: result.rows[0].duration_hours,
          max_devices: result.rows[0].max_devices
        });
      } catch (err) {
        if (err.code === '23505') {
          // collision, try again
          continue;
        } else {
          throw err;
        }
      }
    }

    return res.status(500).json({ success: false, error: 'Failed to generate unique key' });
  } catch (err) {
    console.error('Generate key error:', err);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// Activate key
app.post('/activateKey', async (req, res) => {
  try {
    const { key, device_id } = req.body;
    if (!key || !device_id) {
      return res.status(400).json({ success: false, error: 'Key and device_id are required' });
    }
    if (device_id.length < 5 || device_id.length > 255) {
      return res.status(400).json({ success: false, error: 'Invalid device_id format' });
    }

    const keyResult = await pool.query(`SELECT * FROM keys WHERE key_string = $1`, [key.trim().toUpperCase()]);
    if (keyResult.rows.length === 0) return res.status(404).json({ success: false, error: 'Key not found' });

    const keyData = keyResult.rows[0];
    const isExpired = new Date() > new Date(keyData.expires_at);

    if (isExpired) {
      await pool.query(`UPDATE keys SET status = 'expired' WHERE id = $1`, [keyData.id]);
      await logKeyActivity(keyData.id, 'activation_expired', req);
      return res.status(400).json({ success: false, error: 'Key has expired' });
    }

    if (keyData.status !== 'active') {
      return res.status(400).json({ success: false, error: 'Key is not active' });
    }

    const existingActivation = await pool.query(
      `SELECT * FROM key_activations WHERE key_id = $1 AND device_id = $2`,
      [keyData.id, device_id]
    );
    if (existingActivation.rows.length > 0) {
      await logKeyActivity(keyData.id, 'reactivated', req);
      return res.json({
        success: true,
        expires_at: keyData.expires_at,
        duration_hours: keyData.duration_hours,
        message: 'Device already activated'
      });
    }

    const activationCount = await pool.query(`SELECT COUNT(*) FROM key_activations WHERE key_id = $1`, [keyData.id]);
    const currentDevices = parseInt(activationCount.rows[0].count, 10);

    if (currentDevices >= keyData.max_devices) {
      return res.status(400).json({ success: false, error: 'Key has reached maximum device limit' });
    }

    // Insert activation and increment used_devices in a transaction
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(
        `INSERT INTO key_activations (key_id, device_id, ip_address) VALUES ($1, $2, $3)`,
        [keyData.id, device_id, req.ip]
      );
      await client.query(`UPDATE keys SET used_devices = used_devices + 1 WHERE id = $1`, [keyData.id]);
      await client.query('COMMIT');
    } catch (txErr) {
      await client.query('ROLLBACK');
      throw txErr;
    } finally {
      client.release();
    }

    await logKeyActivity(keyData.id, 'activated', req);

    res.json({
      success: true,
      expires_at: keyData.expires_at,
      duration_hours: keyData.duration_hours,
      devices_used: currentDevices + 1,
      max_devices: keyData.max_devices
    });
  } catch (err) {
    console.error('Activate key error:', err);
    if (err.code === '23505') {
      return res.status(409).json({ success: false, error: 'Device already activated with this key' });
    }
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// Verify key
app.post('/verifyKey', async (req, res) => {
  try {
    const { key, device_id } = req.body;
    if (!key || !device_id) {
      return res.status(400).json({ success: false, error: 'Key and device_id are required' });
    }

    const keyResult = await pool.query(`
      SELECT k.*, (ka.device_id IS NOT NULL) AS device_activated
      FROM keys k
      LEFT JOIN key_activations ka ON k.id = ka.key_id AND ka.device_id = $2
      WHERE k.key_string = $1
    `, [key.trim().toUpperCase(), device_id]);

    if (keyResult.rows.length === 0) {
      return res.json({ valid: false, error: 'Key not found' });
    }
    const keyData = keyResult.rows[0];

    const isExpired = new Date() > new Date(keyData.expires_at);
    if (isExpired) {
      await pool.query(`UPDATE keys SET status = 'expired' WHERE id = $1`, [keyData.id]);
      await logKeyActivity(keyData.id, 'auto_expired', req);
      const deviceCount = await pool.query(`SELECT COUNT(*) FROM key_activations WHERE key_id = $1`, [keyData.id]);
      return res.json({
        valid: false,
        expires_at: keyData.expires_at,
        status: 'expired',
        devices_used: parseInt(deviceCount.rows[0].count, 10),
        max_devices: keyData.max_devices,
        message: 'Key has expired'
      });
    }

    const isValid = keyData.status === 'active' && keyData.device_activated === true && !isExpired;

    await logKeyActivity(keyData.id, isValid ? 'verified' : 'verification_failed', req);

    const deviceCount = await pool.query(`SELECT COUNT(*) FROM key_activations WHERE key_id = $1`, [keyData.id]);

    res.json({
      valid: isValid,
      expires_at: keyData.expires_at,
      status: keyData.status,
      devices_used: parseInt(deviceCount.rows[0].count, 10),
      max_devices: keyData.max_devices,
      message: isValid ? 'Key is valid' : 'Key is invalid'
    });
  } catch (err) {
    console.error('Verify key error:', err);
    res.status(500).json({ success: false, valid: false, error: 'Internal server error' });
  }
});

// Admin: list keys
app.get('/admin/keys', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query(`SELECT k.* FROM keys k ORDER BY k.created_at DESC`);
    res.json(result.rows);
  } catch (err) {
    console.error('Get keys error:', err);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// Admin: update key
app.put('/admin/keys/:id', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { duration_hours, status, max_devices } = req.body;

    const updates = [];
    const params = [];
    let idx = 1;

    if (duration_hours !== undefined) {
      updates.push(`duration_hours = $${idx}, expires_at = CURRENT_TIMESTAMP + INTERVAL '1 hour' * $${idx}`);
      params.push(duration_hours);
      idx++;
    }
    if (status !== undefined) {
      updates.push(`status = $${idx}`);
      params.push(status);
      idx++;
    }
    if (max_devices !== undefined) {
      updates.push(`max_devices = $${idx}`);
      params.push(max_devices);
      idx++;
    }

    if (updates.length === 0) return res.status(400).json({ error: 'No fields to update' });

    const query = `UPDATE keys SET ${updates.join(', ')} WHERE id = $${idx} RETURNING *`;
    params.push(id);

    const result = await pool.query(query, params);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Key not found' });

    res.json({ success: true, key: result.rows[0] });
  } catch (err) {
    console.error('Update key error:', err);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// Admin: delete key (transaction)
app.delete('/admin/keys/:id', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('DELETE FROM key_logs WHERE key_id = $1', [id]);
      await client.query('DELETE FROM key_activations WHERE key_id = $1', [id]);
      const result = await client.query('DELETE FROM keys WHERE id = $1 RETURNING *', [id]);
      await client.query('COMMIT');

      if (result.rows.length === 0) return res.status(404).json({ error: 'Key not found' });

      res.json({ success: true, message: 'Key deleted successfully' });
    } catch (txErr) {
      await client.query('ROLLBACK');
      throw txErr;
    } finally {
      client.release();
    }
  } catch (err) {
    console.error('Delete key error:', err);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// Admin: get logs for a key
app.get('/admin/keys/:id/logs', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query(`SELECT * FROM key_logs WHERE key_id = $1 ORDER BY created_at DESC`, [id]);
    res.json(result.rows);
  } catch (err) {
    console.error('Get key logs error:', err);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// Admin: cleanup expired keys (manual)
app.post('/admin/cleanup', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query(`DELETE FROM keys WHERE expires_at < CURRENT_TIMESTAMP RETURNING *`);
    res.json({ success: true, deleted_count: result.rows.length, deleted_keys: result.rows });
  } catch (err) {
    console.error('Cleanup error:', err);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// Health check
app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'healthy', database: 'connected', timestamp: new Date().toISOString() });
  } catch (err) {
    res.status(503).json({ status: 'unhealthy', database: 'disconnected', error: err.message });
  }
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ success: false, error: 'Endpoint not found' });
});

// Generic error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ success: false, error: 'Internal server error' });
});

// Start
(async () => {
  try {
    await initDatabase();
    await updateDatabaseSchema();
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
      console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
    });
  } catch (err) {
    console.error('Failed to initialize database or start server:', err);
    process.exit(1);
  }
})();
