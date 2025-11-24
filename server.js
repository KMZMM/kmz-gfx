const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
//app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Enhanced rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false
});
app.use(limiter);

// Database connection with SSL for production
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Admin authentication middleware
const authenticateAdmin = (req, res, next) => {
  const adminSecret = req.headers['admin-secret'] || req.body.admin_secret;
  
  if (!adminSecret) {
    return res.status(401).json({ error: 'Admin secret required' });
  }
  
  // Compare with hashed secret from environment
  if (bcrypt.compareSync(adminSecret, process.env.ADMIN_SECRET_HASH)) {
    next();
  } else {
    res.status(401).json({ error: 'Invalid admin secret' });
  }
};

// Initialize database tables
const initDatabase = async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS keys (
        id SERIAL PRIMARY KEY,
        key_string VARCHAR(255) UNIQUE NOT NULL,
        duration_hours INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP,
        status VARCHAR(20) DEFAULT 'active',
        used BOOLEAN DEFAULT false,
        owner_device_id TEXT,
        ip_address TEXT,
        last_verified TIMESTAMP
      )
    `);
    
    await pool.query(`
      CREATE TABLE IF NOT EXISTS key_logs (
        id SERIAL PRIMARY KEY,
        key_id INTEGER REFERENCES keys(id),
        action VARCHAR(50) NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('Database tables initialized');
  } catch (err) {
    console.error('Database initialization error:', err);
  }
};

// Utility function to generate random keys
const generateKey = () => {
  return Buffer.from(Math.random().toString(36).substring(2, 15) + 
         Math.random().toString(36).substring(2, 15)).toString('base64').replace(/[^a-zA-Z0-9]/g, '').substring(0, 16).toUpperCase();
};

// Log key activity
const logKeyActivity = async (keyId, action, req) => {
  try {
    await pool.query(
      'INSERT INTO key_logs (key_id, action, ip_address, user_agent) VALUES ($1, $2, $3, $4)',
      [keyId, action, req.ip, req.get('User-Agent')]
    );
  } catch (err) {
    console.error('Logging error:', err);
  }
};

// API Endpoints

// Generate new key (Admin only)
app.post('/generateKey', authenticateAdmin, async (req, res) => {
  try {
    const { duration_hours = 720, status = 'active' } = req.body; // Default 30 days
    
    const keyString = generateKey();
    const expiresAt = new Date(Date.now() + duration_hours * 60 * 60 * 1000);
    
    const result = await pool.query(
      `INSERT INTO keys (key_string, duration_hours, expires_at, status) 
       VALUES ($1, $2, $3, $4) RETURNING key_string, expires_at, duration_hours`,
      [keyString, duration_hours, expiresAt, status]
    );
    
    res.json({
      success: true,
      key: result.rows[0].key_string,
      expires_at: result.rows[0].expires_at,
      duration_hours: result.rows[0].duration_hours
    });
  } catch (err) {
    console.error('Generate key error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Serve admin page from ROOT folder
app.get('/admin', (req, res) => {
  res.sendFile(__dirname + '/admin.html');
});

app.get('/login', (req, res) => {
  res.sendFile(__dirname + '/login.html');
});

// Serve CSS file from root
app.get('/style.css', (req, res) => {
  res.sendFile(__dirname + '/style.css');
});

app.get('/', (req, res) => {
  res.json({ 
    message: 'Key System API is running!',
    admin_panel: '/admin'
  });
});

// Activate key (User endpoint)
app.post('/activateKey', async (req, res) => {
  try {
    const { key, device_id } = req.body;
    
    if (!key || !device_id) {
      return res.status(400).json({ error: 'Key and device_id are required' });
    }
    
    const keyResult = await pool.query(
      `SELECT * FROM keys WHERE key_string = $1`,
      [key]
    );
    
    if (keyResult.rows.length === 0) {
      return res.status(404).json({ error: 'Key not found' });
    }
    
    const keyData = keyResult.rows[0];
    
    // Check if key is active
    if (keyData.status !== 'active') {
      return res.status(400).json({ error: 'Key is not active' });
    }
    
    // Check if key is expired
    if (new Date() > new Date(keyData.expires_at)) {
      return res.status(400).json({ error: 'Key has expired' });
    }
    
    // Check if key is already used by different device
    if (keyData.used && keyData.owner_device_id !== device_id) {
      return res.status(400).json({ error: 'Key already used by another device' });
    }
    
    // Activate key for this device
    if (!keyData.used) {
      await pool.query(
        `UPDATE keys SET used = true, owner_device_id = $1, ip_address = $2 WHERE id = $3`,
        [device_id, req.ip, keyData.id]
      );
      
      await logKeyActivity(keyData.id, 'activated', req);
    } else {
      await logKeyActivity(keyData.id, 'verified_activation', req);
    }
    
    res.json({
      success: true,
      expires_at: keyData.expires_at,
      duration_hours: keyData.duration_hours
    });
    
  } catch (err) {
    console.error('Activate key error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Verify key (Automatic validation)
app.post('/verifyKey', async (req, res) => {
  try {
    const { key, device_id } = req.body;
    
    if (!key || !device_id) {
      return res.status(400).json({ error: 'Key and device_id are required' });
    }
    
    const keyResult = await pool.query(
      `SELECT * FROM keys WHERE key_string = $1`,
      [key]
    );
    
    if (keyResult.rows.length === 0) {
      return res.json({ valid: false, error: 'Key not found' });
    }
    
    const keyData = keyResult.rows[0];
    
    // Update last verified timestamp
    await pool.query(
      `UPDATE keys SET last_verified = CURRENT_TIMESTAMP WHERE id = $1`,
      [keyData.id]
    );
    
    // Check all validation conditions
    const isValid = keyData.status === 'active' && 
                   keyData.used === true && 
                   keyData.owner_device_id === device_id && 
                   new Date() < new Date(keyData.expires_at);
    
    if (isValid) {
      await logKeyActivity(keyData.id, 'verified', req);
    } else {
      await logKeyActivity(keyData.id, 'verification_failed', req);
    }
    
    res.json({
      valid: isValid,
      expires_at: keyData.expires_at,
      status: keyData.status
    });
    
  } catch (err) {
    console.error('Verify key error:', err);
    res.status(500).json({ valid: false, error: 'Internal server error' });
  }
});

// Admin endpoints
app.get('/admin/getKeys', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM keys ORDER BY created_at DESC`
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Get keys error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/admin/updateKey', authenticateAdmin, async (req, res) => {
  try {
    const { key_id, duration_hours, status } = req.body;
    
    let query = 'UPDATE keys SET ';
    const params = [];
    let paramCount = 1;
    
    if (duration_hours !== undefined) {
      query += `duration_hours = $${paramCount}, expires_at = CURRENT_TIMESTAMP + INTERVAL '1 hour' * $${paramCount} `;
      params.push(duration_hours);
      paramCount++;
    }
    
    if (status !== undefined) {
      if (paramCount > 1) query += ', ';
      query += `status = $${paramCount} `;
      params.push(status);
      paramCount++;
    }
    
    query += `WHERE id = $${paramCount} RETURNING *`;
    params.push(key_id);
    
    const result = await pool.query(query, params);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Key not found' });
    }
    
    res.json({ success: true, key: result.rows[0] });
  } catch (err) {
    console.error('Update key error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/admin/deleteKey', authenticateAdmin, async (req, res) => {
  try {
    const { key_id } = req.body;
    
    await pool.query('DELETE FROM key_logs WHERE key_id = $1', [key_id]);
    const result = await pool.query('DELETE FROM keys WHERE id = $1 RETURNING *', [key_id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Key not found' });
    }
    
    res.json({ success: true });
  } catch (err) {
    console.error('Delete key error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Cleanup expired keys (can be called via cron)
app.post('/admin/cleanup', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `DELETE FROM keys WHERE expires_at < CURRENT_TIMESTAMP RETURNING *`
    );
    
    res.json({ 
      success: true, 
      deleted_count: result.rows.length,
      deleted_keys: result.rows 
    });
  } catch (err) {
    console.error('Cleanup error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Initialize database and start server
initDatabase().then(() => {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
});
