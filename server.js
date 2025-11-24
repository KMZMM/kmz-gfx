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
app.use(helmet({
  contentSecurityPolicy: false, // Adjust based on your needs
}));
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Enhanced rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
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

// Utility functions
const generateKey = () => {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let key = '';
  for (let i = 0; i < 25; i++) {
    if (i > 0 && i % 5 === 0) key += '-';
    key += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return key;
};

const logKeyActivity = async (keyId, action, req) => {
  try {
    await pool.query(
      `INSERT INTO key_logs (key_id, action, ip_address, user_agent) 
       VALUES ($1, $2, $3, $4)`,
      [keyId, action, req.ip, req.get('User-Agent')]
    );
  } catch (err) {
    console.error('Log activity error:', err);
  }
};


// Admin authentication middleware
// DEBUGGED Admin authentication middleware
const authenticateAdmin = (req, res, next) => {
  try {
    const adminSecret = req.headers['admin-secret'] || req.body.admin_secret;
    
    console.log('🔐 Admin auth attempt');
    console.log('Secret provided:', adminSecret ? 'Yes' : 'No');
    console.log('Hash exists:', process.env.ADMIN_SECRET_HASH ? 'Yes' : 'No');
    
    if (!adminSecret) {
      console.log('❌ No admin secret provided');
      return res.status(401).json({ error: 'Admin secret required' });
    }
    
    if (!process.env.ADMIN_SECRET_HASH) {
      console.error('❌ ADMIN_SECRET_HASH environment variable is not set');
      return res.status(500).json({ 
        error: 'Server configuration error' 
      });
    }
    
    // Add detailed bcrypt debugging
    console.log('Hash length:', process.env.ADMIN_SECRET_HASH.length);
    console.log('Hash prefix:', process.env.ADMIN_SECRET_HASH.substring(0, 10));
    
    // Use async bcrypt comparison to avoid blocking
    bcrypt.compare(adminSecret, process.env.ADMIN_SECRET_HASH, (err, result) => {
      if (err) {
        console.error('💥 Bcrypt comparison error:', err);
        return res.status(500).json({ 
          error: 'Authentication error',
          details: process.env.NODE_ENV === 'development' ? err.message : undefined
        });
      }
      
      if (result) {
        console.log('✅ Admin authentication successful');
        next();
      } else {
        console.log('❌ Admin authentication failed - Invalid secret');
        res.status(401).json({ error: 'Invalid admin secret' });
      }
    });
    
  } catch (err) {
    console.error('💥 Auth middleware error:', err);
    res.status(500).json({ 
      error: 'Authentication server error',
      details: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
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
        max_devices INTEGER DEFAULT 1,
        used_devices INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP,
        status VARCHAR(20) DEFAULT 'active'
      )
    `);
    
    await pool.query(`
      CREATE TABLE IF NOT EXISTS key_activations (
        id SERIAL PRIMARY KEY,
        key_id INTEGER REFERENCES keys(id),
        device_id TEXT NOT NULL,
        activated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        ip_address TEXT,
        UNIQUE(key_id, device_id)
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
    
    // Update existing tables with new columns
    await updateDatabaseSchema();
    
  } catch (err) {
    console.error('Database initialization error:', err);
  }
};

// Add this function after your initDatabase function
const updateDatabaseSchema = async () => {
  try {
    // Check if max_devices column exists
    const checkResult = await pool.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = 'keys' AND column_name = 'max_devices'
    `);
    
    if (checkResult.rows.length === 0) {
      console.log('🔄 Adding max_devices column to keys table...');
      await pool.query(`
        ALTER TABLE keys ADD COLUMN max_devices INTEGER DEFAULT 1
      `);
      console.log('✅ Added max_devices column successfully');
    } else {
      console.log('✅ max_devices column already exists');
    }
    
    // Also check for used_devices column
    const checkUsedDevices = await pool.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = 'keys' AND column_name = 'used_devices'
    `);
    
    if (checkUsedDevices.rows.length === 0) {
      console.log('🔄 Adding used_devices column to keys table...');
      await pool.query(`
        ALTER TABLE keys ADD COLUMN used_devices INTEGER DEFAULT 0
      `);
      console.log('✅ Added used_devices column successfully');
    } else {
      console.log('✅ used_devices column already exists');
    }
    
  } catch (err) {
    console.error('Database schema update error:', err);
  }
};


// API Endpoints

// Root endpoint
app.get('/', (req, res) => {
  res.json({ 
    message: 'Team KMZ Gfx System API is running!',
    version: '1.0.0'
  });
});

// Serve static files
app.get('/admin', (req, res) => {
  res.sendFile(__dirname + '/admin.html');
});

app.get('/login', (req, res) => {
  res.sendFile(__dirname + '/login.html');
});

app.get('/style.css', (req, res) => {
  res.sendFile(__dirname + '/style.css');
});

// Generate new key (Admin only) - SINGLE ENDPOINT
app.post('/generateKey', authenticateAdmin, async (req, res) => {
  try {
    const { duration_hours = 720, max_devices = 10, status = 'active' } = req.body;
    
    if (!duration_hours || duration_hours <= 0) {
      return res.status(400).json({ error: 'Valid duration_hours is required' });
    }
    
    const keyString = generateKey();
    const expiresAt = new Date(Date.now() + duration_hours * 60 * 60 * 1000);
    
    const result = await pool.query(
      `INSERT INTO keys (key_string, duration_hours, max_devices, expires_at, status) 
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [keyString, duration_hours, max_devices, expiresAt, status]
    );
    
    res.json({
      success: true,
      key: result.rows[0].key_string,
      expires_at: result.rows[0].expires_at,
      duration_hours: result.rows[0].duration_hours,
      max_devices: result.rows[0].max_devices
    });
  } catch (err) {
    console.error('Generate key error:', err);
    if (err.code === '23505') { // Unique violation
      return res.status(409).json({ error: 'Key already exists, please try again' });
    }
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Activate key (User endpoint)
app.post('/activateKey', async (req, res) => {
  try {
    const { key, device_id } = req.body;
    
    if (!key || !device_id) {
      return res.status(400).json({ error: 'Key and device_id are required' });
    }
    
    // Validate device_id format (basic validation)
    if (device_id.length < 5 || device_id.length > 255) {
      return res.status(400).json({ error: 'Invalid device_id format' });
    }
    
    const keyResult = await pool.query(
      `SELECT * FROM keys WHERE key_string = $1`,
      [key.trim().toUpperCase()]
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
    
    // Check if device is already activated
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
    
    // Check if key has reached device limit
    const activationCount = await pool.query(
      `SELECT COUNT(*) FROM key_activations WHERE key_id = $1`,
      [keyData.id]
    );
    
    const currentDevices = parseInt(activationCount.rows[0].count);
    
    if (currentDevices >= keyData.max_devices) {
      return res.status(400).json({ error: 'Key has reached maximum device limit' });
    }
    
    // Activate key for this device
    await pool.query(
      `INSERT INTO key_activations (key_id, device_id, ip_address) VALUES ($1, $2, $3)`,
      [keyData.id, device_id, req.ip]
    );
    
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
    if (err.code === '23505') { // Unique constraint violation
      return res.status(409).json({ error: 'Device already activated with this key' });
    }
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
    
    const keyResult = await pool.query(`
      SELECT k.*, ka.device_id IS NOT NULL as device_activated
      FROM keys k
      LEFT JOIN key_activations ka ON k.id = ka.key_id AND ka.device_id = $2
      WHERE k.key_string = $1
    `, [key.trim().toUpperCase(), device_id]);
    
    if (keyResult.rows.length === 0) {
      return res.json({ valid: false, error: 'Key not found' });
    }
    
    const keyData = keyResult.rows[0];
    
    // Check all validation conditions
    const isValid = keyData.status === 'active' && 
                   keyData.device_activated === true && 
                   new Date() < new Date(keyData.expires_at);
    
    if (isValid) {
      await logKeyActivity(keyData.id, 'verified', req);
    } else {
      await logKeyActivity(keyData.id, 'verification_failed', req);
    }
    
    // Get current device count
    const deviceCount = await pool.query(
      `SELECT COUNT(*) FROM key_activations WHERE key_id = $1`,
      [keyData.id]
    );
    
    res.json({
      valid: isValid,
      expires_at: keyData.expires_at,
      status: keyData.status,
      devices_used: parseInt(deviceCount.rows[0].count),
      max_devices: keyData.max_devices,
      message: isValid ? 'Key is valid' : 'Key is invalid'
    });
    
  } catch (err) {
    console.error('Verify key error:', err);
    res.status(500).json({ valid: false, error: 'Internal server error' });
  }
});

// Admin endpoints
app.get('/admin/keys', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT k.*, 
             COUNT(ka.id) as activated_devices
      FROM keys k
      LEFT JOIN key_activations ka ON k.id = ka.key_id
      GROUP BY k.id
      ORDER BY k.created_at DESC
    `);
    res.json(result.rows);
  } catch (err) {
    console.error('Get keys error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/admin/keys/:id', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { duration_hours, status, max_devices } = req.body;
    
    let query = 'UPDATE keys SET ';
    const params = [];
    let paramCount = 1;
    const updates = [];
    
    if (duration_hours !== undefined) {
      updates.push(`duration_hours = $${paramCount}, expires_at = CURRENT_TIMESTAMP + INTERVAL '1 hour' * $${paramCount}`);
      params.push(duration_hours);
      paramCount++;
    }
    
    if (status !== undefined) {
      updates.push(`status = $${paramCount}`);
      params.push(status);
      paramCount++;
    }
    
    if (max_devices !== undefined) {
      updates.push(`max_devices = $${paramCount}`);
      params.push(max_devices);
      paramCount++;
    }
    
    if (updates.length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
    }
    
    query += updates.join(', ') + ` WHERE id = $${paramCount} RETURNING *`;
    params.push(id);
    
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

app.delete('/admin/keys/:id', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Use transaction to ensure data consistency
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      
      await client.query('DELETE FROM key_logs WHERE key_id = $1', [id]);
      await client.query('DELETE FROM key_activations WHERE key_id = $1', [id]);
      const result = await client.query('DELETE FROM keys WHERE id = $1 RETURNING *', [id]);
      
      await client.query('COMMIT');
      
      if (result.rows.length === 0) {
        return res.status(404).json({ error: 'Key not found' });
      }
      
      res.json({ success: true, message: 'Key deleted successfully' });
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  } catch (err) {
    console.error('Delete key error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get key logs (Admin only)
app.get('/admin/keys/:id/logs', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    
    const result = await pool.query(
      `SELECT * FROM key_logs WHERE key_id = $1 ORDER BY created_at DESC`,
      [id]
    );
    
    res.json(result.rows);
  } catch (err) {
    console.error('Get key logs error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Cleanup expired keys
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

// Health check endpoint
app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ 
      status: 'healthy', 
      database: 'connected',
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    res.status(503).json({ 
      status: 'unhealthy', 
      database: 'disconnected',
      error: err.message 
    });
  }
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Initialize database and start server
initDatabase().then(() => {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  });
}).catch(err => {
  console.error('Failed to initialize database:', err);
  process.exit(1);
});
