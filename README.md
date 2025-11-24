

# Team KMZ Gfx System - API Documentation
## Table of Contents
1. [Overview](#overview)
2. [API Endpoints](#api-endpoints)
3. [Authentication](#authentication)
4. [Request/Response Examples](#requestresponse-examples)
5. [Database Schema](#database-schema)
6. [Setup & Deployment](#setup--deployment)
7. [Error Handling](#error-handling)
8. [Security](#security)

## Overview

The Team KMZ Gfx System is a secure key management API for software licensing and activation. It provides endpoints for generating, activating, and verifying license keys with device-based activation limits.

### Base URL
```
https://kmz-gfx.onrender.com
```

### Response Format
All responses are in JSON format.

## API Endpoints

### Public Endpoints

#### 1. Activate Key
**POST** `/activateKey`

Activates a license key for a specific device.

**Request Body:**
```json
{
  "key": "ABCDE-FGHIJ-KLMNO-PQRST-UWXYZ",
  "device_id": "device_unique_identifier_123"
}
```

**Response:**
```json
{
  "success": true,
  "expires_at": "2024-12-31T23:59:59.000Z",
  "duration_hours": 720,
  "devices_used": 1,
  "max_devices": 10
}
```

**Error Responses:**
- `400` - Missing required fields or invalid input
- `404` - Key not found
- `400` - Key expired, inactive, or reached device limit
- `409` - Device already activated
- `500` - Internal server error

#### 2. Verify Key
**POST** `/verifyKey`

Verifies if a key is valid for a specific device.

**Request Body:**
```json
{
  "key": "ABCDE-FGHIJ-KLMNO-PQRST-UWXYZ",
  "device_id": "device_unique_identifier_123"
}
```

**Response:**
```json
{
  "valid": true,
  "expires_at": "2024-12-31T23:59:59.000Z",
  "status": "active",
  "devices_used": 1,
  "max_devices": 10,
  "message": "Key is valid"
}
```

**Error Responses:**
- `400` - Missing required fields
- `500` - Internal server error

#### 3. Health Check
**GET** `/health`

Checks API and database status.

**Response:**
```json
{
  "status": "healthy",
  "database": "connected",
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

### Admin Endpoints (Require Authentication)

All admin endpoints require the `admin-secret` header or `admin_secret` in the request body.

#### 1. Generate Key
**POST** `/generateKey`

Generates a new license key.

**Headers:**
```
admin-secret: your_admin_secret_here
```

**Request Body:**
```json
{
  "duration_hours": 720,
  "max_devices": 10,
  "status": "active"
}
```

**Parameters:**
- `duration_hours` (optional): Key validity in hours (default: 720 = 30 days)
- `max_devices` (optional): Maximum devices allowed (default: 10)
- `status` (optional): Key status - "active" or "inactive" (default: "active")

**Response:**
```json
{
  "success": true,
  "key": "ABCDE-FGHIJ-KLMNO-PQRST-UWXYZ",
  "expires_at": "2024-12-31T23:59:59.000Z",
  "duration_hours": 720,
  "max_devices": 10
}
```

#### 2. Get All Keys
**GET** `/admin/keys`

Retrieves all keys with activation counts.

**Headers:**
```
admin-secret: your_admin_secret_here
```

**Response:**
```json
[
  {
    "id": 1,
    "key_string": "ABCDE-FGHIJ-KLMNO-PQRST-UWXYZ",
    "duration_hours": 720,
    "max_devices": 10,
    "used_devices": 0,
    "created_at": "2024-01-15T10:00:00.000Z",
    "expires_at": "2024-12-31T23:59:59.000Z",
    "status": "active",
    "activated_devices": 1
  }
]
```

#### 3. Update Key
**PUT** `/admin/keys/:id`

Updates a specific key's properties.

**Headers:**
```
admin-secret: your_admin_secret_here
```

**Request Body:**
```json
{
  "duration_hours": 1440,
  "max_devices": 5,
  "status": "active"
}
```

**Response:**
```json
{
  "success": true,
  "key": {
    "id": 1,
    "key_string": "ABCDE-FGHIJ-KLMNO-PQRST-UWXYZ",
    "duration_hours": 1440,
    "max_devices": 5,
    "status": "active"
  }
}
```

#### 4. Delete Key
**DELETE** `/admin/keys/:id`

Deletes a key and all associated data.

**Headers:**
```
admin-secret: your_admin_secret_here
```

**Response:**
```json
{
  "success": true,
  "message": "Key deleted successfully"
}
```

#### 5. Get Key Logs
**GET** `/admin/keys/:id/logs`

Retrieves activity logs for a specific key.

**Headers:**
```
admin-secret: your_admin_secret_here
```

**Response:**
```json
[
  {
    "id": 1,
    "key_id": 1,
    "action": "activated",
    "ip_address": "192.168.1.100",
    "user_agent": "Mozilla/5.0...",
    "created_at": "2024-01-15T10:30:00.000Z"
  }
]
```

#### 6. Cleanup Expired Keys
**POST** `/admin/cleanup`

Deletes all expired keys.

**Headers:**
```
admin-secret: your_admin_secret_here
```

**Response:**
```json
{
  "success": true,
  "deleted_count": 5,
  "deleted_keys": [
    {
      "id": 2,
      "key_string": "EXPIRED-KEY-EXAMPLE-12345",
      "expires_at": "2024-01-01T00:00:00.000Z"
    }
  ]
}
```

### Static Pages

#### 1. Admin Panel
**GET** `/admin`

Serves the admin interface HTML page.

#### 2. Login Page
**GET** `/login`

Serves the login HTML page.

#### 3. CSS File
**GET** `/style.css`

Serves the stylesheet.

## Authentication

### Admin Authentication
Admin endpoints use a shared secret authentication method:

**Method 1:** Header-based
```http
POST /admin/keys
admin-secret: your_hashed_admin_secret_here
```

**Method 2:** Body-based
```json
{
  "admin_secret": "your_hashed_admin_secret_here",
  "other_data": "value"
}
```

### Setting up Admin Secret

1. Generate a secure secret
2. Hash it using bcrypt:
```javascript
const bcrypt = require('bcryptjs');
const hashedSecret = bcrypt.hashSync('your_plain_secret', 10);
```

3. Set in environment variables:
```env
ADMIN_SECRET_HASH=your_hashed_secret_here
```

## Database Schema

### Tables

#### 1. keys
Stores license key information.

| Column | Type | Description |
|--------|------|-------------|
| id | SERIAL PRIMARY KEY | Unique identifier |
| key_string | VARCHAR(255) UNIQUE | License key string |
| duration_hours | INTEGER | Validity duration in hours |
| max_devices | INTEGER | Maximum allowed devices |
| used_devices | INTEGER | Currently used devices |
| created_at | TIMESTAMP | Creation timestamp |
| expires_at | TIMESTAMP | Expiration timestamp |
| status | VARCHAR(20) | Key status ('active', 'inactive') |

#### 2. key_activations
Tracks device activations.

| Column | Type | Description |
|--------|------|-------------|
| id | SERIAL PRIMARY KEY | Unique identifier |
| key_id | INTEGER REFERENCES keys(id) | Foreign key to keys table |
| device_id | TEXT | Unique device identifier |
| activated_at | TIMESTAMP | Activation timestamp |
| ip_address | TEXT | IP address at activation |

#### 3. key_logs
Logs all key-related activities.

| Column | Type | Description |
|--------|------|-------------|
| id | SERIAL PRIMARY KEY | Unique identifier |
| key_id | INTEGER REFERENCES keys(id) | Foreign key to keys table |
| action | VARCHAR(50) | Action performed |
| ip_address | TEXT | IP address |
| user_agent | TEXT | User agent string |
| created_at | TIMESTAMP | Log timestamp |

## Setup & Deployment

### Prerequisites
- Node.js 16+
- PostgreSQL 12+
- Environment variables configured

### Installation

1. **Clone and install dependencies:**
```bash
npm install express pg bcryptjs express-rate-limit helmet dotenv
```

2. **Environment Configuration (.env):**
```env
DATABASE_URL=postgresql://username:password@localhost:5432/kmz_gfx_system
ADMIN_SECRET_HASH=$2a$10$your_bcrypt_hashed_secret_here
NODE_ENV=production
PORT=3000
```

3. **Database Setup:**
The system automatically creates required tables on startup.

4. **Start Server:**
```bash
node server.js
```

### Production Deployment

#### Using PM2
```bash
npm install -g pm2
pm2 start server.js --name "kmz-gfx-api"
pm2 startup
pm2 save
```

#### Docker Deployment
```dockerfile
FROM node:16-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --production
COPY . .
EXPOSE 3000
CMD ["node", "server.js"]
```

## Error Handling

### Common HTTP Status Codes

- `200` - Success
- `400` - Bad Request (invalid input)
- `401` - Unauthorized (admin authentication failed)
- `404` - Not Found (resource not found)
- `409` - Conflict (duplicate activation)
- `500` - Internal Server Error

### Error Response Format
```json
{
  "error": "Descriptive error message",
  "details": "Additional context if available"
}
```

## Security Features

### 1. Rate Limiting
- 100 requests per 15 minutes per IP
- Protects against brute force attacks

### 2. Helmet.js Security Headers
- Sets security-related HTTP headers
- Prevents common web vulnerabilities

### 3. Input Validation
- Key format validation
- Device ID length checks
- SQL injection prevention

### 4. Database Security
- Parameterized queries
- SSL connections in production
- Proper connection pooling

### 5. Admin Authentication
- BCrypt hashed secrets
- Header or body authentication options

## Key Generation Format

Keys are generated in the format: `XXXXX-XXXXX-XXXXX-XXXXX-XXXXX`
- 25 characters total
- 5 groups of 5 characters
- Uppercase letters and numbers only
- No ambiguous characters (0, O, 1, I, L)

## Usage Examples

### Client Integration Example

```javascript
class KMZLicenseClient {
  constructor(baseUrl, deviceId) {
    this.baseUrl = baseUrl;
    this.deviceId = deviceId;
  }

  async activateLicense(key) {
    const response = await fetch(`${this.baseUrl}/activateKey`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        key: key,
        device_id: this.deviceId
      })
    });
    
    return await response.json();
  }

  async verifyLicense(key) {
    const response = await fetch(`${this.baseUrl}/verifyKey`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        key: key,
        device_id: this.deviceId
      })
    });
    
    return await response.json();
  }
}

// Usage
const client = new KMZLicenseClient('https://api.yourdomain.com', 'user-device-123');
const result = await client.activateLicense('ABCDE-FGHIJ-KLMNO-PQRST-UWXYZ');
```

### Admin Panel Integration

```javascript
class KMZAdminClient {
  constructor(baseUrl, adminSecret) {
    this.baseUrl = baseUrl;
    this.adminSecret = adminSecret;
  }

  async generateKey(options = {}) {
    const response = await fetch(`${this.baseUrl}/generateKey`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'admin-secret': this.adminSecret
      },
      body: JSON.stringify(options)
    });
    
    return await response.json();
  }

  async getAllKeys() {
    const response = await fetch(`${this.baseUrl}/admin/keys`, {
      headers: { 'admin-secret': this.adminSecret }
    });
    
    return await response.json();
  }
}
```

## Monitoring and Maintenance

### Regular Tasks

1. **Monitor logs** for suspicious activities
2. **Run cleanup** periodically for expired keys
3. **Backup database** regularly
4. **Update dependencies** for security patches

### Performance Tips

1. **Database indexing:**
```sql
CREATE INDEX idx_keys_key_string ON keys(key_string);
CREATE INDEX idx_keys_expires_at ON keys(expires_at);
CREATE INDEX idx_activations_key_device ON key_activations(key_id, device_id);
```

2. **Connection pooling** is handled automatically
3. **Rate limiting** prevents abuse

## Troubleshooting

### Common Issues

1. **Database connection errors**
   - Check DATABASE_URL environment variable
   - Verify PostgreSQL is running
   - Ensure SSL configuration for production

2. **Admin authentication failures**
   - Verify ADMIN_SECRET_HASH is set
   - Check bcrypt hash format
   - Ensure secret is sent correctly

3. **Key activation issues**
   - Verify key exists and is active
   - Check expiration date
   - Confirm device limit not reached

### Logs
Check server logs for detailed error information and activity tracking.

## Support

For technical support or issues:
1. Check server logs for error details
2. Verify environment configuration
3. Ensure database connectivity
4. Review API documentation for correct usage

---

**Version:** 1.0.0  
**Last Updated:** January 2024  
**Maintainer:** Team KMZ Gfx System
