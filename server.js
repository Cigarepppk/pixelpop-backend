
// server.js
/*require('dotenv').config(); // Loads: MONGODB_URI, MONGODB_DB, JWT_SECRET, PUBLIC_BASE_URL, PORT, CORS_ORIGINS

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const { GridFSBucket, ObjectId } = require('mongodb');

const app = express();

// ─────────────────────────────────────────────────────────────
// Config
// ─────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 5000;

// Honor HTTPS behind proxies (Render/NGINX)
app.set('trust proxy', true);

// CORS: allow your frontend + local dev (edit CORS_ORIGINS env if needed)
const DEFAULT_ORIGINS = [
  'http://localhost:3000',
  'https://pixelpop-server.onrender.com', // your frontend on Render
];
const CORS_ORIGINS = (process.env.CORS_ORIGINS || DEFAULT_ORIGINS.join(','))
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

app.use(cors({ origin: CORS_ORIGINS, credentials: false }));

// JSON body limit (allow big data URLs from canvas)
app.use(express.json({ limit: '15mb' }));

// Optionally serve static files (if you put a frontend in /public for local dev)
const publicDir = path.join(__dirname, 'public');
app.use(express.static(publicDir));

// ─────────────────────────────────────────────────────────────
// Mongo / Mongoose init
// ─────────────────────────────────────────────────────────────
if (!process.env.MONGODB_URI) {
  console.error('❌ Missing MONGODB_URI in environment.');
  process.exit(1);
}

mongoose
  .connect(process.env.MONGODB_URI, {
    dbName: process.env.MONGODB_DB || 'pixelpop', // ensure correct DB (not "test")
  })
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch((err) => {
    console.error('❌ Could not connect to MongoDB:', err);
    process.exit(1);
  });

// Create GridFS bucket once native connection is open
let gridfsBucket = null;
mongoose.connection.once('open', () => {
  gridfsBucket = new GridFSBucket(mongoose.connection.db, { bucketName: 'photos' });
  console.log('✅ GridFS bucket "photos" ready');
});

// Build absolute base URL (prefer PUBLIC_BASE_URL in prod)
function getBaseUrl(req) {
  if (process.env.PUBLIC_BASE_URL) return process.env.PUBLIC_BASE_URL;
  const proto = req.headers['x-forwarded-proto'] || req.protocol || 'https';
  const host = req.get('host');
  return `${proto}://${host}`;
}

// ─────────────────────────────────────────────────────────────
// Auth — User model & endpoints
// ─────────────────────────────────────────────────────────────
const UserSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  email:    { type: String, unique: true, required: true },
  password: { type: String, required: true },
});
const User = mongoose.model('User', UserSchema);

function authMiddleware(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'No token provided' });

  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Invalid token' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret123'); // set JWT_SECRET in prod
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// Health & root
app.get('/health', (_req, res) => res.json({ ok: true }));
app.get('/', (_req, res) => res.send('Backend server is running!'));

// Signup
app.post('/signup', async (req, res) => {
  try {
    const { username, email, password } = req.body || {};
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Username, email, and password are required.' });
    }
    const hashed = await bcrypt.hash(password, 10);
    const user = new User({ username, email, password: hashed });
    await user.save();
    res.status(201).json({ message: 'User registered successfully!' });
  } catch (err) {
    if (err.code === 11000) {
      const field = Object.keys(err.keyPattern)[0];
      const message = field === 'username' ? 'Username already exists.' : 'Email already exists.';
      return res.status(409).json({ error: message });
    }
    console.error(err);
    res.status(500).json({ error: 'An error occurred during registration.' });
  }
});

// Login
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required.' });
    }
    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ error: 'Invalid username or password' });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ error: 'Invalid username or password' });

    const token = jwt.sign(
      { id: user._id, username: user.username },
      process.env.JWT_SECRET || 'secret123',
      { expiresIn: '1h' }
    );
    res.json({ message: 'Login successful', token, username: user.username });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'An error occurred during login.' });
  }
});

// Example protected routes
app.get('/api/auth/verify', authMiddleware, (req, res) => {
  res.json({ ok: true, user: req.user });
});

app.get('/api/photobooth', authMiddleware, (req, res) => {
  res.json({ message: 'Welcome to Photobooth', user: req.user });
});

// ─────────────────────────────────────────────────────────────
// Image Uploads via GridFS
// ─────────────────────────────────────────────────────────────

// POST /api/upload
// Body: { imageData: "data:image/jpeg;base64,...", fileName?: "name.jpg" }
// Returns: { success: true, url, downloadUrl, viewerUrl, id, contentType }
app.post('/api/upload', async (req, res) => {
  try {
    if (!gridfsBucket) return res.status(503).json({ error: 'Storage not ready' });

    const { imageData, fileName = `pixelpop-photo-${Date.now()}.jpg` } = req.body || {};
    if (!imageData || typeof imageData !== 'string' || !imageData.startsWith('data:')) {
      return res.status(400).json({ error: 'imageData must be a data URL string' });
    }

    // Parse "data:image/jpeg;base64,...."
    const [meta, base64] = imageData.split(',');
    const m = /^data:(.*?);base64$/i.exec(meta);
    const contentType = (m && m[1]) || 'image/jpeg';
    const buffer = Buffer.from(base64, 'base64');

    if (buffer.length > 15 * 1024 * 1024) {
      return res.status(413).json({ error: 'Image too large (max 15MB)' });
    }

    const uploadStream = gridfsBucket.openUploadStream(fileName, {
      contentType,
      metadata: { contentType, source: 'pixelpop', createdAt: new Date() },
    });

    uploadStream.on('error', (err) => {
      console.error('GridFS upload error:', err);
      return res.status(500).json({ error: 'Upload failed' });
    });

    uploadStream.on('finish', () => {
      const id = uploadStream.id.toString();
      const base = getBaseUrl(req);
      const url         = `${base}/i/${id}`; // raw image
      const downloadUrl = `${base}/d/${id}`; // force download
      const viewerUrl   = `${base}/v/${id}`; // landing page with big Download button
      return res.json({ success: true, url, downloadUrl, viewerUrl, id, contentType });
    });

    uploadStream.end(buffer);
  } catch (e) {
    console.error('Upload route error:', e);
    return res.status(500).json({ error: 'Server error' });
  }
});

// GET /i/:id → stream the image by id
app.get('/i/:id', async (req, res) => {
  try {
    if (!gridfsBucket) return res.status(503).send('Storage not ready');
    const id = new ObjectId(req.params.id);

    // Get file doc to set headers
    const filesCol = mongoose.connection.db.collection('photos.files');
    const doc = await filesCol.findOne({ _id: id });
    if (!doc) return res.status(404).send('Not found');

    const type = doc.contentType || doc.metadata?.contentType || 'image/jpeg';
    res.set('Content-Type', type);
    res.set('Cache-Control', 'public, max-age=31536000, immutable');

    const dl = gridfsBucket.openDownloadStream(id);
    dl.on('error', () => res.status(404).end('Not found'));
    dl.pipe(res);
  } catch {
    return res.status(400).send('Bad id');
  }
});

// HEAD /i/:id → quick reachability check (optional for frontend verification)
app.head('/i/:id', async (req, res) => {
  try {
    if (!gridfsBucket) return res.status(503).end();
    const id = new ObjectId(req.params.id);
    const filesCol = mongoose.connection.db.collection('photos.files');
    const doc = await filesCol.findOne({ _id: id }, { projection: { contentType: 1, metadata: 1 } });
    if (!doc) return res.status(404).end();
    const type = doc.contentType || doc.metadata?.contentType || 'image/jpeg';
    res.set('Content-Type', type);
    res.set('Cache-Control', 'public, max-age=31536000, immutable');
    return res.status(200).end();
  } catch {
    return res.status(400).end();
  }
});

// GET /d/:id → force download with Content-Disposition
app.get('/d/:id', async (req, res) => {
  try {
    if (!gridfsBucket) return res.status(503).send('Storage not ready');
    const id = new ObjectId(req.params.id);

    const filesCol = mongoose.connection.db.collection('photos.files');
    const doc = await filesCol.findOne({ _id: id });
    if (!doc) return res.status(404).send('Not found');

    const type = doc.contentType || doc.metadata?.contentType || 'image/jpeg';
    const ext  = (type.split('/')[1] || 'jpg').toLowerCase();
    const safeFilename = (doc.filename || `pixelpop-${id.toString()}.${ext}`).replace(/[^\w.\-]/g, '_');

    res.set('Content-Type', type);
    res.set('Content-Disposition', `attachment; filename="${safeFilename}"`);

    const dl = gridfsBucket.openDownloadStream(id);
    dl.on('error', () => res.status(404).end('Not found'));
    dl.pipe(res);
  } catch {
    return res.status(400).send('Bad id');
  }
});

// GET /v/:id → simple viewer page with Download button
app.get('/v/:id', async (req, res) => {
  try {
    const id = new ObjectId(req.params.id);

    const filesCol = mongoose.connection.db.collection('photos.files');
    const doc = await filesCol.findOne({ _id: id });
    if (!doc) return res.status(404).send('<h1>Not found</h1>');

    const base = getBaseUrl(req);
    const rawUrl = `${base}/i/${id.toString()}`;
    const dlUrl  = `${base}/d/${id.toString()}`;

    res.type('html').send(`
      <!doctype html>
      <html>
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width, initial-scale=1" />
          <title>PixelPop Photo</title>
          <style>
            body { margin:0; background:#111; color:#fff; font-family:system-ui, -apple-system, Segoe UI, Roboto, sans-serif; }
            .wrap { min-height:100vh; display:flex; flex-direction:column; align-items:center; justify-content:center; gap:16px; padding:16px; }
            img { max-width:96vw; max-height:70vh; border-radius:12px; box-shadow:0 10px 30px rgba(0,0,0,.6); background:#000; }
            a.button { display:inline-block; background:#fff; color:#111; padding:12px 18px; border-radius:10px; text-decoration:none; font-weight:600; }
            .row { display:flex; gap:12px; flex-wrap:wrap; justify-content:center; }
          </style>
        </head>
        <body>
          <div class="wrap">
            <img src="${rawUrl}" alt="PixelPop Photo" />
            <div class="row">
              <a class="button" href="${dlUrl}">Download</a>
              <a class="button" href="${rawUrl}" target="_blank" rel="noopener">Open Raw</a>
            </div>
          </div>
        </body>
      </html>
    `);
  } catch {
    return res.status(400).send('Bad id');
  }
});

// ─────────────────────────────────────────────────────────────
// Start server
// ─────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 Server is running on http://localhost:${PORT}`);
});
*/
// server.js
require('dotenv').config(); // Loads: MONGODB_URI, MONGODB_DB, JWT_SECRET, PUBLIC_BASE_URL, PORT, CORS_ORIGINS, NODE_ENV

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const { GridFSBucket, ObjectId } = require('mongodb');

const app = express();

/* ────────────────────────────────────────────────────────────
   Config
   ──────────────────────────────────────────────────────────── */
const PORT = process.env.PORT || 5000;

// Honor HTTPS behind proxies (Render/NGINX)
app.set('trust proxy', true);

// Require JWT secret in production
if (process.env.NODE_ENV === 'production' && !process.env.JWT_SECRET) {
  throw new Error('JWT_SECRET is required in production');
}

// CORS: allow your frontend + local dev (edit CORS_ORIGINS env if needed)
const DEFAULT_ORIGINS = [
  'http://localhost:3000',
  'https://pixelpop-server.onrender.com', // <- put your frontend origin here
];
const CORS_ORIGINS = (process.env.CORS_ORIGINS || DEFAULT_ORIGINS.join(','))
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

app.use(cors({ origin: CORS_ORIGINS, credentials: false }));

// JSON body limit (allow big data URLs from canvas)
app.use(express.json({ limit: '15mb' }));

// Optionally serve static files for local dev (put a simple frontend in /public)
const publicDir = path.join(__dirname, 'public');
app.use(express.static(publicDir));

/* ────────────────────────────────────────────────────────────
   Mongo / Mongoose init
   ──────────────────────────────────────────────────────────── */
if (!process.env.MONGODB_URI) {
  console.error('❌ Missing MONGODB_URI in environment.');
  process.exit(1);
}

mongoose
  .connect(process.env.MONGODB_URI, {
    dbName: process.env.MONGODB_DB || 'pixelpop', // ensure correct DB (not "test")
  })
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch((err) => {
    console.error('❌ Could not connect to MongoDB:', err);
    process.exit(1);
  });

// Create GridFS bucket once native connection is open
let gridfsBucket = null;
mongoose.connection.once('open', () => {
  gridfsBucket = new GridFSBucket(mongoose.connection.db, { bucketName: 'photos' });
  console.log('✅ GridFS bucket "photos" ready');
});

// Build absolute base URL (prefer PUBLIC_BASE_URL in prod)
function getBaseUrl(req) {
  if (process.env.PUBLIC_BASE_URL) return process.env.PUBLIC_BASE_URL;
  const proto = req.headers['x-forwarded-proto'] || req.protocol || 'https';
  const host = req.get('host');
  return `${proto}://${host}`;
}

/* ────────────────────────────────────────────────────────────
   Models
   ──────────────────────────────────────────────────────────── */
const UserSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  email:    { type: String, unique: true, required: true },
  password: { type: String, required: true },
});
const User = mongoose.model('User', UserSchema);

const GalleryItemSchema = new mongoose.Schema({
  owner:      { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true, required: true },
  fileId:     { type: mongoose.Schema.Types.ObjectId, required: true },
  url:        { type: String, required: true },
  visibility: { type: String, enum: ['private', 'public'], default: 'private' },
  createdAt:  { type: Date, default: Date.now },
  fileName:   { type: String },
  contentType:{ type: String },
});
const GalleryItem = mongoose.model('GalleryItem', GalleryItemSchema);

/* ────────────────────────────────────────────────────────────
   Auth middleware
   ──────────────────────────────────────────────────────────── */
function authMiddleware(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'No token provided' });

  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Invalid token' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret123'); // set JWT_SECRET in prod
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

/* ────────────────────────────────────────────────────────────
   Health / Root
   ──────────────────────────────────────────────────────────── */
app.get('/health', (_req, res) => res.json({ ok: true }));
app.get('/', (_req, res) => res.send('Backend server is running!'));

/* ────────────────────────────────────────────────────────────
   Auth endpoints (signup / login) — match frontend
   ──────────────────────────────────────────────────────────── */
app.post('/signup', async (req, res) => {
  try {
    const { username, email, password } = req.body || {};
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Username, email, and password are required.' });
    }
    const hashed = await bcrypt.hash(password, 10);
    const user = new User({ username, email, password: hashed });
    await user.save();
    res.status(201).json({ message: 'User registered successfully!' });
  } catch (err) {
    if (err.code === 11000) {
      const field = Object.keys(err.keyPattern)[0];
      const message = field === 'username' ? 'Username already exists.' : 'Email already exists.';
      return res.status(409).json({ error: message });
    }
    console.error(err);
    res.status(500).json({ error: 'An error occurred during registration.' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required.' });
    }
    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ error: 'Invalid username or password' });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ error: 'Invalid username or password' });

    const token = jwt.sign(
      { id: user._id, username: user.username },
      process.env.JWT_SECRET || 'secret123',
      { expiresIn: '1h' }
    );
    res.json({ message: 'Login successful', token, username: user.username });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'An error occurred during login.' });
  }
});

// Used by frontend to gate “Save to My Gallery”
app.get('/api/auth/verify', authMiddleware, (req, res) => {
  res.json({ ok: true, user: req.user });
});

/* ────────────────────────────────────────────────────────────
   Image Uploads via GridFS (QR upload endpoint used by frontend)
   ──────────────────────────────────────────────────────────── */
// POST /api/upload
// Body: { imageData: "data:image/jpeg;base64,...", fileName?: "name.jpg" }
// Returns: { success, url, downloadUrl, viewerUrl, id, contentType }
app.post('/api/upload', async (req, res) => {
  try {
    if (!gridfsBucket) return res.status(503).json({ error: 'Storage not ready' });

    const { imageData, fileName = `pixelpop-photo-${Date.now()}.jpg` } = req.body || {};
    if (!imageData || typeof imageData !== 'string' || !imageData.startsWith('data:')) {
      return res.status(400).json({ error: 'imageData must be a data URL string' });
    }

    // Parse "data:image/jpeg;base64,...."
    const [meta, base64] = imageData.split(',');
    const m = /^data:(.*?);base64$/i.exec(meta);
    const contentType = (m && m[1]) || 'image/jpeg';
    const buffer = Buffer.from(base64, 'base64');

    if (buffer.length > 15 * 1024 * 1024) {
      return res.status(413).json({ error: 'Image too large (max 15MB)' });
    }

    const uploadStream = gridfsBucket.openUploadStream(fileName, {
      contentType,
      metadata: { contentType, source: 'pixelpop-upload', createdAt: new Date() },
    });

    uploadStream.on('error', (err) => {
      console.error('GridFS upload error:', err);
      return res.status(500).json({ error: 'Upload failed' });
    });

    uploadStream.on('finish', () => {
      const id = uploadStream.id.toString();
      const base = getBaseUrl(req);
      const url         = `${base}/i/${id}`; // raw image
      const downloadUrl = `${base}/d/${id}`; // force download
      const viewerUrl   = `${base}/v/${id}`; // landing page with big Download button
      return res.json({ success: true, url, downloadUrl, viewerUrl, id, contentType });
    });

    uploadStream.end(buffer);
  } catch (e) {
    console.error('Upload route error:', e);
    return res.status(500).json({ error: 'Server error' });
  }
});

// GET /i/:id → stream the image by id
app.get('/i/:id', async (req, res) => {
  try {
    if (!gridfsBucket) return res.status(503).send('Storage not ready');
    const id = new ObjectId(req.params.id);

    // Get file doc to set headers
    const filesCol = mongoose.connection.db.collection('photos.files');
    const doc = await filesCol.findOne({ _id: id });
    if (!doc) return res.status(404).send('Not found');

    const type = doc.contentType || doc.metadata?.contentType || 'image/jpeg';
    res.set('Content-Type', type);
    res.set('Cache-Control', 'public, max-age=31536000, immutable');

    const dl = gridfsBucket.openDownloadStream(id);
    dl.on('error', () => res.status(404).end('Not found'));
    dl.pipe(res);
  } catch {
    return res.status(400).send('Bad id');
  }
});

// HEAD /i/:id → quick reachability check (for frontend verification)
app.head('/i/:id', async (req, res) => {
  try {
    if (!gridfsBucket) return res.status(503).end();
    const id = new ObjectId(req.params.id);
    const filesCol = mongoose.connection.db.collection('photos.files');
    const doc = await filesCol.findOne({ _id: id }, { projection: { contentType: 1, metadata: 1 } });
    if (!doc) return res.status(404).end();
    const type = doc.contentType || doc.metadata?.contentType || 'image/jpeg';
    res.set('Content-Type', type);
    res.set('Cache-Control', 'public, max-age=31536000, immutable');
    return res.status(200).end();
  } catch {
    return res.status(400).end();
  }
});

// GET /d/:id → force download
app.get('/d/:id', async (req, res) => {
  try {
    if (!gridfsBucket) return res.status(503).send('Storage not ready');
    const id = new ObjectId(req.params.id);

    const filesCol = mongoose.connection.db.collection('photos.files');
    const doc = await filesCol.findOne({ _id: id });
    if (!doc) return res.status(404).send('Not found');

    const type = doc.contentType || doc.metadata?.contentType || 'image/jpeg';
    const ext  = (type.split('/')[1] || 'jpg').toLowerCase();
    const safeFilename = (doc.filename || `pixelpop-${id.toString()}.${ext}`).replace(/[^\w.\-]/g, '_');

    res.set('Content-Type', type);
    res.set('Content-Disposition', `attachment; filename="${safeFilename}"`);

    const dl = gridfsBucket.openDownloadStream(id);
    dl.on('error', () => res.status(404).end('Not found'));
    dl.pipe(res);
  } catch {
    return res.status(400).send('Bad id');
  }
});

// GET /v/:id → simple viewer page
app.get('/v/:id', async (req, res) => {
  try {
    const id = new ObjectId(req.params.id);

    const filesCol = mongoose.connection.db.collection('photos.files');
    const doc = await filesCol.findOne({ _id: id });
    if (!doc) return res.status(404).send('<h1>Not found</h1>');

    const base = getBaseUrl(req);
    const rawUrl = `${base}/i/${id.toString()}`;
    const dlUrl  = `${base}/d/${id.toString()}`;

    res.type('html').send(`
      <!doctype html>
      <html>
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width, initial-scale=1" />
          <title>PixelPop Photo</title>
          <style>
            body { margin:0; background:#111; color:#fff; font-family:system-ui, -apple-system, Segoe UI, Roboto, sans-serif; }
            .wrap { min-height:100vh; display:flex; flex-direction:column; align-items:center; justify-content:center; gap:16px; padding:16px; }
            img { max-width:96vw; max-height:70vh; border-radius:12px; box-shadow:0 10px 30px rgba(0,0,0,.6); background:#000; }
            a.button { display:inline-block; background:#fff; color:#111; padding:12px 18px; border-radius:10px; text-decoration:none; font-weight:600; }
            .row { display:flex; gap:12px; flex-wrap:wrap; justify-content:center; }
          </style>
        </head>
        <body>
          <div class="wrap">
            <img src="${rawUrl}" alt="PixelPop Photo" />
            <div class="row">
              <a class="button" href="${dlUrl}">Download</a>
              <a class="button" href="${rawUrl}" target="_blank" rel="noopener">Open Raw</a>
            </div>
          </div>
        </body>
      </html>
    `);
  } catch {
    return res.status(400).send('Bad id');
  }
});

/* ────────────────────────────────────────────────────────────
   Gallery API — matches frontend expectations
   ──────────────────────────────────────────────────────────── */

// POST /api/gallery
// Body: { imageData, visibility?: 'private'|'public', fileName? }
// Returns: { item: { id, url, createdAt } }
app.post('/api/gallery', authMiddleware, async (req, res) => {
  try {
    if (!gridfsBucket) return res.status(503).json({ error: 'Storage not ready' });

    const { imageData, visibility = 'private', fileName = `pixelpop-${Date.now()}.jpg` } = req.body || {};
    if (!imageData || typeof imageData !== 'string' || !imageData.startsWith('data:')) {
      return res.status(400).json({ error: 'imageData must be a data URL string' });
    }

    // Parse data URL
    const [meta, base64] = imageData.split(',');
    const m = /^data:(.*?);base64$/i.exec(meta);
    const contentType = (m && m[1]) || 'image/jpeg';
    const buffer = Buffer.from(base64, 'base64');
    if (buffer.length > 15 * 1024 * 1024) {
      return res.status(413).json({ error: 'Image too large (max 15MB)' });
    }

    // Save to GridFS
    const uploadStream = gridfsBucket.openUploadStream(fileName, {
      contentType,
      metadata: { contentType, source: 'pixelpop-gallery', userId: req.user.id, createdAt: new Date() },
    });
    uploadStream.end(buffer);

    uploadStream.on('error', (err) => {
      console.error('GridFS upload error:', err);
      return res.status(500).json({ error: 'Upload failed' });
    });

    uploadStream.on('finish', async () => {
      try {
        const fileId = uploadStream.id; // ObjectId
        const base = getBaseUrl(req);
        const url  = `${base}/i/${fileId.toString()}`;

        const doc = await GalleryItem.create({
          owner: req.user.id,
          fileId,
          url,
          visibility,
          fileName,
          contentType
        });

        return res.json({
          item: {
            id: doc._id.toString(),
            url: doc.url,
            createdAt: doc.createdAt
          }
        });
      } catch (e) {
        console.error('Gallery save doc error:', e);
        return res.status(500).json({ error: 'Could not save gallery item' });
      }
    });
  } catch (e) {
    console.error('POST /api/gallery error:', e);
    return res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/gallery/mine
// Returns: { items: [{ id, url, createdAt }] }
app.get('/api/gallery/mine', authMiddleware, async (req, res) => {
  try {
    const docs = await GalleryItem
      .find({ owner: req.user.id })
      .sort({ createdAt: -1 })
      .limit(200);

    return res.json({
      items: docs.map((d) => ({
        id: d._id.toString(),
        url: d.url,
        createdAt: d.createdAt
      }))
    });
  } catch (e) {
    console.error('GET /api/gallery/mine error:', e);
    return res.status(500).json({ error: 'Server error' });
  }
});

// DELETE /api/gallery/:id
// Returns 200 + { ok:true } on success
app.delete('/api/gallery/:id', authMiddleware, async (req, res) => {
  try {
    const _id = new ObjectId(req.params.id);
    const doc = await GalleryItem.findOne({ _id, owner: req.user.id });
    if (!doc) return res.status(404).json({ error: 'Not found' });

    // Remove file from GridFS (ignore if already gone)
    try {
      await gridfsBucket.delete(doc.fileId);
    } catch (e) {
      console.warn('GridFS delete warning:', e.message || e);
    }

    await GalleryItem.deleteOne({ _id: doc._id });
    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error('DELETE /api/gallery/:id error:', e);
    return res.status(400).json({ error: 'Bad id' });
  }
});

/* ────────────────────────────────────────────────────────────
   Start server
   ──────────────────────────────────────────────────────────── */
app.listen(PORT, () => {
  console.log(`🚀 Server is running on http://localhost:${PORT}`);
});
