/**
 * server.js - NotionIQ with Caching, User Rate Limiting, and Multiple API Keys
 */

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const path = require('path');
const cors = require('cors');
const multer = require('multer');
const mammoth = require('mammoth');
const pdfParse = require('pdf-parse');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const fetch = (...args) => import('node-fetch').then(({ default: f }) => f(...args));

const app = express();
const PORT = process.env.PORT || 3000;

// ---------- ENV ----------
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/notioniq';
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-me';
const GEMINI_MODEL = process.env.GEMINI_MODEL || 'gemini-2.5-flash';
const GEMINI_ENDPOINT_BASE = process.env.GEMINI_ENDPOINT_BASE || 'https://generativelanguage.googleapis.com/v1beta/models';

// ---------- API Key Manager ----------
class APIKeyManager {
  constructor() {
    const keysString = process.env.GEMINI_API_KEYS || process.env.GEMINI_API_KEY || '';
    this.keys = keysString.split(',').map(k => k.trim()).filter(Boolean);
    
    if (this.keys.length === 0) {
      console.error('❌ No API keys configured! Add GEMINI_API_KEY or GEMINI_API_KEYS to .env');
      throw new Error('No API keys configured');
    }
    
    console.log(`🔑 Loaded ${this.keys.length} API key(s)`);
    
    this.keyStats = this.keys.map(key => ({
      key: key,
      requestCount: 0,
      dailyCount: 0,
      lastReset: Date.now(),
      lastDailyReset: Date.now(),
      failures: 0,
      blocked: false,
      blockedUntil: null
    }));
    
    this.currentKeyIndex = 0;
    this.maxRequestsPerMinute = 15;
    this.dailyLimit = 50;
  }
  
  getCurrentKey() {
    for (let i = 0; i < this.keys.length; i++) {
      const index = (this.currentKeyIndex + i) % this.keys.length;
      const stats = this.keyStats[index];
      
      if (stats.blocked && stats.blockedUntil && Date.now() < stats.blockedUntil) {
        continue;
      } else if (stats.blocked) {
        stats.blocked = false;
        stats.blockedUntil = null;
        console.log(`✅ API key ${index + 1} unblocked`);
      }
      
      const now = Date.now();
      if (now - stats.lastReset > 60000) {
        stats.requestCount = 0;
        stats.lastReset = now;
      }
      if (now - stats.lastDailyReset > 86400000) {
        stats.dailyCount = 0;
        stats.lastDailyReset = now;
        stats.failures = 0;
      }
      
      if (stats.requestCount < this.maxRequestsPerMinute && stats.dailyCount < this.dailyLimit) {
        this.currentKeyIndex = index;
        return { key: stats.key, index };
      }
    }
    
    throw new Error('All API keys have reached their limits. Please try again later or add more keys.');
  }
  
  recordSuccess(index) {
    this.keyStats[index].requestCount++;
    this.keyStats[index].dailyCount++;
    this.keyStats[index].failures = 0;
  }
  
  recordFailure(index, error) {
    this.keyStats[index].failures++;
    
    if (error.message.includes('quota') || error.message.includes('429') || this.keyStats[index].failures >= 3) {
      this.keyStats[index].blocked = true;
      this.keyStats[index].blockedUntil = Date.now() + (60 * 60 * 1000);
      console.log(`🚫 API key ${index + 1} blocked for 1 hour`);
    }
  }
  
  getStats() {
    return {
      totalKeys: this.keys.length,
      activeKeys: this.keyStats.filter(s => !s.blocked).length,
      keys: this.keyStats.map((s, i) => ({
        id: i + 1,
        blocked: s.blocked,
        requestsThisMinute: s.requestCount,
        requestsToday: s.dailyCount,
        failures: s.failures
      }))
    };
  }
}

const apiKeyManager = new APIKeyManager();

// ---------- Cache Manager ----------
class CacheManager {
  constructor() {
    this.cache = new Map();
    this.maxCacheSize = 1000;
    this.defaultTTL = 3600000; // 1 hour
    
    setInterval(() => this.cleanup(), 600000); // Cleanup every 10 mins
    console.log('💾 Cache manager initialized');
  }
  
  generateKey(prompt, systemInstruction = '') {
    const content = prompt + (systemInstruction || '');
    return crypto.createHash('md5').update(content).digest('hex');
  }
  
  get(key) {
    const entry = this.cache.get(key);
    if (!entry) return null;
    
    if (Date.now() > entry.expiresAt) {
      this.cache.delete(key);
      return null;
    }
    
    entry.hits++;
    entry.lastAccessed = Date.now();
    console.log(`💾 Cache HIT (${entry.hits} hits)`);
    return entry.data;
  }
  
  set(key, data, ttl = this.defaultTTL) {
    if (this.cache.size >= this.maxCacheSize) {
      this.evictLRU();
    }
    
    this.cache.set(key, {
      data,
      createdAt: Date.now(),
      expiresAt: Date.now() + ttl,
      lastAccessed: Date.now(),
      hits: 0
    });
    console.log('💾 Cache SET');
  }
  
  cleanup() {
    const now = Date.now();
    let cleaned = 0;
    
    for (const [key, entry] of this.cache.entries()) {
      if (now > entry.expiresAt) {
        this.cache.delete(key);
        cleaned++;
      }
    }
    
    if (cleaned > 0) console.log(`🧹 Cleaned ${cleaned} cache entries`);
  }
  
  evictLRU() {
    let oldestKey = null;
    let oldestTime = Infinity;
    
    for (const [key, entry] of this.cache.entries()) {
      if (entry.lastAccessed < oldestTime) {
        oldestTime = entry.lastAccessed;
        oldestKey = key;
      }
    }
    
    if (oldestKey) this.cache.delete(oldestKey);
  }
  
  getStats() {
    let totalHits = 0;
    for (const entry of this.cache.values()) {
      totalHits += entry.hits;
    }
    
    return {
      size: this.cache.size,
      maxSize: this.maxCacheSize,
      totalHits,
      hitRate: this.cache.size > 0 ? (totalHits / this.cache.size).toFixed(2) : 0
    };
  }
}

const cacheManager = new CacheManager();

// ---------- DB ----------
mongoose.connect(MONGODB_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error('❌ MongoDB error:', err));

// ---------- Updated User Model with Usage Tracking ----------
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true, minlength: 3 },
  email: { type: String, required: true, unique: true, trim: true, lowercase: true },
  password: { type: String, required: true, minlength: 6 },
  tier: { type: String, enum: ['free', 'premium'], default: 'free' },
  usage: {
    dailyRequests: { type: Number, default: 0 },
    lastResetDate: { type: Date, default: Date.now },
    totalRequests: { type: Number, default: 0 },
    lastRequestTime: { type: Date }
  },
  createdAt: { type: Date, default: Date.now }
});

userSchema.pre('save', async function(next){ 
  if(!this.isModified('password')) return next(); 
  this.password = await bcrypt.hash(this.password, 10); 
  next(); 
});

userSchema.methods.comparePassword = async function(p){ 
  return bcrypt.compare(p, this.password); 
};

const User = mongoose.model('User', userSchema);

// ---------- Rate Limits by Tier ----------
const TIER_LIMITS = {
  free: {
    dailyLimit: 10,
    minuteLimit: 3,
    concurrentLimit: 1
  },
  premium: {
    dailyLimit: 100,
    minuteLimit: 15,
    concurrentLimit: 3
  }
};

// ---------- Middleware ----------
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true, limit: '20mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  name: 'notioniq.sid',  // Custom name to avoid conflicts
  store: MongoStore.create({ 
    mongoUrl: MONGODB_URI,
    touchAfter: 24 * 3600,
    ttl: 24 * 60 * 60,
    autoRemove: 'native'
  }),
  cookie: { 
    maxAge: 1000 * 60 * 60 * 24,  // 24 hours
    httpOnly: true,
    secure: false,                 // CRITICAL: false for localhost!
    sameSite: 'lax',              // CRITICAL: lax not strict!
    path: '/'                      // Available on all routes
  }
}));
app.use((req, res, next) => {
  if (req.path.includes('/api/')) {
    console.log(`📍 ${req.method} ${req.path} | Session: ${req.sessionID?.substring(0, 8)}... | User: ${req.session.userId || 'none'}`);
  }
  next();
});

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 20 * 1024 * 1024 } });

// ---------- User Rate Limit Middleware ----------
async function checkUserRateLimit(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({
      success: false,
      message: 'Please sign in to use AI features'
    });
  }
  
  try {
    const user = await User.findById(req.session.userId);
    if (!user) {
      return res.status(401).json({ success: false, message: 'User not found' });
    }
    
    const limits = TIER_LIMITS[user.tier] || TIER_LIMITS.free;
    const now = new Date();
    
    // Reset daily counter
    const lastResetDate = new Date(user.usage.lastResetDate);
    if (now.toDateString() !== lastResetDate.toDateString()) {
      user.usage.dailyRequests = 0;
      user.usage.lastResetDate = now;
      await user.save();
    }
    
    // Check daily limit
    if (user.usage.dailyRequests >= limits.dailyLimit) {
      return res.status(429).json({
        success: false,
        message: `Daily limit reached (${limits.dailyLimit} requests). ${
          user.tier === 'free' ? 'Upgrade to premium for 10x more requests!' : 'Resets at midnight.'
        }`,
        limit: limits.dailyLimit,
        used: user.usage.dailyRequests,
        tier: user.tier,
        upgradeable: user.tier === 'free'
      });
    }
    
    // Check minute rate limit
    if (user.usage.lastRequestTime) {
      const timeSinceLastRequest = now - user.usage.lastRequestTime;
      const minInterval = (60 / limits.minuteLimit) * 1000;
      
      if (timeSinceLastRequest < minInterval) {
        const waitSeconds = Math.ceil((minInterval - timeSinceLastRequest) / 1000);
        return res.status(429).json({
          success: false,
          message: `Please wait ${waitSeconds} seconds before next request`,
          retryAfter: waitSeconds
        });
      }
    }
    
    req.user = user;
    req.userLimits = limits;
    next();
    
  } catch (error) {
    console.error('Rate limit check error:', error);
    res.status(500).json({ success: false, message: 'Error checking rate limit' });
  }
}

async function recordUserRequest(userId) {
  try {
    await User.findByIdAndUpdate(userId, {
      $inc: { 'usage.dailyRequests': 1, 'usage.totalRequests': 1 },
      $set: { 'usage.lastRequestTime': new Date() }
    });
  } catch (error) {
    console.error('Error recording usage:', error);
  }
}

// ---------- Improved Gemini Helper with Caching and Key Rotation ----------
async function callGemini(prompt, systemInstruction = '', opts = {}) {
  const attempts = Number(opts.attempts || 3);
  const cacheKey = cacheManager.generateKey(prompt, systemInstruction);
  
  // Check cache first
  if (!opts.skipCache) {
    const cached = cacheManager.get(cacheKey);
    if (cached) return cached;
  }
  
  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      const { key, index } = apiKeyManager.getCurrentKey();
      
      const url = `${GEMINI_ENDPOINT_BASE}/${encodeURIComponent(GEMINI_MODEL)}:generateContent?key=${key}`;
      const body = {
        contents: [{ parts: [{ text: (systemInstruction ? (systemInstruction + '\n\n') : '') + prompt }] }],
        generationConfig: { temperature: 0.7, maxOutputTokens: 2048 }
      };
      
      console.log(`🔄 Gemini API call with key ${index + 1} (attempt ${attempt}/${attempts})`);
      
      const resp = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      
      const responseText = await resp.text();
      
      if (!resp.ok) {
        console.error(`❌ API error (${resp.status}):`, responseText.substring(0, 200));
        
        const error = new Error(`API error: ${resp.status}`);
        apiKeyManager.recordFailure(index, error);
        
        if (resp.status === 429 || resp.status === 403) {
          console.log(`⚠️ Key ${index + 1} quota exceeded, rotating...`);
          await new Promise(r => setTimeout(r, 1000));
          continue;
        }
        
        throw error;
      }
      
      const data = JSON.parse(responseText);
      const result = data?.candidates?.[0]?.content?.parts?.map(p => p.text).join('\n') || '';
      
      if (!result) throw new Error('Empty response');
      
      apiKeyManager.recordSuccess(index);
      
      // Cache the result
      if (!opts.skipCache) {
        cacheManager.set(cacheKey, result, opts.cacheTTL || 3600000);
      }
      
      console.log('✅ API call successful');
      return result;
      
    } catch (err) {
      console.error(`❌ Attempt ${attempt} failed:`, err.message);
      
      if (attempt === attempts) throw err;
      await new Promise(r => setTimeout(r, 2000 * attempt));
    }
  }
  
  throw new Error('All retry attempts failed');
}

function extractJSON(str) {
  if (!str) return null;
  const m = str.match(/```json\s*([\s\S]*?)\s*```/i) || str.match(/```([\s\S]*?)```/i) || str.match(/(\[[\s\S]*\]|\{[\s\S]*\})/);
  const candidate = m ? (m[1] || m[0]) : str;
  try { return JSON.parse(candidate); } catch (e) { return null; }
}

// ---------- HTML Generator ----------
function escapeHtml(s){ if(!s) return ''; return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

function saveImportantHtml(id, title, pagesPoints) {
  const filePath = path.join(__dirname, 'public', 'important', `${id}.html`);
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${escapeHtml(title)}</title>
  <link rel="stylesheet" href="/style.css">
  <style>
    body { background: #0b0014; color: white; font-family: 'Poppins', sans-serif; padding: 40px 0; }
    .container { width: 90%; max-width: 900px; margin: auto; padding: 20px; }
    h1 { text-align: center; margin-bottom: 40px; color: #fff; }
    .page-card { background: rgba(255, 255, 255, 0.05); border: 1px solid rgba(158, 0, 255, 0.3); padding: 25px; margin-bottom: 30px; border-radius: 12px; }
    .page-title { font-size: 1.3rem; margin-bottom: 15px; color: #c57bff; font-weight: 600; }
    ol { padding-left: 20px; line-height: 1.6; }
    li { margin-bottom: 8px; }
    .controls { display: flex; justify-content: center; gap: 20px; margin-top: 40px; }
    .btn { padding: 12px 25px; border-radius: 30px; text-decoration: none; color: white; font-weight: bold; cursor: pointer; border: none; font-size: 1rem; transition: transform 0.2s; }
    .btn-primary { background: linear-gradient(90deg, #9E00FF, #BF6FFF); }
    .btn-secondary { background: rgba(255,255,255,0.1); border: 1px solid rgba(158,0,255,0.3); }
    .btn:hover { transform: translateY(-3px); }
    .btn:disabled { opacity: 0.5; cursor: not-allowed; }
  </style>
</head>
<body>
  <div class="container">
    <h1>${escapeHtml(title)}</h1>
    <div id="points-container">
    ${pagesPoints.map(pg => `
      <div class="page-card">
        <div class="page-title">Page ${escapeHtml(String(pg.page))}</div>
        <ol>${pg.points.map(pt => `<li>${escapeHtml(pt)}</li>`).join("")}</ol>
      </div>
    `).join("")}
    </div>
    <div class="controls">
      <a class="btn btn-secondary" href="/Notion.html">← Back to Notes</a>
      <button id="gen-quiz-btn" class="btn btn-primary">Generate Quiz from these Points</button>
    </div>
  </div>
  <script>
    document.getElementById('gen-quiz-btn').addEventListener('click', async () => {
      const btn = document.getElementById('gen-quiz-btn');
      const listItems = document.querySelectorAll('li');
      let combinedText = '';
      listItems.forEach(li => combinedText += li.textContent + '\\n');
      if(combinedText.length < 50) { alert('Not enough content'); return; }
      btn.disabled = true;
      btn.textContent = 'Generating...';
      try {
        const res = await fetch('/api/generate-quiz', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ notes: combinedText })
        });
        const data = await res.json();
        if(data.success && data.questions) {
          sessionStorage.setItem('aiQuizQuestions', JSON.stringify(data.questions));
          window.location.href = '/take-quiz.html';
        } else {
          alert('Failed: ' + (data.message || 'Unknown error'));
        }
      } catch(e) {
        alert('Error: ' + e.message);
      } finally {
        btn.disabled = false;
        btn.textContent = 'Generate Quiz from these Points';
      }
    });
    sessionStorage.setItem('notioniq_last_points_url', window.location.pathname);
  </script>
  <script src="/script.js"></script>
</body>
</html>`;
  fs.writeFileSync(filePath, html, "utf8");
  return `/important/${id}.html`;
}

function splitIntoPages(text, numPages) {
  const clean = (text || '').replace(/\s+/g,' ').trim();
  if (!clean) return [];
  const parts = Math.max(1, numPages || 5);
  const chunkSize = Math.ceil(clean.length / parts);
  const pages = [];
  for (let i=0;i<parts;i++){
    const slice = clean.slice(i*chunkSize, (i+1)*chunkSize).trim();
    if (slice) pages.push({ page: i+1, text: slice });
  }
  return pages;
}

// ---------- API Routes ----------
app.get('/api/my-usage', async (req, res) => {
  // Better error messages for debugging
  if (!req.session) {
    console.error('❌ No session object found!');
    return res.status(500).json({ 
      authenticated: false,
      message: 'Session not initialized',
      debug: 'Session middleware may not be working'
    });
  }

  if (!req.session.userId) {
    console.log('⚠️  No userId in session. SessionID:', req.sessionID);
    return res.status(401).json({ 
      authenticated: false,
      message: 'Not authenticated',
      debug: 'No userId in session'
    });
  }
  
  try {
    const user = await User.findById(req.session.userId);
    
    if (!user) {
      console.error('❌ User not found for ID:', req.session.userId);
      // Clear invalid session
      req.session.destroy();
      return res.status(401).json({ 
        authenticated: false,
        message: 'User not found',
        debug: 'Session had invalid userId'
      });
    }
    
    const limits = TIER_LIMITS[user.tier] || TIER_LIMITS.free;
    
    // Reset daily counter if new day
    const now = new Date();
    const lastResetDate = new Date(user.usage.lastResetDate);
    if (now.toDateString() !== lastResetDate.toDateString()) {
      user.usage.dailyRequests = 0;
      user.usage.lastResetDate = now;
      await user.save();
    }
    
    console.log(`✅ Usage data for ${user.username}: ${user.usage.dailyRequests}/${limits.dailyLimit}`);
    
    res.json({
      authenticated: true,
      tier: user.tier,
      usage: {
        today: user.usage.dailyRequests,
        total: user.usage.totalRequests,
        lastRequest: user.usage.lastRequestTime
      },
      limits: {
        daily: limits.dailyLimit,
        perMinute: limits.minuteLimit
      },
      remaining: limits.dailyLimit - user.usage.dailyRequests,
      canUpgrade: user.tier === 'free'
    });
    
  } catch (error) {
    console.error('❌ Error in /api/my-usage:', error);
    res.status(500).json({ 
      authenticated: false,
      message: 'Server error',
      debug: error.message
    });
  }
});


// Extract text - NO AI, NO rate limiting
app.post('/api/extract-text', upload.single('file'), async (req, res) => {
  try {
    const file = req.file;
    if (!file) return res.status(400).json({ success:false, message:'No file uploaded' });
    
    let text = '';
    if (file.mimetype === 'text/plain') {
      text = file.buffer.toString('utf8');
    } else if (file.mimetype.includes('word')) { 
      const result = await mammoth.extractRawText({ buffer: file.buffer }); 
      text = result.value; 
    } else if (file.mimetype === 'application/pdf') { 
      const data = await pdfParse(file.buffer); 
      text = data.text; 
    } else {
      return res.status(400).json({ success:false, message:'Unsupported file type' });
    }
    
    text = (text||'').replace(/\s+/g,' ').trim();
    if(!text) return res.status(400).json({ success:false, message:'File is empty' });
    
    res.json({ success:true, text });
  } catch (e) { 
    console.error('Extract error:', e);
    res.status(500).json({ success:false, message: 'Error extracting: ' + e.message }); 
  }
});

// Analyze - with rate limiting
app.post('/api/analyze', checkUserRateLimit, async (req, res) => {
  try {
    const notes = (req.body.notes || '').trim();
    if(notes.length < 50) return res.status(400).json({success:false, message:'Notes too short (minimum 50 characters)'});
    
    await recordUserRequest(req.user._id);
    
    const raw = await callGemini(
      `Extract exactly 7 concise key points from this text:\n\n${notes}`,
      'You are a study expert. Return ONLY a valid JSON array of 7 strings. Format: ["point 1", "point 2", ...]'
    );
    
    const pts = extractJSON(raw);
    if (!Array.isArray(pts)) throw new Error('Failed to parse AI response');
    
    const updatedUser = await User.findById(req.user._id);
    
    res.json({ 
      success:true, 
      points: pts.slice(0, 7),
      usage: {
        used: updatedUser.usage.dailyRequests,
        limit: req.userLimits.dailyLimit,
        remaining: req.userLimits.dailyLimit - updatedUser.usage.dailyRequests
      }
    });
  } catch(e) { 
    console.error('Analyze error:', e);
    res.status(500).json({success:false, message: e.message}); 
  }
});

// Generate quiz - with rate limiting
app.post('/api/generate-quiz', checkUserRateLimit, async (req, res) => {
  try {
    const notes = (req.body.notes || '').trim();
    if(notes.length < 50) return res.status(400).json({success:false, message:'Notes too short'});
    
    await recordUserRequest(req.user._id);
    
    const sys = 'You create quizzes. Return ONLY valid JSON: [{"question": "...", "options": ["A", "B", "C", "D"], "answer": "correct", "explanation": "..."}]';
    const usr = `Generate 5 multiple choice questions:\n\n${notes}`;
    
    const raw = await callGemini(usr, sys);
    const q = extractJSON(raw);
    if(!Array.isArray(q)) throw new Error('Failed to generate quiz');
    
    const updatedUser = await User.findById(req.user._id);
    
    res.json({ 
      success:true, 
      questions: q.slice(0,5),
      usage: {
        used: updatedUser.usage.dailyRequests,
        limit: req.userLimits.dailyLimit,
        remaining: req.userLimits.dailyLimit - updatedUser.usage.dailyRequests
      }
    });
  } catch(e) { 
    console.error('Quiz error:', e);
    res.status(500).json({success:false, message: e.message}); 
  }
});

// Detailed analysis - with rate limiting
app.post('/api/analyze-pages', checkUserRateLimit, upload.single('file'), async (req, res) => {
  try {
    let pages = [];
    
    if (req.file && req.file.mimetype === 'application/pdf') {
      const data = await pdfParse(req.file.buffer);
      const num = Number(data.numpages) || 1;
      pages = splitIntoPages(data.text, Math.min(10, Math.max(3, num)));
    } else {
      const raw = (req.body.notes || '').trim();
      if(!raw || raw.length < 50) return res.status(400).json({success:false, message:'No content'});
      pages = splitIntoPages(raw, 5);
    }

    await recordUserRequest(req.user._id);

    const pagesPoints = [];
    const system = 'Study expert. Return ONLY JSON: {"points": ["point 1", ...]}. Include 10-15 key points.';
    
    for (const p of pages) {
      const prompt = `Analyze page ${p.page}, extract 10-15 key points:\n\n${p.text}`;
      
      try {
        const raw = await callGemini(prompt, system, { attempts: 2 });
        const data = extractJSON(raw);
        let pts = (data && Array.isArray(data.points)) ? data.points : [];
        if(pts.length < 5) pts = raw.split('\n').filter(l => l.trim().length > 10).slice(0, 15);
        pagesPoints.push({ page: p.page, points: pts.slice(0, 15) });
      } catch (err) {
        console.error(`Page ${p.page} failed:`, err.message);
        pagesPoints.push({ page: p.page, points: [`Analysis failed: ${err.message}`] });
      }
    }

    const id = uuidv4();
    const title = req.body.title || 'Detailed Study Notes';
    const url = saveImportantHtml(id, title, pagesPoints);
    
    const updatedUser = await User.findById(req.user._id);
    
    res.json({ 
      success:true, 
      url,
      usage: {
        used: updatedUser.usage.dailyRequests,
        limit: req.userLimits.dailyLimit,
        remaining: req.userLimits.dailyLimit - updatedUser.usage.dailyRequests
      }
    });

  } catch (e) {
    console.error('Page analysis error:', e);
    res.status(500).json({ success:false, message: e.message });
  }
});

// User usage endpoint
app.get('/api/my-usage', async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ message: 'Not authenticated' });
  }
  
  try {
    const user = await User.findById(req.session.userId);
    const limits = TIER_LIMITS[user.tier];
    
    res.json({
      tier: user.tier,
      usage: {
        today: user.usage.dailyRequests,
        total: user.usage.totalRequests,
        lastRequest: user.usage.lastRequestTime
      },
      limits: {
        daily: limits.dailyLimit,
        perMinute: limits.minuteLimit
      },
      remaining: limits.dailyLimit - user.usage.dailyRequests,
      canUpgrade: user.tier === 'free'
    });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching usage' });
  }
});

// Auth routes
app.post('/api/signup', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    if (await User.findOne({ $or: [{ email }, { username }] })) {
      return res.status(400).json({ 
        success: false,
        message: 'User already exists' 
      });
    }
    
    const user = await new User({ username, email, password }).save();
    
    // Set session after signup
    req.session.regenerate((err) => {
      if (err) {
        return res.status(500).json({ 
          success: false,
          message: 'Signup succeeded but login failed' 
        });
      }
      
      req.session.userId = user._id;
      req.session.username = user.username;
      
      req.session.save((err) => {
        if (err) {
          return res.status(500).json({ 
            success: false,
            message: 'Signup succeeded but login failed' 
          });
        }
        
        console.log(`✅ New user: ${user.username}`);
        
        res.status(201).json({ 
          success: true, 
          user: { name: user.username } 
        });
      });
    });
    
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Signup failed' 
    });
  }
});


app.post('/api/signin', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ 
        success: false,
        message: 'Email and password required' 
      });
    }
    
    const user = await User.findOne({ email });
    
    if (!user || !(await user.comparePassword(password))) {
      return res.status(401).json({ 
        success: false,
        message: 'Invalid credentials' 
      });
    }
    
    // Regenerate session on login (security best practice)
    req.session.regenerate((err) => {
      if (err) {
        console.error('Session regeneration error:', err);
        return res.status(500).json({ 
          success: false,
          message: 'Login failed' 
        });
      }
      
      // Set session data
      req.session.userId = user._id;
      req.session.username = user.username;
      
      // Save session explicitly
      req.session.save((err) => {
        if (err) {
          console.error('Session save error:', err);
          return res.status(500).json({ 
            success: false,
            message: 'Login failed' 
          });
        }
        
        console.log(`✅ User logged in: ${user.username} (${req.sessionID.substring(0, 8)}...)`);
        
        res.json({ 
          success: true, 
          user: { name: user.username },
          sessionId: req.sessionID.substring(0, 8) + '...'  // For debugging
        });
      });
    });
    
  } catch (error) {
    console.error('Signin error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Signin failed' 
    });
  }
});


app.post('/api/signout', (req,res)=>{ req.session.destroy(); res.json({success:true}); });
app.get('/api/me', (req,res)=> res.json({authenticated:!!req.session.userId, user:{name:req.session.username}}));
app.get('/api/test-session', (req, res) => {
  res.json({
    sessionExists: !!req.session,
    sessionID: req.sessionID,
    userId: req.session?.userId || 'NOT SET',
    username: req.session?.username || 'NOT SET',
    cookie: req.session?.cookie,
    working: !!req.session?.userId
  });
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🔑 API Keys: ${apiKeyManager.keys.length}`);
  console.log(`💾 Cache: Enabled`);
  console.log(`👥 User Rate Limiting: Enabled`);
});