/**
 * server.js - NotionIQ with improved rate limiting and error handling
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
const fetch = (...args) => import('node-fetch').then(({ default: f }) => f(...args));

const app = express();
const PORT = process.env.PORT || 3000;

// ---------- ENV ----------
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/notioniq';
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-me';
const GEMINI_API_KEY = process.env.GEMINI_API_KEY || '';
const GEMINI_MODEL = process.env.GEMINI_MODEL || 'gemini-2.5-flash';
const GEMINI_ENDPOINT_BASE = process.env.GEMINI_ENDPOINT_BASE || 'https://generativelanguage.googleapis.com/v1beta/models';

// ---------- Rate Limiting Tracker ----------
const rateLimitTracker = {
  requestCount: 0,
  lastReset: Date.now(),
  maxRequestsPerMinute: 15, // Conservative limit for free tier
  dailyLimit: 50, // Conservative daily limit
  dailyCount: 0,
  lastDailyReset: Date.now()
};

function checkRateLimit() {
  const now = Date.now();
  
  // Reset minute counter
  if (now - rateLimitTracker.lastReset > 60000) {
    rateLimitTracker.requestCount = 0;
    rateLimitTracker.lastReset = now;
  }
  
  // Reset daily counter
  if (now - rateLimitTracker.lastDailyReset > 86400000) {
    rateLimitTracker.dailyCount = 0;
    rateLimitTracker.lastDailyReset = now;
  }
  
  // Check limits
  if (rateLimitTracker.dailyCount >= rateLimitTracker.dailyLimit) {
    throw new Error('Daily API limit reached. Please try again tomorrow or upgrade to paid tier.');
  }
  
  if (rateLimitTracker.requestCount >= rateLimitTracker.maxRequestsPerMinute) {
    throw new Error('Rate limit exceeded. Please wait a minute before trying again.');
  }
  
  rateLimitTracker.requestCount++;
  rateLimitTracker.dailyCount++;
}

// ---------- DB ----------
mongoose.connect(MONGODB_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error('❌ MongoDB error:', err));

// ---------- User model ----------
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true, minlength: 3 },
  email: { type: String, required: true, unique: true, trim: true, lowercase: true },
  password: { type: String, required: true, minlength: 6 },
  createdAt: { type: Date, default: Date.now }
});
userSchema.pre('save', async function(next){ if(!this.isModified('password')) return next(); this.password = await bcrypt.hash(this.password, 10); next(); });
userSchema.methods.comparePassword = async function(p){ return bcrypt.compare(p, this.password); };
const User = mongoose.model('User', userSchema);

// ---------- Middleware ----------
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true, limit: '20mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: MONGODB_URI, touchAfter: 24 * 3600 }),
  cookie: { maxAge: 1000*60*60*24, httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax' }
}));

// ---------- Uploads ----------
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 20 * 1024 * 1024 } });

// ---------- Improved Gemini Helper ----------
async function callGemini(prompt, systemInstruction = '', opts = {}) {
  const attempts = Number(opts.attempts || 3);
  const backoffBaseMs = Number(opts.backoffBaseMs || 2000); // Increased base backoff
  const timeoutMs = Number(opts.timeoutMs || 120000);

  if (!GEMINI_API_KEY) {
    throw new Error('GEMINI_API_KEY is not set. Please add it to your .env file.');
  }

  // Check our local rate limit first
  try {
    checkRateLimit();
  } catch (e) {
    throw new Error(`Rate limit: ${e.message}`);
  }

  const url = `${GEMINI_ENDPOINT_BASE}/${encodeURIComponent(GEMINI_MODEL)}:generateContent?key=${GEMINI_API_KEY}`;
  const body = {
    contents: [{ parts: [{ text: (systemInstruction ? (systemInstruction + '\n\n') : '') + prompt }] }],
    generationConfig: {
      temperature: 0.7,
      maxOutputTokens: 2048
    }
  };

  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

      console.log(`🔄 Gemini API call (attempt ${attempt}/${attempts})...`);
      
      const resp = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: controller.signal
      });
      
      clearTimeout(timeoutId);

      const responseText = await resp.text();
      
      if (!resp.ok) {
        console.error(`❌ Gemini API error (${resp.status}):`, responseText);
        
        // Parse error details
        let errorDetails;
        try {
          errorDetails = JSON.parse(responseText);
        } catch (e) {
          errorDetails = { error: { message: responseText } };
        }

        // Handle specific error codes
        if (resp.status === 429) {
          const retryAfter = resp.headers.get('retry-after') || 60;
          console.log(`⏳ Rate limited. Retry after ${retryAfter}s`);
          
          if (attempt < attempts) {
            const waitMs = Math.max(backoffBaseMs * Math.pow(2, attempt - 1), retryAfter * 1000);
            console.log(`⏱️  Waiting ${waitMs}ms before retry...`);
            await new Promise(r => setTimeout(r, waitMs));
            continue;
          }
          
          // Provide user-friendly error message
          throw new Error(
            'API quota exceeded. Options:\n' +
            '1. Wait 24 hours for quota reset\n' +
            '2. Upgrade to paid tier at https://console.cloud.google.com/\n' +
            '3. Try using a different API key'
          );
        }
        
        if (resp.status === 503) {
          if (attempt < attempts) {
            const waitMs = backoffBaseMs * Math.pow(2, attempt - 1);
            console.log(`⏱️  Service unavailable. Waiting ${waitMs}ms...`);
            await new Promise(r => setTimeout(r, waitMs));
            continue;
          }
          throw new Error('Gemini service temporarily unavailable. Please try again later.');
        }
        
        throw new Error(errorDetails.error?.message || `API error: ${resp.status}`);
      }

      const data = JSON.parse(responseText);
      const result = data?.candidates?.[0]?.content?.parts?.map(p => p.text).join('\n') || '';
      
      if (!result) {
        throw new Error('Empty response from Gemini API');
      }
      
      console.log('✅ Gemini API call successful');
      return result;
      
    } catch (err) {
      console.error(`❌ Attempt ${attempt} failed:`, err.message);
      
      if (err.name === 'AbortError') {
        throw new Error('Request timeout. The AI is taking too long to respond.');
      }
      
      if (attempt < attempts && !err.message.includes('quota')) {
        const waitMs = backoffBaseMs * Math.pow(2, attempt - 1);
        console.log(`⏱️  Retrying in ${waitMs}ms...`);
        await new Promise(r => setTimeout(r, waitMs));
        continue;
      }
      
      throw err;
    }
  }
  
  throw new Error('All retry attempts failed');
}

function extractJSON(str) {
  if (!str) return null;
  const m = str.match(/```json\s*([\s\S]*?)\s*```/i) || str.match(/```([\s\S]*?)```/i) || str.match(/(\[[\s\S]*\]|\{[\s\S]*\})/);
  const candidate = m ? (m[1] || m[0]) : str;
  try { return JSON.parse(candidate); } catch (e) { 
    console.error('JSON parse error:', e.message);
    return null; 
  }
}

// ---------- HTML Generator for Important Points ----------
function escapeHtml(s){ if(!s) return ''; return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

function saveImportantHtml(id, title, pagesPoints) {
  const filePath = path.join(__dirname, 'public', 'important', `${id}.html`);
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  const html = `
<!DOCTYPE html>
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
    .loading { display: none; margin-left: 10px; }
  </style>
</head>
<body>
  <div class="container">
    <h1>${escapeHtml(title)}</h1>

    <div id="points-container">
    ${pagesPoints.map(pg => `
      <div class="page-card">
        <div class="page-title">Page ${escapeHtml(String(pg.page))}</div>
        <ol>
          ${pg.points.map(pt => `<li>${escapeHtml(pt)}</li>`).join("")}
        </ol>
      </div>
    `).join("")}
    </div>

    <div class="controls">
      <a class="btn btn-secondary" href="/Notion.html">← Back to Notes</a>
      <button id="gen-quiz-btn" class="btn btn-primary">
        Generate Quiz from these Points <span id="spinner" class="loading">⏳</span>
      </button>
    </div>
  </div>

  <script>
    document.getElementById('gen-quiz-btn').addEventListener('click', async () => {
      const btn = document.getElementById('gen-quiz-btn');
      const spinner = document.getElementById('spinner');
      
      const listItems = document.querySelectorAll('li');
      let combinedText = '';
      listItems.forEach(li => combinedText += li.textContent + '\\n');
      
      if(combinedText.length < 50) { alert('Not enough content for a quiz.'); return; }

      btn.disabled = true;
      spinner.style.display = 'inline';
      
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
          alert('Failed to generate quiz: ' + (data.message || 'Unknown error'));
        }
      } catch(e) {
        alert('Error connecting to server: ' + e.message);
      } finally {
        btn.disabled = false;
        spinner.style.display = 'none';
      }
    });
    
    sessionStorage.setItem('notioniq_last_points_url', window.location.pathname);
  </script>
  <script src="/script.js"></script>
</body>
</html>
`;
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
app.get('/api/health', (_req, res) => res.json({ 
  status: 'ok',
  rateLimit: {
    requestsThisMinute: rateLimitTracker.requestCount,
    requestsToday: rateLimitTracker.dailyCount,
    dailyLimit: rateLimitTracker.dailyLimit
  }
}));

// TEXT EXTRACTION - NO AI USED
app.post('/api/extract-text', upload.single('file'), async (req, res) => {
  try {
    const file = req.file;
    if (!file) return res.status(400).json({ success:false, message:'No file uploaded' });
    
    let text = '';
    
    if (file.mimetype === 'text/plain') {
      text = file.buffer.toString('utf8');
    } 
    else if (file.mimetype.includes('word')) { 
      const result = await mammoth.extractRawText({ buffer: file.buffer }); 
      text = result.value; 
    }
    else if (file.mimetype === 'application/pdf') { 
      const data = await pdfParse(file.buffer); 
      text = data.text; 
    }
    else {
      return res.status(400).json({ success:false, message:'Unsupported file type' });
    }
    
    text = (text||'').replace(/\s+/g,' ').trim();
    if(!text) return res.status(400).json({ success:false, message:'File is empty or unreadable' });
    
    res.json({ success:true, text });
  } catch (e) { 
    console.error('Extract error:', e);
    res.status(500).json({ success:false, message: 'Error extracting text: ' + e.message }); 
  }
});

// Quick analyze (uses AI)
app.post('/api/analyze', async (req, res) => {
  try {
    const notes = (req.body.notes || '').trim();
    if(notes.length < 50) return res.status(400).json({success:false, message:'Notes too short (minimum 50 characters)'});
    
    const raw = await callGemini(
      `Extract exactly 7 concise key points from this text:\n\n${notes}`,
      'You are a study expert. Return ONLY a valid JSON array of 7 strings. Each string should be a clear, concise key point. Format: ["point 1", "point 2", ...]'
    );
    
    const pts = extractJSON(raw);
    if (!Array.isArray(pts)) {
      throw new Error('Failed to parse AI response');
    }
    
    res.json({ success:true, points: pts.slice(0, 7) });
  } catch(e) { 
    console.error('Analyze error:', e);
    res.status(500).json({success:false, message: e.message}); 
  }
});

// Generate quiz (uses AI)
app.post('/api/generate-quiz', async (req, res) => {
  try {
    const notes = (req.body.notes || '').trim();
    if(notes.length < 50) return res.status(400).json({success:false, message:'Notes too short (minimum 50 characters)'});
    
    const sys = 'You create multiple choice quizzes. Return ONLY valid JSON array of question objects. Format: [{"question": "...", "options": ["A", "B", "C", "D"], "answer": "correct option text", "explanation": "..."}]';
    const usr = `Generate exactly 5 multiple choice questions from this text:\n\n${notes}`;
    
    const raw = await callGemini(usr, sys);
    const q = extractJSON(raw);
    
    if(!Array.isArray(q)) {
      throw new Error('Failed to generate valid quiz questions');
    }
    
    res.json({ success:true, questions: q.slice(0,5) });
  } catch(e) { 
    console.error('Quiz generation error:', e);
    res.status(500).json({success:false, message: e.message}); 
  }
});

// Detailed analysis (uses AI)
app.post('/api/analyze-pages', upload.single('file'), async (req, res) => {
  try {
    let pages = [];
    
    if (req.file && req.file.mimetype === 'application/pdf') {
      const data = await pdfParse(req.file.buffer);
      const num = Number(data.numpages) || 1;
      pages = splitIntoPages(data.text, Math.min(10, Math.max(3, num)));
    } else {
      const raw = (req.body.notes || '').trim();
      if(!raw || raw.length < 50) return res.status(400).json({success:false, message:'No content provided (minimum 50 characters)'});
      pages = splitIntoPages(raw, 5);
    }

    const pagesPoints = [];
    const system = 'You are a study expert. Return ONLY valid JSON: {"points": ["point 1", "point 2", ...]}. Include 10-15 distinct, valuable key points.';
    
    for (const p of pages) {
      const prompt = `Analyze page ${p.page} and extract 10-15 key learning points:\n\n${p.text}`;
      
      try {
        const raw = await callGemini(prompt, system, { attempts: 2, backoffBaseMs: 2000 });
        const data = extractJSON(raw);
        let pts = (data && Array.isArray(data.points)) ? data.points : [];
        
        if(pts.length < 5) {
          pts = raw.split('\n').filter(l => l.trim().length > 10).slice(0, 15);
        }
        
        pagesPoints.push({ page: p.page, points: pts.slice(0, 15) });
      } catch (err) {
        console.error(`Page ${p.page} analysis failed:`, err.message);
        pagesPoints.push({ page: p.page, points: [`Analysis failed: ${err.message}`] });
      }
    }

    const id = uuidv4();
    const title = req.body.title || 'Detailed Study Notes';
    const url = saveImportantHtml(id, title, pagesPoints);
    res.json({ success:true, url });

  } catch (e) {
    console.error('Page analysis error:', e);
    res.status(500).json({ success:false, message: e.message });
  }
});

// Auth routes
app.post('/api/signup', async (req, res) => {
  try {
     const {username,email,password}=req.body;
     if(await User.findOne({$or:[{email},{username}]})) return res.status(400).json({message:'User already exists'});
     const u = await new User({username,email,password}).save();
     req.session.userId=u._id; req.session.username=u.username;
     res.status(201).json({success:true, user:{name:u.username}});
  } catch(e) { 
    console.error('Signup error:', e);
    res.status(500).json({message:'Signup failed'}); 
  }
});

app.post('/api/signin', async (req, res) => {
  try {
     const {email,password}=req.body;
     const u = await User.findOne({email});
     if(!u || !(await u.comparePassword(password))) return res.status(401).json({message:'Invalid credentials'});
     req.session.userId=u._id; req.session.username=u.username;
     res.json({success:true, user:{name:u.username}});
  } catch(e) { 
    console.error('Signin error:', e);
    res.status(500).json({message:'Signin failed'}); 
  }
});

app.post('/api/signout', (req,res)=>{ req.session.destroy(); res.json({success:true}); });
app.get('/api/me', (req,res)=> res.json({authenticated:!!req.session.userId, user:{name:req.session.username}}));

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📊 Rate limits: ${rateLimitTracker.maxRequestsPerMinute}/min, ${rateLimitTracker.dailyLimit}/day`);
});