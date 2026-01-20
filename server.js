/**
 * AI Brand Insights Pro - Multi-User Server
 * For Standex Scientific internal use
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const Database = require('better-sqlite3');
const { CronJob } = require('cron');
const Sentiment = require('sentiment');
const nodemailer = require('nodemailer');
const PDFDocument = require('pdfkit');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'standex-ai-brand-insights-secret-change-me';

// Initialize
const db = new Database('./data/brand_insights.db');
const sentiment = new Sentiment();

// Middleware
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// ============================================
// Database Schema
// ============================================
function initDatabase() {
    db.exec(`
        -- Users table
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            name TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            status TEXT DEFAULT 'pending',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login DATETIME
        );
        
        -- API Keys (stored securely, managed by admins)
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            platform TEXT UNIQUE NOT NULL,
            api_key TEXT NOT NULL,
            is_active INTEGER DEFAULT 1,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_by INTEGER,
            FOREIGN KEY (updated_by) REFERENCES users(id)
        );
        
        -- Brands
        CREATE TABLE IF NOT EXISTS brands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            domain TEXT,
            keywords TEXT,
            is_active INTEGER DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        
        -- Competitors
        CREATE TABLE IF NOT EXISTS competitors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            brand_id INTEGER,
            name TEXT NOT NULL,
            domain TEXT,
            FOREIGN KEY (brand_id) REFERENCES brands(id)
        );
        
        -- Queries
        CREATE TABLE IF NOT EXISTS queries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            brand_id INTEGER,
            query_text TEXT NOT NULL,
            category TEXT,
            is_active INTEGER DEFAULT 1,
            FOREIGN KEY (brand_id) REFERENCES brands(id)
        );
        
        -- Analysis Runs
        CREATE TABLE IF NOT EXISTS analysis_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            brand_id INTEGER,
            platform TEXT NOT NULL,
            run_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            run_by INTEGER,
            visibility_score INTEGER,
            mention_count INTEGER,
            citation_count INTEGER,
            sentiment_score REAL,
            status TEXT DEFAULT 'completed',
            FOREIGN KEY (brand_id) REFERENCES brands(id),
            FOREIGN KEY (run_by) REFERENCES users(id)
        );
        
        -- Query Results
        CREATE TABLE IF NOT EXISTS query_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER,
            query_id INTEGER,
            platform TEXT NOT NULL,
            response_text TEXT,
            brand_mentioned INTEGER,
            sentiment_score REAL,
            positive_keywords TEXT,
            negative_keywords TEXT,
            citations TEXT,
            FOREIGN KEY (run_id) REFERENCES analysis_runs(id),
            FOREIGN KEY (query_id) REFERENCES queries(id)
        );
        
        -- Citations
        CREATE TABLE IF NOT EXISTS citations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER,
            url TEXT NOT NULL,
            domain TEXT,
            category TEXT,
            mention_count INTEGER DEFAULT 1,
            FOREIGN KEY (run_id) REFERENCES analysis_runs(id)
        );
        
        -- Activity Log
        CREATE TABLE IF NOT EXISTS activity_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            details TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        -- Settings
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        );
        
        -- Scheduled Runs tracking
        CREATE TABLE IF NOT EXISTS scheduled_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            brand_id INTEGER,
            last_run DATETIME,
            next_run DATETIME,
            is_enabled INTEGER DEFAULT 1,
            FOREIGN KEY (brand_id) REFERENCES brands(id)
        );
        
        -- Email notification preferences
        CREATE TABLE IF NOT EXISTS email_notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            brand_id INTEGER,
            is_enabled INTEGER DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (brand_id) REFERENCES brands(id),
            UNIQUE(user_id, brand_id)
        );
    `);
    
    // Create default admin if no users exist
    const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get();
    if (userCount.count === 0) {
        const hash = bcrypt.hashSync('admin123', 10);
        db.prepare(`
            INSERT INTO users (email, password_hash, name, role, status) 
            VALUES (?, ?, ?, ?, ?)
        `).run('admin@standex.com', hash, 'Admin', 'admin', 'active');
        console.log('✅ Default admin created: admin@standex.com / admin123');
    }
    
    // Seed brands if none exist
    const brandCount = db.prepare('SELECT COUNT(*) as count FROM brands').get();
    if (brandCount.count === 0) {
        seedBrands();
    }
    
    console.log('✅ Database initialized');
}

function seedBrands() {
    const brands = [
        {
            name: 'American Biotech Supply',
            domain: 'americanbiotechsupply.com',
            keywords: 'ABS, laboratory refrigerators, medical freezers, vaccine storage, pharmacy refrigerators, blood bank refrigerators',
            queries: [
                { text: 'What is American Biotech Supply?', category: 'brand' },
                { text: 'American Biotech Supply reviews', category: 'brand' },
                { text: 'Best laboratory refrigerators', category: 'product' },
                { text: 'Best vaccine storage refrigerators', category: 'product' },
                { text: 'CDC compliant vaccine refrigerator', category: 'product' },
                { text: 'Medical grade refrigerator for pharmacy', category: 'product' },
                { text: 'Where to buy laboratory freezers', category: 'product' },
                { text: 'Blood bank refrigerator brands', category: 'product' },
                { text: 'American Biotech Supply vs Thermo Fisher', category: 'comparison' },
                { text: 'American Biotech Supply vs Helmer', category: 'comparison' },
                { text: 'Best refrigerator for vaccine storage VFC program', category: 'use_case' },
                { text: 'Laboratory cold storage solutions', category: 'use_case' }
            ],
            competitors: [
                { name: 'Thermo Fisher Scientific', domain: 'thermofisher.com' },
                { name: 'Helmer Scientific', domain: 'helmerinc.com' },
                { name: 'PHC Corporation', domain: 'phchd.com' },
                { name: 'Haier Biomedical', domain: 'haiermedical.com' }
            ]
        },
        {
            name: 'Corepoint Scientific',
            domain: 'corepointscientific.com',
            keywords: 'scientific refrigerators, laboratory freezers, ultra-low temperature freezers, plasma freezers',
            queries: [
                { text: 'What is Corepoint Scientific?', category: 'brand' },
                { text: 'Corepoint Scientific reviews', category: 'brand' },
                { text: 'Best ultra-low temperature freezers', category: 'product' },
                { text: 'Scientific refrigerator brands', category: 'product' },
                { text: 'Plasma storage freezer', category: 'product' },
                { text: 'Laboratory grade refrigerator', category: 'product' },
                { text: 'Corepoint Scientific vs Thermo Fisher', category: 'comparison' },
                { text: 'Corepoint Scientific vs PHC', category: 'comparison' },
                { text: 'Best freezer for biological samples', category: 'use_case' },
                { text: 'Research laboratory cold storage', category: 'use_case' }
            ],
            competitors: [
                { name: 'Thermo Fisher Scientific', domain: 'thermofisher.com' },
                { name: 'PHC Corporation', domain: 'phchd.com' },
                { name: 'Eppendorf', domain: 'eppendorf.com' }
            ]
        },
        {
            name: 'LabRepCo',
            domain: 'labresprod.com',
            keywords: 'laboratory equipment, lab supplies, scientific instruments, laboratory refrigerators',
            queries: [
                { text: 'What is LabRepCo?', category: 'brand' },
                { text: 'LabRepCo reviews', category: 'brand' },
                { text: 'Laboratory equipment suppliers', category: 'product' },
                { text: 'Lab refrigerator distributors', category: 'product' },
                { text: 'Scientific equipment sales', category: 'product' },
                { text: 'LabRepCo vs Fisher Scientific', category: 'comparison' },
                { text: 'Where to buy lab equipment', category: 'use_case' },
                { text: 'Laboratory equipment service and repair', category: 'use_case' }
            ],
            competitors: [
                { name: 'Fisher Scientific', domain: 'fishersci.com' },
                { name: 'VWR', domain: 'vwr.com' },
                { name: 'Cole-Parmer', domain: 'coleparmer.com' }
            ]
        },
        {
            name: 'Cryosafe',
            domain: 'cryosafe.com',
            keywords: 'cryogenic storage, liquid nitrogen dewars, cryogenic freezers, sample storage, biorepository',
            queries: [
                { text: 'What is Cryosafe?', category: 'brand' },
                { text: 'Cryosafe reviews', category: 'brand' },
                { text: 'Best cryogenic storage tanks', category: 'product' },
                { text: 'Liquid nitrogen dewars for laboratory', category: 'product' },
                { text: 'Cryogenic sample storage systems', category: 'product' },
                { text: 'LN2 freezers for biobank', category: 'product' },
                { text: 'Cryosafe vs Chart Industries', category: 'comparison' },
                { text: 'Cryosafe vs Thermo Fisher cryogenic', category: 'comparison' },
                { text: 'Best storage for stem cells and biological samples', category: 'use_case' },
                { text: 'Biorepository cryogenic equipment', category: 'use_case' }
            ],
            competitors: [
                { name: 'Chart Industries', domain: 'chartindustries.com' },
                { name: 'Thermo Fisher Scientific', domain: 'thermofisher.com' },
                { name: 'Worthington Industries', domain: 'worthingtonindustries.com' }
            ]
        },
        {
            name: 'Custom Biogenic Systems',
            domain: 'custombiogenics.com',
            keywords: 'CBS, cryogenic freezers, controlled rate freezers, isothermal dewars, LN2 storage, cell freezing',
            queries: [
                { text: 'What is Custom Biogenic Systems?', category: 'brand' },
                { text: 'Custom Biogenic Systems reviews', category: 'brand' },
                { text: 'Best controlled rate freezers', category: 'product' },
                { text: 'Isothermal liquid nitrogen freezer', category: 'product' },
                { text: 'Cryogenic storage for IVF clinics', category: 'product' },
                { text: 'Laboratory LN2 freezers', category: 'product' },
                { text: 'Custom Biogenic Systems vs Thermo Fisher', category: 'comparison' },
                { text: 'CBS cryogenic vs Chart Industries', category: 'comparison' },
                { text: 'Cell freezing equipment for research', category: 'use_case' },
                { text: 'IVF embryo cryopreservation equipment', category: 'use_case' },
                { text: 'Stem cell storage solutions', category: 'use_case' }
            ],
            competitors: [
                { name: 'Chart Industries', domain: 'chartindustries.com' },
                { name: 'Thermo Fisher Scientific', domain: 'thermofisher.com' },
                { name: 'PHC Corporation', domain: 'phchd.com' },
                { name: 'Planer', domain: 'planer.com' }
            ]
        },
        {
            name: 'Standex International',
            domain: 'standex.com',
            keywords: 'Standex, industrial manufacturing, diversified manufacturing, food service equipment, engineering technologies',
            queries: [
                { text: 'What is Standex International?', category: 'brand' },
                { text: 'Standex International company overview', category: 'brand' },
                { text: 'Standex stock analysis', category: 'brand' },
                { text: 'Diversified industrial manufacturing companies', category: 'product' },
                { text: 'Standex vs Dover Corporation', category: 'comparison' },
                { text: 'Standex vs Illinois Tool Works', category: 'comparison' },
                { text: 'Industrial conglomerate companies USA', category: 'use_case' },
                { text: 'Food service equipment manufacturers', category: 'use_case' }
            ],
            competitors: [
                { name: 'Dover Corporation', domain: 'dovercorporation.com' },
                { name: 'Illinois Tool Works', domain: 'itw.com' },
                { name: 'IDEX Corporation', domain: 'idexcorp.com' }
            ]
        },
        {
            name: 'Standex Electronics',
            domain: 'standexelectronics.com',
            keywords: 'reed switches, reed relays, magnetics, sensors, transformers, inductors',
            queries: [
                { text: 'What is Standex Electronics?', category: 'brand' },
                { text: 'Standex Electronics reviews', category: 'brand' },
                { text: 'Best reed switch manufacturers', category: 'product' },
                { text: 'Reed relay suppliers', category: 'product' },
                { text: 'Custom magnetics manufacturers', category: 'product' },
                { text: 'High reliability sensors', category: 'product' },
                { text: 'Standex Electronics vs Littelfuse', category: 'comparison' },
                { text: 'Standex Electronics vs TE Connectivity', category: 'comparison' },
                { text: 'Reed switches for automotive applications', category: 'use_case' },
                { text: 'Medical device sensor components', category: 'use_case' },
                { text: 'Industrial magnetics and transformers', category: 'use_case' }
            ],
            competitors: [
                { name: 'Littelfuse', domain: 'littelfuse.com' },
                { name: 'TE Connectivity', domain: 'te.com' },
                { name: 'Sensata Technologies', domain: 'sensata.com' },
                { name: 'Comus International', domain: 'comus-intl.com' }
            ]
        }
    ];
    
    const insertBrand = db.prepare('INSERT INTO brands (name, domain, keywords) VALUES (?, ?, ?)');
    const insertQuery = db.prepare('INSERT INTO queries (brand_id, query_text, category) VALUES (?, ?, ?)');
    const insertCompetitor = db.prepare('INSERT INTO competitors (brand_id, name, domain) VALUES (?, ?, ?)');
    
    for (const brand of brands) {
        const result = insertBrand.run(brand.name, brand.domain, brand.keywords);
        const brandId = result.lastInsertRowid;
        
        for (const query of brand.queries) {
            insertQuery.run(brandId, query.text, query.category);
        }
        
        for (const competitor of brand.competitors) {
            insertCompetitor.run(brandId, competitor.name, competitor.domain);
        }
    }
    
    console.log('✅ Seeded 7 Standex brands with queries and competitors');
}

initDatabase();

// ============================================
// Email Configuration
// ============================================
function getEmailTransporter() {
    const smtpHost = db.prepare("SELECT value FROM settings WHERE key = 'smtp_host'").get()?.value;
    const smtpPort = db.prepare("SELECT value FROM settings WHERE key = 'smtp_port'").get()?.value || '587';
    const smtpUser = db.prepare("SELECT value FROM settings WHERE key = 'smtp_user'").get()?.value;
    const smtpPass = db.prepare("SELECT value FROM settings WHERE key = 'smtp_pass'").get()?.value;
    
    if (!smtpHost || !smtpUser || !smtpPass) {
        return null;
    }
    
    return nodemailer.createTransport({
        host: smtpHost,
        port: parseInt(smtpPort),
        secure: smtpPort === '465',
        auth: {
            user: smtpUser,
            pass: smtpPass
        }
    });
}

async function sendAnalysisEmail(brand, runResults) {
    const transporter = getEmailTransporter();
    if (!transporter) {
        console.log('📧 Email not configured - skipping notification');
        return;
    }
    
    // Get users subscribed to this brand's notifications
    const subscribers = db.prepare(`
        SELECT u.email, u.name FROM email_notifications en
        JOIN users u ON en.user_id = u.id
        WHERE en.brand_id = ? AND en.is_enabled = 1 AND u.status = 'active'
    `).all(brand.id);
    
    if (subscribers.length === 0) {
        console.log(`📧 No subscribers for ${brand.name}`);
        return;
    }
    
    const fromEmail = db.prepare("SELECT value FROM settings WHERE key = 'smtp_from'").get()?.value || 'noreply@standex.com';
    
    const emailHtml = `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #0ea5e9;">AI Brand Insights Report</h2>
            <h3>${brand.name} - Weekly Analysis Complete</h3>
            
            <div style="background: #f1f5f9; padding: 20px; border-radius: 8px; margin: 20px 0;">
                <h4 style="margin-top: 0;">Summary</h4>
                <table style="width: 100%;">
                    <tr>
                        <td><strong>Visibility Score:</strong></td>
                        <td>${runResults.visibility || '--'}</td>
                    </tr>
                    <tr>
                        <td><strong>Mentions:</strong></td>
                        <td>${runResults.mentions || 0} / ${runResults.totalQueries || 0}</td>
                    </tr>
                    <tr>
                        <td><strong>Sentiment:</strong></td>
                        <td>${runResults.sentiment || '--'}%</td>
                    </tr>
                    <tr>
                        <td><strong>Citations Found:</strong></td>
                        <td>${runResults.citations || 0}</td>
                    </tr>
                </table>
            </div>
            
            <p>Log in to view the full report and detailed query results.</p>
            
            <p style="color: #64748b; font-size: 12px;">
                This is an automated weekly report from AI Brand Insights Pro.<br>
                To unsubscribe, update your notification preferences in the app.
            </p>
        </div>
    `;
    
    for (const subscriber of subscribers) {
        try {
            await transporter.sendMail({
                from: fromEmail,
                to: subscriber.email,
                subject: `AI Brand Insights: ${brand.name} Weekly Report`,
                html: emailHtml
            });
            console.log(`📧 Email sent to ${subscriber.email} for ${brand.name}`);
        } catch (err) {
            console.error(`📧 Failed to send email to ${subscriber.email}:`, err.message);
        }
    }
}

// ============================================
// Weekly Scheduled Analysis
// ============================================
async function runScheduledAnalysis() {
    console.log('\n⏰ Running scheduled weekly analysis...');
    
    const brands = db.prepare('SELECT * FROM brands WHERE is_active = 1').all();
    
    for (const brand of brands) {
        console.log(`\n📊 Analyzing: ${brand.name}`);
        
        try {
            const competitors = db.prepare('SELECT * FROM competitors WHERE brand_id = ?').all(brand.id);
            const platforms = ['chatgpt', 'gemini', 'perplexity'];
            const results = { visibility: 0, mentions: 0, totalQueries: 0, sentiment: 0, citations: 0 };
            let platformCount = 0;
            
            for (const platform of platforms) {
                const apiKey = getApiKey(platform === 'chatgpt' ? 'openai' : platform === 'gemini' ? 'google' : platform);
                if (!apiKey) continue;
                
                const queries = db.prepare('SELECT * FROM queries WHERE brand_id = ? AND is_active = 1').all(brand.id);
                if (queries.length === 0) continue;
                
                const run = db.prepare(`
                    INSERT INTO analysis_runs (brand_id, platform, run_by, status)
                    VALUES (?, ?, NULL, 'running')
                `).run(brand.id, platform);
                
                const runId = run.lastInsertRowid;
                let mentions = 0;
                let totalSentiment = 0;
                let citationCount = 0;
                
                for (const query of queries) {
                    try {
                        // Use existing query functions
                        let response;
                        switch (platform) {
                            case 'chatgpt': response = await queryChatGPT(query.query_text); break;
                            case 'gemini': response = await queryGemini(query.query_text); break;
                            case 'perplexity': response = await queryPerplexity(query.query_text); break;
                        }
                        
                        if (response.error) {
                            console.error(`  Error on query "${query.query_text}":`, response.error);
                            continue;
                        }
                        
                        // Use existing analysis function
                        const analysis = analyzeResponse(response.response, brand.name, competitors);
                        
                        if (analysis.mentioned) mentions++;
                        totalSentiment += analysis.sentimentScore;
                        
                        // Store citations
                        const citationsList = response.citations || [];
                        citationCount += citationsList.length;
                        
                        for (const url of citationsList) {
                            try {
                                const domain = new URL(url).hostname.replace('www.', '');
                                const category = categorizeDomain(domain);
                                db.prepare(`
                                    INSERT INTO citations (run_id, url, domain, category)
                                    VALUES (?, ?, ?, ?)
                                `).run(runId, url, domain, category);
                            } catch (e) {}
                        }
                        
                        db.prepare(`
                            INSERT INTO query_results (run_id, query_id, platform, response_text, brand_mentioned, sentiment_score, positive_keywords, negative_keywords, citations)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        `).run(runId, query.id, platform, response.response.substring(0, 5000), analysis.mentioned ? 1 : 0, analysis.sentimentScore,
                            JSON.stringify(analysis.positiveKeywords), JSON.stringify(analysis.negativeKeywords), JSON.stringify(citationsList));
                        
                        // Small delay between queries
                        await new Promise(resolve => setTimeout(resolve, 300));
                        
                    } catch (err) {
                        console.error(`  Error on query "${query.query_text}":`, err.message);
                    }
                }
                
                const visibilityScore = queries.length > 0 ? Math.round((mentions / queries.length) * 100) : 0;
                const avgSentiment = queries.length > 0 ? Math.round(totalSentiment / queries.length) : 50;
                
                db.prepare(`
                    UPDATE analysis_runs 
                    SET visibility_score = ?, mention_count = ?, citation_count = ?, sentiment_score = ?, status = 'completed'
                    WHERE id = ?
                `).run(visibilityScore, mentions, citationCount, avgSentiment, runId);
                
                results.visibility += visibilityScore;
                results.mentions += mentions;
                results.totalQueries += queries.length;
                results.sentiment += avgSentiment;
                results.citations += citationCount;
                platformCount++;
            }
            
            // Average across platforms
            if (platformCount > 0) {
                results.visibility = Math.round(results.visibility / platformCount);
                results.sentiment = Math.round(results.sentiment / platformCount);
            }
            
            // Update scheduled run tracking
            db.prepare(`
                INSERT INTO scheduled_runs (brand_id, last_run, next_run)
                VALUES (?, datetime('now'), datetime('now', '+7 days'))
                ON CONFLICT(brand_id) DO UPDATE SET
                    last_run = datetime('now'),
                    next_run = datetime('now', '+7 days')
            `).run(brand.id);
            
            // Send email notification
            await sendAnalysisEmail(brand, results);
            
            console.log(`  ✅ ${brand.name}: Visibility ${results.visibility}%, ${results.mentions}/${results.totalQueries} mentions`);
            
        } catch (err) {
            console.error(`  ❌ Error analyzing ${brand.name}:`, err.message);
        }
    }
    
    console.log('\n✅ Scheduled analysis complete\n');
}

// Schedule weekly analysis - runs every Sunday at 2:00 AM
const weeklyAnalysisJob = new CronJob(
    '0 2 * * 0', // Sunday at 2 AM
    runScheduledAnalysis,
    null,
    false, // Don't start immediately
    'America/New_York'
);

// ============================================
// Authentication Middleware
// ============================================
function authenticateToken(req, res, next) {
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = db.prepare('SELECT id, email, name, role, status FROM users WHERE id = ?').get(decoded.userId);
        
        if (!user || user.status !== 'active') {
            return res.status(401).json({ error: 'Account not active' });
        }
        
        req.user = user;
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Invalid token' });
    }
}

function requireAdmin(req, res, next) {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
}

function logActivity(userId, action, details = null) {
    db.prepare('INSERT INTO activity_log (user_id, action, details) VALUES (?, ?, ?)').run(
        userId, action, details ? JSON.stringify(details) : null
    );
}

// ============================================
// Auth Routes
// ============================================
app.post('/api/auth/register', (req, res) => {
    const { email, password, name } = req.body;
    
    if (!email || !password || !name) {
        return res.status(400).json({ error: 'Email, password, and name required' });
    }
    
    const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (existing) {
        return res.status(400).json({ error: 'Email already registered' });
    }
    
    const hash = bcrypt.hashSync(password, 10);
    const result = db.prepare(`
        INSERT INTO users (email, password_hash, name, status) VALUES (?, ?, ?, 'pending')
    `).run(email, hash, name);
    
    logActivity(result.lastInsertRowid, 'user_registered', { email });
    
    res.json({ 
        message: 'Registration successful. Please wait for admin approval.',
        status: 'pending'
    });
});

app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;
    
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    
    if (!user || !bcrypt.compareSync(password, user.password_hash)) {
        return res.status(401).json({ error: 'Invalid email or password' });
    }
    
    if (user.status === 'pending') {
        return res.status(403).json({ error: 'Account pending approval' });
    }
    
    if (user.status === 'disabled') {
        return res.status(403).json({ error: 'Account disabled' });
    }
    
    // Update last login
    db.prepare('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?').run(user.id);
    
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
    
    res.cookie('token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });
    
    logActivity(user.id, 'user_login');
    
    res.json({
        user: {
            id: user.id,
            email: user.email,
            name: user.name,
            role: user.role
        },
        token
    });
});

app.post('/api/auth/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ message: 'Logged out' });
});

app.get('/api/auth/me', authenticateToken, (req, res) => {
    res.json({ user: req.user });
});

// ============================================
// Admin Routes - User Management
// ============================================
app.get('/api/admin/users', authenticateToken, requireAdmin, (req, res) => {
    const users = db.prepare(`
        SELECT id, email, name, role, status, created_at, last_login 
        FROM users ORDER BY created_at DESC
    `).all();
    res.json(users);
});

app.put('/api/admin/users/:id/approve', authenticateToken, requireAdmin, (req, res) => {
    db.prepare('UPDATE users SET status = ? WHERE id = ?').run('active', req.params.id);
    logActivity(req.user.id, 'user_approved', { userId: req.params.id });
    res.json({ message: 'User approved' });
});

app.put('/api/admin/users/:id/disable', authenticateToken, requireAdmin, (req, res) => {
    if (req.params.id == req.user.id) {
        return res.status(400).json({ error: 'Cannot disable yourself' });
    }
    db.prepare('UPDATE users SET status = ? WHERE id = ?').run('disabled', req.params.id);
    logActivity(req.user.id, 'user_disabled', { userId: req.params.id });
    res.json({ message: 'User disabled' });
});

app.put('/api/admin/users/:id/role', authenticateToken, requireAdmin, (req, res) => {
    const { role } = req.body;
    if (!['user', 'admin'].includes(role)) {
        return res.status(400).json({ error: 'Invalid role' });
    }
    db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, req.params.id);
    logActivity(req.user.id, 'user_role_changed', { userId: req.params.id, role });
    res.json({ message: 'Role updated' });
});

app.delete('/api/admin/users/:id', authenticateToken, requireAdmin, (req, res) => {
    if (req.params.id == req.user.id) {
        return res.status(400).json({ error: 'Cannot delete yourself' });
    }
    db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
    logActivity(req.user.id, 'user_deleted', { userId: req.params.id });
    res.json({ message: 'User deleted' });
});

// ============================================
// Admin Routes - API Keys
// ============================================
app.get('/api/admin/api-keys', authenticateToken, requireAdmin, (req, res) => {
    const keys = db.prepare(`
        SELECT id, platform, 
               CASE WHEN api_key IS NOT NULL THEN '••••••••' || SUBSTR(api_key, -4) ELSE NULL END as api_key_masked,
               is_active, updated_at
        FROM api_keys
    `).all();
    res.json(keys);
});

app.post('/api/admin/api-keys', authenticateToken, requireAdmin, (req, res) => {
    const { platform, api_key } = req.body;
    
    if (!['openai', 'google', 'perplexity'].includes(platform)) {
        return res.status(400).json({ error: 'Invalid platform' });
    }
    
    db.prepare(`
        INSERT INTO api_keys (platform, api_key, updated_by) 
        VALUES (?, ?, ?)
        ON CONFLICT(platform) DO UPDATE SET 
            api_key = excluded.api_key,
            updated_at = CURRENT_TIMESTAMP,
            updated_by = excluded.updated_by
    `).run(platform, api_key, req.user.id);
    
    logActivity(req.user.id, 'api_key_updated', { platform });
    res.json({ message: 'API key saved' });
});

app.get('/api/admin/api-keys/status', authenticateToken, (req, res) => {
    const keys = db.prepare('SELECT platform, is_active FROM api_keys').all();
    const status = {
        openai: false,
        google: false,
        perplexity: false
    };
    keys.forEach(k => {
        status[k.platform] = k.is_active === 1;
    });
    res.json(status);
});

// ============================================
// Brand Routes
// ============================================
app.get('/api/brands', authenticateToken, (req, res) => {
    const brands = db.prepare('SELECT * FROM brands WHERE is_active = 1 ORDER BY name').all();
    res.json(brands);
});

app.get('/api/brands/:id', authenticateToken, (req, res) => {
    const brand = db.prepare('SELECT * FROM brands WHERE id = ?').get(req.params.id);
    if (!brand) {
        return res.status(404).json({ error: 'Brand not found' });
    }
    
    const competitors = db.prepare('SELECT * FROM competitors WHERE brand_id = ?').all(req.params.id);
    const queries = db.prepare('SELECT * FROM queries WHERE brand_id = ? AND is_active = 1').all(req.params.id);
    
    res.json({ ...brand, competitors, queries });
});

app.post('/api/brands', authenticateToken, requireAdmin, (req, res) => {
    const { name, domain, keywords } = req.body;
    const result = db.prepare('INSERT INTO brands (name, domain, keywords) VALUES (?, ?, ?)').run(
        name, domain, JSON.stringify(keywords || [])
    );
    logActivity(req.user.id, 'brand_created', { name });
    res.json({ id: result.lastInsertRowid, name, domain });
});

app.post('/api/brands/:id/competitors', authenticateToken, requireAdmin, (req, res) => {
    const { name, domain } = req.body;
    const result = db.prepare('INSERT INTO competitors (brand_id, name, domain) VALUES (?, ?, ?)').run(
        req.params.id, name, domain
    );
    res.json({ id: result.lastInsertRowid, name, domain });
});

app.post('/api/brands/:id/queries', authenticateToken, requireAdmin, (req, res) => {
    const { query_text, category } = req.body;
    const result = db.prepare('INSERT INTO queries (brand_id, query_text, category) VALUES (?, ?, ?)').run(
        req.params.id, query_text, category || 'general'
    );
    res.json({ id: result.lastInsertRowid, query_text, category });
});

// ============================================
// Analysis Routes
// ============================================

// Get API key from database
function getApiKey(platform) {
    const row = db.prepare('SELECT api_key FROM api_keys WHERE platform = ? AND is_active = 1').get(platform);
    return row?.api_key;
}

// Query functions
async function queryChatGPT(prompt) {
    const apiKey = getApiKey('openai');
    if (!apiKey) return { error: 'OpenAI not configured', response: null };
    
    try {
        const { OpenAI } = require('openai');
        const openai = new OpenAI({ apiKey });
        const completion = await openai.chat.completions.create({
            model: "gpt-4-turbo-preview",
            messages: [{ role: "user", content: prompt }],
            max_tokens: 1000
        });
        return { response: completion.choices[0].message.content };
    } catch (error) {
        return { error: error.message, response: null };
    }
}

async function queryGemini(prompt) {
    const apiKey = getApiKey('google');
    if (!apiKey) return { error: 'Gemini not configured', response: null };
    
    try {
        const { GoogleGenerativeAI } = require('@google/generative-ai');
        const genAI = new GoogleGenerativeAI(apiKey);
        const model = genAI.getGenerativeModel({ model: "gemini-pro" });
        const result = await model.generateContent(prompt);
        return { response: result.response.text() };
    } catch (error) {
        return { error: error.message, response: null };
    }
}

async function queryPerplexity(prompt) {
    const apiKey = getApiKey('perplexity');
    if (!apiKey) return { error: 'Perplexity not configured', response: null };
    
    try {
        const response = await fetch('https://api.perplexity.ai/chat/completions', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${apiKey}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                model: 'llama-3.1-sonar-large-128k-online',
                messages: [{ role: 'user', content: prompt }],
                return_citations: true
            })
        });
        const data = await response.json();
        return { 
            response: data.choices?.[0]?.message?.content,
            citations: data.citations || []
        };
    } catch (error) {
        return { error: error.message, response: null };
    }
}

function analyzeResponse(response, brandName, competitors = []) {
    if (!response) return { mentioned: false, sentimentScore: 50, positiveKeywords: [], negativeKeywords: [], competitorMentions: {} };
    
    const lowerResponse = response.toLowerCase();
    const mentioned = lowerResponse.includes(brandName.toLowerCase());
    const result = sentiment.analyze(response);
    const sentimentScore = Math.round(((result.comparative + 5) / 10) * 100);
    
    const competitorMentions = {};
    competitors.forEach(comp => {
        if (lowerResponse.includes(comp.name.toLowerCase())) {
            competitorMentions[comp.name] = (lowerResponse.match(new RegExp(comp.name.toLowerCase(), 'g')) || []).length;
        }
    });
    
    return {
        mentioned,
        sentimentScore,
        positiveKeywords: result.positive.slice(0, 8),
        negativeKeywords: result.negative.slice(0, 8),
        competitorMentions
    };
}

function categorizeDomain(domain) {
    const categories = {
        'Own Site': [
            'americanbiotechsupply.com', 
            'corepointscientific.com',
            'labresprod.com',
            'cryosafe.com',
            'custombiogenics.com',
            'standex.com',
            'standexelectronics.com'
        ],
        'Industry': ['labmanager.com', 'labtechonline.com', 'laboratoryequipment.com'],
        'Comparison': ['biocompare.com', 'selectscience.net', 'thomasnet.com'],
        'Academic': ['sciencedirect.com', 'pubmed.ncbi.nlm.nih.gov', 'nature.com'],
        'E-commerce': ['amazon.com', 'fishersci.com', 'vwr.com'],
        'Forum': ['reddit.com', 'quora.com']
    };
    
    for (const [category, domains] of Object.entries(categories)) {
        if (domains.some(d => domain.includes(d))) return category;
    }
    return 'Other';
}

// Run analysis endpoint
app.post('/api/brands/:id/analyze', authenticateToken, async (req, res) => {
    const { platforms = ['chatgpt', 'gemini', 'perplexity'] } = req.body;
    const brandId = req.params.id;
    
    const brand = db.prepare('SELECT * FROM brands WHERE id = ?').get(brandId);
    if (!brand) return res.status(404).json({ error: 'Brand not found' });
    
    const competitors = db.prepare('SELECT * FROM competitors WHERE brand_id = ?').all(brandId);
    const queries = db.prepare('SELECT * FROM queries WHERE brand_id = ? AND is_active = 1').all(brandId);
    
    if (queries.length === 0) {
        return res.status(400).json({ error: 'No queries configured' });
    }
    
    logActivity(req.user.id, 'analysis_started', { brandId, platforms });
    
    const results = { brand: brand.name, platforms: {}, summary: {} };
    
    for (const platform of platforms) {
        const platformResults = { queries: [], mentions: 0, totalSentiment: 0, citations: [] };
        
        const run = db.prepare(
            'INSERT INTO analysis_runs (brand_id, platform, run_by, status) VALUES (?, ?, ?, ?)'
        ).run(brandId, platform, req.user.id, 'running');
        const runId = run.lastInsertRowid;
        
        for (const query of queries) {
            let response;
            switch (platform) {
                case 'chatgpt': response = await queryChatGPT(query.query_text); break;
                case 'gemini': response = await queryGemini(query.query_text); break;
                case 'perplexity': response = await queryPerplexity(query.query_text); break;
            }
            
            if (response.error) {
                platformResults.queries.push({ query: query.query_text, error: response.error, mentioned: false });
                continue;
            }
            
            const analysis = analyzeResponse(response.response, brand.name, competitors);
            const citations = (response.citations || []).map(url => {
                try {
                    const domain = new URL(url).hostname.replace('www.', '');
                    return { url, domain, category: categorizeDomain(domain) };
                } catch { return null; }
            }).filter(Boolean);
            
            db.prepare(`
                INSERT INTO query_results (run_id, query_id, platform, response_text, brand_mentioned, sentiment_score, positive_keywords, negative_keywords, citations)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            `).run(runId, query.id, platform, response.response, analysis.mentioned ? 1 : 0, analysis.sentimentScore,
                JSON.stringify(analysis.positiveKeywords), JSON.stringify(analysis.negativeKeywords), JSON.stringify(citations));
            
            citations.forEach(c => {
                db.prepare('INSERT INTO citations (run_id, url, domain, category) VALUES (?, ?, ?, ?)').run(runId, c.url, c.domain, c.category);
            });
            
            if (analysis.mentioned) platformResults.mentions++;
            platformResults.totalSentiment += analysis.sentimentScore;
            platformResults.citations.push(...citations);
            
            platformResults.queries.push({
                query: query.query_text,
                mentioned: analysis.mentioned,
                sentimentScore: analysis.sentimentScore,
                positiveKeywords: analysis.positiveKeywords,
                negativeKeywords: analysis.negativeKeywords,
                competitorMentions: analysis.competitorMentions,
                citations
            });
            
            await new Promise(resolve => setTimeout(resolve, 300));
        }
        
        const avgSentiment = platformResults.totalSentiment / queries.length;
        const mentionRate = platformResults.mentions / queries.length;
        const visibilityScore = Math.round(mentionRate * 50 + avgSentiment * 0.5);
        
        db.prepare(`
            UPDATE analysis_runs SET visibility_score = ?, mention_count = ?, citation_count = ?, sentiment_score = ?, status = ?
            WHERE id = ?
        `).run(visibilityScore, platformResults.mentions, platformResults.citations.length, avgSentiment, 'completed', runId);
        
        results.platforms[platform] = {
            runId,
            queries: platformResults.queries,
            summary: {
                mentions: platformResults.mentions,
                totalQueries: queries.length,
                mentionRate: Math.round(mentionRate * 100),
                avgSentiment: Math.round(avgSentiment),
                citationCount: platformResults.citations.length,
                visibilityScore
            }
        };
    }
    
    const platformCount = Object.keys(results.platforms).length;
    results.summary = {
        overallVisibility: Math.round(Object.values(results.platforms).reduce((sum, p) => sum + p.summary.visibilityScore, 0) / platformCount),
        totalMentions: Object.values(results.platforms).reduce((sum, p) => sum + p.summary.mentions, 0),
        avgSentiment: Math.round(Object.values(results.platforms).reduce((sum, p) => sum + p.summary.avgSentiment, 0) / platformCount)
    };
    
    logActivity(req.user.id, 'analysis_completed', { brandId, platforms, summary: results.summary });
    
    res.json(results);
});

// Get analysis history
app.get('/api/brands/:id/history', authenticateToken, (req, res) => {
    const { limit = 50 } = req.query;
    const runs = db.prepare(`
        SELECT ar.*, u.name as run_by_name 
        FROM analysis_runs ar
        LEFT JOIN users u ON ar.run_by = u.id
        WHERE ar.brand_id = ?
        ORDER BY ar.run_date DESC
        LIMIT ?
    `).all(req.params.id, parseInt(limit));
    res.json(runs);
});

// Get run details
app.get('/api/runs/:id', authenticateToken, (req, res) => {
    const run = db.prepare(`
        SELECT ar.*, b.name as brand_name, u.name as run_by_name
        FROM analysis_runs ar
        JOIN brands b ON ar.brand_id = b.id
        LEFT JOIN users u ON ar.run_by = u.id
        WHERE ar.id = ?
    `).get(req.params.id);
    
    if (!run) return res.status(404).json({ error: 'Run not found' });
    
    const results = db.prepare(`
        SELECT qr.*, q.query_text
        FROM query_results qr
        JOIN queries q ON qr.query_id = q.id
        WHERE qr.run_id = ?
    `).all(req.params.id);
    
    const citations = db.prepare('SELECT * FROM citations WHERE run_id = ?').all(req.params.id);
    
    res.json({ run, results, citations });
});

// Auto-detect competitors for a brand
app.post('/api/brands/:id/detect-competitors', authenticateToken, async (req, res) => {
    const brandId = req.params.id;
    const brand = db.prepare('SELECT * FROM brands WHERE id = ?').get(brandId);
    
    if (!brand) {
        return res.status(404).json({ error: 'Brand not found' });
    }
    
    const { industry } = req.body;
    const industryText = industry || 'their industry';
    
    const prompt = `Who are the main competitors of ${brand.name} in ${industryText}? 
List only company names, one per line. 
Include 5-10 direct competitors. 
Format: Just the company names, nothing else.`;
    
    const detectedCompetitors = {};
    const platforms = [];
    
    // Query each platform
    if (getApiKey('openai')) {
        platforms.push('chatgpt');
        try {
            const result = await queryChatGPT(prompt);
            if (result.response) {
                extractCompanyNames(result.response).forEach(name => {
                    if (!detectedCompetitors[name]) detectedCompetitors[name] = { name, platforms: [], count: 0 };
                    detectedCompetitors[name].platforms.push('ChatGPT');
                    detectedCompetitors[name].count++;
                });
            }
        } catch (e) { console.error('ChatGPT competitor detection error:', e); }
    }
    
    if (getApiKey('google')) {
        platforms.push('gemini');
        try {
            const result = await queryGemini(prompt);
            if (result.response) {
                extractCompanyNames(result.response).forEach(name => {
                    if (!detectedCompetitors[name]) detectedCompetitors[name] = { name, platforms: [], count: 0 };
                    detectedCompetitors[name].platforms.push('Gemini');
                    detectedCompetitors[name].count++;
                });
            }
        } catch (e) { console.error('Gemini competitor detection error:', e); }
    }
    
    if (getApiKey('perplexity')) {
        platforms.push('perplexity');
        try {
            const result = await queryPerplexity(prompt);
            if (result.response) {
                extractCompanyNames(result.response).forEach(name => {
                    if (!detectedCompetitors[name]) detectedCompetitors[name] = { name, platforms: [], count: 0 };
                    detectedCompetitors[name].platforms.push('Perplexity');
                    detectedCompetitors[name].count++;
                });
            }
        } catch (e) { console.error('Perplexity competitor detection error:', e); }
    }
    
    if (platforms.length === 0) {
        return res.status(400).json({ error: 'No API keys configured. Add API keys in Admin → API Keys.' });
    }
    
    // Filter out the brand itself and sort by count
    const competitors = Object.values(detectedCompetitors)
        .filter(c => !c.name.toLowerCase().includes(brand.name.toLowerCase()) && 
                    !brand.name.toLowerCase().includes(c.name.toLowerCase()))
        .sort((a, b) => b.count - a.count)
        .slice(0, 15);
    
    // Get existing competitors to mark duplicates
    const existing = db.prepare('SELECT name FROM competitors WHERE brand_id = ?').all(brandId);
    const existingNames = existing.map(e => e.name.toLowerCase());
    
    competitors.forEach(c => {
        c.alreadyAdded = existingNames.some(e => 
            e.includes(c.name.toLowerCase()) || c.name.toLowerCase().includes(e)
        );
    });
    
    logActivity(req.user.id, 'competitors_detected', { brandId, count: competitors.length });
    
    res.json({ 
        brand: brand.name,
        platformsQueried: platforms.length,
        competitors 
    });
});

// Helper function to extract company names from AI response
function extractCompanyNames(text) {
    const names = [];
    const lines = text.split('\n');
    
    for (let line of lines) {
        // Clean up the line
        let cleaned = line
            .replace(/^\d+[\.\)]\s*/, '')  // Remove numbering like "1." or "1)"
            .replace(/^[-•*]\s*/, '')       // Remove bullet points
            .replace(/\*\*/g, '')           // Remove markdown bold
            .replace(/\([^)]*\)/g, '')      // Remove parenthetical notes
            .replace(/[-–—].*$/, '')        // Remove descriptions after dashes
            .replace(/[:,].*$/, '')         // Remove descriptions after colons/commas
            .trim();
        
        // Skip empty lines, headers, and explanatory text
        if (!cleaned || 
            cleaned.length < 3 || 
            cleaned.length > 50 ||
            cleaned.toLowerCase().includes('competitor') ||
            cleaned.toLowerCase().includes('include') ||
            cleaned.toLowerCase().includes('here are') ||
            cleaned.toLowerCase().includes('the main') ||
            cleaned.toLowerCase().includes('such as') ||
            cleaned.toLowerCase().startsWith('note')) {
            continue;
        }
        
        // Check if it looks like a company name (starts with capital, reasonable length)
        if (/^[A-Z]/.test(cleaned) && cleaned.split(' ').length <= 6) {
            names.push(cleaned);
        }
    }
    
    return [...new Set(names)]; // Remove duplicates
}

// Bulk add competitors
app.post('/api/brands/:id/competitors/bulk', authenticateToken, requireAdmin, (req, res) => {
    const { competitors } = req.body;
    const brandId = req.params.id;
    
    if (!competitors || !Array.isArray(competitors)) {
        return res.status(400).json({ error: 'competitors array required' });
    }
    
    const insert = db.prepare('INSERT INTO competitors (brand_id, name, domain) VALUES (?, ?, ?)');
    const added = [];
    
    for (const comp of competitors) {
        try {
            insert.run(brandId, comp.name, comp.domain || '');
            added.push(comp.name);
        } catch (e) {
            // Skip duplicates
        }
    }
    
    logActivity(req.user.id, 'competitors_bulk_added', { brandId, count: added.length });
    
    res.json({ added, count: added.length });
});

// Auto-generate queries for a brand
app.post('/api/brands/:id/generate-queries', authenticateToken, async (req, res) => {
    const brandId = req.params.id;
    const brand = db.prepare('SELECT * FROM brands WHERE id = ?').get(brandId);
    
    if (!brand) {
        return res.status(404).json({ error: 'Brand not found' });
    }
    
    const { industry, productTypes } = req.body;
    const competitors = db.prepare('SELECT name FROM competitors WHERE brand_id = ? LIMIT 3').all(brandId);
    
    // Generate smart queries based on the brand
    const queries = [
        // Brand awareness
        { text: `What is ${brand.name}?`, category: 'brand' },
        { text: `${brand.name} reviews`, category: 'brand' },
        { text: `Is ${brand.name} a good company?`, category: 'brand' },
        
        // Product queries (if industry provided)
        ...(industry ? [
            { text: `Best ${industry} companies`, category: 'product' },
            { text: `Where to buy ${industry}`, category: 'product' },
            { text: `Top ${industry} suppliers`, category: 'product' },
        ] : []),
        
        // Product type queries
        ...(productTypes ? productTypes.split(',').map(p => ({
            text: `Best ${p.trim()} for laboratories`,
            category: 'product'
        })) : []),
        
        // Competitor comparisons
        ...competitors.slice(0, 2).map(c => ({
            text: `${brand.name} vs ${c.name}`,
            category: 'comparison'
        })),
    ];
    
    // Check existing queries to avoid duplicates
    const existing = db.prepare('SELECT query_text FROM queries WHERE brand_id = ?').all(brandId);
    const existingTexts = existing.map(e => e.query_text.toLowerCase());
    
    const newQueries = queries.filter(q => 
        !existingTexts.some(e => e.includes(q.text.toLowerCase()) || q.text.toLowerCase().includes(e))
    );
    
    res.json({ suggestedQueries: newQueries });
});

// Get competitor ranking
app.get('/api/brands/:id/ranking', authenticateToken, (req, res) => {
    const { days = 30 } = req.query;
    const brandId = req.params.id;
    
    const brand = db.prepare('SELECT * FROM brands WHERE id = ?').get(brandId);
    const competitors = db.prepare('SELECT * FROM competitors WHERE brand_id = ?').all(brandId);
    
    const results = db.prepare(`
        SELECT qr.response_text, qr.brand_mentioned
        FROM query_results qr
        JOIN analysis_runs ar ON qr.run_id = ar.id
        WHERE ar.brand_id = ? AND ar.run_date > datetime('now', '-${parseInt(days)} days')
    `).all(brandId);
    
    const mentionCounts = { [brand.name]: 0 };
    competitors.forEach(c => mentionCounts[c.name] = 0);
    
    results.forEach(r => {
        if (r.brand_mentioned) mentionCounts[brand.name]++;
        competitors.forEach(c => {
            if (r.response_text?.toLowerCase().includes(c.name.toLowerCase())) {
                mentionCounts[c.name]++;
            }
        });
    });
    
    const ranking = Object.entries(mentionCounts)
        .map(([name, mentions]) => ({ name, mentions, isYou: name === brand.name }))
        .sort((a, b) => b.mentions - a.mentions)
        .map((item, i) => ({ ...item, rank: i + 1 }));
    
    res.json({ ranking, totalResults: results.length });
});

// Dashboard stats
app.get('/api/dashboard', authenticateToken, (req, res) => {
    const brands = db.prepare('SELECT COUNT(*) as count FROM brands WHERE is_active = 1').get();
    const recentRuns = db.prepare(`
        SELECT ar.*, b.name as brand_name, u.name as run_by_name
        FROM analysis_runs ar
        JOIN brands b ON ar.brand_id = b.id
        LEFT JOIN users u ON ar.run_by = u.id
        ORDER BY ar.run_date DESC
        LIMIT 10
    `).all();
    
    const avgScores = db.prepare(`
        SELECT platform, AVG(visibility_score) as avg_score, AVG(sentiment_score) as avg_sentiment
        FROM analysis_runs
        WHERE run_date > datetime('now', '-30 days')
        GROUP BY platform
    `).all();
    
    res.json({ brandCount: brands.count, recentRuns, avgScores });
});

// Activity log (admin)
app.get('/api/admin/activity', authenticateToken, requireAdmin, (req, res) => {
    const { limit = 100 } = req.query;
    const logs = db.prepare(`
        SELECT al.*, u.name as user_name, u.email
        FROM activity_log al
        LEFT JOIN users u ON al.user_id = u.id
        ORDER BY al.created_at DESC
        LIMIT ?
    `).all(parseInt(limit));
    res.json(logs);
});

// ============================================
// PDF Report Generation
// ============================================
app.get('/api/brands/:id/report/pdf', authenticateToken, async (req, res) => {
    const brandId = req.params.id;
    const brand = db.prepare('SELECT * FROM brands WHERE id = ?').get(brandId);
    
    if (!brand) {
        return res.status(404).json({ error: 'Brand not found' });
    }
    
    // Get latest analysis data
    const latestRuns = db.prepare(`
        SELECT ar.*, u.name as run_by_name
        FROM analysis_runs ar
        LEFT JOIN users u ON ar.run_by = u.id
        WHERE ar.brand_id = ?
        ORDER BY ar.run_date DESC
        LIMIT 10
    `).all(brandId);
    
    const competitors = db.prepare('SELECT * FROM competitors WHERE brand_id = ?').all(brandId);
    const queries = db.prepare('SELECT * FROM queries WHERE brand_id = ? AND is_active = 1').all(brandId);
    
    // Get latest query results
    const latestRun = latestRuns[0];
    let queryResults = [];
    if (latestRun) {
        queryResults = db.prepare(`
            SELECT qr.*, q.query_text, q.category
            FROM query_results qr
            JOIN queries q ON qr.query_id = q.id
            WHERE qr.run_id = ?
        `).all(latestRun.id);
    }
    
    // Create PDF
    const doc = new PDFDocument({ margin: 50 });
    
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${brand.name.replace(/[^a-z0-9]/gi, '_')}_Report.pdf"`);
    
    doc.pipe(res);
    
    // Header
    doc.fontSize(24).fillColor('#0ea5e9').text('AI Brand Insights Report', { align: 'center' });
    doc.moveDown(0.5);
    doc.fontSize(18).fillColor('#1e293b').text(brand.name, { align: 'center' });
    doc.moveDown(0.3);
    doc.fontSize(10).fillColor('#64748b').text(`Generated: ${new Date().toLocaleString()}`, { align: 'center' });
    doc.moveDown(1.5);
    
    // Summary Box
    if (latestRun) {
        doc.fontSize(14).fillColor('#1e293b').text('Latest Analysis Summary', { underline: true });
        doc.moveDown(0.5);
        
        doc.fontSize(11).fillColor('#334155');
        doc.text(`Platform: ${latestRun.platform.toUpperCase()}`);
        doc.text(`Date: ${new Date(latestRun.run_date).toLocaleString()}`);
        doc.text(`Visibility Score: ${latestRun.visibility_score}%`);
        doc.text(`Mentions: ${latestRun.mention_count} / ${queries.length}`);
        doc.text(`Sentiment: ${Math.round(latestRun.sentiment_score)}%`);
        doc.text(`Citations Found: ${latestRun.citation_count || 0}`);
        doc.moveDown(1.5);
    }
    
    // Query Results
    doc.fontSize(14).fillColor('#1e293b').text('Query Results', { underline: true });
    doc.moveDown(0.5);
    
    if (queryResults.length > 0) {
        for (const result of queryResults) {
            const status = result.brand_mentioned ? '✓ Found' : '✗ Not Found';
            const statusColor = result.brand_mentioned ? '#10b981' : '#ef4444';
            
            doc.fontSize(10).fillColor('#334155').text(`• ${result.query_text}`);
            doc.fontSize(9).fillColor(statusColor).text(`  ${status} | Sentiment: ${Math.round(result.sentiment_score)}%`);
            doc.moveDown(0.3);
        }
    } else {
        doc.fontSize(10).fillColor('#64748b').text('No query results available. Run an analysis first.');
    }
    doc.moveDown(1);
    
    // Competitors
    doc.fontSize(14).fillColor('#1e293b').text('Tracked Competitors', { underline: true });
    doc.moveDown(0.5);
    
    if (competitors.length > 0) {
        for (const comp of competitors) {
            doc.fontSize(10).fillColor('#334155').text(`• ${comp.name}${comp.domain ? ` (${comp.domain})` : ''}`);
        }
    } else {
        doc.fontSize(10).fillColor('#64748b').text('No competitors configured.');
    }
    doc.moveDown(1);
    
    // Historical Data
    if (latestRuns.length > 1) {
        doc.addPage();
        doc.fontSize(14).fillColor('#1e293b').text('Analysis History', { underline: true });
        doc.moveDown(0.5);
        
        for (const run of latestRuns) {
            doc.fontSize(10).fillColor('#334155');
            doc.text(`${new Date(run.run_date).toLocaleDateString()} - ${run.platform.toUpperCase()}: Score ${run.visibility_score}%, ${run.mention_count} mentions`);
        }
    }
    
    // Footer
    doc.fontSize(8).fillColor('#94a3b8').text(
        'AI Brand Insights Pro - Standex Scientific',
        50,
        doc.page.height - 50,
        { align: 'center' }
    );
    
    doc.end();
    
    logActivity(req.user.id, 'pdf_generated', { brandId, brandName: brand.name });
});

// ============================================
// Email Settings (Admin)
// ============================================
app.get('/api/admin/email-settings', authenticateToken, requireAdmin, (req, res) => {
    const settings = {};
    const keys = ['smtp_host', 'smtp_port', 'smtp_user', 'smtp_from'];
    
    for (const key of keys) {
        const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
        settings[key] = row?.value || '';
    }
    
    // Check if password is set (don't return actual password)
    const hasPassword = !!db.prepare("SELECT value FROM settings WHERE key = 'smtp_pass'").get()?.value;
    settings.smtp_pass_set = hasPassword;
    
    res.json(settings);
});

app.post('/api/admin/email-settings', authenticateToken, requireAdmin, (req, res) => {
    const { smtp_host, smtp_port, smtp_user, smtp_pass, smtp_from } = req.body;
    
    const upsert = db.prepare(`
        INSERT INTO settings (key, value) VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
    `);
    
    if (smtp_host !== undefined) upsert.run('smtp_host', smtp_host);
    if (smtp_port !== undefined) upsert.run('smtp_port', smtp_port);
    if (smtp_user !== undefined) upsert.run('smtp_user', smtp_user);
    if (smtp_pass && smtp_pass.trim()) upsert.run('smtp_pass', smtp_pass);
    if (smtp_from !== undefined) upsert.run('smtp_from', smtp_from);
    
    logActivity(req.user.id, 'email_settings_updated');
    
    res.json({ message: 'Email settings saved' });
});

app.post('/api/admin/email-settings/test', authenticateToken, requireAdmin, async (req, res) => {
    const transporter = getEmailTransporter();
    
    if (!transporter) {
        return res.status(400).json({ error: 'Email not configured. Please set SMTP settings first.' });
    }
    
    try {
        await transporter.sendMail({
            from: db.prepare("SELECT value FROM settings WHERE key = 'smtp_from'").get()?.value || 'test@standex.com',
            to: req.user.email,
            subject: 'AI Brand Insights - Test Email',
            html: '<h2>Test Successful!</h2><p>Your email configuration is working correctly.</p>'
        });
        
        res.json({ message: `Test email sent to ${req.user.email}` });
    } catch (err) {
        res.status(500).json({ error: `Email test failed: ${err.message}` });
    }
});

// ============================================
// Notification Preferences
// ============================================
app.get('/api/notifications', authenticateToken, (req, res) => {
    const notifications = db.prepare(`
        SELECT en.*, b.name as brand_name
        FROM email_notifications en
        JOIN brands b ON en.brand_id = b.id
        WHERE en.user_id = ?
    `).all(req.user.id);
    
    res.json(notifications);
});

app.post('/api/notifications/:brandId', authenticateToken, (req, res) => {
    const { brandId } = req.params;
    const { enabled } = req.body;
    
    db.prepare(`
        INSERT INTO email_notifications (user_id, brand_id, is_enabled)
        VALUES (?, ?, ?)
        ON CONFLICT(user_id, brand_id) DO UPDATE SET is_enabled = excluded.is_enabled
    `).run(req.user.id, brandId, enabled ? 1 : 0);
    
    res.json({ message: 'Notification preference saved' });
});

// ============================================
// Scheduled Analysis Management
// ============================================
app.get('/api/admin/scheduled-runs', authenticateToken, requireAdmin, (req, res) => {
    const runs = db.prepare(`
        SELECT sr.*, b.name as brand_name
        FROM scheduled_runs sr
        JOIN brands b ON sr.brand_id = b.id
        ORDER BY sr.next_run ASC
    `).all();
    
    res.json({
        runs,
        schedule: 'Weekly on Sunday at 2:00 AM EST',
        isRunning: weeklyAnalysisJob.running
    });
});

app.post('/api/admin/scheduled-runs/toggle', authenticateToken, requireAdmin, (req, res) => {
    if (weeklyAnalysisJob.running) {
        weeklyAnalysisJob.stop();
        res.json({ message: 'Weekly scheduled analysis stopped', isRunning: false });
    } else {
        weeklyAnalysisJob.start();
        res.json({ message: 'Weekly scheduled analysis started', isRunning: true });
    }
    
    logActivity(req.user.id, 'scheduled_analysis_toggled', { running: weeklyAnalysisJob.running });
});

app.post('/api/admin/scheduled-runs/run-now', authenticateToken, requireAdmin, async (req, res) => {
    res.json({ message: 'Scheduled analysis started. This will run in the background.' });
    
    logActivity(req.user.id, 'manual_scheduled_analysis');
    
    // Run in background
    setImmediate(async () => {
        await runScheduledAnalysis();
    });
});

// Health check
app.get('/api/health', (req, res) => {
    const apiStatus = {
        openai: !!getApiKey('openai'),
        google: !!getApiKey('google'),
        perplexity: !!getApiKey('perplexity')
    };
    res.json({ status: 'ok', apis: apiStatus });
});

// Serve frontend
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
app.listen(PORT, () => {
    console.log(`\n🚀 AI Brand Insights Pro running at http://localhost:${PORT}`);
    console.log(`\n📧 Default login: admin@standex.com / admin123`);
    console.log(`   (Change this password immediately!)\n`);
    
    // Start weekly scheduled analysis
    weeklyAnalysisJob.start();
    console.log('⏰ Weekly analysis scheduled: Sundays at 2:00 AM EST\n');
});

module.exports = app;
