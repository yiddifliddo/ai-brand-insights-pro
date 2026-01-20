#!/usr/bin/env node
/**
 * Initialize database with Standex brands, competitors, and queries
 */

const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');

// Ensure data directory exists
const dataDir = path.join(__dirname, '..', 'data');
if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
}

const db = new Database(path.join(dataDir, 'brand_insights.db'));

console.log('\n🔧 Initializing AI Brand Insights Pro database...\n');

// Create all tables
db.exec(`
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
    
    CREATE TABLE IF NOT EXISTS api_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        platform TEXT UNIQUE NOT NULL,
        api_key TEXT NOT NULL,
        is_active INTEGER DEFAULT 1,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_by INTEGER
    );
    
    CREATE TABLE IF NOT EXISTS brands (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        domain TEXT,
        keywords TEXT,
        is_active INTEGER DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    
    CREATE TABLE IF NOT EXISTS competitors (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        brand_id INTEGER,
        name TEXT NOT NULL,
        domain TEXT,
        FOREIGN KEY (brand_id) REFERENCES brands(id)
    );
    
    CREATE TABLE IF NOT EXISTS queries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        brand_id INTEGER,
        query_text TEXT NOT NULL,
        category TEXT,
        is_active INTEGER DEFAULT 1,
        FOREIGN KEY (brand_id) REFERENCES brands(id)
    );
    
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
        status TEXT DEFAULT 'completed'
    );
    
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
        citations TEXT
    );
    
    CREATE TABLE IF NOT EXISTS citations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id INTEGER,
        url TEXT NOT NULL,
        domain TEXT,
        category TEXT,
        mention_count INTEGER DEFAULT 1
    );
    
    CREATE TABLE IF NOT EXISTS activity_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        details TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
    );
`);

console.log('✅ Tables created\n');

// Check if data already exists
const existingBrands = db.prepare('SELECT COUNT(*) as count FROM brands').get();
const existingUsers = db.prepare('SELECT COUNT(*) as count FROM users').get();

if (existingBrands.count > 0) {
    console.log('⚠️  Database already contains brand data. Skipping seed.\n');
} else {
    // Insert Standex brands
    console.log('📦 Adding Standex brands...\n');
    
    // American Biotech Supply
    const abs = db.prepare('INSERT INTO brands (name, domain, keywords) VALUES (?, ?, ?)').run(
        'American Biotech Supply',
        'americanbiotechsupply.com',
        JSON.stringify(['laboratory freezers', 'ultra-low freezers', 'medical refrigerators', 'vaccine storage'])
    );
    
    // Custom Biogenic Systems  
    const cbs = db.prepare('INSERT INTO brands (name, domain, keywords) VALUES (?, ?, ?)').run(
        'Custom Biogenic Systems',
        'custombiogenics.com',
        JSON.stringify(['cryogenic storage', 'LN2 freezers', 'liquid nitrogen', 'cell storage'])
    );
    
    console.log('   ✓ American Biotech Supply');
    console.log('   ✓ Custom Biogenic Systems');
    
    // Add competitors for ABS
    const absCompetitors = [
        ['Thermo Fisher Scientific', 'thermofisher.com'],
        ['VWR International', 'vwr.com'],
        ['Helmer Scientific', 'helmerinc.com'],
        ['So-Low Environmental', 'so-low.com'],
        ['PHCbi', 'phchd.com'],
        ['Stirling Ultracold', 'stirlingultracold.com']
    ];
    
    // Add competitors for CBS
    const cbsCompetitors = [
        ['Thermo Fisher Scientific', 'thermofisher.com'],
        ['Chart Industries', 'chartindustries.com'],
        ['Worthington Industries', 'worthingtonindustries.com'],
        ['MVE', 'mve-cryo.com'],
        ['Taylor-Wharton', 'taylorwharton.com']
    ];
    
    console.log('\n📊 Adding competitors...\n');
    
    const insertComp = db.prepare('INSERT INTO competitors (brand_id, name, domain) VALUES (?, ?, ?)');
    absCompetitors.forEach(([name, domain]) => insertComp.run(abs.lastInsertRowid, name, domain));
    cbsCompetitors.forEach(([name, domain]) => insertComp.run(cbs.lastInsertRowid, name, domain));
    
    console.log(`   ✓ ${absCompetitors.length} competitors for ABS`);
    console.log(`   ✓ ${cbsCompetitors.length} competitors for CBS`);
    
    // Add queries for ABS
    const absQueries = [
        ['What is American Biotech Supply?', 'brand'],
        ['American Biotech Supply reviews', 'brand'],
        ['Best laboratory freezers for biomedical storage', 'product'],
        ['Where to buy ultra-low temperature freezers', 'product'],
        ['Medical grade freezers for vaccine storage', 'product'],
        ['Best -80 freezers for laboratories', 'product'],
        ['Affordable lab freezers for small laboratories', 'product'],
        ['Laboratory refrigerator brands comparison', 'comparison'],
        ['American Biotech Supply vs Thermo Fisher', 'comparison'],
        ['Best laboratory freezer brands 2025', 'comparison'],
        ['CDC compliant vaccine storage freezers', 'use_case'],
        ['Laboratory cold storage for pharmaceutical research', 'use_case']
    ];
    
    // Add queries for CBS
    const cbsQueries = [
        ['What is Custom Biogenic Systems?', 'brand'],
        ['Custom Biogenic Systems reviews', 'brand'],
        ['Best cryogenic storage systems for laboratories', 'product'],
        ['Liquid nitrogen freezers for cell storage', 'product'],
        ['LN2 storage tanks for biorepositories', 'product'],
        ['Cryopreservation equipment suppliers', 'product'],
        ['Custom Biogenic Systems vs MVE', 'comparison'],
        ['Best cryogenic storage brands comparison', 'comparison'],
        ['How to store biological samples in liquid nitrogen', 'use_case'],
        ['Biobank cryogenic storage solutions', 'use_case']
    ];
    
    console.log('\n🔍 Adding analysis queries...\n');
    
    const insertQuery = db.prepare('INSERT INTO queries (brand_id, query_text, category) VALUES (?, ?, ?)');
    absQueries.forEach(([text, cat]) => insertQuery.run(abs.lastInsertRowid, text, cat));
    cbsQueries.forEach(([text, cat]) => insertQuery.run(cbs.lastInsertRowid, text, cat));
    
    console.log(`   ✓ ${absQueries.length} queries for ABS`);
    console.log(`   ✓ ${cbsQueries.length} queries for CBS`);
}

// Create admin user if none exists
if (existingUsers.count === 0) {
    console.log('\n👤 Creating default admin user...\n');
    
    const hash = bcrypt.hashSync('admin123', 10);
    db.prepare(`
        INSERT INTO users (email, password_hash, name, role, status) 
        VALUES (?, ?, ?, ?, ?)
    `).run('admin@standex.com', hash, 'Admin', 'admin', 'active');
    
    console.log('   ✓ Admin user created');
    console.log('   📧 Email: admin@standex.com');
    console.log('   🔑 Password: admin123');
    console.log('   ⚠️  CHANGE THIS PASSWORD AFTER FIRST LOGIN!\n');
}

// Summary
const brands = db.prepare('SELECT COUNT(*) as count FROM brands').get();
const competitors = db.prepare('SELECT COUNT(*) as count FROM competitors').get();
const queries = db.prepare('SELECT COUNT(*) as count FROM queries').get();
const users = db.prepare('SELECT COUNT(*) as count FROM users').get();

console.log('\n' + '='.repeat(50));
console.log('✅ Database initialization complete!');
console.log('='.repeat(50));
console.log(`\n📊 Summary:`);
console.log(`   • Brands: ${brands.count}`);
console.log(`   • Competitors: ${competitors.count}`);
console.log(`   • Queries: ${queries.count}`);
console.log(`   • Users: ${users.count}`);
console.log(`\n🚀 Run "npm start" to start the server\n`);

db.close();
