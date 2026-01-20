# AI Brand Insights Pro

Multi-user platform for monitoring how Standex brands appear across ChatGPT, Gemini, and Perplexity AI platforms.

## Features

- 🔐 **User Authentication** - Email/password login with admin approval
- 👥 **Multi-User Support** - 20+ users with role-based access
- 🔑 **Centralized API Keys** - Admins manage keys, users just run analyses
- 📊 **Full Dashboard** - Visibility scores, mentions, sentiment, citations
- 📈 **Historical Tracking** - View trends over time
- 🏢 **Brand Management** - Add brands, competitors, and queries
- 📋 **Activity Logging** - Track who ran what analysis

## Pre-Configured

- **American Biotech Supply** (12 queries, 6 competitors)
- **Custom Biogenic Systems** (10 queries, 5 competitors)

---

## 🚀 Deploy to Railway (Recommended)

### Step 1: Create Railway Account

1. Go to [railway.app](https://railway.app)
2. Sign up with GitHub (recommended) or email
3. Verify your account

### Step 2: Deploy from GitHub

1. Fork this repository to your GitHub account
2. In Railway, click **"New Project"**
3. Select **"Deploy from GitHub repo"**
4. Choose your forked repository
5. Railway will auto-detect the Dockerfile and deploy

### Step 3: Configure Environment Variables

In Railway dashboard → Your project → **Variables** tab, add:

```
JWT_SECRET=your-very-long-random-secret-string-here
```

Generate a secure secret: `openssl rand -base64 32`

### Step 4: Get Your URL

1. Go to **Settings** → **Networking**
2. Click **"Generate Domain"**
3. Your app is now live at `https://your-app.up.railway.app`

### Step 5: First Login

1. Open your Railway URL
2. Login with default credentials:
   - **Email:** `admin@standex.com`
   - **Password:** `admin123`
3. **IMMEDIATELY** change the admin password (or create a new admin and delete the default)

### Step 6: Configure API Keys

1. Go to **Admin** → **API Keys**
2. Add your API keys for ChatGPT, Gemini, and Perplexity
3. Users can now run analyses!

---

## 💻 Local Development

### Prerequisites

- Node.js 18+
- npm

### Setup

```bash
# Clone the repo
git clone <your-repo-url>
cd ai-brand-insights-pro

# Install dependencies
npm install

# Initialize database with Standex brands
npm run init-db

# Start the server
npm start
```

Open http://localhost:3000

---

## 👥 User Management

### User Roles

| Role | Permissions |
|------|-------------|
| **Admin** | Manage users, API keys, brands, queries, run analyses |
| **User** | Run analyses, view history and results |

### User Flow

1. New user registers at login page
2. Admin approves user in **Admin → Users**
3. User can now login and run analyses

### Adding Users

1. Share your Railway URL with team members
2. They click "Request Access" and register
3. You approve them in the admin panel

---

## 📊 Running Analyses

1. Go to **Run Analysis**
2. Select brand (ABS or CBS)
3. Choose platforms (ChatGPT, Gemini, Perplexity)
4. Click **Run Analysis**
5. View results immediately and in **History**

---

## 🔑 API Keys

Get your API keys from:

| Platform | URL | Cost |
|----------|-----|------|
| OpenAI (ChatGPT) | [platform.openai.com/api-keys](https://platform.openai.com/api-keys) | ~$0.01/query |
| Google AI (Gemini) | [aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey) | Free tier |
| Perplexity | [perplexity.ai/settings/api](https://www.perplexity.ai/settings/api) | ~$0.005/query |

**Estimated cost:** ~$5-15/month with weekly analyses

---

## 📁 Project Structure

```
ai-brand-insights-pro/
├── server.js           # Express API server
├── public/
│   └── index.html      # React frontend
├── scripts/
│   └── init-database.js # DB setup with Standex data
├── data/
│   └── brand_insights.db # SQLite database
├── Dockerfile          # For Railway deployment
├── railway.json        # Railway config
└── package.json
```

---

## 🔧 Customization

### Add a New Brand

1. Go to **Admin → Brands**
2. Enter brand name and domain
3. Add competitors
4. Add analysis queries

### Query Categories

- `brand` - Direct brand queries ("What is [brand]?")
- `product` - Product searches ("Best [product type]")
- `comparison` - Vs queries ("[brand] vs [competitor]")
- `use_case` - How-to queries ("How to store [item]")

---

## 🔒 Security Notes

- Change the default admin password immediately
- Use a strong JWT_SECRET in production
- API keys are stored encrypted in the database
- All passwords are hashed with bcrypt

---

## 📈 Estimated Costs

| Item | Cost |
|------|------|
| Railway Hobby | $5/month (includes $5 usage credit) |
| AI APIs (weekly scans) | ~$5-10/month |
| **Total** | **~$10-15/month** |

---

## 🆘 Troubleshooting

### "Account pending approval"
→ Ask an admin to approve your account in Admin → Users

### "API not configured"
→ Admin needs to add API keys in Admin → API Keys

### Database reset
```bash
rm data/brand_insights.db
npm run init-db
```

### Railway deployment issues
1. Check **Deployments** tab for build logs
2. Ensure JWT_SECRET is set in Variables
3. Check **Logs** tab for runtime errors

---

## 📝 License

MIT - Built for Standex Scientific internal use.
