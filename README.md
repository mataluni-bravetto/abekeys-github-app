# AbeKEYs GitHub App

Scan PRs for exposed secrets. Block merges with critical findings.

## What It Detects

| Secret Type | Pattern | Severity |
|-------------|---------|----------|
| GitHub PAT | `ghp_*` | Critical |
| OpenAI API Key | `sk-*`, `sk-proj-*` | Critical |
| AWS Access Key | `AKIA*` | Critical |
| Stripe Secret | `sk_live_*` | Critical |
| Stripe Test | `sk_test_*` | High |
| Slack Tokens | `xoxb-*`, `xoxp-*` | High |
| Private Keys | `-----BEGIN PRIVATE KEY-----` | Critical |
| JWTs | `eyJ*.*.*` | Medium |

## Setup

### 1. Deploy to Vercel

```bash
cd abekeys-github-app
vercel --prod
```

Note the deployment URL (e.g., `https://abekeys-github-app.vercel.app`)

### 2. Create GitHub App

1. Go to https://github.com/settings/apps/new
2. Fill in:
   - **Name**: `AbeKEYs Secret Scanner`
   - **Homepage URL**: Your repo URL
   - **Webhook URL**: `https://YOUR-VERCEL-URL/webhook`
   - **Webhook Secret**: Generate one and save it

3. Permissions:
   - `Checks`: Read & Write
   - `Contents`: Read
   - `Pull requests`: Read & Write
   - `Metadata`: Read

4. Events:
   - Subscribe to: `Pull request`

5. Click "Create GitHub App"

### 3. Generate Private Key

1. In your new app's settings, scroll to "Private keys"
2. Click "Generate a private key"
3. Save the downloaded `.pem` file

### 4. Set Vercel Environment Variables

```bash
vercel env add GITHUB_APP_ID        # From app settings
vercel env add GITHUB_PRIVATE_KEY   # Contents of .pem file
vercel env add GITHUB_WEBHOOK_SECRET # The secret you created
```

### 5. Install the App

1. Go to your app's public page
2. Click "Install"
3. Select repositories to protect

## How It Works

```
PR Opened/Updated
       ↓
AbeKEYs scans changed files
       ↓
   ┌───┴───┐
   ↓       ↓
Clean   Secrets Found
   ↓       ↓
   ✓    Block PR + Comment
```

## Local Development

```bash
npm install
npm run dev
```

## License

Proprietary - Bravetto
