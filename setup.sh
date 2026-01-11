#!/usr/bin/env bash
#
# AbeKEYs GitHub App - Quick Setup
#
set -euo pipefail

echo ""
echo "==================================="
echo "  AbeKEYs GitHub App Setup"
echo "==================================="
echo ""

# Check prerequisites
command -v vercel >/dev/null 2>&1 || { echo "Error: vercel CLI required"; exit 1; }
command -v gh >/dev/null 2>&1 || { echo "Error: gh CLI required"; exit 1; }

# Deploy to Vercel
echo "[1/3] Deploying to Vercel..."
DEPLOY_URL=$(vercel --prod --yes 2>/dev/null | tail -1)
echo "      Deployed to: $DEPLOY_URL"

# Create GitHub repo if needed
echo ""
echo "[2/3] Creating GitHub repo..."
if ! gh repo view mataluni-bravetto/abekeys-github-app >/dev/null 2>&1; then
  gh repo create abekeys-github-app --public --source=. --push
  echo "      Repo created and pushed"
else
  echo "      Repo exists, pushing..."
  git push origin main 2>/dev/null || git push -u origin main
fi

echo ""
echo "[3/3] Next Steps:"
echo ""
echo "  1. Go to: https://github.com/settings/apps/new"
echo ""
echo "  2. Fill in:"
echo "     Name: AbeKEYs Secret Scanner"
echo "     Webhook URL: ${DEPLOY_URL}/webhook"
echo "     Webhook Secret: <generate one>"
echo ""
echo "  3. Set permissions:"
echo "     - Checks: Read & Write"
echo "     - Contents: Read"
echo "     - Pull requests: Read & Write"
echo ""
echo "  4. Subscribe to events:"
echo "     - Pull request"
echo ""
echo "  5. After creating, generate a private key"
echo ""
echo "  6. Set Vercel env vars:"
echo "     vercel env add GITHUB_APP_ID"
echo "     vercel env add GITHUB_PRIVATE_KEY"
echo "     vercel env add GITHUB_WEBHOOK_SECRET"
echo ""
echo "  7. Redeploy: vercel --prod"
echo ""
echo "==================================="
echo "  Setup script complete"
echo "==================================="
echo ""
