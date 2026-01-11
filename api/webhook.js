/**
 * AbeKEYs GitHub App - Vercel Serverless Webhook Handler
 */

import crypto from 'crypto';
import { scanPatch, formatAnnotation } from '../src/scanner.js';

const APP_ID = process.env.GITHUB_APP_ID;
const PRIVATE_KEY = process.env.GITHUB_PRIVATE_KEY?.replace(/\\n/g, '\n');
const WEBHOOK_SECRET = process.env.GITHUB_WEBHOOK_SECRET;

/**
 * Create JWT for GitHub App authentication
 */
function createJWT() {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iat: now - 60,
    exp: now + 600,
    iss: APP_ID,
  };

  const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto.sign('RSA-SHA256', Buffer.from(`${header}.${body}`), PRIVATE_KEY);

  return `${header}.${body}.${signature.toString('base64url')}`;
}

/**
 * Get installation access token
 */
async function getInstallationToken(installationId) {
  const jwt = createJWT();
  const response = await fetch(
    `https://api.github.com/app/installations/${installationId}/access_tokens`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${jwt}`,
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
      },
    }
  );
  const data = await response.json();
  return data.token;
}

/**
 * GitHub API helper
 */
async function github(token, method, endpoint, body = null) {
  const response = await fetch(`https://api.github.com${endpoint}`, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      ...(body && { 'Content-Type': 'application/json' }),
    },
    ...(body && { body: JSON.stringify(body) }),
  });
  return response.json();
}

/**
 * Handle pull_request event
 */
async function handlePullRequest(payload) {
  const { action, pull_request, repository, installation } = payload;

  if (!['opened', 'synchronize', 'reopened'].includes(action)) {
    return { status: 'skipped', reason: `Action ${action} not scanned` };
  }

  const token = await getInstallationToken(installation.id);
  const owner = repository.owner.login;
  const repo = repository.name;

  // Create check run
  const check = await github(token, 'POST', `/repos/${owner}/${repo}/check-runs`, {
    name: 'AbeKEYs Secret Scanner',
    head_sha: pull_request.head.sha,
    status: 'in_progress',
    started_at: new Date().toISOString(),
  });

  // Get changed files
  const files = await github(token, 'GET', `/repos/${owner}/${repo}/pulls/${pull_request.number}/files`);

  // Scan each file
  const allFindings = [];
  for (const file of files) {
    if (file.patch) {
      const findings = scanPatch(file.patch, file.filename);
      allFindings.push(...findings);
    }
  }

  // Prepare results
  const annotations = allFindings.map(formatAnnotation);
  const criticalCount = allFindings.filter(f => f.severity === 'critical').length;
  const hasCritical = criticalCount > 0;

  // Update check run
  await github(token, 'PATCH', `/repos/${owner}/${repo}/check-runs/${check.id}`, {
    status: 'completed',
    completed_at: new Date().toISOString(),
    conclusion: hasCritical ? 'failure' : (allFindings.length > 0 ? 'neutral' : 'success'),
    output: {
      title: allFindings.length > 0
        ? `${criticalCount} critical, ${allFindings.length - criticalCount} warnings`
        : 'Clean - No secrets detected',
      summary: getSummary(allFindings, hasCritical),
      annotations: annotations.slice(0, 50),
    },
  });

  // Comment on PR if critical
  if (hasCritical) {
    await github(token, 'POST', `/repos/${owner}/${repo}/issues/${pull_request.number}/comments`, {
      body: getAlertComment(allFindings),
    });
  }

  return { status: 'scanned', findings: allFindings.length, critical: criticalCount };
}

function getSummary(findings, hasCritical) {
  if (findings.length === 0) {
    return 'All files scanned. No exposed secrets detected.';
  }
  return `AbeKEYs detected **${findings.length}** potential secret(s).\n\n` +
    (hasCritical ? '**This PR is blocked until critical secrets are removed.**' : 'Please review warnings.');
}

function getAlertComment(findings) {
  const critical = findings.filter(f => f.severity === 'critical');
  return `## AbeKEYs Security Alert

**${critical.length} critical secret(s)** detected. This PR is blocked.

| Type | File | Line |
|------|------|------|
${critical.map(f => `| ${f.type} | \`${f.file}\` | ${f.line} |`).join('\n')}

### Fix
1. Remove secrets from code
2. Use environment variables
3. **Rotate any exposed secrets immediately**

---
*[AbeKEYs](https://github.com/mataluni-bravetto/abekeys) - Protecting your secrets*`;
}

/**
 * Verify webhook signature
 */
function verifySignature(payload, signature) {
  if (!WEBHOOK_SECRET || !signature) return true; // Skip if not configured
  const expected = 'sha256=' + crypto.createHmac('sha256', WEBHOOK_SECRET).update(payload).digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
  } catch {
    return false;
  }
}

/**
 * Main handler
 */
export default async function handler(req, res) {
  // Health check
  if (req.method === 'GET') {
    return res.status(200).json({ status: 'ok', app: 'AbeKEYs GitHub App', version: '1.0.0' });
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // Verify signature
  const rawBody = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
  if (!verifySignature(rawBody, req.headers['x-hub-signature-256'])) {
    return res.status(401).json({ error: 'Invalid signature' });
  }

  const event = req.headers['x-github-event'];
  const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;

  console.log(`[AbeKEYs] ${event} event received`);

  try {
    let result;
    switch (event) {
      case 'pull_request':
        result = await handlePullRequest(body);
        break;
      case 'ping':
        result = { status: 'pong', zen: body.zen };
        break;
      default:
        result = { status: 'ignored', event };
    }
    return res.status(200).json(result);
  } catch (error) {
    console.error('[AbeKEYs] Error:', error);
    return res.status(500).json({ error: error.message });
  }
}
