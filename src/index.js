/**
 * AbeKEYs GitHub App - Webhook Handler
 * Scans PRs and pushes for exposed secrets
 */

import { createAppAuth } from '@octokit/auth-app';
import { Octokit } from '@octokit/core';
import { scanPatch, formatAnnotation } from './scanner.js';

// Environment variables (set in Vercel)
const APP_ID = process.env.GITHUB_APP_ID;
const PRIVATE_KEY = process.env.GITHUB_PRIVATE_KEY?.replace(/\\n/g, '\n');
const WEBHOOK_SECRET = process.env.GITHUB_WEBHOOK_SECRET;

/**
 * Verify webhook signature
 */
async function verifySignature(payload, signature) {
  const crypto = await import('crypto');
  const expected = 'sha256=' + crypto
    .createHmac('sha256', WEBHOOK_SECRET)
    .update(payload)
    .digest('hex');
  return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
}

/**
 * Get authenticated Octokit instance for installation
 */
async function getInstallationOctokit(installationId) {
  const auth = createAppAuth({
    appId: APP_ID,
    privateKey: PRIVATE_KEY,
    installationId,
  });

  const { token } = await auth({ type: 'installation' });
  return new Octokit({ auth: token });
}

/**
 * Handle pull_request event
 */
async function handlePullRequest(payload) {
  const { action, pull_request, repository, installation } = payload;

  if (!['opened', 'synchronize', 'reopened'].includes(action)) {
    return { status: 'skipped', reason: `PR action ${action} not relevant` };
  }

  const octokit = await getInstallationOctokit(installation.id);

  // Create a check run
  const check = await octokit.request('POST /repos/{owner}/{repo}/check-runs', {
    owner: repository.owner.login,
    repo: repository.name,
    name: 'AbeKEYs Secret Scanner',
    head_sha: pull_request.head.sha,
    status: 'in_progress',
    started_at: new Date().toISOString(),
  });

  // Get PR files
  const { data: files } = await octokit.request('GET /repos/{owner}/{repo}/pulls/{pull_number}/files', {
    owner: repository.owner.login,
    repo: repository.name,
    pull_number: pull_request.number,
  });

  // Scan each file
  const allFindings = [];
  for (const file of files) {
    if (file.patch) {
      const findings = scanPatch(file.patch, file.filename);
      allFindings.push(...findings);
    }
  }

  // Update check run with results
  const annotations = allFindings.map(formatAnnotation);
  const hasCritical = allFindings.some(f => f.severity === 'critical');

  await octokit.request('PATCH /repos/{owner}/{repo}/check-runs/{check_run_id}', {
    owner: repository.owner.login,
    repo: repository.name,
    check_run_id: check.data.id,
    status: 'completed',
    completed_at: new Date().toISOString(),
    conclusion: hasCritical ? 'failure' : (allFindings.length > 0 ? 'neutral' : 'success'),
    output: {
      title: allFindings.length > 0
        ? `Found ${allFindings.length} exposed secret(s)`
        : 'No secrets detected',
      summary: allFindings.length > 0
        ? `AbeKEYs detected ${allFindings.length} potential secret(s) in this PR.\n\n${hasCritical ? '**CRITICAL**: This PR cannot be merged until critical secrets are removed.' : 'Please review the warnings below.'}`
        : 'All files scanned. No exposed secrets found.',
      annotations: annotations.slice(0, 50), // GitHub limits to 50
    },
  });

  // Comment on PR if critical findings
  if (hasCritical) {
    await octokit.request('POST /repos/{owner}/{repo}/issues/{issue_number}/comments', {
      owner: repository.owner.login,
      repo: repository.name,
      issue_number: pull_request.number,
      body: `## AbeKEYs Security Alert

This PR contains **${allFindings.filter(f => f.severity === 'critical').length} critical secret(s)** that must be removed before merging.

### Detected Secrets
${allFindings.map(f => `- **${f.type}** in \`${f.file}\` (line ${f.line}): \`${f.match}\``).join('\n')}

### How to Fix
1. Remove the secret from your code
2. Use environment variables instead
3. If the secret was already pushed, **rotate it immediately**

---
*Powered by [AbeKEYs](https://github.com/mataluni-bravetto/abekeys)*`,
    });
  }

  return {
    status: 'completed',
    findings: allFindings.length,
    conclusion: hasCritical ? 'failure' : 'success',
  };
}

/**
 * Main webhook handler (Vercel serverless function)
 */
export default async function handler(req, res) {
  // Health check
  if (req.method === 'GET') {
    return res.status(200).json({
      status: 'ok',
      app: 'AbeKEYs GitHub App',
      version: '1.0.0',
    });
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // Verify webhook signature
  const signature = req.headers['x-hub-signature-256'];
  const payload = JSON.stringify(req.body);

  if (WEBHOOK_SECRET && signature) {
    const valid = await verifySignature(payload, signature);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid signature' });
    }
  }

  const event = req.headers['x-github-event'];
  const body = req.body;

  console.log(`Received ${event} event`);

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
    console.error('Error handling webhook:', error);
    return res.status(500).json({ error: error.message });
  }
}
