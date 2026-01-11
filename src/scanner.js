/**
 * AbeKEYs Secret Scanner
 * Detects plaintext secrets in code using proven patterns
 */

// Patterns that indicate exposed secrets - battle-tested from our sanitizer
const SECRET_PATTERNS = [
  // GitHub
  { name: 'GitHub PAT', pattern: /ghp_[A-Za-z0-9]{36,}/, severity: 'critical' },
  { name: 'GitHub OAuth', pattern: /gho_[A-Za-z0-9]{36,}/, severity: 'critical' },
  { name: 'GitHub App Token', pattern: /ghu_[A-Za-z0-9]{36,}/, severity: 'critical' },
  { name: 'GitHub Refresh', pattern: /ghr_[A-Za-z0-9]{36,}/, severity: 'critical' },

  // OpenAI
  { name: 'OpenAI API Key', pattern: /sk-[A-Za-z0-9]{48,}/, severity: 'critical' },
  { name: 'OpenAI Project Key', pattern: /sk-proj-[A-Za-z0-9-_]{48,}/, severity: 'critical' },

  // Stripe
  { name: 'Stripe Secret (Live)', pattern: /sk_live_[A-Za-z0-9]{24,}/, severity: 'critical' },
  { name: 'Stripe Secret (Test)', pattern: /sk_test_[A-Za-z0-9]{24,}/, severity: 'high' },
  { name: 'Stripe Webhook', pattern: /whsec_[A-Za-z0-9]{24,}/, severity: 'high' },

  // AWS
  { name: 'AWS Access Key', pattern: /AKIA[A-Z0-9]{16}/, severity: 'critical' },
  { name: 'AWS Secret Key', pattern: /[A-Za-z0-9/+=]{40}(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])/, severity: 'critical' },

  // Slack
  { name: 'Slack Bot Token', pattern: /xoxb-[A-Za-z0-9-]{50,}/, severity: 'high' },
  { name: 'Slack User Token', pattern: /xoxp-[A-Za-z0-9-]{50,}/, severity: 'high' },
  { name: 'Slack Webhook', pattern: /hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/, severity: 'high' },

  // Vercel
  { name: 'Vercel Token', pattern: /vercel_[A-Za-z0-9]{24,}/, severity: 'high' },

  // Twilio
  { name: 'Twilio Auth Token', pattern: /SK[a-f0-9]{32}/, severity: 'high' },

  // SendGrid
  { name: 'SendGrid API Key', pattern: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/, severity: 'high' },

  // Generic patterns
  { name: 'Bearer Token', pattern: /Bearer\s+[A-Za-z0-9_-]{20,}/, severity: 'medium' },
  { name: 'JWT Token', pattern: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/, severity: 'medium' },
  { name: 'Private Key', pattern: /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/, severity: 'critical' },
];

// Files to skip (binary, lock files, etc.)
const SKIP_PATTERNS = [
  /\.lock$/,
  /package-lock\.json$/,
  /yarn\.lock$/,
  /\.min\.js$/,
  /\.map$/,
  /\.woff2?$/,
  /\.ttf$/,
  /\.png$/,
  /\.jpg$/,
  /\.gif$/,
  /\.ico$/,
  /node_modules\//,
  /\.git\//,
];

/**
 * Scan content for exposed secrets
 * @param {string} content - File content to scan
 * @param {string} filename - Name of file being scanned
 * @returns {Array} Array of findings
 */
export function scanContent(content, filename = 'unknown') {
  // Skip binary/irrelevant files
  if (SKIP_PATTERNS.some(pattern => pattern.test(filename))) {
    return [];
  }

  const findings = [];

  for (const { name, pattern, severity } of SECRET_PATTERNS) {
    const matches = content.match(new RegExp(pattern, 'g'));
    if (matches) {
      for (const match of matches) {
        // Find line number
        const lines = content.split('\n');
        let lineNumber = 1;
        for (let i = 0; i < lines.length; i++) {
          if (lines[i].includes(match.slice(0, 20))) {
            lineNumber = i + 1;
            break;
          }
        }

        findings.push({
          type: name,
          severity,
          file: filename,
          line: lineNumber,
          match: redact(match),
        });
      }
    }
  }

  return findings;
}

/**
 * Redact a secret for safe logging
 */
function redact(secret) {
  if (secret.length <= 10) return '***';
  return secret.slice(0, 6) + '...' + secret.slice(-4);
}

/**
 * Scan a diff/patch for secrets
 * @param {string} patch - Git diff patch
 * @param {string} filename - File being changed
 * @returns {Array} Findings only in added lines
 */
export function scanPatch(patch, filename) {
  if (!patch) return [];

  // Only scan added lines (lines starting with +)
  const addedLines = patch
    .split('\n')
    .filter(line => line.startsWith('+') && !line.startsWith('+++'))
    .map(line => line.slice(1))
    .join('\n');

  return scanContent(addedLines, filename);
}

/**
 * Format findings for GitHub Check annotation
 */
export function formatAnnotation(finding) {
  return {
    path: finding.file,
    start_line: finding.line,
    end_line: finding.line,
    annotation_level: finding.severity === 'critical' ? 'failure' : 'warning',
    title: `Exposed ${finding.type}`,
    message: `Found ${finding.type}: ${finding.match}\n\nThis secret should not be committed to the repository. Use environment variables or a secrets manager instead.`,
  };
}

export default { scanContent, scanPatch, formatAnnotation, SECRET_PATTERNS };
