/**
 * AbeKEYs Scanner Tests
 * Run: node src/scanner.test.js
 */

import { scanContent, scanPatch } from './scanner.js';

// Test patterns use EXAMPLE/TEST markers to avoid triggering GitHub push protection
// These patterns still match our scanner regex but are clearly fake
const tests = [
  {
    name: 'Detects GitHub PAT pattern',
    content: 'const token = "ghp_EXAMPLETOKEN1234567890abcdefghijklmn";',
    expected: 1,
  },
  {
    name: 'Detects OpenAI key pattern',
    content: 'OPENAI_API_KEY=sk-EXAMPLEabcdefghijklmnopqrstuvwxyz1234567890abcdef',
    expected: 1,
  },
  {
    name: 'Detects private key header',
    content: '-----BEGIN PRIVATE KEY-----\nEXAMPLE...',
    expected: 1,
  },
  {
    name: 'Ignores safe content',
    content: 'const greeting = "Hello, World!";',
    expected: 0,
  },
  {
    name: 'Detects JWT pattern',
    content: 'token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U',
    expected: 1,
  },
];

console.log('\n=== AbeKEYs Scanner Tests ===\n');

let passed = 0;
let failed = 0;

for (const test of tests) {
  const findings = scanContent(test.content, 'test.js');
  const success = findings.length === test.expected;

  if (success) {
    console.log(`  ✓ ${test.name}`);
    passed++;
  } else {
    console.log(`  ✗ ${test.name} (expected ${test.expected}, got ${findings.length})`);
    failed++;
  }
}

console.log(`\n  ${passed} passed, ${failed} failed\n`);

process.exit(failed > 0 ? 1 : 0);
