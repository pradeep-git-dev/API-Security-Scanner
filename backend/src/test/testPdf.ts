import * as fs from 'fs';
import * as path from 'path';
import { generateScanPDF } from '../services/pdfService';

const mockScan = {
  _id: 'mock_scan_123',
};

const mockReport = {
  score: 65,
  targetType: 'REST API',
  framework: 'Express/Node.js',
  server: 'nginx/1.25.1',
  contentType: 'application/json',
  tlsVersion: 'TLSv1.2',
  responseTimeMs: 245,
  confidence: { score: 85, label: 'HIGH' },
  categories: [
    { name: 'Header Security', score: 10, max: 30, percentage: 33.3 },
    { name: 'Transport Security', score: 10, max: 15, percentage: 66.7 },
    { name: 'Server Security', score: 15, max: 15, percentage: 100 },
    { name: 'API Security', score: 15, max: 25, percentage: 60 },
    { name: 'Data Protection', score: 15, max: 15, percentage: 100 }
  ],
  headersStatus: [
    { header: 'Content-Security-Policy', status: false },
    { header: 'Strict-Transport-Security', status: true },
    { header: 'X-Content-Type-Options', status: true },
    { header: 'X-Frame-Options', status: false },
    { header: 'X-XSS-Protection', status: false }
  ],
  rateLimitReport: {
    requestsSent: 100,
    responses429: 2,
    retryAfter: 'None',
    conclusion: 'Rate limiting is partially implemented but does not block requests efficiently.'
  },
  scoreBreakdown: [
    { category: 'Header Security', reason: 'Missing Content-Security-Policy header', penalty: 15 },
    { category: 'Header Security', reason: 'Missing X-Frame-Options header', penalty: 10 },
    { category: 'Header Security', reason: 'Missing X-XSS-Protection header', penalty: 5 },
    { category: 'API Security', reason: 'Rate limiting does not enforce blocking on high requests', penalty: 5 }
  ]
};

const mockFindings = [
  {
    category: 'Security Findings',
    issue: 'Missing Content-Security-Policy (CSP) Header',
    severity: 'MEDIUM',
    method: 'GET',
    endpoint: '/api/v1/users',
    owasp: 'OWASP A5:2021',
    cwe: 'CWE-1021',
    description: 'The Content-Security-Policy header is missing from the HTTP response. A Content Security Policy (CSP) is an HTTP header that allows site operators to restrict the resources (such as JavaScript, CSS, Images) that the browser is allowed to load for a given page.',
    evidence: {
      type: 'missing_headers',
      details: ['Content-Security-Policy']
    },
    impact: 'Without CSP, attackers can exploit Cross-Site Scripting (XSS) or Clickjacking vulnerabilities on the frontend if user input is reflected.',
    recommendation: 'Configure your web server or application framework to send a robust Content-Security-Policy header, such as: "default-src \'self\'".',
    codeExample: `// Express helmet middleware configuration
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "trusted-cdn.com"],
    },
  })
);`
  },
  {
    category: 'Security Findings',
    issue: 'SQL Injection Vulnerability in User Search',
    severity: 'CRITICAL',
    method: 'POST',
    endpoint: '/api/v1/users/search',
    owasp: 'OWASP A3:2021-Injection',
    cwe: 'CWE-89',
    description: 'The user search endpoint dynamically constructs an SQL query using unvalidated user input. This allows an attacker to manipulate the SQL statement structure and execute arbitrary SQL commands, potentially leading to unauthorized data access, modification, or administrative privilege escalation. This is a very critical finding that should be resolved immediately to prevent data leakage.',
    evidence: {
      type: 'sql_error',
      details: [
        'Input payload: { "query": "admin\' OR \'1\'=\'1" }',
        'Database response contained SQL syntax error indicator: "SELECT * FROM users WHERE name = \'admin\' OR \'1\'=\'1\'"'
      ]
    },
    impact: 'Complete compromise of the underlying relational database. Attackers can read, modify, or delete all records, and potentially execute system commands on the database server.',
    recommendation: 'Use parameterized queries or prepared statements for all database operations. Never concatenate raw user input into SQL strings.',
    codeExample: `// Bad: db.query("SELECT * FROM users WHERE name = '" + req.body.query + "'");
// Good: Use parameterized query
const query = 'SELECT * FROM users WHERE name = $1';
const values = [req.body.query];
const result = await db.query(query, values);`
  },
  {
    category: 'Security Findings',
    issue: 'Exposure of Sensitive Stack Trace',
    severity: 'HIGH',
    method: 'GET',
    endpoint: '/api/v1/debug/error',
    cwe: 'CWE-209',
    description: 'When an exception occurs, the API returns the full stack trace in the JSON error response. Stack traces expose implementation details, file paths, database schemas, and library versions, which can help attackers customize their exploits.',
    evidence: 'Response body contains: "TypeError: Cannot read property \'id\' of undefined\\n    at getUser (/usr/src/app/src/controllers/userController.ts:25:21)\\n    at processTicksAndRejections (node:internal/process/task_queues:95:5)"',
    impact: 'Information disclosure that simplifies target enumeration and helps identify specific vulnerable software versions.',
    recommendation: 'Configure the application error handler to return a generic error message (e.g., "Internal Server Error") and log the stack trace internally.',
    codeExample: `// Express error handling middleware
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  console.error(err.stack); // Log internally
  res.status(500).json({
    success: false,
    message: 'Something went wrong. Please try again later.'
  });
});`
  },
  {
    category: 'Observations',
    issue: 'Server Banner Information Disclosure',
    severity: 'LOW',
    method: 'GET',
    endpoint: '/api/v1/health',
    cwe: 'CWE-200',
    description: 'The server returns the "Server: nginx/1.25.1" response header. Revealing specific web server names and versions helps attackers search for known vulnerabilities.',
    evidence: 'Header: "Server: nginx/1.25.1"',
    impact: 'Enables attackers to target vulnerabilities specific to nginx 1.25.1.',
    recommendation: 'Disable the server banner in nginx config using: "server_tokens off;".',
    codeExample: `server {
    listen 80;
    server_tokens off;
    # ...
}`
  },
  {
    category: 'Passed Checks',
    issue: 'Strict-Transport-Security Header Present',
    severity: 'PASSED',
    method: 'GET',
    endpoint: '/api/v1/users',
    description: 'The endpoint returns a valid Strict-Transport-Security header, enforcing HTTPS.',
    evidence: 'Header: "Strict-Transport-Security: max-age=63072000; includeSubDomains"'
  }
];

async function main() {
  try {
    const pdfBuffer = await generateScanPDF(mockScan, mockReport, mockFindings);
    const outputPath = path.join(__dirname, '../../test_report.pdf');
    fs.writeFileSync(outputPath, pdfBuffer);
    console.log(`PDF successfully generated and saved to: ${outputPath}`);
  } catch (error) {
    console.error('Failed to generate PDF:', error);
  }
}

main();
