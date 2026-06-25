import { GoogleGenerativeAI } from '@google/generative-ai';

export interface AIEvaluation {
  aiExplanation: string;
  aiImpact: string;
  aiFix: string;
  codeExample: string;
}

// Fallback data generator for offline/unconfigured environments
const getFallbackEvaluation = (
  issue: string,
  severity: string,
  description: string,
  recommendation: string
): AIEvaluation => {
  const issueLower = issue.toLowerCase();
  
  if (issueLower.includes('header') || issueLower.includes('missing security headers')) {
    return {
      aiExplanation: "The application is missing critical HTTP response headers that protect against common web vulnerabilities, such as Clickjacking (X-Frame-Options), Cross-Site Scripting (X-Content-Type-Options), and MIME-sniffing.",
      aiImpact: "Without these headers, modern browsers may execute malicious scripts, allow clickjacking attacks in frames, or leak sensitive details, increasing the attack surface.",
      aiFix: "Configure your web server or application framework (e.g., using Helmet.js in Express) to send security-oriented HTTP headers like Content-Security-Policy, X-Frame-Options, and X-Content-Type-Options.",
      codeExample: `// Express.js secure headers configuration using Helmet
const express = require('express');
const helmet = require('helmet');
const app = express();

// Use helmet to automatically set secure HTTP headers
app.use(helmet());

app.get('/api', (req, res) => {
  res.json({ message: "Secure headers configured" });
});`
    };
  }

  if (issueLower.includes('https') || issueLower.includes('ssl') || issueLower.includes('tls')) {
    return {
      aiExplanation: "The endpoint is accessible over unencrypted HTTP. Data sent between the client and server is transmitted in cleartext, exposing it to interception.",
      aiImpact: "An attacker positioned on the network (e.g., public Wi-Fi) can intercept or manipulate the traffic, stealing credentials, session tokens, or sensitive API data.",
      aiFix: "Enforce SSL/TLS encryption for all endpoints and redirect all HTTP traffic to HTTPS. Implement HTTP Strict Transport Security (HSTS).",
      codeExample: `// Express.js middleware to force HTTPS redirection
const express = require('express');
const app = express();

app.use((req, res, next) => {
  if (req.headers['x-forwarded-proto'] !== 'https' && process.env.NODE_ENV === 'production') {
    return res.redirect('https://' + req.headers.host + req.url);
  }
  next();
});`
    };
  }

  if (issueLower.includes('sql injection') || issueLower.includes('sqli')) {
    return {
      aiExplanation: "User input is directly concatenated into SQL query strings without sanitization or parameterized inputs, allowing malicious SQL commands to run.",
      aiImpact: "Attackers can bypass authentication, read, modify, or delete database records, or even execute administrative commands on the database server.",
      aiFix: "Use parameterized queries, prepared statements, or an Object-Relational Mapper (ORM) like Mongoose, Sequelize, or Prisma to separate user input from SQL code.",
      codeExample: `// Secure vs Vulnerable Database Queries in Node.js

// ❌ VULNERABLE: Direct concatenation
// db.query(\`SELECT * FROM users WHERE id = '\${userId}'\`);

// ✅ SECURE: Using Parameterized Queries
db.query('SELECT * FROM users WHERE id = ?', [userId], (err, results) => {
  if (err) throw err;
  res.json(results);
});`
    };
  }

  if (issueLower.includes('jwt') || issueLower.includes('json web token')) {
    return {
      aiExplanation: "The application uses insecure JWT implementations, such as using weak signing keys, accepting the 'none' algorithm, or failing to verify token signatures.",
      aiImpact: "Attackers can forge JWT signatures or modify payloads, bypassing authentication checks and escalating privileges to arbitrary accounts.",
      aiFix: "Enforce strong signature verification using asymmetrical keys (e.g., RS256) or strong secrets. Reject tokens that use weak algorithms or the 'none' algorithm.",
      codeExample: `// Secure JWT verification in Express.js
const jwt = require('jsonwebtoken');

function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.sendStatus(401);

  // Enforce validation and specify valid algorithms
  jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] }, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}`
    };
  }

  if (issueLower.includes('data exposure') || issueLower.includes('excessive data') || issueLower.includes('exposure')) {
    return {
      aiExplanation: "The API returns full database objects or sensitive fields (like passwords, keys, tokens) to the client, relying on the client-side UI to filter them out.",
      aiImpact: "Attackers can inspect the raw network responses and extract sensitive credentials, private tokens, or proprietary business data.",
      aiFix: "Implement proper Data Transfer Objects (DTOs) or selectively project/serialize only the necessary non-sensitive fields before sending the response.",
      codeExample: `// Secure serialization of User objects using Mongoose
const mongoose = require('mongoose');

// Exclude sensitive fields during query projection
async function getUserProfile(userId) {
  const user = await User.findById(userId)
                         .select('-password -privateKey -__v');
  return user;
}`
    };
  }

  if (issueLower.includes('rate limit') || issueLower.includes('rate-limiting') || issueLower.includes('brute force')) {
    return {
      aiExplanation: "The API lacks protection against excessive requests, allowing clients to send an unlimited number of requests in a short timeframe.",
      aiImpact: "This exposes the application to Denial of Service (DoS) attacks, brute-force credential stuffing, and resource exhaustion.",
      aiFix: "Implement rate limiting middleware to throttle requests based on client IP or authenticated user session.",
      codeExample: `// Rate limiting implementation in Express.js
const rateLimit = require('express-rate-limit');

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per window
  standardHeaders: true, // Return rate limit info in the Headers
  legacyHeaders: false, // Disable the X-RateLimit headers
  message: { error: 'Too many requests, please try again later.' }
});

// Apply rate limiter to API routes
app.use('/api/', apiLimiter);`
    };
  }

  if (issueLower.includes('auth') || issueLower.includes('authorization') || issueLower.includes('authentication')) {
    return {
      aiExplanation: "The endpoint lacks proper authentication checks or has broken object-level authorization, allowing users to access resources they do not own.",
      aiImpact: "Unauthenticated or unauthorized actors can access, modify, or delete sensitive data of other users, leading to a complete breach of confidentiality.",
      aiFix: "Implement authentication middleware on all private endpoints, and verify that the logged-in user owns the resource they are requesting.",
      codeExample: `// Secure Object-Level Authorization check in Express.js
app.get('/api/documents/:id', protect, async (req, res) => {
  const doc = await Document.findById(req.params.id);
  if (!doc) return res.status(404).json({ message: 'Not found' });
  
  // Verify resource ownership
  if (doc.userId.toString() !== req.user.id) {
    return res.status(403).json({ message: 'Access denied' });
  }
  
  res.json(doc);
});`
    };
  }

  // General default fallback
  return {
    aiExplanation: description || "The endpoint displays a security vulnerability related to API design or configuration. This could be due to missing defensive controls or improper input handling.",
    aiImpact: "Depending on the deployment environment, this vulnerability could be leveraged to gain unauthorized access, leak information, or cause service disruptions.",
    aiFix: recommendation || "Apply secure coding principles: validate all inputs, restrict output data, enforce authentication, and log security events.",
    codeExample: `// Standard Secure Response Handler
// Ensure inputs are validated and outputs are filtered
app.post('/api/data', validateInput, (req, res) => {
  const safeData = sanitize(req.body.data);
  res.status(200).json({
    success: true,
    data: safeData
  });
});`
  };
};

/**
 * Enriches a vulnerability finding with Gemini-generated explanation, impact, fix, and code example.
 * Cascades gracefully to offline fallback library if GEMINI_API_KEY is not configured or calls fail.
 */
export const enrichVulnerability = async (
  issue: string,
  severity: string,
  description: string,
  recommendation: string
): Promise<AIEvaluation> => {
  const apiKey = process.env.GEMINI_API_KEY;

  if (!apiKey) {
    console.log(`[AI Service] GEMINI_API_KEY not configured. Using high-quality offline fallback for: "${issue}"`);
    return getFallbackEvaluation(issue, severity, description, recommendation);
  }

  try {
    const genAI = new GoogleGenerativeAI(apiKey);
    // Use gemini-1.5-flash for fast response and structured JSON compatibility
    const model = genAI.getGenerativeModel({
      model: 'gemini-1.5-flash',
      generationConfig: {
        responseMimeType: 'application/json',
      },
    });

    const prompt = `You are an expert API security analyst. Analyze the following API security vulnerability and provide a structured JSON response containing remediation advice.

Vulnerability Details:
- Issue: ${issue}
- Severity: ${severity}
- Scanner Description: ${description}
- Scanner Recommendation: ${recommendation}

Your response must be a JSON object with the following four string keys:
1. "aiExplanation": A professional, detailed explanation of the vulnerability, explaining why it occurs and how an attacker might exploit it. Make it educational for a developer.
2. "aiImpact": A concise paragraph explaining the security impact (e.g., data breach risk, token hijacking, etc.).
3. "aiFix": A clear, step-by-step technical remediation plan.
4. "codeExample": A high-quality, secure code snippet showing how to implement the fix. Comment the code properly, explaining what makes it secure. Prefer standard Node.js/Express, Python, or generic clean backend code as appropriate.

Provide ONLY the raw JSON object. Do not wrap the JSON in markdown code blocks like \\\`\\\`\\\`json or anything else. Just the raw JSON.`;

    const result = await model.generateContent(prompt);
    const responseText = result.response.text().trim();

    try {
      const parsed = JSON.parse(responseText);
      
      // Ensure all required fields are present
      return {
        aiExplanation: parsed.aiExplanation || description,
        aiImpact: parsed.aiImpact || "Potential security risk exposing endpoints to unauthorized access or manipulation.",
        aiFix: parsed.aiFix || recommendation,
        codeExample: parsed.codeExample || "// Standard remediation required.",
      };
    } catch (parseErr) {
      console.error('[AI Service] Failed to parse Gemini JSON response, using fallback:', responseText);
      return getFallbackEvaluation(issue, severity, description, recommendation);
    }
  } catch (apiErr: any) {
    console.error('[AI Service] Gemini API call failed, using fallback:', apiErr.message || apiErr);
    return getFallbackEvaluation(issue, severity, description, recommendation);
  }
};
