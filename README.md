# API Sentinel 🛡️
### AI-Powered API Security Vulnerability Scanner

API Sentinel is a professional, high-performance web application designed to automatically audit, analyze, and secure REST APIs. It runs high-speed, asynchronous security probes against target endpoints and integrates with **Google Gemini AI** to provide developer-friendly explanations, risk impact assessments, and secure code remediations.

---

## 🏗️ Architecture & Data Flow

API Sentinel utilizes a modern, 5-tier architecture that segregates the presentation, orchestration, scanning, and intelligence layers for optimal performance and scalability.

```
+------------------+      HTTPS / JSON      +---------------------+
|                  | ---------------------> |                     |
|  Next.js Client  |                        |   Express Gateway   |
|   (TypeScript)   | <--------------------- |    (Orchestrator)   |
|                  |      JWT Authed        |                     |
+------------------+                        +---------------------+
                                                       |
                                                       | Proxy Request
                                                       v
+------------------+     Asynchronous HTTP  +---------------------+
|                  | <--------------------- |                     |
|    Target API    |                        |   FastAPI Engine    |
|   (Under Test)   | ---------------------> |   (Python Scanner)  |
|                  |       Responses        |                     |
+------------------+                        +---------------------+
                                                       |
                                                       | MongoDB
                                                       v
                                            +---------------------+
                                            |                     |
                                            |   Google Gemini AI  |
                                            | (Threat Intelligence)
                                            +---------------------+
```

## 🔄 End-to-End Application Workflow

API Sentinel operates on a highly coordinated multi-step scanning and intelligence pipeline. Here is the step-by-step workflow:

```mermaid
graph TD
    A["User/Frontend Dashboard"] -->|1. Setup Target & Auth Config| B("Express Gateway Backend")
    B -->|2. Persist Target / Set Status: PENDING| C[("MongoDB Database")]
    B -->|3. Trigger Scan Request| D("FastAPI Python Scanner")
    
    subgraph FastAPI Scanning Suite
        D -->|4a. URL & Input Validation| E["Validator Modules"]
        D -->|4b. Fingerprint Server, TLS, & Framework| F["Fingerprint Module"]
        D -->|4c. Parse Endpoint Path Tree| G["OpenAPI Parser"]
        D -->|4d. Run Parallel Probes| H["Vulnerability Check Engines"]
    end
    
    H -->|SQLi, JWT, CORS, Rate Limit, Data Exposure| I["Raw Scan Findings"]
    I -->|5. Return JSON Report Payload| B
    
    subgraph AI Security Enrichment
        B -->|6a. Send Raw Vulnerabilities| J["Google Gemini AI Engine"]
        J -->|6b. Generate Contextual Remediation & Fixes| K["Enriched Findings"]
    end
    
    K -->|7. Calculate Scoring & Posture Drift| B
    B -->|8. Persist Findings & PDF Report| C
    B -->|9. Update Status: COMPLETED| A
    A -->|10. View Interactive Reports & Download PDF| L["User UI / PDFKit Report"]
```

### Detailed Execution Phase Breakdown

1. **Scan Initialization (Frontend & Backend)**
   * The user registers a target API URL inside the Next.js Dashboard. Optionally, the user can configure authentication criteria (e.g., Bearer token, Custom Header, Basic Auth) and upload an OpenAPI Specification.
   * The Next.js frontend sends a `POST /scan` payload to the Express Backend Gateway.
   * The Express Backend validates the request schema (using Zod), saves a scan instance in **MongoDB** initialized to a `PENDING` state, and returns the scan info.

2. **Trigger Scan & Environment Reconnaissance (Backend to FastAPI)**
   * When the user clicks **Start Scan**, the frontend sends a `POST /scan/start/:id` request containing transient credentials (never stored in DB).
   * The Backend sets the database scan status to `SCANNING` and routes the request to the high-performance Python FastAPI service.
   * The Scanner immediately runs URL validation and checks if TLS/HTTPS is enforced.
   * The **Fingerprinting Engine** analyzes headers and response signatures to deduce the target server (e.g., Nginx, Apache), application framework (e.g., Express, FastAPI), hosting environment (e.g., AWS, Heroku), and connection latency.

3. **Discovery & Crawling Tree Resolution**
   * If an OpenAPI specification was provided, the scanner parses it to extract every declared route and supported HTTP verb (GET, POST, etc.) and maps them as an endpoint tree.
   * If no OpenAPI spec is provided, it targets the primary root URL.
   * To keep scans fast and optimized, the scanner compiles a list of up to 10 unique target endpoints to query in parallel.

4. **Vulnerability Probing & Security Test Suite**
   * The scanner spawns asynchronous HTTP client tasks (`aiohttp`) to inspect each target endpoint using dedicated checking modules:
     * **SQL Injection (SQLi)**: Tests input parameters using SQL syntax disclosures and blind sleep-delay queries.
     * **Broken Authentication & JWT Checks**: Inspects authorization mechanisms, analyzing tokens for weak signing keys or "none" algorithm bypasses.
     * **Excessive Data Exposure**: Evaluates response bodies against regex lists looking for leaked environment files, AWS keys, database connection strings, JWTs, and private keys.
     * **CORS Policies**: Probes headers to detect wildcards (`*`) or unreflected origin vulnerabilities.
     * **Rate Limiting Checks**: Floods the endpoint to determine if rate limit blocks (HTTP 429) or throttling features are in place.
     * **HTTP Security Headers**: Checks for standard defensive headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options).

5. **AI Enrichment and Remediation Generation (Gemini AI)**
   * The FastAPI scanner packages all security check findings, calculates a security score and returns the payload to the Backend.
   * The Express Backend receives raw findings and filters out passed checks and informational messages.
   * For every actual vulnerability found, the Backend invokes **Google Gemini AI** (using Gemini 1.5/3.5 Flash).
   * Gemini analyzes the raw vulnerability context and generates:
     * A developer-focused description of the risk.
     * An impact assessment explaining how an attacker could exploit it.
     * An exact secure refactoring block (code patch) to remediate the vulnerability.
   * These enriched details are dynamically saved back to the database.

6. **Historical Posture Comparison (Drift Analysis)**
   * The Backend queries the database for the user's previous completed scan against the same target URL.
   * The comparison service performs **Drift Analysis** to compute the security score change, identifies new vulnerabilities, and marks resolved issues.

7. **PDF Reporting & Frontend Presentation**
   * The Express backend utilizes `PDFKit` to compile a professional, print-ready PDF audit containing visual security scores, category breakdowns, and AI-generated code patches.
   * The scan status changes to `COMPLETED`. The Next.js dashboard receives the update and renders dynamic charts, severity indicators, interactive code editors with the secure fixes, and a download link for the PDF report.

---

## ✨ Features

* **Secure Authentication**: Built-in signup, login, and token-based state preservation using JSON Web Tokens (JWT) and secure cookie backups.
* **Asynchronous API Scanning**: Runs high-speed parallel probes against endpoints to detect vulnerabilities without blocking.
* **OWASP-Inspired Security Checks**:
  * **Transport Layer Security**: Verifies SSL/TLS enforcement and identifies unencrypted HTTP channels.
  * **HTTP Security Headers**: Checks for missing defensive headers (`Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Strict-Transport-Security`).
  * **SQL Injection (SQLi)**: Probes endpoints for SQL syntax error disclosures and time-delay vulnerabilities.
  * **Excessive Data Exposure**: Analyzes responses for leaked secrets, credentials, API keys, or full database record projections.
  * **Broken JWT Verification**: Tests for weak signing keys, insecure algorithms, or the `'none'` algorithm bypass.
  * **Rate Limiting Checks**: Audits endpoints for API abuse protection.
* **AI-Powered Threat Analysis**: Provides human-readable descriptions of security risks and exact copy-pasteable, secure refactoring snippets.
* **Professional PDF Reporting**: Exports beautifully formatted PDF assessment reports including a security score, severity card breakdown, and AI remediations.
* **Self-Documenting API**: Fully interactive Swagger UI available out of the box for testing backend endpoints.

---

## 🛠️ Tech Stack

* **Frontend**: Next.js 14, TypeScript, Tailwind CSS, Lucide Icons, Axios.
* **Backend**: Node.js, Express, TypeScript, Mongoose, Swagger UI, PDFKit.
* **Scanner**: Python 3, FastAPI, Uvicorn, aiohttp, asyncio.
* **Database**: MongoDB (Mongoose ODM).
* **AI Core**: Google Gemini AI (via `@google/generative-ai` SDK) with high-quality offline fallbacks.

---

## 🚀 Installation & Setup

Ensure you have **Node.js (v18+)**, **Python (v3.9+)**, and **MongoDB** installed and running locally.

### 1. Database Setup
Ensure MongoDB is running locally on its default port:
```bash
mongodb://localhost:27017/
```

### 2. Backend Gateway
1. Navigate to the `backend/` directory:
   ```bash
   cd backend
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Create a `.env` file from the template:
   ```bash
   cp .env.example .env
   ```
4. Update the variables in `.env` (add your `GEMINI_API_KEY` for live AI generation; if left empty, the application will automatically fall back to its robust offline security knowledge library).
5. Start the development server:
   ```bash
   npm run dev
   ```
   *The backend will start on **`http://localhost:5000`**.*

### 3. FastAPI Scanner Engine
1. Navigate to the `scanner/` directory:
   ```bash
   cd scanner
   ```
2. Create a Python virtual environment and activate it:
   ```bash
   python -m venv venv
   # On Windows:
   .\venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   ```
3. Install the required Python libraries:
   ```bash
   pip install -r requirements.txt
   ```
4. Start the FastAPI service:
   ```bash
   uvicorn app:app --reload
   ```
   *The scanner service will start on **`http://localhost:8000`**.*

### 4. Frontend Application
1. Navigate to the `frontend/` directory:
   ```bash
   cd frontend
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Start the Next.js development server:
   ```bash
   npm run dev
   ```
   *The frontend will start on **`http://localhost:3000`**.*

---

## 📈 Screenshots

### 1. Secure Authentication
*Register and authenticate sessions with JWT-protected route guards.*
*(Placeholder: `public/screenshots/login.png`)*

### 2. Interactive Dashboard
*Analyze all configured target scopes, check average security posture scores, and track recent runs.*
*(Placeholder: `public/screenshots/dashboard.png`)*

### 3. Detailed Scan Findings & AI Recommendations
*Drill down into specific endpoints to view raw findings, confidence metrics, and Gemini AI-generated secure code blocks.*
*(Placeholder: `public/screenshots/scan_details.png`)*

### 4. Professional Swagger Documentation
*Explore and interact with backend routes at `/api/docs` in real time.*
*(Placeholder: `public/screenshots/swagger.png`)*

### 5. Exported PDF Security Assessment
*Download a highly styled, print-ready PDF assessment report for stakeholder review.*
*(Placeholder: `public/screenshots/pdf_report.png`)*

---

## 🧭 API Reference

API Sentinel is self-documenting. Start the backend server and navigate to:
```
http://localhost:5000/api/docs
```

### Key Endpoints
* **Health Check**: `GET /health` (Returns gateway health and version)
* **Auth**:
  * `POST /auth/register` (Create a new account)
  * `POST /auth/login` (Authenticate credentials)
  * `GET /profile` (Retrieve session profile details)
* **Scanner**:
  * `POST /scan` (Register target URL)
  * `GET /scans` (Retrieve user scan targets and statistics)
  * `GET /scan/{id}` (Retrieve target findings and AI analysis)
  * `POST /scan/start/{id}` (Trigger security probe execution)
  * `GET /scan/{id}/pdf` (Download formatted PDF assessment report)

---

## 🔮 Future Roadmap

API Sentinel is built with extension in mind. Key features planned for future releases include:
1. **OpenAPI File Uploads**: Enable users to upload an `openapi.json` file to automatically parse, map, and scan all documented endpoints.
2. **Queue-Based Scanning**: Implement **Redis** and **BullMQ** to run scans as background jobs, supporting longer timeout limits and queue scheduling.
3. **WebSockets Integration**: Use **Socket.io** to stream live, real-time scanning progress updates and probe logs directly to the dashboard.
4. **Additional OWASP API Checks**: Add dedicated fuzzing checks for Broken Object-Level Authorization (BOLA), Broken Function-Level Authorization (BFLA), and SSRF.
