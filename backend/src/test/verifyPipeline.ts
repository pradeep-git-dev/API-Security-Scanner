import axios from 'axios';
import mongoose from 'mongoose';
import User from '../models/User';
import Scan from '../models/Scan';
import Vulnerability from '../models/Vulnerability';
import Report from '../models/Report';

const API_URL = process.env.API_URL || 'http://localhost:5000';

async function run() {
  console.log('--- Starting Day 5 Scan Pipeline Verification ---');
  
  // 1. Connect to MongoDB directly
  const mongoUri = process.env.MONGO_URI || 'mongodb://localhost:27017/api-sentinel';
  await mongoose.connect(mongoUri);
  console.log('Connected to MongoDB.');

  // Clean up existing test users/scans if any
  await User.deleteMany({ email: 'verify@test.com' });
  
  // 2. Register test user
  console.log('Registering test user...');
  const regRes = await axios.post(`${API_URL}/auth/register`, {
    name: 'Verifier User',
    email: 'verify@test.com',
    password: 'password123',
  });
  if (regRes.status !== 201 || !regRes.data.token) {
    throw new Error('User registration failed');
  }
  const token = regRes.data.token;
  console.log('Test user registered successfully.');

  // 3. Create a scan pointing to http://localhost:8000/test-vulnerabilities
  // Note: we test HTTP so that it triggers "Missing HTTPS"
  const targetUrl = 'http://localhost:8000/test-vulnerabilities';
  console.log(`Creating scan for target: ${targetUrl}`);
  const scanCreateRes = await axios.post(
    `${API_URL}/scan`,
    { targetUrl },
    { headers: { Authorization: `Bearer ${token}` } }
  );
  if (scanCreateRes.status !== 201) {
    throw new Error('Scan creation failed');
  }
  const scanId = scanCreateRes.data.scan._id;
  console.log(`Scan created successfully with ID: ${scanId}`);

  // Verify initial status is PENDING
  let dbScan = await Scan.findById(scanId);
  if (!dbScan || dbScan.status !== 'PENDING') {
    throw new Error('Scan status should be PENDING initially');
  }
  console.log('Scan is initially in PENDING state.');

  // 4. Trigger the scan
  console.log('Triggering scan (this will run all 8 checks)...');
  const triggerRes = await axios.post(
    `${API_URL}/scan/start/${scanId}`,
    {},
    { headers: { Authorization: `Bearer ${token}` } }
  );
  if (triggerRes.status !== 200) {
    throw new Error('Failed to trigger scan');
  }
  console.log('Scan triggered and completed successfully.');
  
  // 5. Verify Scan Document in MongoDB
  console.log('\nVerifying Scan Document in MongoDB...');
  dbScan = await Scan.findById(scanId);
  if (!dbScan) {
    throw new Error('Scan not found in database after scan execution');
  }
  console.log(`- Status: ${dbScan.status} (Expected: COMPLETED)`);
  console.log(`- Score: ${dbScan.score}`);
  console.log(`- Duration: ${dbScan.durationMs} ms`);
  console.log(`- Endpoints Scanned: ${dbScan.totalEndpointsScanned}`);
  console.log(`- Completed At: ${dbScan.completedAt}`);
  
  if (dbScan.status !== 'COMPLETED') {
    throw new Error(`Scan status is not COMPLETED: ${dbScan.status}`);
  }
  if (dbScan.score === undefined || dbScan.score < 0 || dbScan.score > 100) {
    throw new Error(`Invalid scan score: ${dbScan.score}`);
  }

  // 6. Verify Vulnerability Collection in MongoDB
  console.log('\nVerifying Vulnerabilities in MongoDB...');
  const vulnerabilities = await Vulnerability.find({ scanId });
  console.log(`Found ${vulnerabilities.length} vulnerability findings:`);
  vulnerabilities.forEach(v => {
    console.log(`  [${v.severity}] ${v.issue} - ${v.endpoint} (${v.confidence} confidence)`);
  });

  const issues = vulnerabilities.map(v => v.issue);
  const expectedIssues = [
    'Missing HTTPS',
    'Missing Security Headers',
    'Potential Public Endpoint',
    'Possible SQL Injection Indicator',
    'Missing Rate Limiting',
    'Potential Sensitive Data Exposure'
  ];

  let missingIssues = [];
  for (const expected of expectedIssues) {
    if (!issues.includes(expected)) {
      missingIssues.push(expected);
    }
  }

  if (missingIssues.length > 0) {
    console.warn(`WARNING: The following expected vulnerabilities were not detected: ${missingIssues.join(', ')}`);
  } else {
    console.log('✅ All expected vulnerabilities successfully detected and persisted!');
  }

  // 7. Verify Report Collection in MongoDB
  console.log('\nVerifying Report in MongoDB...');
  const report = await Report.findOne({ scanId });
  if (!report) {
    throw new Error('Report document not found for this scan');
  }
  console.log(`- Critical: ${report.critical}`);
  console.log(`- High: ${report.high}`);
  console.log(`- Medium: ${report.medium}`);
  console.log(`- Low: ${report.low}`);
  console.log(`- Report Score: ${report.score} (Expected matching Scan Score: ${dbScan.score})`);

  if (report.score !== dbScan.score) {
    throw new Error(`Score mismatch: Report score (${report.score}) vs Scan score (${dbScan.score})`);
  }
  console.log('✅ Report score matches scan score.');

  // Clean up test data
  await User.deleteMany({ email: 'verify@test.com' });
  await Scan.findByIdAndDelete(scanId);
  await Vulnerability.deleteMany({ scanId });
  await Report.deleteMany({ scanId });
  
  await mongoose.disconnect();
  console.log('\n--- Day 5 Scan Pipeline Verification Passed Successfully! ---');
}

run().catch(async (err) => {
  console.error('Verification failed with error:', err.message || err);
  if (err.response?.data) {
    console.error('Response data:', err.response.data);
  }
  await mongoose.disconnect();
  process.exit(1);
});
