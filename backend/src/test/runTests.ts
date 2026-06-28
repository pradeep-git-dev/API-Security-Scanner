import axios from 'axios';
import mongoose from 'mongoose';
import User from '../models/User';
import Scan from '../models/Scan';

const API_URL = process.env.API_URL || 'http://localhost:5000';

async function run() {
  console.log('--- Starting Integration Tests ---');
  
  // Connect to DB directly
  const mongoUri = process.env.MONGO_URI || 'mongodb://localhost:27017/api-sentinel';
  await mongoose.connect(mongoUri);
  console.log('Connected to MongoDB.');

  // Clean up existing test users if any
  await User.deleteMany({ email: { $in: ['user1@test.com', 'user2@test.com'] } });
  
  // 1. Register User 1
  console.log('\nTesting User 1 Registration...');
  const reg1Res = await axios.post(`${API_URL}/auth/register`, {
    name: 'User One',
    email: 'user1@test.com',
    password: 'password123',
  });
  if (reg1Res.status !== 201 || !reg1Res.data.token) {
    throw new Error('User 1 registration failed');
  }
  const token1 = reg1Res.data.token;
  console.log('User 1 registered successfully.');

  // 2. Register User 2
  console.log('Testing User 2 Registration...');
  const reg2Res = await axios.post(`${API_URL}/auth/register`, {
    name: 'User Two',
    email: 'user2@test.com',
    password: 'password123',
  });
  if (reg2Res.status !== 201 || !reg2Res.data.token) {
    throw new Error('User 2 registration failed');
  }
  const token2 = reg2Res.data.token;
  console.log('User 2 registered successfully.');

  // 3. Test Scan Creation Validation (Invalid URL)
  console.log('\nTesting Scan Creation Validation with invalid URL...');
  try {
    await axios.post(
      `${API_URL}/scan`,
      { targetUrl: 'invalid-url' },
      { headers: { Authorization: `Bearer ${token1}` } }
    );
    throw new Error('Scan creation succeeded for invalid URL (expected failure)');
  } catch (error: any) {
    if (error.response?.status === 400) {
      console.log('Validation correctly rejected invalid URL.');
    } else {
      throw error;
    }
  }

  // 4. Test Scan Creation (Valid URL)
  console.log('Testing Scan Creation with valid URL...');
  const scanCreateRes = await axios.post(
    `${API_URL}/scan`,
    { targetUrl: 'https://example.com' },
    { headers: { Authorization: `Bearer ${token1}` } }
  );
  if (scanCreateRes.status !== 201) {
    throw new Error('Scan creation failed');
  }
  const scan = scanCreateRes.data.scan;
  console.log('Scan created successfully:', scan._id);

  // 5. Verify Scan Stored in MongoDB
  console.log('Verifying Scan in MongoDB...');
  const dbScan = await Scan.findById(scan._id);
  if (!dbScan) {
    throw new Error('Scan not found in database');
  }
  if (dbScan.status !== 'PENDING' || dbScan.progress !== 0) {
    throw new Error(`Unexpected scan state in DB: status=${dbScan.status}, progress=${dbScan.progress}`);
  }
  console.log('Scan successfully verified in MongoDB.');

  // 6. Test Scan List Loading
  console.log('\nTesting Scan List Loading for User 1...');
  const list1Res = await axios.get(`${API_URL}/scans`, {
    headers: { Authorization: `Bearer ${token1}` },
  });
  if (list1Res.data.scans.length !== 1 || list1Res.data.scans[0]._id !== scan._id) {
    throw new Error('User 1 scan list verification failed');
  }
  console.log('User 1 scan list loaded correctly.');

  console.log('Testing Scan List Loading for User 2 (should be empty)...');
  const list2Res = await axios.get(`${API_URL}/scans`, {
    headers: { Authorization: `Bearer ${token2}` },
  });
  if (list2Res.data.scans.length !== 0) {
    throw new Error('User 2 scan list is not empty (expected empty)');
  }
  console.log('User 2 scan list loaded correctly (empty).');

  // 7. Test Access Control (Ownership Check)
  console.log('\nTesting access control (User 2 trying to get User 1\'s scan)...');
  try {
    await axios.get(`${API_URL}/scan/${scan._id}`, {
      headers: { Authorization: `Bearer ${token2}` },
    });
    throw new Error('User 2 successfully fetched User 1\'s scan (expected 403)');
  } catch (error: any) {
    if (error.response?.status === 403) {
      console.log('Access control correctly blocked unauthorized access (403 Forbidden).');
    } else {
      throw error;
    }
  }

  // 8. Test Running Scan (Trigger scan microservice)
  console.log('\nTesting trigger scan (Express -> FastAPI dummy check)...');
  const triggerRes = await axios.post(
    `${API_URL}/scan/start/${scan._id}`,
    {},
    { headers: { Authorization: `Bearer ${token1}` } }
  );
  if (triggerRes.status !== 200 || !triggerRes.data.findings) {
    throw new Error('Failed to trigger scan or no findings returned');
  }
  console.log('Trigger scan responded successfully.');
  console.log('Returned findings:', triggerRes.data.findings);

  // 9. Test Delete Scan and associated data
  console.log('\nTesting delete scan (User 2 attempting to delete User 1\'s scan)...');
  try {
    await axios.delete(`${API_URL}/scan/${scan._id}`, {
      headers: { Authorization: `Bearer ${token2}` },
    });
    throw new Error('User 2 successfully deleted User 1\'s scan (expected 403)');
  } catch (error: any) {
    if (error.response?.status === 403) {
      console.log('Access control correctly blocked unauthorized delete (403 Forbidden).');
    } else {
      throw error;
    }
  }

  console.log('Testing delete scan (User 1 deleting own scan)...');
  const deleteRes = await axios.delete(`${API_URL}/scan/${scan._id}`, {
    headers: { Authorization: `Bearer ${token1}` },
  });
  if (deleteRes.status !== 200) {
    throw new Error('Failed to delete scan as owner');
  }
  console.log('Delete scan API call succeeded.');

  // Verify deletion in DB
  const deletedScan = await Scan.findById(scan._id);
  if (deletedScan) {
    throw new Error('Scan still exists in database after deletion');
  }
  console.log('Verified scan is completely removed from DB.');

  // Clean up users
  await User.deleteMany({ email: { $in: ['user1@test.com', 'user2@test.com'] } });
  
  await mongoose.disconnect();
  console.log('\n--- All Tests Passed Successfully! ---');
}

run().catch(async (err) => {
  console.error('Test failed with error:', err.message || err);
  if (err.response?.data) {
    console.error('Response data:', err.response.data);
  }
  await mongoose.disconnect();
  process.exit(1);
});
