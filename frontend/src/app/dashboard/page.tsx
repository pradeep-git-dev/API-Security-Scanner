'use client';

import React, { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import api from '../../utils/api';

interface Scan {
  _id: string;
  targetUrl: string;
  status: string;
  score: number;
  createdAt: string;
}

export default function DashboardPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [targetUrl, setTargetUrl] = useState('');
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const router = useRouter();

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (!token) {
      router.push('/login');
      return;
    }
    fetchScans();
  }, [router]);

  const fetchScans = async () => {
    setLoading(true);
    setError('');
    try {
      const response = await api.get('/scans');
      setScans(response.data.scans || []);
    } catch (err: any) {
      console.error(err);
      if (err.response?.status === 401) {
        localStorage.removeItem('token');
        router.push('/login');
      } else {
        setError('Failed to fetch scans. Please try again.');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleCreateScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setMessage('');
    setSubmitting(true);

    try {
      const response = await api.post('/scan', { targetUrl });
      setMessage('Scan started successfully!');
      setTargetUrl('');
      // Prepend new scan to list
      if (response.data.scan) {
        setScans((prev) => [response.data.scan, ...prev]);
      }
    } catch (err: any) {
      console.error(err);
      setError(
        err.response?.data?.message || 
        err.response?.data?.errors?.targetUrl?.message ||
        'Failed to start scan. Ensure URL is valid.'
      );
    } finally {
      setSubmitting(false);
    }
  };

  const handleDeleteScan = async (id: string) => {
    setError('');
    setMessage('');
    if (!confirm('Are you sure you want to delete this scan?')) return;

    try {
      await api.delete(`/scan/${id}`);
      setMessage('Scan deleted successfully.');
      setScans((prev) => prev.filter((scan) => scan._id !== id));
    } catch (err: any) {
      console.error(err);
      setError(err.response?.data?.message || 'Failed to delete scan.');
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    router.push('/login');
  };

  return (
    <div style={{ padding: '30px', maxWidth: '800px', margin: 'auto', fontFamily: 'sans-serif' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '30px' }}>
        <h1>API Sentinel - Dashboard</h1>
        <button 
          onClick={handleLogout}
          style={{ padding: '8px 15px', backgroundColor: '#e0e0e0', border: '1px solid #ccc', cursor: 'pointer' }}
        >
          Logout
        </button>
      </div>

      {error && <div style={{ color: 'red', padding: '10px', border: '1px solid red', marginBottom: '20px', backgroundColor: '#fff8f8' }}>{error}</div>}
      {message && <div style={{ color: 'green', padding: '10px', border: '1px solid green', marginBottom: '20px', backgroundColor: '#f8fff8' }}>{message}</div>}

      <div style={{ padding: '20px', border: '1px solid #ddd', borderRadius: '5px', marginBottom: '40px', backgroundColor: '#f9f9f9' }}>
        <h2>Start New Scan</h2>
        <form onSubmit={handleCreateScan} style={{ display: 'flex', gap: '10px' }}>
          <input
            type="text"
            placeholder="Target URL (e.g. https://example.com)"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            required
            style={{ flex: 1, padding: '10px', border: '1px solid #ccc' }}
          />
          <button 
            type="submit" 
            disabled={submitting}
            style={{ padding: '10px 20px', backgroundColor: '#0070f3', color: 'white', border: 'none', cursor: 'pointer' }}
          >
            {submitting ? 'Starting...' : 'Start Scan'}
          </button>
        </form>
      </div>

      <h2>Recent Scans</h2>
      {loading ? (
        <p>Loading scans...</p>
      ) : scans.length === 0 ? (
        <p>No scans found. Start a scan above!</p>
      ) : (
        <table style={{ width: '100%', borderCollapse: 'collapse', marginTop: '10px' }}>
          <thead>
            <tr style={{ borderBottom: '2px solid #ccc', textAlign: 'left' }}>
              <th style={{ padding: '10px' }}>URL</th>
              <th style={{ padding: '10px' }}>Status</th>
              <th style={{ padding: '10px' }}>Score</th>
              <th style={{ padding: '10px' }}>Created Time</th>
              <th style={{ padding: '10px' }}>Action</th>
            </tr>
          </thead>
          <tbody>
            {scans.map((scan) => (
              <tr key={scan._id} style={{ borderBottom: '1px solid #eee' }}>
                <td style={{ padding: '10px', wordBreak: 'break-all' }}>{scan.targetUrl}</td>
                <td style={{ padding: '10px' }}>
                  <span style={{
                    padding: '3px 8px',
                    borderRadius: '3px',
                    fontSize: '12px',
                    fontWeight: 'bold',
                    backgroundColor: 
                      scan.status === 'COMPLETED' ? '#e1f5fe' : 
                      scan.status === 'FAILED' ? '#ffebee' : 
                      scan.status === 'SCANNING' ? '#e8f5e9' : '#eceff1',
                    color: 
                      scan.status === 'COMPLETED' ? '#0288d1' : 
                      scan.status === 'FAILED' ? '#c62828' : 
                      scan.status === 'SCANNING' ? '#2e7d32' : '#37474f'
                  }}>
                    {scan.status}
                  </span>
                </td>
                <td style={{ padding: '10px' }}>{scan.score ?? 0}</td>
                <td style={{ padding: '10px' }}>
                  {new Date(scan.createdAt || new Date()).toLocaleString()}
                </td>
                <td style={{ padding: '10px' }}>
                  <button
                    onClick={() => handleDeleteScan(scan._id)}
                    style={{ padding: '5px 10px', backgroundColor: '#d32f2f', color: 'white', border: 'none', cursor: 'pointer' }}
                  >
                    Delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
