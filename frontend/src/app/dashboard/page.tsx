'use client';

import React, { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { Shield, Play, Trash2, ArrowRight, Activity, Award, ShieldAlert, Plus, Loader2, LogOut, Globe, Calendar } from 'lucide-react';
import api from '../../utils/api';

interface Scan {
  _id: string;
  targetUrl: string;
  status: string;
  score: number;
  createdAt: string;
}

interface Stats {
  totalScans: number;
  averageScore: number;
  criticalFindings: number;
}

export default function DashboardPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [stats, setStats] = useState<Stats>({ totalScans: 0, averageScore: 100, criticalFindings: 0 });
  const [targetUrl, setTargetUrl] = useState('');
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [runningScans, setRunningScans] = useState<Record<string, boolean>>({});
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
      
      if (response.data.stats) {
        setStats(response.data.stats);
      } else {
        // Fallback calculation in case backend stats are not available
        const list = response.data.scans || [];
        const total = list.length;
        const completed = list.filter((s: Scan) => s.status === 'COMPLETED');
        const avg = completed.length === 0 
          ? 100 
          : Math.round(completed.reduce((acc: number, s: Scan) => acc + (s.score || 0), 0) / completed.length);
        setStats({
          totalScans: total,
          averageScore: avg,
          criticalFindings: 0,
        });
      }
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
      setMessage('Scan configured successfully! Trigger it from the table below.');
      setTargetUrl('');
      
      if (response.data.scan) {
        const newScan = response.data.scan;
        setScans((prev) => [newScan, ...prev]);
        setStats((prev) => ({
          ...prev,
          totalScans: prev.totalScans + 1,
        }));
      }
    } catch (err: any) {
      console.error(err);
      setError(
        err.response?.data?.message || 
        err.response?.data?.errors?.targetUrl?.message ||
        'Failed to configure scan. Ensure URL is valid.'
      );
    } finally {
      setSubmitting(false);
    }
  };

  const handleDeleteScan = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setError('');
    setMessage('');
    if (!confirm('Are you sure you want to delete this scan and all its associated findings?')) return;

    try {
      await api.delete(`/scan/${id}`);
      setMessage('Scan deleted successfully.');
      setScans((prev) => prev.filter((scan) => scan._id !== id));
      
      // Recalculate stats locally
      fetchScans();
    } catch (err: any) {
      console.error(err);
      setError(err.response?.data?.message || 'Failed to delete scan.');
    }
  };

  const handleRunScan = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setError('');
    setMessage('');
    setRunningScans((prev) => ({ ...prev, [id]: true }));

    // Update local scan status to SCANNING
    setScans((prev) => 
      prev.map((s) => (s._id === id ? { ...s, status: 'SCANNING' } : s))
    );

    try {
      await api.post(`/scan/start/${id}`);
      setMessage('Scan completed successfully!');
      fetchScans(); // Refresh list and stats
    } catch (err: any) {
      console.error(err);
      setError(err.response?.data?.message || 'Failed to execute scan.');
      // Refresh list to restore correct status
      fetchScans();
    } finally {
      setRunningScans((prev) => ({ ...prev, [id]: false }));
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    router.push('/login');
  };

  const getStatusBadge = (status: string) => {
    const s = status.toUpperCase();
    if (s === 'COMPLETED') {
      return (
        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-100 text-emerald-800 border border-emerald-200 dark:bg-emerald-950/30 dark:text-emerald-300 dark:border-emerald-900/50">
          Completed
        </span>
      );
    } else if (s === 'SCANNING') {
      return (
        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-blue-100 text-blue-800 border border-blue-200 dark:bg-blue-950/30 dark:text-blue-300 dark:border-blue-900/50 animate-pulse">
          <Loader2 className="w-3 h-3 mr-1 animate-spin" /> Scanning
        </span>
      );
    } else if (s === 'FAILED') {
      return (
        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-100 text-rose-800 border border-rose-200 dark:bg-rose-950/30 dark:text-rose-300 dark:border-rose-900/50">
          Failed
        </span>
      );
    } else {
      return (
        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-100 text-amber-800 border border-amber-200 dark:bg-amber-950/30 dark:text-amber-300 dark:border-amber-900/50">
          Pending
        </span>
      );
    }
  };

  const getScoreColor = (score: number, status: string) => {
    if (status !== 'COMPLETED') return 'text-zinc-400 dark:text-zinc-600';
    if (score >= 90) return 'text-emerald-600 dark:text-emerald-400 font-bold';
    if (score >= 70) return 'text-amber-600 dark:text-amber-400 font-bold';
    return 'text-rose-600 dark:text-rose-400 font-bold';
  };

  return (
    <div className="min-h-screen bg-zinc-50 dark:bg-zinc-950 text-zinc-900 dark:text-zinc-100 font-sans pb-12">
      {/* Top Navbar */}
      <header className="sticky top-0 z-40 w-full bg-white/80 dark:bg-zinc-900/85 backdrop-blur border-b border-zinc-200 dark:border-zinc-800">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <span className="font-bold text-lg text-indigo-600 dark:text-indigo-400 tracking-tight flex items-center">
            <Shield className="w-5 h-5 mr-2" /> API Sentinel
          </span>
          <div className="flex items-center space-x-4">
            <button 
              onClick={handleLogout}
              className="inline-flex items-center space-x-2 px-3 py-1.5 border border-zinc-200 dark:border-zinc-800 hover:bg-zinc-50 dark:hover:bg-zinc-800 text-zinc-600 dark:text-zinc-300 rounded-lg text-sm font-medium transition-all cursor-pointer"
            >
              <LogOut className="w-4 h-4" />
              <span>Logout</span>
            </button>
          </div>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 pt-8 space-y-8">
        {/* Messages */}
        {error && (
          <div className="p-4 bg-rose-50 dark:bg-rose-950/20 border border-rose-200 dark:border-rose-900/50 rounded-xl text-sm text-rose-800 dark:text-rose-300 flex items-start">
            <ShieldAlert className="w-5 h-5 mr-3 text-rose-500 flex-shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}
        {message && (
          <div className="p-4 bg-emerald-50 dark:bg-emerald-950/15 border border-emerald-200 dark:border-emerald-900/40 rounded-xl text-sm text-emerald-800 dark:text-emerald-300 flex items-start">
            <Shield className="w-5 h-5 mr-3 text-emerald-500 flex-shrink-0 mt-0.5" />
            <span>{message}</span>
          </div>
        )}

        {/* Statistics Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-6">
          <div className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 p-6 rounded-xl shadow-sm flex items-center space-x-4">
            <div className="p-3 rounded-lg bg-indigo-50 dark:bg-indigo-950/30 text-indigo-600 dark:text-indigo-400">
              <Activity className="w-6 h-6" />
            </div>
            <div>
              <p className="text-xs font-semibold text-zinc-400 dark:text-zinc-500 uppercase tracking-wider">Total Scans</p>
              <p className="text-2xl font-extrabold text-zinc-900 dark:text-zinc-50 mt-1">{stats.totalScans}</p>
            </div>
          </div>

          <div className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 p-6 rounded-xl shadow-sm flex items-center space-x-4">
            <div className="p-3 rounded-lg bg-emerald-50 dark:bg-emerald-950/30 text-emerald-600 dark:text-emerald-400">
              <Award className="w-6 h-6" />
            </div>
            <div>
              <p className="text-xs font-semibold text-zinc-400 dark:text-zinc-500 uppercase tracking-wider">Average Score</p>
              <p className="text-2xl font-extrabold text-zinc-900 dark:text-zinc-50 mt-1">{stats.averageScore}</p>
            </div>
          </div>

          <div className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 p-6 rounded-xl shadow-sm flex items-center space-x-4">
            <div className="p-3 rounded-lg bg-rose-50 dark:bg-rose-950/30 text-rose-600 dark:text-rose-400">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <div>
              <p className="text-xs font-semibold text-zinc-400 dark:text-zinc-500 uppercase tracking-wider">Critical Findings</p>
              <p className="text-2xl font-extrabold text-zinc-900 dark:text-zinc-50 mt-1">{stats.criticalFindings}</p>
            </div>
          </div>
        </div>

        {/* Start New Scan Form */}
        <div className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-xl p-6 shadow-sm">
          <h2 className="text-lg font-bold text-zinc-900 dark:text-zinc-50 mb-1 flex items-center">
            Configure New Scan Target
          </h2>
          <p className="text-sm text-zinc-500 dark:text-zinc-400 mb-5">
            Add a target API endpoint to scan. Once configured, click 'Run Scan' to trigger security checks.
          </p>
          <form onSubmit={handleCreateScan} className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                <Globe className="w-5 h-5 text-zinc-400" />
              </div>
              <input
                type="url"
                placeholder="https://api.example.com/v1"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                required
                className="block w-full pl-10 pr-4 py-2.5 bg-zinc-50 dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 rounded-lg text-sm text-zinc-900 dark:text-zinc-100 placeholder-zinc-400 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all"
              />
            </div>
            <button 
              type="submit" 
              disabled={submitting}
              className="inline-flex items-center justify-center px-5 py-2.5 bg-indigo-600 hover:bg-indigo-700 disabled:bg-indigo-600/50 text-white rounded-lg text-sm font-medium transition-colors cursor-pointer"
            >
              {submitting ? (
                <>
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  <span>Configuring...</span>
                </>
              ) : (
                <>
                  <Plus className="w-4 h-4 mr-2" />
                  <span>Configure Target</span>
                </>
              )}
            </button>
          </form>
        </div>

        {/* Scan List Section */}
        <div className="space-y-4">
          <h2 className="text-xl font-bold text-zinc-900 dark:text-zinc-50">Recent Targets</h2>
          
          {loading ? (
            <div className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-xl p-12 shadow-sm text-center">
              <Loader2 className="w-8 h-8 text-indigo-600 animate-spin mx-auto mb-4" />
              <p className="text-zinc-600 dark:text-zinc-400 font-medium">Retrieving scan history...</p>
            </div>
          ) : scans.length === 0 ? (
            <div className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-xl p-12 shadow-sm text-center">
              <Globe className="w-12 h-12 text-zinc-350 dark:text-zinc-600 mx-auto mb-4" />
              <h3 className="text-lg font-bold text-zinc-900 dark:text-zinc-200 mb-1">No Scans Yet</h3>
              <p className="text-zinc-600 dark:text-zinc-400 max-w-sm mx-auto mb-6">
                Start your first scan by entering a target URL in the form above.
              </p>
            </div>
          ) : (
            <div className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-xl overflow-hidden shadow-sm">
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="bg-zinc-50 dark:bg-zinc-900/55 border-b border-zinc-200 dark:border-zinc-800 text-xs font-semibold text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">
                      <th className="py-4 px-6">Target URL</th>
                      <th className="py-4 px-6">Status</th>
                      <th className="py-4 px-6">Score</th>
                      <th className="py-4 px-6">Date Configured</th>
                      <th className="py-4 px-6 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scans.map((scan) => (
                      <tr 
                        key={scan._id}
                        onClick={() => router.push(`/dashboard/scan/${scan._id}`)}
                        className="border-b border-zinc-100 dark:border-zinc-800/60 hover:bg-zinc-50/40 dark:hover:bg-zinc-850/20 transition-colors cursor-pointer"
                      >
                        <td className="py-4 px-6 font-medium text-zinc-900 dark:text-zinc-100 break-all max-w-[280px]">
                          <div className="flex items-center space-x-2.5">
                            <Globe className="w-4 h-4 text-zinc-400 flex-shrink-0" />
                            <span className="truncate">{scan.targetUrl}</span>
                          </div>
                        </td>
                        <td className="py-4 px-6 whitespace-nowrap">
                          {getStatusBadge(scan.status)}
                        </td>
                        <td className="py-4 px-6 whitespace-nowrap font-semibold">
                          <span className={getScoreColor(scan.score ?? 0, scan.status)}>
                            {scan.status === 'COMPLETED' ? (scan.score ?? 0) : '—'}
                          </span>
                        </td>
                        <td className="py-4 px-6 whitespace-nowrap text-sm text-zinc-500 dark:text-zinc-400">
                          <div className="flex items-center space-x-2">
                            <Calendar className="w-4 h-4 text-zinc-400" />
                            <span>{new Date(scan.createdAt).toLocaleDateString()}</span>
                          </div>
                        </td>
                        <td className="py-4 px-6 whitespace-nowrap text-right">
                          <div className="flex items-center justify-end space-x-2.5">
                            <button
                              onClick={(e) => handleRunScan(scan._id, e)}
                              disabled={runningScans[scan._id] || scan.status === 'SCANNING'}
                              title="Execute Scan"
                              className="inline-flex items-center px-3 py-1.5 bg-emerald-650 hover:bg-emerald-700 disabled:bg-emerald-650/45 text-white rounded-lg text-xs font-semibold transition-colors cursor-pointer"
                            >
                              {runningScans[scan._id] ? (
                                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                              ) : (
                                <Play className="w-3.5 h-3.5 mr-1" />
                              )}
                              <span>{runningScans[scan._id] ? 'Running...' : 'Run'}</span>
                            </button>
                            <Link
                              href={`/dashboard/scan/${scan._id}`}
                              onClick={(e) => e.stopPropagation()}
                              className="inline-flex items-center px-3 py-1.5 border border-zinc-200 dark:border-zinc-800 hover:bg-zinc-50 dark:hover:bg-zinc-800 text-zinc-700 dark:text-zinc-300 rounded-lg text-xs font-semibold transition-colors"
                            >
                              <span>View</span>
                              <ArrowRight className="w-3.5 h-3.5 ml-1" />
                            </Link>
                            <button
                              onClick={(e) => handleDeleteScan(scan._id, e)}
                              title="Delete Scan"
                              className="p-1.5 text-zinc-400 hover:text-rose-600 hover:bg-rose-50 dark:hover:bg-rose-950/20 rounded-lg transition-all cursor-pointer"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
