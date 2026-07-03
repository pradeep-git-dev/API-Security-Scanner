'use client';

import React, { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { 
  Shield, Play, Trash2, ArrowRight, Activity, Award, ShieldAlert, 
  Plus, Loader2, LogOut, Globe, Calendar, Clock, ChevronDown, ChevronUp, FileText, Key, Eye, EyeOff
} from 'lucide-react';
import api from '../../utils/api';

interface Scan {
  _id: string;
  targetUrl: string;
  status: string;
  score: number;
  createdAt: string;
  durationMs?: number;
}

interface Stats {
  totalScans: number;
  averageScore: number;
  criticalFindings: number;
  lastScanTime?: string | null;
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
  
  // Advanced Scan Configuration State
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [authType, setAuthType] = useState('None');
  const [headerName, setHeaderName] = useState('');
  const [tokenValue, setTokenValue] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [openApiSpec, setOpenApiSpec] = useState('');
  const [fileName, setFileName] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  
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
          lastScanTime: list.length > 0 ? (list[0].completedAt || list[0].createdAt) : null,
        });
      }
    } catch (err: any) {
      console.error(err);
      if (err.response?.status === 401) {
        console.log("Status:", err.response?.status);
        console.log("Data:", err.response?.data);
        console.log("Headers:", err.response?.headers);
        alert(JSON.stringify(err.response?.data));
      } else {
        setError('Failed to fetch scans. Please try again.');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setFileName(file.name);
    
    const reader = new FileReader();
    reader.onload = (event) => {
      if (event.target?.result) {
        setOpenApiSpec(event.target.result as string);
      }
    };
    reader.readAsText(file);
  };

  const handleCreateScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setMessage('');
    setSubmitting(true);

    try {
      // 1. Build auth config parameters
      let resolvedHeaderName = undefined;
      if (authType === 'Bearer') {
        resolvedHeaderName = 'Authorization';
      } else if (authType === 'Basic') {
        resolvedHeaderName = 'Authorization';
      } else if (authType === 'API Key') {
        resolvedHeaderName = headerName || 'x-api-key';
      } else if (authType === 'Custom Header') {
        resolvedHeaderName = headerName;
      }

      const response = await api.post('/scan', { 
        targetUrl,
        authConfig: authType !== 'None' ? {
          authType,
          headerName: resolvedHeaderName,
        } : undefined,
        openApiSpec: openApiSpec || undefined
      });

      setMessage('Target configured successfully! Click "Run" to launch scanning.');
      setTargetUrl('');
      // Reset advanced config
      setAuthType('None');
      setHeaderName('');
      setTokenValue('');
      setUsername('');
      setPassword('');
      setOpenApiSpec('');
      setFileName('');
      setShowAdvanced(false);
      
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
        'Failed to configure target. Ensure URL format is correct.'
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

    setScans((prev) => 
      prev.map((s) => (s._id === id ? { ...s, status: 'SCANNING' } : s))
    );

    // Build credentials payload for transient injection
    let payloadToken = tokenValue;
    if (authType === 'Basic') {
      payloadToken = btoa(`${username}:${password}`);
    }

    try {
      await api.post(`/scan/start/${id}`, {
        tokenValue: payloadToken || undefined,
        username: username || undefined,
        password: password || undefined,
        openApiSpec: openApiSpec || undefined
      });
      setMessage('Scan completed successfully!');
      fetchScans();
    } catch (err: any) {
      console.error(err);
      setError(err.response?.data?.message || 'Failed to execute scan.');
      fetchScans();
    } finally {
      setRunningScans((prev) => ({ ...prev, [id]: false }));
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    document.cookie = 'token=; path=/; expires=Thu, 01 Jan 1970 00:00:00 UTC; SameSite=Lax;';
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
    if (status !== 'COMPLETED') return 'text-zinc-400 dark:text-zinc-650';
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
              onClick={fetchScans}
              className="px-3 py-1.5 border border-zinc-200 dark:border-zinc-800 hover:bg-zinc-50 dark:hover:bg-zinc-800 text-zinc-650 dark:text-zinc-300 rounded-lg text-xs font-semibold transition-all cursor-pointer"
            >
              Refresh
            </button>
            <button 
              onClick={handleLogout}
              className="inline-flex items-center space-x-2 px-3 py-1.5 border border-zinc-200 dark:border-zinc-800 hover:bg-zinc-50 dark:hover:bg-zinc-800 text-zinc-650 dark:text-zinc-305 rounded-lg text-sm font-medium transition-all cursor-pointer"
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
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
          <div className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 p-6 rounded-xl shadow-sm flex items-center space-x-4">
            <div className="p-3 rounded-lg bg-indigo-50 dark:bg-indigo-950/30 text-indigo-600 dark:text-indigo-400">
              <Activity className="w-6 h-6" />
            </div>
            <div>
              <p className="text-xs font-semibold text-zinc-405 dark:text-zinc-500 uppercase tracking-wider">Total Scans</p>
              <p className="text-2xl font-extrabold text-zinc-900 dark:text-zinc-50 mt-1">{stats.totalScans}</p>
            </div>
          </div>

          <div className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 p-6 rounded-xl shadow-sm flex items-center space-x-4">
            <div className="p-3 rounded-lg bg-emerald-50 dark:bg-emerald-950/30 text-emerald-600 dark:text-emerald-400">
              <Award className="w-6 h-6" />
            </div>
            <div>
              <p className="text-xs font-semibold text-zinc-405 dark:text-zinc-500 uppercase tracking-wider">Average Score</p>
              <p className="text-2xl font-extrabold text-zinc-900 dark:text-zinc-50 mt-1">{stats.averageScore}</p>
            </div>
          </div>

          <div className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 p-6 rounded-xl shadow-sm flex items-center space-x-4">
            <div className="p-3 rounded-lg bg-rose-50 dark:bg-rose-950/30 text-rose-600 dark:text-rose-400">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <div>
              <p className="text-xs font-semibold text-zinc-405 dark:text-zinc-500 uppercase tracking-wider">Critical Findings</p>
              <p className="text-2xl font-extrabold text-zinc-900 dark:text-zinc-50 mt-1">{stats.criticalFindings}</p>
            </div>
          </div>

          <div className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 p-6 rounded-xl shadow-sm flex items-center space-x-4">
            <div className="p-3 rounded-lg bg-purple-50 dark:bg-purple-950/30 text-purple-600 dark:text-purple-400">
              <Clock className="w-6 h-6" />
            </div>
            <div>
              <p className="text-xs font-semibold text-zinc-405 dark:text-zinc-500 uppercase tracking-wider">Last Scan Time</p>
              <p className="text-sm font-bold text-zinc-900 dark:text-zinc-50 mt-1 truncate" title={stats.lastScanTime ? new Date(stats.lastScanTime).toLocaleString() : 'Never'}>
                {stats.lastScanTime 
                  ? new Date(stats.lastScanTime).toLocaleString([], { dateStyle: 'short', timeStyle: 'short' }) 
                  : 'Never'}
              </p>
            </div>
          </div>
        </div>

        {/* Start New Scan Form */}
        <div className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-xl p-6 shadow-sm space-y-4">
          <h2 className="text-lg font-bold text-zinc-900 dark:text-zinc-50 mb-1 flex items-center">
            Configure New Scan Target
          </h2>
          <p className="text-sm text-zinc-500 dark:text-zinc-400">
            Add a target API endpoint to scan. Once configured, click 'Run Scan' to trigger security checks.
          </p>
          
          <form onSubmit={handleCreateScan} className="space-y-4">
            <div className="flex flex-col sm:flex-row gap-3">
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
                className="inline-flex items-center justify-center px-5 py-2.5 bg-indigo-605 hover:bg-indigo-700 disabled:bg-indigo-600/50 text-white rounded-lg text-sm font-medium transition-colors cursor-pointer"
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
            </div>

            {/* Collapsible Advanced Config panel */}
            <div className="border border-zinc-200/60 dark:border-zinc-800 rounded-lg overflow-hidden">
              <button
                type="button"
                onClick={() => setShowAdvanced(!showAdvanced)}
                className="w-full flex items-center justify-between px-4 py-3 bg-zinc-50 dark:bg-zinc-900/50 hover:bg-zinc-100 dark:hover:bg-zinc-900 text-sm font-semibold transition-colors cursor-pointer text-zinc-700 dark:text-zinc-300"
              >
                <span className="flex items-center">
                  <Key className="w-4 h-4 mr-2 text-indigo-500" />
                  Advanced Scan Configuration (Authentication & OpenAPI)
                </span>
                {showAdvanced ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
              </button>

              {showAdvanced && (
                <div className="p-5 border-t border-zinc-200/60 dark:border-zinc-800 bg-white dark:bg-zinc-900/25 grid grid-cols-1 md:grid-cols-2 gap-6">
                  
                  {/* Left Column: Authentication Settings */}
                  <div className="space-y-4">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-zinc-400">Authentication Setup</h3>
                    
                    <div className="space-y-1.5">
                      <label className="text-xs font-medium text-zinc-500">Auth Type</label>
                      <select 
                        value={authType}
                        onChange={(e) => setAuthType(e.target.value)}
                        className="block w-full px-3.5 py-2 bg-zinc-50 dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                      >
                        <option value="None">None</option>
                        <option value="Bearer">Bearer Token</option>
                        <option value="Basic">Basic Authentication</option>
                        <option value="API Key">API Key</option>
                        <option value="Custom Header">Custom Header</option>
                      </select>
                    </div>

                    {authType === 'Basic' && (
                      <div className="grid grid-cols-2 gap-3">
                        <div className="space-y-1">
                          <label className="text-xs font-medium text-zinc-550">Username</label>
                          <input 
                            type="text" 
                            value={username}
                            onChange={(e) => setUsername(e.target.value)}
                            className="block w-full px-3 py-1.5 bg-zinc-50 dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 rounded-lg text-sm"
                          />
                        </div>
                        <div className="space-y-1">
                          <label className="text-xs font-medium text-zinc-550">Password</label>
                          <div className="relative">
                            <input 
                              type={showPassword ? 'text' : 'password'} 
                              value={password}
                              onChange={(e) => setPassword(e.target.value)}
                              className="block w-full pl-3 pr-9 py-1.5 bg-zinc-50 dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 rounded-lg text-sm"
                            />
                            <button
                              type="button"
                              onClick={() => setShowPassword(!showPassword)}
                              className="absolute inset-y-0 right-0 pr-3 flex items-center text-zinc-400"
                            >
                              {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                            </button>
                          </div>
                        </div>
                      </div>
                    )}

                    {(authType === 'API Key' || authType === 'Custom Header') && (
                      <div className="space-y-1">
                        <label className="text-xs font-medium text-zinc-550">Header Name</label>
                        <input 
                          type="text" 
                          placeholder={authType === 'API Key' ? 'x-api-key' : 'x-custom-auth'}
                          value={headerName}
                          onChange={(e) => setHeaderName(e.target.value)}
                          className="block w-full px-3.5 py-1.5 bg-zinc-50 dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 rounded-lg text-sm"
                        />
                      </div>
                    )}

                    {authType !== 'None' && authType !== 'Basic' && (
                      <div className="space-y-1">
                        <label className="text-xs font-medium text-zinc-550">Secret Key / Token Value</label>
                        <div className="relative">
                          <input 
                            type={showPassword ? 'text' : 'password'} 
                            placeholder="Transient token value (not saved to DB)"
                            value={tokenValue}
                            onChange={(e) => setTokenValue(e.target.value)}
                            className="block w-full pl-3 pr-9 py-1.5 bg-zinc-50 dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 rounded-lg text-sm"
                          />
                          <button
                            type="button"
                            onClick={() => setShowPassword(!showPassword)}
                            className="absolute inset-y-0 right-0 pr-3 flex items-center text-zinc-400"
                          >
                            {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                          </button>
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Right Column: OpenAPI upload */}
                  <div className="space-y-4">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-zinc-400">OpenAPI Spec Discovery</h3>
                    
                    <div className="space-y-1.5">
                      <label className="text-xs font-medium text-zinc-500">Swagger / OpenAPI definition (JSON or YAML)</label>
                      <div className="border-2 border-dashed border-zinc-200 dark:border-zinc-800 rounded-xl p-6 text-center hover:border-indigo-500/50 dark:hover:border-indigo-500/30 transition-colors relative cursor-pointer">
                        <input 
                          type="file" 
                          accept=".json,.yaml,.yml"
                          onChange={handleFileUpload}
                          className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                        />
                        <FileText className="w-8 h-8 text-zinc-400 mx-auto mb-2" />
                        <p className="text-xs font-semibold text-zinc-700 dark:text-zinc-300">
                          {fileName ? `Uploaded: ${fileName}` : 'Choose OpenAPI spec file'}
                        </p>
                        <p className="text-[10px] text-zinc-450 mt-1">Accepts Swagger 2.0, OpenAPI 3.0, OpenAPI 3.1</p>
                      </div>
                    </div>
                  </div>

                </div>
              )}
            </div>
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
              <p className="text-zinc-650 dark:text-zinc-400 max-w-sm mx-auto mb-6">
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
                      <th className="py-4 px-6">Duration</th>
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
                          {scan.status === 'COMPLETED' && scan.durationMs !== undefined
                            ? `${(scan.durationMs / 1000).toFixed(2)}s`
                            : '—'}
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
