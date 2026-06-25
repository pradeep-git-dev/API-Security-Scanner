'use client';

import React, { useState, useEffect } from 'react';
import { useRouter, useParams } from 'next/navigation';
import Link from 'next/link';
import { ArrowLeft, LogOut, Shield, ShieldAlert, ShieldCheck, AlertTriangle, Info, ChevronDown, ChevronUp, Clock, Calendar, Globe, AlertCircle, Sparkles } from 'lucide-react';
import api from '../../../../utils/api';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';

interface Vulnerability {
  _id: string;
  endpoint: string;
  method: string;
  issue: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  recommendation: string;
  aiExplanation?: string;
  aiImpact?: string;
  aiFix?: string;
  codeExample?: string;
}

interface Scan {
  _id: string;
  targetUrl: string;
  status: string;
  score: number;
  createdAt: string;
  startedAt: string;
  completedAt?: string;
  durationMs?: number;
  totalEndpointsScanned: number;
}

export default function ScanDetailsPage() {
  const router = useRouter();
  const { id } = useParams();
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Vulnerability[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [expandedFindings, setExpandedFindings] = useState<Record<string, boolean>>({});

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (!token) {
      router.push('/login');
      return;
    }
    if (id) {
      fetchScanDetails();
    }
  }, [id, router]);

  const fetchScanDetails = async () => {
    setLoading(true);
    setError('');
    try {
      const response = await api.get(`/scan/${id}`);
      setScan(response.data.scan);
      setFindings(response.data.findings || []);
    } catch (err: any) {
      console.error(err);
      if (err.response?.status === 401) {
        localStorage.removeItem('token');
        router.push('/login');
      } else {
        setError(err.response?.data?.message || 'Failed to load scan details. Please try again.');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    router.push('/login');
  };

  const toggleExpand = (findingId: string) => {
    setExpandedFindings((prev) => ({
      ...prev,
      [findingId]: !prev[findingId],
    }));
  };

  const getSeverityBadgeColor = (severity: string) => {
    const sev = severity.toUpperCase();
    if (sev === 'CRITICAL') {
      return 'bg-purple-100 text-purple-800 border-purple-200 dark:bg-purple-950/40 dark:text-purple-300 dark:border-purple-900/50';
    } else if (sev === 'HIGH') {
      return 'bg-red-100 text-red-800 border-red-200 dark:bg-red-950/40 dark:text-red-300 dark:border-red-900/50';
    } else if (sev === 'MEDIUM') {
      return 'bg-amber-100 text-amber-800 border-amber-200 dark:bg-amber-950/40 dark:text-amber-300 dark:border-amber-900/50';
    } else {
      return 'bg-blue-100 text-blue-800 border-blue-200 dark:bg-blue-950/40 dark:text-blue-300 dark:border-blue-900/50';
    }
  };

  const getConfidenceBadgeColor = (confidence: string) => {
    const conf = confidence.toUpperCase();
    if (conf === 'HIGH') {
      return 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950/30 dark:text-emerald-300';
    } else if (conf === 'MEDIUM') {
      return 'bg-blue-100 text-blue-800 dark:bg-blue-950/30 dark:text-blue-300';
    } else {
      return 'bg-zinc-100 text-zinc-800 dark:bg-zinc-800/50 dark:text-zinc-300';
    }
  };

  const getMethodBadgeColor = (method: string) => {
    const m = method.toUpperCase();
    if (m === 'GET') return 'bg-sky-100 text-sky-800 dark:bg-sky-950/30 dark:text-sky-300';
    if (m === 'POST') return 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950/30 dark:text-emerald-300';
    if (m === 'PUT') return 'bg-amber-100 text-amber-800 dark:bg-amber-950/30 dark:text-amber-300';
    if (m === 'DELETE') return 'bg-rose-100 text-rose-800 dark:bg-rose-950/30 dark:text-rose-300';
    return 'bg-zinc-100 text-zinc-800 dark:bg-zinc-800/50 dark:text-zinc-300';
  };

  const getScoreColor = (score: number) => {
    if (score >= 90) return 'text-emerald-500';
    if (score >= 70) return 'text-amber-500';
    return 'text-rose-500';
  };

  const formatDuration = (ms?: number) => {
    if (ms === undefined) return 'N/A';
    if (ms < 1000) return `${ms}ms`;
    return `${(ms / 1000).toFixed(2)}s`;
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-zinc-50 dark:bg-zinc-950 flex flex-col justify-center items-center p-6">
        <div className="flex flex-col items-center space-y-4">
          <div className="w-12 h-12 border-4 border-indigo-600 border-t-transparent rounded-full animate-spin"></div>
          <p className="text-zinc-600 dark:text-zinc-400 font-medium">Loading scan details...</p>
        </div>
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="min-h-screen bg-zinc-50 dark:bg-zinc-950 flex flex-col justify-center items-center p-6">
        <div className="max-w-md w-full bg-white dark:bg-zinc-900 rounded-xl border border-zinc-200 dark:border-zinc-800 p-6 shadow-sm text-center">
          <AlertCircle className="w-12 h-12 text-rose-500 mx-auto mb-4" />
          <h2 className="text-xl font-bold text-zinc-900 dark:text-zinc-50 mb-2">Failed to Load Scan</h2>
          <p className="text-zinc-600 dark:text-zinc-400 mb-6">{error || 'Scan details not found.'}</p>
          <div className="flex justify-center space-x-4">
            <Link href="/dashboard" className="inline-flex items-center px-4 py-2 bg-zinc-800 hover:bg-zinc-750 text-white rounded-lg font-medium text-sm transition-colors">
              <ArrowLeft className="w-4 h-4 mr-2" /> Back to Dashboard
            </Link>
            <button onClick={fetchScanDetails} className="px-4 py-2 border border-zinc-300 dark:border-zinc-700 hover:bg-zinc-50 dark:hover:bg-zinc-800 text-zinc-700 dark:text-zinc-300 rounded-lg font-medium text-sm transition-colors">
              Retry
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-zinc-50 dark:bg-zinc-950 text-zinc-900 dark:text-zinc-100 font-sans pb-12">
      {/* Top Navbar */}
      <header className="sticky top-0 z-40 w-full bg-white/80 dark:bg-zinc-900/85 backdrop-blur border-b border-zinc-200 dark:border-zinc-800">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <Link href="/dashboard" className="p-2 -ml-2 text-zinc-500 hover:text-zinc-900 dark:hover:text-zinc-100 transition-colors">
              <ArrowLeft className="w-5 h-5" />
            </Link>
            <span className="font-bold text-lg text-indigo-600 dark:text-indigo-400 tracking-tight flex items-center">
              <Shield className="w-5 h-5 mr-2" /> API Sentinel
            </span>
          </div>
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
        {/* Scan Header Card */}
        <div className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-xl p-6 shadow-sm">
          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-6">
            <div className="space-y-2 flex-1">
              <div className="flex items-center space-x-3 flex-wrap gap-y-2">
                <h1 className="text-xl sm:text-2xl font-bold text-zinc-950 dark:text-zinc-50 break-all">{scan.targetUrl}</h1>
                <span className={`px-2.5 py-0.5 rounded-full text-xs font-semibold uppercase tracking-wider border ${
                  scan.status === 'COMPLETED' ? 'bg-emerald-100 text-emerald-800 border-emerald-200 dark:bg-emerald-950/30 dark:text-emerald-300 dark:border-emerald-900/50' : 
                  scan.status === 'SCANNING' ? 'bg-blue-100 text-blue-800 border-blue-200 dark:bg-blue-950/30 dark:text-blue-300 dark:border-blue-900/50 animate-pulse' : 
                  scan.status === 'FAILED' ? 'bg-rose-100 text-rose-800 border-rose-200 dark:bg-rose-950/30 dark:text-rose-300 dark:border-rose-900/50' :
                  'bg-amber-100 text-amber-800 border-amber-200 dark:bg-amber-950/30 dark:text-amber-300 dark:border-amber-900/50'
                }`}>
                  {scan.status}
                </span>
              </div>
              <p className="text-sm text-zinc-500 dark:text-zinc-400">Scan Details & Security Assessment</p>
            </div>
            
            <div className="flex items-center gap-6 border-t md:border-t-0 md:border-l border-zinc-100 dark:border-zinc-800 pt-6 md:pt-0 md:pl-8">
              <div className="text-center">
                <p className="text-xs text-zinc-400 dark:text-zinc-500 font-medium uppercase tracking-wider">Security Score</p>
                <p className={`text-4xl sm:text-5xl font-extrabold tracking-tight mt-1 ${getScoreColor(scan.score)}`}>
                  {scan.score}
                </p>
              </div>
              <div>
                {scan.score >= 90 ? (
                  <ShieldCheck className="w-12 h-12 text-emerald-500" />
                ) : scan.score >= 70 ? (
                  <AlertTriangle className="w-12 h-12 text-amber-500" />
                ) : (
                  <ShieldAlert className="w-12 h-12 text-rose-500" />
                )}
              </div>
            </div>
          </div>

          {/* Quick Metrics Grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-8 pt-6 border-t border-zinc-100 dark:border-zinc-800">
            <div className="flex items-center space-x-3">
              <Globe className="w-5 h-5 text-zinc-400 dark:text-zinc-500 flex-shrink-0" />
              <div>
                <p className="text-xs text-zinc-400 dark:text-zinc-500 font-medium">Scanned Target</p>
                <p className="text-sm font-semibold truncate max-w-[150px]">{new URL(scan.targetUrl).hostname}</p>
              </div>
            </div>
            <div className="flex items-center space-x-3">
              <Clock className="w-5 h-5 text-zinc-400 dark:text-zinc-500 flex-shrink-0" />
              <div>
                <p className="text-xs text-zinc-400 dark:text-zinc-500 font-medium">Duration</p>
                <p className="text-sm font-semibold">{formatDuration(scan.durationMs)}</p>
              </div>
            </div>
            <div className="flex items-center space-x-3">
              <Calendar className="w-5 h-5 text-zinc-400 dark:text-zinc-500 flex-shrink-0" />
              <div>
                <p className="text-xs text-zinc-400 dark:text-zinc-500 font-medium">Date Run</p>
                <p className="text-sm font-semibold">{new Date(scan.createdAt).toLocaleDateString()}</p>
              </div>
            </div>
            <div className="flex items-center space-x-3">
              <Shield className="w-5 h-5 text-zinc-400 dark:text-zinc-500 flex-shrink-0" />
              <div>
                <p className="text-xs text-zinc-400 dark:text-zinc-500 font-medium">Endpoints Found</p>
                <p className="text-sm font-semibold">{scan.totalEndpointsScanned || findings.length || 0}</p>
              </div>
            </div>
          </div>
        </div>

        {/* Findings Section */}
        <div className="space-y-4">
          <h2 className="text-xl font-bold text-zinc-950 dark:text-zinc-50 flex items-center">
            Vulnerability Findings ({findings.length})
          </h2>

          {findings.length === 0 ? (
            <div className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-xl p-8 shadow-sm text-center">
              <ShieldCheck className="w-12 h-12 text-emerald-500 mx-auto mb-3" />
              <h3 className="text-lg font-bold text-zinc-900 dark:text-zinc-100 mb-1">No Vulnerabilities Found</h3>
              <p className="text-zinc-600 dark:text-zinc-400 max-w-md mx-auto">
                Excellent! The scanner did not detect any security issues on the tested API endpoints.
              </p>
            </div>
          ) : (
            <div className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-xl overflow-hidden shadow-sm">
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="bg-zinc-50 dark:bg-zinc-900/55 border-b border-zinc-200 dark:border-zinc-800 text-xs font-semibold text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">
                      <th className="py-4 px-6">Endpoint</th>
                      <th className="py-4 px-6">Issue</th>
                      <th className="py-4 px-6">Severity</th>
                      <th className="py-4 px-6">Confidence</th>
                      <th className="py-4 px-6 text-right">Details</th>
                    </tr>
                  </thead>
                  <tbody>
                    {findings.map((finding) => {
                      const isExpanded = !!expandedFindings[finding._id];
                      return (
                        <React.Fragment key={finding._id}>
                          {/* Row Summary */}
                          <tr 
                            onClick={() => toggleExpand(finding._id)}
                            className="border-b border-zinc-100 dark:border-zinc-800/60 hover:bg-zinc-50/50 dark:hover:bg-zinc-850/30 transition-colors cursor-pointer"
                          >
                            <td className="py-4 px-6 font-mono text-sm whitespace-nowrap">
                              <div className="flex items-center space-x-2">
                                <span className={`px-2 py-0.5 rounded text-xxs font-bold uppercase tracking-tight border ${getMethodBadgeColor(finding.method)}`}>
                                  {finding.method}
                                </span>
                                <span className="text-zinc-600 dark:text-zinc-300 truncate max-w-[200px]" title={finding.endpoint}>
                                  {finding.endpoint}
                                </span>
                              </div>
                            </td>
                            <td className="py-4 px-6 font-medium text-zinc-900 dark:text-zinc-100">
                              {finding.issue}
                            </td>
                            <td className="py-4 px-6">
                              <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold uppercase border ${getSeverityBadgeColor(finding.severity)}`}>
                                {finding.severity}
                              </span>
                            </td>
                            <td className="py-4 px-6">
                              <span className={`px-2 py-0.5 rounded text-xs font-medium border border-transparent ${getConfidenceBadgeColor(finding.confidence)}`}>
                                {finding.confidence}
                              </span>
                            </td>
                            <td className="py-4 px-6 text-right">
                              <button className="text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-200 transition-colors">
                                {isExpanded ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
                              </button>
                            </td>
                          </tr>
                          
                          {/* Expanded Details */}
                          {isExpanded && (
                            <tr className="bg-zinc-50/30 dark:bg-zinc-900/20 border-b border-zinc-200 dark:border-zinc-800">
                              <td colSpan={5} className="py-6 px-6 sm:px-8 space-y-6">
                                {/* Basic Info */}
                                <div className="space-y-2">
                                  <h4 className="text-xs text-zinc-400 dark:text-zinc-500 font-semibold uppercase tracking-wider flex items-center">
                                    <Info className="w-4 h-4 mr-1.5 text-indigo-500 flex-shrink-0" />
                                    Scanner Description
                                  </h4>
                                  <p className="text-sm text-zinc-600 dark:text-zinc-300 leading-relaxed max-w-4xl">
                                    {finding.description}
                                  </p>
                                </div>

                                {/* AI Enrichment Card */}
                                <div className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-xl shadow-sm overflow-hidden">
                                  {/* AI Title Banner */}
                                  <div className="bg-gradient-to-r from-indigo-50 to-purple-50 dark:from-indigo-950/20 dark:to-purple-950/20 px-5 py-3 border-b border-zinc-200 dark:border-zinc-800 flex items-center justify-between">
                                    <span className="text-sm font-bold text-indigo-750 dark:text-indigo-350 flex items-center">
                                      <Sparkles className="w-4.5 h-4.5 mr-2 text-indigo-500 animate-pulse" />
                                      AI-Powered Analysis & Remediation
                                    </span>
                                    <span className="text-xxs font-semibold bg-indigo-100 text-indigo-800 dark:bg-indigo-950 dark:text-indigo-450 px-2 py-0.5 rounded uppercase">
                                      Gemini AI
                                    </span>
                                  </div>
                                  
                                  <div className="p-5 sm:p-6 space-y-6">
                                    {/* Explanation */}
                                    <div className="space-y-2">
                                      <h5 className="text-xs font-bold text-zinc-800 dark:text-zinc-300 uppercase tracking-wide">
                                        Understanding the Vulnerability
                                      </h5>
                                      <p className="text-sm text-zinc-600 dark:text-zinc-400 leading-relaxed">
                                        {finding.aiExplanation || finding.description}
                                      </p>
                                    </div>

                                    {/* Impact */}
                                    {finding.aiImpact && (
                                      <div className="space-y-2">
                                        <h5 className="text-xs font-bold text-rose-600 dark:text-rose-400 uppercase tracking-wide">
                                          Security Impact
                                        </h5>
                                        <p className="text-sm text-zinc-600 dark:text-zinc-400 leading-relaxed">
                                          {finding.aiImpact}
                                        </p>
                                      </div>
                                    )}

                                    {/* Recommended Fix */}
                                    <div className="space-y-2">
                                      <h5 className="text-xs font-bold text-emerald-600 dark:text-emerald-400 uppercase tracking-wide">
                                        Recommended Fix
                                      </h5>
                                      <p className="text-sm text-zinc-600 dark:text-zinc-400 leading-relaxed whitespace-pre-line">
                                        {finding.aiFix || finding.recommendation}
                                      </p>
                                    </div>

                                    {/* Code Example */}
                                    {finding.codeExample && (
                                      <div className="space-y-2 pt-2">
                                        <h5 className="text-xs font-bold text-indigo-600 dark:text-indigo-400 uppercase tracking-wide">
                                          Secure Implementation Example
                                        </h5>
                                        <div className="rounded-lg overflow-hidden border border-zinc-200 dark:border-zinc-800 max-w-full">
                                          <SyntaxHighlighter 
                                            language="javascript" 
                                            style={vscDarkPlus}
                                            customStyle={{
                                              margin: 0,
                                              fontSize: '13px',
                                              fontFamily: 'var(--font-geist-mono), monospace',
                                              padding: '16px',
                                              backgroundColor: '#1e1e1e',
                                            }}
                                          >
                                            {finding.codeExample}
                                          </SyntaxHighlighter>
                                        </div>
                                      </div>
                                    )}
                                  </div>
                                </div>
                              </td>
                            </tr>
                          )}
                        </React.Fragment>
                      );
                    })}
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
