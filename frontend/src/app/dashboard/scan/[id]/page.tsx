'use client';

import React, { useState, useEffect } from 'react';
import { useRouter, useParams } from 'next/navigation';
import Link from 'next/link';
import { 
  ArrowLeft, LogOut, Shield, ShieldAlert, ShieldCheck, AlertTriangle, 
  Info, ChevronDown, ChevronUp, Clock, Calendar, Globe, AlertCircle, 
  Sparkles, Download, Loader2, CheckCircle2, XCircle, Check, Database
} from 'lucide-react';
import api from '../../../../utils/api';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';

interface Vulnerability {
  _id: string;
  findingId?: string;
  endpoint: string;
  method: string;
  issue: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  recommendation: string;
  aiExplanation?: string;
  aiImpact?: string;
  aiFix?: string;
  codeExample?: string;
  category: 'Security Findings' | 'Observations' | 'Passed Checks' | 'Informational';
  evidence?: {
    headers?: Record<string, string>;
    details?: string[];
    bodyPreview?: string;
    truncated?: boolean;
  };
  impact?: string;
  owasp?: string;
  cwe?: string;
}

interface ScoreDeduction {
  category?: string;
  reason: string;
  penalty: number;
}

interface HeaderStatus {
  header: string;
  status: boolean;
}

interface RateLimitReport {
  requestsSent: number;
  responses429: number;
  retryAfter: string;
  conclusion: string;
}

interface EndpointNode {
  path: string;
  methods: string[];
}

interface Report {
  _id: string;
  scanId: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  score: number;
  generatedAt: string;
  targetType: string;
  framework: string;
  contentType: string;
  server: string;
  tlsVersion: string;
  responseTimeMs: number;
  scoreBreakdown?: ScoreDeduction[];
  categories?: { name: string; score: number; max: number; percentage: number }[];
  confidence?: { score: number; label: string };
  headersStatus?: HeaderStatus[];
  rateLimitReport?: RateLimitReport;
  endpointTree?: EndpointNode[];
  driftComparison?: {
    previousScore: number;
    currentScore: number;
    difference: number;
    resolvedCount: number;
    newCount: number;
    severityChanges: {
      issue: string;
      endpoint: string;
      from: string;
      to: string;
    }[];
  };
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
  fingerprint?: {
    server: { name: string; confidence: string };
    framework: { name: string; confidence: string };
    hosting: { name: string; confidence: string };
    tls: string;
    responseTime: number;
  };
  discoveryMetadata?: {
    source: string;
    endpointCount: number;
    version: string;
    parsedSuccessfully: boolean;
  };
}

export default function ScanDetailsPage() {
  const router = useRouter();
  const { id } = useParams();
  const [scan, setScan] = useState<Scan | null>(null);
  const [report, setReport] = useState<Report | null>(null);
  const [findings, setFindings] = useState<Vulnerability[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [expandedFindings, setExpandedFindings] = useState<Record<string, boolean>>({});
  const [exporting, setExporting] = useState(false);
  const [activeTab, setActiveTab] = useState<'Security Findings' | 'Observations' | 'Passed Checks' | 'Informational'>('Security Findings');
  const [showConfDetails, setShowConfDetails] = useState(false);

  const handleExportPDF = async () => {
    setExporting(true);
    try {
      const response = await api.get(`/scan/${id}/pdf`, {
        responseType: 'blob',
      });
      const blob = new Blob([response.data], { type: 'application/pdf' });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `API-Auditor-Report-${scan?._id || id}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.parentNode?.removeChild(link);
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Failed to export PDF:', err);
      alert('Failed to export PDF report. Please try again.');
    } finally {
      setExporting(false);
    }
  };

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
      setReport(response.data.report);
      
      const list: Vulnerability[] = response.data.findings || [];
      setFindings(list);

      if (list.some(f => f.category === 'Security Findings')) {
        setActiveTab('Security Findings');
      } else if (list.some(f => f.category === 'Observations')) {
        setActiveTab('Observations');
      } else if (list.some(f => f.category === 'Passed Checks')) {
        setActiveTab('Passed Checks');
      } else if (list.some(f => f.category === 'Informational')) {
        setActiveTab('Informational');
      }
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
    document.cookie = 'token=; path=/; expires=Thu, 01 Jan 1970 00:00:00 UTC; SameSite=Lax;';
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
    } else if (sev === 'LOW') {
      return 'bg-blue-100 text-blue-800 border-blue-200 dark:bg-blue-950/40 dark:text-blue-300 dark:border-blue-900/50';
    } else {
      return 'bg-zinc-105 text-zinc-800 border-zinc-200 dark:bg-zinc-800/40 dark:text-zinc-300 dark:border-zinc-700/50';
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
    if (m === 'GET') return 'bg-sky-100 text-sky-850 dark:bg-sky-950/30 dark:text-sky-300';
    if (m === 'POST') return 'bg-emerald-105 text-emerald-800 dark:bg-emerald-950/30 dark:text-emerald-300';
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

  const renderEvidence = (evidence: any) => {
    if (!evidence) return null;

    const headers = evidence.headers || {};
    const details = evidence.details || [];
    const bodyPreview = evidence.bodyPreview || "";
    const truncated = evidence.truncated || false;

    return (
      <div className="space-y-4">
        {details.length > 0 && (
          <div className="space-y-1.5 font-mono text-xs">
            <span className="text-zinc-400 block font-semibold uppercase tracking-wider">Analysis Details:</span>
            <ul className="list-disc pl-4 space-y-1 text-zinc-600 dark:text-zinc-400">
              {details.map((d: string, idx: number) => (
                <li key={idx}>{d}</li>
              ))}
            </ul>
          </div>
        )}

        {((headers && Object.keys(headers).length > 0) || bodyPreview) && (
          <div className="space-y-1.5">
            <span className="text-xs font-bold text-zinc-500 dark:text-zinc-400 uppercase tracking-wider block">HTTP Transaction Logs</span>
            <div className="rounded-lg overflow-hidden border border-zinc-200 dark:border-zinc-800 bg-[#1e1e1e] p-4 text-xs font-mono text-zinc-300 space-y-3 max-h-[300px] overflow-y-auto">
              {headers && Object.keys(headers).length > 0 && (
                <div>
                  <span className="text-indigo-400 block font-bold">// Response Headers</span>
                  {Object.entries(headers).map(([k, v]) => (
                    <div key={k} className="pl-3 truncate">
                      <span className="text-zinc-500">{k}:</span> {String(v)}
                    </div>
                  ))}
                </div>
              )}

              {bodyPreview && (
                <div className="pt-2 border-t border-zinc-800">
                  <span className="text-emerald-400 block font-bold">
                    // Response Body Preview {truncated && <span className="text-xxs text-amber-500 font-normal italic">(truncated)</span>}
                  </span>
                  <pre className="pl-3 text-zinc-400 whitespace-pre-wrap select-all max-w-full overflow-x-auto mt-1 leading-relaxed">
                    {bodyPreview}
                  </pre>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    );
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-zinc-50 dark:bg-zinc-950 flex flex-col justify-center items-center p-6">
        <div className="flex flex-col items-center space-y-4">
          <div className="w-12 h-12 border-4 border-indigo-600 border-t-transparent rounded-full animate-spin"></div>
          <p className="text-zinc-650 dark:text-zinc-400 font-medium animate-pulse">Running analysis engine...</p>
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
            <button onClick={fetchScanDetails} className="px-4 py-2 border border-zinc-300 dark:border-zinc-700 hover:bg-zinc-50 dark:hover:bg-zinc-800 text-zinc-700 dark:text-zinc-303 rounded-lg font-medium text-sm transition-colors">
              Retry
            </button>
          </div>
        </div>
      </div>
    );
  }

  const filteredFindings = findings.filter(f => f.category === activeTab);

  return (
    <div className="min-h-screen flex flex-col bg-zinc-50 dark:bg-zinc-950 text-zinc-900 dark:text-zinc-100 font-sans">
      {/* Top Navbar */}
      <header className="sticky top-0 z-40 w-full bg-white/80 dark:bg-zinc-900/85 backdrop-blur border-b border-zinc-200 dark:border-zinc-800">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <Link href="/dashboard" className="p-2 -ml-2 text-zinc-500 hover:text-zinc-900 dark:hover:text-zinc-100 transition-colors">
              <ArrowLeft className="w-5 h-5" />
            </Link>
            <span className="font-bold text-lg text-red-650 dark:text-red-500 tracking-tight flex items-center">
              <Shield className="w-5 h-5 mr-2" /> API Auditor
            </span>
          </div>
          <div className="flex items-center space-x-4">
            <button 
              onClick={handleLogout}
              className="inline-flex items-center space-x-2 px-3 py-1.5 border border-zinc-200 dark:border-zinc-800 hover:bg-zinc-50 dark:hover:bg-zinc-800 text-zinc-650 dark:text-zinc-300 rounded-lg text-sm font-medium transition-all cursor-pointer"
            >
              <LogOut className="w-4 h-4" />
              <span>Logout</span>
            </button>
          </div>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 pt-8 space-y-8 flex-grow w-full">
        
        {/* URL, Type and Basic Status */}
        <div className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-xl p-6 shadow-sm">
          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-6">
            <div className="space-y-2 flex-1">
              <div className="flex items-center space-x-3 flex-wrap gap-y-2">
                <h1 className="text-xl sm:text-2xl font-bold text-zinc-950 dark:text-zinc-50 break-all">{scan.targetUrl}</h1>
                <span className={`px-2.5 py-0.5 rounded-full text-xs font-semibold uppercase tracking-wider border ${
                  scan.status === 'COMPLETED' ? 'bg-emerald-105 text-emerald-800 border-emerald-200 dark:bg-emerald-950/30 dark:text-emerald-300 dark:border-emerald-900/50' : 
                  scan.status === 'SCANNING' ? 'bg-blue-105 text-blue-800 border-blue-200 dark:bg-blue-950/30 dark:text-blue-300 dark:border-blue-900/50 animate-pulse' : 
                  scan.status === 'FAILED' ? 'bg-rose-100 text-rose-800 border-rose-200 dark:bg-rose-950/30 dark:text-rose-300 dark:border-rose-900/50' :
                  'bg-amber-100 text-amber-800 border-amber-200 dark:bg-amber-950/30 dark:text-amber-300 dark:border-amber-900/50'
                }`}>
                  {scan.status}
                </span>
                
                {report && (
                  <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold uppercase tracking-wider bg-indigo-50 text-indigo-700 border border-indigo-200 dark:bg-indigo-950/40 dark:text-indigo-300 dark:border-indigo-900/50">
                    {report.targetType === 'REST_API' ? 'REST API' : report.targetType}
                  </span>
                )}
              </div>
              <div className="flex items-center space-x-4 pt-1">
                <p className="text-sm text-zinc-500 dark:text-zinc-400">Security Assessment Report v1.0</p>
                {scan.status === 'COMPLETED' && (
                  <button
                    onClick={handleExportPDF}
                    disabled={exporting}
                    className="inline-flex items-center px-3 py-1 bg-red-600 hover:bg-red-700 disabled:bg-red-600/50 text-white rounded-lg text-xs font-semibold transition-colors cursor-pointer"
                  >
                    {exporting ? (
                      <Loader2 className="w-3.5 h-3.5 mr-1 animate-spin" />
                    ) : (
                      <Download className="w-3.5 h-3.5 mr-1" />
                    )}
                    <span>{exporting ? 'Exporting...' : 'Export PDF'}</span>
                  </button>
                )}
              </div>
            </div>
            
            <div className="flex items-center gap-6 border-t md:border-t-0 md:border-l border-zinc-100 dark:border-zinc-800 pt-6 md:pt-0 md:pl-8 flex-shrink-0">
              <div className="text-center">
                <p className="text-xs text-zinc-405 dark:text-zinc-500 font-medium uppercase tracking-wider">
                  {report?.confidence && report.confidence.score < 70 ? 'Estimated Security Score' : 'Security Score'}
                </p>
                <p className={`text-4xl sm:text-5xl font-extrabold tracking-tight mt-1 ${getScoreColor(scan.score)}`}>
                  {scan.score}/100
                </p>
                {report?.confidence && report.confidence.score < 70 && (
                  <p className="text-[10px] text-zinc-405 dark:text-zinc-500 mt-1 italic max-w-[150px] mx-auto leading-normal">
                    Some checks could not be verified.
                  </p>
                )}
                {report?.driftComparison && report.driftComparison.difference !== 0 && (
                  <div className={`mt-1.5 text-[10px] font-extrabold px-2 py-0.5 rounded-full inline-block ${
                    report.driftComparison.difference > 0 
                      ? 'bg-emerald-50 text-emerald-700 dark:bg-emerald-950/20 dark:text-emerald-400' 
                      : 'bg-rose-50 text-rose-700 dark:bg-rose-950/20 dark:text-rose-400'
                  }`}>
                    {report.driftComparison.difference > 0 ? '+' : ''}{report.driftComparison.difference} diff
                  </div>
                )}
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
            <div>
              <p className="text-xs text-zinc-400 dark:text-zinc-500 font-semibold uppercase tracking-wider">Scanned Host</p>
              <p className="text-sm font-semibold truncate max-w-[150px] mt-1">{new URL(scan.targetUrl).hostname}</p>
            </div>
            <div>
              <p className="text-xs text-zinc-400 dark:text-zinc-500 font-semibold uppercase tracking-wider">Duration</p>
              <p className="text-sm font-semibold mt-1">{formatDuration(scan.durationMs)}</p>
            </div>
            <div>
              <p className="text-xs text-zinc-400 dark:text-zinc-500 font-semibold uppercase tracking-wider">Scan Date</p>
              <p className="text-sm font-semibold truncate max-w-[150px] mt-1" title={scan.completedAt ? new Date(scan.completedAt).toLocaleString() : 'N/A'}>
                {scan.completedAt ? new Date(scan.completedAt).toLocaleDateString() : 'N/A'}
              </p>
            </div>
            <div>
              <p className="text-xs text-zinc-400 dark:text-zinc-500 font-semibold uppercase tracking-wider">Endpoints Scanned</p>
              <p className="text-sm font-semibold mt-1">{scan.totalEndpointsScanned || 1}</p>
            </div>
          </div>
        </div>

        {/* Dashboard Columns */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          
          {/* LEFT/SIDE PANEL: Score Breakdown & Historical Comparisons */}
          <div className="lg:col-span-1 space-y-8">
            
            {/* Score & Category Breakdown Card */}
            <div className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-xl p-5 shadow-sm space-y-5">
              <div>
                <h3 className="text-sm font-bold text-zinc-850 dark:text-zinc-300 uppercase tracking-wider mb-2">Overall Security</h3>
                <div className="flex items-baseline justify-between">
                  <span className={`text-3xl font-extrabold tracking-tight ${getScoreColor(scan.score)}`}>
                    {scan.score}/100
                  </span>
                  {report?.confidence && (
                    <div className="relative">
                      <button 
                        onClick={() => setShowConfDetails(!showConfDetails)}
                        className={`text-xs font-semibold px-2 py-1 rounded-md transition-all cursor-pointer select-none hover:opacity-80 flex items-center gap-1 ${
                          report.confidence.label === 'HIGH' 
                            ? 'bg-emerald-50 text-emerald-755 dark:bg-emerald-950/20 dark:text-emerald-400'
                            : report.confidence.label === 'MEDIUM'
                            ? 'bg-amber-50 text-amber-755 dark:bg-amber-950/20 dark:text-amber-400'
                            : 'bg-rose-50 text-rose-755 dark:bg-rose-950/20 dark:text-rose-400'
                        }`}
                      >
                        <span>Confidence: {report.confidence.score}% {report.confidence.label}</span>
                        <span className="text-[10px]">ℹ️</span>
                      </button>
                      
                      {showConfDetails && (
                        <div className="absolute right-0 mt-2 z-10 w-64 p-3 bg-zinc-900 border border-zinc-800 rounded-lg shadow-xl text-left text-xs font-sans text-zinc-300 space-y-2 leading-relaxed animate-in fade-in duration-200">
                          <p className="font-bold text-zinc-100">Confidence Calculation details:</p>
                          <ul className="space-y-1.5 font-medium">
                            <li className="flex items-center gap-1.5">
                              {scan?.fingerprint?.tls && scan.fingerprint.tls !== 'N/A' ? '✔' : '✘'} <span>HTTPS verified</span>
                            </li>
                            <li className="flex items-center gap-1.5">
                              {findings.some(f => f.issue === 'Missing Security Headers' || f.issue === 'Security Headers Configured') ? '✔' : '✘'} <span>Response headers analyzed</span>
                            </li>
                            <li className="flex items-center gap-1.5">
                              {scan?.totalEndpointsScanned && scan.totalEndpointsScanned > 0 ? '✔' : '✘'} <span>Endpoint discovery completed</span>
                            </li>
                            <li className="flex items-center gap-1.5">
                              {scan?.fingerprint?.framework?.name && scan.fingerprint.framework.name !== 'Unknown' ? '✔' : '✘'} <span>Framework fingerprint status</span>
                            </li>
                            <li className="flex items-center gap-1.5">
                              {scan?.fingerprint?.hosting?.name && scan.fingerprint.hosting.name !== 'Unknown' ? '✔' : '✘'} <span>Hosting fingerprint status</span>
                            </li>
                            <li className="flex items-center gap-1.5">
                              {scan?.totalEndpointsScanned && scan.totalEndpointsScanned > 1 ? '✔' : '✘'} <span>Broad endpoint coverage</span>
                            </li>
                            <li className="flex items-center gap-1.5">
                              {scan?.fingerprint?.server?.name && scan.fingerprint.server.name !== 'Unknown' ? '✔' : '✘'} <span>Server fingerprint status</span>
                            </li>
                          </ul>
                          <p className="text-[10px] text-zinc-550 pt-1 border-t border-zinc-800">
                            Confidence represents completeness and coverage of execution checks.
                          </p>
                        </div>
                      )}
                    </div>
                  )}
                </div>
                {report?.confidence && report.confidence.score < 70 && (
                  <p className="text-[10px] text-zinc-405 dark:text-zinc-500 mt-2 italic">
                    Some checks could not be verified.
                  </p>
                )}
              </div>

              {/* Category Breakdown */}
              <div className="space-y-4 border-t border-zinc-100 dark:border-zinc-800/80 pt-4">
                <h4 className="text-xs font-bold text-zinc-400 dark:text-zinc-500 uppercase tracking-wider">Category Breakdown</h4>
                
                <div className="space-y-3">
                  {(report?.categories || [
                    { name: 'Header Security', score: 30, max: 30, percentage: 100 },
                    { name: 'Transport Security', score: 15, max: 15, percentage: 100 },
                    { name: 'Server Security', score: 15, max: 15, percentage: 100 },
                    { name: 'API Security', score: 25, max: 25, percentage: 100 },
                    { name: 'Data Protection', score: 15, max: 15, percentage: 100 }
                  ]).map((cat, idx) => (
                    <div key={idx} className="space-y-1">
                      <div className="flex justify-between text-xs font-medium">
                        <span className="text-zinc-700 dark:text-zinc-350">{cat.name}</span>
                        <span className="text-zinc-500 dark:text-zinc-450">{cat.score}/{cat.max} ({cat.percentage}%)</span>
                      </div>
                      <div className="w-full bg-zinc-100 dark:bg-zinc-800 rounded-full h-1.5 overflow-hidden">
                        <div 
                          className="bg-red-650 dark:bg-red-500 h-1.5 rounded-full transition-all duration-500" 
                          style={{ width: `${cat.percentage}%` }}
                        ></div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Detailed Deductions */}
              <div className="space-y-2 border-t border-zinc-100 dark:border-zinc-800/80 pt-4">
                <h4 className="text-xs font-bold text-zinc-400 dark:text-zinc-500 uppercase tracking-wider">Detailed Deductions</h4>
                
                {report?.scoreBreakdown && report.scoreBreakdown.length > 0 ? (
                  <div className="space-y-2">
                    {report.scoreBreakdown.map((item, idx) => (
                      <div key={idx} className="flex justify-between items-start text-xs">
                        <div className="flex flex-col">
                          <span className="text-[9px] font-bold text-zinc-400 dark:text-zinc-500 uppercase tracking-wider">{item.category || 'General'}</span>
                          <span className="text-zinc-600 dark:text-zinc-300 font-medium">{item.reason}</span>
                        </div>
                        <span className="text-rose-600 dark:text-rose-450 font-bold ml-2">-{item.penalty}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-zinc-550 italic">No deductions applied. High security posture.</p>
                )}
              </div>
            </div>

            {/* Historical Compare Card */}
            {report?.driftComparison && report.driftComparison.previousScore !== 100 && (
              <div className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-xl p-5 shadow-sm space-y-4">
                <h3 className="text-sm font-bold text-zinc-855 dark:text-zinc-300 uppercase tracking-wider">Historical Compare</h3>
                <div className="grid grid-cols-3 gap-2 text-center">
                  <div className="bg-zinc-50 dark:bg-zinc-950 p-2.5 rounded border border-zinc-200/50 dark:border-zinc-850">
                    <span className="text-[9px] text-zinc-400 uppercase block font-semibold leading-tight">Prev Score</span>
                    <span className="text-base font-extrabold text-zinc-700 dark:text-zinc-300 mt-1 block">{report.driftComparison.previousScore}</span>
                  </div>
                  <div className="bg-zinc-50 dark:bg-zinc-950 p-2.5 rounded border border-zinc-200/50 dark:border-zinc-850">
                    <span className="text-[9px] text-zinc-400 uppercase block font-semibold leading-tight">New</span>
                    <span className="text-base font-extrabold text-rose-605 mt-1 block">{report.driftComparison.newCount}</span>
                  </div>
                  <div className="bg-zinc-50 dark:bg-zinc-950 p-2.5 rounded border border-zinc-200/50 dark:border-zinc-850">
                    <span className="text-[9px] text-zinc-400 uppercase block font-semibold leading-tight">Resolved</span>
                    <span className="text-base font-extrabold text-emerald-600 dark:text-emerald-400 mt-1 block">{report.driftComparison.resolvedCount}</span>
                  </div>
                </div>
                
                {report.driftComparison.severityChanges && report.driftComparison.severityChanges.length > 0 && (
                  <div className="space-y-2 pt-2 border-t border-zinc-100 dark:border-zinc-800/80">
                    <span className="text-xs font-bold text-zinc-450 uppercase block">Severity Drift</span>
                    <div className="space-y-1.5">
                      {report.driftComparison.severityChanges.map((change, i) => (
                        <div key={i} className="text-xxs font-medium flex justify-between bg-zinc-50 dark:bg-zinc-950 p-2 rounded border border-zinc-200/60 dark:border-zinc-850">
                          <span className="text-zinc-650 dark:text-zinc-300 font-semibold truncate max-w-[120px]" title={`${change.issue} on ${change.endpoint}`}>{change.issue}</span>
                          <span className="text-zinc-500">
                            <span className="line-through">{change.from}</span> → <span className="font-bold text-indigo-500">{change.to}</span>
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Endpoint Tree Card */}
            {report?.endpointTree && report.endpointTree.length > 0 && (
              <div className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-xl p-5 shadow-sm space-y-4">
                <h3 className="text-sm font-bold text-zinc-850 dark:text-zinc-300 uppercase tracking-wider flex items-center justify-between">
                  <span>Endpoint Tree</span>
                  <span className="text-[10px] font-bold bg-zinc-100 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-350 px-2 py-0.5 rounded">
                    {scan.discoveryMetadata?.source || 'OpenAPI'}
                  </span>
                </h3>
                <div className="space-y-2.5">
                  {report.endpointTree.map((node, i) => (
                    <div key={i} className="flex justify-between items-center text-xs pb-2 border-b border-zinc-100 dark:border-zinc-800/40 last:border-b-0 last:pb-0">
                      <span className="font-mono text-zinc-750 dark:text-zinc-300 break-all">{node.path}</span>
                      <div className="flex gap-1 flex-wrap flex-shrink-0">
                        {node.methods.map((m) => (
                          <span key={m} className={`px-1.5 py-0.5 rounded text-[9px] font-extrabold uppercase ${getMethodBadgeColor(m)}`}>
                            {m}
                          </span>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* RIGHT PANEL: Metadata, Header Analysis, Rate Limit Report, and Findings list */}
          <div className="lg:col-span-2 space-y-8">
            
            {/* Header Status & Rate Limit Report */}
            {report && (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
                
                {/* Header Verification Card */}
                <div className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-xl p-5 shadow-sm space-y-4">
                  <h3 className="text-sm font-bold text-zinc-855 dark:text-zinc-303 uppercase tracking-wider flex items-center justify-between">
                    <span>Header Verification</span>
                    <span className="text-xxs font-normal bg-red-50 dark:bg-red-950/20 text-red-600 dark:text-red-400 px-2 py-0.5 rounded">Security Headers</span>
                  </h3>
                  
                  <div className="space-y-2">
                    {report.headersStatus && report.headersStatus.length > 0 ? (
                      report.headersStatus.map((h, i) => (
                        <div key={i} className="flex justify-between items-center text-xs pb-1.5 border-b border-zinc-100 dark:border-zinc-800/40 last:border-b-0">
                          <span className="font-semibold text-zinc-750 dark:text-zinc-400">{h.header}</span>
                          {h.status ? (
                            <span className="flex items-center text-emerald-600 dark:text-emerald-400 font-bold gap-1 text-xxs">
                              <CheckCircle2 className="w-3.5 h-3.5" /> Present
                            </span>
                          ) : (
                            <span className="flex items-center text-rose-650 dark:text-rose-455 font-bold gap-1 text-xxs">
                              <XCircle className="w-3.5 h-3.5" /> Missing
                            </span>
                          )}
                        </div>
                      ))
                    ) : (
                      <p className="text-xs text-zinc-500 italic">No header status details found.</p>
                    )}
                  </div>
                </div>

                {/* Rate Limit Summary Card */}
                <div className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-xl p-5 shadow-sm space-y-4">
                  <h3 className="text-sm font-bold text-zinc-855 dark:text-zinc-300 uppercase tracking-wider">Rate Limit Test</h3>
                  
                  {report.rateLimitReport ? (
                    <div className="space-y-3.5">
                      <div className="grid grid-cols-3 gap-2 text-center">
                        <div className="bg-zinc-50 dark:bg-zinc-950 p-2 rounded border border-zinc-200/60 dark:border-zinc-850">
                          <span className="text-xxs text-zinc-400 block uppercase">Sent</span>
                          <span className="text-sm font-bold text-zinc-800 dark:text-zinc-300">{report.rateLimitReport.requestsSent}</span>
                        </div>
                        <div className="bg-zinc-50 dark:bg-zinc-950 p-2 rounded border border-zinc-200/60 dark:border-zinc-850">
                          <span className="text-xxs text-zinc-400 block uppercase">429s</span>
                          <span className="text-sm font-bold text-zinc-800 dark:text-zinc-300">{report.rateLimitReport.responses429}</span>
                        </div>
                        <div className="bg-zinc-50 dark:bg-zinc-950 p-2 rounded border border-zinc-200/60 dark:border-zinc-850">
                          <span className="text-xxs text-zinc-400 block uppercase">Retry-After</span>
                          <span className="text-xs font-semibold text-zinc-800 dark:text-zinc-300 truncate block">{report.rateLimitReport.retryAfter}</span>
                        </div>
                      </div>
                      
                      <div className="space-y-1">
                        <span className="text-xxs text-zinc-405 dark:text-zinc-500 uppercase tracking-wider block font-bold">Conclusion</span>
                        <p className="text-xs text-zinc-700 dark:text-zinc-400 bg-zinc-50 dark:bg-zinc-950 p-2 rounded border border-zinc-200/60 dark:border-zinc-850 leading-relaxed">
                          {report.rateLimitReport.conclusion}
                        </p>
                      </div>
                    </div>
                  ) : (
                    <p className="text-xs text-zinc-500 italic">No rate limit test details found.</p>
                  )}
                </div>
              </div>
            )}

            {/* Environmental Metadata (with technology & hosting confidence) */}
            {scan.fingerprint && (
              <div className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-xl p-5 shadow-sm space-y-4">
                <h3 className="text-sm font-bold text-zinc-855 dark:text-zinc-300 uppercase tracking-wider flex items-center justify-between">
                  <span>Environment Fingerprint</span>
                  <span className="text-xxs font-normal bg-zinc-100 dark:bg-zinc-850 text-zinc-750 dark:text-zinc-300 px-2 py-0.5 rounded">
                    Confidence Rated
                  </span>
                </h3>
                <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-4">
                  <div className="text-xs">
                    <span className="text-zinc-400 block mb-0.5">Framework</span>
                    <span className="font-semibold block">{scan.fingerprint.framework?.name || 'Unknown'}</span>
                    <span className={`text-[9px] font-bold ${
                      scan.fingerprint.framework?.confidence === 'HIGH' ? 'text-emerald-500' : 'text-zinc-500'
                    }`}>{scan.fingerprint.framework?.confidence || 'LOW'} CONFIDENCE</span>
                  </div>
                  <div className="text-xs">
                    <span className="text-zinc-400 block mb-0.5">Hosting</span>
                    <span className="font-semibold block">{scan.fingerprint.hosting?.name || 'Unknown'}</span>
                    <span className={`text-[9px] font-bold ${
                      scan.fingerprint.hosting?.confidence === 'HIGH' ? 'text-emerald-500' : 'text-zinc-500'
                    }`}>{scan.fingerprint.hosting?.confidence || 'LOW'} CONFIDENCE</span>
                  </div>
                  <div className="text-xs">
                    <span className="text-zinc-400 block mb-0.5">Server</span>
                    <span className="font-semibold block">{scan.fingerprint.server?.name || 'Unknown'}</span>
                    <span className={`text-[9px] font-bold ${
                      scan.fingerprint.server?.confidence === 'HIGH' ? 'text-emerald-500' : 'text-zinc-500'
                    }`}>{scan.fingerprint.server?.confidence || 'LOW'} CONFIDENCE</span>
                  </div>
                  <div className="text-xs">
                    <span className="text-zinc-400 block mb-0.5">TLS version</span>
                    <span className="font-semibold block pt-1">{scan.fingerprint.tls || 'N/A'}</span>
                  </div>
                  <div className="text-xs">
                    <span className="text-zinc-400 block mb-0.5">Response Time</span>
                    <span className="font-semibold block pt-1">{scan.fingerprint.responseTime || 0} ms</span>
                  </div>
                </div>
              </div>
            )}

          </div>

        </div>

        {/* Categorized Findings Section */}
        <div className="space-y-4 pt-6 border-t border-zinc-200 dark:border-zinc-800">
              <div className="border-b border-zinc-200 dark:border-zinc-800 flex flex-wrap gap-2">
                {[
                  { key: 'Security Findings', label: 'Security Findings', count: findings.filter(f => f.category === 'Security Findings').length },
                  { key: 'Observations', label: 'Observations', count: findings.filter(f => f.category === 'Observations').length },
                  { key: 'Passed Checks', label: 'Passed Checks', count: findings.filter(f => f.category === 'Passed Checks').length },
                  { key: 'Informational', label: 'Informational', count: findings.filter(f => f.category === 'Informational').length }
                ].map((tab) => {
                  const isActive = activeTab === tab.key;
                  return (
                    <button
                      key={tab.key}
                      onClick={() => setActiveTab(tab.key as any)}
                      className={`px-4 py-2 border-b-2 text-sm font-bold flex items-center gap-1.5 transition-all cursor-pointer ${
                        isActive 
                          ? 'border-red-600 text-red-605 dark:border-red-500 dark:text-red-500' 
                          : 'border-transparent text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300'
                      }`}
                    >
                      <span>{tab.label}</span>
                      <span className={`text-xxs px-1.5 py-0.5 rounded-full ${
                        isActive 
                          ? 'bg-red-105 text-red-800 dark:bg-red-950/40 dark:text-red-300' 
                          : 'bg-zinc-100 text-zinc-650 dark:bg-zinc-800 dark:text-zinc-405'
                      }`}>
                        {tab.count}
                      </span>
                    </button>
                  );
                })}
              </div>

              {filteredFindings.length === 0 ? (
                <div className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-xl p-8 shadow-sm text-center">
                  <ShieldCheck className="w-12 h-12 text-emerald-500 mx-auto mb-3" />
                  <h3 className="text-lg font-bold text-zinc-900 dark:text-zinc-100 mb-1">No Items Here</h3>
                  <p className="text-zinc-655 dark:text-zinc-400 max-w-sm mx-auto text-sm">
                    No findings were categorized as {activeTab} in this security sweep.
                  </p>
                </div>
              ) : (
                <div className="space-y-4">
                  {filteredFindings.map((finding) => {
                    const isExpanded = !!expandedFindings[finding._id];
                    return (
                      <div 
                        key={finding._id} 
                        className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-xl shadow-sm overflow-hidden"
                      >
                        {/* Header Row */}
                        <div 
                          onClick={() => toggleExpand(finding._id)}
                          className="p-5 flex items-center justify-between gap-4 hover:bg-zinc-50/50 dark:hover:bg-zinc-855/20 cursor-pointer select-none transition-colors"
                        >
                          <div className="flex items-center space-x-3 truncate">
                            <span className={`px-2 py-0.5 rounded text-xxs font-extrabold uppercase tracking-wider border ${getMethodBadgeColor(finding.method)}`}>
                              {finding.method}
                            </span>
                            <span className="font-semibold text-zinc-900 dark:text-zinc-100 text-sm truncate" title={finding.issue}>
                              {finding.issue}
                            </span>
                            <span className="text-xs text-zinc-400 dark:text-zinc-500 font-mono hidden sm:inline truncate max-w-[180px]">
                              {finding.endpoint}
                            </span>
                          </div>

                          <div className="flex items-center space-x-3 flex-shrink-0">
                            {finding.severity !== 'INFO' && (
                              <span className={`px-2 py-0.5 rounded-full text-xxs font-extrabold uppercase border ${getSeverityBadgeColor(finding.severity)}`}>
                                {finding.severity}
                              </span>
                            )}
                            <button className="text-zinc-450 hover:text-zinc-700 dark:hover:text-zinc-200 transition-all">
                              {isExpanded ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
                            </button>
                          </div>
                        </div>

                        {/* Expandable Details */}
                        {isExpanded && (
                          <div className="border-t border-zinc-100 dark:border-zinc-800 p-6 space-y-6 bg-zinc-50/15 dark:bg-zinc-900/10">
                            
                            {/* Standard details */}
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs bg-zinc-50 dark:bg-zinc-950 p-4 rounded-lg border border-zinc-200 dark:border-zinc-850">
                              <div>
                                <span className="text-zinc-400 block uppercase tracking-wider font-semibold">Endpoint / URL Path</span>
                                <span className="font-mono text-zinc-700 dark:text-zinc-300 break-all">{finding.endpoint}</span>
                              </div>
                              <div className="flex justify-between items-start">
                                <div>
                                  <span className="text-zinc-400 block uppercase tracking-wider font-semibold">Standard Mappings</span>
                                  <span className="font-semibold text-zinc-750 dark:text-zinc-350">
                                    {finding.owasp ? finding.owasp : 'N/A'} {finding.cwe ? `(${finding.cwe})` : ''}
                                  </span>
                                </div>
                                <div>
                                  <span className="text-zinc-400 block uppercase tracking-wider font-semibold">Confidence</span>
                                  <span className={`px-1.5 py-0.5 rounded text-xxs font-bold border border-transparent ${getConfidenceBadgeColor(finding.confidence)}`}>
                                    {finding.confidence}
                                  </span>
                                </div>
                              </div>
                            </div>

                            {/* Description block */}
                            <div className="space-y-1.5">
                              <h4 className="text-xs text-zinc-405 dark:text-zinc-500 font-bold uppercase tracking-wider">
                                Description
                              </h4>
                              <p className="text-sm text-zinc-700 dark:text-zinc-350 leading-relaxed">
                                {finding.description}
                              </p>
                            </div>

                            {/* Evidence block (Unified Schema) */}
                            {finding.evidence && (
                              <div className="space-y-2">
                                <h4 className="text-xs text-zinc-405 dark:text-zinc-500 font-bold uppercase tracking-wider">
                                  Evidence Logs
                                </h4>
                                {renderEvidence(finding.evidence)}
                              </div>
                            )}

                            {/* Security Impact */}
                            {finding.impact && (
                              <div className="space-y-1.5">
                                <h4 className="text-xs text-rose-600 dark:text-rose-455 font-bold uppercase tracking-wider flex items-center gap-1.5">
                                  <ShieldAlert className="w-3.5 h-3.5" /> Security Impact
                                </h4>
                                <p className="text-sm text-zinc-755 dark:text-zinc-350 leading-relaxed">
                                  {finding.impact}
                                </p>
                              </div>
                            )}

                            {/* AI Remediation Card */}
                            {finding.category !== 'Passed Checks' && finding.category !== 'Informational' && finding.severity !== 'INFO' && (
                              <div className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-xl overflow-hidden shadow-sm">
                                <div className="bg-zinc-50 dark:bg-zinc-900 px-5 py-3 border-b border-zinc-200 dark:border-zinc-800 flex items-center justify-between">
                                  <span className="text-xs font-bold text-zinc-900 dark:text-zinc-100 flex items-center">
                                    AI Remediation & Fix Recommendation
                                  </span>
                                  <span className="text-[10px] font-bold bg-red-100 text-red-800 dark:bg-red-950/40 dark:text-red-400 px-2 py-0.5 rounded uppercase">
                                    Gemini AI
                                  </span>
                                </div>
                                
                                <div className="p-5 space-y-4">
                                  {finding.aiExplanation && (
                                    <div className="space-y-1">
                                      <h5 className="text-xxs font-bold text-zinc-405 dark:text-zinc-550 uppercase tracking-wider">AI Assessment</h5>
                                      <p className="text-sm text-zinc-655 dark:text-zinc-405 leading-relaxed">
                                        {finding.aiExplanation}
                                      </p>
                                    </div>
                                  )}

                                  {finding.aiImpact && (
                                    <div className="space-y-1">
                                      <h5 className="text-xxs font-bold text-rose-600 dark:text-rose-455 uppercase tracking-wider">Threat Scenario</h5>
                                      <p className="text-sm text-zinc-655 dark:text-zinc-450 leading-relaxed">
                                        {finding.aiImpact}
                                      </p>
                                    </div>
                                  )}

                                  <div className="space-y-1">
                                    <h5 className="text-xxs font-bold text-emerald-650 dark:text-emerald-455 uppercase tracking-wider">Actionable Solution</h5>
                                    <p className="text-sm text-zinc-655 dark:text-zinc-450 leading-relaxed whitespace-pre-line">
                                      {finding.aiFix || finding.recommendation}
                                    </p>
                                  </div>

                                  {finding.codeExample && (
                                    <div className="space-y-2 pt-2 border-t border-zinc-100 dark:border-zinc-800/80">
                                      <h5 className="text-xxs font-bold text-red-600 dark:text-red-400 uppercase tracking-wider">Secure Implementation Code Example</h5>
                                      <div className="rounded-lg overflow-hidden border border-zinc-200 dark:border-zinc-800 max-w-full">
                                        <SyntaxHighlighter 
                                          language="javascript" 
                                          style={vscDarkPlus}
                                          customStyle={{
                                            margin: 0,
                                            fontSize: '12px',
                                            padding: '14px',
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
                            )}

                            {/* Standard recommendation if not AI-enriched */}
                            {(finding.category === 'Passed Checks' || finding.category === 'Informational' || finding.severity === 'INFO') && finding.recommendation && (
                              <div className="space-y-1.5 pt-2 border-t border-zinc-100 dark:border-zinc-800/60">
                                <h4 className="text-xs text-emerald-650 dark:text-emerald-455 font-bold uppercase tracking-wider flex items-center gap-1.5">
                                  <CheckCircle2 className="w-3.5 h-3.5" /> Recommendation
                                </h4>
                                <p className="text-sm text-zinc-700 dark:text-zinc-350 leading-relaxed">
                                  {finding.recommendation}
                                </p>
                              </div>
                            )}

                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

        {/* Scan Summary Card */}
        <div className="w-full max-w-6xl mx-auto px-4 mt-8">
          <div className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-xl p-5 shadow-sm space-y-4">
            <h3 className="text-sm font-bold text-zinc-850 dark:text-zinc-300 uppercase tracking-wider border-b border-zinc-150 dark:border-zinc-800 pb-2">
              Scan Summary
            </h3>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-center">
              <div className="bg-zinc-50 dark:bg-zinc-950 p-3 rounded border border-zinc-200/50 dark:border-zinc-850">
                <span className="text-[10px] text-zinc-400 uppercase block font-semibold">Checks Executed</span>
                <span className="text-lg font-bold mt-1 block">{findings.length}</span>
              </div>
              <div className="bg-zinc-50 dark:bg-zinc-950 p-3 rounded border border-zinc-200/50 dark:border-zinc-850">
                <span className="text-[10px] text-zinc-400 uppercase block font-semibold text-emerald-500">Checks Passed</span>
                <span className="text-lg font-bold mt-1 block text-emerald-500">
                  {findings.filter(f => f.category === 'Passed Checks').length}
                </span>
              </div>
              <div className="bg-zinc-50 dark:bg-zinc-950 p-3 rounded border border-zinc-200/50 dark:border-zinc-850">
                <span className="text-[10px] text-zinc-400 uppercase block font-semibold text-rose-500">Checks Failed</span>
                <span className="text-lg font-bold mt-1 block text-rose-500">
                  {findings.filter(f => f.category === 'Security Findings').length}
                </span>
              </div>
              <div className="bg-zinc-50 dark:bg-zinc-950 p-3 rounded border border-zinc-200/50 dark:border-zinc-850">
                <span className="text-[10px] text-zinc-400 uppercase block font-semibold text-amber-500 font-semibold">Inconclusive</span>
                <span className="text-lg font-bold mt-1 block text-amber-500 font-semibold">
                  {findings.filter(f => f.category === 'Observations' || f.category === 'Informational').length}
                </span>
              </div>
            </div>
          </div>
        </div>

      </main>
      {/* Footer */}
      <footer className="mt-auto py-8 border-t border-zinc-200 dark:border-zinc-800 text-center space-y-1 w-full max-w-6xl mx-auto px-4">
        <p className="text-xs font-bold text-zinc-400 dark:text-zinc-650">API Auditor v1.0</p>
        <p className="text-[10px] text-zinc-450 dark:text-zinc-700">Automated REST API Security Assessment Platform</p>
      </footer>
    </div>
  );
}
