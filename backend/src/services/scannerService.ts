import axios from 'axios';

export interface VulnerabilityFinding {
  findingId?: string;
  endpoint: string;
  method: string;
  issue: string;
  severity: string;
  confidence: string;
  description: string;
  recommendation: string;
  category?: string;
  evidence?: any;
  impact?: string;
  owasp?: string;
  cwe?: string;
}

export interface ScanResult {
  score: number;
  scoreBreakdown: { category: string; reason: string; penalty: number }[];
  categories: { name: string; score: number; max: number; percentage: number }[];
  confidence: { score: number; label: string };
  targetType: string;
  framework: string;
  hosting: string;
  contentType: string;
  server: string;
  tlsVersion: string;
  responseTimeMs: number;
  headersStatus: { header: string; status: boolean }[];
  rateLimitReport: {
    requestsSent: number;
    responses429: number;
    retryAfter: string;
    conclusion: string;
  };
  fingerprint: {
    server: { name: string; confidence: string };
    framework: { name: string; confidence: string };
    hosting: { name: string; confidence: string };
    tls: string;
    responseTime: number;
  };
  discoveryMetadata: {
    source: string;
    endpointCount: number;
    version: string;
    parsedSuccessfully: boolean;
  };
  endpointTree: { path: string; methods: string[] }[];
  findings: VulnerabilityFinding[];
}

const SCANNER_URL = process.env.SCANNER_URL || 'http://localhost:8000';

export const scanTarget = async (
  targetUrl: string,
  openApiSpec?: string,
  authConfig?: {
    authType: string;
    headerName?: string;
    tokenValue?: string;
    username?: string;
    password?: string;
  }
): Promise<ScanResult> => {
  try {
    const response = await axios.post<ScanResult>(`${SCANNER_URL}/scan`, {
      targetUrl,
      openApiSpec,
      authConfig,
    });
    return response.data;
  } catch (error: any) {
    console.error('Error calling scanner service:', error.message || error);
    throw new Error('Failed to communicate with scanner service');
  }
};
