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

const wakeScanner = async (): Promise<void> => {
  console.log(`Checking if scanner is awake at ${SCANNER_URL}/health...`);
  const maxRetries = 20; // 20 retries * 3 seconds = 60 seconds max
  const delayMs = 3000;

  for (let i = 0; i < maxRetries; i++) {
    try {
      await axios.get(`${SCANNER_URL}/health`, { timeout: 5000 });
      console.log('Scanner is awake and healthy!');
      return;
    } catch (err: any) {
      console.log(`Scanner not ready yet (attempt ${i + 1}/${maxRetries}): ${err.message}`);
      if (i < maxRetries - 1) {
        await new Promise((resolve) => setTimeout(resolve, delayMs));
      }
    }
  }
  console.warn('Scanner did not wake up in time, proceeding with scan anyway...');
};

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
    console.log({
      targetUrl,
      openApiSpec,
      authConfig
    });
    const response = await axios.post<ScanResult>(`${SCANNER_URL}/scan`, {
      targetUrl,
      openApiSpec,
      authConfig,
    });
    return response.data;
  } catch (error: any) {
    console.error("Status:", error.response?.status);
    console.error("Response:", error.response?.data);
    console.error("Message:", error.message);
    throw error;
  }
};
