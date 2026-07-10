import axios from 'axios';
import { SCANNER_CONFIG } from '../config/scannerConfig';
import { waitForScanner, ScannerError } from './scannerWakeService';

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
  headersStatus: { header: string; status: boolean | null }[];
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

export interface ScanExecutionResult {
  scanResult: ScanResult;
  wakeDurationMs: number;
  scanDurationMs: number;
}

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
): Promise<ScanExecutionResult> => {
  try {
    console.log({
      targetUrl,
      openApiSpec,
      authConfig
    });

    // 1. Wait for the scanner to be awake and measure the wake duration
    const { wakeDurationMs } = await waitForScanner();

    // 2. Perform the scan request with retries on transient errors
    const scanStartTime = Date.now();
    let lastError: any;
    let scanResult: ScanResult | null = null;

    for (let attempt = 0; attempt <= SCANNER_CONFIG.maxScanRetries; attempt++) {
      try {
        const response = await axios.post<ScanResult>(
          `${SCANNER_URL}/scan`,
          { targetUrl, openApiSpec, authConfig },
          { timeout: SCANNER_CONFIG.scanTimeout }
        );
        scanResult = response.data;
        break;
      } catch (err: any) {
        lastError = err;

        // Determine if it is a transient infrastructure error
        const isTransient =
          err.code === 'ECONNREFUSED' ||
          err.code === 'ECONNRESET' ||
          err.code === 'ETIMEDOUT' ||
          err.code === 'EAI_AGAIN' ||
          err.response?.status === 502 ||
          err.response?.status === 503 ||
          err.response?.status === 504;

        if (isTransient && attempt < SCANNER_CONFIG.maxScanRetries) {
          console.warn(
            `[Scanner Service] Scan request failed (attempt ${attempt + 1}/${
              SCANNER_CONFIG.maxScanRetries + 1
            }) due to transient error: ${err.message}. Retrying in 5s...`
          );
          await new Promise((resolve) => setTimeout(resolve, 5000));
        } else {
          break;
        }
      }
    }

    if (!scanResult) {
      // Wrap transient connect errors to return structured response
      if (
        lastError.code === 'ECONNREFUSED' ||
        lastError.code === 'ECONNRESET' ||
        lastError.code === 'ETIMEDOUT' ||
        lastError.code === 'EAI_AGAIN'
      ) {
        throw new ScannerError(
          'SCANNER_UNAVAILABLE',
          `Scanner service is unavailable: ${lastError.message}`,
          true,
          503
        );
      }
      throw lastError;
    }

    const scanDurationMs = Date.now() - scanStartTime;

    return {
      scanResult,
      wakeDurationMs,
      scanDurationMs,
    };
  } catch (error: any) {
    if (error.name === 'ScannerError') {
      throw error;
    }
    console.error("Status:", error.response?.status);
    console.error("Response:", error.response?.data);
    console.error("Message:", error.message);
    throw error;
  }
};
