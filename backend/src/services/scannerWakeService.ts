import axios from 'axios';
import { SCANNER_CONFIG } from '../config/scannerConfig';

const SCANNER_URL = process.env.SCANNER_URL || 'http://localhost:8000';

export class ScannerError extends Error {
  status: string;
  retryable: boolean;
  statusCode: number;

  constructor(status: string, message: string, retryable: boolean, statusCode: number = 500) {
    super(message);
    this.name = 'ScannerError';
    this.status = status;
    this.retryable = retryable;
    this.statusCode = statusCode;
  }
}

export const waitForScanner = async (): Promise<{ wakeDurationMs: number }> => {
  const startTime = Date.now();
  console.log(`[Scanner Wake] Checking if scanner is awake at ${SCANNER_URL}/health...`);

  for (let attempt = 1; attempt <= SCANNER_CONFIG.maxWakeAttempts; attempt++) {
    try {
      await axios.get(`${SCANNER_URL}/health`, {
        timeout: SCANNER_CONFIG.healthTimeout,
      });
      const elapsedSeconds = ((Date.now() - startTime) / 1000).toFixed(1);
      console.log(`\nScanner awake after ${elapsedSeconds} seconds\nStarting scan...\n`);
      return { wakeDurationMs: Date.now() - startTime };
    } catch (err: any) {
      console.log(`Attempt ${attempt}/${SCANNER_CONFIG.maxWakeAttempts}`);
      console.log(`Scanner unavailable\n`);
      if (attempt < SCANNER_CONFIG.maxWakeAttempts) {
        await new Promise((resolve) => setTimeout(resolve, SCANNER_CONFIG.retryInterval));
      }
    }
  }

  throw new ScannerError(
    'SCANNER_TIMEOUT',
    `Scanner did not become available within ${(SCANNER_CONFIG.maxWakeAttempts * SCANNER_CONFIG.retryInterval) / 1000} seconds.`,
    true,
    504 // Gateway Timeout
  );
};
