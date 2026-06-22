import axios from 'axios';

export interface VulnerabilityFinding {
  endpoint: string;
  method: string;
  issue: string;
  severity: string;
  confidence: string;
  description: string;
  recommendation: string;
}

const SCANNER_URL = process.env.SCANNER_URL || 'http://localhost:8000';

export const scanTarget = async (targetUrl: string): Promise<VulnerabilityFinding[]> => {
  try {
    const response = await axios.post<VulnerabilityFinding[]>(`${SCANNER_URL}/scan`, {
      targetUrl,
    });
    return response.data;
  } catch (error: any) {
    console.error('Error calling scanner service:', error.message || error);
    throw new Error('Failed to communicate with scanner service');
  }
};
