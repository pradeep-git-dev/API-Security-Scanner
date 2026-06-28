import { Schema, model, Document, Types } from 'mongoose';
import { ScanStatus } from '../types';

export interface IScan extends Document {
  userId: Types.ObjectId;
  targetUrl: string;
  sourceType: string;
  status: ScanStatus;
  progress: number;
  score: number;
  createdAt: Date;
  startedAt: Date;
  completedAt?: Date;
  durationMs?: number;
  totalEndpointsScanned: number;
  scannerVersion: string;
  authConfig?: {
    authType: string;
    headerName?: string;
  };
  discoveryMetadata?: {
    source: string;
    endpointCount: number;
    version: string;
    parsedSuccessfully: boolean;
  };
  fingerprint?: {
    server: { name: string; confidence: string };
    framework: { name: string; confidence: string };
    hosting: { name: string; confidence: string };
    tls: string;
    responseTime: number;
  };
}

const scanSchema = new Schema<IScan>(
  {
    userId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: [true, 'User ID is required'],
    },
    targetUrl: {
      type: String,
      required: [true, 'Target URL is required'],
      trim: true,
    },
    sourceType: {
      type: String,
      default: 'web',
    },
    status: {
      type: String,
      enum: Object.values(ScanStatus),
      default: ScanStatus.PENDING,
    },
    progress: {
      type: Number,
      min: 0,
      max: 100,
      default: 0,
    },
    score: {
      type: Number,
      default: 0,
    },
    createdAt: {
      type: Date,
      default: Date.now,
    },
    startedAt: {
      type: Date,
      default: Date.now,
    },
    completedAt: {
      type: Date,
    },
    durationMs: {
      type: Number,
    },
    totalEndpointsScanned: {
      type: Number,
      default: 0,
    },
    scannerVersion: {
      type: String,
      default: '1.0.0',
    },
    authConfig: {
      authType: { type: String, default: 'None' },
      headerName: { type: String },
    },
    discoveryMetadata: {
      source: { type: String, default: 'Recon Probing' },
      endpointCount: { type: Number, default: 1 },
      version: { type: String, default: 'N/A' },
      parsedSuccessfully: { type: Boolean, default: false },
    },
    fingerprint: {
      server: {
        name: { type: String, default: 'Unknown' },
        confidence: { type: String, default: 'LOW' },
      },
      framework: {
        name: { type: String, default: 'Unknown' },
        confidence: { type: String, default: 'LOW' },
      },
      hosting: {
        name: { type: String, default: 'Unknown' },
        confidence: { type: String, default: 'LOW' },
      },
      tls: { type: String, default: 'N/A' },
      responseTime: { type: Number, default: 0 },
    },
  }
);

export const Scan = model<IScan>('Scan', scanSchema);
export default Scan;
