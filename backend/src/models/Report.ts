import { Schema, model, Document, Types } from 'mongoose';

export interface IReport extends Document {
  scanId: Types.ObjectId;
  critical: number;
  high: number;
  medium: number;
  low: number;
  score: number;
  generatedAt: Date;
  targetType?: string;
  framework?: string;
  contentType?: string;
  server?: string;
  tlsVersion?: string;
  responseTimeMs?: number;
  scoreBreakdown?: { category: string; reason: string; penalty: number }[];
  categories?: { name: string; score: number; max: number; percentage: number }[];
  confidence?: { score: number; label: string };
  headersStatus?: { header: string; status: boolean }[];
  rateLimitReport?: {
    requestsSent: number;
    responses429: number;
    retryAfter: string;
    conclusion: string;
  };
  endpointTree?: { path: string; methods: string[] }[];
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

const reportSchema = new Schema<IReport>({
  scanId: {
    type: Schema.Types.ObjectId,
    ref: 'Scan',
    required: [true, 'Scan ID is required'],
  },
  critical: {
    type: Number,
    default: 0,
  },
  high: {
    type: Number,
    default: 0,
  },
  medium: {
    type: Number,
    default: 0,
  },
  low: {
    type: Number,
    default: 0,
  },
  score: {
    type: Number,
    default: 0,
  },
  generatedAt: {
    type: Date,
    default: Date.now,
  },
  targetType: {
    type: String,
    default: 'UNKNOWN',
  },
  framework: {
    type: String,
    default: 'Unknown',
  },
  contentType: {
    type: String,
    default: 'Unknown',
  },
  server: {
    type: String,
    default: 'Unknown',
  },
  tlsVersion: {
    type: String,
    default: 'N/A',
  },
  responseTimeMs: {
    type: Number,
    default: 0,
  },
  scoreBreakdown: [
    {
      category: { type: String, required: true },
      reason: { type: String, required: true },
      penalty: { type: Number, required: true },
    }
  ],
  categories: [
    {
      name: { type: String, required: true },
      score: { type: Number, required: true },
      max: { type: Number, required: true },
      percentage: { type: Number, required: true },
    }
  ],
  confidence: {
    score: { type: Number, default: 0 },
    label: { type: String, default: 'LOW' },
  },
  headersStatus: [
    {
      header: { type: String, required: true },
      status: { type: Boolean, required: true },
    }
  ],
  rateLimitReport: {
    requestsSent: { type: Number, default: 0 },
    responses429: { type: Number, default: 0 },
    retryAfter: { type: String, default: 'Missing' },
    conclusion: { type: String, default: 'Unable to verify rate limiting.' }
  },
  endpointTree: [
    {
      path: { type: String, required: true },
      methods: [{ type: String }],
    }
  ],
  driftComparison: {
    previousScore: { type: Number, default: 100 },
    currentScore: { type: Number, default: 100 },
    difference: { type: Number, default: 0 },
    resolvedCount: { type: Number, default: 0 },
    newCount: { type: Number, default: 0 },
    severityChanges: [
      {
        issue: { type: String, required: true },
        endpoint: { type: String, required: true },
        from: { type: String, required: true },
        to: { type: String, required: true },
      }
    ]
  }
});

export const Report = model<IReport>('Report', reportSchema);
export default Report;
