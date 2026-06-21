import { Schema, model, Document, Types } from 'mongoose';

export interface IReport extends Document {
  scanId: Types.ObjectId;
  critical: number;
  high: number;
  medium: number;
  low: number;
  score: number;
  generatedAt: Date;
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
});

export const Report = model<IReport>('Report', reportSchema);
export default Report;
