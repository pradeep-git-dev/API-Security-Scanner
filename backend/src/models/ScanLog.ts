import { Schema, model, Document, Types } from 'mongoose';

export interface IScanLog extends Document {
  scanId: Types.ObjectId;
  stage: string;
  message: string;
  timestamp: Date;
}

const scanLogSchema = new Schema<IScanLog>({
  scanId: {
    type: Schema.Types.ObjectId,
    ref: 'Scan',
    required: [true, 'Scan ID is required'],
  },
  stage: {
    type: String,
    required: [true, 'Stage is required'],
    trim: true,
  },
  message: {
    type: String,
    required: [true, 'Message is required'],
    trim: true,
  },
  timestamp: {
    type: Date,
    default: Date.now,
  },
});

export const ScanLog = model<IScanLog>('ScanLog', scanLogSchema);
export default ScanLog;
