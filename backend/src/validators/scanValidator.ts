import { z } from 'zod';

export const createScanSchema = z.object({
  targetUrl: z.string().url({ message: 'Invalid URL format' }).trim(),
  openApiSpec: z.string().optional(),
  authConfig: z.object({
    authType: z.string(),
    headerName: z.string().optional(),
    tokenValue: z.string().optional(),
    username: z.string().optional(),
    password: z.string().optional(),
  }).optional(),
});
