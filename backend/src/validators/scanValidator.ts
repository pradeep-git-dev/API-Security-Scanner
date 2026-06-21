import { z } from 'zod';

export const createScanSchema = z.object({
  targetUrl: z.string().url({ message: 'Invalid URL format' }).trim(),
});
