import { Request } from 'express';

export * from './enums';

export interface AuthenticatedUser {
  id: string;
  email: string;
  role: 'user' | 'admin';
}

export interface AuthenticatedRequest extends Request {
  user?: AuthenticatedUser;
}

