import { Request, Response, NextFunction } from 'express';

export interface AppError extends Error {
  statusCode?: number;
  errorCode?: string;
  errors?: any;
}

/**
 * Global error handler middleware.
 * Intercepts all unhandled exceptions and formats them into standard professional JSON responses.
 */
export const errorHandler = (
  err: AppError,
  req: Request,
  res: Response,
  next: NextFunction
) => {
  console.error('[Global Error Handler] Caught error:', err.message || err);

  let statusCode = err.statusCode || 500;
  let message = err.message || 'Internal Server Error';
  let errorCode = err.errorCode || 'INTERNAL_SERVER_ERROR';
  let errors = err.errors || undefined;

  // Handle Mongoose Duplicate Key Error (code 11000)
  if ((err as any).code === 11000) {
    statusCode = 400;
    message = 'An account with this email address already exists.';
    errorCode = 'DUPLICATE_KEY_ERROR';
  }

  // Handle Mongoose CastError (e.g. invalid MongoDB ObjectId)
  if (err.name === 'CastError') {
    statusCode = 400;
    message = 'Invalid resource identifier format.';
    errorCode = 'INVALID_ID_FORMAT';
  }

  // Handle Mongoose Schema ValidationError
  if (err.name === 'ValidationError') {
    statusCode = 400;
    message = 'Database validation failed.';
    errorCode = 'DATABASE_VALIDATION_ERROR';
    errors = Object.values((err as any).errors).map((el: any) => el.message);
  }

  // Handle JWT Sign/Verify Errors
  if (err.name === 'JsonWebTokenError') {
    statusCode = 401;
    message = 'Invalid authentication token.';
    errorCode = 'INVALID_TOKEN';
  }
  
  if (err.name === 'TokenExpiredError') {
    statusCode = 401;
    message = 'Authentication token has expired.';
    errorCode = 'TOKEN_EXPIRED';
  }

  // Handle Python Scanner Service Connection Failures
  if (
    message.includes('ECONNREFUSED') || 
    message.includes('connect ECONNREFUSED') || 
    (err as any).code === 'ECONNREFUSED'
  ) {
    statusCode = 502;
    message = 'The security scanner service is currently offline. Ensure the FastAPI service is running on port 8000.';
    errorCode = 'SCANNER_SERVICE_OFFLINE';
  }

  // Return formatted JSON response
  return res.status(statusCode).json({
    success: false,
    message,
    errorCode,
    ...(errors && { errors }),
  });
};
