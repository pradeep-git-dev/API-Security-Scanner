import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import authRoutes from './routes/authRoutes';
import scanRoutes from './routes/scanRoutes';
import { getUserProfile } from './controllers/authController';
import { protect } from './middleware/authMiddleware';

// Initialize environment variables
dotenv.config();

const app = express();

// Set secure HTTP headers via Helmet
app.use(helmet());

// Apply rate limiting to all requests
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per window
  message: { message: 'Too many requests from this IP, please try again later.' },
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});
app.use(limiter);

// Enforce HTTPS redirection in production environment
app.use((req, res, next) => {
  if (req.headers['x-forwarded-proto'] !== 'https' && process.env.NODE_ENV === 'production') {
    return res.redirect('https://' + req.headers.host + req.url);
  }
  next();
});

// Setup standard middlewares
app.use(
  cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    credentials: true,
  })
);
app.use(express.json());
app.use(cookieParser());

// Basic health check route
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Map routers
app.use('/auth', authRoutes);
app.use('/', scanRoutes);

// Protected Route: GET /profile
app.get('/profile', protect as any, getUserProfile as any);

// 404 Route handler
app.use((req, res) => {
  res.status(404).json({ message: 'Resource not found' });
});

// Global Error Handler middleware
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('Unhandled Error:', err.message || err);
  res.status(500).json({ message: 'Internal Server Error' });
});

export default app;
