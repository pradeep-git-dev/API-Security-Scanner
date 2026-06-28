import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import swaggerUi from 'swagger-ui-express';
import authRoutes from './routes/authRoutes';
import scanRoutes from './routes/scanRoutes';
import { getUserProfile } from './controllers/authController';
import { protect } from './middleware/authMiddleware';
import { errorHandler } from './middleware/errorHandler';

const swaggerDocument = require('./config/swagger.json');

// Initialize environment variables
dotenv.config();

const app = express();

// Set secure HTTP headers via Helmet
app.use(helmet({
  // Disable content security policy on Swagger UI so it renders properly without inline script blocks issues
  contentSecurityPolicy: false,
}));

// Apply rate limiting to all requests
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: process.env.NODE_ENV === 'production' ? 100 : 10000, // Limit each IP to 100 requests per window in production, 10000 in development
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
  res.json({
    status: 'ok',
    service: 'backend',
    version: '1.0.0',
  });
});

// Mount Swagger documentation UI
app.use('/api/docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

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
app.use(errorHandler as any);

export default app;
