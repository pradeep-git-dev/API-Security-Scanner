import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import authRoutes from './routes/authRoutes';
import scanRoutes from './routes/scanRoutes';
import { getUserProfile } from './controllers/authController';
import { protect } from './middleware/authMiddleware';

// Initialize environment variables
dotenv.config();

const app = express();

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
