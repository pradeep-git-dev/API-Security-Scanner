import app from './app';
import { connectDB } from './config/db';

const PORT = process.env.PORT || 5000;

const startServer = async () => {
  // Connect to MongoDB
  await connectDB();

  // Start HTTP Server
  app.listen(PORT, () => {
    console.log(`[Server] running on port ${PORT} in ${process.env.NODE_ENV || 'development'} mode`);
  });
};

startServer();
