require('dotenv').config();
const express = require('express');
const morgan = require('morgan');
const connectDB = require('./config/database');

// Import middleware
const {
  helmet,
  cors,
  generalLimiter,
  requestLogger,
  securityHeaders,
  errorHandler,
  notFoundHandler
} = require('./middleware/security');

// Import routes
const authRoutes = require('./routes/auth');
const fileRoutes = require('./routes/files');
const adminRoutes = require('./routes/admin');

// Initialize Express app
const app = express();

// Trust proxy (important for rate limiting and IP detection)
app.set('trust proxy', 1);

// Connect to database
connectDB();

// Security middleware (order matters!)
app.use(helmet);
app.use(cors);
app.use(securityHeaders);
app.use(generalLimiter);

// Request logging
if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
} else {
  app.use(morgan('combined'));
}
app.use(requestLogger);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    success: true,
    message: 'Server is running',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// API routes
app.use('/api/auth', authRoutes);
app.use('/api/files', fileRoutes);
app.use('/api/admin', adminRoutes);

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'Secure File-Sharing REST API',
    version: '1.0.0',
    endpoints: {
      auth: '/api/auth',
      files: '/api/files',
      admin: '/api/admin',
      health: '/health'
    },
    documentation: 'https://github.com/Aug246/File-Sharing-REST-API'
  });
});

// Error handling middleware (must be last)
app.use(notFoundHandler);
app.use(errorHandler);

// Start server
const PORT = process.env.PORT || 3000;

const server = app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📁 Upload directory: ${process.env.UPLOAD_DIR || 'uploads'}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔒 Security features enabled`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received. Shutting down gracefully...');
  server.close(() => {
    console.log('Process terminated');
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT received. Shutting down gracefully...');
  server.close(() => {
    console.log('Process terminated');
  });
});

module.exports = app;
