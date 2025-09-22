const { MongoMemoryServer } = require('mongodb-memory-server');
const path = require('path');
const fs = require('fs');

let mongoServer;

module.exports = async () => {
  // Start in-memory MongoDB instance
  mongoServer = await MongoMemoryServer.create({
    instance: {
      dbName: 'test-file-sharing-api'
    }
  });
  
  const mongoUri = mongoServer.getUri();
  process.env.MONGODB_URI = mongoUri;
  process.env.NODE_ENV = 'test';
  process.env.JWT_SECRET = 'test-jwt-secret-key';
  process.env.JWT_REFRESH_SECRET = 'test-refresh-secret-key';
  process.env.UPLOAD_DIR = 'test-uploads';
  
  // Create test uploads directory
  const testUploadDir = path.join(process.cwd(), 'test-uploads');
  if (!fs.existsSync(testUploadDir)) {
    fs.mkdirSync(testUploadDir, { recursive: true });
  }
  
  // Store server instance for teardown
  global.__MONGOD__ = mongoServer;
};
