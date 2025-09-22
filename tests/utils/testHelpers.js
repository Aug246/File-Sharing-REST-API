const request = require('supertest');
const app = require('../../src/index');
const User = require('../../src/models/User');
const File = require('../../src/models/File');
const { generateTokens } = require('../../src/middleware/auth');
const fs = require('fs');
const path = require('path');

class TestHelpers {
  constructor() {
    this.app = app;
    this.testUsers = {};
    this.testFiles = {};
  }

  // Create test user
  async createTestUser(userData = {}) {
    const defaultUser = {
      username: 'testuser',
      email: 'test@example.com',
      password: 'TestPass123!',
      role: 'user',
      isActive: true
    };

    const user = new User({ ...defaultUser, ...userData });
    await user.save();
    
    const tokens = generateTokens(user);
    await user.addRefreshToken(tokens.refreshToken);
    
    this.testUsers[user.username] = {
      user,
      tokens,
      authHeader: `Bearer ${tokens.accessToken}`
    };
    
    return this.testUsers[user.username];
  }

  // Create admin user
  async createTestAdmin() {
    return this.createTestUser({
      username: 'admin',
      email: 'admin@example.com',
      role: 'admin'
    });
  }

  // Create test file
  async createTestFile(ownerId, fileData = {}) {
    const testFilePath = path.join(__dirname, '../fixtures/test-file.txt');
    
    // Create a test file if it doesn't exist
    if (!fs.existsSync(testFilePath)) {
      fs.writeFileSync(testFilePath, 'This is a test file content');
    }

    const defaultFile = {
      filename: 'test-file.txt',
      storedFilename: `test_${Date.now()}.txt`,
      mimetype: 'text/plain',
      size: 26, // Size of test file content
      owner: ownerId,
      description: 'Test file description',
      tags: ['test'],
      isPublic: false
    };

    const file = new File({ ...defaultFile, ...fileData });
    await file.save();

    // Copy test file to upload directory
    const uploadDir = process.env.UPLOAD_DIR || 'test-uploads';
    const finalPath = path.join(uploadDir, file.storedFilename);
    fs.copyFileSync(testFilePath, finalPath);

    this.testFiles[file._id.toString()] = file;
    return file;
  }

  // Make authenticated request
  async makeAuthenticatedRequest(method, endpoint, authHeader, data = {}) {
    const req = request(this.app)[method](endpoint);
    
    if (authHeader) {
      req.set('Authorization', authHeader);
    }

    if (method === 'get' || method === 'delete') {
      return req.query(data);
    } else {
      return req.send(data);
    }
  }

  // Make file upload request
  async makeFileUploadRequest(authHeader, filePath, additionalFields = {}) {
    const req = request(this.app)
      .post('/api/files/upload')
      .set('Authorization', authHeader);

    if (fs.existsSync(filePath)) {
      req.attach('file', filePath);
    }

    // Add additional form fields
    Object.keys(additionalFields).forEach(key => {
      req.field(key, additionalFields[key]);
    });

    return req;
  }

  // Generate malicious test files
  generateMaliciousFiles() {
    const maliciousFiles = {};

    // Empty file
    maliciousFiles.empty = '';

    // Very large file content (simulate large file)
    maliciousFiles.large = 'A'.repeat(11 * 1024 * 1024); // 11MB

    // File with suspicious name
    maliciousFiles.suspiciousName = 'test<script>alert("xss")</script>.txt';

    // File with directory traversal
    maliciousFiles.directoryTraversal = '../../../etc/passwd';

    // Executable file content
    maliciousFiles.executable = '#!/bin/bash\necho "malicious script"';

    // File with null bytes
    maliciousFiles.nullBytes = 'test\x00file.txt';

    return maliciousFiles;
  }

  // Generate test data for validation
  generateValidationTestData() {
    return {
      validUser: {
        username: 'validuser',
        email: 'valid@example.com',
        password: 'ValidPass123!'
      },
      invalidUsers: {
        shortUsername: {
          username: 'ab',
          email: 'test@example.com',
          password: 'ValidPass123!'
        },
        invalidEmail: {
          username: 'testuser',
          email: 'invalid-email',
          password: 'ValidPass123!'
        },
        weakPassword: {
          username: 'testuser',
          email: 'test@example.com',
          password: 'weak'
        },
        missingFields: {
          username: 'testuser'
        }
      }
    };
  }

  // Generate JWT tokens for testing
  generateTestTokens(userId, username, role = 'user') {
    const jwt = require('jsonwebtoken');
    
    const accessToken = jwt.sign(
      { id: userId, username, role },
      process.env.JWT_SECRET,
      { expiresIn: '15m' }
    );

    const refreshToken = jwt.sign(
      { id: userId, username, role },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: '7d' }
    );

    return { accessToken, refreshToken };
  }

  // Generate invalid JWT tokens
  generateInvalidTokens() {
    return {
      malformed: 'invalid.token.here',
      expired: require('jsonwebtoken').sign(
        { id: 'test', username: 'test', role: 'user' },
        process.env.JWT_SECRET,
        { expiresIn: '-1h' } // Expired 1 hour ago
      ),
      wrongSecret: require('jsonwebtoken').sign(
        { id: 'test', username: 'test', role: 'user' },
        'wrong-secret',
        { expiresIn: '15m' }
      ),
      noBearer: 'some-token-without-bearer'
    };
  }

  // Clean up test data
  async cleanup() {
    await User.deleteMany({});
    await File.deleteMany({});
    
    // Clean up test files
    const uploadDir = process.env.UPLOAD_DIR || 'test-uploads';
    if (fs.existsSync(uploadDir)) {
      const files = fs.readdirSync(uploadDir);
      files.forEach(file => {
        const filePath = path.join(uploadDir, file);
        if (fs.statSync(filePath).isFile()) {
          fs.unlinkSync(filePath);
        }
      });
    }
  }

  // Wait for async operations
  async wait(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

module.exports = TestHelpers;
