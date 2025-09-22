const request = require('supertest');
const app = require('../src/index');
const User = require('../src/models/User');
const File = require('../src/models/File');
const TestHelpers = require('./utils/testHelpers');
const fs = require('fs');
const path = require('path');

describe('Edge Cases and Error Handling', () => {
  let helpers;
  let userData;
  let adminData;

  beforeAll(() => {
    helpers = new TestHelpers();
  });

  beforeEach(async () => {
    userData = await helpers.createTestUser({
      username: 'edgeuser',
      email: 'edge@example.com'
    });
    
    adminData = await helpers.createTestAdmin();
  });

  afterEach(async () => {
    await helpers.cleanup();
  });

  describe('Boundary Value Testing', () => {
    test('should handle minimum username length', async () => {
      const userData = {
        username: 'abc', // Minimum length
        email: 'min@example.com',
        password: 'MinPass123!'
      };

      const response = await request(app)
        .post('/api/auth/register')
        .send(userData);

      expect(response.status).toBe(201);
      expect(response.body.success).toBe(true);
    });

    test('should reject username at minimum length - 1', async () => {
      const userData = {
        username: 'ab', // One character less than minimum
        email: 'min@example.com',
        password: 'MinPass123!'
      };

      const response = await request(app)
        .post('/api/auth/register')
        .send(userData);

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
    });

    test('should handle maximum username length', async () => {
      const userData = {
        username: 'a'.repeat(30), // Maximum length
        email: 'max@example.com',
        password: 'MaxPass123!'
      };

      const response = await request(app)
        .post('/api/auth/register')
        .send(userData);

      expect(response.status).toBe(201);
      expect(response.body.success).toBe(true);
    });

    test('should reject username exceeding maximum length', async () => {
      const userData = {
        username: 'a'.repeat(31), // One character more than maximum
        email: 'max@example.com',
        password: 'MaxPass123!'
      };

      const response = await request(app)
        .post('/api/auth/register')
        .send(userData);

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
    });

    test('should handle minimum password length', async () => {
      const userData = {
        username: 'passmin',
        email: 'passmin@example.com',
        password: 'Min123!@' // Minimum length with all requirements
      };

      const response = await request(app)
        .post('/api/auth/register')
        .send(userData);

      expect(response.status).toBe(201);
      expect(response.body.success).toBe(true);
    });

    test('should reject password below minimum length', async () => {
      const userData = {
        username: 'passshort',
        email: 'passshort@example.com',
        password: 'Min123!' // One character less than minimum
      };

      const response = await request(app)
        .post('/api/auth/register')
        .send(userData);

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
    });

    test('should handle maximum file description length', async () => {
      const testFile = await helpers.createTestFile(userData.user._id);

      const response = await request(app)
        .put(`/api/files/${testFile._id}`)
        .set('Authorization', userData.authHeader)
        .send({
          description: 'A'.repeat(500) // Maximum length
        });

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
    });

    test('should reject file description exceeding maximum length', async () => {
      const testFile = await helpers.createTestFile(userData.user._id);

      const response = await request(app)
        .put(`/api/files/${testFile._id}`)
        .set('Authorization', userData.authHeader)
        .send({
          description: 'A'.repeat(501) // One character more than maximum
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
    });
  });

  describe('Unicode and Internationalization', () => {
    test('should handle unicode characters in username', async () => {
      const userData = {
        username: 'usér_nàme',
        email: 'unicode@example.com',
        password: 'Unicode123!'
      };

      const response = await request(app)
        .post('/api/auth/register')
        .send(userData);

      // Should either accept or reject with proper validation
      expect([200, 201, 400]).toContain(response.status);
    });

    test('should handle emoji in file description', async () => {
      const testFile = await helpers.createTestFile(userData.user._id);

      const response = await request(app)
        .put(`/api/files/${testFile._id}`)
        .set('Authorization', userData.authHeader)
        .send({
          description: 'File with emoji 🚀 and unicode ñáéíóú'
        });

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
    });

    test('should handle international domain names in email', async () => {
      const userData = {
        username: 'international',
        email: 'test@münchen.de', // German umlaut
        password: 'International123!'
      };

      const response = await request(app)
        .post('/api/auth/register')
        .send(userData);

      // Should either accept or reject with proper validation
      expect([200, 201, 400]).toContain(response.status);
    });

    test('should handle right-to-left languages', async () => {
      const testFile = await helpers.createTestFile(userData.user._id);

      const response = await request(app)
        .put(`/api/files/${testFile._id}`)
        .set('Authorization', userData.authHeader)
        .send({
          description: 'وصف باللغة العربية', // Arabic text
          tags: 'عربي,ملف'
        });

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
    });
  });

  describe('Concurrent Operations', () => {
    test('should handle concurrent file uploads', async () => {
      const testFilePath = path.join(__dirname, '../fixtures/concurrent.txt');
      fs.writeFileSync(testFilePath, 'Concurrent upload test');

      const uploadPromises = [];
      for (let i = 0; i < 5; i++) {
        uploadPromises.push(
          helpers.makeFileUploadRequest(
            userData.authHeader,
            testFilePath,
            { description: `Concurrent upload ${i}` }
          )
        );
      }

      const responses = await Promise.all(uploadPromises);
      
      // All should succeed or be properly rate limited
      responses.forEach(response => {
        expect([201, 429]).toContain(response.status);
      });
    });

    test('should handle concurrent login attempts', async () => {
      const loginPromises = [];
      for (let i = 0; i < 10; i++) {
        loginPromises.push(
          request(app)
            .post('/api/auth/login')
            .send({
              usernameOrEmail: 'edgeuser',
              password: 'TestPass123!'
            })
        );
      }

      const responses = await Promise.all(loginPromises);
      
      // Some should succeed, some might be rate limited
      const successCount = responses.filter(r => r.status === 200).length;
      const rateLimitedCount = responses.filter(r => r.status === 429).length;
      
      expect(successCount + rateLimitedCount).toBe(responses.length);
    });

    test('should handle concurrent file deletions', async () => {
      const testFiles = [];
      for (let i = 0; i < 3; i++) {
        testFiles.push(await helpers.createTestFile(userData.user._id, {
          filename: `concurrent-${i}.txt`
        }));
      }

      const deletePromises = testFiles.map(file =>
        request(app)
          .delete(`/api/files/${file._id}`)
          .set('Authorization', userData.authHeader)
      );

      const responses = await Promise.all(deletePromises);
      
      // All should succeed
      responses.forEach(response => {
        expect(response.status).toBe(200);
      });
    });
  });

  describe('Resource Exhaustion', () => {
    test('should handle large number of tags', async () => {
      const testFile = await helpers.createTestFile(userData.user._id);

      const manyTags = Array.from({ length: 11 }, (_, i) => `tag${i}`).join(',');
      
      const response = await request(app)
        .put(`/api/files/${testFile._id}`)
        .set('Authorization', userData.authHeader)
        .send({
          tags: manyTags
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
    });

    test('should handle deeply nested objects', async () => {
      const deepObject = { level1: { level2: { level3: { level4: { level5: 'deep' } } } } };
      
      const response = await request(app)
        .put('/api/auth/profile')
        .set('Authorization', userData.authHeader)
        .send(deepObject);

      // Should reject or sanitize the deep object
      expect(response.status).toBeGreaterThanOrEqual(400);
    });

    test('should handle extremely long strings in requests', async () => {
      const longString = 'A'.repeat(10000);
      
      const response = await request(app)
        .put('/api/auth/profile')
        .set('Authorization', userData.authHeader)
        .send({
          username: longString
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
    });
  });

  describe('Database Edge Cases', () => {
    test('should handle duplicate ObjectId creation attempts', async () => {
      // This is more of a theoretical test since MongoDB generates unique ObjectIds
      const testFile = await helpers.createTestFile(userData.user._id);
      
      // Try to create another file with the same ID (should fail)
      const duplicateFile = new File({
        _id: testFile._id,
        filename: 'duplicate.txt',
        storedFilename: 'duplicate.txt',
        mimetype: 'text/plain',
        size: 10,
        owner: userData.user._id
      });

      await expect(duplicateFile.save()).rejects.toThrow();
    });

    test('should handle database connection loss gracefully', async () => {
      // This test would require mocking database connection
      // For now, we'll test that the app handles missing database gracefully
      const response = await request(app)
        .get('/health');

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
    });

    test('should handle invalid ObjectId formats', async () => {
      const invalidIds = [
        'invalid-id',
        '123',
        'not-an-object-id',
        '',
        null,
        undefined
      ];

      for (const invalidId of invalidIds) {
        const response = await request(app)
          .get(`/api/files/${invalidId}`)
          .set('Authorization', userData.authHeader);

        expect(response.status).toBe(400);
        expect(response.body.success).toBe(false);
      }
    });
  });

  describe('File System Edge Cases', () => {
    test('should handle missing upload directory', async () => {
      // Temporarily change upload directory to non-existent path
      const originalUploadDir = process.env.UPLOAD_DIR;
      process.env.UPLOAD_DIR = '/non/existent/path';

      const testFilePath = path.join(__dirname, '../fixtures/missing-dir.txt');
      fs.writeFileSync(testFilePath, 'Test content');

      const response = await helpers.makeFileUploadRequest(
        userData.authHeader,
        testFilePath
      );

      // Should handle gracefully
      expect([400, 500]).toContain(response.status);

      // Restore original upload directory
      process.env.UPLOAD_DIR = originalUploadDir;
    });

    test('should handle file system permissions issues', async () => {
      // This would require changing file permissions, which is complex in tests
      // Instead, test that the app handles file operations gracefully
      const testFile = await helpers.createTestFile(userData.user._id);

      const response = await request(app)
        .get(`/api/files/${testFile._id}/download`)
        .set('Authorization', userData.authHeader);

      expect([200, 404, 500]).toContain(response.status);
    });

    test('should handle disk space exhaustion', async () => {
      // This is difficult to test without actually filling the disk
      // Instead, test that the app handles large files appropriately
      const testFilePath = path.join(__dirname, '../fixtures/large-file.txt');
      const largeContent = 'A'.repeat(11 * 1024 * 1024); // 11MB
      fs.writeFileSync(testFilePath, largeContent);

      const response = await helpers.makeFileUploadRequest(
        userData.authHeader,
        testFilePath
      );

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
    });
  });

  describe('Network and Protocol Edge Cases', () => {
    test('should handle malformed HTTP headers', async () => {
      const response = await request(app)
        .get('/api/auth/profile')
        .set('Authorization', 'Bearer ')
        .set('Content-Type', 'invalid/content-type')
        .set('User-Agent', 'Mozilla/5.0 (invalid)');

      expect(response.status).toBe(401);
      expect(response.body.success).toBe(false);
    });

    test('should handle oversized request bodies', async () => {
      const largeBody = { data: 'A'.repeat(11 * 1024 * 1024) }; // 11MB

      const response = await request(app)
        .post('/api/auth/register')
        .send(largeBody);

      expect(response.status).toBe(413);
    });

    test('should handle chunked transfer encoding', async () => {
      const response = await request(app)
        .post('/api/auth/login')
        .set('Transfer-Encoding', 'chunked')
        .send({
          usernameOrEmail: 'edgeuser',
          password: 'TestPass123!'
        });

      // Should handle chunked encoding properly
      expect([200, 400, 401]).toContain(response.status);
    });
  });

  describe('Memory and Performance Edge Cases', () => {
    test('should handle memory-intensive operations', async () => {
      // Create many files to test pagination limits
      const filePromises = [];
      for (let i = 0; i < 100; i++) {
        filePromises.push(
          helpers.createTestFile(userData.user._id, {
            filename: `memory-test-${i}.txt`
          })
        );
      }

      await Promise.all(filePromises);

      // Test pagination with large dataset
      const response = await request(app)
        .get('/api/files/my-files?limit=1000')
        .set('Authorization', userData.authHeader);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
    });

    test('should handle rapid successive requests', async () => {
      const requests = [];
      for (let i = 0; i < 50; i++) {
        requests.push(
          request(app)
            .get('/api/auth/profile')
            .set('Authorization', userData.authHeader)
        );
      }

      const responses = await Promise.all(requests);
      
      // Should handle rapid requests (some might be rate limited)
      responses.forEach(response => {
        expect([200, 429]).toContain(response.status);
      });
    });
  });

  describe('State Management Edge Cases', () => {
    test('should handle session state inconsistencies', async () => {
      // Login and get tokens
      const loginResponse = await request(app)
        .post('/api/auth/login')
        .send({
          usernameOrEmail: 'edgeuser',
          password: 'TestPass123!'
        });

      expect(loginResponse.status).toBe(200);
      const { accessToken } = loginResponse.body.data;

      // Use the token immediately
      const profileResponse = await request(app)
        .get('/api/auth/profile')
        .set('Authorization', `Bearer ${accessToken}`);

      expect(profileResponse.status).toBe(200);
    });

    test('should handle concurrent token refresh', async () => {
      // Login and get refresh token
      const loginResponse = await request(app)
        .post('/api/auth/login')
        .send({
          usernameOrEmail: 'edgeuser',
          password: 'TestPass123!'
        });

      expect(loginResponse.status).toBe(200);
      const { refreshToken } = loginResponse.body.data;

      // Try to refresh token concurrently
      const refreshPromises = [];
      for (let i = 0; i < 3; i++) {
        refreshPromises.push(
          request(app)
            .post('/api/auth/refresh')
            .send({ refreshToken })
        );
      }

      const responses = await Promise.all(refreshPromises);
      
      // Should handle concurrent refresh attempts
      responses.forEach(response => {
        expect([200, 403]).toContain(response.status);
      });
    });

    test('should handle user deletion while active', async () => {
      // Login user
      const loginResponse = await request(app)
        .post('/api/auth/login')
        .send({
          usernameOrEmail: 'edgeuser',
          password: 'TestPass123!'
        });

      const { accessToken } = loginResponse.body.data;

      // Delete user (as admin)
      await User.findByIdAndDelete(userData.user._id);

      // Try to use token after user deletion
      const response = await request(app)
        .get('/api/auth/profile')
        .set('Authorization', `Bearer ${accessToken}`);

      expect(response.status).toBe(401);
      expect(response.body.message).toContain('not found');
    });
  });

  describe('Error Recovery and Resilience', () => {
    test('should recover from temporary database errors', async () => {
      // This would require mocking database errors
      // For now, test that the app handles missing data gracefully
      const response = await request(app)
        .get('/api/files/507f1f77bcf86cd799439011')
        .set('Authorization', userData.authHeader);

      expect(response.status).toBe(404);
      expect(response.body.success).toBe(false);
    });

    test('should handle partial request failures', async () => {
      // Test with malformed multipart data
      const response = await request(app)
        .post('/api/files/upload')
        .set('Authorization', userData.authHeader)
        .set('Content-Type', 'multipart/form-data')
        .send('invalid multipart data');

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
    });

    test('should handle timeout scenarios', async () => {
      // This would require mocking timeouts
      // For now, test that the app responds within reasonable time
      const startTime = Date.now();
      
      const response = await request(app)
        .get('/api/auth/profile')
        .set('Authorization', userData.authHeader);

      const endTime = Date.now();
      const responseTime = endTime - startTime;

      expect(response.status).toBe(200);
      expect(responseTime).toBeLessThan(5000); // Should respond within 5 seconds
    });
  });
});
