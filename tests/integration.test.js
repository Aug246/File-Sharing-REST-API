const request = require('supertest');
const app = require('../src/index');
const User = require('../src/models/User');
const File = require('../src/models/File');
const TestHelpers = require('./utils/testHelpers');
const fs = require('fs');
const path = require('path');

describe('End-to-End Integration Tests', () => {
  let helpers;
  let userData;
  let adminData;

  beforeAll(() => {
    helpers = new TestHelpers();
  });

  beforeEach(async () => {
    userData = await helpers.createTestUser({
      username: 'integrationuser',
      email: 'integration@example.com'
    });
    
    adminData = await helpers.createTestAdmin();
  });

  afterEach(async () => {
    await helpers.cleanup();
  });

  describe('Complete User Journey', () => {
    test('should complete full user registration and file management workflow', async () => {
      // Step 1: Register new user
      const registrationData = {
        username: 'journeyuser',
        email: 'journey@example.com',
        password: 'JourneyPass123!'
      };

      const registerResponse = await request(app)
        .post('/api/auth/register')
        .send(registrationData);

      expect(registerResponse.status).toBe(201);
      expect(registerResponse.body.success).toBe(true);
      
      const { accessToken, refreshToken } = registerResponse.body.data;
      const authHeader = `Bearer ${accessToken}`;

      // Step 2: Login with registered user
      const loginResponse = await request(app)
        .post('/api/auth/login')
        .send({
          usernameOrEmail: registrationData.username,
          password: registrationData.password
        });

      expect(loginResponse.status).toBe(200);
      expect(loginResponse.body.success).toBe(true);

      // Step 3: Get user profile
      const profileResponse = await request(app)
        .get('/api/auth/profile')
        .set('Authorization', authHeader);

      expect(profileResponse.status).toBe(200);
      expect(profileResponse.body.data.user.username).toBe(registrationData.username);

      // Step 4: Upload a file
      const testFilePath = path.join(__dirname, '../fixtures/journey-file.txt');
      fs.writeFileSync(testFilePath, 'Journey file content');

      const uploadResponse = await helpers.makeFileUploadRequest(
        authHeader,
        testFilePath,
        {
          description: 'File uploaded during user journey',
          tags: 'journey,test',
          isPublic: 'false'
        }
      );

      expect(uploadResponse.status).toBe(201);
      expect(uploadResponse.body.success).toBe(true);
      
      const uploadedFile = uploadResponse.body.data.file;

      // Step 5: List user files
      const listResponse = await request(app)
        .get('/api/files/my-files')
        .set('Authorization', authHeader);

      expect(listResponse.status).toBe(200);
      expect(listResponse.body.data.files).toHaveLength(1);
      expect(listResponse.body.data.files[0].filename).toBe('journey-file.txt');

      // Step 6: Update file metadata
      const updateResponse = await request(app)
        .put(`/api/files/${uploadedFile._id}`)
        .set('Authorization', authHeader)
        .send({
          description: 'Updated journey file description',
          isPublic: 'true'
        });

      expect(updateResponse.status).toBe(200);
      expect(updateResponse.body.data.file.isPublic).toBe(true);

      // Step 7: Download the file
      const downloadResponse = await request(app)
        .get(`/api/files/${uploadedFile._id}/download`)
        .set('Authorization', authHeader);

      expect(downloadResponse.status).toBe(200);
      expect(downloadResponse.headers['content-disposition']).toContain('journey-file.txt');

      // Step 8: Get file statistics
      const statsResponse = await request(app)
        .get('/api/files/stats/overview')
        .set('Authorization', authHeader);

      expect(statsResponse.status).toBe(200);
      expect(statsResponse.body.data.totalFiles).toBe(1);

      // Step 9: Delete the file
      const deleteResponse = await request(app)
        .delete(`/api/files/${uploadedFile._id}`)
        .set('Authorization', authHeader);

      expect(deleteResponse.status).toBe(200);
      expect(deleteResponse.body.success).toBe(true);

      // Step 10: Verify file is deleted
      const verifyDeleteResponse = await request(app)
        .get(`/api/files/${uploadedFile._id}`)
        .set('Authorization', authHeader);

      expect(verifyDeleteResponse.status).toBe(404);

      // Step 11: Logout
      const logoutResponse = await request(app)
        .post('/api/auth/logout')
        .set('Authorization', authHeader)
        .send({ refreshToken });

      expect(logoutResponse.status).toBe(200);
      expect(logoutResponse.body.success).toBe(true);
    });

    test('should handle complete admin workflow', async () => {
      // Create regular user for admin to manage
      const regularUser = await helpers.createTestUser({
        username: 'regularuser',
        email: 'regular@example.com'
      });

      // Admin views all users
      const usersResponse = await request(app)
        .get('/api/admin/users')
        .set('Authorization', adminData.authHeader);

      expect(usersResponse.status).toBe(200);
      expect(usersResponse.body.data.users.length).toBeGreaterThan(0);

      // Admin views system statistics
      const statsResponse = await request(app)
        .get('/api/admin/stats')
        .set('Authorization', adminData.authHeader);

      expect(statsResponse.status).toBe(200);
      expect(statsResponse.body.data.users.total).toBeGreaterThan(0);

      // Admin deactivates user
      const deactivateResponse = await request(app)
        .put(`/api/admin/users/${regularUser.user._id}/status`)
        .set('Authorization', adminData.authHeader)
        .send({ isActive: false });

      expect(deactivateResponse.status).toBe(200);
      expect(deactivateResponse.body.success).toBe(true);

      // Verify user is deactivated
      const updatedUser = await User.findById(regularUser.user._id);
      expect(updatedUser.isActive).toBe(false);

      // Reactivate user
      const reactivateResponse = await request(app)
        .put(`/api/admin/users/${regularUser.user._id}/status`)
        .set('Authorization', adminData.authHeader)
        .send({ isActive: true });

      expect(reactivateResponse.status).toBe(200);

      // Verify user is reactivated
      const reactivatedUser = await User.findById(regularUser.user._id);
      expect(reactivatedUser.isActive).toBe(true);
    });
  });

  describe('Multi-User Scenarios', () => {
    test('should handle multiple users with shared public files', async () => {
      // Create two users
      const user1 = await helpers.createTestUser({
        username: 'user1',
        email: 'user1@example.com'
      });

      const user2 = await helpers.createTestUser({
        username: 'user2',
        email: 'user2@example.com'
      });

      // User1 uploads a public file
      const testFilePath = path.join(__dirname, '../fixtures/shared-file.txt');
      fs.writeFileSync(testFilePath, 'Shared file content');

      const uploadResponse = await helpers.makeFileUploadRequest(
        user1.authHeader,
        testFilePath,
        {
          description: 'Public file for sharing',
          isPublic: 'true'
        }
      );

      expect(uploadResponse.status).toBe(201);
      const sharedFile = uploadResponse.body.data.file;

      // User2 should be able to see the public file
      const publicFilesResponse = await request(app)
        .get('/api/files/public')
        .set('Authorization', user2.authHeader);

      expect(publicFilesResponse.status).toBe(200);
      expect(publicFilesResponse.body.data.files.length).toBeGreaterThan(0);

      // User2 should be able to download the public file
      const downloadResponse = await request(app)
        .get(`/api/files/${sharedFile._id}/download`)
        .set('Authorization', user2.authHeader);

      expect(downloadResponse.status).toBe(200);

      // User2 should not be able to modify the file
      const modifyResponse = await request(app)
        .put(`/api/files/${sharedFile._id}`)
        .set('Authorization', user2.authHeader)
        .send({
          description: 'Unauthorized modification'
        });

      expect(modifyResponse.status).toBe(403);

      // User2 should not be able to delete the file
      const deleteResponse = await request(app)
        .delete(`/api/files/${sharedFile._id}`)
        .set('Authorization', user2.authHeader);

      expect(deleteResponse.status).toBe(403);
    });

    test('should handle file ownership transfer scenarios', async () => {
      // Create two users
      const user1 = await helpers.createTestUser({
        username: 'owner1',
        email: 'owner1@example.com'
      });

      const user2 = await helpers.createTestUser({
        username: 'owner2',
        email: 'owner2@example.com'
      });

      // User1 uploads a file
      const testFilePath = path.join(__dirname, '../fixtures/ownership-file.txt');
      fs.writeFileSync(testFilePath, 'Ownership test file');

      const uploadResponse = await helpers.makeFileUploadRequest(
        user1.authHeader,
        testFilePath
      );

      expect(uploadResponse.status).toBe(201);
      const uploadedFile = uploadResponse.body.data.file;

      // User1 should be able to access the file
      const user1AccessResponse = await request(app)
        .get(`/api/files/${uploadedFile._id}`)
        .set('Authorization', user1.authHeader);

      expect(user1AccessResponse.status).toBe(200);

      // User2 should not be able to access the private file
      const user2AccessResponse = await request(app)
        .get(`/api/files/${uploadedFile._id}`)
        .set('Authorization', user2.authHeader);

      expect(user2AccessResponse.status).toBe(403);

      // User1 makes the file public
      const makePublicResponse = await request(app)
        .put(`/api/files/${uploadedFile._id}`)
        .set('Authorization', user1.authHeader)
        .send({ isPublic: true });

      expect(makePublicResponse.status).toBe(200);

      // Now User2 should be able to access the file
      const user2AccessAfterPublicResponse = await request(app)
        .get(`/api/files/${uploadedFile._id}`)
        .set('Authorization', user2.authHeader);

      expect(user2AccessAfterPublicResponse.status).toBe(200);
    });
  });

  describe('Complex File Operations', () => {
    test('should handle file operations with different file types', async () => {
      const fileTypes = [
        { name: 'text-file.txt', content: 'Text file content', mimetype: 'text/plain' },
        { name: 'data-file.json', content: '{"key": "value"}', mimetype: 'application/json' },
        { name: 'markup-file.html', content: '<html><body>Test</body></html>', mimetype: 'text/html' }
      ];

      const uploadedFiles = [];

      // Upload different file types
      for (const fileType of fileTypes) {
        const testFilePath = path.join(__dirname, `../fixtures/${fileType.name}`);
        fs.writeFileSync(testFilePath, fileType.content);

        const uploadResponse = await helpers.makeFileUploadRequest(
          userData.authHeader,
          testFilePath,
          {
            description: `${fileType.name} uploaded for testing`,
            tags: fileType.name.split('.')[1],
            isPublic: 'false'
          }
        );

        expect(uploadResponse.status).toBe(201);
        uploadedFiles.push(uploadResponse.body.data.file);
      }

      // List all files
      const listResponse = await request(app)
        .get('/api/files/my-files')
        .set('Authorization', userData.authHeader);

      expect(listResponse.status).toBe(200);
      expect(listResponse.body.data.files).toHaveLength(fileTypes.length);

      // Download each file
      for (const file of uploadedFiles) {
        const downloadResponse = await request(app)
          .get(`/api/files/${file._id}/download`)
          .set('Authorization', userData.authHeader);

        expect(downloadResponse.status).toBe(200);
      }

      // Update metadata for each file
      for (let i = 0; i < uploadedFiles.length; i++) {
        const updateResponse = await request(app)
          .put(`/api/files/${uploadedFiles[i]._id}`)
          .set('Authorization', userData.authHeader)
          .send({
            description: `Updated description for ${fileTypes[i].name}`,
            isPublic: i % 2 === 0 ? 'true' : 'false'
          });

        expect(updateResponse.status).toBe(200);
      }

      // Verify mixed public/private files
      const publicResponse = await request(app)
        .get('/api/files/public');

      expect(publicResponse.status).toBe(200);
      expect(publicResponse.body.data.files.length).toBeGreaterThan(0);
    });

    test('should handle bulk file operations', async () => {
      const fileCount = 5;
      const uploadedFiles = [];

      // Upload multiple files
      for (let i = 0; i < fileCount; i++) {
        const testFilePath = path.join(__dirname, `../fixtures/bulk-${i}.txt`);
        fs.writeFileSync(testFilePath, `Bulk file content ${i}`);

        const uploadResponse = await helpers.makeFileUploadRequest(
          userData.authHeader,
          testFilePath,
          {
            description: `Bulk file ${i}`,
            tags: `bulk,file${i}`,
            isPublic: i % 2 === 0 ? 'true' : 'false'
          }
        );

        expect(uploadResponse.status).toBe(201);
        uploadedFiles.push(uploadResponse.body.data.file);
      }

      // Test pagination with bulk files
      const page1Response = await request(app)
        .get('/api/files/my-files?page=1&limit=2')
        .set('Authorization', userData.authHeader);

      expect(page1Response.status).toBe(200);
      expect(page1Response.body.data.files).toHaveLength(2);
      expect(page1Response.body.data.pagination.totalFiles).toBe(fileCount);

      const page2Response = await request(app)
        .get('/api/files/my-files?page=2&limit=2')
        .set('Authorization', userData.authHeader);

      expect(page2Response.status).toBe(200);
      expect(page2Response.body.data.files).toHaveLength(2);

      // Test filtering
      const filteredResponse = await request(app)
        .get('/api/files/my-files?isPublic=true')
        .set('Authorization', userData.authHeader);

      expect(filteredResponse.status).toBe(200);
      expect(filteredResponse.body.data.files.length).toBeGreaterThan(0);

      // Bulk delete files
      for (const file of uploadedFiles) {
        const deleteResponse = await request(app)
          .delete(`/api/files/${file._id}`)
          .set('Authorization', userData.authHeader);

        expect(deleteResponse.status).toBe(200);
      }

      // Verify all files are deleted
      const finalListResponse = await request(app)
        .get('/api/files/my-files')
        .set('Authorization', userData.authHeader);

      expect(finalListResponse.status).toBe(200);
      expect(finalListResponse.body.data.files).toHaveLength(0);
    });
  });

  describe('Authentication Flow Integration', () => {
    test('should handle complete token lifecycle', async () => {
      // Register and login
      const registrationData = {
        username: 'tokenuser',
        email: 'token@example.com',
        password: 'TokenPass123!'
      };

      const registerResponse = await request(app)
        .post('/api/auth/register')
        .send(registrationData);

      expect(registerResponse.status).toBe(201);
      const { accessToken, refreshToken } = registerResponse.body.data;

      // Use access token
      const profileResponse = await request(app)
        .get('/api/auth/profile')
        .set('Authorization', `Bearer ${accessToken}`);

      expect(profileResponse.status).toBe(200);

      // Refresh token
      const refreshResponse = await request(app)
        .post('/api/auth/refresh')
        .send({ refreshToken });

      expect(refreshResponse.status).toBe(200);
      const newAccessToken = refreshResponse.body.data.accessToken;

      // Use new access token
      const newProfileResponse = await request(app)
        .get('/api/auth/profile')
        .set('Authorization', `Bearer ${newAccessToken}`);

      expect(newProfileResponse.status).toBe(200);

      // Logout
      const logoutResponse = await request(app)
        .post('/api/auth/logout')
        .set('Authorization', `Bearer ${newAccessToken}`)
        .send({ refreshToken });

      expect(logoutResponse.status).toBe(200);

      // Try to use old refresh token (should fail)
      const oldRefreshResponse = await request(app)
        .post('/api/auth/refresh')
        .send({ refreshToken });

      expect(oldRefreshResponse.status).toBe(403);
    });

    test('should handle account lockout and recovery', async () => {
      // Make multiple failed login attempts
      for (let i = 0; i < 5; i++) {
        const response = await request(app)
          .post('/api/auth/login')
          .send({
            usernameOrEmail: 'integrationuser',
            password: 'wrongpassword'
          });

        expect(response.status).toBe(401);
      }

      // Account should be locked
      const lockedResponse = await request(app)
        .post('/api/auth/login')
        .send({
          usernameOrEmail: 'integrationuser',
          password: 'TestPass123!'
        });

      expect(lockedResponse.status).toBe(401);
      expect(lockedResponse.body.message).toContain('locked');

      // Wait for lockout to expire (simulate by manually resetting)
      const user = await User.findOne({ username: 'integrationuser' });
      user.lockUntil = undefined;
      user.loginAttempts = 0;
      await user.save();

      // Should be able to login again
      const recoveredResponse = await request(app)
        .post('/api/auth/login')
        .send({
          usernameOrEmail: 'integrationuser',
          password: 'TestPass123!'
        });

      expect(recoveredResponse.status).toBe(200);
      expect(recoveredResponse.body.success).toBe(true);
    });
  });

  describe('Error Recovery Scenarios', () => {
    test('should recover from file upload failures', async () => {
      // Try to upload invalid file
      const testFilePath = path.join(__dirname, '../fixtures/invalid.exe');
      fs.writeFileSync(testFilePath, 'executable content');

      const invalidUploadResponse = await helpers.makeFileUploadRequest(
        userData.authHeader,
        testFilePath
      );

      expect(invalidUploadResponse.status).toBe(400);

      // Should still be able to upload valid files
      const validFilePath = path.join(__dirname, '../fixtures/valid-recovery.txt');
      fs.writeFileSync(validFilePath, 'Valid content');

      const validUploadResponse = await helpers.makeFileUploadRequest(
        userData.authHeader,
        validFilePath
      );

      expect(validUploadResponse.status).toBe(201);
    });

    test('should handle concurrent operations gracefully', async () => {
      const testFilePath = path.join(__dirname, '../fixtures/concurrent-test.txt');
      fs.writeFileSync(testFilePath, 'Concurrent test content');

      // Upload file
      const uploadResponse = await helpers.makeFileUploadRequest(
        userData.authHeader,
        testFilePath
      );

      expect(uploadResponse.status).toBe(201);
      const fileId = uploadResponse.body.data.file._id;

      // Perform concurrent operations on the same file
      const concurrentOperations = [
        request(app).get(`/api/files/${fileId}`).set('Authorization', userData.authHeader),
        request(app).get(`/api/files/${fileId}/download`).set('Authorization', userData.authHeader),
        request(app).put(`/api/files/${fileId}`).set('Authorization', userData.authHeader).send({
          description: 'Concurrent update'
        })
      ];

      const responses = await Promise.all(concurrentOperations);
      
      // All operations should succeed
      responses.forEach(response => {
        expect([200, 201]).toContain(response.status);
      });
    });
  });

  describe('Performance and Scalability', () => {
    test('should handle large datasets efficiently', async () => {
      // Create many files
      const fileCount = 20;
      const uploadedFiles = [];

      for (let i = 0; i < fileCount; i++) {
        const testFilePath = path.join(__dirname, `../fixtures/perf-${i}.txt`);
        fs.writeFileSync(testFilePath, `Performance test file ${i}`);

        const uploadResponse = await helpers.makeFileUploadRequest(
          userData.authHeader,
          testFilePath,
          {
            description: `Performance test file ${i}`,
            tags: `perf,test${i}`,
            isPublic: 'false'
          }
        );

        expect(uploadResponse.status).toBe(201);
        uploadedFiles.push(uploadResponse.body.data.file);
      }

      // Test pagination performance
      const startTime = Date.now();
      
      const listResponse = await request(app)
        .get('/api/files/my-files?limit=10')
        .set('Authorization', userData.authHeader);

      const endTime = Date.now();
      const responseTime = endTime - startTime;

      expect(listResponse.status).toBe(200);
      expect(responseTime).toBeLessThan(2000); // Should respond within 2 seconds

      // Test search performance
      const searchStartTime = Date.now();
      
      const searchResponse = await request(app)
        .get('/api/files/my-files?search=performance')
        .set('Authorization', userData.authHeader);

      const searchEndTime = Date.now();
      const searchResponseTime = searchEndTime - searchStartTime;

      expect(searchResponse.status).toBe(200);
      expect(searchResponseTime).toBeLessThan(2000);
    });
  });
});
