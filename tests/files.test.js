const request = require('supertest');
const app = require('../src/index');
const File = require('../src/models/File');
const User = require('../src/models/User');
const TestHelpers = require('./utils/testHelpers');
const fs = require('fs');
const path = require('path');

describe('File Management System', () => {
  let helpers;
  let userData;
  let adminData;

  beforeAll(() => {
    helpers = new TestHelpers();
  });

  beforeEach(async () => {
    userData = await helpers.createTestUser({
      username: 'fileuser',
      email: 'file@example.com'
    });
    
    adminData = await helpers.createTestAdmin();
  });

  afterEach(async () => {
    await helpers.cleanup();
  });

  describe('POST /api/files/upload', () => {
    describe('Success Cases', () => {
      test('should upload valid text file', async () => {
        const testFilePath = path.join(__dirname, '../fixtures/test-file.txt');
        fs.writeFileSync(testFilePath, 'Test file content');

        const response = await helpers.makeFileUploadRequest(
          userData.authHeader,
          testFilePath,
          {
            description: 'Test file description',
            tags: 'test,upload',
            isPublic: 'false'
          }
        );

        expect(response.status).toBe(201);
        expect(response.body.success).toBe(true);
        expect(response.body.message).toBe('File uploaded successfully');
        expect(response.body.data.file.filename).toBe('test-file.txt');
        expect(response.body.data.file.owner).toBe(userData.user._id.toString());
        expect(response.body.data.file.description).toBe('Test file description');
        expect(response.body.data.file.tags).toEqual(['test', 'upload']);

        // Verify file exists on disk
        const file = await File.findById(response.body.data.file._id);
        const filePath = path.join(process.env.UPLOAD_DIR, file.storedFilename);
        expect(fs.existsSync(filePath)).toBe(true);
      });

      test('should upload file with minimal data', async () => {
        const testFilePath = path.join(__dirname, '../fixtures/minimal.txt');
        fs.writeFileSync(testFilePath, 'Minimal content');

        const response = await helpers.makeFileUploadRequest(
          userData.authHeader,
          testFilePath
        );

        expect(response.status).toBe(201);
        expect(response.body.success).toBe(true);
      });

      test('should handle different file types', async () => {
        const testFiles = [
          { name: 'test.pdf', content: 'PDF content', mimetype: 'application/pdf' },
          { name: 'test.jpg', content: 'Image content', mimetype: 'image/jpeg' },
          { name: 'test.png', content: 'PNG content', mimetype: 'image/png' }
        ];

        for (const testFile of testFiles) {
          const testFilePath = path.join(__dirname, `../fixtures/${testFile.name}`);
          fs.writeFileSync(testFilePath, testFile.content);

          const response = await helpers.makeFileUploadRequest(
            userData.authHeader,
            testFilePath
          );

          expect(response.status).toBe(201);
        }
      });
    });

    describe('Authentication Failures', () => {
      test('should fail without authentication', async () => {
        const testFilePath = path.join(__dirname, '../fixtures/unauth.txt');
        fs.writeFileSync(testFilePath, 'Unauthorized content');

        const response = await request(app)
          .post('/api/files/upload')
          .attach('file', testFilePath);

        expect(response.status).toBe(401);
        expect(response.body.success).toBe(false);
      });

      test('should fail with invalid token', async () => {
        const testFilePath = path.join(__dirname, '../fixtures/invalid.txt');
        fs.writeFileSync(testFilePath, 'Invalid token content');

        const response = await request(app)
          .post('/api/files/upload')
          .set('Authorization', 'Bearer invalid-token')
          .attach('file', testFilePath);

        expect(response.status).toBe(403);
        expect(response.body.success).toBe(false);
      });
    });

    describe('File Validation Failures', () => {
      test('should fail without file', async () => {
        const response = await helpers.makeFileUploadRequest(
          userData.authHeader,
          null
        );

        expect(response.status).toBe(400);
        expect(response.body.success).toBe(false);
        expect(response.body.message).toBe('No file uploaded');
      });

      test('should fail with disallowed file type', async () => {
        const testFilePath = path.join(__dirname, '../fixtures/test.exe');
        fs.writeFileSync(testFilePath, 'Executable content');

        const response = await helpers.makeFileUploadRequest(
          userData.authHeader,
          testFilePath
        );

        expect(response.status).toBe(400);
        expect(response.body.success).toBe(false);
        expect(response.body.message).toContain('not allowed');
      });

      test('should fail with oversized file', async () => {
        const testFilePath = path.join(__dirname, '../fixtures/large.txt');
        const largeContent = 'A'.repeat(11 * 1024 * 1024); // 11MB
        fs.writeFileSync(testFilePath, largeContent);

        const response = await helpers.makeFileUploadRequest(
          userData.authHeader,
          testFilePath
        );

        expect(response.status).toBe(400);
        expect(response.body.success).toBe(false);
        expect(response.body.message).toContain('exceeds maximum');
      });

      test('should fail with suspicious filename', async () => {
        const testFilePath = path.join(__dirname, '../fixtures/../../../etc/passwd');
        fs.writeFileSync(testFilePath, 'Suspicious content');

        const response = await helpers.makeFileUploadRequest(
          userData.authHeader,
          testFilePath
        );

        expect(response.status).toBe(400);
        expect(response.body.success).toBe(false);
      });

      test('should fail with filename containing script tags', async () => {
        const testFilePath = path.join(__dirname, '../fixtures/test<script>alert("xss")</script>.txt');
        fs.writeFileSync(testFilePath, 'XSS attempt');

        const response = await helpers.makeFileUploadRequest(
          userData.authHeader,
          testFilePath
        );

        expect(response.status).toBe(400);
        expect(response.body.success).toBe(false);
      });
    });

    describe('Rate Limiting', () => {
      test('should apply rate limiting to uploads', async () => {
        const testFilePath = path.join(__dirname, '../fixtures/rate-limit.txt');
        fs.writeFileSync(testFilePath, 'Rate limit test');

        // Make multiple upload requests rapidly
        const promises = [];
        for (let i = 0; i < 15; i++) {
          promises.push(
            helpers.makeFileUploadRequest(
              userData.authHeader,
              testFilePath,
              { description: `Upload ${i}` }
            )
          );
        }

        const responses = await Promise.all(promises);
        
        // Some requests should be rate limited
        const rateLimitedResponses = responses.filter(r => r.status === 429);
        expect(rateLimitedResponses.length).toBeGreaterThan(0);
      });
    });
  });

  describe('GET /api/files/my-files', () => {
    beforeEach(async () => {
      // Create test files
      await helpers.createTestFile(userData.user._id, {
        filename: 'file1.txt',
        description: 'First file',
        tags: ['test', 'first'],
        isPublic: false
      });

      await helpers.createTestFile(userData.user._id, {
        filename: 'file2.txt',
        description: 'Second file',
        tags: ['test', 'second'],
        isPublic: true
      });

      await helpers.createTestFile(userData.user._id, {
        filename: 'file3.pdf',
        description: 'Third file',
        tags: ['document'],
        isPublic: false
      });
    });

    test('should get user files with pagination', async () => {
      const response = await request(app)
        .get('/api/files/my-files?page=1&limit=2')
        .set('Authorization', userData.authHeader);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data.files).toHaveLength(2);
      expect(response.body.data.pagination.currentPage).toBe(1);
      expect(response.body.data.pagination.totalFiles).toBe(3);
    });

    test('should filter files by search term', async () => {
      const response = await request(app)
        .get('/api/files/my-files?search=first')
        .set('Authorization', userData.authHeader);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data.files).toHaveLength(1);
      expect(response.body.data.files[0].description).toBe('First file');
    });

    test('should filter files by tag', async () => {
      const response = await request(app)
        .get('/api/files/my-files?tag=document')
        .set('Authorization', userData.authHeader);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data.files).toHaveLength(1);
      expect(response.body.data.files[0].filename).toBe('file3.pdf');
    });

    test('should filter files by public status', async () => {
      const response = await request(app)
        .get('/api/files/my-files?isPublic=true')
        .set('Authorization', userData.authHeader);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data.files).toHaveLength(1);
      expect(response.body.data.files[0].isPublic).toBe(true);
    });

    test('should sort files by different criteria', async () => {
      const response = await request(app)
        .get('/api/files/my-files?sortBy=filename&sortOrder=asc')
        .set('Authorization', userData.authHeader);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data.files[0].filename).toBe('file1.txt');
    });

    test('should fail without authentication', async () => {
      const response = await request(app)
        .get('/api/files/my-files');

      expect(response.status).toBe(401);
      expect(response.body.success).toBe(false);
    });
  });

  describe('GET /api/files/public', () => {
    beforeEach(async () => {
      // Create public files
      await helpers.createTestFile(userData.user._id, {
        filename: 'public1.txt',
        description: 'Public file 1',
        tags: ['public'],
        isPublic: true
      });

      await helpers.createTestFile(userData.user._id, {
        filename: 'public2.pdf',
        description: 'Public file 2',
        tags: ['public', 'document'],
        isPublic: true
      });

      // Create private file
      await helpers.createTestFile(userData.user._id, {
        filename: 'private.txt',
        description: 'Private file',
        tags: ['private'],
        isPublic: false
      });
    });

    test('should get only public files', async () => {
      const response = await request(app)
        .get('/api/files/public');

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data.files).toHaveLength(2);
      response.body.data.files.forEach(file => {
        expect(file.isPublic).toBe(true);
      });
    });

    test('should work without authentication', async () => {
      const response = await request(app)
        .get('/api/files/public');

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
    });

    test('should not expose stored filename in public endpoint', async () => {
      const response = await request(app)
        .get('/api/files/public');

      expect(response.status).toBe(200);
      response.body.data.files.forEach(file => {
        expect(file.storedFilename).toBeUndefined();
      });
    });

    test('should filter public files by search and tags', async () => {
      const response = await request(app)
        .get('/api/files/public?search=document&tag=document');

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data.files).toHaveLength(1);
      expect(response.body.data.files[0].filename).toBe('public2.pdf');
    });
  });

  describe('GET /api/files/:id', () => {
    let testFile;

    beforeEach(async () => {
      testFile = await helpers.createTestFile(userData.user._id, {
        filename: 'test-detail.txt',
        description: 'File for detail testing',
        tags: ['detail'],
        isPublic: false
      });
    });

    test('should get file details for owner', async () => {
      const response = await request(app)
        .get(`/api/files/${testFile._id}`)
        .set('Authorization', userData.authHeader);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data.file.filename).toBe('test-detail.txt');
      expect(response.body.data.file.owner.username).toBe('fileuser');
    });

    test('should deny access to private file for non-owner', async () => {
      const otherUser = await helpers.createTestUser({
        username: 'otheruser',
        email: 'other@example.com'
      });

      const response = await request(app)
        .get(`/api/files/${testFile._id}`)
        .set('Authorization', otherUser.authHeader);

      expect(response.status).toBe(403);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toBe('Access denied');
    });

    test('should allow access to public file for any user', async () => {
      testFile.isPublic = true;
      await testFile.save();

      const otherUser = await helpers.createTestUser({
        username: 'otheruser',
        email: 'other@example.com'
      });

      const response = await request(app)
        .get(`/api/files/${testFile._id}`)
        .set('Authorization', otherUser.authHeader);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
    });

    test('should fail with invalid file ID', async () => {
      const response = await request(app)
        .get('/api/files/invalid-id')
        .set('Authorization', userData.authHeader);

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
    });

    test('should fail with non-existent file ID', async () => {
      const fakeId = '507f1f77bcf86cd799439011'; // Valid ObjectId format
      const response = await request(app)
        .get(`/api/files/${fakeId}`)
        .set('Authorization', userData.authHeader);

      expect(response.status).toBe(404);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toBe('File not found');
    });
  });

  describe('GET /api/files/:id/download', () => {
    let testFile;

    beforeEach(async () => {
      testFile = await helpers.createTestFile(userData.user._id, {
        filename: 'download-test.txt',
        description: 'File for download testing',
        isPublic: false
      });
    });

    test('should download file for owner', async () => {
      const response = await request(app)
        .get(`/api/files/${testFile._id}/download`)
        .set('Authorization', userData.authHeader);

      expect(response.status).toBe(200);
      expect(response.headers['content-disposition']).toContain('download-test.txt');
      expect(response.headers['content-type']).toBe('text/plain');
    });

    test('should increment download count', async () => {
      const initialCount = testFile.downloadCount;

      await request(app)
        .get(`/api/files/${testFile._id}/download`)
        .set('Authorization', userData.authHeader);

      const updatedFile = await File.findById(testFile._id);
      expect(updatedFile.downloadCount).toBe(initialCount + 1);
      expect(updatedFile.lastDownloaded).toBeDefined();
    });

    test('should deny download for private file by non-owner', async () => {
      const otherUser = await helpers.createTestUser({
        username: 'otheruser',
        email: 'other@example.com'
      });

      const response = await request(app)
        .get(`/api/files/${testFile._id}/download`)
        .set('Authorization', otherUser.authHeader);

      expect(response.status).toBe(403);
      expect(response.body.success).toBe(false);
    });

    test('should allow download for public file by any user', async () => {
      testFile.isPublic = true;
      await testFile.save();

      const otherUser = await helpers.createTestUser({
        username: 'otheruser',
        email: 'other@example.com'
      });

      const response = await request(app)
        .get(`/api/files/${testFile._id}/download`)
        .set('Authorization', otherUser.authHeader);

      expect(response.status).toBe(200);
    });

    test('should fail when file does not exist on disk', async () => {
      // Delete the physical file
      const filePath = path.join(process.env.UPLOAD_DIR, testFile.storedFilename);
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }

      const response = await request(app)
        .get(`/api/files/${testFile._id}/download`)
        .set('Authorization', userData.authHeader);

      expect(response.status).toBe(404);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toBe('File not found on disk');
    });

    test('should fail without authentication', async () => {
      const response = await request(app)
        .get(`/api/files/${testFile._id}/download`);

      expect(response.status).toBe(401);
      expect(response.body.success).toBe(false);
    });
  });

  describe('PUT /api/files/:id', () => {
    let testFile;

    beforeEach(async () => {
      testFile = await helpers.createTestFile(userData.user._id, {
        filename: 'update-test.txt',
        description: 'Original description',
        tags: ['original'],
        isPublic: false
      });
    });

    test('should update file metadata for owner', async () => {
      const updateData = {
        description: 'Updated description',
        tags: 'updated,tags',
        isPublic: 'true'
      };

      const response = await request(app)
        .put(`/api/files/${testFile._id}`)
        .set('Authorization', userData.authHeader)
        .send(updateData);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data.file.description).toBe('Updated description');
      expect(response.body.data.file.tags).toEqual(['updated', 'tags']);
      expect(response.body.data.file.isPublic).toBe(true);
    });

    test('should deny update for non-owner', async () => {
      const otherUser = await helpers.createTestUser({
        username: 'otheruser',
        email: 'other@example.com'
      });

      const updateData = {
        description: 'Unauthorized update'
      };

      const response = await request(app)
        .put(`/api/files/${testFile._id}`)
        .set('Authorization', otherUser.authHeader)
        .send(updateData);

      expect(response.status).toBe(403);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toBe('You can only update your own files');
    });

    test('should validate update data', async () => {
      const updateData = {
        description: 'A'.repeat(501) // Too long description
      };

      const response = await request(app)
        .put(`/api/files/${testFile._id}`)
        .set('Authorization', userData.authHeader)
        .send(updateData);

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
    });

    test('should fail with invalid file ID', async () => {
      const response = await request(app)
        .put('/api/files/invalid-id')
        .set('Authorization', userData.authHeader)
        .send({ description: 'Test' });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
    });
  });

  describe('DELETE /api/files/:id', () => {
    let testFile;

    beforeEach(async () => {
      testFile = await helpers.createTestFile(userData.user._id, {
        filename: 'delete-test.txt',
        description: 'File for deletion testing'
      });
    });

    test('should delete file for owner', async () => {
      const filePath = path.join(process.env.UPLOAD_DIR, testFile.storedFilename);
      expect(fs.existsSync(filePath)).toBe(true);

      const response = await request(app)
        .delete(`/api/files/${testFile._id}`)
        .set('Authorization', userData.authHeader);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.message).toBe('File deleted successfully');

      // Verify file is deleted from database
      const deletedFile = await File.findById(testFile._id);
      expect(deletedFile).toBeNull();

      // Verify physical file is deleted
      expect(fs.existsSync(filePath)).toBe(false);
    });

    test('should deny deletion for non-owner', async () => {
      const otherUser = await helpers.createTestUser({
        username: 'otheruser',
        email: 'other@example.com'
      });

      const response = await request(app)
        .delete(`/api/files/${testFile._id}`)
        .set('Authorization', otherUser.authHeader);

      expect(response.status).toBe(403);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toBe('You can only delete your own files');

      // Verify file still exists
      const existingFile = await File.findById(testFile._id);
      expect(existingFile).toBeTruthy();
    });

    test('should handle deletion when physical file is missing', async () => {
      // Delete physical file first
      const filePath = path.join(process.env.UPLOAD_DIR, testFile.storedFilename);
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }

      const response = await request(app)
        .delete(`/api/files/${testFile._id}`)
        .set('Authorization', userData.authHeader);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);

      // Verify file is deleted from database even if physical file was missing
      const deletedFile = await File.findById(testFile._id);
      expect(deletedFile).toBeNull();
    });

    test('should fail without authentication', async () => {
      const response = await request(app)
        .delete(`/api/files/${testFile._id}`);

      expect(response.status).toBe(401);
      expect(response.body.success).toBe(false);
    });
  });

  describe('GET /api/files/stats/overview', () => {
    beforeEach(async () => {
      // Create multiple test files
      await helpers.createTestFile(userData.user._id, { filename: 'stats1.txt', isPublic: true });
      await helpers.createTestFile(userData.user._id, { filename: 'stats2.txt', isPublic: false });
      await helpers.createTestFile(userData.user._id, { filename: 'stats3.pdf', isPublic: true });
    });

    test('should get file statistics for user', async () => {
      const response = await request(app)
        .get('/api/files/stats/overview')
        .set('Authorization', userData.authHeader);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data.totalFiles).toBe(3);
      expect(response.body.data.publicFiles).toBe(2);
      expect(response.body.data.privateFiles).toBe(1);
    });

    test('should fail without authentication', async () => {
      const response = await request(app)
        .get('/api/files/stats/overview');

      expect(response.status).toBe(401);
      expect(response.body.success).toBe(false);
    });
  });
});
