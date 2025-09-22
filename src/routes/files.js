const express = require('express');
const router = express.Router();
const fileController = require('../controllers/fileController');
const { authenticateToken, requireRole, optionalAuth } = require('../middleware/auth');
const { validate, schemas, validateFile } = require('../middleware/validation');
const { sanitizeInput } = require('../middleware/validation');
const { uploadLimiter, generalLimiter } = require('../middleware/security');
const { upload, handleUploadError, cleanupTempFiles } = require('../middleware/upload');

// Apply rate limiting and input sanitization to all file routes
router.use(generalLimiter);
router.use(sanitizeInput);

// File upload route (stricter rate limiting)
router.post('/upload', 
  authenticateToken,
  uploadLimiter,
  upload,
  handleUploadError,
  validateFile,
  cleanupTempFiles,
  validate(schemas.fileUpload),
  fileController.uploadFile
);

// Get user's files (authenticated)
router.get('/my-files', 
  authenticateToken,
  fileController.getUserFiles
);

// Get public files (optional authentication for better UX)
router.get('/public', 
  optionalAuth,
  fileController.getPublicFiles
);

// Get specific file details
router.get('/:id', 
  authenticateToken,
  fileController.getFile
);

// Download file
router.get('/:id/download', 
  authenticateToken,
  fileController.downloadFile
);

// Update file metadata
router.put('/:id', 
  authenticateToken,
  validate(schemas.fileUpdate),
  fileController.updateFile
);

// Delete file
router.delete('/:id', 
  authenticateToken,
  fileController.deleteFile
);

// Get file statistics
router.get('/stats/overview', 
  authenticateToken,
  fileController.getFileStats
);

module.exports = router;
