const multer = require('multer');
const path = require('path');
const fs = require('fs');

// Ensure upload directory exists
const uploadDir = process.env.UPLOAD_DIR || 'uploads';
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Configure multer storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    // Generate temporary filename - will be renamed after validation
    const timestamp = Date.now();
    const random = Math.random().toString(36).substring(2, 15);
    const ext = path.extname(file.originalname);
    cb(null, `temp_${timestamp}_${random}${ext}`);
  }
});

// File filter function
const fileFilter = (req, file, cb) => {
  // Get allowed file types from environment
  const allowedTypes = process.env.ALLOWED_FILE_TYPES ? 
    process.env.ALLOWED_FILE_TYPES.split(',').map(type => type.trim()) : 
    ['pdf', 'docx', 'jpeg', 'jpg', 'png', 'gif', 'txt'];

  // Get file extension
  const ext = path.extname(file.originalname).toLowerCase().substring(1);
  
  // Check if file type is allowed
  if (allowedTypes.includes(ext)) {
    cb(null, true);
  } else {
    cb(new Error(`File type .${ext} is not allowed. Allowed types: ${allowedTypes.join(', ')}`), false);
  }
};

// Multer configuration
const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: parseInt(process.env.MAX_FILE_SIZE) || 10 * 1024 * 1024, // 10MB default
    files: 1 // Only one file at a time
  }
});

// Error handling middleware for multer
const handleUploadError = (error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({
        success: false,
        message: `File size exceeds maximum allowed size of ${Math.round((parseInt(process.env.MAX_FILE_SIZE) || 10 * 1024 * 1024) / (1024 * 1024))}MB`
      });
    }
    
    if (error.code === 'LIMIT_FILE_COUNT') {
      return res.status(400).json({
        success: false,
        message: 'Too many files. Only one file is allowed per upload'
      });
    }

    return res.status(400).json({
      success: false,
      message: error.message
    });
  }

  if (error.message.includes('File type')) {
    return res.status(400).json({
      success: false,
      message: error.message
    });
  }

  next(error);
};

// Clean up temporary files middleware
const cleanupTempFiles = (req, res, next) => {
  // Clean up any temporary files on request end
  res.on('finish', () => {
    if (req.file && req.file.path.includes('temp_')) {
      try {
        if (fs.existsSync(req.file.path)) {
          fs.unlinkSync(req.file.path);
        }
      } catch (error) {
        console.warn('Failed to cleanup temp file:', error.message);
      }
    }
  });

  next();
};

module.exports = {
  upload: upload.single('file'),
  handleUploadError,
  cleanupTempFiles
};
