const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

/**
 * Generate a secure random string
 * @param {number} length - Length of the string
 * @returns {string} Random string
 */
const generateRandomString = (length = 32) => {
  return crypto.randomBytes(length).toString('hex');
};

/**
 * Generate a secure filename
 * @param {string} originalName - Original filename
 * @returns {string} Secure filename
 */
const generateSecureFilename = (originalName) => {
  const ext = path.extname(originalName);
  const timestamp = Date.now();
  const random = generateRandomString(8);
  return `${timestamp}_${random}${ext}`;
};

/**
 * Validate file type by extension and MIME type
 * @param {string} filename - File name
 * @param {string} mimetype - MIME type
 * @returns {boolean} Is valid file type
 */
const validateFileType = (filename, mimetype) => {
  const allowedTypes = process.env.ALLOWED_FILE_TYPES ? 
    process.env.ALLOWED_FILE_TYPES.split(',').map(type => type.trim()) : 
    ['pdf', 'docx', 'jpeg', 'jpg', 'png', 'gif', 'txt'];

  const ext = path.extname(filename).toLowerCase().substring(1);
  
  // Check extension
  if (!allowedTypes.includes(ext)) {
    return false;
  }

  // Additional MIME type validation
  const mimeTypeMap = {
    'pdf': 'application/pdf',
    'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'jpeg': 'image/jpeg',
    'jpg': 'image/jpeg',
    'png': 'image/png',
    'gif': 'image/gif',
    'txt': 'text/plain'
  };

  const expectedMimeType = mimeTypeMap[ext];
  return expectedMimeType ? mimetype === expectedMimeType : true;
};

/**
 * Calculate file checksum
 * @param {string} filePath - Path to file
 * @returns {Promise<string>} SHA256 checksum
 */
const calculateChecksum = async (filePath) => {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    
    stream.on('data', (data) => hash.update(data));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', reject);
  });
};

/**
 * Format file size in human readable format
 * @param {number} bytes - File size in bytes
 * @returns {string} Formatted size
 */
const formatFileSize = (bytes) => {
  if (bytes === 0) return '0 Bytes';
  
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

/**
 * Sanitize filename for safe storage
 * @param {string} filename - Original filename
 * @returns {string} Sanitized filename
 */
const sanitizeFilename = (filename) => {
  return filename
    .replace(/[^a-zA-Z0-9.-]/g, '_') // Replace special chars with underscore
    .replace(/_{2,}/g, '_') // Replace multiple underscores with single
    .replace(/^_+|_+$/g, '') // Remove leading/trailing underscores
    .toLowerCase();
};

/**
 * Check if file exists and is readable
 * @param {string} filePath - Path to file
 * @returns {Promise<boolean>} File exists and is readable
 */
const fileExists = async (filePath) => {
  try {
    await fs.promises.access(filePath, fs.constants.F_OK | fs.constants.R_OK);
    return true;
  } catch {
    return false;
  }
};

/**
 * Delete file safely
 * @param {string} filePath - Path to file
 * @returns {Promise<boolean>} Success status
 */
const deleteFile = async (filePath) => {
  try {
    if (await fileExists(filePath)) {
      await fs.promises.unlink(filePath);
      return true;
    }
    return false;
  } catch (error) {
    console.error(`Failed to delete file ${filePath}:`, error.message);
    return false;
  }
};

/**
 * Create directory if it doesn't exist
 * @param {string} dirPath - Directory path
 * @returns {Promise<void>}
 */
const ensureDirectoryExists = async (dirPath) => {
  try {
    await fs.promises.access(dirPath, fs.constants.F_OK);
  } catch {
    await fs.promises.mkdir(dirPath, { recursive: true });
  }
};

/**
 * Validate email format
 * @param {string} email - Email to validate
 * @returns {boolean} Is valid email
 */
const isValidEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

/**
 * Validate password strength
 * @param {string} password - Password to validate
 * @returns {object} Validation result
 */
const validatePasswordStrength = (password) => {
  const minLength = 8;
  const hasLowercase = /[a-z]/.test(password);
  const hasUppercase = /[A-Z]/.test(password);
  const hasNumbers = /\d/.test(password);
  const hasSpecialChar = /[@$!%*?&]/.test(password);
  
  const isValid = password.length >= minLength && 
                  hasLowercase && 
                  hasUppercase && 
                  hasNumbers && 
                  hasSpecialChar;
  
  const errors = [];
  if (password.length < minLength) errors.push('Password must be at least 8 characters long');
  if (!hasLowercase) errors.push('Password must contain at least one lowercase letter');
  if (!hasUppercase) errors.push('Password must contain at least one uppercase letter');
  if (!hasNumbers) errors.push('Password must contain at least one number');
  if (!hasSpecialChar) errors.push('Password must contain at least one special character (@$!%*?&)');
  
  return {
    isValid,
    errors
  };
};

/**
 * Generate pagination metadata
 * @param {number} page - Current page
 * @param {number} limit - Items per page
 * @param {number} total - Total items
 * @returns {object} Pagination metadata
 */
const generatePagination = (page, limit, total) => {
  const totalPages = Math.ceil(total / limit);
  
  return {
    currentPage: page,
    totalPages,
    totalItems: total,
    itemsPerPage: limit,
    hasNextPage: page < totalPages,
    hasPrevPage: page > 1,
    nextPage: page < totalPages ? page + 1 : null,
    prevPage: page > 1 ? page - 1 : null
  };
};

/**
 * Log security event
 * @param {string} event - Event type
 * @param {object} details - Event details
 */
const logSecurityEvent = (event, details = {}) => {
  const logEntry = {
    timestamp: new Date().toISOString(),
    event,
    ...details
  };
  
  console.warn('Security Event:', JSON.stringify(logEntry));
};

/**
 * Check if request is from admin panel
 * @param {object} req - Express request object
 * @returns {boolean} Is admin request
 */
const isAdminRequest = (req) => {
  return req.path.startsWith('/api/admin') || req.path.includes('admin');
};

/**
 * Get client IP address
 * @param {object} req - Express request object
 * @returns {string} Client IP
 */
const getClientIP = (req) => {
  return req.ip || 
         req.connection.remoteAddress || 
         req.socket.remoteAddress ||
         (req.connection.socket ? req.connection.socket.remoteAddress : null) ||
         '127.0.0.1';
};

module.exports = {
  generateRandomString,
  generateSecureFilename,
  validateFileType,
  calculateChecksum,
  formatFileSize,
  sanitizeFilename,
  fileExists,
  deleteFile,
  ensureDirectoryExists,
  isValidEmail,
  validatePasswordStrength,
  generatePagination,
  logSecurityEvent,
  isAdminRequest,
  getClientIP
};
