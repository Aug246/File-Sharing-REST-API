const mongoose = require('mongoose');
const path = require('path');

const fileSchema = new mongoose.Schema({
  filename: {
    type: String,
    required: [true, 'Original filename is required'],
    trim: true
  },
  storedFilename: {
    type: String,
    required: [true, 'Stored filename is required'],
    unique: true
  },
  mimetype: {
    type: String,
    required: [true, 'MIME type is required']
  },
  size: {
    type: Number,
    required: [true, 'File size is required'],
    min: [1, 'File size must be greater than 0']
  },
  owner: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'File owner is required']
  },
  description: {
    type: String,
    trim: true,
    maxlength: [500, 'Description cannot exceed 500 characters']
  },
  isPublic: {
    type: Boolean,
    default: false
  },
  downloadCount: {
    type: Number,
    default: 0
  },
  lastDownloaded: {
    type: Date
  },
  tags: [{
    type: String,
    trim: true,
    lowercase: true
  }],
  metadata: {
    // Store additional file metadata
    uploadIP: String,
    userAgent: String,
    checksum: String // For file integrity verification
  }
}, {
  timestamps: true
});

// Indexes for better performance
fileSchema.index({ owner: 1, createdAt: -1 });
fileSchema.index({ storedFilename: 1 });
fileSchema.index({ tags: 1 });
fileSchema.index({ isPublic: 1 });

// Virtual for file extension
fileSchema.virtual('extension').get(function() {
  return path.extname(this.filename).toLowerCase();
});

// Virtual for human-readable file size
fileSchema.virtual('sizeFormatted').get(function() {
  const bytes = this.size;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  if (bytes === 0) return '0 Bytes';
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
});

// Virtual for file path
fileSchema.virtual('filePath').get(function() {
  return path.join(process.env.UPLOAD_DIR || 'uploads', this.storedFilename);
});

// Pre-save middleware to validate file type
fileSchema.pre('save', function(next) {
  const allowedTypes = process.env.ALLOWED_FILE_TYPES ? 
    process.env.ALLOWED_FILE_TYPES.split(',') : 
    ['pdf', 'docx', 'jpeg', 'jpg', 'png', 'gif', 'txt'];

  const fileExtension = path.extname(this.filename).toLowerCase().replace('.', '');
  
  if (!allowedTypes.includes(fileExtension)) {
    return next(new Error(`File type .${fileExtension} is not allowed`));
  }

  // Validate file size
  const maxSize = parseInt(process.env.MAX_FILE_SIZE) || 10 * 1024 * 1024; // 10MB default
  if (this.size > maxSize) {
    return next(new Error(`File size exceeds maximum allowed size of ${maxSize} bytes`));
  }

  next();
});

// Instance method to increment download count
fileSchema.methods.incrementDownload = function() {
  this.downloadCount += 1;
  this.lastDownloaded = new Date();
  return this.save();
};

// Instance method to check if user can access file
fileSchema.methods.canAccess = function(userId) {
  // Owner can always access
  if (this.owner.toString() === userId.toString()) {
    return true;
  }
  
  // Public files can be accessed by anyone
  if (this.isPublic) {
    return true;
  }
  
  return false;
};

// Static method to generate unique stored filename
fileSchema.statics.generateStoredFilename = function(originalFilename) {
  const ext = path.extname(originalFilename);
  const timestamp = Date.now();
  const random = Math.random().toString(36).substring(2, 15);
  return `${timestamp}_${random}${ext}`;
};

// Static method to get file statistics
fileSchema.statics.getStats = async function(userId = null) {
  const match = userId ? { owner: userId } : {};
  
  const stats = await this.aggregate([
    { $match: match },
    {
      $group: {
        _id: null,
        totalFiles: { $sum: 1 },
        totalSize: { $sum: '$size' },
        totalDownloads: { $sum: '$downloadCount' },
        averageSize: { $avg: '$size' }
      }
    }
  ]);

  return stats[0] || {
    totalFiles: 0,
    totalSize: 0,
    totalDownloads: 0,
    averageSize: 0
  };
};

// Transform JSON output
fileSchema.methods.toJSON = function() {
  const fileObject = this.toObject();
  delete fileObject.__v;
  return fileObject;
};

module.exports = mongoose.model('File', fileSchema);
