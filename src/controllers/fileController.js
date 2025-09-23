const File = require('../models/File');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Upload a new file
const uploadFile = async (req, res, next) => {
  try {
    const { description, tags, isPublic } = req.body;
    const userId = req.user._id;

    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: 'No file uploaded'
      });
    }

    // Generate unique stored filename
    const storedFilename = File.generateStoredFilename(req.file.originalname);

    // Calculate file checksum for integrity verification
    const fileBuffer = fs.readFileSync(req.file.path);
    const checksum = crypto.createHash('sha256').update(fileBuffer).digest('hex');

    // Create file record in database
    const fileData = new File({
      filename: req.file.originalname,
      storedFilename,
      mimetype: req.file.mimetype,
      size: req.file.size,
      owner: userId,
      description: description || '',
      tags: tags ? (Array.isArray(tags) ? tags.map(tag => tag.trim().toLowerCase()) : tags.split(',').map(tag => tag.trim().toLowerCase())) : [],
      isPublic: isPublic === 'true' || isPublic === true,
      metadata: {
        uploadIP: req.ip,
        userAgent: req.get('User-Agent'),
        checksum
      }
    });

    // Move file to final location
    const finalPath = path.join(process.env.UPLOAD_DIR || 'uploads', storedFilename);
    fs.renameSync(req.file.path, finalPath);

    try {
      // Save file record
      await fileData.save();

      // Log file upload
      console.log(`File uploaded: ${req.file.originalname} by user ${req.user.username}`);

      res.status(201).json({
        success: true,
        message: 'File uploaded successfully',
        data: {
          file: fileData.toJSON()
        }
      });
    } catch (saveError) {
      // Clean up moved file if database save fails
      if (fs.existsSync(finalPath)) {
        fs.unlinkSync(finalPath);
      }
      throw saveError;
    }
  } catch (error) {
    // Clean up uploaded file if database save fails
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    next(error);
  }
};

// Get user's files with pagination and filtering
const getUserFiles = async (req, res, next) => {
  try {
    const userId = req.user._id;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const sortBy = req.query.sortBy || 'createdAt';
    const sortOrder = req.query.sortOrder === 'asc' ? 1 : -1;
    const search = req.query.search || '';
    const tag = req.query.tag || '';
    const isPublic = req.query.isPublic;

    // Build query
    const query = { owner: userId };

    if (search) {
      query.$or = [
        { filename: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } }
      ];
    }

    if (tag) {
      query.tags = { $in: [tag.toLowerCase()] };
    }

    if (isPublic !== undefined) {
      query.isPublic = isPublic === 'true';
    }

    // Calculate pagination
    const skip = (page - 1) * limit;

    // Get files with pagination
    const files = await File.find(query)
      .sort({ [sortBy]: sortOrder })
      .skip(skip)
      .limit(limit)
      .populate('owner', 'username email')
      .lean();

    // Get total count for pagination
    const totalFiles = await File.countDocuments(query);
    const totalPages = Math.ceil(totalFiles / limit);

    res.json({
      success: true,
      data: {
        files,
        pagination: {
          currentPage: page,
          totalPages,
          totalFiles,
          hasNextPage: page < totalPages,
          hasPrevPage: page > 1
        }
      }
    });
  } catch (error) {
    next(error);
  }
};

// Get public files (for browsing)
const getPublicFiles = async (req, res, next) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const sortBy = req.query.sortBy || 'createdAt';
    const sortOrder = req.query.sortOrder === 'asc' ? 1 : -1;
    const search = req.query.search || '';
    const tag = req.query.tag || '';

    // Build query for public files only
    const query = { isPublic: true };

    if (search) {
      query.$or = [
        { filename: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } }
      ];
    }

    if (tag) {
      query.tags = { $in: [tag.toLowerCase()] };
    }

    // Calculate pagination
    const skip = (page - 1) * limit;

    // Get files with pagination
    const files = await File.find(query)
      .sort({ [sortBy]: sortOrder })
      .skip(skip)
      .limit(limit)
      .populate('owner', 'username')
      .select('-storedFilename') // Don't expose internal filename
      .lean();

    // Get total count for pagination
    const totalFiles = await File.countDocuments(query);
    const totalPages = Math.ceil(totalFiles / limit);

    res.json({
      success: true,
      data: {
        files,
        pagination: {
          currentPage: page,
          totalPages,
          totalFiles,
          hasNextPage: page < totalPages,
          hasPrevPage: page > 1
        }
      }
    });
  } catch (error) {
    next(error);
  }
};

// Get file by ID
const getFile = async (req, res, next) => {
  try {
    const fileId = req.params.id;
    const userId = req.user._id;

    const file = await File.findById(fileId).populate('owner', 'username email');

    if (!file) {
      return res.status(404).json({
        success: false,
        message: 'File not found'
      });
    }

    // Check if user can access this file
    if (!file.canAccess(userId)) {
      return res.status(403).json({
        success: false,
        message: 'Access denied'
      });
    }

    res.json({
      success: true,
      data: {
        file: file.toJSON()
      }
    });
  } catch (error) {
    next(error);
  }
};

// Download file
const downloadFile = async (req, res, next) => {
  try {
    const fileId = req.params.id;
    const userId = req.user._id;

    const file = await File.findById(fileId);

    if (!file) {
      return res.status(404).json({
        success: false,
        message: 'File not found'
      });
    }

    // Check if user can access this file
    if (!file.canAccess(userId)) {
      return res.status(403).json({
        success: false,
        message: 'Access denied'
      });
    }

    // Check if file exists on disk
    const filePath = path.join(process.env.UPLOAD_DIR || 'uploads', file.storedFilename);
    
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({
        success: false,
        message: 'File not found on disk'
      });
    }

    // Increment download count
    await file.incrementDownload();

    // Log download
    console.log(`File downloaded: ${file.filename} by user ${req.user.username}`);

    // Set appropriate headers
    res.setHeader('Content-Disposition', `attachment; filename="${file.filename}"`);
    res.setHeader('Content-Type', file.mimetype);
    res.setHeader('Content-Length', file.size);

    // Stream file to response
    const fileStream = fs.createReadStream(filePath);
    fileStream.pipe(res);

    fileStream.on('error', (error) => {
      console.error('File stream error:', error);
      if (!res.headersSent) {
        res.status(500).json({
          success: false,
          message: 'Error reading file'
        });
      }
    });
  } catch (error) {
    next(error);
  }
};

// Update file metadata
const updateFile = async (req, res, next) => {
  try {
    const fileId = req.params.id;
    const userId = req.user._id;
    const { description, tags, isPublic } = req.body;

    const file = await File.findById(fileId);

    if (!file) {
      return res.status(404).json({
        success: false,
        message: 'File not found'
      });
    }

    // Check if user owns this file
    if (file.owner.toString() !== userId.toString()) {
      return res.status(403).json({
        success: false,
        message: 'You can only update your own files'
      });
    }

    // Update file metadata
    const updateData = {};
    if (description !== undefined) updateData.description = description;
    if (tags !== undefined) {
      // Handle both array (from validation) and string formats
      updateData.tags = Array.isArray(tags) 
        ? tags.map(tag => tag.trim().toLowerCase()) 
        : tags.split(',').map(tag => tag.trim().toLowerCase());
    }
    if (isPublic !== undefined) updateData.isPublic = isPublic === 'true' || isPublic === true;

    const updatedFile = await File.findByIdAndUpdate(
      fileId,
      updateData,
      { new: true, runValidators: true }
    ).populate('owner', 'username email');

    res.json({
      success: true,
      message: 'File updated successfully',
      data: {
        file: updatedFile.toJSON()
      }
    });
  } catch (error) {
    next(error);
  }
};

// Delete file
const deleteFile = async (req, res, next) => {
  try {
    const fileId = req.params.id;
    const userId = req.user._id;

    const file = await File.findById(fileId);

    if (!file) {
      return res.status(404).json({
        success: false,
        message: 'File not found'
      });
    }

    // Check if user owns this file
    if (file.owner.toString() !== userId.toString()) {
      return res.status(403).json({
        success: false,
        message: 'You can only delete your own files'
      });
    }

    // Delete physical file
    const filePath = path.join(process.env.UPLOAD_DIR || 'uploads', file.storedFilename);
    try {
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }
    } catch (error) {
      console.warn(`Failed to delete physical file: ${filePath}`, error.message);
    }

    // Delete file record from database
    await File.findByIdAndDelete(fileId);

    // Log file deletion
    console.log(`File deleted: ${file.filename} by user ${req.user.username}`);

    res.json({
      success: true,
      message: 'File deleted successfully'
    });
  } catch (error) {
    next(error);
  }
};

// Get file statistics
const getFileStats = async (req, res, next) => {
  try {
    const userId = req.user._id;
    const isAdmin = req.user.role === 'admin';

    // Get stats for user's files or all files if admin
    const stats = await File.getStats(isAdmin ? null : userId);

    // Get additional statistics
    const totalFiles = await File.countDocuments(isAdmin ? {} : { owner: userId });
    const publicFiles = await File.countDocuments(
      isAdmin ? { isPublic: true } : { owner: userId, isPublic: true }
    );
    const totalDownloads = await File.aggregate([
      { $match: isAdmin ? {} : { owner: userId } },
      { $group: { _id: null, total: { $sum: '$downloadCount' } } }
    ]);

    res.json({
      success: true,
      data: {
        ...stats,
        totalFiles,
        publicFiles,
        privateFiles: totalFiles - publicFiles,
        totalDownloads: totalDownloads[0]?.total || 0
      }
    });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  uploadFile,
  getUserFiles,
  getPublicFiles,
  getFile,
  downloadFile,
  updateFile,
  deleteFile,
  getFileStats
};
