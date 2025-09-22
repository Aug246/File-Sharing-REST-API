const express = require('express');
const router = express.Router();
const User = require('../models/User');
const File = require('../models/File');
const { authenticateToken, requireRole } = require('../middleware/auth');
const { sanitizeInput } = require('../middleware/validation');
const { generalLimiter } = require('../middleware/security');

// Apply authentication, authorization, and rate limiting to all admin routes
router.use(authenticateToken);
router.use(requireRole('admin'));
router.use(generalLimiter);
router.use(sanitizeInput);

// Get all users with pagination
router.get('/users', async (req, res, next) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const search = req.query.search || '';
    const role = req.query.role || '';
    const isActive = req.query.isActive;

    // Build query
    const query = {};
    
    if (search) {
      query.$or = [
        { username: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } }
      ];
    }

    if (role) {
      query.role = role;
    }

    if (isActive !== undefined) {
      query.isActive = isActive === 'true';
    }

    // Calculate pagination
    const skip = (page - 1) * limit;

    // Get users with pagination
    const users = await User.find(query)
      .select('-password -refreshTokens')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    // Get total count for pagination
    const totalUsers = await User.countDocuments(query);
    const totalPages = Math.ceil(totalUsers / limit);

    res.json({
      success: true,
      data: {
        users,
        pagination: {
          currentPage: page,
          totalPages,
          totalUsers,
          hasNextPage: page < totalPages,
          hasPrevPage: page > 1
        }
      }
    });
  } catch (error) {
    next(error);
  }
});

// Get user details by ID
router.get('/users/:id', async (req, res, next) => {
  try {
    const userId = req.params.id;

    const user = await User.findById(userId).select('-password -refreshTokens');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Get user's file statistics
    const fileStats = await File.getStats(userId);
    const totalFiles = await File.countDocuments({ owner: userId });

    res.json({
      success: true,
      data: {
        user,
        stats: {
          ...fileStats,
          totalFiles
        }
      }
    });
  } catch (error) {
    next(error);
  }
});

// Update user status (activate/deactivate)
router.put('/users/:id/status', async (req, res, next) => {
  try {
    const userId = req.params.id;
    const { isActive } = req.body;

    if (typeof isActive !== 'boolean') {
      return res.status(400).json({
        success: false,
        message: 'isActive must be a boolean value'
      });
    }

    const user = await User.findByIdAndUpdate(
      userId,
      { isActive },
      { new: true, runValidators: true }
    ).select('-password -refreshTokens');

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Log admin action
    console.log(`Admin ${req.user.username} ${isActive ? 'activated' : 'deactivated'} user ${user.username}`);

    res.json({
      success: true,
      message: `User ${isActive ? 'activated' : 'deactivated'} successfully`,
      data: { user }
    });
  } catch (error) {
    next(error);
  }
});

// Update user role
router.put('/users/:id/role', async (req, res, next) => {
  try {
    const userId = req.params.id;
    const { role } = req.body;

    if (!['user', 'admin'].includes(role)) {
      return res.status(400).json({
        success: false,
        message: 'Role must be either "user" or "admin"'
      });
    }

    // Prevent admin from demoting themselves
    if (userId === req.user._id.toString()) {
      return res.status(400).json({
        success: false,
        message: 'You cannot change your own role'
      });
    }

    const user = await User.findByIdAndUpdate(
      userId,
      { role },
      { new: true, runValidators: true }
    ).select('-password -refreshTokens');

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Log admin action
    console.log(`Admin ${req.user.username} changed user ${user.username} role to ${role}`);

    res.json({
      success: true,
      message: 'User role updated successfully',
      data: { user }
    });
  } catch (error) {
    next(error);
  }
});

// Delete user account
router.delete('/users/:id', async (req, res, next) => {
  try {
    const userId = req.params.id;

    // Prevent admin from deleting themselves
    if (userId === req.user._id.toString()) {
      return res.status(400).json({
        success: false,
        message: 'You cannot delete your own account'
      });
    }

    const user = await User.findById(userId);
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Delete user's files first
    const userFiles = await File.find({ owner: userId });
    
    // Delete physical files
    const fs = require('fs');
    const path = require('path');
    
    for (const file of userFiles) {
      const filePath = path.join(process.env.UPLOAD_DIR || 'uploads', file.storedFilename);
      try {
        if (fs.existsSync(filePath)) {
          fs.unlinkSync(filePath);
        }
      } catch (error) {
        console.warn(`Failed to delete file: ${filePath}`, error.message);
      }
    }

    // Delete file records from database
    await File.deleteMany({ owner: userId });

    // Delete user account
    await User.findByIdAndDelete(userId);

    // Log admin action
    console.log(`Admin ${req.user.username} deleted user ${user.username} and all their files`);

    res.json({
      success: true,
      message: 'User and all associated files deleted successfully'
    });
  } catch (error) {
    next(error);
  }
});

// Get all files with pagination (admin view)
router.get('/files', async (req, res, next) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const search = req.query.search || '';
    const owner = req.query.owner || '';
    const isPublic = req.query.isPublic;

    // Build query
    const query = {};
    
    if (search) {
      query.$or = [
        { filename: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } }
      ];
    }

    if (owner) {
      query.owner = owner;
    }

    if (isPublic !== undefined) {
      query.isPublic = isPublic === 'true';
    }

    // Calculate pagination
    const skip = (page - 1) * limit;

    // Get files with pagination
    const files = await File.find(query)
      .populate('owner', 'username email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
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
});

// Get system statistics
router.get('/stats', async (req, res, next) => {
  try {
    // Get user statistics
    const totalUsers = await User.countDocuments();
    const activeUsers = await User.countDocuments({ isActive: true });
    const adminUsers = await User.countDocuments({ role: 'admin' });

    // Get file statistics
    const fileStats = await File.getStats();
    const totalFiles = await File.countDocuments();
    const publicFiles = await File.countDocuments({ isPublic: true });
    const totalDownloads = await File.aggregate([
      { $group: { _id: null, total: { $sum: '$downloadCount' } } }
    ]);

    // Get recent activity (last 24 hours)
    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const recentUsers = await User.countDocuments({ createdAt: { $gte: oneDayAgo } });
    const recentFiles = await File.countDocuments({ createdAt: { $gte: oneDayAgo } });

    // Get top file types
    const topFileTypes = await File.aggregate([
      {
        $group: {
          _id: '$mimetype',
          count: { $sum: 1 },
          totalSize: { $sum: '$size' }
        }
      },
      { $sort: { count: -1 } },
      { $limit: 10 }
    ]);

    res.json({
      success: true,
      data: {
        users: {
          total: totalUsers,
          active: activeUsers,
          inactive: totalUsers - activeUsers,
          admins: adminUsers,
          recent: recentUsers
        },
        files: {
          total: totalFiles,
          public: publicFiles,
          private: totalFiles - publicFiles,
          recent: recentFiles,
          totalSize: fileStats.totalSize,
          totalDownloads: totalDownloads[0]?.total || 0,
          averageSize: fileStats.averageSize
        },
        fileTypes: topFileTypes
      }
    });
  } catch (error) {
    next(error);
  }
});

// Get activity logs (basic implementation)
router.get('/logs', async (req, res, next) => {
  try {
    // This is a basic implementation
    // In a production system, you'd want to use a proper logging solution
    const logs = [
      {
        timestamp: new Date().toISOString(),
        level: 'info',
        message: 'Admin panel accessed',
        user: req.user.username,
        ip: req.ip
      }
    ];

    res.json({
      success: true,
      data: { logs }
    });
  } catch (error) {
    next(error);
  }
});

module.exports = router;
