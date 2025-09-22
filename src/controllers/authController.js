const User = require('../models/User');
const { generateTokens } = require('../middleware/auth');

// Register a new user
const register = async (req, res, next) => {
  try {
    const { username, email, password } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({
      $or: [{ username }, { email }]
    });

    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: existingUser.username === username ? 
          'Username already exists' : 'Email already exists'
      });
    }

    // Create new user
    const user = new User({
      username,
      email,
      password
    });

    await user.save();

    // Generate tokens
    const tokens = generateTokens(user);
    await user.addRefreshToken(tokens.refreshToken);

    // Log successful registration
    console.log(`New user registered: ${username} (${email})`);

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      data: {
        user: user.toJSON(),
        ...tokens
      }
    });
  } catch (error) {
    next(error);
  }
};

// Login user
const login = async (req, res, next) => {
  try {
    const { usernameOrEmail, password } = req.body;
    const clientIP = req.ip;
    const userAgent = req.get('User-Agent');

    // Find user and validate credentials
    const user = await User.findByCredentials(usernameOrEmail, password);

    // Update last login information
    user.lastLogin = new Date();
    user.lastLoginIP = clientIP;
    await user.save();

    // Generate tokens
    const tokens = generateTokens(user);
    await user.addRefreshToken(tokens.refreshToken);

    // Log successful login
    console.log(`User logged in: ${user.username} from IP: ${clientIP}`);

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        user: user.toJSON(),
        ...tokens
      }
    });
  } catch (error) {
    // Log failed login attempt
    console.warn(`Failed login attempt for: ${req.body.usernameOrEmail} from IP: ${req.ip}`);
    
    if (error.message === 'Invalid credentials' || error.message.includes('locked')) {
      return res.status(401).json({
        success: false,
        message: error.message
      });
    }
    
    next(error);
  }
};

// Get current user profile
const getProfile = async (req, res, next) => {
  try {
    const user = await User.findById(req.user._id);
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      data: {
        user: user.toJSON()
      }
    });
  } catch (error) {
    next(error);
  }
};

// Update user profile
const updateProfile = async (req, res, next) => {
  try {
    const { username, email } = req.body;
    const userId = req.user._id;

    // Check if username or email is already taken by another user
    if (username || email) {
      const existingUser = await User.findOne({
        _id: { $ne: userId },
        $or: [
          ...(username ? [{ username }] : []),
          ...(email ? [{ email }] : [])
        ]
      });

      if (existingUser) {
        return res.status(409).json({
          success: false,
          message: existingUser.username === username ? 
            'Username already exists' : 'Email already exists'
        });
      }
    }

    // Update user
    const updateData = {};
    if (username) updateData.username = username;
    if (email) updateData.email = email;

    const user = await User.findByIdAndUpdate(
      userId,
      updateData,
      { new: true, runValidators: true }
    );

    res.json({
      success: true,
      message: 'Profile updated successfully',
      data: {
        user: user.toJSON()
      }
    });
  } catch (error) {
    next(error);
  }
};

// Change password
const changePassword = async (req, res, next) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const userId = req.user._id;

    // Get user with password field
    const user = await User.findById(userId).select('+password');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Verify current password
    const isCurrentPasswordValid = await user.comparePassword(currentPassword);
    if (!isCurrentPasswordValid) {
      return res.status(400).json({
        success: false,
        message: 'Current password is incorrect'
      });
    }

    // Update password
    user.password = newPassword;
    await user.save();

    // Log password change
    console.log(`Password changed for user: ${user.username}`);

    res.json({
      success: true,
      message: 'Password changed successfully'
    });
  } catch (error) {
    next(error);
  }
};

// Get user statistics
const getUserStats = async (req, res, next) => {
  try {
    const userId = req.user._id;
    
    // Get user with additional info
    const user = await User.findById(userId);
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Get file statistics (we'll implement this in fileController)
    const File = require('../models/File');
    const fileStats = await File.getStats(userId);

    const stats = {
      user: {
        username: user.username,
        email: user.email,
        role: user.role,
        createdAt: user.createdAt,
        lastLogin: user.lastLogin,
        lastLoginIP: user.lastLoginIP
      },
      files: fileStats
    };

    res.json({
      success: true,
      data: stats
    });
  } catch (error) {
    next(error);
  }
};

// Delete user account
const deleteAccount = async (req, res, next) => {
  try {
    const userId = req.user._id;
    const { password } = req.body;

    // Verify password before deletion
    const user = await User.findById(userId).select('+password');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      return res.status(400).json({
        success: false,
        message: 'Password is incorrect'
      });
    }

    // Delete user's files first (we'll implement this in fileController)
    const File = require('../models/File');
    const userFiles = await File.find({ owner: userId });
    
    // Delete physical files (we'll implement file deletion utility)
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

    // Log account deletion
    console.log(`User account deleted: ${user.username} (${user.email})`);

    res.json({
      success: true,
      message: 'Account deleted successfully'
    });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  register,
  login,
  getProfile,
  updateProfile,
  changePassword,
  getUserStats,
  deleteAccount
};
