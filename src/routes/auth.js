const express = require('express');
const router = express.Router();
const Joi = require('joi');
const authController = require('../controllers/authController');
const { authenticateToken, refreshToken, logout } = require('../middleware/auth');
const { validate, schemas } = require('../middleware/validation');
const { sanitizeInput } = require('../middleware/validation');
const { authLimiter } = require('../middleware/security');

// Apply rate limiting and input sanitization to all auth routes
router.use(authLimiter);
router.use(sanitizeInput);

// Public routes (no authentication required)
router.post('/register', 
  validate(schemas.register),
  authController.register
);

router.post('/login', 
  validate(schemas.login),
  authController.login
);

// Token management routes
router.post('/refresh', refreshToken);
router.post('/logout', authenticateToken, logout);

// Protected routes (authentication required)
router.get('/profile', 
  authenticateToken,
  authController.getProfile
);

router.put('/profile', 
  authenticateToken,
  validate(schemas.profileUpdate),
  authController.updateProfile
);

router.put('/change-password', 
  authenticateToken,
  validate(schemas.passwordChange),
  authController.changePassword
);

router.get('/stats', 
  authenticateToken,
  authController.getUserStats
);

router.delete('/account', 
  authenticateToken,
  validate(Joi.object({ currentPassword: Joi.string().required() })),
  authController.deleteAccount
);

module.exports = router;
