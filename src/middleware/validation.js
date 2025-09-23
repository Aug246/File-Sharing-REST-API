const Joi = require('joi');

// Validation schemas
const schemas = {
  // User registration validation
  register: Joi.object({
    username: Joi.string()
      .pattern(/^[a-zA-Z0-9_-]+$/)
      .min(3)
      .max(30)
      .required()
      .messages({
        'string.pattern.base': 'Username can only contain letters, numbers, underscores, and hyphens',
        'string.min': 'Username must be at least 3 characters long',
        'string.max': 'Username cannot exceed 30 characters',
        'any.required': 'Username is required'
      }),
    email: Joi.string()
      .email()
      .required()
      .messages({
        'string.email': 'Please provide a valid email address',
        'any.required': 'Email is required'
      }),
    password: Joi.string()
      .min(8)
      .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
      .required()
      .messages({
        'string.min': 'Password must be at least 8 characters long',
        'string.pattern.base': 'Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character',
        'any.required': 'Password is required'
      })
  }),

  // User login validation
  login: Joi.object({
    usernameOrEmail: Joi.string()
      .required()
      .messages({
        'any.required': 'Username or email is required'
      }),
    password: Joi.string()
      .required()
      .messages({
        'any.required': 'Password is required'
      })
  }),

  // File upload validation
  fileUpload: Joi.object({
    description: Joi.string()
      .max(500)
      .optional()
      .messages({
        'string.max': 'Description cannot exceed 500 characters'
      }),
    tags: Joi.alternatives()
      .try(
        Joi.array()
          .items(Joi.string().trim().max(50))
          .max(10),
        Joi.string()
          .max(500)
          .custom((value, helpers) => {
            // Convert comma-separated string to array for validation
            const tags = value.split(',').map(tag => tag.trim()).filter(tag => tag.length > 0);
            if (tags.length > 10) {
              return helpers.error('custom.maxTags');
            }
            if (tags.some(tag => tag.length > 50)) {
              return helpers.error('custom.tagTooLong');
            }
            return tags;
          })
      )
      .optional()
      .messages({
        'custom.maxTags': 'Maximum 10 tags allowed',
        'custom.tagTooLong': 'Each tag cannot exceed 50 characters',
        'string.max': 'Tags string too long'
      }),
    isPublic: Joi.boolean()
      .optional()
  }),

  // File update validation
  fileUpdate: Joi.object({
    description: Joi.string()
      .max(500)
      .optional()
      .messages({
        'string.max': 'Description cannot exceed 500 characters'
      }),
    tags: Joi.alternatives()
      .try(
        Joi.array()
          .items(Joi.string().trim().max(50))
          .max(10),
        Joi.string()
          .max(500)
          .custom((value, helpers) => {
            // Convert comma-separated string to array for validation
            const tags = value.split(',').map(tag => tag.trim()).filter(tag => tag.length > 0);
            if (tags.length > 10) {
              return helpers.error('custom.maxTags');
            }
            if (tags.some(tag => tag.length > 50)) {
              return helpers.error('custom.tagTooLong');
            }
            return tags;
          })
      )
      .optional()
      .messages({
        'custom.maxTags': 'Maximum 10 tags allowed',
        'custom.tagTooLong': 'Each tag cannot exceed 50 characters',
        'string.max': 'Tags string too long'
      }),
    isPublic: Joi.boolean()
      .optional()
  }),

  // User profile update validation
  profileUpdate: Joi.object({
    username: Joi.string()
      .pattern(/^[a-zA-Z0-9_-]+$/)
      .min(3)
      .max(30)
      .optional()
      .messages({
        'string.pattern.base': 'Username can only contain letters, numbers, underscores, and hyphens',
        'string.min': 'Username must be at least 3 characters long',
        'string.max': 'Username cannot exceed 30 characters'
      }),
    email: Joi.string()
      .email()
      .optional()
      .messages({
        'string.email': 'Please provide a valid email address'
      })
  }),

  // Password change validation
  passwordChange: Joi.object({
    currentPassword: Joi.string()
      .required()
      .messages({
        'any.required': 'Current password is required'
      }),
    newPassword: Joi.string()
      .min(8)
      .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
      .required()
      .messages({
        'string.min': 'Password must be at least 8 characters long',
        'string.pattern.base': 'Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character',
        'any.required': 'New password is required'
      })
  })
};

// Validation middleware factory
const validate = (schema) => {
  return (req, res, next) => {
    const { error, value } = schema.validate(req.body, {
      abortEarly: false,
      stripUnknown: true
    });

    if (error) {
      const errorMessages = error.details.map(detail => ({
        field: detail.path.join('.'),
        message: detail.message
      }));

      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errorMessages
      });
    }

    // Replace req.body with validated and sanitized data
    req.body = value;
    next();
  };
};

// Sanitize input middleware
const sanitizeInput = (req, res, next) => {
  // Remove any potential XSS attempts
  const sanitizeString = (str) => {
    if (typeof str !== 'string') return str;
    
    return str
      .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '') // Remove script tags
      .replace(/javascript:/gi, '') // Remove javascript: protocol
      .replace(/on\w+\s*=/gi, '') // Remove event handlers
      .trim();
  };

  const sanitizeObject = (obj) => {
    if (typeof obj !== 'object' || obj === null) return obj;
    
    const sanitized = {};
    for (const [key, value] of Object.entries(obj)) {
      if (typeof value === 'string') {
        sanitized[key] = sanitizeString(value);
      } else if (typeof value === 'object') {
        sanitized[key] = sanitizeObject(value);
      } else {
        sanitized[key] = value;
      }
    }
    return sanitized;
  };

  req.body = sanitizeObject(req.body);
  req.query = sanitizeObject(req.query);
  req.params = sanitizeObject(req.params);

  next();
};

// File validation middleware
const validateFile = (req, res, next) => {
  if (!req.file) {
    return res.status(400).json({
      success: false,
      message: 'No file uploaded'
    });
  }

  const allowedTypes = process.env.ALLOWED_FILE_TYPES ? 
    process.env.ALLOWED_FILE_TYPES.split(',').map(type => type.trim()) : 
    ['pdf', 'docx', 'jpeg', 'jpg', 'png', 'gif', 'txt'];

  const maxSize = parseInt(process.env.MAX_FILE_SIZE) || 10 * 1024 * 1024; // 10MB default

  // Check file size
  if (req.file.size > maxSize) {
    return res.status(400).json({
      success: false,
      message: `File size exceeds maximum allowed size of ${Math.round(maxSize / (1024 * 1024))}MB`
    });
  }

  // Check file type
  const fileExtension = req.file.originalname.split('.').pop().toLowerCase();
  if (!allowedTypes.includes(fileExtension)) {
    return res.status(400).json({
      success: false,
      message: `File type .${fileExtension} is not allowed. Allowed types: ${allowedTypes.join(', ')}`
    });
  }

  // Check for suspicious file names
  const suspiciousPatterns = [
    /\.\./, // Directory traversal
    /[<>:"|?*]/, // Invalid characters
    /^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$/i, // Reserved names
    /\.(exe|bat|cmd|scr|com|pif)$/i // Executable extensions
  ];

  const isSuspicious = suspiciousPatterns.some(pattern => pattern.test(req.file.originalname));
  if (isSuspicious) {
    return res.status(400).json({
      success: false,
      message: 'File name contains suspicious patterns'
    });
  }

  next();
};

module.exports = {
  schemas,
  validate,
  sanitizeInput,
  validateFile
};
