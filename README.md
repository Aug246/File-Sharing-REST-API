# 🔒 Secure File-Sharing REST API

A robust, secure file-sharing REST API built with Express.js and MongoDB, featuring comprehensive security measures, role-based access control, and advanced file management capabilities.

## ✨ Features

### 🔐 Security Features
- **JWT Authentication** with access and refresh tokens
- **Role-based Access Control** (User/Admin roles)
- **Rate Limiting** to prevent abuse
- **Input Validation & Sanitization** using Joi
- **File Type Validation** with whitelist approach
- **Account Lockout** after failed login attempts
- **Security Headers** with Helmet.js
- **CORS Protection** with configurable origins
- **File Integrity** verification with checksums

### 📁 File Management
- **Secure File Upload** with randomized filenames
- **File Metadata** storage and management
- **Public/Private** file sharing options
- **Download Tracking** and analytics
- **File Search & Filtering** capabilities
- **Bulk Operations** support
- **File Size & Type** restrictions

### 👥 User Management
- **User Registration & Authentication**
- **Profile Management** with validation
- **Password Change** functionality
- **Account Deletion** with cleanup
- **Admin Panel** for user management
- **Activity Logging** and monitoring

### 🛡️ Advanced Security
- **OWASP Top 10** compliance considerations
- **SQL Injection** prevention
- **XSS Protection** with input sanitization
- **CSRF Protection** ready
- **Directory Traversal** prevention
- **Malicious File** detection patterns

## 🚀 Quick Start

### Prerequisites
- Node.js (v14 or higher)
- MongoDB (v4.4 or higher)
- npm or yarn

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/Aug246/File-Sharing-REST-API.git
   cd File-Sharing-REST-API
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Environment Setup**
   ```bash
   cp config.example.env .env
   ```
   
   Edit `.env` file with your configuration:
   ```env
   # Server Configuration
   PORT=3000
   NODE_ENV=development

   # Database Configuration
   MONGODB_URI=mongodb://localhost:27017/file-sharing-api

   # JWT Configuration
   JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
   JWT_REFRESH_SECRET=your-super-secret-refresh-key-change-this-in-production

   # File Upload Configuration
   MAX_FILE_SIZE=10485760
   ALLOWED_FILE_TYPES=pdf,docx,jpeg,jpg,png,gif,txt
   ```

4. **Start MongoDB**
   ```bash
   # Using MongoDB service
   sudo systemctl start mongod
   
   # Or using Docker
   docker run -d -p 27017:27017 --name mongodb mongo:latest
   ```

5. **Run the application**
   ```bash
   # Development mode
   npm run dev
   
   # Production mode
   npm start
   ```

## 📚 API Documentation

### Base URL
```
http://localhost:3000/api
```

### Authentication Endpoints

#### Register User
```http
POST /api/auth/register
Content-Type: application/json

{
  "username": "johndoe",
  "email": "john@example.com",
  "password": "SecurePass123!"
}
```

#### Login
```http
POST /api/auth/login
Content-Type: application/json

{
  "usernameOrEmail": "johndoe",
  "password": "SecurePass123!"
}
```

#### Refresh Token
```http
POST /api/auth/refresh
Content-Type: application/json

{
  "refreshToken": "your-refresh-token"
}
```

#### Logout
```http
POST /api/auth/logout
Authorization: Bearer your-access-token
Content-Type: application/json

{
  "refreshToken": "your-refresh-token"
}
```

### File Management Endpoints

#### Upload File
```http
POST /api/files/upload
Authorization: Bearer your-access-token
Content-Type: multipart/form-data

file: [file]
description: "File description"
tags: "tag1,tag2,tag3"
isPublic: false
```

#### Get User Files
```http
GET /api/files/my-files?page=1&limit=10&search=document
Authorization: Bearer your-access-token
```

#### Get Public Files
```http
GET /api/files/public?page=1&limit=20&tag=pdf
```

#### Download File
```http
GET /api/files/:fileId/download
Authorization: Bearer your-access-token
```

#### Update File Metadata
```http
PUT /api/files/:fileId
Authorization: Bearer your-access-token
Content-Type: application/json

{
  "description": "Updated description",
  "tags": "updated,tags",
  "isPublic": true
}
```

#### Delete File
```http
DELETE /api/files/:fileId
Authorization: Bearer your-access-token
```

### Admin Endpoints

#### Get All Users
```http
GET /api/admin/users?page=1&limit=20&search=john
Authorization: Bearer admin-access-token
```

#### Update User Status
```http
PUT /api/admin/users/:userId/status
Authorization: Bearer admin-access-token
Content-Type: application/json

{
  "isActive": false
}
```

#### Get System Statistics
```http
GET /api/admin/stats
Authorization: Bearer admin-access-token
```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | 3000 |
| `NODE_ENV` | Environment | development |
| `MONGODB_URI` | MongoDB connection string | mongodb://localhost:27017/file-sharing-api |
| `JWT_SECRET` | JWT signing secret | - |
| `JWT_REFRESH_SECRET` | JWT refresh secret | - |
| `JWT_EXPIRES_IN` | Access token expiry | 15m |
| `JWT_REFRESH_EXPIRES_IN` | Refresh token expiry | 7d |
| `MAX_FILE_SIZE` | Maximum file size in bytes | 10485760 (10MB) |
| `ALLOWED_FILE_TYPES` | Comma-separated allowed extensions | pdf,docx,jpeg,jpg,png,gif,txt |
| `BCRYPT_ROUNDS` | Password hashing rounds | 12 |
| `RATE_LIMIT_WINDOW_MS` | Rate limit window | 900000 (15 min) |
| `RATE_LIMIT_MAX_REQUESTS` | Max requests per window | 100 |
| `MAX_LOGIN_ATTEMPTS` | Max failed login attempts | 5 |
| `LOCKOUT_TIME_MS` | Account lockout duration | 1800000 (30 min) |

## 🛡️ Security Considerations

### Implemented Security Measures

1. **Authentication & Authorization**
   - JWT-based authentication
   - Role-based access control
   - Account lockout mechanism
   - Secure password requirements

2. **Input Validation**
   - Joi schema validation
   - Input sanitization
   - File type validation
   - Size restrictions

3. **Rate Limiting**
   - General API rate limiting
   - Stricter auth endpoint limits
   - Upload-specific rate limiting

4. **File Security**
   - Randomized filenames
   - File type whitelisting
   - Checksum verification
   - Secure file storage

5. **HTTP Security**
   - Helmet.js security headers
   - CORS configuration
   - XSS protection
   - Content type validation

### Security Best Practices

1. **Environment Variables**
   - Never commit `.env` files
   - Use strong, unique secrets
   - Rotate secrets regularly

2. **Database Security**
   - Use MongoDB authentication
   - Enable SSL/TLS connections
   - Regular backups

3. **File Storage**
   - Store files outside web root
   - Regular file integrity checks
   - Consider virus scanning integration

4. **Monitoring**
   - Log security events
   - Monitor failed login attempts
   - Track file access patterns

## 🧪 Testing

### Manual Testing Checklist

1. **Authentication Tests**
   - [ ] User registration with valid data
   - [ ] User registration with invalid data
   - [ ] Login with correct credentials
   - [ ] Login with incorrect credentials
   - [ ] Account lockout after failed attempts
   - [ ] Token refresh functionality
   - [ ] Logout functionality

2. **File Upload Tests**
   - [ ] Upload valid file types
   - [ ] Reject invalid file types
   - [ ] Respect file size limits
   - [ ] Handle duplicate filenames
   - [ ] Metadata validation

3. **Access Control Tests**
   - [ ] Users can only access their files
   - [ ] Public files accessible to all
   - [ ] Admin access to all resources
   - [ ] Proper error messages for unauthorized access

4. **Security Tests**
   - [ ] Rate limiting functionality
   - [ ] Input validation and sanitization
   - [ ] XSS prevention
   - [ ] File type validation
   - [ ] Directory traversal prevention

## 🚀 Deployment

### Docker Deployment

1. **Create Dockerfile**
   ```dockerfile
   FROM node:18-alpine
   WORKDIR /app
   COPY package*.json ./
   RUN npm ci --only=production
   COPY . .
   EXPOSE 3000
   CMD ["npm", "start"]
   ```

2. **Create docker-compose.yml**
   ```yaml
   version: '3.8'
   services:
     app:
       build: .
       ports:
         - "3000:3000"
       environment:
         - MONGODB_URI=mongodb://mongo:27017/file-sharing-api
       depends_on:
         - mongo
     
     mongo:
       image: mongo:latest
       ports:
         - "27017:27017"
       volumes:
         - mongo_data:/data/db
   
   volumes:
     mongo_data:
   ```

3. **Deploy**
   ```bash
   docker-compose up -d
   ```

### Production Considerations

1. **Environment Setup**
   - Use production MongoDB cluster
   - Enable SSL/TLS
   - Set up proper logging
   - Configure monitoring

2. **Security Hardening**
   - Use strong secrets
   - Enable MongoDB authentication
   - Set up firewall rules
   - Regular security updates

3. **Performance Optimization**
   - Enable MongoDB indexes
   - Use CDN for static files
   - Implement caching
   - Monitor performance metrics

## 📝 License

This project is licensed under the ISC License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📞 Support

If you have any questions or need help, please:
- Open an issue on GitHub
- Check the documentation
- Review the code comments

## 🔮 Future Enhancements

- [ ] Virus scanning integration
- [ ] File encryption at rest
- [ ] Advanced file sharing (time-limited links)
- [ ] File versioning
- [ ] Advanced analytics dashboard
- [ ] Webhook support
- [ ] Multi-tenant support
- [ ] API versioning
- [ ] GraphQL endpoint
- [ ] Mobile app support

---

**⚠️ Security Notice**: This is a demonstration project. For production use, ensure you:
- Use strong, unique secrets
- Enable all security features
- Regularly update dependencies
- Conduct security audits
- Monitor for vulnerabilities