# Secure File-Sharing REST API

A robust, secure file-sharing REST API built with Express.js and MongoDB, featuring comprehensive security measures, role-based access control, and advanced file management capabilities.

## Features

### Security Features
- **JWT Authentication** with access and refresh tokens
- **Role-based Access Control** (User/Admin roles)
- **Rate Limiting** to prevent abuse
- **Input Validation & Sanitization** using Joi
- **File Type Validation** with whitelist approach
- **Account Lockout** after failed login attempts
- **Security Headers** with Helmet.js
- **CORS Protection** with configurable origins
- **File Integrity** verification with checksums

### File Management
- **Secure File Upload** with randomized filenames
- **File Metadata** storage and management
- **Public/Private** file sharing options
- **Download Tracking** and analytics
- **File Search & Filtering** capabilities
- **Bulk Operations** support
- **File Size & Type** restrictions

### User Management
- **User Registration & Authentication**
- **Profile Management** with validation
- **Password Change** functionality
- **Account Deletion** with cleanup
- **Admin Panel** for user management
- **Activity Logging** and monitoring

### Advanced Security
- **OWASP Top 10** compliance considerations
- **SQL Injection** prevention
- **XSS Protection** with input sanitization
- **CSRF Protection** ready
- **Directory Traversal** prevention
- **Malicious File** detection patterns

## Quick Start

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

## API Documentation

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

**Terminal Command:**
```bash
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "johndoe",
    "email": "john@example.com",
    "password": "SecurePass123!"
  }' | jq .
```

**Expected Output:**
```json
{
  "success": true,
  "message": "User registered successfully",
  "data": {
    "user": {
      "_id": "68d1e8d1e2a12c8ff3d0aa4b",
      "username": "johndoe",
      "email": "john@example.com",
      "role": "user",
      "isActive": true,
      "createdAt": "2025-09-23T00:24:49.830Z"
    },
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
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

**Terminal Command:**
```bash
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "usernameOrEmail": "johndoe",
    "password": "SecurePass123!"
  }' | jq .
```

**Expected Output:**
```json
{
  "success": true,
  "message": "Login successful",
  "data": {
    "user": {
      "_id": "68d1e8d1e2a12c8ff3d0aa4b",
      "username": "johndoe",
      "email": "john@example.com",
      "role": "user",
      "isActive": true
    },
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
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

**Terminal Command:**
```bash
curl -X POST http://localhost:3000/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "your-refresh-token"
  }' | jq .
```

**Expected Output:**
```json
{
  "success": true,
  "data": {
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
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

**Terminal Command:**
```bash
curl -X POST http://localhost:3000/api/auth/logout \
  -H "Authorization: Bearer your-access-token" \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "your-refresh-token"
  }' | jq .
```

**Expected Output:**
```json
{
  "success": true,
  "message": "Logged out successfully"
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

**Terminal Command:**
```bash
# Create a test file first
echo "This is a test file content" > test-file.txt

# Upload file
curl -X POST http://localhost:3000/api/files/upload \
  -H "Authorization: Bearer your-access-token" \
  -F "file=@test-file.txt" \
  -F "description=File description" \
  -F "tags=tag1,tag2,tag3" \
  -F "isPublic=false" | jq .
```

**Expected Output:**
```json
{
  "success": true,
  "message": "File uploaded successfully",
  "data": {
    "file": {
      "_id": "68d1ea7ddc1b331d096ec97d",
      "filename": "test-file.txt",
      "storedFilename": "1758587517391_i6m8wt26zl.txt",
      "mimetype": "text/plain",
      "size": 28,
      "owner": {
        "_id": "68d1e8d1e2a12c8ff3d0aa4b",
        "username": "johndoe",
        "email": "john@example.com"
      },
      "description": "File description",
      "isPublic": false,
      "downloadCount": 0,
      "tags": ["tag1", "tag2", "tag3"],
      "metadata": {
        "uploadIP": "::1",
        "userAgent": "curl/8.7.1",
        "checksum": "d9192aa31791250d7e77c32c19231c3e465855cd2ce4ba5e4d2d94050d390834"
      },
      "createdAt": "2025-09-23T00:31:57.396Z",
      "updatedAt": "2025-09-23T00:31:57.396Z"
    }
  }
}
```

#### Get User Files
```http
GET /api/files/my-files?page=1&limit=10&search=test&tag=tag1
Authorization: Bearer your-access-token
```

**Query Parameters:**
- `page`: Page number (default: 1)
- `limit`: Items per page (default: 10)
- `search`: Search in filename and description (optional)
- `tag`: Search by specific tag (optional)
- `sortBy`: Sort field (default: createdAt)
- `sortOrder`: Sort order - asc or desc (default: desc)

**Terminal Commands:**
```bash
# Get all user files
curl -X GET "http://localhost:3000/api/files/my-files?page=1&limit=10" \
  -H "Authorization: Bearer your-access-token" | jq .

# Search by filename or description
curl -X GET "http://localhost:3000/api/files/my-files?page=1&limit=10&search=test" \
  -H "Authorization: Bearer your-access-token" | jq .

# Search by tag
curl -X GET "http://localhost:3000/api/files/my-files?page=1&limit=10&tag=tag1" \
  -H "Authorization: Bearer your-access-token" | jq .
```

**Expected Output:**
```json
{
  "success": true,
  "data": {
    "files": [
      {
        "_id": "68d1ea7ddc1b331d096ec97d",
        "filename": "test-file.txt",
        "storedFilename": "1758587517391_i6m8wt26zl.txt",
        "mimetype": "text/plain",
        "size": 28,
        "owner": {
          "_id": "68d1e8d1e2a12c8ff3d0aa4b",
          "username": "johndoe",
          "email": "john@example.com"
        },
        "description": "File description",
        "isPublic": false,
        "downloadCount": 0,
        "tags": ["tag1", "tag2", "tag3"],
        "createdAt": "2025-09-23T00:31:57.396Z",
        "updatedAt": "2025-09-23T00:31:57.396Z"
      }
    ],
    "pagination": {
      "currentPage": 1,
      "totalPages": 1,
      "totalFiles": 1,
      "hasNextPage": false,
      "hasPrevPage": false
    }
  }
}
```

#### Get Public Files
```http
GET /api/files/public?page=1&limit=20&search=document&tag=pdf
```

**Query Parameters:**
- `page`: Page number (default: 1)
- `limit`: Items per page (default: 20)
- `search`: Search in filename and description (optional)
- `tag`: Search by specific tag (optional)
- `sortBy`: Sort field (default: createdAt)
- `sortOrder`: Sort order - asc or desc (default: desc)

**Terminal Commands:**
```bash
# Get all public files
curl -X GET "http://localhost:3000/api/files/public?page=1&limit=20" | jq .

# Search public files by filename or description
curl -X GET "http://localhost:3000/api/files/public?page=1&limit=20&search=document" | jq .

# Search public files by tag
curl -X GET "http://localhost:3000/api/files/public?page=1&limit=20&tag=pdf" | jq .
```

**Expected Output:**
```json
{
  "success": true,
  "data": {
    "files": [
      {
        "_id": "68d1ea7ddc1b331d096ec97d",
        "filename": "document.pdf",
        "storedFilename": "1758587517391_document.pdf",
        "mimetype": "application/pdf",
        "size": 1024,
        "owner": {
          "_id": "68d1e8d1e2a12c8ff3d0aa4b",
          "username": "johndoe",
          "email": "john@example.com"
        },
        "description": "Public document",
        "isPublic": true,
        "downloadCount": 5,
        "tags": ["pdf", "document", "public"],
        "createdAt": "2025-09-23T00:31:57.396Z",
        "updatedAt": "2025-09-23T00:31:57.396Z"
      }
    ],
    "pagination": {
      "currentPage": 1,
      "totalPages": 1,
      "totalFiles": 1,
      "hasNextPage": false,
      "hasPrevPage": false
    }
  }
}
```

#### Download File
```http
GET /api/files/:fileId/download
Authorization: Bearer your-access-token
```

**Terminal Command:**
```bash
curl -X GET http://localhost:3000/api/files/FILE_ID/download \
  -H "Authorization: Bearer your-access-token" \
  -o downloaded-file.txt

# Check download status (optional)
echo "Download completed. File saved as downloaded-file.txt"
ls -la downloaded-file.txt
```

**Expected Output:**
```bash
Download completed. File saved as downloaded-file.txt
-rw-r--r--  1 user  staff  28 Sep 23 00:54 downloaded-file.txt
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

**Terminal Command:**
```bash
curl -X PUT http://localhost:3000/api/files/FILE_ID \
  -H "Authorization: Bearer your-access-token" \
  -H "Content-Type: application/json" \
  -d '{
    "description": "Updated description",
    "tags": "updated,tags",
    "isPublic": true
  }' | jq .
```

**Expected Output:**
```json
{
  "success": true,
  "message": "File updated successfully",
  "data": {
    "file": {
      "_id": "68d1ea7ddc1b331d096ec97d",
      "filename": "test-file.txt",
      "description": "Updated description",
      "isPublic": true,
      "tags": ["updated", "tags"],
      "updatedAt": "2025-09-23T00:45:12.123Z"
    }
  }
}
```

#### Delete File
```http
DELETE /api/files/:fileId
Authorization: Bearer your-access-token
```

**Terminal Command:**
```bash
curl -X DELETE http://localhost:3000/api/files/FILE_ID \
  -H "Authorization: Bearer your-access-token" | jq .
```

**Expected Output:**
```json
{
  "success": true,
  "message": "File deleted successfully"
}
```

### Admin Endpoints

> **Note:** All admin endpoints require admin role authentication. First, you need to create an admin user or promote an existing user to admin role.

#### Create Admin User (Database Method)
To create your first admin user, run this Node.js script:

```bash
node -e "
const mongoose = require('mongoose');
require('dotenv').config();

async function makeAdmin() {
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('Connected to MongoDB');
    
    const User = require('./src/models/User');
    const user = await User.findOneAndUpdate(
      { username: 'johndoe' },
      { role: 'admin' },
      { new: true }
    );
    
    if (user) {
      console.log('✅ Successfully promoted johndoe to admin!');
      console.log('User:', { username: user.username, email: user.email, role: user.role });
    } else {
      console.log('❌ User not found');
    }
    
    await mongoose.disconnect();
  } catch (error) {
    console.error('Error:', error.message);
    process.exit(1);
  }
}

makeAdmin();
"
```

#### Get All Users
```http
GET /api/admin/users?page=1&limit=20&search=john&role=user&isActive=true
Authorization: Bearer admin-access-token
```

**Query Parameters:**
- `page` (optional): Page number for pagination (default: 1)
- `limit` (optional): Number of users per page (default: 20)
- `search` (optional): Search by username or email
- `role` (optional): Filter by role (`user` or `admin`)
- `isActive` (optional): Filter by active status (`true` or `false`)

**Terminal Command:**
```bash
curl -X GET "http://localhost:3000/api/admin/users?page=1&limit=20" \
  -H "Authorization: Bearer ADMIN_TOKEN" | jq .
```

**Expected Output:**
```json
{
  "success": true,
  "data": {
    "users": [
      {
        "_id": "68d2c19972b14b75635218ea",
        "username": "aug",
        "email": "aug@example.com",
        "role": "user",
        "isActive": true,
        "loginAttempts": 0,
        "createdAt": "2025-09-23T15:49:45.167Z",
        "updatedAt": "2025-09-23T15:49:45.454Z"
      },
      {
        "_id": "68d1e8d1e2a12c8ff3d0aa4b",
        "username": "johndoe",
        "email": "john@example.com",
        "role": "admin",
        "isActive": true,
        "loginAttempts": 0,
        "createdAt": "2025-09-23T00:24:49.503Z",
        "lastLogin": "2025-09-23T15:48:02.340Z"
      },
      {
        "_id": "68d1e19ee4a0fcc1e5459bef",
        "username": "example",
        "email": "example@example.com",
        "role": "user",
        "isActive": true,
        "createdAt": "2025-09-22T23:54:06.523Z",
        "lastLogin": "2025-09-22T23:55:33.412Z"
      }
    ],
    "pagination": {
      "currentPage": 1,
      "totalPages": 1,
      "totalUsers": 3,
      "hasNextPage": false,
      "hasPrevPage": false
    }
  }
}
```

#### Get User Details
```http
GET /api/admin/users/:userId
Authorization: Bearer admin-access-token
```

**Terminal Command:**
```bash
curl -X GET "http://localhost:3000/api/admin/users/68d2c19972b14b75635218ea" \
  -H "Authorization: Bearer ADMIN_TOKEN" | jq .
```

**Expected Output:**
```json
{
  "success": true,
  "data": {
    "user": {
      "_id": "68d1e8d1e2a12c8ff3d0aa4b",
      "username": "johndoe",
      "email": "john@example.com",
      "role": "admin",
      "isActive": true,
      "loginAttempts": 0,
      "createdAt": "2025-09-23T00:24:49.503Z",
      "updatedAt": "2025-09-23T15:48:02.400Z",
      "lastLogin": "2025-09-23T15:48:02.340Z",
      "lastLoginIP": "::1"
    },
  }
}
```

#### Update User Role
```http
PUT /api/admin/users/:userId/role
Authorization: Bearer admin-access-token
Content-Type: application/json

{
  "role": "admin"
}
```

**Terminal Command:**
```bash
curl -X PUT "http://localhost:3000/api/admin/users/68d2c19972b14b75635218ea/role" \
  -H "Authorization: Bearer ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role": "admin"}' | jq .
```

**Expected Output:**
```json
{
  "success": true,
  "message": "User role updated successfully",
  "data": {
    "user": {
      "_id": "68d2c19972b14b75635218ea",
      "username": "aug",
      "email": "aug@example.com",
      "role": "admin",
      "isActive": true,
      "updatedAt": "2025-09-23T15:55:12.123Z"
    }
  }
}
```

#### Update User Status (Activate/Deactivate)
```http
PUT /api/admin/users/:userId/status
Authorization: Bearer admin-access-token
Content-Type: application/json

{
  "isActive": false
}
```

**Terminal Command:**
```bash
curl -X PUT "http://localhost:3000/api/admin/users/68d2c19972b14b75635218ea/status" \
  -H "Authorization: Bearer ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"isActive": false}' | jq .
```

**Expected Output:**
```json
{
  "success": true,
  "message": "User deactivated successfully",
  "data": {
    "user": {
      "_id": "68d2c19972b14b75635218ea",
      "username": "aug",
      "email": "aug@example.com",
      "role": "user",
      "isActive": false,
      "updatedAt": "2025-09-23T15:55:12.123Z"
    }
  }
}
```

#### Delete User Account
```http
DELETE /api/admin/users/:userId
Authorization: Bearer admin-access-token
```

**Terminal Command:**
```bash
curl -X DELETE "http://localhost:3000/api/admin/users/68d2c19972b14b75635218ea" \
  -H "Authorization: Bearer ADMIN_TOKEN" | jq .
```

**Expected Output:**
```json
{
  "success": true,
  "message": "User account deleted successfully"
}
```

#### Get All Files (Admin View)
```http
GET /api/admin/files?page=1&limit=20&search=document&owner=USER_ID&isPublic=true
Authorization: Bearer admin-access-token
```

**Query Parameters:**
- `page` (optional): Page number for pagination (default: 1)
- `limit` (optional): Number of files per page (default: 20)
- `search` (optional): Search by filename or description
- `owner` (optional): Filter by owner user ID
- `isPublic` (optional): Filter by public status (`true` or `false`)

**Terminal Command:**
```bash
curl -X GET "http://localhost:3000/api/admin/files?page=1&limit=20" \
  -H "Authorization: Bearer ADMIN_TOKEN" | jq .
```

**Expected Output:**
```json
{
  "success": true,
  "data": {
    "files": [
      {
        "_id": "68d1ea7ddc1b331d096ec97d",
        "filename": "test-file.txt",
        "storedFilename": "1758587517391_i6m8wt26zl.txt",
        "mimetype": "text/plain",
        "size": 28,
        "owner": {
          "_id": "68d1e8d1e2a12c8ff3d0aa4b",
          "username": "johndoe",
          "email": "john@example.com"
        },
        "description": "Updated description",
        "isPublic": true,
        "downloadCount": 1,
        "tags": ["updated", "tags"],
        "createdAt": "2025-09-23T00:31:57.396Z",
        "updatedAt": "2025-09-23T15:41:02.989Z"
      }
    ],
    "pagination": {
      "currentPage": 1,
      "totalPages": 1,
      "totalFiles": 1,
      "hasNextPage": false,
      "hasPrevPage": false
    }
  }
}
```

#### Delete Any User's File
```http
DELETE /api/admin/files/:fileId
Authorization: Bearer admin-access-token
```

**Terminal Command:**
```bash
curl -X DELETE "http://localhost:3000/api/admin/files/68d1ea7ddc1b331d096ec97d" \
  -H "Authorization: Bearer ADMIN_TOKEN" | jq .
```

**Expected Output:**
```json
{
  "success": true,
  "message": "File deleted successfully"
}
```

#### Get System Statistics
```http
GET /api/admin/stats
Authorization: Bearer admin-access-token
```

**Terminal Command:**
```bash
curl -X GET http://localhost:3000/api/admin/stats \
  -H "Authorization: Bearer ADMIN_TOKEN" | jq .
```

**Expected Output:**
```json
{
  "success": true,
  "data": {
    "users": {
      "total": 3,
      "active": 3,
      "inactive": 0,
      "admins": 1,
      "regular": 2
    },
    "files": {
      "total": 1,
      "public": 1,
      "private": 0,
      "totalSize": 28,
      "averageSize": 28
    },
    "system": {
      "uptime": "2 hours, 15 minutes",
      "version": "1.0.0",
      "environment": "development"
    }
  }
}
```

### Basic Health Check Endpoints

#### Server Health
```http
GET /health
```

**Terminal Command:**
```bash
curl http://localhost:3000/health | jq .
```

**Expected Output:**
```json
{
  "success": true,
  "message": "Server is running",
  "timestamp": "2025-09-23T00:55:40.811Z",
  "environment": "development",
  "uptime": "2 hours, 15 minutes"
}
```

#### API Information
```http
GET /
```

**Terminal Command:**
```bash
curl http://localhost:3000/ | jq .
```

**Expected Output:**
```json
{
  "success": true,
  "message": "Secure File-Sharing REST API",
  "version": "1.0.0",
  "environment": "development",
  "timestamp": "2025-09-23T00:55:40.811Z",
  "endpoints": {
    "authentication": "/api/auth",
    "files": "/api/files",
    "admin": "/api/admin",
    "health": "/health"
  }
}
```

### Complete Testing Workflow

Here's a complete workflow to test the entire API:

```bash
#!/bin/bash

# 1. Check server health
echo "1. Checking server health..."
curl -s http://localhost:3000/health | jq .

# 2. Register a user
echo "2. Registering user..."
REGISTER_RESPONSE=$(curl -s -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "TestPass123!"
  }')

echo $REGISTER_RESPONSE | jq .

# Extract access token
ACCESS_TOKEN=$(echo $REGISTER_RESPONSE | jq -r '.data.accessToken')
echo "Access Token: $ACCESS_TOKEN"

# 3. Upload a file
echo "3. Uploading file..."
echo "Test file content for API testing" > test-file.txt

UPLOAD_RESPONSE=$(curl -s -X POST http://localhost:3000/api/files/upload \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -F "file=@test-file.txt" \
  -F "description=API test file" \
  -F "tags=test,api" \
  -F "isPublic=false")

echo $UPLOAD_RESPONSE | jq .

# Extract file ID
FILE_ID=$(echo $UPLOAD_RESPONSE | jq -r '.data.file._id')
echo "File ID: $FILE_ID"

# 4. List user's files
echo "4. Listing user files..."
curl -s -X GET http://localhost:3000/api/files/my-files \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq .

# 4b. Search files by tag
echo "4b. Searching files by tag..."
curl -s -X GET "http://localhost:3000/api/files/my-files?tag=test" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq .

# 5. Download file
echo "5. Downloading file..."
curl -s -X GET http://localhost:3000/api/files/$FILE_ID/download \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -o downloaded-test-file.txt

echo "File downloaded as downloaded-test-file.txt"

# 6. Update file metadata
echo "6. Updating file metadata..."
curl -s -X PUT http://localhost:3000/api/files/$FILE_ID \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "description": "Updated test file",
    "isPublic": true
  }' | jq .

# 7. Delete file
echo "7. Deleting file..."
curl -s -X DELETE http://localhost:3000/api/files/$FILE_ID \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq .

# 8. Logout
echo "8. Logging out..."
curl -s -X POST http://localhost:3000/api/auth/logout \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "'$(echo $REGISTER_RESPONSE | jq -r '.data.refreshToken')'"
  }' | jq .

# Cleanup
rm -f test-file.txt downloaded-test-file.txt

echo "Complete API workflow test finished!"
```

### Search Functionality

The API provides two different search mechanisms:

#### **Text Search (`?search=term`)**
- Searches in **filename** and **description** fields only
- Case-insensitive partial matching
- Example: `?search=document` finds files with "document" in filename or description

#### **Tag Search (`?tag=tagname`)**
- Searches in the **tags** array
- Exact tag matching (case-insensitive)
- Example: `?tag=pdf` finds files tagged with "pdf"

#### **Combined Usage**
You can use both parameters together:
```bash
# Find files with "report" in name/description AND tagged with "pdf"
curl -X GET "http://localhost:3000/api/files/my-files?search=report&tag=pdf" \
  -H "Authorization: Bearer YOUR_TOKEN" | jq .
```

### Testing Tips

1. **Install jq for better JSON formatting:**
   ```bash
   # macOS
   brew install jq
   
   # Ubuntu/Debian
   sudo apt-get install jq
   ```

2. **Save the workflow script:**
   ```bash
   # Save the complete workflow as a script
   curl -s [script_url] > test-api.sh
   chmod +x test-api.sh
   ./test-api.sh
   ```

3. **Use environment variables for tokens:**
   ```bash
   export ACCESS_TOKEN="your-token-here"
   curl -H "Authorization: Bearer $ACCESS_TOKEN" http://localhost:3000/api/files/my-files | jq .
   ```

## Configuration

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

## Security Considerations

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

## Testing

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


## Future Enhancements

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

**Security Notice**: This is a demonstration project. For production use, ensure you:
- Use strong, unique secrets
- Enable all security features
- Regularly update dependencies
- Conduct security audits
- Monitor for vulnerabilities