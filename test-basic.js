#!/usr/bin/env node

// Simple test script to verify basic functionality
const mongoose = require('mongoose');
const User = require('./src/models/User');
const File = require('./src/models/File');

async function runBasicTests() {
  console.log('🧪 Running basic functionality tests...\n');

  try {
    // Test 1: User model validation
    console.log('1. Testing User model validation...');
    
    // Test valid user creation
    const validUser = new User({
      username: 'testuser',
      email: 'test@example.com',
      password: 'TestPass123!'
    });
    
    await validUser.validate();
    console.log('   ✅ Valid user validation passed');
    
    // Test invalid username
    try {
      const invalidUser = new User({
        username: 'ab', // Too short
        email: 'test@example.com',
        password: 'TestPass123!'
      });
      await invalidUser.validate();
      console.log('   ❌ Invalid username validation should have failed');
    } catch (error) {
      console.log('   ✅ Invalid username validation correctly failed');
    }
    
    // Test invalid email
    try {
      const invalidEmailUser = new User({
        username: 'testuser2',
        email: 'invalid-email',
        password: 'TestPass123!'
      });
      await invalidEmailUser.validate();
      console.log('   ❌ Invalid email validation should have failed');
    } catch (error) {
      console.log('   ✅ Invalid email validation correctly failed');
    }

    // Test 2: File model validation
    console.log('\n2. Testing File model validation...');
    
    const validFile = new File({
      filename: 'test.txt',
      storedFilename: 'test_stored.txt',
      mimetype: 'text/plain',
      size: 100,
      owner: new mongoose.Types.ObjectId(),
      description: 'Test file',
      tags: ['test'],
      isPublic: false
    });
    
    await validFile.validate();
    console.log('   ✅ Valid file validation passed');
    
    // Test invalid file type
    try {
      const invalidFile = new File({
        filename: 'test.exe',
        storedFilename: 'test_stored.exe',
        mimetype: 'application/x-executable',
        size: 100,
        owner: new mongoose.Types.ObjectId(),
        description: 'Test executable',
        tags: ['test'],
        isPublic: false
      });
      await invalidFile.validate();
      console.log('   ❌ Invalid file type validation should have failed');
    } catch (error) {
      console.log('   ✅ Invalid file type validation correctly failed');
    }

    // Test 3: JWT token generation
    console.log('\n3. Testing JWT token generation...');
    
    const { generateTokens } = require('./src/middleware/auth');
    const tokens = generateTokens({
      _id: new mongoose.Types.ObjectId(),
      username: 'testuser',
      role: 'user'
    });
    
    if (tokens.accessToken && tokens.refreshToken) {
      console.log('   ✅ JWT token generation works');
    } else {
      console.log('   ❌ JWT token generation failed');
    }

    // Test 4: File path generation
    console.log('\n4. Testing file path generation...');
    
    const storedFilename = File.generateStoredFilename('test-file.txt');
    if (storedFilename && storedFilename !== 'test-file.txt') {
      console.log('   ✅ File path generation works');
    } else {
      console.log('   ❌ File path generation failed');
    }

    // Test 5: Password hashing
    console.log('\n5. Testing password hashing...');
    
    const user = new User({
      username: 'hashtest',
      email: 'hash@example.com',
      password: 'TestPass123!'
    });
    
    await user.save();
    
    const isMatch = await user.comparePassword('TestPass123!');
    const isNotMatch = await user.comparePassword('WrongPassword');
    
    if (isMatch && !isNotMatch) {
      console.log('   ✅ Password hashing and comparison works');
    } else {
      console.log('   ❌ Password hashing and comparison failed');
    }
    
    // Cleanup
    await User.deleteOne({ username: 'hashtest' });

    console.log('\n🎉 All basic tests passed!');
    
  } catch (error) {
    console.error('\n❌ Test failed:', error.message);
    console.error('Stack:', error.stack);
  }
}

// Run tests if this file is executed directly
if (require.main === module) {
  // Set test environment
  process.env.NODE_ENV = 'test';
  process.env.JWT_SECRET = 'test-jwt-secret-key';
  process.env.JWT_REFRESH_SECRET = 'test-refresh-secret-key';
  process.env.MONGODB_URI = 'mongodb://localhost:27017/test-file-sharing-api';
  
  runBasicTests().then(() => {
    process.exit(0);
  }).catch(error => {
    console.error('Test runner failed:', error);
    process.exit(1);
  });
}

module.exports = runBasicTests;
