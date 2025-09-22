const mongoose = require('mongoose');
const fs = require('fs');
const path = require('path');

// Increase timeout for all tests
jest.setTimeout(30000);

// Clean up after each test
afterEach(async () => {
  // Clear all collections
  const collections = mongoose.connection.collections;
  for (const key in collections) {
    const collection = collections[key];
    await collection.deleteMany({});
  }
  
  // Clean up test files
  const testUploadDir = path.join(process.cwd(), 'test-uploads');
  if (fs.existsSync(testUploadDir)) {
    const files = fs.readdirSync(testUploadDir);
    files.forEach(file => {
      const filePath = path.join(testUploadDir, file);
      if (fs.statSync(filePath).isFile()) {
        fs.unlinkSync(filePath);
      }
    });
  }
});

// Suppress console logs during tests unless explicitly enabled
const originalConsoleLog = console.log;
const originalConsoleWarn = console.warn;
const originalConsoleError = console.error;

beforeAll(() => {
  if (process.env.NODE_ENV === 'test' && !process.env.DEBUG_TESTS) {
    console.log = jest.fn();
    console.warn = jest.fn();
    console.error = jest.fn();
  }
});

afterAll(() => {
  console.log = originalConsoleLog;
  console.warn = originalConsoleWarn;
  console.error = originalConsoleError;
});
