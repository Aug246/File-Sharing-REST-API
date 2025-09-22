const fs = require('fs');
const path = require('path');

module.exports = async () => {
  // Stop MongoDB memory server
  if (global.__MONGOD__) {
    await global.__MONGOD__.stop();
  }
  
  // Clean up test uploads directory
  const testUploadDir = path.join(process.cwd(), 'test-uploads');
  if (fs.existsSync(testUploadDir)) {
    fs.rmSync(testUploadDir, { recursive: true, force: true });
  }
};
