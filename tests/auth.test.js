const request = require('supertest');
const app = require('../src/index');
const User = require('../src/models/User');
const TestHelpers = require('./utils/testHelpers');

describe('Authentication System', () => {
  let helpers;

  beforeAll(() => {
    helpers = new TestHelpers();
  });

  afterEach(async () => {
    await helpers.cleanup();
  });

  describe('POST /api/auth/register', () => {
    describe('Success Cases', () => {
      test('should register a new user with valid data', async () => {
        const userData = {
          username: 'newuser',
          email: 'newuser@example.com',
          password: 'SecurePass123!'
        };

        const response = await request(app)
          .post('/api/auth/register')
          .send(userData);

        expect(response.status).toBe(201);
        expect(response.body.success).toBe(true);
        expect(response.body.message).toBe('User registered successfully');
        expect(response.body.data.user.username).toBe(userData.username);
        expect(response.body.data.user.email).toBe(userData.email);
        expect(response.body.data.user.password).toBeUndefined();
        expect(response.body.data.accessToken).toBeDefined();
        expect(response.body.data.refreshToken).toBeDefined();

        // Verify user was saved to database
        const savedUser = await User.findOne({ username: userData.username });
        expect(savedUser).toBeTruthy();
        expect(savedUser.email).toBe(userData.email);
      });

      test('should register user with minimal valid data', async () => {
        const userData = {
          username: 'minimaluser',
          email: 'minimal@test.com',
          password: 'Minimal123!'
        };

        const response = await request(app)
          .post('/api/auth/register')
          .send(userData);

        expect(response.status).toBe(201);
        expect(response.body.success).toBe(true);
      });
    });

    describe('Validation Failures', () => {
      test('should fail with short username', async () => {
        const userData = {
          username: 'ab',
          email: 'test@example.com',
          password: 'ValidPass123!'
        };

        const response = await request(app)
          .post('/api/auth/register')
          .send(userData);

        expect(response.status).toBe(400);
        expect(response.body.success).toBe(false);
        expect(response.body.message).toBe('Validation failed');
      });

      test('should fail with invalid email', async () => {
        const userData = {
          username: 'testuser',
          email: 'invalid-email',
          password: 'ValidPass123!'
        };

        const response = await request(app)
          .post('/api/auth/register')
          .send(userData);

        expect(response.status).toBe(400);
        expect(response.body.success).toBe(false);
      });

      test('should fail with weak password', async () => {
        const userData = {
          username: 'testuser',
          email: 'test@example.com',
          password: 'weak'
        };

        const response = await request(app)
          .post('/api/auth/register')
          .send(userData);

        expect(response.status).toBe(400);
        expect(response.body.success).toBe(false);
      });

      test('should fail with missing required fields', async () => {
        const userData = {
          username: 'testuser'
        };

        const response = await request(app)
          .post('/api/auth/register')
          .send(userData);

        expect(response.status).toBe(400);
        expect(response.body.success).toBe(false);
      });

      test('should fail with special characters in username', async () => {
        const userData = {
          username: 'test@user!',
          email: 'test@example.com',
          password: 'ValidPass123!'
        };

        const response = await request(app)
          .post('/api/auth/register')
          .send(userData);

        expect(response.status).toBe(400);
        expect(response.body.success).toBe(false);
      });

      test('should fail with extremely long username', async () => {
        const userData = {
          username: 'a'.repeat(31),
          email: 'test@example.com',
          password: 'ValidPass123!'
        };

        const response = await request(app)
          .post('/api/auth/register')
          .send(userData);

        expect(response.status).toBe(400);
        expect(response.body.success).toBe(false);
      });
    });

    describe('Duplicate User Failures', () => {
      beforeEach(async () => {
        await helpers.createTestUser({
          username: 'existinguser',
          email: 'existing@example.com'
        });
      });

      test('should fail when username already exists', async () => {
        const userData = {
          username: 'existinguser',
          email: 'new@example.com',
          password: 'ValidPass123!'
        };

        const response = await request(app)
          .post('/api/auth/register')
          .send(userData);

        expect(response.status).toBe(409);
        expect(response.body.success).toBe(false);
        expect(response.body.message).toBe('Username already exists');
      });

      test('should fail when email already exists', async () => {
        const userData = {
          username: 'newuser',
          email: 'existing@example.com',
          password: 'ValidPass123!'
        };

        const response = await request(app)
          .post('/api/auth/register')
          .send(userData);

        expect(response.status).toBe(409);
        expect(response.body.success).toBe(false);
        expect(response.body.message).toBe('Email already exists');
      });
    });

    describe('Security Tests', () => {
      test('should sanitize XSS attempts in input', async () => {
        const userData = {
          username: '<script>alert("xss")</script>',
          email: '<script>alert("xss")</script>@example.com',
          password: 'ValidPass123!'
        };

        const response = await request(app)
          .post('/api/auth/register')
          .send(userData);

        // Should either reject or sanitize the input
        expect(response.status).toBeGreaterThanOrEqual(400);
      });

      test('should handle SQL injection attempts', async () => {
        const userData = {
          username: "admin'; DROP TABLE users; --",
          email: 'test@example.com',
          password: 'ValidPass123!'
        };

        const response = await request(app)
          .post('/api/auth/register')
          .send(userData);

        // Should reject invalid characters
        expect(response.status).toBe(400);
      });
    });
  });

  describe('POST /api/auth/login', () => {
    beforeEach(async () => {
      await helpers.createTestUser({
        username: 'logintest',
        email: 'login@example.com',
        password: 'LoginPass123!'
      });
    });

    describe('Success Cases', () => {
      test('should login with username', async () => {
        const loginData = {
          usernameOrEmail: 'logintest',
          password: 'LoginPass123!'
        };

        const response = await request(app)
          .post('/api/auth/login')
          .send(loginData);

        expect(response.status).toBe(200);
        expect(response.body.success).toBe(true);
        expect(response.body.message).toBe('Login successful');
        expect(response.body.data.user.username).toBe('logintest');
        expect(response.body.data.accessToken).toBeDefined();
        expect(response.body.data.refreshToken).toBeDefined();
      });

      test('should login with email', async () => {
        const loginData = {
          usernameOrEmail: 'login@example.com',
          password: 'LoginPass123!'
        };

        const response = await request(app)
          .post('/api/auth/login')
          .send(loginData);

        expect(response.status).toBe(200);
        expect(response.body.success).toBe(true);
      });
    });

    describe('Authentication Failures', () => {
      test('should fail with incorrect username', async () => {
        const loginData = {
          usernameOrEmail: 'nonexistent',
          password: 'LoginPass123!'
        };

        const response = await request(app)
          .post('/api/auth/login')
          .send(loginData);

        expect(response.status).toBe(401);
        expect(response.body.success).toBe(false);
        expect(response.body.message).toBe('Invalid credentials');
      });

      test('should fail with incorrect password', async () => {
        const loginData = {
          usernameOrEmail: 'logintest',
          password: 'WrongPassword123!'
        };

        const response = await request(app)
          .post('/api/auth/login')
          .send(loginData);

        expect(response.status).toBe(401);
        expect(response.body.success).toBe(false);
        expect(response.body.message).toBe('Invalid credentials');
      });

      test('should fail with empty credentials', async () => {
        const loginData = {
          usernameOrEmail: '',
          password: ''
        };

        const response = await request(app)
          .post('/api/auth/login')
          .send(loginData);

        expect(response.status).toBe(400);
        expect(response.body.success).toBe(false);
      });

      test('should increment login attempts on failure', async () => {
        const user = await User.findOne({ username: 'logintest' });
        const initialAttempts = user.loginAttempts;

        const loginData = {
          usernameOrEmail: 'logintest',
          password: 'WrongPassword123!'
        };

        await request(app)
          .post('/api/auth/login')
          .send(loginData);

        const updatedUser = await User.findOne({ username: 'logintest' });
        expect(updatedUser.loginAttempts).toBe(initialAttempts + 1);
      });
    });

    describe('Account Lockout Tests', () => {
      test('should lock account after max failed attempts', async () => {
        const loginData = {
          usernameOrEmail: 'logintest',
          password: 'WrongPassword123!'
        };

        // Make multiple failed login attempts
        for (let i = 0; i < 5; i++) {
          await request(app)
            .post('/api/auth/login')
            .send(loginData);
        }

        // Should be locked now
        const response = await request(app)
          .post('/api/auth/login')
          .send({
            usernameOrEmail: 'logintest',
            password: 'LoginPass123!'
          });

        expect(response.status).toBe(401);
        expect(response.body.message).toContain('locked');
      });

      test('should unlock account after lockout time expires', async () => {
        // First, lock the account
        const user = await User.findOne({ username: 'logintest' });
        user.lockUntil = Date.now() + 1000; // Lock for 1 second
        await user.save();

        // Wait for lockout to expire
        await helpers.wait(1100);

        const loginData = {
          usernameOrEmail: 'logintest',
          password: 'LoginPass123!'
        };

        const response = await request(app)
          .post('/api/auth/login')
          .send(loginData);

        expect(response.status).toBe(200);
        expect(response.body.success).toBe(true);
      });
    });

    describe('Inactive User Tests', () => {
      test('should prevent login for inactive users', async () => {
        const user = await User.findOne({ username: 'logintest' });
        user.isActive = false;
        await user.save();

        const loginData = {
          usernameOrEmail: 'logintest',
          password: 'LoginPass123!'
        };

        const response = await request(app)
          .post('/api/auth/login')
          .send(loginData);

        expect(response.status).toBe(401);
        expect(response.body.message).toBe('User not found or inactive');
      });
    });
  });

  describe('POST /api/auth/refresh', () => {
    let userData;

    beforeEach(async () => {
      userData = await helpers.createTestUser({
        username: 'refreshtest',
        email: 'refresh@example.com'
      });
    });

    test('should refresh access token with valid refresh token', async () => {
      const response = await request(app)
        .post('/api/auth/refresh')
        .send({
          refreshToken: userData.tokens.refreshToken
        });

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data.accessToken).toBeDefined();
      expect(response.body.data.refreshToken).toBeDefined();
      expect(response.body.data.accessToken).not.toBe(userData.tokens.accessToken);
    });

    test('should fail with invalid refresh token', async () => {
      const response = await request(app)
        .post('/api/auth/refresh')
        .send({
          refreshToken: 'invalid-refresh-token'
        });

      expect(response.status).toBe(403);
      expect(response.body.success).toBe(false);
    });

    test('should fail with missing refresh token', async () => {
      const response = await request(app)
        .post('/api/auth/refresh')
        .send({});

      expect(response.status).toBe(401);
      expect(response.body.success).toBe(false);
    });

    test('should fail with expired refresh token', async () => {
      const expiredToken = helpers.generateInvalidTokens().expired;
      
      const response = await request(app)
        .post('/api/auth/refresh')
        .send({
          refreshToken: expiredToken
        });

      expect(response.status).toBe(403);
      expect(response.body.success).toBe(false);
    });
  });

  describe('POST /api/auth/logout', () => {
    let userData;

    beforeEach(async () => {
      userData = await helpers.createTestUser({
        username: 'logouttest',
        email: 'logout@example.com'
      });
    });

    test('should logout successfully with valid tokens', async () => {
      const response = await request(app)
        .post('/api/auth/logout')
        .set('Authorization', userData.authHeader)
        .send({
          refreshToken: userData.tokens.refreshToken
        });

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.message).toBe('Logged out successfully');
    });

    test('should fail without authentication', async () => {
      const response = await request(app)
        .post('/api/auth/logout')
        .send({
          refreshToken: userData.tokens.refreshToken
        });

      expect(response.status).toBe(401);
      expect(response.body.success).toBe(false);
    });

    test('should fail with invalid access token', async () => {
      const response = await request(app)
        .post('/api/auth/logout')
        .set('Authorization', 'Bearer invalid-token')
        .send({
          refreshToken: userData.tokens.refreshToken
        });

      expect(response.status).toBe(403);
      expect(response.body.success).toBe(false);
    });
  });

  describe('GET /api/auth/profile', () => {
    let userData;

    beforeEach(async () => {
      userData = await helpers.createTestUser({
        username: 'profiletest',
        email: 'profile@example.com'
      });
    });

    test('should get user profile with valid token', async () => {
      const response = await request(app)
        .get('/api/auth/profile')
        .set('Authorization', userData.authHeader);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data.user.username).toBe('profiletest');
      expect(response.body.data.user.password).toBeUndefined();
    });

    test('should fail without authentication', async () => {
      const response = await request(app)
        .get('/api/auth/profile');

      expect(response.status).toBe(401);
      expect(response.body.success).toBe(false);
    });

    test('should fail with invalid token', async () => {
      const response = await request(app)
        .get('/api/auth/profile')
        .set('Authorization', 'Bearer invalid-token');

      expect(response.status).toBe(403);
      expect(response.body.success).toBe(false);
    });

    test('should fail with malformed authorization header', async () => {
      const response = await request(app)
        .get('/api/auth/profile')
        .set('Authorization', 'invalid-format');

      expect(response.status).toBe(401);
      expect(response.body.success).toBe(false);
    });
  });

  describe('Rate Limiting Tests', () => {
    test('should apply rate limiting to registration endpoint', async () => {
      const userData = {
        username: 'ratetest',
        email: 'rate@example.com',
        password: 'RatePass123!'
      };

      // Make multiple requests rapidly
      const promises = [];
      for (let i = 0; i < 10; i++) {
        promises.push(
          request(app)
            .post('/api/auth/register')
            .send({
              ...userData,
              username: `ratetest${i}`,
              email: `rate${i}@example.com`
            })
        );
      }

      const responses = await Promise.all(promises);
      
      // Some requests should be rate limited
      const rateLimitedResponses = responses.filter(r => r.status === 429);
      expect(rateLimitedResponses.length).toBeGreaterThan(0);
    });

    test('should apply stricter rate limiting to login endpoint', async () => {
      // Make multiple failed login attempts rapidly
      const promises = [];
      for (let i = 0; i < 10; i++) {
        promises.push(
          request(app)
            .post('/api/auth/login')
            .send({
              usernameOrEmail: 'nonexistent',
              password: 'wrong'
            })
        );
      }

      const responses = await Promise.all(promises);
      
      // Most requests should be rate limited
      const rateLimitedResponses = responses.filter(r => r.status === 429);
      expect(rateLimitedResponses.length).toBeGreaterThan(5);
    });
  });
});
