# Rust Auth API - Project Index

## Project Structure Overview

This document provides a comprehensive index of the Rust Authentication API project, including all files, folders, methods, functions, and a brief description of each component.

## Directory Structure

```
rust-auth-api/
├── .cargo/
├── .env
├── .env.example
├── .git/
├── .gitignore
├── Cargo.lock
├── Cargo.toml
├── README.md
├── data/
├── melhorias.md
├── migrations/
├── src/
│   ├── config/
│   │   └── mod.rs
│   ├── controllers/
│   │   ├── auth_controller.rs
│   │   ├── health_controller.rs
│   │   ├── mod.rs
│   │   └── user_controller.rs
│   ├── db/
│   │   └── [database files]
│   ├── errors/
│   │   └── [error handling files]
│   ├── lib.rs
│   ├── main.rs
│   ├── middleware/
│   │   ├── auth.rs
│   │   ├── cors.rs
│   │   ├── error.rs
│   │   ├── logger.rs
│   │   ├── mod.rs
│   │   └── rate_limiter.rs
│   ├── models/
│   │   ├── auth.rs
│   │   ├── mod.rs
│   │   ├── response.rs
│   │   └── user.rs
│   ├── routes/
│   │   └── mod.rs
│   ├── services/
│   │   ├── auth_service.rs
│   │   ├── email_service.rs
│   │   ├── mod.rs
│   │   └── user_service.rs
│   └── utils/
│       └── [utility files]
├── target/
├── test_api.py
└── tests/
```

## Core Files

### main.rs
The entry point of the application that initializes and starts the web server.

**Main Functions:**
- `main()`: Initializes the application, loads configuration, sets up database connection, and starts the web server.

### lib.rs
Exports all the modules for use in other parts of the application.

## Modules

### Config Module (`src/config/`)

#### mod.rs
Manages application configuration loaded from environment variables.

**Structs:**
- `Config`: Main configuration container
- `ServerConfig`: Server-specific settings (host, port)
- `DatabaseConfig`: Database connection settings
- `JwtConfig`: JWT authentication settings
- `EmailConfig`: Email service configuration
- `SecurityConfig`: Security settings like password hashing and rate limiting
- `CorsConfig`: CORS policy configuration

**Functions:**
- `Config::from_env()`: Loads configuration from environment variables
- `load_config()`: Helper function to load the configuration

### Controllers Module (`src/controllers/`)

#### auth_controller.rs
Handles authentication-related HTTP requests.

**Functions:**
- `register()`: Registers a new user
- `login()`: Authenticates a user and returns tokens
- `refresh_token()`: Updates access token using a refresh token
- `forgot_password()`: Initiates password recovery process
- `reset_password()`: Resets a user's password
- `unlock_account()`: Unlocks a locked user account
- `me()`: Returns the current authenticated user's information

#### user_controller.rs
Handles user-related HTTP requests.

**Functions:**
- `list_users()`: Lists all users (admin only)
- `get_user()`: Gets a specific user by ID
- `update_user()`: Updates a user's information
- `delete_user()`: Deletes a user (admin only)
- `change_password()`: Changes a user's password

#### health_controller.rs
Handles health check endpoints.

**Functions:**
- `health_check()`: Returns the API health status
- `version()`: Returns the API version information

### Models Module (`src/models/`)

#### user.rs
Defines user-related data structures.

**Structs:**
- `User`: Main user entity with all user data
- `CreateUserDto`: Data transfer object for user creation
- `UpdateUserDto`: Data transfer object for user updates
- `ChangePasswordDto`: Data transfer object for password changes
- `UserResponse`: User data safe for API responses (excludes sensitive data)

**Methods:**
- `User::new()`: Creates a new user
- `User::full_name()`: Returns the user's full name
- `User::is_locked()`: Checks if the user account is locked

#### auth.rs
Defines authentication-related data structures.

**Structs:**
- `LoginDto`: Data transfer object for login
- `RegisterDto`: Data transfer object for registration
- `RefreshTokenDto`: Data transfer object for token refresh
- `ForgotPasswordDto`: Data transfer object for password recovery
- `ResetPasswordDto`: Data transfer object for password reset
- `UnlockAccountDto`: Data transfer object for account unlocking
- `TokenClaims`: JWT token claims
- `AuthResponse`: Authentication response with tokens
- `Session`: User session information
- `RefreshToken`: Refresh token data
- `PasswordResetToken`: Password reset token data
- `AuthLog`: Authentication event log

#### response.rs
Defines API response structures.

**Structs:**
- `ApiResponse<T>`: Generic API response wrapper

### Services Module (`src/services/`)

#### auth_service.rs
Implements authentication business logic.

**Functions:**
- `register()`: Registers a new user
- `login()`: Authenticates a user
- `forgot_password()`: Initiates password recovery
- `reset_password()`: Resets a user's password
- `refresh_token()`: Refreshes an access token
- `unlock_account()`: Unlocks a locked account
- `validate_token()`: Validates a JWT token
- `generate_jwt()`: Generates a JWT token
- `create_session()`: Creates a new user session
- `log_auth_event()`: Logs authentication events
- `parse_expiration()`: Parses token expiration time
- `save_refresh_token()`: Saves a refresh token
- `find_and_validate_refresh_token()`: Finds and validates a refresh token
- `revoke_refresh_token()`: Revokes a specific refresh token
- `hash_token()`: Hashes a token for secure storage
- `revoke_all_user_refresh_tokens()`: Revokes all refresh tokens for a user

#### email_service.rs
Handles email sending functionality.

**Struct:**
- `EmailService`: Service for sending emails

**Methods:**
- `new()`: Creates a new email service
- `send_welcome_email()`: Sends welcome email to new users
- `send_password_reset_email()`: Sends password reset instructions
- `send_account_locked_email()`: Sends account locked notification
- `send_email()`: Generic method to send emails

#### user_service.rs
Implements user management business logic.

**Functions:**
- `create_user()`: Creates a new user
- `get_user_by_id()`: Retrieves a user by ID
- `get_user_by_email()`: Retrieves a user by email
- `get_user_by_username()`: Retrieves a user by username
- `get_user_by_email_or_username()`: Retrieves a user by email or username
- `update_user()`: Updates a user's information
- `delete_user()`: Deletes a user
- `change_password()`: Changes a user's password
- `hash_password()`: Hashes a password
- `verify_password()`: Verifies a password against its hash
- `list_users()`: Lists all users

### Middleware Module (`src/middleware/`)

#### auth.rs
Implements authentication middleware.

**Structs:**
- `JwtAuth`: Middleware for JWT authentication
- `AdminAuth`: Middleware for admin authorization

**Methods:**
- `JwtAuth::new()`: Creates a new JWT authentication middleware
- `AdminAuth::new()`: Creates a new admin authorization middleware

#### cors.rs
Configures CORS (Cross-Origin Resource Sharing) policies.

**Functions:**
- `configure_cors()`: Configures CORS settings based on application config

#### error.rs
Handles error transformation for consistent API responses.

**Struct:**
- `ErrorHandler`: Middleware for consistent error handling

#### logger.rs
Logs HTTP requests and responses.

**Struct:**
- `RequestLogger`: Middleware for request logging

#### rate_limiter.rs
Implements rate limiting to prevent abuse.

**Struct:**
- `RateLimiter`: Middleware for rate limiting requests

**Methods:**
- `RateLimiter::new()`: Creates a new rate limiter with specified limits

### Routes Module (`src/routes/`)

#### mod.rs
Configures API routes and middleware.

**Functions:**
- `configure_routes()`: Sets up all API routes with their respective middleware

## API Endpoints

### Authentication Endpoints
- `POST /api/auth/register`: Register a new user
- `POST /api/auth/login`: Authenticate a user
- `POST /api/auth/forgot-password`: Request password reset
- `POST /api/auth/reset-password`: Reset password with token
- `POST /api/auth/unlock`: Unlock a locked account
- `POST /api/auth/refresh`: Refresh access token
- `GET /api/auth/me`: Get current user info (requires authentication)

### User Endpoints
- `GET /api/users`: List all users (admin only)
- `GET /api/users/{id}`: Get user by ID
- `PUT /api/users/{id}`: Update user
- `DELETE /api/users/{id}`: Delete user (admin only)
- `POST /api/users/{id}/change-password`: Change user password

### Health Check Endpoints
- `GET /api/health`: Check API health
- `GET /api/health/version`: Get API version

## Security Features

1. **JWT Authentication**: Secure token-based authentication
2. **Password Hashing**: Secure password storage with bcrypt
3. **Rate Limiting**: Protection against brute force attacks
4. **Account Locking**: Automatic account locking after failed login attempts
5. **CORS Protection**: Configurable cross-origin resource sharing
6. **Refresh Tokens**: Secure token refresh mechanism
7. **Admin Authorization**: Role-based access control
8. **Email Verification**: Optional email verification for security actions
