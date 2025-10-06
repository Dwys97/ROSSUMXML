# Authentication System Implementation

This document provides an overview of the implemented authentication system for the ROSSUMXML project.

## Overview

A complete authentication system has been implemented including:
- User registration with email validation
- Secure login with JWT tokens
- Password hashing with bcrypt
- Protected routes on both frontend and backend
- User profile management
- Password change functionality
- Billing details management

## Architecture

### Backend (Node.js/Express)

#### Routes
- **`/auth/register`** - User registration endpoint
- **`/auth/login`** - User authentication endpoint
- **`/user/profile`** - Get user profile (protected)
- **`/user/change-password`** - Change password (protected)
- **`/user/update-billing`** - Update billing details (protected)

#### Middleware
- **`authenticateToken`** - JWT verification middleware for protected routes

#### Services
- **`user.service.js`** - User profile and billing management
- **`xmlParser.service.js`** - XML parsing (existing)
- **`transform.service.js`** - XML transformation (existing)

#### Database
- PostgreSQL with three main tables:
  - `users` - User accounts
  - `subscriptions` - Subscription information
  - `billing_details` - Payment information

### Frontend (React)

#### Context
- **`AuthContext`** - Global authentication state management
  - Stores user info and JWT token
  - Persists state in localStorage
  - Provides login/logout functions

#### Components
- **`ProtectedRoute`** - HOC for route protection
- **`LoginPage`** - User login form
- **`RegisterPage`** - User registration form
- **`UserProfile`** - User profile management

#### Protected Routes
- `/transformer` - XML transformation page (requires authentication)
- `/editor` - XML editor page (requires authentication)

## Security Features

### Password Security
- Passwords hashed using bcrypt with 10 salt rounds
- Password strength validation on frontend
- Requirements:
  - Minimum 8 characters
  - At least one uppercase letter
  - At least one lowercase letter
  - At least one number
  - At least one special character

### JWT Tokens
- 24-hour expiration
- Signed with secret key from environment
- Contains user ID and email
- Verified on all protected endpoints

### API Security
- CORS enabled for cross-origin requests
- Input validation on all endpoints
- Error messages don't expose sensitive information
- Token required for all user-specific operations

## Setup Instructions

### 1. Backend Setup

```bash
cd backend
npm install
```

Create a `.env` file:
```env
NODE_ENV=development
PORT=3000
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
POSTGRES_DB=rossumxml
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
JWT_SECRET=your-secret-key-here
```

Start the server:
```bash
npm run dev
```

### 2. Frontend Setup

```bash
cd frontend
npm install
```

Start the development server:
```bash
npm run dev
```

### 3. Database Setup

Using Docker Compose:
```bash
docker-compose up -d
```

The database will be automatically initialized with the schema from `backend/db/init.sql`.

## Usage Examples

### Registration

```javascript
const response = await fetch('/api/auth/register', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    email: 'user@example.com',
    fullName: 'John Doe',
    password: 'SecurePassword123!'
  })
});

const data = await response.json();
// { message: "Регистрация успешна", user: { id, email, username } }
```

### Login

```javascript
const response = await fetch('/api/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    email: 'user@example.com',
    password: 'SecurePassword123!'
  })
});

const data = await response.json();
// { message: "Вход успешен", token: "...", user: { id, email, username } }

// Store token
localStorage.setItem('authToken', data.token);
```

### Accessing Protected Endpoints

```javascript
const token = localStorage.getItem('authToken');

const response = await fetch('/api/user/profile', {
  headers: {
    'Authorization': `Bearer ${token}`
  }
});

const profile = await response.json();
```

### Using AuthContext in React

```javascript
import { useAuth } from '../context/AuthContext';

function MyComponent() {
  const { user, isAuthenticated, login, logout } = useAuth();

  if (!isAuthenticated) {
    return <Navigate to="/login" />;
  }

  return (
    <div>
      <h1>Welcome, {user.username}!</h1>
      <button onClick={logout}>Logout</button>
    </div>
  );
}
```

## Testing

### Manual Testing

1. **Test Registration:**
   - Navigate to `/register`
   - Fill in email, full name, and password
   - Submit the form
   - Should redirect to login page

2. **Test Login:**
   - Navigate to `/login`
   - Enter credentials
   - Should redirect to `/transformer`

3. **Test Protected Routes:**
   - Without logging in, try to access `/transformer`
   - Should redirect to `/login`
   - After logging in, should be able to access protected routes

4. **Test Logout:**
   - Click logout button
   - Should clear user data and token
   - Protected routes should redirect to login

### Testing with Docker

Start the full stack with Docker:
```bash
docker-compose up --build
```

This will start:
- Backend on `http://localhost:3000`
- Frontend on `http://localhost:5173`
- PostgreSQL on `localhost:5432`

## API Documentation

For detailed API documentation, see [AUTHENTICATION.md](./AUTHENTICATION.md).

## Troubleshooting

### Database Connection Issues
- Ensure PostgreSQL is running
- Check database credentials in `.env`
- Verify database exists: `psql -U postgres -l`

### JWT Token Issues
- Ensure `JWT_SECRET` is set in `.env`
- Check token expiration (24 hours)
- Verify token format in Authorization header

### CORS Issues
- Backend has CORS enabled by default
- Frontend proxy configured in `vite.config.js`

## Future Improvements

- [ ] Add refresh token mechanism
- [ ] Implement email verification
- [ ] Add password reset functionality
- [ ] Implement rate limiting
- [ ] Add two-factor authentication
- [ ] Add OAuth integration (Google, GitHub)
- [ ] Add comprehensive test suite
- [ ] Add logging and monitoring

## Contributing

When working with the authentication system:
1. Never commit `.env` files
2. Always validate user input
3. Use the existing middleware for protected routes
4. Follow the existing error handling patterns
5. Test thoroughly before committing
