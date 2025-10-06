# Authentication API Documentation

This document describes the authentication and user management API endpoints.

## Base URL

```
http://localhost:3000
```

## Authentication Endpoints

### 1. Register a New User

**Endpoint:** `POST /auth/register`

**Description:** Creates a new user account with optional billing details.

**Request Body:**
```json
{
  "email": "user@example.com",
  "fullName": "John Doe",
  "password": "SecurePassword123!",
  "enableBilling": false,
  "billingDetails": {
    "cardNumber": "4111111111111111",
    "address": "123 Main St",
    "city": "New York",
    "country": "US",
    "zip": "10001"
  }
}
```

**Success Response (201):**
```json
{
  "message": "Регистрация успешна",
  "user": {
    "id": "uuid-here",
    "email": "user@example.com",
    "username": "user"
  }
}
```

**Error Responses:**
- `400`: Missing required fields (email, fullName, password)
- `409`: User with this email already exists
- `500`: Internal server error

---

### 2. Login

**Endpoint:** `POST /auth/login`

**Description:** Authenticates a user and returns a JWT token.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

**Success Response (200):**
```json
{
  "message": "Вход успешен",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "uuid-here",
    "email": "user@example.com",
    "username": "user"
  }
}
```

**Error Responses:**
- `400`: Missing email or password
- `400`: Invalid credentials (user not found or wrong password)

---

## User Management Endpoints (Protected)

All user management endpoints require authentication. Include the JWT token in the Authorization header:

```
Authorization: Bearer <token>
```

### 3. Get User Profile

**Endpoint:** `GET /user/profile`

**Description:** Retrieves the authenticated user's profile information.

**Headers:**
```
Authorization: Bearer <token>
```

**Success Response (200):**
```json
{
  "id": "uuid-here",
  "username": "user",
  "email": "user@example.com",
  "created_at": "2024-01-01T00:00:00.000Z",
  "subscription_status": "active",
  "subscription_level": "free",
  "subscription_expires": null,
  "card_last4": "1111",
  "card_brand": "visa",
  "billing_address": "123 Main St",
  "billing_city": "New York",
  "billing_country": "US",
  "billing_zip": "10001"
}
```

**Error Responses:**
- `401`: Access token required
- `403`: Invalid or expired token
- `404`: User not found
- `500`: Failed to fetch profile

---

### 4. Change Password

**Endpoint:** `POST /user/change-password`

**Description:** Changes the authenticated user's password.

**Headers:**
```
Authorization: Bearer <token>
```

**Request Body:**
```json
{
  "currentPassword": "OldPassword123!",
  "newPassword": "NewPassword123!"
}
```

**Success Response (200):**
```json
{
  "message": "Password changed successfully"
}
```

**Error Responses:**
- `400`: Current and new password are required
- `400`: Current password is incorrect
- `401`: Access token required
- `403`: Invalid or expired token

---

### 5. Update Billing Details

**Endpoint:** `POST /user/update-billing`

**Description:** Updates the authenticated user's billing information.

**Headers:**
```
Authorization: Bearer <token>
```

**Request Body:**
```json
{
  "cardNumber": "4111111111111111",
  "cardExpiry": "12/25",
  "cardCvv": "123",
  "billingAddress": "456 Oak Ave",
  "billingCity": "Los Angeles",
  "billingCountry": "US",
  "billingZip": "90001"
}
```

**Success Response (200):**
```json
{
  "message": "Billing details updated successfully"
}
```

**Error Responses:**
- `401`: Access token required
- `403`: Invalid or expired token
- `400`: Failed to update billing details

---

## Security Features

### Password Requirements
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character (!@#$%^&*)

### JWT Token
- Expires in 24 hours
- Contains user ID and email
- Must be included in Authorization header for protected routes

### Password Storage
- Passwords are hashed using bcrypt with salt rounds of 10
- Plain text passwords are never stored

### Card Information
- Only last 4 digits are stored
- Card CVV is never stored
- Full card numbers should only be sent for initial registration or updates

---

## Database Schema

### Users Table
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(100) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
```

### Subscriptions Table
```sql
CREATE TABLE subscriptions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status VARCHAR(50) NOT NULL DEFAULT 'inactive',
    level VARCHAR(50) NOT NULL DEFAULT 'free',
    starts_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
```

### Billing Details Table
```sql
CREATE TABLE billing_details (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE UNIQUE,
    card_last4 VARCHAR(4),
    card_brand VARCHAR(50),
    billing_address TEXT,
    billing_city VARCHAR(100),
    billing_country VARCHAR(100),
    billing_zip VARCHAR(20),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
```

---

## Frontend Integration

### Setting Up Authentication

```javascript
import { AuthProvider, useAuth } from './context/AuthContext';

// Wrap your app with AuthProvider
<AuthProvider>
  <App />
</AuthProvider>
```

### Using Authentication in Components

```javascript
import { useAuth } from '../context/AuthContext';

function MyComponent() {
  const { user, token, isAuthenticated, login, logout } = useAuth();
  
  // Check if user is authenticated
  if (!isAuthenticated) {
    return <Navigate to="/login" />;
  }
  
  // Use user data
  return <div>Welcome, {user.username}!</div>;
}
```

### Protecting Routes

```javascript
import ProtectedRoute from './components/auth/ProtectedRoute';

<Route 
  path="/dashboard" 
  element={
    <ProtectedRoute>
      <Dashboard />
    </ProtectedRoute>
  } 
/>
```

### Making Authenticated API Calls

```javascript
const { token } = useAuth();

const response = await fetch('/api/user/profile', {
  headers: {
    'Authorization': `Bearer ${token}`
  }
});
```

---

## Environment Variables

Create a `.env` file in the backend directory:

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

**Important:** Never commit the `.env` file to version control. The JWT_SECRET should be a long, random string in production.
