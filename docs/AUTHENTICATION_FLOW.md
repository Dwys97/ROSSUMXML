# Authentication Flow Diagram

## User Registration Flow

```
┌─────────────┐
│   Browser   │
└──────┬──────┘
       │ 1. Fill registration form
       │    (email, fullName, password)
       ▼
┌─────────────────┐
│ RegisterPage.jsx│
└──────┬──────────┘
       │ 2. Validate input
       │    - Password strength
       │    - Password confirmation
       │    - Required fields
       ▼
┌─────────────────┐
│  POST /auth/    │
│   register      │
└──────┬──────────┘
       │ 3. Server validates
       ▼
┌─────────────────┐
│ auth.routes.js  │
└──────┬──────────┘
       │ 4. Check existing user
       │ 5. Hash password (bcrypt)
       │ 6. Create user in DB
       │ 7. Create subscription
       │ 8. Create billing (optional)
       ▼
┌─────────────────┐
│   PostgreSQL    │
│   Database      │
└──────┬──────────┘
       │ 9. Return success
       ▼
┌─────────────────┐
│ RegisterPage.jsx│
└──────┬──────────┘
       │ 10. Redirect to /login
       ▼
┌─────────────┐
│ LoginPage   │
└─────────────┘
```

---

## User Login Flow

```
┌─────────────┐
│   Browser   │
└──────┬──────┘
       │ 1. Enter credentials
       │    (email, password)
       ▼
┌─────────────────┐
│  LoginPage.jsx  │
└──────┬──────────┘
       │ 2. Submit form
       ▼
┌─────────────────┐
│  POST /auth/    │
│     login       │
└──────┬──────────┘
       │ 3. Validate input
       ▼
┌─────────────────┐
│ auth.routes.js  │
└──────┬──────────┘
       │ 4. Query user by email
       ▼
┌─────────────────┐
│   PostgreSQL    │
└──────┬──────────┘
       │ 5. Return user data
       ▼
┌─────────────────┐
│ auth.routes.js  │
└──────┬──────────┘
       │ 6. Compare passwords
       │    (bcrypt.compare)
       │ 7. Generate JWT token
       │    (24h expiration)
       ▼
┌─────────────────┐
│  LoginPage.jsx  │
└──────┬──────────┘
       │ 8. Store in AuthContext
       │    - user data
       │    - JWT token
       │ 9. Store in localStorage
       ▼
┌─────────────────┐
│   AuthContext   │
└──────┬──────────┘
       │ 10. Redirect to /transformer
       ▼
┌─────────────────┐
│ ProtectedRoute  │
└──────┬──────────┘
       │ 11. Check isAuthenticated
       │     ✓ User is authenticated
       ▼
┌─────────────────┐
│ TransformerPage │
└─────────────────┘
```

---

## Protected Route Access Flow

```
┌─────────────┐
│   Browser   │
└──────┬──────┘
       │ 1. Navigate to /transformer
       ▼
┌─────────────────┐
│   App.jsx       │
└──────┬──────────┘
       │ 2. Route matches
       ▼
┌─────────────────┐
│ ProtectedRoute  │
└──────┬──────────┘
       │ 3. Check loading state
       ├─ If loading: Show "Loading..."
       │
       │ 4. Check isAuthenticated
       ├─ If NOT authenticated:
       │  └─> Navigate to /login
       │
       │ If authenticated:
       ▼
┌─────────────────┐
│ TransformerPage │
│   (Rendered)    │
└─────────────────┘
```

---

## API Call with Authentication Flow

```
┌─────────────────┐
│  React Component│
└──────┬──────────┘
       │ 1. User action
       │    (e.g., load profile)
       ▼
┌─────────────────┐
│   AuthContext   │
└──────┬──────────┘
       │ 2. Get token from state
       ▼
┌─────────────────┐
│  fetch() call   │
│  with headers   │
└──────┬──────────┘
       │ 3. Authorization: Bearer <token>
       ▼
┌─────────────────┐
│ GET /user/      │
│    profile      │
└──────┬──────────┘
       │ 4. Request hits middleware
       ▼
┌─────────────────┐
│ auth.middleware │
└──────┬──────────┘
       │ 5. Extract token from header
       │ 6. Verify JWT signature
       │ 7. Check expiration
       │
       ├─ If invalid/expired:
       │  └─> Return 403 Forbidden
       │
       │ If valid:
       │ 8. Add user to req.user
       ▼
┌─────────────────┐
│ user.routes.js  │
└──────┬──────────┘
       │ 9. Process request
       │    (req.user.id available)
       ▼
┌─────────────────┐
│ user.service.js │
└──────┬──────────┘
       │ 10. Query database
       ▼
┌─────────────────┐
│   PostgreSQL    │
└──────┬──────────┘
       │ 11. Return user profile
       ▼
┌─────────────────┐
│  React Component│
└──────┬──────────┘
       │ 12. Update UI with data
       ▼
┌─────────────┐
│   Browser   │
└─────────────┘
```

---

## State Persistence Flow (Page Refresh)

```
┌─────────────┐
│   Browser   │
└──────┬──────┘
       │ 1. Page refresh/reload
       ▼
┌─────────────────┐
│   App.jsx       │
│  (AuthProvider) │
└──────┬──────────┘
       │ 2. Initialize
       ▼
┌─────────────────┐
│  AuthContext    │
│   useEffect()   │
└──────┬──────────┘
       │ 3. Check localStorage
       │    - authToken
       │    - user
       ▼
┌─────────────────┐
│  localStorage   │
└──────┬──────────┘
       │ 4. Return stored data
       ▼
┌─────────────────┐
│  AuthContext    │
└──────┬──────────┘
       │ 5. Restore state
       │    - setToken(storedToken)
       │    - setUser(storedUser)
       │ 6. setLoading(false)
       ▼
┌─────────────────┐
│  ProtectedRoute │
└──────┬──────────┘
       │ 7. isAuthenticated = true
       │    (token exists)
       ▼
┌─────────────────┐
│ Protected Page  │
│   (Rendered)    │
└─────────────────┘
```

---

## Logout Flow

```
┌─────────────┐
│   Browser   │
└──────┬──────┘
       │ 1. Click logout button
       ▼
┌─────────────────┐
│  React Component│
└──────┬──────────┘
       │ 2. Call logout()
       ▼
┌─────────────────┐
│  AuthContext    │
└──────┬──────────┘
       │ 3. Clear state
       │    - setUser(null)
       │    - setToken(null)
       ▼
┌─────────────────┐
│  localStorage   │
└──────┬──────────┘
       │ 4. Remove items
       │    - removeItem('authToken')
       │    - removeItem('user')
       ▼
┌─────────────────┐
│  ProtectedRoute │
└──────┬──────────┘
       │ 5. isAuthenticated = false
       │    (no token)
       ▼
┌─────────────────┐
│  Navigate to    │
│    /login       │
└─────────────────┘
```

---

## Password Change Flow

```
┌─────────────┐
│   Browser   │
└──────┬──────┘
       │ 1. Enter current & new password
       ▼
┌─────────────────┐
│ UserProfile.jsx │
└──────┬──────────┘
       │ 2. Validate passwords match
       │ 3. Get token from AuthContext
       ▼
┌─────────────────┐
│ POST /user/     │
│ change-password │
└──────┬──────────┘
       │ 4. Authorization: Bearer <token>
       ▼
┌─────────────────┐
│ auth.middleware │
└──────┬──────────┘
       │ 5. Verify JWT token
       │ 6. Add user to req.user
       ▼
┌─────────────────┐
│ user.routes.js  │
└──────┬──────────┘
       │ 7. Call service
       ▼
┌─────────────────┐
│ user.service.js │
└──────┬──────────┘
       │ 8. Get current password hash
       │ 9. Compare with provided
       │    (bcrypt.compare)
       │ 10. Hash new password
       │ 11. Update in database
       ▼
┌─────────────────┐
│   PostgreSQL    │
└──────┬──────────┘
       │ 12. Return success
       ▼
┌─────────────────┐
│ UserProfile.jsx │
└──────┬──────────┘
       │ 13. Show success message
       ▼
┌─────────────┐
│   Browser   │
└─────────────┘
```

---

## Error Handling Flow

```
┌─────────────────┐
│  Any Request    │
└──────┬──────────┘
       │
       ├─ Network Error
       │  └─> Catch in component
       │      └─> Show error message
       │
       ├─ 400 Bad Request
       │  └─> Invalid input
       │      └─> Show validation error
       │
       ├─ 401 Unauthorized
       │  └─> No token
       │      └─> Redirect to /login
       │
       ├─ 403 Forbidden
       │  └─> Invalid/expired token
       │      └─> Logout user
       │      └─> Redirect to /login
       │
       ├─ 404 Not Found
       │  └─> Resource doesn't exist
       │      └─> Show error message
       │
       ├─ 409 Conflict
       │  └─> Duplicate user
       │      └─> Show "User exists" error
       │
       └─ 500 Internal Server Error
          └─> Server error
              └─> Show generic error
              └─> Log to console
```

---

## Database Schema Relationships

```
┌─────────────────────┐
│      users          │
│  ─────────────────  │
│  id (PK, UUID)      │
│  username (UNIQUE)  │
│  email (UNIQUE)     │
│  password (HASHED)  │
│  full_name          │
│  created_at         │
│  updated_at         │
└──────────┬──────────┘
           │
           │ 1:1
           ├──────────────────────┐
           │                      │
           │ 1:N                  │
           ▼                      ▼
┌──────────────────┐   ┌───────────────────┐
│  subscriptions   │   │ billing_details   │
│  ──────────────  │   │ ───────────────── │
│  id (PK, UUID)   │   │ id (PK, UUID)     │
│  user_id (FK)    │   │ user_id (FK, UQ)  │
│  status          │   │ card_last4        │
│  level           │   │ card_brand        │
│  starts_at       │   │ billing_address   │
│  expires_at      │   │ billing_city      │
│  created_at      │   │ billing_country   │
│  updated_at      │   │ billing_zip       │
└──────────────────┘   │ created_at        │
                       │ updated_at        │
                       └───────────────────┘
```

---

## Component Hierarchy

```
App.jsx
│
├─ AuthProvider (Context)
│  │
│  ├─ BrowserRouter
│  │  │
│  │  ├─ Route: / → LandingPage
│  │  │
│  │  ├─ Route: /login → LoginPage
│  │  │
│  │  ├─ Route: /register → RegisterPage
│  │  │
│  │  ├─ Route: /transformer
│  │  │  └─ ProtectedRoute
│  │  │     └─ TransformerPage
│  │  │
│  │  └─ Route: /editor
│  │     └─ ProtectedRoute
│  │        └─ EditorPage
│  │           └─ UserProfile (modal)
```

---

## Security Layers

```
┌─────────────────────────────────────┐
│  Layer 1: Frontend Validation       │
│  - Email format                     │
│  - Password strength                │
│  - Required fields                  │
└─────────────┬───────────────────────┘
              │
              ▼
┌─────────────────────────────────────┐
│  Layer 2: Protected Routes (Client) │
│  - ProtectedRoute component         │
│  - Redirect if not authenticated    │
└─────────────┬───────────────────────┘
              │
              ▼
┌─────────────────────────────────────┐
│  Layer 3: API Input Validation      │
│  - Required fields check            │
│  - Data type validation             │
└─────────────┬───────────────────────┘
              │
              ▼
┌─────────────────────────────────────┐
│  Layer 4: JWT Middleware            │
│  - Token presence verification      │
│  - Token signature validation       │
│  - Token expiration check           │
└─────────────┬───────────────────────┘
              │
              ▼
┌─────────────────────────────────────┐
│  Layer 5: Database Security         │
│  - Parameterized queries            │
│  - Foreign key constraints          │
│  - Unique constraints               │
└─────────────┬───────────────────────┘
              │
              ▼
┌─────────────────────────────────────┐
│  Layer 6: Password Hashing          │
│  - bcrypt with 10 salt rounds       │
│  - Never store plain text           │
└─────────────────────────────────────┘
```

This multi-layered approach ensures security at every level of the application.
