# Admin Panel Testing Guide

## Overview

This document provides comprehensive testing guidelines for the Admin Panel, including backend API tests, frontend component tests, and integration tests.

## Test Structure

```
ROSSUMXML/
├── test-admin-api.sh           # Backend API automated tests
├── frontend/
│   └── src/
│       └── __tests__/         # Frontend component tests (to be added)
│           └── admin/
│               ├── UserManagement.test.jsx
│               ├── SubscriptionManagement.test.jsx
│               └── SecurityDashboard.test.jsx
└── docs/
    └── ADMIN_TESTING_GUIDE.md  # This file
```

## Backend API Tests

### Test Suite: `test-admin-api.sh`

**Total Tests:** 16  
**Test Categories:**
1. User Management (8 tests)
2. Role Management (3 tests)
3. Subscription Management (3 tests)
4. Security & Authorization (2 tests)

### Running Backend Tests

```bash
# Prerequisites
# 1. Ensure database is running
docker-compose up -d db

# 2. Ensure backend server is running
cd backend && npm start

# 3. Run the test suite
./test-admin-api.sh
```

### Test Cases

#### 1. User Management Tests

| Test # | Test Name | Expected Result |
|--------|-----------|-----------------|
| 1 | List all users | Returns paginated user list with status 200 |
| 2 | List users with pagination | Returns page 1 with limit 10 |
| 3 | Search users | Filters users by search term |
| 4 | Create new user | Creates user and returns 201 with user ID |
| 5 | Get specific user details | Returns full user profile with roles |
| 6 | Update user details | Updates user and returns 200 |
| 15 | Deactivate user | Soft-deletes user and returns 200 |

#### 2. Role Management Tests

| Test # | Test Name | Expected Result |
|--------|-----------|-----------------|
| 7 | List all roles | Returns all system roles |
| 8 | Assign role to user | Assigns role and returns 200 |
| 16 | Revoke role from user | Removes role and returns 200 |

#### 3. Subscription Management Tests

| Test # | Test Name | Expected Result |
|--------|-----------|-----------------|
| 10 | List all subscriptions | Returns paginated subscription list |
| 11 | Filter subscriptions by status | Returns only active subscriptions |
| 12 | Update subscription | Updates subscription level/status |

#### 4. Permission Tests

| Test # | Test Name | Expected Result |
|--------|-----------|-----------------|
| 9 | List all permissions | Returns all available permissions |

#### 5. Security & Authorization Tests

| Test # | Test Name | Expected Result |
|--------|-----------|-----------------|
| 13 | Unauthorized access (no token) | Returns 401 Unauthorized |
| 14 | Invalid token | Returns 401 Unauthorized |

### Expected Test Results

```
============================================================================
TEST SUMMARY
============================================================================
Total Tests:  16
Passed:       16
Failed:       0
Success Rate: 100.0%
============================================================================

✓ ALL TESTS PASSED!
```

## Frontend Component Tests

### Testing Framework

- **Test Runner:** Vitest (or Jest)
- **Testing Library:** React Testing Library
- **Utilities:** @testing-library/user-event

### Installing Test Dependencies

```bash
cd frontend
npm install --save-dev @testing-library/react @testing-library/jest-dom @testing-library/user-event vitest jsdom
```

### UserManagement Component Tests

**File:** `frontend/src/__tests__/admin/UserManagement.test.jsx`

```javascript
import { describe, it, expect, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import UserManagement from '../../components/admin/UserManagement';

describe('UserManagement Component', () => {
  it('renders user management interface', () => {
    render(<UserManagement />);
    expect(screen.getByText('User Management')).toBeInTheDocument();
    expect(screen.getByText('+ Create User')).toBeInTheDocument();
  });

  it('displays users in a table', async () => {
    render(<UserManagement />);
    await waitFor(() => {
      expect(screen.getByRole('table')).toBeInTheDocument();
    });
  });

  it('opens create user modal on button click', async () => {
    const user = userEvent.setup();
    render(<UserManagement />);
    
    const createButton = screen.getByText('+ Create User');
    await user.click(createButton);
    
    expect(screen.getByText('Create New User')).toBeInTheDocument();
  });

  it('filters users by search term', async () => {
    const user = userEvent.setup();
    render(<UserManagement />);
    
    const searchInput = screen.getByPlaceholderText(/search by email/i);
    await user.type(searchInput, 'john');
    
    // Verify API call was made with search parameter
    // (using mocked fetch or MSW)
  });

  it('assigns role to user', async () => {
    const user = userEvent.setup();
    render(<UserManagement />);
    
    // Wait for users to load
    await waitFor(() => {
      expect(screen.getByRole('table')).toBeInTheDocument();
    });
    
    // Find role dropdown and select a role
    const roleSelect = screen.getAllByRole('combobox')[0];
    await user.selectOptions(roleSelect, 'developer');
    
    // Verify success message or role badge appears
  });
});
```

### SubscriptionManagement Component Tests

**Test Cases:**
1. Renders subscription table
2. Filters by status
3. Filters by level
4. Updates subscription inline
5. Handles pagination

### SecurityDashboard Component Tests

**Test Cases:**
1. Displays security statistics
2. Shows active threats
3. Renders recent events table
4. Auto-refresh toggles correctly
5. Exports to CSV
6. Refreshes data on button click

## Integration Tests

### End-to-End Testing Strategy

**Tools:** Playwright or Cypress

### Key User Flows to Test

#### Flow 1: Admin Creates and Manages User

```
1. Login as admin
2. Navigate to /admin
3. Click "Users" tab
4. Click "+ Create User"
5. Fill in user details
6. Submit form
7. Verify user appears in table
8. Assign role to user
9. Edit user details
10. Deactivate user
```

#### Flow 2: Subscription Management

```
1. Login as admin
2. Navigate to /admin
3. Click "Subscriptions" tab
4. Filter by status="active"
5. Update subscription level
6. Set expiry date
7. Verify changes persist
```

#### Flow 3: Security Monitoring

```
1. Login as admin
2. Navigate to /admin
3. Click "Security" tab
4. Verify stats display
5. Check threats panel
6. Scroll through events table
7. Export to CSV
8. Verify download
```

## Performance Tests

### Load Testing

**Tool:** Apache JMeter or k6

**Scenarios:**

1. **User List Performance**
   - 100 concurrent requests to `/api/admin/users`
   - Response time < 500ms
   - 0% error rate

2. **Bulk User Creation**
   - Create 1000 users sequentially
   - Average response time < 200ms
   - No database errors

3. **Subscription Updates**
   - Update 500 subscriptions concurrently
   - Response time < 300ms
   - Data consistency verified

### Frontend Performance

**Metrics to Track:**

- Page load time < 2 seconds
- Time to Interactive (TTI) < 3 seconds
- First Contentful Paint (FCP) < 1 second
- User table render time < 500ms
- Chart render time < 300ms

**Testing Tools:**

- Lighthouse CI
- WebPageTest
- Chrome DevTools Performance profiler

## Security Tests

### Authentication Tests

1. **Token Validation**
   - Test with expired token → 401
   - Test with invalid token → 401
   - Test with no token → 401

2. **Permission Checks**
   - Test each endpoint without required permission → 403
   - Test with wrong role → 403
   - Test with correct permission → 200

3. **SQL Injection Prevention**
   - Test search parameter with SQL injection: `' OR 1=1 --`
   - Test pagination with negative values
   - Test with special characters

4. **XSS Prevention**
   - Test user creation with script tags
   - Test search with HTML entities
   - Verify output is sanitized

### RBAC Tests

**Test Matrix:**

| Endpoint | Admin | Developer | Viewer | Expected Result |
|----------|-------|-----------|--------|-----------------|
| GET /api/admin/users | ✅ | ❌ | ❌ | Admin: 200, Others: 403 |
| POST /api/admin/users | ✅ | ❌ | ❌ | Admin: 201, Others: 403 |
| PUT /api/admin/users/:id | ✅ | ❌ | ❌ | Admin: 200, Others: 403 |
| DELETE /api/admin/users/:id | ✅ | ❌ | ❌ | Admin: 200, Others: 403 |

## Regression Tests

### Before Each Release

Run the following regression test suite:

1. **Backend API Tests** - `./test-admin-api.sh`
2. **Frontend Unit Tests** - `npm test`
3. **Integration Tests** - `npm run test:e2e`
4. **Security Scan** - `npm audit`
5. **Performance Tests** - Lighthouse CI

### Smoke Tests (Production)

After deployment to production:

1. Login as admin
2. View user list
3. Create test user
4. Assign role
5. Update subscription
6. View security dashboard
7. Delete test user
8. Logout

## Test Data

### Test Users

```json
{
  "admin_user": {
    "email": "admin@test.com",
    "password": "Admin123!",
    "role": "admin"
  },
  "developer_user": {
    "email": "dev@test.com",
    "password": "Dev123!",
    "role": "developer"
  },
  "viewer_user": {
    "email": "viewer@test.com",
    "password": "Viewer123!",
    "role": "viewer"
  }
}
```

### Test Subscriptions

```json
[
  {
    "user_email": "user1@test.com",
    "level": "free",
    "status": "active"
  },
  {
    "user_email": "user2@test.com",
    "level": "premium",
    "status": "active",
    "expires_at": "2026-12-31"
  }
]
```

## Continuous Integration

### GitHub Actions Workflow

```yaml
name: Admin Panel Tests

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v2
      
      - name: Setup Node.js
        uses: actions/setup-node@v2
        with:
          node-version: '18'
      
      - name: Start Database
        run: docker-compose up -d db
      
      - name: Install Dependencies
        run: |
          cd backend && npm install
          cd ../frontend && npm install
      
      - name: Run Backend Tests
        run: ./test-admin-api.sh
      
      - name: Run Frontend Tests
        run: cd frontend && npm test
      
      - name: Generate Coverage Report
        run: cd frontend && npm run test:coverage
```

## Coverage Goals

- **Backend:** 80% code coverage
- **Frontend:** 70% code coverage
- **Integration:** All critical user flows covered

## Troubleshooting Tests

### Common Issues

1. **Database Connection Error**
   - Ensure Docker is running
   - Check `docker-compose up -d db`
   - Verify POSTGRES_HOST in .env

2. **Token Expired**
   - Login again to get fresh token
   - Check JWT_SECRET is set

3. **Permission Denied**
   - Verify test user has admin role
   - Check role_permissions table

4. **Tests Timing Out**
   - Increase timeout in test configuration
   - Check network connectivity
   - Verify backend is running

## Reporting

### Test Report Format

```
============================================================================
ADMIN PANEL TEST REPORT
Date: 2025-01-10
Environment: Development
============================================================================

Backend API Tests:        16/16 PASSED ✅
Frontend Unit Tests:       -/- PENDING ⏳
Integration Tests:         -/- PENDING ⏳
Security Tests:            -/- PENDING ⏳
Performance Tests:         -/- PENDING ⏳

Total Coverage:           TBD%
============================================================================
```

## Next Steps

1. ✅ Complete backend API tests
2. ⏳ Implement frontend unit tests
3. ⏳ Set up integration tests with Playwright
4. ⏳ Add security penetration tests
5. ⏳ Configure CI/CD pipeline
6. ⏳ Achieve 80% code coverage

## Resources

- [Jest Documentation](https://jestjs.io/)
- [React Testing Library](https://testing-library.com/react)
- [Playwright Documentation](https://playwright.dev/)
- [Vitest Documentation](https://vitest.dev/)

## Support

For testing support, contact:
- Testing Team: qa@rossumxml.com
- DevOps: devops@rossumxml.com
