# E2E Testing Plan - Admin Panel Frontend Integration

## 🎯 Objective
Test all 11 admin panel endpoints through the browser UI to verify complete frontend-backend integration.

## 🔐 Test Credentials
- **Admin User:** d.radionovs@gmail.com
- **Password:** Danka2006!
- **Access:** http://localhost:5173/admin

## 📋 Test Checklist

### Phase 1: Authentication & Access (5 minutes)
- [ ] **Test 1.1:** Login with admin credentials
  - Navigate to: http://localhost:5173/login
  - Enter: d.radionovs@gmail.com / Danka2006!
  - Expected: Redirect to landing page, show user menu

- [ ] **Test 1.2:** Access admin panel
  - Navigate to: http://localhost:5173/admin
  - Expected: Admin dashboard loads with 3 tabs (Users, Subscriptions, Security)
  - Expected: "Users" tab active by default

### Phase 2: User Management Tab (15 minutes)

#### A. List Users (GET /api/admin/users)
- [ ] **Test 2.1:** View user list
  - Verify: Users table displays with columns (Email, Username, Full Name, Roles, Subscription, Created, Actions)
  - Expected: At least 5 users visible
  - Expected: Pagination controls visible

- [ ] **Test 2.2:** Search functionality
  - Type in search box: "radionovs"
  - Expected: Filter to user(s) matching search
  - Clear search
  - Expected: All users return

- [ ] **Test 2.3:** Filter by role
  - Select role dropdown: "admin"
  - Expected: Filter to admin users only
  - Reset to "All Roles"

#### B. Create User (POST /api/admin/users)
- [ ] **Test 2.4:** Create new user
  - Click: "+ Create User" button
  - Fill form:
    - Email: e2etest@example.com
    - Username: e2etester
    - Full Name: E2E Test User
    - Password: TestPass123!
    - Subscription: Basic
  - Click: "Create User"
  - Expected: Success alert
  - Expected: New user appears in table

#### C. View User Details (GET /api/admin/users/:id)
- [ ] **Test 2.5:** View user profile
  - Click: "Edit" button on e2etest@example.com
  - Expected: Modal opens with user details
  - Verify: All fields populated correctly

#### D. Update User (PUT /api/admin/users/:id)
- [ ] **Test 2.6:** Update user information
  - In Edit modal, change:
    - Full Name: E2E Test User Updated
    - Phone: +1234567890
    - City: Test City
    - Country: Test Country
  - Click: "Update User"
  - Expected: Success alert
  - Expected: Changes reflected in table

#### E. Assign Role (POST /api/admin/users/:id/roles)
- [ ] **Test 2.7:** Assign developer role
  - Find e2etest@example.com in table
  - In Roles column, select dropdown: "developer"
  - Expected: Success alert
  - Expected: "developer" badge appears in Roles column

#### F. Revoke Role (DELETE /api/admin/users/:id/roles/:roleId)
- [ ] **Test 2.8:** Remove developer role
  - Find e2etest@example.com in table
  - Click "×" button on "developer" badge
  - Confirm dialog
  - Expected: Success alert
  - Expected: "developer" badge disappears

#### G. Deactivate User (DELETE /api/admin/users/:id)
- [ ] **Test 2.9:** Deactivate test user
  - Find e2etest@example.com in table
  - Click: "Deactivate" button
  - Confirm dialog
  - Expected: Success alert
  - Expected: User subscription becomes "inactive" or user disappears from active list

### Phase 3: Subscription Management Tab (10 minutes)

#### A. List Subscriptions (GET /api/admin/subscriptions)
- [ ] **Test 3.1:** View subscriptions
  - Click: "Subscriptions" tab
  - Expected: Subscriptions table displays (User, Email, Level, Status, Starts, Expires, Actions)
  - Expected: At least 6 subscriptions visible

- [ ] **Test 3.2:** Filter by status
  - Select status filter: "active"
  - Expected: Only active subscriptions shown
  - Reset to "All Statuses"

- [ ] **Test 3.3:** Filter by level
  - Select level filter: "professional"
  - Expected: Only professional subscriptions shown
  - Reset to "All Levels"

#### B. Update Subscription (PUT /api/admin/subscriptions/:userId)
- [ ] **Test 3.4:** Change subscription level
  - Find any user with "free" subscription
  - Change Level dropdown: "professional"
  - Expected: Immediate update (dropdown changes)
  - Expected: Success alert

- [ ] **Test 3.5:** Change subscription status
  - Find same user
  - Change Status dropdown: "active"
  - Expected: Immediate update
  - Expected: Success alert

- [ ] **Test 3.6:** Set expiry date
  - Click: "Set Expiry" button
  - Enter: 2026-12-31
  - Expected: Success alert
  - Refresh page
  - Expected: Expiry date shows "12/31/2026"

### Phase 4: Security Dashboard Tab (5 minutes)

#### A. View Security Dashboard
- [ ] **Test 4.1:** Access security tab
  - Click: "Security" tab
  - Expected: Dashboard loads with stats cards
  - Expected: Stats show:
    - Total Events: 156
    - Failed Auth: 3
    - Active Threats: 0
    - Success Rate: 98%

- [ ] **Test 4.2:** View recent events
  - Scroll to "Recent Security Events" table
  - Expected: At least 3 mock events displayed
  - Expected: Events show: Time, Event Type, Action, User, IP, Severity, Status

- [ ] **Test 4.3:** Export to CSV
  - Click: "📥 Export CSV" button
  - Expected: CSV file downloads
  - Expected: Filename: security-audit-YYYY-MM-DD.csv
  - Open file
  - Expected: Contains event data in CSV format

### Phase 5: Error Handling & Edge Cases (5 minutes)

- [ ] **Test 5.1:** Invalid subscription level
  - In Subscriptions tab, manually try to set level to "invalid"
  - Expected: Error handling (validation or error message)

- [ ] **Test 5.2:** Unauthorized access simulation
  - Open DevTools → Application → Local Storage
  - Delete token
  - Try to access /admin
  - Expected: Redirect to login

- [ ] **Test 5.3:** Network error simulation
  - Open DevTools → Network → Throttle to "Offline"
  - Try to create user
  - Expected: Error alert with meaningful message
  - Set back to "No throttling"

### Phase 6: Roles & Permissions (5 minutes)

#### A. View Roles (GET /api/admin/roles)
- [ ] **Test 6.1:** Verify roles loaded
  - In Users tab → Create User modal
  - Check role dropdown in "Add role" select
  - Expected: Roles loaded (admin, user, developer, viewer)
  
- [ ] **Test 6.2:** Verify permissions
  - Check Network tab for GET /api/admin/roles response
  - Expected: Each role includes permissions array
  - Expected: Admin role has 23 permissions

## 🎯 Success Criteria

### ✅ All Tests Must Pass:
1. **Authentication:** Login successful, admin access granted
2. **User Management:** All 9 user operations work (list, create, view, update, delete, assign role, revoke role, search, filter)
3. **Subscription Management:** All 4 subscription operations work (list, update level, update status, set expiry)
4. **Security Dashboard:** Dashboard displays, shows mock stats, CSV export works
5. **Error Handling:** Graceful handling of errors, unauthorized access blocked
6. **Data Integrity:** All changes persist after page refresh
7. **UI/UX:** No console errors, smooth interactions, proper loading states

## 📊 Test Results Template

```
═══════════════════════════════════════════════════
   ADMIN PANEL E2E TEST RESULTS
═══════════════════════════════════════════════════
Test Date: YYYY-MM-DD HH:MM
Tester: [Name]
Environment: Development (localhost)
Browser: [Chrome/Firefox/Safari]
───────────────────────────────────────────────────

PHASE 1: Authentication & Access
  ☐ 1.1 Login                        PASS / FAIL
  ☐ 1.2 Admin Access                 PASS / FAIL

PHASE 2: User Management (9 tests)
  ☐ 2.1 List Users                   PASS / FAIL
  ☐ 2.2 Search Users                 PASS / FAIL
  ☐ 2.3 Filter by Role               PASS / FAIL
  ☐ 2.4 Create User                  PASS / FAIL
  ☐ 2.5 View User Details            PASS / FAIL
  ☐ 2.6 Update User                  PASS / FAIL
  ☐ 2.7 Assign Role                  PASS / FAIL
  ☐ 2.8 Revoke Role                  PASS / FAIL
  ☐ 2.9 Deactivate User              PASS / FAIL

PHASE 3: Subscription Management (6 tests)
  ☐ 3.1 List Subscriptions           PASS / FAIL
  ☐ 3.2 Filter by Status             PASS / FAIL
  ☐ 3.3 Filter by Level              PASS / FAIL
  ☐ 3.4 Change Level                 PASS / FAIL
  ☐ 3.5 Change Status                PASS / FAIL
  ☐ 3.6 Set Expiry                   PASS / FAIL

PHASE 4: Security Dashboard (3 tests)
  ☐ 4.1 View Dashboard               PASS / FAIL
  ☐ 4.2 View Events                  PASS / FAIL
  ☐ 4.3 Export CSV                   PASS / FAIL

PHASE 5: Error Handling (3 tests)
  ☐ 5.1 Invalid Data                 PASS / FAIL
  ☐ 5.2 Unauthorized Access          PASS / FAIL
  ☐ 5.3 Network Error                PASS / FAIL

PHASE 6: Roles & Permissions (2 tests)
  ☐ 6.1 Roles Loaded                 PASS / FAIL
  ☐ 6.2 Permissions Verified         PASS / FAIL

───────────────────────────────────────────────────
TOTAL: __ / 23 PASSED

NOTES:
[Add any observations, bugs found, or performance issues]

SCREENSHOTS:
[Attach screenshots of key UI states]

═══════════════════════════════════════════════════
```

## 🚀 Quick Start Commands

```bash
# 1. Ensure backend is running (SAM Local on port 3000)
cd /workspaces/ROSSUMXML
bash start-backend.sh

# 2. Ensure frontend is running (Vite on port 5173)
bash start-frontend.sh

# 3. Open browser
echo "Navigate to: http://localhost:5173/admin"

# 4. Login with admin credentials
# Email: d.radionovs@gmail.com
# Password: Danka2006!
```

## 📝 Post-Test Actions

After completing all tests:

1. **Document Results:**
   - Fill in test results template
   - Take screenshots of each major section
   - Note any bugs or issues

2. **Git Commit:**
   ```bash
   git add frontend/src/components/admin/
   git commit -m "feat: Complete frontend integration for admin panel E2E"
   git push origin copilot/develop-admin-panel-features
   ```

3. **Update Pull Request:**
   - Add test results to PR #6
   - Update PR description with E2E test completion
   - Request review

## 🎬 Next Steps After E2E

If all tests pass:
- ✅ Merge PR to main branch
- ✅ Deploy to staging environment
- ✅ Conduct UAT (User Acceptance Testing)
- ✅ Plan production deployment

If tests fail:
- 🔧 Document failures
- 🔧 Fix issues
- 🔧 Re-run failed tests
- 🔧 Iterate until all pass
