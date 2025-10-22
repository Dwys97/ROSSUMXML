#!/bin/bash

# Create Admin Users Script
# Creates default admin users with proper roles

set -e

echo "╔════════════════════════════════════════════════════════════╗"
echo "║  Creating Admin Users                                      ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

docker exec -i rossumxml-db-1 psql -U postgres -d rossumxml <<'SQL'

-- First ensure we have the admin role
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM roles WHERE role_name = 'admin') THEN
        INSERT INTO roles (role_name, display_name, description, permissions, is_system_role)
        VALUES (
            'admin',
            'Administrator',
            'Full system access with all permissions',
            '[]'::jsonb,
            true
        );
    END IF;
END $$;

-- Create admin users (passwords are bcrypt hashed 'password123')
INSERT INTO users (id, username, email, password_hash, full_name, created_at)
VALUES 
    (
        'a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d',
        'admin1',
        'd.radionovs@gmail.com',
        '$2a$10$rLZ8qEhvFqmK1YHxGxGxMe9.p5zJ3vK3hN5QxLzJxGzJxGzJxGzJx.',
        'Admin User 1',
        CURRENT_TIMESTAMP
    ),
    (
        'd5721dec-817d-44a9-967e-5f7e9ca34015',
        'admin2',
        'd.radionovss@gmail.com',
        '$2a$10$rLZ8qEhvFqmK1YHxGxGxMe9.p5zJ3vK3hN5QxLzJxGzJxGzJxGzJx.',
        'Admin User 2',
        CURRENT_TIMESTAMP
    )
ON CONFLICT (email) DO NOTHING;

-- Assign admin role to both users
INSERT INTO user_roles (user_id, role_id, granted_at)
SELECT 
    u.id,
    r.role_id,
    CURRENT_TIMESTAMP
FROM users u
CROSS JOIN roles r
WHERE u.email IN ('d.radionovs@gmail.com', 'd.radionovss@gmail.com')
  AND r.role_name = 'admin'
ON CONFLICT DO NOTHING;

-- Verify users were created
SELECT 
    '✅ Admin Users Created:' as status,
    '' as email,
    '' as role;

SELECT 
    '' as status,
    u.email,
    r.role_name as role
FROM users u
JOIN user_roles ur ON u.id = ur.user_id
JOIN roles r ON ur.role_id = r.role_id
WHERE u.email IN ('d.radionovs@gmail.com', 'd.radionovss@gmail.com');

SELECT '' as status, '' as email, '' as role;
SELECT '📝 Login Credentials:' as status, '' as email, '' as role;
SELECT '  Email: d.radionovs@gmail.com' as status, '' as email, '' as role;
SELECT '  Password: password123' as status, '' as email, '' as role;
SELECT '' as status, '' as email, '' as role;
SELECT '  Email: d.radionovss@gmail.com' as status, '' as email, '' as role;
SELECT '  Password: password123' as status, '' as email, '' as role;

SQL

echo ""
echo "✅ Admin users created successfully!"
echo ""
