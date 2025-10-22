# Backend Dependencies

Complete list of npm dependencies for the backend (AWS Lambda function).

## Production Dependencies

```json
{
  "pg": "^8.11.3",              // PostgreSQL client for database operations
  "bcryptjs": "^2.4.3",         // Password hashing for user authentication
  "jsonwebtoken": "^9.0.2",     // JWT token generation and verification
  "uuid": "^9.0.1",             // UUID generation for unique identifiers
  "xml2js": "^0.6.2",           // XML to JSON conversion
  "fast-xml-parser": "^4.3.2",  // High-performance XML parser
  "axios": "^1.6.5",            // HTTP client for external API calls
  "dotenv": "^16.3.1"           // Environment variable management
}
```

## Installation

```bash
cd backend
npm install
```

## Key Package Usage

### Database (`pg`)
- Used for all PostgreSQL database connections
- Handles connection pooling
- Executes SQL queries for:
  - User authentication
  - RBAC permission checks
  - Transformation mapping storage
  - Webhook event logging
  - Analytics tracking

### Authentication (`bcryptjs`, `jsonwebtoken`)
- `bcryptjs`: Hashes user passwords with salt rounds (10)
- `jsonwebtoken`: Creates and verifies JWT tokens for API authentication
- Token expiration: 24 hours by default

### UUID Generation (`uuid`)
- Generates UUIDs for:
  - User IDs
  - Mapping IDs
  - Webhook event IDs
  - API key IDs
  - Audit log entries

### XML Processing (`xml2js`, `fast-xml-parser`)
- `xml2js`: Used for complex XML transformations with attribute handling
- `fast-xml-parser`: Used for high-performance parsing in webhook processing
- Both support:
  - XML to JSON conversion
  - JSON to XML conversion
  - Namespace handling
  - Attribute preservation

### HTTP Client (`axios`)
- Used for:
  - Rossum API integration
  - External webhook calls
  - IP geolocation lookups
  - API key validation

### Environment Variables (`dotenv`)
- Loads configuration from `.env` files
- Manages:
  - Database connection strings
  - JWT secrets
  - API keys
  - Environment-specific settings

## Development Dependencies

Not required for Lambda deployment but useful for local development:

```json
{
  "nodemon": "^3.0.2"  // Auto-restart server on file changes (optional)
}
```

## Package Lock

The `package-lock.json` file is committed to ensure consistent dependency versions across environments.

## Security Considerations

1. **Password Hashing**: Uses bcrypt with 10 salt rounds for secure password storage
2. **JWT Security**: Tokens signed with HS256 algorithm and secret key
3. **SQL Injection Prevention**: Uses parameterized queries throughout
4. **XML Bomb Protection**: Parser configured with entity expansion limits
5. **Dependency Updates**: Regularly check for security updates with `npm audit`

## Lambda-Specific Notes

- All dependencies are bundled into the Lambda deployment package
- Total package size should stay under AWS Lambda limits (250MB)
- Cold start time is optimized by using lightweight dependencies
- Database connection pooling configured for Lambda's execution model

## Troubleshooting

### Installation Issues

```bash
# Clear cache and reinstall
rm -rf node_modules package-lock.json
npm cache clean --force
npm install
```

### Security Vulnerabilities

```bash
# Check for vulnerabilities
npm audit

# Auto-fix non-breaking changes
npm audit fix

# Review and fix breaking changes
npm audit fix --force
```

### Version Conflicts

If you encounter version conflicts, check:
1. Node.js version (should be v18.x for Lambda compatibility)
2. npm version (should be 8.x or higher)
3. Platform-specific binaries (especially for `bcrypt`)

## Future Dependencies

Potential additions for new features:
- `sharp` - Image processing if file upload support added
- `pdf-lib` - PDF generation for reports
- `redis` - Caching layer for high-traffic scenarios
- `helmet` - Additional security headers (if using Express server mode)
