# ROSSUMXML - XML Data Visualization and Transformation Tool

A full-stack web application for XML data visualization, transformation, and mapping with integrated user authentication and subscription management.

## Features

### Core Functionality
- **XML Parsing & Visualization**: Parse and visualize XML structure in a tree format
- **XML Transformation**: Transform XML data using custom mappings
- **Interactive Mapping Editor**: Create and manage XML field mappings
- **Real-time Preview**: See transformation results in real-time

### User Management
- **User Authentication**: Secure login and registration system
- **JWT-based Sessions**: Secure token-based authentication
- **User Profiles**: Manage user information and settings
- **Password Management**: Secure password hashing and change functionality
- **Subscription Management**: Free and paid subscription tiers
- **Billing Integration**: Payment information management

## Technology Stack

### Frontend
- **React 19**: Modern React with hooks
- **Vite**: Fast build tool and dev server
- **React Router**: Client-side routing
- **Context API**: Global state management

### Backend
- **Node.js**: JavaScript runtime
- **Express**: Web application framework
- **PostgreSQL**: Relational database
- **JWT**: JSON Web Tokens for authentication
- **bcrypt**: Password hashing

### Infrastructure
- **Docker**: Containerization
- **Docker Compose**: Multi-container orchestration

## Project Structure

```
ROSSUMXML/
├── backend/
│   ├── db/                    # Database configuration and initialization
│   ├── middleware/            # Express middleware (auth, etc.)
│   ├── routes/                # API route handlers
│   ├── services/              # Business logic services
│   ├── index.js               # Lambda handler (AWS)
│   ├── server.js              # Express server
│   └── package.json
├── frontend/
│   ├── src/
│   │   ├── components/        # React components
│   │   ├── context/           # React Context providers
│   │   ├── pages/             # Page components
│   │   └── App.jsx            # Main app component
│   └── package.json
├── docs/                      # Documentation
│   ├── AUTHENTICATION.md      # API documentation
│   └── AUTH_IMPLEMENTATION.md # Implementation guide
└── docker-compose.yml         # Docker services configuration
```

## Getting Started

### Prerequisites
- Node.js 18 or higher
- Docker and Docker Compose
- npm or yarn

### Quick Start with Docker

1. **Clone the repository**
   ```bash
   git clone https://github.com/Dwys97/ROSSUMXML.git
   cd ROSSUMXML
   ```

2. **Start all services**
   ```bash
   docker-compose up --build
   ```

   This will start:
   - Backend API on `http://localhost:3000`
   - Frontend on `http://localhost:5173`
   - PostgreSQL database on `localhost:5432`

3. **Access the application**
   - Open your browser to `http://localhost:5173`
   - Register a new account or login

### Manual Setup

#### Backend Setup

1. **Install dependencies**
   ```bash
   cd backend
   npm install
   ```

2. **Configure environment**
   Create a `.env` file in the `backend` directory:
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

3. **Start the server**
   ```bash
   npm run dev
   ```

#### Frontend Setup

1. **Install dependencies**
   ```bash
   cd frontend
   npm install
   ```

2. **Start development server**
   ```bash
   npm run dev
   ```

#### Database Setup

The database schema will be automatically initialized when the backend starts. If you need to manually initialize:

```bash
psql -U postgres -d rossumxml -f backend/db/init.sql
```

## Authentication

The application includes a complete authentication system:

- **Registration**: Create new user accounts with email validation
- **Login**: Authenticate with email and password
- **Protected Routes**: Certain pages require authentication
- **JWT Tokens**: Secure session management
- **Password Security**: bcrypt hashing with strong password requirements

For detailed API documentation, see [docs/AUTHENTICATION.md](./docs/AUTHENTICATION.md).

For implementation details, see [docs/AUTH_IMPLEMENTATION.md](./docs/AUTH_IMPLEMENTATION.md).

## Usage

### Registration

1. Navigate to `/register`
2. Fill in your email, full name, and password
3. Optionally add billing details
4. Click "Зарегистрироваться" (Register)

### Login

1. Navigate to `/login`
2. Enter your email and password
3. Click "Login"
4. You'll be redirected to the transformer page

### XML Transformation

1. Login to access protected pages
2. Navigate to `/transformer`
3. Upload or paste your source XML
4. Upload or paste your destination XML template
5. Create field mappings
6. Click transform to see results

## API Endpoints

### Authentication
- `POST /auth/register` - Register new user
- `POST /auth/login` - Authenticate user

### User Management (Protected)
- `GET /user/profile` - Get user profile
- `POST /user/change-password` - Change password
- `POST /user/update-billing` - Update billing details

### XML Operations
- `POST /transform` - Transform XML (returns XML)
- `POST /transform-json` - Transform XML (returns JSON)
- `POST /schema/parse` - Parse XML to tree structure

## Security

- **Password Hashing**: bcrypt with 10 salt rounds
- **JWT Tokens**: 24-hour expiration
- **Input Validation**: All user inputs are validated
- **SQL Injection Protection**: Parameterized queries
- **CORS**: Configured for secure cross-origin requests
- **Environment Variables**: Sensitive data in `.env` files

## Development

### Running Tests

```bash
# Backend tests
cd backend
npm test

# Frontend tests
cd frontend
npm test
```

### Building for Production

```bash
# Build frontend
cd frontend
npm run build

# The backend runs directly with Node.js
cd backend
npm start
```

## Database Schema

### Users
- Unique email and username
- Hashed passwords
- Profile information
- Timestamps

### Subscriptions
- User relationship
- Status (active/inactive/suspended)
- Level (free/basic/professional/enterprise)
- Expiration dates

### Billing Details
- Card information (last 4 digits only)
- Billing address
- One-to-one relationship with users

See `backend/db/init.sql` for complete schema.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

See LICENSE file for details.

## Support

For issues or questions, please open an issue on GitHub.

## Acknowledgments

- XML parsing powered by `@xmldom/xmldom`
- Authentication using `jsonwebtoken`
- Password hashing with `bcryptjs`
