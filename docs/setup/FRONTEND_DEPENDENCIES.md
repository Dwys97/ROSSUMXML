# Frontend Dependencies

Complete list of npm dependencies for the frontend (React + Vite).

## Production Dependencies

```json
{
  "react": "^19.1.1",                    // React core library
  "react-dom": "^19.1.1",                // React DOM rendering
  "react-router-dom": "^7.1.1"           // Client-side routing
}
```

## Development Dependencies

```json
{
  "@vitejs/plugin-react": "^4.3.4",      // Vite plugin for React
  "vite": "^7.1.7",                      // Build tool and dev server
  "@types/react": "^19.0.7",             // TypeScript types for React (optional)
  "@types/react-dom": "^19.0.3"          // TypeScript types for React DOM (optional)
}
```

## Installation

```bash
cd frontend
npm install
```

## Key Package Usage

### React Ecosystem

#### React (`react` ^19.1.1)
- Core React library
- Component-based UI development
- State management with hooks (useState, useEffect, useContext)
- Features used:
  - Functional components
  - Custom hooks
  - Context API for global state
  - Suspense for code splitting

#### React DOM (`react-dom` ^19.1.1)
- DOM rendering for React components
- Hydration support
- Portal support for modals
- Browser-specific React features

#### React Router DOM (`react-router-dom` ^7.1.1)
- Client-side routing without page reloads
- Routes:
  - `/` - Landing page
  - `/login` - Authentication
  - `/editor` - XML mapping editor
  - `/dashboard` - User dashboard
  - `/admin` - Admin panel
  - `/templates` - Schema template library
- Features used:
  - Nested routes
  - Protected routes (auth guards)
  - Route parameters
  - Programmatic navigation
  - URL search params

### Build Tool

#### Vite (`vite` ^7.1.7)
- Lightning-fast dev server with HMR
- Optimized production builds
- ES modules support
- Configuration:
  - API proxy to `http://localhost:3000`
  - Port: 5173
  - HMR disabled in dev containers for stability
- Build output: `/dist` directory

#### Vite React Plugin (`@vitejs/plugin-react` ^4.3.4)
- React Fast Refresh for HMR
- JSX transformation
- Automatic React import injection
- Development optimizations

## CSS/Styling

The project uses CSS Modules for component styling:
- Scoped styles per component
- No additional CSS-in-JS libraries required
- Module naming: `ComponentName.module.css`

Example:
```javascript
import styles from './Component.module.css';
```

## State Management

- **Local State**: React `useState` hook
- **Global State**: React Context API
- **Server State**: Fetched via native `fetch` API
- No external state management libraries (Redux, Zustand, etc.)

## HTTP Client

Uses native browser `fetch` API:
- No axios or other HTTP client libraries
- JWT tokens sent via Authorization headers
- Error handling with try-catch
- Response interceptors for 401/403 handling

## Development Server Configuration

### Vite Config (`vite.config.js`)

```javascript
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    host: true,
    hmr: {
      clientPort: 5173,
    },
    proxy: {
      '/api': {
        target: 'http://localhost:3000',
        changeOrigin: true,
      }
    }
  }
});
```

## Browser Compatibility

Target browsers (via Vite's default config):
- Chrome/Edge: last 2 versions
- Firefox: last 2 versions
- Safari: last 2 versions
- iOS Safari: last 2 versions

## Bundle Size Optimization

Vite automatically:
- Tree-shakes unused code
- Minifies JavaScript
- Compresses assets
- Generates source maps for debugging
- Code-splits by route

## Security Considerations

1. **XSS Prevention**: React auto-escapes content
2. **CSRF Protection**: JWT tokens in headers (not cookies)
3. **Content Security Policy**: Configured via backend headers
4. **Dependency Scanning**: Run `npm audit` regularly

## Performance Optimizations

- **Code Splitting**: Routes are lazy-loaded
- **Asset Optimization**: Images and fonts optimized by Vite
- **Tree Shaking**: Dead code eliminated in production
- **Minification**: JavaScript and CSS minified
- **Caching**: Long-term caching with content hashes

## Development Workflow

```bash
# Install dependencies
npm install

# Start dev server (with HMR)
npm run dev

# Build for production
npm run build

# Preview production build
npm run preview
```

## Troubleshooting

### Port Already in Use

```bash
# Kill process on port 5173
lsof -ti:5173 | xargs kill -9

# Or change port in vite.config.js
```

### HMR Not Working in Codespaces

HMR is intentionally disabled in dev containers for stability. The server will still auto-reload on file saves.

### Build Errors

```bash
# Clear cache and rebuild
rm -rf node_modules dist .vite
npm install
npm run build
```

### Module Not Found

```bash
# Verify all dependencies are installed
npm install

# Check import paths are correct (case-sensitive)
```

## Future Dependencies

Potential additions for new features:
- `@tanstack/react-query` - Advanced server state management
- `framer-motion` - Animation library
- `react-hook-form` - Form validation
- `zod` - Schema validation
- `recharts` - Advanced charting (beyond current simple charts)
- `react-dropzone` - File upload support
- `react-toastify` - Toast notifications

## TypeScript Support

The project includes TypeScript types for React but doesn't enforce TypeScript compilation. To fully enable TypeScript:

1. Rename `.jsx` files to `.tsx`
2. Add `tsconfig.json`
3. Update Vite config for TypeScript
4. Install additional type definitions as needed

## CSS Modules Configuration

Vite automatically supports CSS Modules with the `.module.css` extension:
- Scoped class names
- Composition support
- No additional configuration needed

## Testing (Future)

Testing dependencies not yet added but recommended:
- `vitest` - Test runner (Vite-native)
- `@testing-library/react` - React component testing
- `@testing-library/user-event` - User interaction simulation
- `jsdom` - DOM implementation for testing
