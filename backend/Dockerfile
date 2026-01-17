# backend/Dockerfile
FROM node:18-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install --omit=dev

# Copy application code
COPY . .

# Expose backend port
EXPOSE 3000

# Start server (Express wrapper for Lambda handler)
CMD ["npm", "start"]