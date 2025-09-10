# Use lightweight Node.js Alpine image
FROM node:20-alpine

# Set working directory
WORKDIR /usr/src/app

# Install required system packages
RUN apk add --no-cache curl python3 make g++

# Copy dependency files first for Docker caching
COPY package*.json ./

# Install only production dependencies
RUN npm ci --only=production

# Copy application source code
COPY . .

# Create logs directory and give write permissions
RUN mkdir -p logs && chown -R node:node logs

# Use non-root user
USER node

# Expose the port your app listens on
EXPOSE 5001

# Healthcheck using curl
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl --fail http://localhost:5001/health || exit 1

# Start the application
CMD ["node", "server.js"]
