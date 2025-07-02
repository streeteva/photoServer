# Use official Node image
FROM node:20

# Set working directory
WORKDIR /app

# Copy files
COPY package*.json ./
RUN npm install --omit=dev # Skip dev dependencies

COPY . .

# Start server
EXPOSE 8080
CMD ["node", "server.js"] 
