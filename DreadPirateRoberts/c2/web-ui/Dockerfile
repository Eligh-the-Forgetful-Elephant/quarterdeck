FROM node:20-alpine

WORKDIR /app

# Build-time args (baked into the bundle; default for C2-only compose)
ARG REACT_APP_API_URL=https://localhost:8443
ARG REACT_APP_OP_TOKEN=
ENV REACT_APP_API_URL=$REACT_APP_API_URL
ENV REACT_APP_OP_TOKEN=$REACT_APP_OP_TOKEN

# Install dependencies
COPY package*.json ./
RUN npm install

# Copy source code
COPY . .

# Build the application
RUN npm run build

# Install serve to run the application
RUN npm install -g serve

# Expose port
EXPOSE 3000

# Start the application
CMD ["serve", "-s", "build", "-l", "3000"] 