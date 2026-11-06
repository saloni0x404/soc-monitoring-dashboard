FROM node:20-slim

# sqlite3 needs these to build its native bindings on slim images
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 make g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev || npm install --omit=dev

COPY . .

# SQLite data lives here - mount a volume so it survives container restarts
RUN mkdir -p /app/database
VOLUME ["/app/database"]

ENV NODE_ENV=production
EXPOSE 3000

CMD ["node", "app.js"]
