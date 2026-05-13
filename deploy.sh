#!/bin/bash

echo "================================="
echo "🚀 Nectar Backend Deployment Start"
echo "================================="

APP_DIR="/var/www/nectar-backend"
APP_NAME="nectar-backend"

echo "📂 Going to project directory..."
cd $APP_DIR || exit

echo "🔄 Pulling latest code from GitHub..."
git fetch origin main
git reset --hard origin/main

echo "📦 Installing dependencies..."
npm install --production

echo "🏗 Building project..."
npm run build

echo "♻️ Reloading PM2 process..."
pm2 reload $APP_NAME --update-env || pm2 start ecosystem.config.js

echo "💾 Saving PM2 state..."
pm2 save

echo "================================="
echo "✅ Deployment Successful!"
echo "================================="