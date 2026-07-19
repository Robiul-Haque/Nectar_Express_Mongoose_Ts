#!/bin/bash

set -e

START_TIME=$(date +%s)

echo "=========================================="
echo "🚀 Nectar Backend Deployment Started"
echo "=========================================="

APP_DIR="/home/robiul/vps/apps/nectar-api"
APP_NAME="nectar-api"

echo ""
echo "📂 Switching to project directory..."
cd "$APP_DIR"

echo ""
echo "🌿 Current Branch:"
git branch --show-current

echo ""
echo "📥 Fetching latest code from GitHub..."
git fetch origin main --prune

echo ""
echo "🔄 Resetting to latest commit..."
git reset --hard origin/main

echo ""
echo "🟢 Node Version"
node -v

echo ""
echo "📦 NPM Version"
npm -v

echo ""
echo "📦 Installing dependencies..."
npm ci

echo ""
echo "🏗️ Building TypeScript project..."
npm run build

echo ""
echo "♻️ Reloading PM2 application..."
pm2 reload "$APP_NAME" --update-env

echo ""
echo "✅ PM2 Reload Successful"

echo ""
echo "💾 Saving PM2 process list..."
pm2 save

echo ""
echo "📊 PM2 Status"
pm2 list

echo ""
echo "📌 Latest Commit"
git log -1 --pretty=format:"%h | %an | %ar | %s"

END_TIME=$(date +%s)
TOTAL_TIME=$((END_TIME - START_TIME))

echo ""
echo ""
echo "⏱ Deployment Time : ${TOTAL_TIME}s"

echo ""
echo "🎉 Deployment completed successfully!"
echo "=========================================="