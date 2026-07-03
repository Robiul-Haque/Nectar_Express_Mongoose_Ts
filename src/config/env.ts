import dotenv from "dotenv";
dotenv.config({ quiet: true });

export const env = {
    PORT: Number(process.env.PORT) || 5000,
    DB_URL: process.env.DB_URL as string,
    NODE_ENV: process.env.NODE_ENV || "development",
    DASHBOARD_URL: process.env.DASHBOARD_URL as string,
    ADMIN_NAME: process.env.ADMIN_NAME as string,
    ADMIN_EMAIL: process.env.ADMIN_EMAIL as string,
    ADMIN_PASSWORD: process.env.ADMIN_PASSWORD as string,
    SALT_ROUNDS: Number(process.env.SALT_ROUNDS) || 12,
    SMTP_HOST: process.env.SMTP_HOST as string,
    SMTP_PORT: Number(process.env.SMTP_PORT) || 587,
    SMTP_USER: process.env.SMTP_USER as string,
    SMTP_PASS: process.env.SMTP_PASS as string,
    SENDER_NAME: process.env.SENDER_NAME as string,
    SENDER_EMAIL: process.env.SENDER_EMAIL as string,
    FIREBASE_PROJECT_ID: process.env.FIREBASE_PROJECT_ID as string,
    FIREBASE_CLIENT_EMAIL: process.env.FIREBASE_CLIENT_EMAIL as string,
    FIREBASE_PRIVATE_KEY: process.env.FIREBASE_PRIVATE_KEY as string,
    JWT_ACCESS_TOKEN: process.env.JWT_ACCESS_TOKEN as string,
    ACCESS_TOKEN_EXPIRES_IN: process.env.ACCESS_TOKEN_EXPIRES_IN || "1d",
    JWT_REFRESH_TOKEN: process.env.JWT_REFRESH_TOKEN as string,
    REFRESH_TOKEN_EXPIRES_IN: process.env.REFRESH_TOKEN_EXPIRES_IN || "7d",
    CLOUDINARY_CLOUD_NAME: process.env.CLOUDINARY_CLOUD_NAME as string,
    CLOUDINARY_API_KEY: process.env.CLOUDINARY_API_KEY as string,
    CLOUDINARY_API_SECRET: process.env.CLOUDINARY_API_SECRET as string,
    STRIPE_SECRET_KEY: process.env.STRIPE_SECRET_KEY as string,
    STRIPE_WEBHOOK_SECRET: process.env.STRIPE_WEBHOOK_SECRET as string,
    REDIS_URL: process.env.REDIS_URL as string,
    USE_CLUSTER: process.env.USE_CLUSTER === 'true'
};