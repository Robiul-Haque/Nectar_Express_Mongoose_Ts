import 'dotenv-safe/config';

export const env = {
    PORT: process.env.PORT || 5000,
    DB_URL: process.env.DB_URL as string,
    NODE_ENV: process.env.NODE_ENV,
    SMTP_HOST: process.env.SMTP_HOST as string,
    SMTP_PORT: Number(process.env.SMTP_PORT),
    SMTP_USER: process.env.SMTP_USER as string,
    SMTP_PASS: process.env.SMTP_PASS as string,
    SENDER_NAME: process.env.SENDER_NAME as string,
    SENDER_EMAIL: process.env.SENDER_EMAIL as string,
    FIREBASE_PROJECT_ID: process.env.FIREBASE_PROJECT_ID as string,
    FIREBASE_CLIENT_EMAIL: process.env.FIREBASE_CLIENT_EMAIL as string,
    FIREBASE_PRIVATE_KEY: process.env.FIREBASE_PRIVATE_KEY as string,
};