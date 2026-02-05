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
};