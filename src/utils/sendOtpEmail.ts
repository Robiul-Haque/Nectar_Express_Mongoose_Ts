import nodemailer from "nodemailer";
import logger from "./logger";
import { env } from "../config/env";

interface OTPParams {
    to: string;
    toName?: string;
    otp: string;
}

export const transporter = nodemailer.createTransport({
    host: env.SMTP_HOST,
    port: env.SMTP_PORT,
    secure: env.SMTP_PORT === 465, // true for 465, false for 587
    auth: {
        user: env.SMTP_USER,
        pass: env.SMTP_PASS,
    },
});

// Verify SMTP config
export const verifySMTP = async (): Promise<void> => {
    try {
        await transporter.verify();
        logger.info('📧 SMTP Ready to send emails');
    } catch (error) {
        logger.error(`❌ SMTP Verification Failed: ${(error as Error).message}`);
    }
};

// Send OTP Email
export const sendOTP = async ({ to, toName, otp }: OTPParams) => {
    if (!to || !otp) throw new Error("Missing required parameters");

    const html = `
    <div style="font-family: sans-serif; text-align: center;">
      <h2>Your OTP Code</h2>
      <p>Hi ${toName || "User"},</p>
      <h1 style="color: #2F80ED;">${otp}</h1>
      <p>This OTP is valid for 10 minutes.</p>
    </div>
  `;

    return transporter.sendMail({
        from: `"${env.SENDER_NAME}" <${env.SENDER_EMAIL}>`,
        to,
        subject: "Your OTP Code",
        html,
        text: `Hi ${toName || "User"}, your OTP is ${otp}. Valid for 10 minutes.`,
    });
};

// Safe wrapper with retry
export const sendOTPEmail = async (params: OTPParams, retries = 2) => {
    let attempt = 0;
    while (attempt <= retries) {
        try {
            return await sendOTP(params);
        } catch (err) {
            attempt++;
            logger.warn(`OTP email attempt ${attempt} failed: ${err instanceof Error ? err.message : String(err)}`);
            if (attempt > retries) throw err;
        }
    }
};