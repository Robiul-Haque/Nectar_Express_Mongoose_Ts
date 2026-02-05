import nodemailer from "nodemailer";
import dotenv from "dotenv";

dotenv.config();

interface OTPParams {
    to: string;
    toName?: string;
    otp: string;
}

export const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT),
    secure: process.env.SMTP_PORT === "465", // true for 465, false for 587
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
    },
});

// Verify SMTP config
transporter.verify((error, success) => {
    if (error) {
        console.error("SMTP Verification Failed:", error);
    } else {
        console.log("SMTP Ready to send emails ✅");
    }
});

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
        from: `"${process.env.SENDER_NAME}" <${process.env.SENDER_EMAIL}>`,
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
            console.warn(`Attempt ${attempt} failed:`, err);
            if (attempt > retries) throw err;
        }
    }
};