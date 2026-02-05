import { Request, Response } from "express";
import catchAsync from "../../utils/catchAsync";
import { emailRegisterSchema } from "./user.validation";
import sendResponse from "../../utils/sendResponse";
import status from "http-status";
import User from "./user.model";
import otpGenerator from "../../utils/otpGenerator";
import { sendOTPEmail } from "../../utils/sendOtpEmail";

export const signUp = catchAsync(async (req: Request, res: Response) => {
    const parsed = emailRegisterSchema.safeParse(req.body);
    if (!parsed.success) return sendResponse(res, status.BAD_REQUEST, "Invalid input", parsed.error.flatten().fieldErrors);

    const { name, email, password } = parsed.data;

    // Check if email exists
    const existingUser = await User.findOne({ email });
    if (existingUser) return sendResponse(res, status.BAD_REQUEST, "Email already registered");

    // Generate OTP
    const { otp, otpExpires } = otpGenerator(4, 10);

    // Create user
    const user = await User.create({
        name,
        email,
        password,
        provider: "email",
        otp,
        otpExpires,
    });

    // Send OTP email async (non-blocking)
    sendOTPEmail({ to: email, toName: name, otp }).catch((err: Error) =>
        console.error("[OTP Email Async Error]", err)
    );

    // Immediate response to client
    sendResponse(res, 201, "User registered successfully. OTP sent to email", { userId: user._id });
});