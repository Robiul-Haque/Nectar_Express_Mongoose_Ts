import { Request, Response } from "express";
import catchAsync from "../../utils/catchAsync";
import sendResponse from "../../utils/sendResponse";
import status from "http-status";
import User from "../user/user.model";
import otpGenerator from "../../utils/otpGenerator";
import { sendOTPEmail } from "../../utils/sendOtpEmail";
import logger from "../../utils/logger";
import { emailLoginSchema, emailRegisterSchema, forgotPasswordSchema, otpVerifySchema, resetPasswordSchema } from "./auth.validation";
import { firebaseAdmin } from "../../config/firebaseAdmin.config";
import { createToken } from "../../utils/createToken";
import { env } from "../../config/env";
import { SignOptions } from "jsonwebtoken";

export const signUp = catchAsync(async (req: Request, res: Response) => {
    // Validate request body
    const parsed = emailRegisterSchema.safeParse(req.body);

    if (!parsed.success) {
        return sendResponse(res, status.BAD_REQUEST, "Invalid input", parsed.error.format());
    }

    const { name, email, password, role = "user" } = parsed.data;

    //  Check if email already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
        return sendResponse(res, status.BAD_REQUEST, "Email already registered");
    }

    // If registering as admin, check if an admin already exists
    if (role === "admin") {
        const existingAdmin = await User.findOne({ role: "admin" });
        if (existingAdmin) {
            return sendResponse(res, status.BAD_REQUEST, "Admin already registered");
        }
    }

    // Generate OTP
    const { otp, otpExpires } = otpGenerator(6, 10); // 6-digit OTP, 10 min expiry

    const user = await User.create({
        name,
        email,
        password,
        provider: "email",
        role,
        otp,
        otpExpires,
    });

    // Send OTP email asynchronously (non-blocking)
    sendOTPEmail({ to: email, toName: name, otp }).catch((err: Error) =>
        logger.error(`[OTP Email Async Error] ${err.message}`)
    );

    return sendResponse(res, status.CREATED, "User registered successfully. OTP sent to email", {
        userId: user._id,
        name: name,
        email: email,
        role: role
    });
});

export const verifyOTP = catchAsync(async (req: Request, res: Response) => {
    const parsed = otpVerifySchema.safeParse(req.body);
    if (!parsed.success) {
        return sendResponse(res, status.BAD_REQUEST, "Invalid input", parsed.error.format());
    }

    const { email, otp } = parsed.data;

    const user = await User.findOne({ email }).select("+otp +otpExpires");
    if (!user) {
        return sendResponse(res, status.NOT_FOUND, "User not found");
    }

    if (!user.otp || !user.otpExpires) {
        return sendResponse(res, status.BAD_REQUEST, "No OTP found. Please request a new one");
    }

    if (new Date() > user.otpExpires) {
        return sendResponse(res, status.BAD_REQUEST, "OTP expired. Please request a new one");
    }

    if (user.otp !== otp) {
        return sendResponse(res, status.BAD_REQUEST, "Invalid OTP");
    }

    // ✅ OTP is valid → mark user as verified & remove OTP
    user.isVerified = true;
    user.otp = undefined;
    user.otpExpires = undefined;
    await user.save();

    return sendResponse(res, status.OK, "Email verified successfully");
});

export const emailLogin = catchAsync(async (req: Request, res: Response) => {
    const parsed = emailLoginSchema.safeParse(req.body);

    if (!parsed.success) {
        return sendResponse(res, status.BAD_REQUEST, "Invalid input", parsed.error.flatten());
    }

    const { email, password, fcmToken, platform, deviceId } = parsed.data;

    const user = await User.findOne({ email, provider: "email" }).select("+password");

    if (!user) {
        return sendResponse(res, status.UNAUTHORIZED, "Invalid email or password");
    }

    const isMatch = await user.comparePassword(password);

    if (!isMatch) {
        return sendResponse(res, status.UNAUTHORIZED, "Invalid email or password");
    }

    if (!user.isVerified) {
        return sendResponse(res, status.UNAUTHORIZED, "Account not verified");
    }

    // Device Token Upsert
    if (fcmToken && platform) {
        await User.updateOne(
            {
                _id: user._id,
                "devices.token": { $ne: fcmToken }
            },
            {
                $push: {
                    devices: {
                        token: fcmToken,
                        platform,
                        deviceId: deviceId || null,
                        lastActive: new Date()
                    }
                }
            }
        );

        await User.updateOne(
            {
                _id: user._id,
                "devices.token": fcmToken
            },
            {
                $set: {
                    "devices.$.lastActive": new Date()
                }
            }
        );
    }

    // Update last login
    user.lastLoginAt = new Date();
    await user.save();

    // Generate Tokens
    const accessToken = createToken(
        "access",
        {
            sub: user._id.toString(),
            role: user.role,
            provider: user.provider,
            v: user.refreshTokenVersion
        },
        {
            secret: env.JWT_ACCESS_TOKEN,
            expiresIn: env.ACCESS_TOKEN_EXPIRES_IN as SignOptions["expiresIn"],
            issuer: "nectar-api",
            audience: "nectar-users"
        }
    );

    const refreshToken = createToken(
        "refresh",
        {
            sub: user._id.toString(),
            v: user.refreshTokenVersion
        },
        {
            secret: env.JWT_REFRESH_TOKEN,
            expiresIn: env.REFRESH_TOKEN_EXPIRES_IN as SignOptions["expiresIn"],
            issuer: "nectar-api",
            audience: "nectar-users"
        }
    );

    // Set Refresh Token in HTTP-Only Cookie
    res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: env.NODE_ENV === "production", // true in production
        sameSite: env.NODE_ENV === "production" ? "none" : "lax",
        maxAge: 1000 * 60 * 60 * 24 * 7 // 7 days
    });

    return sendResponse(res, status.OK, "Login successful", {
        accessToken
    });
});

export const forgotPassword = catchAsync(async (req: Request, res: Response) => {
    const parsed = forgotPasswordSchema.safeParse(req.body);

    if (!parsed.success) {
        return sendResponse(res, status.BAD_REQUEST, "Invalid input", parsed.error.format());
    }

    const { email } = parsed.data;

    // Check if user exists and is email provider
    const user = await User.findOne({ email, provider: "email" });
    if (!user) return sendResponse(res, status.OK, "If the email exists, a reset token has been sent");

    // Generate OTP / Reset Token
    const { otp, otpExpires } = otpGenerator(6, 10);

    user.otp = otp;
    user.otpExpires = otpExpires;
    await user.save();

    // Send OTP Email asynchronously
    sendOTPEmail({ to: email, toName: user.name, otp }).catch(err => logger.error(`[Forgot Password Email Error]: ${err.message}`));

    return sendResponse(res, status.OK, "If the email exists, a reset token has been sent");
});

export const resetPassword = catchAsync(async (req: Request, res: Response) => {
    const parsed = resetPasswordSchema.safeParse(req.body);

    if (!parsed.success) {
        return sendResponse(res, status.BAD_REQUEST, "Invalid input", parsed.error.format());
    }

    const { email, otp, newPassword } = parsed.data;

    // 1️⃣ Find user
    const user = await User.findOne({ email, provider: "email" }).select("+password +otp +otpExpires");
    if (!user) {
        return sendResponse(res, status.BAD_REQUEST, "Invalid token or email");
    }

    // 2️⃣ Validate OTP
    if (!user.otp || !user.otpExpires || user.otp !== otp || user.otpExpires < new Date()) {
        return sendResponse(res, status.BAD_REQUEST, "Invalid or expired token");
    }

    // 3️⃣ Update password
    user.password = newPassword;

    // 4️⃣ Clear OTP & increment refreshTokenVersion
    user.otp = undefined;
    user.otpExpires = undefined;
    user.refreshTokenVersion += 1;

    await user.save();

    return sendResponse(res, status.OK, "Password reset successfully. Please login with new password");
});

export const googleLogin = catchAsync(async (req: Request, res: Response) => {
    const { idToken, fcmToken, platform, deviceId } = req.body;

    if (!idToken) {
        return sendResponse(res, status.BAD_REQUEST, "Firebase ID token is required");
    }

    const decodedToken = await firebaseAdmin.auth().verifyIdToken(idToken);

    const { email, name, picture } = decodedToken;

    if (!email) {
        return sendResponse(res, status.UNAUTHORIZED, "Invalid Google account");
    }

    let user = await User.findOne({ email });

    if (!user) {
        user = await User.create({
            name: name || email.split("@")[0],
            email,
            provider: "google",
            avatar: picture || "",
            isVerified: true,
            role: "user",
            devices: fcmToken && platform ?
                [
                    {
                        token: fcmToken,
                        platform,
                        deviceId: deviceId || null,
                        lastActive: new Date()
                    }
                ]
                :
                []
        });

    } else {
        if (user.provider !== "google") {
            user.provider = "google";
            user.isVerified = true;
        }

        await user.save();

        if (fcmToken && platform) {
            await User.updateOne(
                {
                    _id: user._id,
                    "devices.token": { $ne: fcmToken }
                },
                {
                    $push: {
                        devices: {
                            token: fcmToken,
                            platform,
                            deviceId: deviceId || null,
                            lastActive: new Date()
                        }
                    }
                }
            );

            await User.updateOne(
                {
                    _id: user._id,
                    "devices.token": fcmToken
                },
                {
                    $set: {
                        "devices.$.lastActive": new Date()
                    }
                }
            );
        }
    }

    user.lastLoginAt = new Date();
    await user.save();

    const accessToken = createToken(
        "access",
        {
            sub: user._id.toString(),
            role: user.role,
            provider: user.provider,
            v: user.refreshTokenVersion
        },
        {
            secret: env.JWT_ACCESS_TOKEN,
            expiresIn: env.ACCESS_TOKEN_EXPIRES_IN as SignOptions["expiresIn"],
        }
    );

    const refreshToken = createToken(
        "refresh",
        {
            sub: user._id.toString(),
            v: user.refreshTokenVersion
        },
        {
            secret: env.JWT_REFRESH_TOKEN,
            expiresIn: env.REFRESH_TOKEN_EXPIRES_IN as SignOptions["expiresIn"],
        }
    );

    return sendResponse(res, status.OK, "Google login successful", {
        accessToken,
        refreshToken,
        user: {
            id: user._id,
            name: user.name,
            email: user.email,
            role: user.role,
            avatar: user.avatar,
            provider: user.provider
        }
    });
});

export const facebookLogin = catchAsync(async (req: Request, res: Response) => {
    const { idToken, fcmToken } = req.body;

    if (!idToken) {
        return sendResponse(res, status.BAD_REQUEST, "Firebase ID token is required");
    }

    // Verify Firebase ID token (revocation check enabled)
    const decodedToken = await firebaseAdmin.auth().verifyIdToken(idToken, true);

    const { email, name, picture, firebase } = decodedToken;

    // Strict provider validation
    if (!firebase?.sign_in_provider?.includes("facebook.com")) {
        return sendResponse(res, status.UNAUTHORIZED, "Invalid Facebook authentication");
    }

    if (!email) {
        return sendResponse(res, status.UNAUTHORIZED, "Email not available from Facebook account");
    }

    // Find existing user by email
    let user = await User.findOne({ email });

    if (!user) {
        // Create new Facebook user
        user = await User.create({
            name: name || email.split("@")[0],
            email,
            provider: "facebook",
            avatar: picture || "",
            isVerified: true,
            role: "user",
        });
    } else {
        // Handle provider switch or linking
        if (user.provider !== "facebook") {
            user.provider = "facebook";
        }

        user.isVerified = true;

        // Optional: Keep avatar updated
        if (picture && user.avatar !== picture) {
            user.avatar = picture;
        }

        await user.save();
    }

    // Add FCM token (idempotent)
    if (fcmToken) {
        await User.updateOne({ _id: user._id }, { $addToSet: { fcmTokens: fcmToken } });
    }

    // Issue backend JWT
    const accessToken = createToken(
        "access",
        {
            sub: user._id.toString(),
            role: user.role,
            provider: user.provider,
        },
        {
            secret: env.JWT_ACCESS_TOKEN,
            expiresIn: env.ACCESS_TOKEN_EXPIRES_IN as SignOptions["expiresIn"],
            issuer: "nectar-api",
            audience: "nectar-users",
        }
    );

    return sendResponse(
        res,
        status.OK,
        "Facebook login successful",
        {
            accessToken,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role,
                avatar: user.avatar,
                provider: user.provider,
            },
        }
    );
});


// Admin controllers
export const adminLogin = catchAsync(async (req: Request, res: Response) => {
    const parsed = emailLoginSchema.safeParse(req.body);

    if (!parsed.success) {
        return sendResponse(
            res,
            status.BAD_REQUEST,
            "Invalid input",
            parsed.error.flatten()
        );
    }

    const { email, password } = parsed.data;

    // Optimized Query (Only necessary fields)
    const admin = await User.findOne({
        email,
        provider: "email",
        role: "admin"
    })
        .select("+password isVerified refreshTokenVersion")
        .lean(false);

    if (!admin) {
        return sendResponse(res, status.UNAUTHORIZED, "Invalid credentials");
    }

    const isMatch = await admin.comparePassword(password);

    if (!isMatch) {
        return sendResponse(res, status.UNAUTHORIZED, "Invalid credentials");
    }

    if (!admin.isVerified) {
        return sendResponse(res, status.FORBIDDEN, "Admin account not verified");
    }

    // Update last login (atomic)
    await User.updateOne(
        { _id: admin._id },
        { $set: { lastLoginAt: new Date() } }
    );

    // Access Token (Short-lived)
    const accessToken = createToken(
        "access",
        {
            sub: admin._id.toString(),
            role: admin.role,
            v: admin.refreshTokenVersion
        },
        {
            secret: env.JWT_ACCESS_TOKEN,
            expiresIn: "10m",
            issuer: "nectar-api",
            audience: "nectar-admin"
        }
    );

    // Refresh Token
    const refreshToken = createToken(
        "refresh",
        {
            sub: admin._id.toString(),
            v: admin.refreshTokenVersion
        },
        {
            secret: env.JWT_REFRESH_TOKEN,
            expiresIn: "7d",
            issuer: "nectar-api",
            audience: "nectar-admin"
        }
    );

    // Secure Cookie (Admin Scope Only)
    res.cookie("adminRefreshToken", refreshToken, {
        httpOnly: true,
        secure: env.NODE_ENV === "production",
        sameSite: env.NODE_ENV === "production" ? "none" : "lax",
        path: "/auth/admin",
        maxAge: 1000 * 60 * 60 * 24 * 7
    });

    return sendResponse(res, status.OK, "Admin login successful", {
        accessToken
    });
});
