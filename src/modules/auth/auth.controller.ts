import { Request, Response } from "express";
import catchAsync from "../../utils/catchAsync";
import sendResponse from "../../utils/sendResponse";
import status from "http-status";
import jwt, { JwtPayload, SignOptions } from "jsonwebtoken";
import { env } from "../../config/env";
import User from "../user/user.model";
import otpGenerator from "../../utils/otpGenerator";
import { sendOTPEmail } from "../../utils/sendOtpEmail";
import logger from "../../utils/logger";
import { firebaseAdmin } from "../../config/firebaseAdmin.config";
import { createToken } from "../../utils/createToken";
import LoginHistory from "../adminCustomer/loginHistory.model";
import { getRequestContext } from "../../utils/requestContext";
import redis from "../../utils/redis";

// ─── Constants ────────────────────────────────────────────────────────────────
const MAX_FAILED_ATTEMPTS = 3;
const LOCK_DURATION_MS = 20 * 60 * 1000;          // 20 minutes
const LOCK_DURATION_SECONDS = 20 * 60;             // 20 minutes in seconds
const REDIS_LOCK_PREFIX = "auth:lock:";            // Redis key prefix for lock cache

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Record a login event in LoginHistory (fire-and-forget, non-blocking).
 */
const recordLoginEvent = (
    userId: string,
    event: string,
    provider: string,
    req: Request,
    meta?: Record<string, unknown>
): void => {
    const ctx = getRequestContext(req);
    LoginHistory.create({
        userId,
        event,
        provider,
        ip: ctx.ip,
        userAgent: ctx.userAgent,
        platform: ctx.platform,
        deviceId: ctx.deviceId,
        appVersion: ctx.appVersion,
        meta
    }).catch((err) => logger.error(`[LoginHistory] Failed to record event: ${err.message}`));
};

/**
 * Check if an account is currently locked.
 * Uses Redis cache first (fast path), falls back to DB.
 * Returns: { locked: boolean, lockedUntil: Date | null, remainingMs: number }
 */
const checkAccountLock = async (email: string): Promise<{ locked: boolean; lockedUntil: Date | null; remainingMs: number }> => {
    const cacheKey = `${REDIS_LOCK_PREFIX}${email.toLowerCase()}`;

    // Fast path: Redis cache check
    if (redis) {
        try {
            const cached = await redis.get(cacheKey);
            if (cached) {
                const lockedUntil = new Date(cached);
                const now = new Date();
                if (lockedUntil > now) {
                    return { locked: true, lockedUntil, remainingMs: lockedUntil.getTime() - now.getTime() };
                }
            }
        } catch (err) {
            logger.warn(`[Auth] Redis lock check failed, falling back to DB: ${err}`);
        }
    }

    // DB fallback
    const user = await User.findOne({ email: email.toLowerCase() }).select("loginLockedUntil").lean<{ loginLockedUntil?: Date | null }>();
    if (!user || !user.loginLockedUntil) return { locked: false, lockedUntil: null, remainingMs: 0 };

    const lockedUntil = user.loginLockedUntil;
    const now = new Date();
    if (lockedUntil > now) {
        const remainingMs = lockedUntil.getTime() - now.getTime();
        // Re-populate Redis cache
        if (redis) {
            try {
                const ttlSeconds = Math.ceil(remainingMs / 1000);
                await redis.set(cacheKey, lockedUntil.toISOString(), "EX", ttlSeconds);
            } catch (_) { /* non-critical */ }
        }
        return { locked: true, lockedUntil, remainingMs };
    }

    return { locked: false, lockedUntil: null, remainingMs: 0 };
};

/**
 * Increment failed login count. If threshold reached, lock the account.
 * Returns the updated failedLoginCount after increment.
 */
const handleFailedLogin = async (
    userId: string,
    email: string,
    provider: string,
    req: Request
): Promise<void> => {
    const user = await User.findById(userId).select("failedLoginCount loginLockedUntil");
    if (!user) return;

    user.failedLoginCount = (user.failedLoginCount || 0) + 1;

    if (user.failedLoginCount >= MAX_FAILED_ATTEMPTS) {
        const lockedUntil = new Date(Date.now() + LOCK_DURATION_MS);
        user.loginLockedUntil = lockedUntil;
        user.failedLoginCount = 0; // reset after lock so next cycle is clean

        await user.save();

        // Cache lock in Redis
        if (redis) {
            try {
                await redis.set(`${REDIS_LOCK_PREFIX}${email.toLowerCase()}`, lockedUntil.toISOString(), "EX", LOCK_DURATION_SECONDS);
            } catch (_) { /* non-critical */ }
        }

        // Record lock event
        recordLoginEvent(userId, "account_locked", provider, req, {
            lockedUntil: lockedUntil.toISOString(),
            reason: `${MAX_FAILED_ATTEMPTS} consecutive failed login attempts`
        });
    } else {
        await user.save();
    }

    // Always record the failed attempt
    recordLoginEvent(userId, "login_failed", provider, req, {
        attempt: user.failedLoginCount || MAX_FAILED_ATTEMPTS,
        maxAttempts: MAX_FAILED_ATTEMPTS
    });
};

/**
 * Reset failed login counter and clear lock on successful login.
 */
const handleSuccessfulLogin = async (
    userId: string,
    email: string,
    provider: string,
    req: Request
): Promise<void> => {
    const ctx = getRequestContext(req);

    await User.updateOne(
        { _id: userId },
        {
            $set: {
                lastLoginAt: new Date(),
                failedLoginCount: 0,
                loginLockedUntil: null,
                lastKnownIp: ctx.ip,
                ...(ctx.appVersion && { appVersion: ctx.appVersion })
            }
        }
    );

    // Clear Redis lock cache
    if (redis) {
        try {
            await redis.del(`${REDIS_LOCK_PREFIX}${email.toLowerCase()}`);
        } catch (_) { /* non-critical */ }
    }

    // Record success event
    recordLoginEvent(userId, "login_success", provider, req);
};

// ─── Controllers ──────────────────────────────────────────────────────────────

export const signUp = catchAsync(async (req: Request, res: Response) => {
    const { name, email, password, role = "user" } = req.body;

    //  Check if email already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) return sendResponse(res, status.BAD_REQUEST, "Email already registered");

    // If registering as admin, check if an admin already exists
    if (role === "admin") {
        const existingAdmin = await User.findOne({ role: "admin" });
        if (existingAdmin) return sendResponse(res, status.BAD_REQUEST, "Admin already registered");
    }

    // Generate OTP
    const { otp, otpExpires } = otpGenerator(6, 10); // 6-digit OTP, 10 min expiry

    const user = await User.create({
        name,
        email,
        password,
        provider: "email",
        role,
        avatar: { url: undefined, publicId: undefined },
        otp,
        otpExpires,
    });

    // Send OTP email asynchronously (non-blocking)
    sendOTPEmail({ to: email, toName: name, otp }).catch((err: Error) => logger.error(`[OTP Email Async Error] ${err.message}`));

    return sendResponse(res, status.CREATED, "User registered successfully. OTP sent to email", null, {
        userId: user._id,
        name: name,
        email: email,
        role: role
    });
});

export const verifyOTP = catchAsync(async (req: Request, res: Response) => {
    const { email, otp } = req.body;

    const user = await User.findOne({ email }).select("+otp +otpExpires");
    if (!user) return sendResponse(res, status.NOT_FOUND, "User not found");

    if (!user.otp || !user.otpExpires) return sendResponse(res, status.BAD_REQUEST, "No OTP found. Please request a new one");
    if (new Date() > user.otpExpires) return sendResponse(res, status.BAD_REQUEST, "OTP expired. Please request a new one");
    if (user.otp !== otp) return sendResponse(res, status.BAD_REQUEST, "Invalid OTP");

    // Mark user as verified & remove OTP
    user.isVerified = true;
    user.otp = undefined;
    user.otpExpires = undefined;
    await user.save();

    // Record OTP verification event
    recordLoginEvent(user._id.toString(), "otp_verified", user.provider, req);

    return sendResponse(res, status.OK, "Email verified successfully");
});

export const emailLogin = catchAsync(async (req: Request, res: Response) => {
    const { email, password } = req.body;

    // ─── Brute-force: check lock BEFORE touching DB user ──────────────────────
    const lockState = await checkAccountLock(email);
    if (lockState.locked) {
        const remainingMinutes = Math.ceil(lockState.remainingMs / 60000);
        return sendResponse(res, status.TOO_MANY_REQUESTS, `Account temporarily locked due to too many failed login attempts. Please try again in ${remainingMinutes} minute(s) or contact support.`, null, {
            lockedUntil: lockState.lockedUntil,
            remainingMs: lockState.remainingMs
        });
    }

    const user = await User.findOne({ email, provider: "email" }).select("+password");
    if (!user) return sendResponse(res, status.UNAUTHORIZED, "Invalid email or password");
    if (!user.isActive) return sendResponse(res, status.UNAUTHORIZED, "Account is inactive. Please contact support");

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
        // Increment failed count & potentially lock
        await handleFailedLogin(user._id.toString(), email, "email", req);
        // Check if we just triggered a lock
        const newCount = (user.failedLoginCount || 0) + 1;
        const attemptsLeft = MAX_FAILED_ATTEMPTS - newCount;
        if (attemptsLeft <= 0) {
            return sendResponse(res, status.TOO_MANY_REQUESTS, `Account locked for ${LOCK_DURATION_MS / 60000} minutes due to too many failed attempts. Please contact support or wait.`);
        }
        return sendResponse(res, status.UNAUTHORIZED, `Invalid email or password. ${attemptsLeft} attempt(s) remaining before account is locked.`);
    }

    if (!user.isVerified) return sendResponse(res, status.UNAUTHORIZED, "Account not verified");

    // ─── Successful login ─────────────────────────────────────────────────────
    await handleSuccessfulLogin(user._id.toString(), email, "email", req);

    // Generate access Tokens
    const accessToken = createToken(
        "access",
        { sub: user._id.toString(), role: user.role, provider: user.provider, v: user.refreshTokenVersion },
        { secret: env.JWT_ACCESS_TOKEN, expiresIn: env.ACCESS_TOKEN_EXPIRES_IN as SignOptions["expiresIn"], issuer: "nectar-api", audience: "nectar-users" }
    );

    // Generate refresh token with version for revocation
    const refreshToken = createToken(
        "refresh",
        { sub: user._id.toString(), v: user.refreshTokenVersion },
        { secret: env.JWT_REFRESH_TOKEN, expiresIn: env.REFRESH_TOKEN_EXPIRES_IN as SignOptions["expiresIn"], issuer: "nectar-api", audience: "nectar-users" }
    );

    // Set cookies for development
    if (env.NODE_ENV === "development") res.cookie("accessToken", accessToken, { httpOnly: true, secure: false, sameSite: "lax", maxAge: 15 * 60 * 1000 });

    // Set HTTP-only cookies for refresh token
    res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: env.NODE_ENV === "production",
        sameSite: env.NODE_ENV === "production" ? "none" : "lax",
        maxAge: 1000 * 60 * 60 * 24 * 7
    });

    return sendResponse(res, status.OK, "Login successful", null, { accessToken });
});

export const refreshToken = catchAsync(async (req: Request, res: Response) => {
    // Get refresh token from cookie
    const refreshToken = req.cookies?.refreshToken;
    if (!refreshToken) return sendResponse(res, status.UNAUTHORIZED, "Refresh token not found");

    // Verify refresh token
    let payload: JwtPayload;
    try {
        payload = jwt.verify(refreshToken, env.JWT_REFRESH_TOKEN) as JwtPayload;
    } catch (err) {
        return sendResponse(res, status.UNAUTHORIZED, "Invalid or expired refresh token");
    }

    // Find user and check refreshTokenVersion
    const user = await User.findById(payload.sub);
    if (!user || payload.v !== user.refreshTokenVersion) return sendResponse(res, status.UNAUTHORIZED, "Refresh token revoked");

    // isActive check
    if (!user.isActive) return sendResponse(res, status.UNAUTHORIZED, "Account is inactive. Please contact support");

    // Generate new tokens
    const accessToken = createToken(
        "access",
        {
            sub: user._id.toString(),
            role: user.role,
            provider: user.provider,
            v: user.refreshTokenVersion,
        },
        {
            secret: env.JWT_ACCESS_TOKEN,
            expiresIn: env.ACCESS_TOKEN_EXPIRES_IN as SignOptions["expiresIn"],
            issuer: "nectar-api",
            audience: "nectar-users",
        }
    );

    const newRefreshToken = createToken(
        "refresh",
        {
            sub: user._id.toString(),
            v: user.refreshTokenVersion,
        },
        {
            secret: env.JWT_REFRESH_TOKEN,
            expiresIn: env.REFRESH_TOKEN_EXPIRES_IN as SignOptions["expiresIn"],
            issuer: "nectar-api",
            audience: "nectar-users",
        }
    );

    // Set cookies
    res.cookie("accessToken", accessToken, {
        httpOnly: true,
        secure: env.NODE_ENV === "production",
        sameSite: env.NODE_ENV === "production" ? "none" : "lax",
        maxAge: 15 * 60 * 1000, // 15 min
    });

    res.cookie("refreshToken", newRefreshToken, {
        httpOnly: true,
        secure: env.NODE_ENV === "production",
        sameSite: env.NODE_ENV === "production" ? "none" : "lax",
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    return sendResponse(res, status.OK, "Tokens refreshed successfully", null, { accessToken });
});

export const logout = catchAsync(async (req: Request, res: Response) => {
    const userId = req.user?.sub;
    if (!userId) return res.status(status.UNAUTHORIZED).json({ success: false, message: "Unauthorized" });

    // Invalidate all refresh tokens for this user by incrementing version
    await User.findByIdAndUpdate(userId, { $inc: { refreshTokenVersion: 1 } });

    // Record logout event (fire and forget)
    const user = await User.findById(userId).select("email provider").lean<{ email: string; provider: string }>();
    if (user) recordLoginEvent(userId, "logout", user.provider, req);

    // Clear cookies
    res.clearCookie("accessToken", {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: process.env.NODE_ENV === "production" ? "none" : "lax"
    });

    res.clearCookie("refreshToken", {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: process.env.NODE_ENV === "production" ? "none" : "lax"
    });

    return sendResponse(res, status.OK, "Logged out successfully");
});

export const forgotPassword = catchAsync(async (req: Request, res: Response) => {
    const { email } = req.body;

    // Check if user exists and is email provider
    const user = await User.findOne({ email, provider: "email" });
    if (!user) return sendResponse(res, status.OK, "If the email exists, a reset token has been sent");

    // isActive check
    if (!user.isActive) return sendResponse(res, status.UNAUTHORIZED, "Account is inactive. Please contact support");

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
    const { email, otp, newPassword } = req.body;

    const user = await User.findOne({ email, provider: "email" }).select("+password +otp +otpExpires");
    if (!user) return sendResponse(res, status.BAD_REQUEST, "Invalid token or email");

    // isActive check
    if (!user.isActive) return sendResponse(res, status.UNAUTHORIZED, "Account is inactive. Please contact support");

    // Validate OTP
    if (!user.otp || !user.otpExpires || user.otp !== otp || user.otpExpires < new Date()) return sendResponse(res, status.BAD_REQUEST, "Invalid or expired token");

    // Update password
    user.password = newPassword;
    user.passwordChangedAt = new Date();

    // Clear OTP & increment refreshTokenVersion
    user.otp = undefined;
    user.otpExpires = undefined;
    user.refreshTokenVersion += 1;

    // Clear any active lock when password is reset
    user.loginLockedUntil = null;
    user.failedLoginCount = 0;

    await user.save();

    // Clear Redis lock cache on password reset
    if (redis) {
        try {
            await redis.del(`${REDIS_LOCK_PREFIX}${email.toLowerCase()}`);
        } catch (_) { /* non-critical */ }
    }

    // Record password change event
    recordLoginEvent(user._id.toString(), "password_changed", "email", req);

    return sendResponse(res, status.OK, "Password reset successfully. Please login with new password");
});

export const googleLogin = catchAsync(async (req: Request, res: Response) => {
    const { idToken, fcmToken, platform, deviceId } = req.body;
    if (!idToken) return sendResponse(res, status.BAD_REQUEST, "Firebase ID token is required");

    const decodedToken = await firebaseAdmin.auth().verifyIdToken(idToken);

    const { email, name, picture } = decodedToken;
    if (!email) return sendResponse(res, status.UNAUTHORIZED, "Invalid Google account");

    const ctx = getRequestContext(req);

    let user = await User.findOne({ email });

    if (!user) {
        user = await User.create({
            name: name || email.split("@")[0],
            email,
            provider: "google",
            avatar: picture ? { url: picture } : undefined,
            isVerified: true,
            role: "user",
            lastKnownIp: ctx.ip,
            ...(ctx.appVersion && { appVersion: ctx.appVersion }),
            device: fcmToken && platform ?
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
        // isActive check
        if (!user.isActive) return sendResponse(res, status.UNAUTHORIZED, "Account is inactive. Please contact support");

        if (user.provider !== "google") {
            user.provider = "google";
            user.isVerified = true;
        }

        await user.save();

        if (fcmToken && platform) {
            await User.updateOne(
                { _id: user._id, "device.token": { $ne: fcmToken } },
                { $push: { device: { token: fcmToken, platform, deviceId: deviceId || null, lastActive: new Date() } } }
            );

            await User.updateOne(
                { _id: user._id, "device.token": fcmToken },
                { $set: { "device.$.lastActive": new Date() } }
            );
        }
    }

    user.lastLoginAt = new Date();
    user.lastKnownIp = ctx.ip;
    if (ctx.appVersion) user.appVersion = ctx.appVersion;
    await user.save();

    // Record login event
    recordLoginEvent(user._id.toString(), "login_success", "google", req);

    const accessToken = createToken(
        "access",
        { sub: user._id.toString(), role: user.role, provider: user.provider, v: user.refreshTokenVersion },
        { secret: env.JWT_ACCESS_TOKEN, expiresIn: env.ACCESS_TOKEN_EXPIRES_IN as SignOptions["expiresIn"] }
    );

    const refreshToken = createToken(
        "refresh",
        { sub: user._id.toString(), v: user.refreshTokenVersion },
        { secret: env.JWT_REFRESH_TOKEN, expiresIn: env.REFRESH_TOKEN_EXPIRES_IN as SignOptions["expiresIn"] }
    );

    return sendResponse(res, status.OK, "Google login successful", null, { accessToken, refreshToken, user: { id: user._id, name: user.name, email: user.email, role: user.role, avatar: user.avatar, provider: user.provider } });
});

export const facebookLogin = catchAsync(async (req: Request, res: Response) => {
    const { idToken, fcmToken, platform, deviceId } = req.body;
    if (!idToken) return sendResponse(res, status.BAD_REQUEST, "Firebase ID token is required");

    const decodedToken = await firebaseAdmin.auth().verifyIdToken(idToken, true);
    const { email, name, picture, firebase } = decodedToken;

    if (!firebase?.sign_in_provider?.includes("facebook.com")) return sendResponse(res, status.UNAUTHORIZED, "Invalid Facebook authentication");
    if (!email) return sendResponse(res, status.UNAUTHORIZED, "Email not available from Facebook account");

    const ctx = getRequestContext(req);

    let user = await User.findOne({ email });

    if (!user) {
        user = await User.create({
            name: name || email.split("@")[0],
            email,
            provider: "facebook",
            avatar: picture ? { url: picture } : undefined,
            isVerified: true,
            role: "user",
            lastKnownIp: ctx.ip,
            ...(ctx.appVersion && { appVersion: ctx.appVersion }),
            device: fcmToken && platform ?
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
        // isActive check
        if (!user.isActive) return sendResponse(res, status.UNAUTHORIZED, "Account is inactive. Please contact support");

        if (user.provider !== "facebook") user.provider = "facebook";
        user.isVerified = true;
        user.lastKnownIp = ctx.ip;
        if (ctx.appVersion) user.appVersion = ctx.appVersion;

        if (picture && user.avatar?.url !== picture) user.avatar = { url: picture, publicId: "" };
        await user.save();

        if (fcmToken && platform) {
            await User.updateOne(
                { _id: user._id, "device.token": { $ne: fcmToken } },
                { $push: { device: { token: fcmToken, platform, deviceId: deviceId || null, lastActive: new Date() } } }
            );

            await User.updateOne(
                { _id: user._id, "device.token": fcmToken },
                { $set: { "device.$.lastActive": new Date() } }
            );
        }
    }

    user.lastLoginAt = new Date();
    await user.save();

    // Record login event
    recordLoginEvent(user._id.toString(), "login_success", "facebook", req);

    const accessToken = createToken(
        "access",
        { sub: user._id.toString(), role: user.role, provider: user.provider, v: user.refreshTokenVersion },
        { secret: env.JWT_ACCESS_TOKEN, expiresIn: env.ACCESS_TOKEN_EXPIRES_IN as SignOptions["expiresIn"], issuer: "nectar-api", audience: "nectar-users" }
    );

    return sendResponse(res, status.OK, "Facebook login successful", null, {
        accessToken,
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

// Admin controllers
export const adminLogin = catchAsync(async (req: Request, res: Response) => {
    const { email, password } = req.body;

    // ─── Brute-force: check lock BEFORE touching DB user ──────────────────────
    const lockState = await checkAccountLock(email);
    if (lockState.locked) {
        const remainingMinutes = Math.ceil(lockState.remainingMs / 60000);
        return sendResponse(res, status.TOO_MANY_REQUESTS, `Admin account temporarily locked. Please try again in ${remainingMinutes} minute(s).`, null, {
            lockedUntil: lockState.lockedUntil,
            remainingMs: lockState.remainingMs
        });
    }

    // Check if email exists (any provider email account)
    const user = await User.findOne({ email, provider: "email" }).select("+password role isVerified refreshTokenVersion failedLoginCount loginLockedUntil");

    if (!user) return sendResponse(res, status.UNAUTHORIZED, "Admin email not found");

    if (user.role !== "admin") return sendResponse(res, status.FORBIDDEN, "This account is not authorized as admin");

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
        await handleFailedLogin(user._id.toString(), email, "email", req);
        const newCount = (user.failedLoginCount || 0) + 1;
        const attemptsLeft = MAX_FAILED_ATTEMPTS - newCount;
        if (attemptsLeft <= 0) {
            return sendResponse(res, status.TOO_MANY_REQUESTS, `Admin account locked for ${LOCK_DURATION_MS / 60000} minutes.`);
        }
        return sendResponse(res, status.UNAUTHORIZED, `Incorrect password. ${attemptsLeft} attempt(s) remaining before account is locked.`);
    }

    if (!user.isVerified) return sendResponse(res, status.FORBIDDEN, "Admin account not verified");

    // ─── Successful login ─────────────────────────────────────────────────────
    await handleSuccessfulLogin(user._id.toString(), email, "email", req);

    // Access Token
    const accessToken = createToken(
        "access",
        {
            sub: user._id.toString(),
            role: user.role,
            v: user.refreshTokenVersion
        },
        {
            secret: env.JWT_ACCESS_TOKEN,
            expiresIn: (env.ACCESS_TOKEN_EXPIRES_IN || "10m") as SignOptions["expiresIn"],
            issuer: "nectar-api",
            audience: "nectar-admin"
        }
    );

    // Refresh Token
    const refreshToken = createToken(
        "refresh",
        {
            sub: user._id.toString(),
            v: user.refreshTokenVersion
        },
        {
            secret: env.JWT_REFRESH_TOKEN,
            expiresIn: (env.REFRESH_TOKEN_EXPIRES_IN || "7d") as SignOptions["expiresIn"],
            issuer: "nectar-api",
            audience: "nectar-admin"
        }
    );

    if (env.NODE_ENV === "development") {
        res.cookie("accessToken", accessToken, {
            httpOnly: true,
            secure: false,
            sameSite: "lax",
            maxAge: 15 * 60 * 1000
        });
    }

    // HTTP-only Cookie
    res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: env.NODE_ENV === "production",
        sameSite: env.NODE_ENV === "production" ? "none" : "lax",
        path: "/auth/admin",
        maxAge: 1000 * 60 * 60 * 24 * 7
    });

    return sendResponse(res, status.OK, "Admin login successful", null, { accessToken });
});