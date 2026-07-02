import { Router } from "express";
import authenticate from "../../middlewares/auth.middleware";
import validateRequest from "../../middlewares/validateRequest";
import { authRateLimiter, refreshTokenLimiter } from "../../middlewares/rateLimiter.middleware";
import { emailLoginSchema, emailRegisterSchema, facebookLoginSchema, forgotPasswordSchema, googleLoginSchema, otpVerifySchema, refreshTokenSchema, resetPasswordSchema } from "./auth.validation";
import { adminLogin, emailLogin, facebookLogin, forgotPassword, googleLogin, logout, refreshToken, resetPassword, signUp, verifyOTP } from "./auth.controller";

const router = Router();

// App routes
router.post("/signup", authRateLimiter, validateRequest(emailRegisterSchema), signUp);
router.post("/verify-otp", authRateLimiter, validateRequest(otpVerifySchema), verifyOTP);
router.post("/email/login", authRateLimiter, validateRequest(emailLoginSchema), emailLogin);
router.post("/refresh-token", refreshTokenLimiter, validateRequest(refreshTokenSchema), refreshToken);
router.post("/logout", authenticate(["user", "admin"]), logout);
router.post("/forgot-password", authRateLimiter, validateRequest(forgotPasswordSchema), forgotPassword);
router.post("/reset-password", authRateLimiter, validateRequest(resetPasswordSchema), resetPassword);
router.post("/firebase/google-login", authRateLimiter, validateRequest(googleLoginSchema), googleLogin);
router.post("/firebase/facebook-login", authRateLimiter, validateRequest(facebookLoginSchema), facebookLogin);

// Admin routes
router.post("/admin/login", authRateLimiter, validateRequest(emailLoginSchema), adminLogin);
router.post("/admin/refresh-token", refreshTokenLimiter, validateRequest(refreshTokenSchema), refreshToken);
router.post("/admin/logout", authenticate(["admin"]), logout);

export default router;