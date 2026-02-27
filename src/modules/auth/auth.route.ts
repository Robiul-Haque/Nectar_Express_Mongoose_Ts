import { Router } from "express";
import { authenticate } from "../../middlewares/auth.middleware";
import { validateRequest } from "../../middlewares/validateRequest";
import { emailLoginSchema, emailRegisterSchema, facebookLoginSchema, forgotPasswordSchema, googleLoginSchema, otpVerifySchema, refreshTokenSchema, resetPasswordSchema } from "./auth.validation";
import { adminLogin, emailLogin, facebookLogin, forgotPassword, googleLogin, logout, refreshToken, resetPassword, signUp, verifyOTP } from "./auth.controller";

const router = Router();

router.post("/signup", validateRequest(emailRegisterSchema), signUp);
router.post("/verify-otp", validateRequest(otpVerifySchema), verifyOTP);
router.post("/email/login", validateRequest(emailLoginSchema), emailLogin);
router.post("/refresh-token", validateRequest(refreshTokenSchema), refreshToken);
router.post("/logout", authenticate(["user", "admin"]), logout);
router.post("/forgot-password", validateRequest(forgotPasswordSchema), forgotPassword);
router.post("/reset-password", validateRequest(resetPasswordSchema), resetPassword);
router.post("/firebase/google-login", validateRequest(googleLoginSchema), googleLogin);
router.post("/firebase/facebook-login", validateRequest(facebookLoginSchema), facebookLogin);

// Admin routes
router.post("/admin/signup", validateRequest(emailLoginSchema), adminLogin);

export default router;