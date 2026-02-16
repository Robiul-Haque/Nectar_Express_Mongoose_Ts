import { Router } from "express";
import { emailLogin, facebookLogin, forgotPassword, googleLogin, resetPassword, signUp, verifyOTP } from "./auth.controller";

const router = Router();

router.post("/signup", signUp);
router.post("/verify-otp", verifyOTP);
router.post("/email/login", emailLogin);
router.post("/reset-password", resetPassword);
router.post("/forgot-password", forgotPassword);
router.post("/firebase/google-login", googleLogin);
router.post("/firebase/facebook-login", facebookLogin);

export default router;