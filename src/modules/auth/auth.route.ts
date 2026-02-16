import { Router } from "express";
import { facebookLogin, googleLogin, signUp, verifyOTP } from "./auth.controller";

const router = Router();

router.post("/signup", signUp);
router.post("/verify-otp", verifyOTP);
router.post("/firebase/google-login", googleLogin);
router.post("/firebase/facebook-login", facebookLogin);

export default router;