import { Router } from "express";
import { googleLogin, signUp, verifyOTP } from "./auth.controller";

const router = Router();

router.post("/signup", signUp);
router.post("/verify-otp", verifyOTP);
router.post("/firebase/google", googleLogin);

export default router;