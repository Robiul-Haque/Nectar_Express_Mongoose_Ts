import { Router } from "express";
import { getProfile, updateProfile } from "./user.controller";
import { authenticate } from "../../middlewares/auth.middleware";

const router = Router();

router.patch("/profile-update", authenticate(["user"]), updateProfile);
router.get("/profile", authenticate(["user"]), getProfile);

export default router;