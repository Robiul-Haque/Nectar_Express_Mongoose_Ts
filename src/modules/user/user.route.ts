import { Router } from "express";
import { getProfile, updateProfile } from "./user.controller";
import { authenticate } from "../../middlewares/auth.middleware";
import { upload } from "../../middlewares/upload.middleware";
import { validateRequest } from "../../middlewares/validateRequest";
import { updateProfileSchema } from "./user.validation";

const router = Router();

router.patch("/profile-update", authenticate(["user"]), validateRequest(updateProfileSchema), upload.single("avatar"), updateProfile);
router.get("/profile", authenticate(["user"]), getProfile);

export default router;