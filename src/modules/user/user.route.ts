import { Router } from "express";
import { getLocation, getProfile, updateLocation, updateProfile } from "./user.controller";
import { authenticate } from "../../middlewares/auth.middleware";
import { upload } from "../../middlewares/upload.middleware";
import { validateRequest } from "../../middlewares/validateRequest";
import { locationSchema, updateProfileSchema } from "./user.validation";

const router = Router();

router.put("/location-update", authenticate(["user"]), validateRequest(locationSchema), updateLocation);
router.get("/location", authenticate(["user"]), getLocation);
router.patch("/profile-update", authenticate(["user"]), validateRequest(updateProfileSchema), upload.single("avatar"), updateProfile);
router.get("/profile", authenticate(["user"]), getProfile);

// Admin routes


export default router;