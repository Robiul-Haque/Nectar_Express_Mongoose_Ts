import { Router } from "express";
import { getAllUsers, getAdminProfile, getLocation, getProfile, toggleUserStatus, updateAdminProfile, updateLocation, updateProfile } from "./user.controller";
import authenticate from "../../middlewares/auth.middleware";
import upload from "../../middlewares/upload.middleware";
import validateRequest from "../../middlewares/validateRequest";
import { locationSchema, toggleUserStatusSchema, updateAdminProfileSchema, updateProfileSchema } from "./user.validation";

const router = Router();

router.put("/location-update", authenticate(["user"]), validateRequest(locationSchema), updateLocation);
router.get("/location", authenticate(["user"]), getLocation);
router.patch("/profile-update", authenticate(["user"]), upload.single("avatar"), validateRequest(updateProfileSchema), updateProfile);
router.get("/profile", authenticate(["user"]), getProfile);

// Admin routes
router.get("/admin/profile", authenticate(["admin"]), getAdminProfile);
router.put("/admin/profile-update", authenticate(["admin"]), upload.single("avatar"), validateRequest(updateAdminProfileSchema), updateAdminProfile);
router.get("/all", authenticate(["admin"]), getAllUsers);
router.patch("/toggle-status/:id", authenticate(["admin"]), validateRequest(toggleUserStatusSchema), toggleUserStatus);

export default router;