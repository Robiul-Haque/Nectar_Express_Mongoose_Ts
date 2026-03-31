import { Router } from "express";
import authenticate from "../../middlewares/auth.middleware";
import validateRequest from "../../middlewares/validateRequest";
import { registerDeviceSchema, toggleNotificationSchema } from "./notification.validation";
import { registerDevice, toggleNotification } from "./notification.controller";

const router = Router();

router.post("/register-device", authenticate(["user"]), validateRequest(registerDeviceSchema), registerDevice);
router.patch("/toggle", authenticate(["user"]), validateRequest(toggleNotificationSchema), toggleNotification);

export default router;