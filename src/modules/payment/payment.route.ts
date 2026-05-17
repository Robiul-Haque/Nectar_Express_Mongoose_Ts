import { Router } from "express";
import { createPaymentIntent } from "./payment.controller";
import authenticate from "../../middlewares/auth.middleware";
import validateRequest from "../../middlewares/validateRequest";
import { createPaymentIntentSchema } from "./payment.validation";
const router = Router();

router.post("/intent", authenticate(["user"]), validateRequest(createPaymentIntentSchema), createPaymentIntent);

export default router;