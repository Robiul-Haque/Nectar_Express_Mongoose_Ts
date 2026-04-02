import { Router } from "express";
import { createPaymentIntent } from "./payment.controller";
import authenticate from "../../middlewares/auth.middleware";
import { stripeWebhook } from "./payment.webhook";

const router = Router();

router.post("/intent", authenticate(["user"]), createPaymentIntent);

export default router;