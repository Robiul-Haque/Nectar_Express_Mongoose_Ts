import { Router } from "express";
import { createPaymentIntent } from "./payment.controller";
import authenticate from "../../middlewares/auth.middleware";
import { stripeWebhook } from "./payment.webhook";

const router = Router();

router.post("/intent", authenticate(["user"]), createPaymentIntent);
router.post("/webhook", express.raw({ type: "application/json" }), stripeWebhook);

export default router;