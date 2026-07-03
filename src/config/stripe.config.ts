import Stripe from "stripe";
import { env } from "./env";
import logger from "../utils/logger";

let stripeInstance: Stripe | null = null;

if (env.STRIPE_SECRET_KEY) {
    try {
        stripeInstance = new Stripe(env.STRIPE_SECRET_KEY);
    } catch (err) {
        logger.error(`❌ Stripe initialization failed: ${err instanceof Error ? err.message : String(err)}`);
    }
} else {
    logger.warn("⚠️ STRIPE_SECRET_KEY is not defined in env. Stripe payment features will be disabled.");
}

export default stripeInstance;