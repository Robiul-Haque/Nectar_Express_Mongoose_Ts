import admin, { ServiceAccount } from "firebase-admin";
import { env } from "./env";
import logger from "../utils/logger";

let firebaseAdminInstance: typeof admin | null = null;

if (env.FIREBASE_PROJECT_ID && env.FIREBASE_CLIENT_EMAIL && env.FIREBASE_PRIVATE_KEY) {
    try {
        const serviceAccount: ServiceAccount = {
            projectId: env.FIREBASE_PROJECT_ID,
            clientEmail: env.FIREBASE_CLIENT_EMAIL,
            privateKey: env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
        };

        if (!admin.apps.length) {
            admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
        }
        firebaseAdminInstance = admin;
        logger.info("✅ Firebase Admin SDK initialized successfully");
    } catch (error) {
        logger.error(`❌ Firebase Admin SDK initialization failed: ${error instanceof Error ? error.message : String(error)}`);
    }
} else {
    logger.warn("⚠️ Firebase environment variables missing. Firebase services will be disabled.");
}

export const firebaseAdmin = firebaseAdminInstance;