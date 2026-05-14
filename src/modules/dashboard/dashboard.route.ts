import { Router } from "express";
import authenticate from "../../middlewares/auth.middleware";
// import validateRequest from "../../middlewares/validateRequest";
import { getDashboardAnalytics } from "./dashboard.controller";
// import { getSalesOverviewSchema } from "./dashboard.validation";

const router = Router();

// router.get("/sales-overview", authenticate(["admin"]), validateRequest(getSalesOverviewSchema), getSalesOverview);
router.get("/stats", authenticate(["admin"]), getDashboardAnalytics);

export default router;