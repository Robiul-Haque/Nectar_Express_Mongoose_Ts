import { Router } from "express";
import authenticate from "../../middlewares/auth.middleware";
import validateRequest from "../../middlewares/validateRequest";
import {
    updateLocation,
    assignDriver,
    updateTrackingStatus,
    getDriverLocation,
    getOrderTracking,
    toggleDriverActiveStatus,
    getNearbyDrivers
} from "./tracking.controller";
import {
    updateLocationSchema,
    assignDriverSchema,
    updateTrackingStatusSchema,
    toggleActiveStatusSchema,
    getNearbyDriversSchema
} from "./tracking.validation";

const router = Router();

// Driver: update current GPS position (HTTP fallback)
router.post("/location", authenticate(["driver"]), validateRequest(updateLocationSchema), updateLocation);

// Driver: toggle online/offline active status
router.patch("/driver/active-status", authenticate(["driver"]), validateRequest(toggleActiveStatusSchema), toggleDriverActiveStatus);

// Admin: assign driver to order
router.post("/assign", authenticate(["admin"]), validateRequest(assignDriverSchema), assignDriver);

// Admin: fetch specific driver's active tracking record
router.get("/driver/:driverId", authenticate(["admin"]), getDriverLocation);

// Admin: query nearby active/online drivers
router.get("/nearby-drivers", authenticate(["admin"]), validateRequest(getNearbyDriversSchema), getNearbyDrivers);

// Driver / Admin: transition delivery tracking status (e.g. in_transit, delivered)
router.patch("/status/:orderId", authenticate(["driver", "admin"]), validateRequest(updateTrackingStatusSchema), updateTrackingStatus);

// User / Driver / Admin: fetch current live details and path of an order
router.get("/order/:orderId", authenticate(["user", "driver", "admin"]), getOrderTracking);

export default router;