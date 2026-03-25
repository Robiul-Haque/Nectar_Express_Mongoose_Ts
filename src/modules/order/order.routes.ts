import { Router } from "express";
import authenticate from "../../middlewares/auth.middleware";
import validateRequest from "../../middlewares/validateRequest";
import { createOrderSchema, deleteOrderSchema, getAllOrderSchema, updateStatusSchema } from "./order.validation";
import { cancelOrder, createOrder, getAllOrders, getMyOrders, updateOrderStatus } from "./order.controller";

const router = Router();

router.post("/create", authenticate(["user"]), validateRequest(createOrderSchema), createOrder);
router.get("/my", authenticate(["user"]), getMyOrders);
// router.get("/:id", authenticate(["user", "admin"]), getSingleOrder);
router.patch("/cancel/:id", authenticate(["user"]), validateRequest(deleteOrderSchema), cancelOrder);

// Admin routes
router.get("/admin/all", authenticate(["admin"]), validateRequest(getAllOrderSchema), getAllOrders);
router.patch("/status/:id", authenticate(["admin"]), validateRequest(updateStatusSchema), updateOrderStatus);

export default router;