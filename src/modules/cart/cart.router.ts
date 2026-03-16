import { Router } from "express";
import authenticate from "../../middlewares/auth.middleware";
import validateRequest from "../../middlewares/validateRequest";
import { adminUpdateCartSchema, cartBulkSchema, getAllCartsSchema } from "./cart.validation";
import { adminUpdateCartItem, getAllCarts, updateCartItems } from "./cart.controller";

const router = Router();

// App routes
router.patch("/items", authenticate(["user"]), validateRequest(cartBulkSchema), updateCartItems);

// Admin routes
router.get("/", authenticate(["admin"]), validateRequest(getAllCartsSchema), getAllCarts);
router.patch("/admin/cart-item/:cartId", authenticate(["admin"]), validateRequest(adminUpdateCartSchema), adminUpdateCartItem);

export default router;