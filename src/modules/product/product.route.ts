import { Router } from "express";
import authenticate from "../../middlewares/auth.middleware";
import upload from "../../middlewares/upload.middleware";
import validateRequest from "../../middlewares/validateRequest";
import { cacheMiddleware } from "../../middlewares/cache.middleware";
import { createProductSchema, updateProductSchema, getSingleProductSchema } from "./product.validation";
import { createProduct, deleteProduct, getAllProducts, getAdminProducts, getProductStats, updateProduct, getSingleProduct, getHomeProducts } from "./product.controller";

const router = Router();

router.post("/create", authenticate(["admin"]), upload.single("image"), validateRequest(createProductSchema), createProduct);
router.get("/admin", authenticate(["admin"]), getAdminProducts);
router.get("/stats", authenticate(["admin"]), getProductStats);
router.get("/home", cacheMiddleware(300), getHomeProducts);
router.get("/", cacheMiddleware(300), getAllProducts);
router.get("/:id", validateRequest(getSingleProductSchema), cacheMiddleware(600), getSingleProduct);
router.patch("/:id", authenticate(["admin"]), upload.single("image"), validateRequest(updateProductSchema), updateProduct);
router.delete("/:id", authenticate(["admin"]), deleteProduct);

export default router;