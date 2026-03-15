import { Router } from "express";
import authenticate from "../../middlewares/auth.middleware";
import upload from "../../middlewares/upload.middleware";
import validateRequest from "../../middlewares/validateRequest";
import { createProductSchema, updateProductSchema } from "./product.validation";
import { createProduct, deleteProduct, getAllProducts, updateProduct } from "./product.controller";

const router = Router();

router.post("/create", authenticate(["admin"]), upload.single("image"), validateRequest(createProductSchema), createProduct);
router.get("/", authenticate(["admin"]), getAllProducts);
// router.get("/:id", ProductController.getSingleProduct);
router.patch("/:id", authenticate(["admin"]), upload.single("image"), validateRequest(updateProductSchema), updateProduct);
router.delete("/:id", authenticate(["admin"]), deleteProduct);

export default router;