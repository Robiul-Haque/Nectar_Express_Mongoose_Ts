import { Router } from "express";
import { authenticate } from "../../middlewares/auth.middleware";
import { upload } from "../../middlewares/upload.middleware";
import { validateRequest } from "../../middlewares/validateRequest";
import { createProductSchema } from "./product.validation";
import { createProduct } from "./product.controller";

const router = Router();

router.post(
    "/create",
    authenticate(["admin"]),
    upload.array("images"),
    validateRequest(createProductSchema),
    createProduct
);

// router.get("/", ProductController.getAllProducts);

// router.get("/:id", ProductController.getSingleProduct);

// router.patch(
//     "/:id",
//     authenticate(["admin"]),
//     validateRequest(updateProductSchema),
//     ProductController.updateProduct
// );

// router.delete(
//     "/:id",
//     authenticate(["admin"]),
//     ProductController.deleteProduct
// );

export default router;