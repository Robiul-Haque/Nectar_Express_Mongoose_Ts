
import { Router } from "express";
import { authenticate } from "../../middlewares/auth.middleware";
import { upload } from "../../middlewares/upload.middleware";
import { validateRequest } from "../../middlewares/validateRequest";
import { createBrand, deleteBrand, getAllBrands, getAppBrands, getSingleBrand, updateBrand } from "./brand.controller";
import { createBrandSchema, updateBrandSchema } from "./brand.validation";

const router = Router();

router.get("/app/all",  getAppBrands);

// Admin routes
router.post("/create", authenticate(["admin"]), upload.single("logo"), validateRequest(createBrandSchema), createBrand);
router.get("/", authenticate(["admin"]), getAllBrands);
router.get("/:id", authenticate(["admin"]), getSingleBrand);
router.patch("/update/:id", authenticate(["admin"]), upload.single("logo"), validateRequest(updateBrandSchema), updateBrand);
router.delete("/delete/:id", authenticate(["admin"]), deleteBrand);

export default router;