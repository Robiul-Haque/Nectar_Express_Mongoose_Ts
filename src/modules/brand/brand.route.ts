import { Router } from "express";
import { authenticate } from "../../middlewares/auth.middleware";
import { upload } from "../../middlewares/upload.middleware";
import { validateRequest } from "../../middlewares/validateRequest";
import { createBrand, deleteBrand, getAllBrands, getAppBrands, getSingleBrand, updateBrand } from "./brand.controller";
import { createBrandSchema, deleteBrandSchema, getAllBrandsSchema, getSingleBrandSchema, updateBrandSchema } from "./brand.validation";

const router = Router();

// App routes
router.get("/app/all", authenticate(["user"]), validateRequest(getAllBrandsSchema), getAppBrands);

// Admin routes
router.post("/create", authenticate(["admin"]), upload.single("logo"), validateRequest(createBrandSchema), createBrand);
router.get("/", authenticate(["admin"]), validateRequest(getAllBrandsSchema), getAllBrands);
router.get("/:id", authenticate(["admin"]), validateRequest(getSingleBrandSchema), getSingleBrand);
router.patch("/update/:id", authenticate(["admin"]), upload.single("logo"), validateRequest(updateBrandSchema), updateBrand);
router.delete("/delete/:id", authenticate(["admin"]), validateRequest(deleteBrandSchema), deleteBrand);

export default router;