import { Router } from "express";
import { authenticate } from "../../middlewares/auth.middleware";
import { upload } from "../../middlewares/upload.middleware";
import { validateRequest } from "../../middlewares/validateRequest";
import { createCategorySchema, updateCategorySchema } from "./category.validation";
import { createCategory, deleteCategory, getAllCategories, getSingleCategory, updateCategory } from "./category.controller";

const router = Router();

router.post("/create", authenticate(["admin"]), upload.single("icon"), validateRequest(createCategorySchema), createCategory);
router.get("/", authenticate(["admin"]), getAllCategories);
router.get("/:id", authenticate(["admin"]), getSingleCategory);
router.patch("/update/:id", authenticate(["admin"]), upload.single("icon"), validateRequest(updateCategorySchema), updateCategory);
router.delete("/delete/:id", authenticate(["admin"]), deleteCategory);