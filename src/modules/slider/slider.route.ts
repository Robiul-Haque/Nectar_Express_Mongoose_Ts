import { Router } from "express";
import authenticate from "../../middlewares/auth.middleware";
import upload from "../../middlewares/upload.middleware";
import validateRequest from "../../middlewares/validateRequest";
import { createSliderZodSchema, updateSliderZodSchema, deleteSliderSchema, deleteSliderImageSchema, getSliderSchema, SliderImageOrderZodSchema } from "./slider.validation";
import { createSlider, updateSlider, deleteSlider, deleteSliderImage, getActiveSlider, getSlider, sliderImageOrder } from "./slider.controller";

const router = Router();

// Public Route
router.get("/active-slider", getActiveSlider);

// Admin Routes
router.post("/admin", authenticate(["admin"]), upload.array("sliderImages", 10), validateRequest(createSliderZodSchema), createSlider);
router.get("/admin", authenticate(["admin"]), validateRequest(getSliderSchema), getSlider);
router.put("/admin/:id", authenticate(["admin"]), upload.array("sliderImages", 10), validateRequest(updateSliderZodSchema), updateSlider);
router.delete("/admin/:sliderId/images/:imageId", authenticate(["admin"]), validateRequest(deleteSliderImageSchema), deleteSliderImage);
router.delete("/admin/:id", authenticate(["admin"]), validateRequest(deleteSliderSchema), deleteSlider);
router.patch("/admin/update-order", authenticate(["admin"]), validateRequest(SliderImageOrderZodSchema), sliderImageOrder);

export default router;