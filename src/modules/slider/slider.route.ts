import { Router } from 'express';
import authenticate from '../../middlewares/auth.middleware';
import upload from '../../middlewares/upload.middleware';
import validateRequest from '../../middlewares/validateRequest';
import { createSliderZodSchema, deleteSliderImageSchema, deleteSliderSchema, getSliderSchema, reorderSliderZodSchema, updateSliderZodSchema } from './slider.validation';
import { createSlider, deleteSlider, deleteSliderImage, getActiveSlider, getSlider, reorderSlider, updateSlider } from './slider.controller';

const router = Router();

// App Routes
router.get("/sliders", getActiveSlider);

// Admin Routes
router.post("/", authenticate(["admin"]), upload.array("sliderImages", 10), validateRequest(createSliderZodSchema), createSlider);
router.put("/:id", authenticate(["admin"]), upload.array("sliderImages", 10), validateRequest(updateSliderZodSchema), updateSlider);
router.post("/reorder", authenticate(["admin"]), validateRequest(reorderSliderZodSchema), reorderSlider);
router.get("/", authenticate(["admin"]), validateRequest(getSliderSchema), getSlider);
router.delete("/:id", authenticate(["admin"]), validateRequest(deleteSliderSchema), deleteSlider);
router.delete("/:sliderId/images/:imageId", authenticate(["admin"]), validateRequest(deleteSliderImageSchema), deleteSliderImage);

export default router;