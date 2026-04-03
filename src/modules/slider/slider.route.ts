import { Router } from 'express';
import authenticate from '../../middlewares/auth.middleware';
import validateRequest from '../../middlewares/validateRequest';
import { createSliderItemZodSchema, deleteSliderItemSchema, getSliderItemsSchema, reorderSliderItemsZodSchema, updateSliderItemZodSchema } from './slider.validation';
import { createSliderItem, deleteSliderItem, getActiveSliderItems, getSliderItems, reorderSliderItems, updateSliderItem } from './slider.controller';
import upload from '../../middlewares/upload.middleware';

const router = Router();

// App Routes
router.get("/sliders", getActiveSliderItems);

// Admin Routes
router.post("/create", authenticate(["admin"]), upload.array("sliderImages", 10), validateRequest(createSliderItemZodSchema), createSliderItem);
router.put("/:id", authenticate(["admin"]), upload.array("sliderImages", 10), validateRequest(updateSliderItemZodSchema), updateSliderItem);
router.post("/reorder", authenticate(["admin"]), validateRequest(reorderSliderItemsZodSchema), reorderSliderItems);
router.get("/", authenticate(["admin"]), validateRequest(getSliderItemsSchema), getSliderItems);
router.delete("/:id", authenticate(["admin"]), validateRequest(deleteSliderItemSchema), deleteSliderItem);

export default router;