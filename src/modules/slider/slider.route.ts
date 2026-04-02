import express from 'express';
import authenticate from '../../middlewares/auth.middleware';
import multer from 'multer';
import validateRequest from '../../middlewares/validateRequest';
import { createSliderItemZodSchema, deleteSliderItemSchema, getSliderItemsSchema, reorderSliderItemsZodSchema, updateSliderItemZodSchema } from './slider.validation';
import { createSliderItem, deleteSliderItem, getActiveSliderItems, getSliderItems, reorderSliderItems, updateSliderItem } from './slider.controller';

const router = express.Router();
const upload = multer({ storage: multer.memoryStorage() });

router.get("/sliders", getActiveSliderItems);

// Admin Routes
router.post("/sliders", authenticate(["admin"]), upload.single("image"), validateRequest(createSliderItemZodSchema), createSliderItem);
router.put("/sliders/:id", authenticate(["admin"]), upload.single('image'), validateRequest(updateSliderItemZodSchema), updateSliderItem);
router.post("/sliders/reorder", authenticate(["admin"]), validateRequest(reorderSliderItemsZodSchema), reorderSliderItems);
router.get("/sliders", authenticate(["admin"]), validateRequest(getSliderItemsSchema), getSliderItems);
router.delete("/sliders/:id", authenticate(["admin"]), validateRequest(deleteSliderItemSchema), deleteSliderItem);

export default router;