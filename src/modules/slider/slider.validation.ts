import { z } from "zod";
import mongoose from "mongoose";

export const objectIdSchema = z.string().refine((val) => mongoose.Types.ObjectId.isValid(val), { message: "Invalid ObjectId" });

export const createSliderItemZodSchema = z.object({
  title: z.string().min(1, "Title is required").max(200),
  description: z.string().max(500).optional(),
  actionButton: z.object({
    text: z.string().min(1).max(50),
    link: z.string().url("Invalid link URL")
  })
    .optional(),
  animationType: z.enum(["fade", "slide", "zoom", "none"]).default("fade"),
  isActive: z.boolean().default(true)
});

export const updateSliderItemZodSchema = createSliderItemZodSchema.partial();

export const reorderSliderItemsZodSchema = z.object({
  order: z.array(z.string()).min(1, "Order array is required")
});

export const getSliderItemsSchema = z.object({
  query: z.object({
    page: z.string().optional().transform((val) => (val ? parseInt(val) : 1)).refine((val) => val > 0, { message: "Page must be greater than 0" }),
    limit: z.string().optional().transform((val) => (val ? parseInt(val) : 20)).refine((val) => val > 0 && val <= 100, { message: "Limit must be between 1 and 100" })
  })
});

export const deleteSliderItemSchema = z.object({
  params: z.object({
    id: objectIdSchema
  }),
});