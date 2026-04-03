import { z } from "zod";
import mongoose from "mongoose";

export const objectIdSchema = z.string().refine((val) => mongoose.Types.ObjectId.isValid(val), { message: "Invalid ObjectId" });

const actionButtonSchema = z.object({
  text: z.string().min(1).max(50),
  link: z.string().url("Invalid link URL")
});

export const createSliderItemZodSchema = z.object({
  body: z.object({
    title: z.string().min(1).max(200).optional(),
    description: z.string().max(500).optional(),
    actionButton: actionButtonSchema.optional(),
    animationType: z.enum(["fade", "slide", "zoom", "none"]).optional().default("fade"),
    isActive: z.boolean().optional().default(true)
  })
});

export const updateSliderItemZodSchema = z.object({
  body: createSliderItemZodSchema.shape.body.partial()
});

export const getSliderItemsSchema = z.object({
  query: z.object({
    page: z.string().optional().transform((val) => (val ? parseInt(val) : 1)).refine((val) => val > 0, { message: "Page must be greater than 0" }),
    limit: z.string().optional().transform((val) => (val ? parseInt(val) : 20)).refine((val) => val > 0 && val <= 100, { message: "Limit must be between 1 and 100" })
  })
});

export const reorderSliderItemsZodSchema = z.object({
  body: z.object({
    order: z.array(objectIdSchema).min(1, "Order array cannot be empty").refine((arr) => new Set(arr).size === arr.length, { message: "Duplicate slider IDs are not allowed" })
  }),
});

export const deleteSliderItemSchema = z.object({
  params: z.object({
    id: objectIdSchema
  })
});