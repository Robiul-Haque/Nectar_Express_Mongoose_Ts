import { z } from "zod";
import mongoose from "mongoose";

export const objectIdSchema = z.string().refine((val) => mongoose.Types.ObjectId.isValid(val), { message: "Invalid ObjectId" });

const baseActionButtonSchema = z.object({
  text: z.string().min(1).max(50).optional(),
  link: z.string().url("Invalid link URL").optional()
});

const actionButtonCreateSchema = baseActionButtonSchema.refine((data) => data.text || data.link, { message: "At least one of text or link is required" });

const actionButtonUpdateSchema = baseActionButtonSchema;

export const createSliderZodSchema = z.object({
  body: z.object({
    title: z.string().min(1).max(200).optional(),
    description: z.string().max(500).optional(),
    actionButton: actionButtonCreateSchema.optional(),
    animationType: z.enum(["fade", "slide", "zoom", "none"]).optional().default("fade"),
    isActive: z.boolean().optional().default(true)
  })
});

export const updateSliderZodSchema = z.object({
  body: z.object({
    title: z.string().min(1).max(200).optional(),
    description: z.string().max(500).optional(),
    actionButton: actionButtonUpdateSchema.optional(),
    animationType: z.enum(["fade", "slide", "zoom", "none"]).optional(),
    isActive: z.boolean().optional()
  }),
});

export const getSliderSchema = z.object({
  query: z.object({
    page: z.string().optional().transform((val) => (val ? parseInt(val) : 1)).refine((val) => val > 0, { message: "Page must be greater than 0" }),
    limit: z.string().optional().transform((val) => (val ? parseInt(val) : 20)).refine((val) => val > 0 && val <= 100, { message: "Limit must be between 1 and 100" })
  })
});

export const reorderSliderZodSchema = z.object({
  body: z.object({
    order: z.array(objectIdSchema).min(1, "Order array cannot be empty").refine((arr) => new Set(arr).size === arr.length, { message: "Duplicate slider IDs are not allowed" })
  })
});

export const deleteSliderSchema = z.object({
  params: z.object({
    id: objectIdSchema
  })
});

export const deleteSliderImageSchema = z.object({
  params: z.object({
    sliderId: objectIdSchema,
    imageId: objectIdSchema
  })
});