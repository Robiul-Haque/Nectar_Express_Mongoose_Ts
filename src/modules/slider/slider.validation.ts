import { z } from "zod";
import mongoose from "mongoose";

export const objectIdSchema = z.string().refine(val => mongoose.Types.ObjectId.isValid(val), { message: "Invalid ObjectId" });

const actionButtonSchema = z.object({
  text: z.string().min(1).max(50).optional(),
  link: z.string().url("Invalid URL").optional()
}).refine(data => data.text || data.link, { message: "At least one of text or link is required" });

export const createSliderZodSchema = z.object({
  body: z.object({
    title: z.string().min(1).max(200),
    actionButton: actionButtonSchema.optional(),
    animationType: z.enum(["fade", "slide", "zoom", "none"]).optional().default("fade")
  })
});

export const updateSliderZodSchema = z.object({
  body: z.object({
    title: z.string().min(1).max(200).optional(),
    actionButton: actionButtonSchema.optional(),
    animationType: z.enum(["fade", "slide", "zoom", "none"]).optional(),
    isActive: z.union([z.boolean(), z.string()]).optional().transform((val) => { if (typeof val === "string") return val === "true"; return val })
  })
});

export const getSliderSchema = z.object({
  query: z.object({
    page: z.string().optional().transform(val => val ? parseInt(val) : 1).refine(val => val > 0, { message: "Page must be > 0" }),
    limit: z.string().optional().transform(val => val ? parseInt(val) : 20).refine(val => val > 0 && val <= 100, { message: "Limit must be 1-100" })
  })
});

export const deleteSliderSchema = z.object({ params: z.object({ id: objectIdSchema }) });

export const deleteSliderImageSchema = z.object({
  params: z.object({
    sliderId: objectIdSchema,
    imageId: objectIdSchema
  })
});

export const SliderImageOrderZodSchema = z.object({
  body: z.object({ order: z.array(objectIdSchema).min(1).refine(arr => new Set(arr).size === arr.length, { message: "Duplicate slider IDs not allowed" }) })
});