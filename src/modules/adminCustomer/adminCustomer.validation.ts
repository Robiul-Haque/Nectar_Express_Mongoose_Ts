import { z } from "zod";

const mongoIdSchema = z.string({ message: "Invalid ID" }).regex(/^[0-9a-fA-F]{24}$/, "Invalid MongoDB ObjectId format");

/** Shared params schema for :id routes */
export const customerIdParamsSchema = z.object({
    params: z.object({
        id: mongoIdSchema
    })
});

/** Params for note-level routes (:id + :noteId) */
export const customerNoteParamsSchema = z.object({
    params: z.object({
        id: mongoIdSchema,
        noteId: mongoIdSchema
    })
});

/** Pagination query schema */
export const paginationQuerySchema = z.object({
    params: z.object({
        id: mongoIdSchema
    }),
    query: z.object({
        page: z.string().optional().transform(v => Math.max(parseInt(v || "1", 10) || 1, 1)),
        limit: z.string().optional().transform(v => Math.min(parseInt(v || "20", 10) || 20, 100))
    })
});

/** Add admin note */
export const addAdminNoteSchema = z.object({
    params: z.object({
        id: mongoIdSchema
    }),
    body: z.object({
        note: z
            .string({ message: "Note is required" })
            .trim()
            .min(1, "Note cannot be empty")
            .max(2000, "Note cannot exceed 2000 characters")
    })
});

/** Update admin note */
export const updateAdminNoteSchema = z.object({
    params: z.object({
        id: mongoIdSchema,
        noteId: mongoIdSchema
    }),
    body: z.object({
        note: z
            .string({ message: "Note is required" })
            .trim()
            .min(1, "Note cannot be empty")
            .max(2000, "Note cannot exceed 2000 characters")
    })
});
