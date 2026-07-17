import { z } from "zod";

export const getSalesOverviewSchema = z.object({
    query: z.object({
        range: z.enum(["weekly", "monthly", "last6months", "yearly"]).optional()
    })
});
