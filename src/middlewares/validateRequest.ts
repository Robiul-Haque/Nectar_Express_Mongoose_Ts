import { ZodTypeAny } from "zod";
import { Request, Response, NextFunction } from "express";
import catchAsync from "../utils/catchAsync";

export const validateRequest = (schema: ZodTypeAny) =>
    catchAsync(async (req: Request, res: Response, next: NextFunction) => {
        const parsed = await schema.parseAsync(req.body);
        // override body with validated data
        req.body = parsed;
        next();
    });