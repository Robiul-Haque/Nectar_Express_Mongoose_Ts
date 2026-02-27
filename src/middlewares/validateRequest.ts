import { ZodObject } from "zod";
import { Request, Response, NextFunction } from "express";
import catchAsync from "../utils/catchAsync";

export const validateRequest = (schema: ZodObject<any>) =>
    catchAsync(async (req: Request, res: Response, next: NextFunction) => {
        const parsed = await schema.parseAsync({
            body: req.body,
            query: req.query,
            params: req.params,
            cookies: req.cookies,
        });

        if (parsed.body) req.body = parsed.body;

        next();
    });