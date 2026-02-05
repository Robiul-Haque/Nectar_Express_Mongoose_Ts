import { Request, Response, NextFunction, RequestHandler } from "express";

/**
 * @param fn
 * @returns
 */

const catchAsync = (fn: (req: Request, res: Response, next: NextFunction) => Promise<any>): RequestHandler => (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch((err) => {
        console.error("[catchAsync] Caught error:", err);
        next(err);
    });
};

export default catchAsync;