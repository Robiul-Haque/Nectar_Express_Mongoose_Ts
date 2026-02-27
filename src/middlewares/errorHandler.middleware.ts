import { Request, Response, NextFunction } from "express";
import mongoose from "mongoose";
import { ZodError } from "zod";
import status from "http-status";

interface IErrorSource {
    field?: string;
    message: string;
}

interface IErrorResponse {
    success: boolean;
    message: string;
    errors?: IErrorSource[];
    stack?: string;
}

const errorHandler = (err: unknown,req: Request,res: Response,next: NextFunction) => {
    let statusCode: number = status.INTERNAL_SERVER_ERROR;
    let message = "Something went wrong";
    let errors: IErrorSource[] | undefined;

    // Zod Validation Error
    if (err instanceof ZodError) {
        statusCode = status.BAD_REQUEST;
        message = "Validation failed";

        errors = err.issues.map((issue) => ({
            field: issue.path.join("."),
            message: issue.message,
        }));
    }

    // Mongoose Validation Error
    else if (err instanceof mongoose.Error.ValidationError) {
        statusCode = status.BAD_REQUEST;
        message = "Database validation failed";

        errors = Object.values(err.errors).map((e) => ({
            field: (e as any).path,
            message: (e as any).message,
        }));
    }

    // Mongoose Cast Error (Invalid ObjectId etc.)
    else if (err instanceof mongoose.Error.CastError) {
        statusCode = status.BAD_REQUEST;
        message = `Invalid ${err.path}`;

        errors = [
            {
                field: err.path,
                message: `Invalid value for ${err.path}`,
            },
        ];
    }

    // 🔹 MongoDB Duplicate Key Error
    else if (typeof err === "object" &&err !== null &&"code" in err &&(err as any).code === 11000) {
        statusCode = status.CONFLICT;

        const field = Object.keys((err as any).keyValue)[0];

        message = `${field} already exists`;

        errors = [
            {
                field,
                message: `${field} must be unique`,
            },
        ];
    }

    // JWT Errors
    else if (typeof err === "object" &&err !== null &&"name" in err &&(err as any).name === "JsonWebTokenError") {
        statusCode = status.UNAUTHORIZED;
        message = "Invalid token";
    }

    else if (typeof err === "object" &&err !== null &&"name" in err &&(err as any).name === "TokenExpiredError") {
        statusCode = status.UNAUTHORIZED;
        message = "Token expired";
    }

    // Custom App Error (if you throw manually with statusCode)
    else if (typeof err === "object" &&err !== null &&"statusCode" in err) {
        statusCode = (err as any).statusCode;
        message = (err as any).message || message;
    }

    const response: IErrorResponse = {
        success: false,
        message,
    };

    if (errors)  response.errors = errors;
    if (process.env.NODE_ENV === "development" && err instanceof Error) response.stack = err.stack;

    return res.status(statusCode).json(response);
};

export default errorHandler;