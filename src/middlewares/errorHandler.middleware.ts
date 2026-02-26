import { Request, Response, NextFunction } from "express";
import { ZodError } from "zod";
import status from "http-status";

interface IErrorResponse {
    success: boolean;
    message: string;
    errors?: {
        field?: string;
        message: string;
    }[];
    stack?: string;
}

const errorHandler = (err: any, req: Request, res: Response, next: NextFunction) => {
    let statusCode = err.statusCode || status.INTERNAL_SERVER_ERROR;
    let message = err.message || "Internal Server Error";
    let errors: IErrorResponse["errors"] = [];

    // ZOD VALIDATION ERROR
    if (err instanceof ZodError) {
        statusCode = status.BAD_REQUEST;
        message = "Validation failed";

        errors = err.issues.map((error) => ({ field: error.path.join("."), message: error.message, }));
    }

    //  MONGOOSE VALIDATION ERROR
    else if (err?.name === "ValidationError") {
        statusCode = status.BAD_REQUEST;
        message = "Database validation failed";

        errors = Object.values(err.errors).map((error: any) => ({ field: error.path, message: error.message, }));
    }

    //  DUPLICATE KEY ERROR (MongoDB)
    else if (err?.code === 11000) {
        statusCode = status.CONFLICT;
        const field = Object.keys(err.keyValue)[0];

        message = `${field} already exists`;

        errors = [
            {
                field,
                message: `${field} must be unique`,
            },
        ];
    }

    //  JWT ERROR
    else if (err?.name === "JsonWebTokenError") {
        statusCode = status.UNAUTHORIZED;
        message = "Invalid token";
    }

    else if (err?.name === "TokenExpiredError") {
        statusCode = status.UNAUTHORIZED;
        message = "Token expired";
    }

    //  FINAL RESPONSE
    const response: IErrorResponse = {
        success: false,
        message,
        ...(errors.length && { errors }),
        ...(process.env.NODE_ENV === "development" && { stack: err.stack }),
    };

    res.status(statusCode).json(response);
};

export default errorHandler;