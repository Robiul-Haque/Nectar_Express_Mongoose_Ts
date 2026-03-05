import { Response } from "express";

interface IPagination {
    total?: number;
    page?: number;
    limit?: number;
    [key: string]: unknown;
}

const sendResponse = <T>(res: Response, statusCode: number, message: string, pagination: IPagination | null = null, data?: T) => {
    const success = statusCode >= 200 && statusCode < 300;

    const response: Record<string, unknown> = { success, message };

    if (pagination) response.pagination = pagination;
    if (data !== undefined) response.data = data;

    res.status(statusCode).json(response);
};

export default sendResponse;