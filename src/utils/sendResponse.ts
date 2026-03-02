import { Response } from 'express';

const sendResponse = (res: Response, statusCode: number, message: string, data?: unknown) => {
    const success = statusCode >= 200 && statusCode < 300;
    res.status(statusCode).json({ success, message, ...(data !== undefined && { data }) });
};

export default sendResponse;