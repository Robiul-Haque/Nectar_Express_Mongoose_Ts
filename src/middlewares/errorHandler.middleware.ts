import { Request, Response, NextFunction } from 'express';
import status from 'http-status';

const errorHandler = (err: any, req: Request, res: Response, next: NextFunction) => {
    res.status(status.INTERNAL_SERVER_ERROR).json({ success: false, message: err.message || 'Internal Server Error' });
};

export default errorHandler;