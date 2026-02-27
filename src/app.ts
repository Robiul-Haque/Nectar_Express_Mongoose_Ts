import express, { Request, Response } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import cookieParser from 'cookie-parser';
import notFound from './middlewares/errorHandler.middleware';
import errorHandler from './middlewares/errorHandler.middleware';
import { globalRateLimiter } from './middlewares/rateLimiter.middleware';
import sendResponse from './utils/sendResponse';
import status from 'http-status';
import { env } from './config/env';
import router from './router/routes';

const app = express();

// Security
app.use(helmet());
app.use(cors({
    origin: "http://localhost:5173",
    credentials: true
}));
app.use(compression());

// Body
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Rate limit
app.use(globalRateLimiter);

app.get('/', (req: Request, res: Response) => sendResponse(res, status.OK, `Nectar server is running at ${env.PORT}`));

// Routes
app.use('/api/v1', router);

// Errors
app.use(notFound);
app.use(errorHandler);

export default app;