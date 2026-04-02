import express, { Request, Response } from 'express';
import http from 'http';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import cookieParser from 'cookie-parser';
import { Server } from "socket.io";
import { initializeSocket } from './utils/socketUtils';
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
app.use(cors({ origin: "http://localhost:5173", credentials: true }));
app.use(compression());

app.use("/api/v1/payment/webhook", express.raw({ type: "application/json" }));

// Body
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: env.DASHBOARD_URL || "http://localhost:5173",
        methods: ["GET", "POST"],
        credentials: true,
    },
});

// Attach io to app for access in controllers & initialize socket events
app.set("io", io);
initializeSocket(io);

// Rate limit
app.use(globalRateLimiter);

app.get('/', (req: Request, res: Response) => sendResponse(res, status.OK, `Nectar server is running at ${env.PORT}`));

// Routes
app.use('/api/v1', router);

// Errors
app.use(notFound);
app.use(errorHandler);

export default app;