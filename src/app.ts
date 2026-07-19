import express, { Request, Response } from 'express';
import http from 'http';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import cookieParser from 'cookie-parser';
import { Server } from "socket.io";
import { createAdapter } from "@socket.io/redis-adapter";
import Redis from "ioredis";
import { initializeSocket } from './utils/socketUtils';
import notFound from './middlewares/notFound.middleware';
import errorHandler from './middlewares/errorHandler.middleware';
import { globalRateLimiter } from './middlewares/rateLimiter.middleware';
import sendResponse from './utils/sendResponse';
import { stripeWebhookWithOrderComplete } from './modules/payment/payment.webhook';
import status from 'http-status';
import logger from './utils/logger';
import { env } from './config/env';
import router from './router/routes';
import healthRouter from './modules/health/health.route';

const app = express();

// Security
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https://res.cloudinary.com"],
            connectSrc: ["'self'", "https://api.stripe.com"],
        },
    },
    crossOriginResourcePolicy: { policy: "cross-origin" }
}));
app.use(cors({ origin: ["http://localhost:5173", "http://localhost:3000", "http://localhost:3001"], credentials: true }));
app.use(compression());

app.use("/api/v1/payment/webhook", express.raw({ type: "application/json" }), stripeWebhookWithOrderComplete);

// Body
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: ["http://localhost:5173", "http://localhost:3000", "http://localhost:3001"],
        methods: ["GET", "POST"],
        credentials: true,
    },
});

let socketPubClient: Redis | null = null;
let socketSubClient: Redis | null = null;

// Scale Socket.IO using Redis Adapter across CPU cluster workers
if (env.REDIS_URL) {
    socketPubClient = new Redis(env.REDIS_URL, {
        maxRetriesPerRequest: 3,
        retryStrategy: (times) => Math.min(times * 100, 3000),
        reconnectOnError: () => true,
    });
    socketSubClient = socketPubClient.duplicate();

    socketPubClient.on("error", (err) => {
        logger.error(`❌ Redis (pub) connection error: ${err.message}`);
    });

    socketSubClient.on("error", (err) => {
        logger.error(`❌ Redis (sub) connection error: ${err.message}`);
    });

    io.adapter(createAdapter(socketPubClient, socketSubClient));
}

export const closeSocketAdapterClients = async (): Promise<void> => {
    try {
        if (socketPubClient) await socketPubClient.quit();
        if (socketSubClient) await socketSubClient.quit();
        logger.info("Socket.IO Redis adapter clients closed.");
    } catch (err) {
        logger.warn(`Error closing Socket.IO Redis adapter clients: ${err}`);
    }
};

// Attach io to app for access in controllers & initialize socket events
app.set("io", io);
initializeSocket(io);

// Health check endpoint for Docker / LB readiness probing
app.use('/health', healthRouter);

// Rate limit
app.use(globalRateLimiter);

app.get('/', (req: Request, res: Response) => sendResponse(res, status.OK, `Nectar server is running at ${env.PORT}`));

// Routes
app.use('/api/v1', router);

// Errors
app.use(notFound);
app.use(errorHandler);

export { app, server, io };