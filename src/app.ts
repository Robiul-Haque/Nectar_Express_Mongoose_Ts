import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import rateLimit from 'express-rate-limit';
// import routes from './routes';
import notFound from './middlewares/errorHandler';
import errorHandler from './middlewares/errorHandler';
import { globalRateLimiter } from './middlewares/rateLimiter';

const app = express();

// Security
app.use(helmet());
app.use(cors());
app.use(compression());

// Body
app.use(express.json());

// Rate limit
app.use(globalRateLimiter);

// Routes
// app.use('/api/v1', routes);

// Errors
app.use(notFound);
app.use(errorHandler);

export default app;