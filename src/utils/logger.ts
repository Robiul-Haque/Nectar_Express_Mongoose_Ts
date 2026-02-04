import pino from 'pino';

const shouldPrettyPrint = process.env.NODE_ENV !== 'production';

const hasPretty = (): boolean => {
    try {
        require.resolve('pino-pretty');
        return true;
    } catch {
        return false;
    }
};

const transport =
    shouldPrettyPrint && hasPretty() ? { target: 'pino-pretty' } : undefined;

const logger = transport ? pino({ transport }) : pino();

export default logger;
