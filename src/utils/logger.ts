import pino from "pino";

const transport =
    process.env.NODE_ENV !== "production"
        ? {
            target: "pino-pretty",
            options: {
                colorize: true,
                translateTime: "HH:MM:ss",
                ignore: "pid,hostname",
            },
        }
        : undefined;

export default pino({
    level: "info",
    transport,
});