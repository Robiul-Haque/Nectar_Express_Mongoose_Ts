import jwt, { SignOptions, Algorithm, Secret } from "jsonwebtoken";

export type TokenType = "access" | "refresh";

export interface JwtPayload {
    sub: string;
    role?: string;
    provider?: string;
    v?: number;
}

export interface TokenConfig {
    secret: Secret;
    expiresIn: SignOptions["expiresIn"];
    issuer?: string;
    audience?: string;
    algorithm?: Algorithm;
}

export const createToken = (type: TokenType, payload: JwtPayload, config: TokenConfig): string => {
    if (!config.secret) {
        throw new Error("JWT secret is not defined");
    }

    if (!payload.sub) {
        throw new Error("JWT payload must contain 'sub'");
    }

    const finalPayload: JwtPayload = type === "refresh" ? { sub: payload.sub, v: payload.v } : { ...payload };

    const options: SignOptions = {
        algorithm: config.algorithm ?? "HS256",
        expiresIn: config.expiresIn,
        issuer: config.issuer ?? "nectar-api",
        audience: config.audience ?? "nectar-users",
    };

    return jwt.sign(finalPayload, config.secret, options);
};