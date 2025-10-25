import * as jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

// Ensure JWT_SECRET is present at startup and is a string.
// This will throw at import time if missing, so the rest of the app can assume it's present.
const JWT_SECRET =
    process.env.JWT_SECRET ??
    (() => {
        throw new Error("JWT_SECRET must be set in environment");
    })();

/**
 * Sign a JWT that expires in 1 hour by default.
 * Use the exact SignOptions['expiresIn'] type for the parameter so callers can pass
 * either a number or the ms-compatible string value (e.g. '1h').
 *
 * When building the SignOptions object we cast expiresIn to any to satisfy the
 * jsonwebtoken type overloads (string literals like '1h' are fine at runtime).
 */
export function signJwt(
    payload: object,
    expiresIn: jwt.SignOptions["expiresIn"] = "1h"
): string {
    const options: jwt.SignOptions = { expiresIn: expiresIn as any };
    return jwt.sign(payload as any, JWT_SECRET as jwt.Secret, options);
}

/**
 * Verify a JWT and return its payload. Throws if invalid/expired.
 */
export function verifyJwt<T = any>(token: string): T & { iat?: number; exp?: number } {
    return jwt.verify(token, JWT_SECRET as jwt.Secret) as T & { iat?: number; exp?: number };
}