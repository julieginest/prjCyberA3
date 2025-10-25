import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
    throw new Error("JWT_SECRET must be set in environment");
}

export function signJwt(payload: object, expiresIn: string | number = "7d") {
    return jwt.sign(payload, JWT_SECRET, { expiresIn });
}

export function verifyJwt<T = any>(token: string): T {
    return jwt.verify(token, JWT_SECRET) as T;
}