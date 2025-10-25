import jwt from "jsonwebtoken";

const JWT_SECRET = process.env.JWT_SECRET || "change_this_in_prod";

/**
 * Sign a JWT. jsonwebtoken automatically adds iat.
 * payload should include userId and any other non-sensitive data.
 * opts can include expiresIn, e.g. { expiresIn: "7d" }.
 */
export function signJwt(payload: object, opts?: jwt.SignOptions) {
    return jwt.sign(payload, JWT_SECRET, {
        algorithm: "HS256",
        ...(opts || {}),
    });
}

/**
 * Verify a JWT and return the decoded payload (JwtPayload).
 * Throws if invalid/expired.
 */
export function verifyJwt(token: string) {
    return jwt.verify(token, JWT_SECRET) as jwt.JwtPayload;
}