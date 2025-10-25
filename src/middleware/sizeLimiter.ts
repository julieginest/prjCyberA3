import { Request, Response, NextFunction } from "express";

/**
 * sizeLimiter middleware
 * - If Content-Length header exists, enforce:
 *    - multipart/form-data -> 25 MB
 *    - otherwise -> 1 MB
 * - If header is missing, rely on body parsers (express.json / multer) which are configured with limits.
 *
 * Note: Content-Length can be spoofed; the real protection is the parser limits (express.json/multer).
 */
const ONE_MB = 1 * 1024 * 1024;
const TWENTY_FIVE_MB = 25 * 1024 * 1024;

export function sizeLimiter(req: Request, res: Response, next: NextFunction) {
  try {
    const contentLengthHeader = req.headers["content-length"];
    const contentType = (req.headers["content-type"] || "").toString().toLowerCase();

    if (contentLengthHeader) {
      const parsed = parseInt(Array.isArray(contentLengthHeader) ? contentLengthHeader[0] : contentLengthHeader, 10);
      if (!Number.isNaN(parsed)) {
        const limit = contentType.startsWith("multipart/") ? TWENTY_FIVE_MB : ONE_MB;
        if (parsed > limit) {
          res.setHeader("Retry-After", "0");
          return res.status(413).json({ error: `Payload too large. Limit is ${limit} bytes.` });
        }
      }
    }

    // No content-length or within limits -> continue (parsers will enforce actual limit)
    return next();
  } catch (err) {
    console.error("sizeLimiter unexpected error:", err);
    // Fail open to allow parser to handle; but better to surface internal error
    return res.status(500).json({ error: "Internal server error" });
  }
}