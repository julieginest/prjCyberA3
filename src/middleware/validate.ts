import { ZodObject, ZodError } from "zod";
import { Request, Response, NextFunction } from "express";

/**
 * Validate request data against a Zod schema.
 * It merges sources so you can send data in JSON body, query string or route params.
 * The parsed result is assigned to req.body for downstream handlers.
 */
export function validateBody(schema: ZodObject) {
    return (req: Request, res: Response, next: NextFunction) => {
        // Merge in order of precedence: body -> query -> params
        // (body values will overwrite query/params values if same keys exist)
        const source = {
            ...(req.query ?? {}),
            ...(req.params ?? {}),
            ...(req.body ?? {}),
        };

        try {
            const parsed = schema.parse(source);
            // assign the parsed, type-safe object to req.body for downstream handlers
            (req as any).body = parsed;
            return next();
        } catch (err: unknown) {
            if (err instanceof ZodError) {
                const errors = err.errors.map((e) => ({
                    path: e.path,
                    message: e.message,
                    code: e.code,
                }));
                return res.status(400).json({ errors });
            }

            // fallback
            return res.status(400).json({ error: "Invalid request" });
        }
    };
}