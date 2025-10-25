import { z } from "zod";

/**
 * Product creation schema:
 * - name: string
 * - price: number (accepts numeric or string coercion)
 */
export const createProductSchema = z.object({
  name: z.string().min(1, "name is required"),
  price: z.preprocess((val) => {
    if (typeof val === "string") return parseFloat(val);
    return val;
  }, z.number().positive("price must be a positive number")),
});

export type CreateProductBody = z.infer<typeof createProductSchema>;