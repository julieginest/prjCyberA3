import { z } from "zod";

const MAX_IMAGE_BYTES = 25 * 1024 * 1024; // 25 MB

/**
 * createProductSchema:
 * - name: string
 * - price: number
 * - image: optional URL (string)
 * - image_base64: optional base64 string OR data URI (data:<mime>;base64,...)
 *
 * Rules:
 * - cannot provide both image and image_base64
 * - image_base64 must decode to <= 25MB
 */
export const createProductSchema = z
  .object({
    name: z.string().min(1, "name is required"),
    price: z.preprocess((val) => {
      if (typeof val === "string") return parseFloat(val);
      return val;
    }, z.number().positive("price must be a positive number")),
    image: z.string().url("image must be a valid URL").optional(),
    image_base64: z.string().optional(),
  })
  .refine((data) => !(data.image && data.image_base64), {
    message: "Provide either image (URL) or image_base64, not both",
    path: ["image", "image_base64"],
  })
  .superRefine((data, ctx) => {
    if (data.image_base64) {
      // accept data URI or raw base64
      const value = data.image_base64 as string;
      const base64 = value.startsWith("data:") ? value.split(",")[1] ?? "" : value;
      if (!base64) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "image_base64 must be a base64 string or data URI",
          path: ["image_base64"],
        });
        return;
      }
      try {
        const bufLen = Buffer.from(base64, "base64").length;
        if (bufLen === 0) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: "image_base64 is not valid base64",
            path: ["image_base64"],
          });
        } else if (bufLen > MAX_IMAGE_BYTES) {
          // Zod requires 'origin' for too_big issues (indicates type origin such as "string")
          ctx.addIssue({
            code: z.ZodIssueCode.too_big,
            maximum: MAX_IMAGE_BYTES,
            inclusive: true,
            // 'origin' signals the domain/type that is too big; use "string" for base64 payloads
            origin: "string",
            message: `image_base64 must be <= ${MAX_IMAGE_BYTES} bytes when decoded`,
            path: ["image_base64"],
          } as any); // cast to any to be lenient with Zod versions if needed
        }
      } catch (err) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "image_base64 must be valid base64",
          path: ["image_base64"],
        });
      }
    }
  });

export type CreateProductBody = z.infer<typeof createProductSchema>;