import { z } from "zod";

export const createApiKeySchema = z.object({
  name: z.string().min(1, "name is required"),
});

export type CreateApiKeyBody = z.infer<typeof createApiKeySchema>;