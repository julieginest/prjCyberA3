import { z } from "zod";

export const signupSchema = z.object({
    name: z.string().min(1, "name is required"),
    email: z.string().email("invalid email"),
    password: z.string().min(8, "password must be at least 8 characters"),
});

export const loginSchema = z.object({
    email: z.string().email("invalid email"),
    password: z.string().min(1, "password is required"),
});

export type SignupBody = z.infer<typeof signupSchema>;
export type LoginBody = z.infer<typeof loginSchema>;