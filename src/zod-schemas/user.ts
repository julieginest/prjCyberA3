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

export const changePasswordSchema = z.object({
    oldPassword: z.string().min(1, "old password is required"),
    newPassword: z.string().min(8, "new password must be at least 8 characters"),
});

export type SignupBody = z.infer<typeof signupSchema>;
export type LoginBody = z.infer<typeof loginSchema>;
export type ChangePasswordBody = z.infer<typeof changePasswordSchema>;