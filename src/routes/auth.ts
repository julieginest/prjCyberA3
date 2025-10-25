import { Router } from "express";
import bcrypt from "bcrypt";
import { supabase } from "../supabase";
import { signupSchema, loginSchema } from "../../src/zod-schemas/user";
import { validateBody } from "../middleware/validate";
import { signJwt } from "../utils/jwt";

const router = Router();

/**
 * POST /auth/signin
 * Body: { name, email, password }
 * Creates a new user in the Supabase Postgres table `users` and returns a JWT.
 */
router.post("/signin", validateBody(signupSchema), async (req, res) => {
    const { name, email, password } = req.body as {
        name: string;
        email: string;
        password: string;
    };

    const emailLower = email.toLowerCase();

    try {
        // Check if user exists
        const { data: existing, error: selectError } = await supabase
            .from("users")
            .select("id")
            .eq("email", emailLower)
            .limit(1);

        if (selectError) {
            console.error("supabase select error:", selectError);
            return res.status(500).json({ error: "Internal server error" });
        }

        if (existing && existing.length > 0) {
            return res.status(409).json({ error: "Email already in use" });
        }

        // Hash password (we store the bcrypt hash in the `password` column)
        const passwordHash = await bcrypt.hash(password, 12);

        // Insert user and return selected fields
        const { data, error: insertError } = await supabase
            .from("users")
            .insert({
                name,
                email: emailLower,
                password: passwordHash,
            })
            .select("id, name, email, created_at")
            .single();

        if (insertError) {
            console.error("supabase insert error:", insertError);
            // Unique constraint may come back from the DB concurrently
            if (insertError.code === "23505") {
                return res.status(409).json({ error: "Email already in use" });
            }
            return res.status(500).json({ error: "Internal server error" });
        }

        const user = data;

        const token = signJwt({ userId: user.id, email: user.email });

        return res.status(201).json({
            user,
            token,
        });
    } catch (err) {
        console.error("signin error:", err);
        return res.status(500).json({ error: "Internal server error" });
    }
});

/**
 * POST /auth/login
 * Body: { email, password }
 * Authenticates an existing user stored in Supabase and returns a JWT.
 */
router.post("/login", validateBody(loginSchema), async (req, res) => {
    const { email, password } = req.body as { email: string; password: string };

    const emailLower = email.toLowerCase();

    try {
        const { data, error: selectError } = await supabase
            .from("users")
            .select("id, name, email, password")
            .eq("email", emailLower)
            .limit(1)
            .single();

        if (selectError) {
            // If not found, Supabase returns an error; treat as invalid credentials
            console.error("supabase select (login) error:", selectError);
            return res.status(401).json({ error: "Invalid credentials" });
        }

        const userRow: any = data;

        // `userRow.password` contains the bcrypt hash
        const match = await bcrypt.compare(password, userRow.password);

        if (!match) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        const token = signJwt({ userId: userRow.id, email: userRow.email });

        // Build user object without password
        const user = {
            id: userRow.id,
            name: userRow.name,
            email: userRow.email,
        };

        return res.json({ user, token });
    } catch (err) {
        console.error("login error:", err);
        return res.status(500).json({ error: "Internal server error" });
    }
});

export default router;