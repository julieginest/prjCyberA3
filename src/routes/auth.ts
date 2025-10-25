import { Router } from "express";
import bcrypt from "bcrypt";
import { supabase } from "../supabase";
import { signupSchema, loginSchema, changePasswordSchema } from "../zod-schemas/user";
import { validateBody } from "../middleware/validate";
import { signJwt } from "../utils/jwt";
import { authorizer } from "../middleware/authorizer";
import { requirePermission } from "../middleware/permissions";

const router = Router();

const lastLoginAttempt = new Map<string, number>();
const LOGIN_LIMIT_MS = 5_000;

/**
 * POST /auth/signin
 * Insert user with role = 'USER' by default (verifies existence of role)
 */
router.post("/signin", validateBody(signupSchema), async (req, res) => {
    const { name, email, password } = req.body as { name: string; email: string; password: string };
    const emailLower = email.toLowerCase();

    try {
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

        const passwordHash = await bcrypt.hash(password, 12);

        // Verify USER role exists
        const { data: roleData, error: roleError } = await supabase
            .from("roles")
            .select("name")
            .eq("name", "USER")
            .limit(1)
            .single();

        if (roleError || !roleData) {
            console.error("signin: USER role missing:", roleError);
            return res.status(500).json({ error: "Internal server error" });
        }

        const { data, error: insertError } = await supabase
            .from("users")
            .insert({
                name,
                email: emailLower,
                password: passwordHash,
                role: roleData.name, // store role as string referencing roles.name
            })
            .select("id, name, email, created_at")
            .single();

        if (insertError) {
            console.error("supabase insert error:", insertError);
            if ((insertError as any).code === "23505") {
                return res.status(409).json({ error: "Email already in use" });
            }
            return res.status(500).json({ error: "Internal server error" });
        }

        const user = data;
        const token = signJwt({ userId: user.id, email: user.email });

        return res.status(201).json({ user, token });
    } catch (err) {
        console.error("signin error:", err);
        return res.status(500).json({ error: "Internal server error" });
    }
});

/**
 * POST /auth/login
 */
router.post("/login", validateBody(loginSchema), requirePermission("can_post_login"), async (req, res) => {
    const { email, password } = req.body as { email: string; password: string };
    const emailLower = email.toLowerCase();

    const now = Date.now();
    const last = lastLoginAttempt.get(emailLower) ?? 0;
    const diff = now - last;
    if (diff < LOGIN_LIMIT_MS) {
        const retryAfter = Math.ceil((LOGIN_LIMIT_MS - diff) / 1000);
        res.setHeader("Retry-After", String(retryAfter));
        return res.status(429).json({ error: `Too many attempts. Try again in ${retryAfter} seconds` });
    }
    lastLoginAttempt.set(emailLower, now);

    try {
        // fetch user including role (string)
        const { data: userRow, error: selectError } = await supabase
            .from("users")
            .select("id, name, email, password, role, password_changed_at, created_at")
            .eq("email", emailLower)
            .limit(1)
            .single();

        if (selectError || !userRow) {
            console.error("supabase select (login) error:", selectError);
            return res.status(401).json({ error: "Invalid credentials" });
        }

        // Load role row by name to check permissions (do NOT select roles.id)
        let role = null;
        if (userRow.role) {
            const { data: roleRow, error: roleErr } = await supabase
                .from("roles")
                .select("name, can_post_login, can_get_my_user, can_get_users, can_post_products")
                .eq("name", userRow.role)
                .single();

            if (roleErr) {
                console.error("login: failed to load role:", roleErr);
            } else {
                role = roleRow;
            }
        }

        if (role && role.can_post_login === false) {
            return res.status(403).json({ error: "Forbidden: role not allowed to login" });
        }

        const match = await bcrypt.compare(password, userRow.password);
        if (!match) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        const token = signJwt({ userId: userRow.id, email: userRow.email });

        const user = {
            id: userRow.id,
            name: userRow.name,
            email: userRow.email,
            created_at: userRow.created_at,
            role: userRow.role,
        };

        return res.json({ user, token });
    } catch (err) {
        console.error("login error:", err);
        return res.status(500).json({ error: "Internal server error" });
    }
});

/**
 * POST /auth/change-password
 */
router.post("/change-password", authorizer, validateBody(changePasswordSchema), requirePermission("can_post_login"),
    async (req, res) => {
        const { oldPassword, newPassword } = req.body as {
            oldPassword: string;
            newPassword: string;
        };

        const user = (req as any).user;
        if (!user) return res.status(401).json({ error: "Unauthorized" });

        try {
            const { data, error: selectError } = await supabase
                .from("users")
                .select("password")
                .eq("id", user.id)
                .limit(1)
                .single();

            if (selectError || !data) {
                console.error("change-password: supabase select error:", selectError);
                return res.status(500).json({ error: "Internal server error" });
            }

            const currentHash = (data as any).password;
            const match = await bcrypt.compare(oldPassword, currentHash);
            if (!match) {
                return res.status(400).json({ error: "Old password is incorrect" });
            }

            const newHash = await bcrypt.hash(newPassword, 12);

            const { error: updateError } = await supabase
                .from("users")
                .update({
                    password: newHash,
                    password_changed_at: new Date().toISOString(),
                })
                .eq("id", user.id);

            if (updateError) {
                console.error("change-password: supabase update error:", updateError);
                return res.status(500).json({ error: "Internal server error" });
            }

            return res.json({ ok: true });
        } catch (err) {
            console.error("change-password unexpected:", err);
            return res.status(500).json({ error: "Internal server error" });
        }
    }
);

export default router;