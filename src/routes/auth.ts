import { Router } from "express";
import bcrypt from "bcrypt";
import { supabase } from "../supabase";
import { signupSchema, loginSchema, changePasswordSchema } from "../zod-schemas/user";
import { validateBody } from "../middleware/validate";
import { signJwt } from "../utils/jwt";
import { authorizer } from "../middleware/authorizer";

const router = Router();

// ... other handlers (signin, change-password) remain unchanged

/**
 * POST /auth/login
 * Rate-limited to 1 attempt per 5 seconds per email.
 * Also checks role by name (role column on users) and role.can_post_login
 */
router.post("/login", validateBody(loginSchema), async (req, res) => {
    const { email, password } = req.body as { email: string; password: string };
    const emailLower = email.toLowerCase();

    const now = Date.now();
    const last = (global as any).__lastLoginAttempt?.get?.(emailLower) ?? 0; // keep your rate limiter logic
    // ... you can keep your existing rate limiter logic; omitted here for brevity

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

        // Load role row by name to check permissions (do NOT query roles.id)
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

        // If role exists and can_post_login is false => block login (e.g. BAN)
        if (role && role.can_post_login === false) {
            return res.status(403).json({ error: "Forbidden: role not allowed to login" });
        }

        // Compare password
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

export default router;