import { Router } from "express";
import { authorizer } from "../middleware/authorizer";
import { requirePermission } from "../middleware/permissions";
import { supabase } from "../supabase";

const router = Router();

/**
 * GET /my-user
 * - authentifié
 * - permission can_get_my_user requise
 */
router.get("/my-user", authorizer, requirePermission("can_get_my_user"), async (req, res) => {
  const user = (req as any).user;
  if (!user) return res.status(401).json({ error: "Unauthorized" });
  return res.json({ user });
});

/**
 * GET /users
 * - authentifié
 * - permission can_get_users requise
 */
router.get("/users", authorizer, requirePermission("can_get_users"), async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("users")
      .select("id, name, email, created_at")
      .order("created_at", { ascending: true });

    if (error) {
      console.error("GET /users supabase error:", error);
      return res.status(500).json({ error: "Internal server error" });
    }
    return res.json({ users: data });
  } catch (err) {
    console.error("GET /users unexpected:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

export default router;