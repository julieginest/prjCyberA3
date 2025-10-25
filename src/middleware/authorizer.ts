import { Request, Response, NextFunction } from "express";
import crypto from "crypto";
import { verifyJwt } from "../utils/jwt";
import { supabase } from "../supabase";

export async function authorizer(req: Request, res: Response, next: NextFunction) {
  try {
    const authHeader = req.headers.authorization;
    const apiKeyHeader = (req.headers["x-api-key"] as string) || (req.headers["X-API-KEY"] as string);

    if (authHeader && authHeader.startsWith("Bearer ")) {
      const token = authHeader.slice("Bearer ".length).trim();
      let payload: any;
      try { payload = verifyJwt(token); } catch { return res.status(401).json({ error: "Invalid or expired token" }); }
      const userId = payload?.userId;
      if (!userId) return res.status(401).json({ error: "Invalid token payload" });

      const { data: userRow, error: userError } = await supabase
        .from("users")
        .select("id, name, email, created_at, password_changed_at, role")
        .eq("id", userId)
        .single();

      if (userError || !userRow) {
        console.error("authorizer: fetch user error:", userError);
        return res.status(401).json({ error: "Invalid token user" });
      }

      // load role by name and include the new permission
      let roleObj = null;
      if (userRow.role) {
        const { data: roleData, error: roleError } = await supabase
          .from("roles")
          .select("name, can_post_login, can_get_my_user, can_get_users, can_post_products, can_post_product_images, can_get_my_bestsellers")
          .eq("name", userRow.role)
          .single();

        if (roleError) {
          console.error("authorizer: fetch role error:", roleError);
        } else {
          roleObj = roleData;
        }
      }

      (req as any).authMethod = "jwt";
      (req as any).user = {
        id: userRow.id,
        name: userRow.name,
        email: userRow.email,
        created_at: userRow.created_at,
        role: roleObj,
        roleName: userRow.role,
      };

      // debug log (temporary)
      console.debug("authorizer jwt user:", { id: userRow.id, roleName: userRow.role, roleObj });

      return next();
    }

    if (apiKeyHeader) {
      const rawKey = apiKeyHeader.trim();
      if (!rawKey) return res.status(401).json({ error: "Invalid API key" });

      const hashed = crypto.createHash("sha256").update(rawKey).digest("hex");

      const { data: keyRow, error: keyErr } = await supabase
        .from("api_keys")
        .select("id, user_id, name, revoked")
        .eq("hashed_key", hashed)
        .limit(1)
        .single();

      if (keyErr || !keyRow) return res.status(401).json({ error: "Invalid API key" });
      if (keyRow.revoked) return res.status(403).json({ error: "API key revoked" });

      await supabase.from("api_keys").update({ last_used_at: new Date().toISOString() }).eq("id", keyRow.id);

      const { data: userRow, error: userError } = await supabase
        .from("users")
        .select("id, name, email, created_at, role")
        .eq("id", keyRow.user_id)
        .single();

      if (userError || !userRow) {
        console.error("authorizer (api key): fetch user error:", userError);
        return res.status(401).json({ error: "Invalid API key user" });
      }

      let roleObj = null;
      if (userRow.role) {
        const { data: roleData, error: roleError } = await supabase
          .from("roles")
          .select("name, can_post_login, can_get_my_user, can_get_users, can_post_products, can_post_product_images, can_get_my_bestsellers")
          .eq("name", userRow.role)
          .single();

        if (roleError) {
          console.error("authorizer (api key): fetch role error:", roleError);
        } else {
          roleObj = roleData;
        }
      }

      (req as any).authMethod = "api_key";
      (req as any).user = {
        id: userRow.id,
        name: userRow.name,
        email: userRow.email,
        created_at: userRow.created_at,
        role: roleObj,
        roleName: userRow.role,
        apiKeyName: keyRow.name,
        apiKeyId: keyRow.id,
      };

      console.debug("authorizer api_key user:", { id: userRow.id, roleName: userRow.role, roleObj });

      return next();
    }

    return res.status(401).json({ error: "Missing Authorization or x-api-key header" });
  } catch (err) {
    console.error("authorizer unexpected error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
}