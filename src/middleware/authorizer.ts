import { Request, Response, NextFunction } from "express";
import crypto from "crypto";
import { verifyJwt } from "../utils/jwt";
import { supabase } from "../supabase";

/**
 * authorizer:
 * - Support both Authorization: Bearer <jwt> and x-api-key: <raw_key>
 * - Sets (req as any).authMethod = 'jwt' | 'api_key'
 * - Attaches (req as any).user with normalized fields:
 *    - id, name, email, created_at
 *    - role: object|null (role row with permission booleans)
 *    - roleName: normalized string to test identity
 *
 * Additional: invalidates JWTs issued before users.password_changed_at
 */
export async function authorizer(req: Request, res: Response, next: NextFunction) {
  try {
    const authHeader = req.headers.authorization;
    const apiKeyHeader = (req.headers["x-api-key"] as string) || (req.headers["X-API-KEY"] as string);

    const normalizeRoleName = (name: any) => {
      if (!name) return null;
      return String(name).trim();
    };

    // JWT flow
    if (authHeader && authHeader.startsWith("Bearer ")) {
      const token = authHeader.slice("Bearer ".length).trim();
      let payload: any;
      try {
        payload = verifyJwt(token);
      } catch (err) {
        return res.status(401).json({ error: "Invalid or expired token" });
      }

      const userId = payload?.userId;
      const tokenIat = typeof payload?.iat === "number" ? payload.iat : undefined; // seconds since epoch
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

      // If the user has a password_changed_at, invalidate tokens issued before that time
      if (userRow.password_changed_at && tokenIat) {
        const pwdChangedAtSec = Math.floor(new Date(userRow.password_changed_at).getTime() / 1000);
        if (tokenIat < pwdChangedAtSec) {
          console.debug("authorizer: token issued before password change", { tokenIat, pwdChangedAtSec });
          return res.status(401).json({ error: "Invalid or expired token" });
        }
      }

      // Load role row (permissions)
      let roleObj: any = null;
      let roleNameNormalized: string | null = null;
      if (userRow.role) {
        const { data: roleData, error: roleError } = await supabase
          .from("roles")
          .select(
            "name, can_post_login, can_get_my_user, can_get_users, can_post_products, can_post_product_images, can_get_my_bestsellers"
          )
          .eq("name", userRow.role)
          .single();

        if (roleError) {
          console.error("authorizer: fetch role error:", roleError);
        } else if (roleData) {
          roleObj = roleData;
          roleNameNormalized = normalizeRoleName(roleData.name);
        }
      }

      if (!roleNameNormalized && userRow.role) {
        roleNameNormalized = normalizeRoleName(userRow.role);
      }

      (req as any).authMethod = "jwt";
      (req as any).user = {
        id: userRow.id,
        name: userRow.name,
        email: userRow.email,
        created_at: userRow.created_at,
        role: roleObj,
        roleName: roleNameNormalized,
      };

      console.debug("authorizer(jwt) attached user:", { id: userRow.id, roleName: roleNameNormalized });

      return next();
    }

    // API key flow — unchanged (API keys are not invalidated by password changes)
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

      // update last_used_at in background
      void (async () => {
        try {
          await supabase.from("api_keys").update({ last_used_at: new Date().toISOString() }).eq("id", keyRow.id);
        } catch (e) {
          console.error("authorizer: failed to update api_keys.last_used_at", e);
        }
      })();

      const { data: userRow, error: userError } = await supabase
        .from("users")
        .select("id, name, email, created_at, role, password_changed_at")
        .eq("id", keyRow.user_id)
        .single();

      if (userError || !userRow) {
        console.error("authorizer (api key): fetch user error:", userError);
        return res.status(401).json({ error: "Invalid API key user" });
      }

      // Note: We do NOT invalidate api keys on password change. If you want that behavior, add logic here.

      let roleObj: any = null;
      let roleNameNormalized: string | null = null;
      if (userRow.role) {
        const { data: roleData, error: roleError } = await supabase
          .from("roles")
          .select(
            "name, can_post_login, can_get_my_user, can_get_users, can_post_products, can_post_product_images, can_get_my_bestsellers"
          )
          .eq("name", userRow.role)
          .single();

        if (roleError) {
          console.error("authorizer (api key): fetch role error:", roleError);
        } else if (roleData) {
          roleObj = roleData;
          roleNameNormalized = normalizeRoleName(roleData.name);
        }
      }

      if (!roleNameNormalized && userRow.role) {
        roleNameNormalized = normalizeRoleName(userRow.role);
      }

      (req as any).authMethod = "api_key";
      (req as any).user = {
        id: userRow.id,
        name: userRow.name,
        email: userRow.email,
        created_at: userRow.created_at,
        role: roleObj,
        roleName: roleNameNormalized,
        apiKeyName: keyRow.name,
        apiKeyId: keyRow.id,
      };

      console.debug("authorizer(api_key) attached user:", { id: userRow.id, roleName: roleNameNormalized, apiKeyId: keyRow.id });

      return next();
    }

    // No auth
    return res.status(401).json({ error: "Missing Authorization or x-api-key header" });
  } catch (err) {
    console.error("authorizer unexpected error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
}