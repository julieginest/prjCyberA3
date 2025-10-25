import { Request, Response, NextFunction } from "express";
import crypto from "crypto";
import { verifyJwt } from "../utils/jwt";
import { supabase } from "../supabase";

/**
 * authorizer:
 * - Support both Authorization: Bearer <jwt> and x-api-key: <raw_key>
 * - Sets (req as any).authMethod = 'jwt' | 'api_key'
 * - Attaches (req as any).user = { id, name, email, created_at, role, roleName, ... }
 *
 * Behavior:
 * - If Authorization present -> JWT flow (same as before).
 * - Else if x-api-key present -> API key flow:
 *    - hashes provided raw key with SHA-256 and looks up api_keys.hashed_key
 *    - ensures not revoked, updates last_used_at
 *    - fetches linked user and role (by name) and attaches them
 */
export async function authorizer(req: Request, res: Response, next: NextFunction) {
  try {
    const authHeader = req.headers.authorization;
    const apiKeyHeader = (req.headers["x-api-key"] as string) || (req.headers["X-API-KEY"] as string);

    // Prefer JWT if present
    if (authHeader && authHeader.startsWith("Bearer ")) {
      const token = authHeader.slice("Bearer ".length).trim();
      let payload: any;
      try {
        payload = verifyJwt(token);
      } catch (err) {
        return res.status(401).json({ error: "Invalid or expired token" });
      }

      const userId = payload?.userId;
      if (!userId) {
        return res.status(401).json({ error: "Invalid token payload" });
      }

      // Fetch user row (including role text column)
      const { data: userRow, error: userError } = await supabase
        .from("users")
        .select("id, name, email, created_at, password, password_changed_at, role")
        .eq("id", userId)
        .single();

      if (userError || !userRow) {
        console.error("authorizer: supabase fetch user error:", userError);
        return res.status(401).json({ error: "Invalid token user" });
      }

      // password_changed_at revocation check (JWT tokens)
      const tokenIatSec = payload.iat;
      if (tokenIatSec && userRow.password_changed_at) {
        const pwdChangedAt = new Date(userRow.password_changed_at).getTime() / 1000;
        if (pwdChangedAt > tokenIatSec) {
          return res.status(401).json({ error: "Token revoked due to password change" });
        }
      }

      // Load role by name (userRow.role)
      let roleObj = null;
      if (userRow.role) {
        const { data: roleData, error: roleError } = await supabase
          .from("roles")
          .select("name, can_post_login, can_get_my_user, can_get_users, can_post_products")
          .eq("name", userRow.role)
          .single();

        if (roleError) {
          console.error("authorizer: supabase fetch role error:", roleError);
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

      return next();
    }

    // Else try x-api-key header
    if (apiKeyHeader) {
      const rawKey = apiKeyHeader.trim();
      if (!rawKey) return res.status(401).json({ error: "Invalid API key" });

      // hash key with sha256 (same as creation)
      const hashed = crypto.createHash("sha256").update(rawKey).digest("hex");

      // find api_key row
      const { data: keyRow, error: keyErr } = await supabase
        .from("api_keys")
        .select("id, user_id, name, revoked")
        .eq("hashed_key", hashed)
        .limit(1)
        .single();

      if (keyErr || !keyRow) {
        // don't leak which part failed
        return res.status(401).json({ error: "Invalid API key" });
      }

      if (keyRow.revoked) {
        return res.status(403).json({ error: "API key revoked" });
      }

      // update last_used_at
      await supabase.from("api_keys").update({ last_used_at: new Date().toISOString() }).eq("id", keyRow.id);

      // fetch the user
      const { data: userRow, error: userError } = await supabase
        .from("users")
        .select("id, name, email, created_at, role")
        .eq("id", keyRow.user_id)
        .single();

      if (userError || !userRow) {
        console.error("authorizer (api key): supabase fetch user error:", userError);
        return res.status(401).json({ error: "Invalid API key user" });
      }

      // Load role by name
      let roleObj = null;
      if (userRow.role) {
        const { data: roleData, error: roleError } = await supabase
          .from("roles")
          .select("name, can_post_login, can_get_my_user, can_get_users, can_post_products")
          .eq("name", userRow.role)
          .single();

        if (roleError) {
          console.error("authorizer (api key): supabase fetch role error:", roleError);
        } else {
          roleObj = roleData;
        }
      }

      (req as any).authMethod = "api_key";
      // attach user as for JWT flow (but authMethod differs)
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

      return next();
    }

    // neither header -> unauthorized
    return res.status(401).json({ error: "Missing Authorization or x-api-key header" });
  } catch (err) {
    console.error("authorizer unexpected error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
}