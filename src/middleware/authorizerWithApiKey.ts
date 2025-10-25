import { Request, Response, NextFunction } from "express";
import { verifyJwt } from "../utils/jwt";
import { supabase } from "../supabase";
import { verifyApiKey } from "../utils/apiKeys";

/**
 * Middleware that accepts either:
 * - Authorization: Bearer <token> (JWT)
 * - x-api-key: <key> (API key format "<id>.<token>")
 *
 * It loads the user row and role (by roles.name) and attaches (req as any).user.
 */
export async function authorizerWithApiKey(req: Request, res: Response, next: NextFunction) {
  try {
    const authHeader = req.headers.authorization;
    const apiKeyHeader = (req.headers["x-api-key"] as string) ?? (req.headers["X-API-KEY"] as string);

    let userId: string | null = null;
    let viaApiKey = false;

    if (authHeader && authHeader.startsWith("Bearer ")) {
      // JWT path
      const token = authHeader.slice("Bearer ".length).trim();
      try {
        const payload: any = verifyJwt(token);
        userId = payload?.userId ?? null;
      } catch (err) {
        return res.status(401).json({ error: "Invalid or expired token" });
      }
    } else if (apiKeyHeader) {
      // API key path
      const userIdFromKey = await verifyApiKey(apiKeyHeader);
      if (!userIdFromKey) {
        return res.status(401).json({ error: "Invalid API key" });
      }
      userId = userIdFromKey;
      viaApiKey = true;
    } else {
      return res.status(401).json({ error: "Missing Authorization or x-api-key header" });
    }

    if (!userId) {
      return res.status(401).json({ error: "Invalid authentication" });
    }

    // Load user row (same as previous authorizer)
    const { data: userRow, error: userError } = await supabase
      .from("users")
      .select("id, name, email, created_at, password_changed_at, role")
      .eq("id", userId)
      .single();

    if (userError || !userRow) {
      console.error("authorizerWithApiKey: supabase fetch user error:", userError);
      return res.status(401).json({ error: "Invalid token user" });
    }

    // If authenticated via JWT, optionally check token iat vs password_changed_at (handled in JWT verify earlier)
    // For API keys, we don't have a token iat, so skip that check.

    // Load role by name
    let roleObj = null;
    if ((userRow as any).role) {
      const { data: roleData, error: roleError } = await supabase
        .from("roles")
        .select("name, can_post_login, can_get_my_user, can_get_users, can_post_products")
        .eq("name", (userRow as any).role)
        .single();

      if (roleError) {
        console.error("authorizerWithApiKey: supabase fetch role error:", roleError);
      } else {
        roleObj = roleData;
      }
    }

    // Attach user (note: mark how they authenticated if needed)
    (req as any).user = {
      id: (userRow as any).id,
      name: (userRow as any).name,
      email: (userRow as any).email,
      created_at: (userRow as any).created_at,
      role: roleObj,
      roleName: (userRow as any).role,
      authMethod: viaApiKey ? "api_key" : "jwt",
    };

    return next();
  } catch (err) {
    console.error("authorizerWithApiKey unexpected error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
}