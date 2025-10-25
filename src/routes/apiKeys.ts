import { Router } from "express";
import crypto from "crypto";
import { supabase } from "../supabase";
import { validateBody } from "../middleware/validate";
import { createApiKeySchema } from "../zod-schemas/apiKey";
import { authorizer } from "../middleware/authorizer";

const router = Router();

/**
 * Helper: hash a raw key with SHA-256 and return hex digest
 */
function hashKey(raw: string) {
  return crypto.createHash("sha256").update(raw).digest("hex");
}

/**
 * POST /api-keys
 * - Create a new API key for the authenticated user
 * - Only allowed when authenticated via JWT (UI)
 * - Returns the raw key only once.
 */
router.post("/", authorizer, validateBody(createApiKeySchema), async (req, res) => {
  const user = (req as any).user;
  const authMethod = (req as any).authMethod as "jwt" | "api_key" | undefined;
  if (!user) return res.status(401).json({ error: "Unauthorized" });

  // Require JWT-based auth for key management (so user must be logged in via UI)
  if (authMethod !== "jwt") {
    return res.status(403).json({ error: "Must be authenticated via user session to manage API keys" });
  }

  const { name } = req.body as { name: string };

  try {
    // Ensure name unique for this user
    const { data: existing, error: existingErr } = await supabase
      .from("api_keys")
      .select("id")
      .eq("user_id", user.id)
      .eq("name", name)
      .limit(1);

    if (existingErr) {
      console.error("api-keys: supabase select error:", existingErr);
      return res.status(500).json({ error: "Internal server error" });
    }
    if (existing && existing.length > 0) {
      return res.status(409).json({ error: "API key name already exists" });
    }

    // Generate random raw key (hex), hash it and store only the hash
    const rawKey = crypto.randomBytes(32).toString("hex"); // 64 hex chars
    const hashed = hashKey(rawKey);

    const { data, error: insertErr } = await supabase
      .from("api_keys")
      .insert({
        user_id: user.id,
        name,
        hashed_key: hashed,
      })
      .select("id, name, created_at")
      .single();

    if (insertErr) {
      console.error("api-keys insert error:", insertErr);
      return res.status(500).json({ error: "Internal server error" });
    }

    // Return raw key once to the caller
    return res.status(201).json({ apiKey: { id: data.id, name: data.name, created_at: data.created_at }, key: rawKey });
  } catch (err) {
    console.error("POST /api-keys unexpected:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * GET /api-keys
 * - List keys for the authenticated user (JWT only)
 * - Does NOT return raw keys, only metadata
 */
router.get("/", authorizer, async (req, res) => {
  const user = (req as any).user;
  const authMethod = (req as any).authMethod as "jwt" | "api_key" | undefined;
  if (!user) return res.status(401).json({ error: "Unauthorized" });

  if (authMethod !== "jwt") {
    return res.status(403).json({ error: "Must be authenticated via user session to manage API keys" });
  }

  try {
    const { data, error } = await supabase
      .from("api_keys")
      .select("id, name, revoked, last_used_at, created_at")
      .eq("user_id", user.id)
      .order("created_at", { ascending: false });

    if (error) {
      console.error("GET /api-keys supabase error:", error);
      return res.status(500).json({ error: "Internal server error" });
    }

    return res.json({ apiKeys: data ?? [] });
  } catch (err) {
    console.error("GET /api-keys unexpected:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * DELETE /api-keys/:id
 * - Revoke/delete an API key owned by the authenticated user (JWT only)
 * - Soft revoke (set revoked=true)
 */
router.delete("/:id", authorizer, async (req, res) => {
  const user = (req as any).user;
  const authMethod = (req as any).authMethod as "jwt" | "api_key" | undefined;
  if (!user) return res.status(401).json({ error: "Unauthorized" });

  if (authMethod !== "jwt") {
    return res.status(403).json({ error: "Must be authenticated via user session to manage API keys" });
  }

  const id = req.params.id;
  try {
    // Verify ownership
    const { data: keyRow, error: selectErr } = await supabase
      .from("api_keys")
      .select("id, user_id, revoked")
      .eq("id", id)
      .limit(1)
      .single();

    if (selectErr || !keyRow) {
      return res.status(404).json({ error: "API key not found" });
    }
    if (keyRow.user_id !== user.id) {
      return res.status(403).json({ error: "Forbidden" });
    }

    // Soft revoke
    const { error: updateErr } = await supabase
      .from("api_keys")
      .update({ revoked: true })
      .eq("id", id);

    if (updateErr) {
      console.error("DELETE /api-keys update error:", updateErr);
      return res.status(500).json({ error: "Internal server error" });
    }

    return res.json({ ok: true });
  } catch (err) {
    console.error("DELETE /api-keys unexpected:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

export default router;