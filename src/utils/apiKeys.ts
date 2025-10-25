import crypto from "crypto";
import { supabase } from "../supabase";

const API_KEY_SECRET = process.env.API_KEY_SECRET ?? process.env.JWT_SECRET ?? "change_this_in_prod";

/**
 * Generate a new API key for a user.
 * Returns { id, key } where key is the plaintext API key that must be shown once to the user.
 */
export async function createApiKeyForUser(userId: string, name: string) {
  // create random token part
  const token = crypto.randomBytes(32).toString("hex"); // 64 hex chars
  // compute HMAC-SHA256 with server secret
  const tokenHash = crypto.createHmac("sha256", API_KEY_SECRET).update(token).digest("hex");

  // insert row and return id + plaintext key = `${id}.${token}`
  const { data, error } = await supabase
    .from("api_keys")
    .insert({
      name,
      user_id: userId,
      token_hash: tokenHash,
    })
    .select("id, name, created_at")
    .single();

  if (error || !data) {
    throw error ?? new Error("Failed to create api key");
  }

  const id = (data as any).id as string;
  const plaintextKey = `${id}.${token}`;
  return {
    id,
    name: (data as any).name,
    key: plaintextKey,
    created_at: (data as any).created_at,
  };
}

/**
 * List API keys for a user (sanitized: do NOT return token_hash)
 */
export async function listApiKeysForUser(userId: string) {
  const { data, error } = await supabase
    .from("api_keys")
    .select("id, name, created_at, last_used_at, revoked")
    .eq("user_id", userId)
    .order("created_at", { ascending: false });

  if (error) throw error;
  return data ?? [];
}

/**
 * Revoke / delete an API key by id for a user.
 * Only allow deletion if the row belongs to the user.
 */
export async function revokeApiKey(userId: string, apiKeyId: string) {
  // We mark revoked = true (safer) or you could delete the row.
  const { error } = await supabase
    .from("api_keys")
    .update({ revoked: true })
    .match({ id: apiKeyId, user_id: userId });

  if (error) throw error;
  return true;
}

/**
 * Verify an API key plaintext.
 * Returns the user_id (string) if valid & not revoked, otherwise null.
 * Also updates last_used_at on success.
 */
export async function verifyApiKey(plaintextKey: string) {
  // expected format: "<id>.<token>"
  const parts = plaintextKey.split(".");
  if (parts.length !== 2) return null;
  const [id, token] = parts;
  if (!id || !token) return null;

  // fetch the row by id
  const { data, error } = await supabase
    .from("api_keys")
    .select("id, user_id, token_hash, revoked")
    .eq("id", id)
    .limit(1)
    .single();

  if (error || !data) return null;
  if ((data as any).revoked) return null;

  const storedHash = (data as any).token_hash as string;
  const computedHash = crypto.createHmac("sha256", API_KEY_SECRET).update(token).digest("hex");

  // timing-safe compare
  const a = Buffer.from(storedHash, "hex");
  const b = Buffer.from(computedHash, "hex");
  if (a.length !== b.length) return null;
  if (!crypto.timingSafeEqual(a, b)) return null;

  // update last_used_at
  await supabase
    .from("api_keys")
    .update({ last_used_at: new Date().toISOString() })
    .eq("id", id);

  return (data as any).user_id as string;
}