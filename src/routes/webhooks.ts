import { Request, Response } from "express";
import crypto from "crypto";
import { supabase } from "../supabase";

/**
 * Shopify order/create webhook handler.
 * - Requires raw Buffer body (express.raw middleware).
 * - Verifies X-Shopify-Hmac-Sha256 using SHOPIFY_WEBHOOK_SECRET (base64 HMAC SHA256).
 * - Aggregates product quantities from line_items and increments products.sales_count.
 */
export default async function shopifySalesWebhookHandler(req: Request, res: Response) {
  try {
    const secret = process.env.SHOPIFY_WEBHOOK_SECRET;
    if (!secret) {
      console.error("SHOPIFY_WEBHOOK_SECRET not set");
      return res.status(500).send("Webhook secret not configured");
    }

    // req.body must be a Buffer (express.raw middleware)
    const rawBody = req.body as Buffer | undefined;
    if (!rawBody || !Buffer.isBuffer(rawBody)) {
      console.error("Webhook handler requires raw Buffer body. Ensure route uses express.raw()");
      return res.status(400).send("Invalid body");
    }

    const hmacHeader = (req.headers["x-shopify-hmac-sha256"] as string) || (req.headers["X-Shopify-Hmac-Sha256"] as string);
    if (!hmacHeader) {
      console.warn("Missing X-Shopify-Hmac-Sha256 header");
      return res.status(401).send("Missing signature");
    }

    // Compute HMAC SHA256 and compare using timingSafeEqual.
    // Note: Shopify provides a base64-encoded HMAC.
    const hmac = crypto.createHmac("sha256", secret).update(rawBody).digest(); // raw buffer
    const expected = Buffer.from(hmac).toString("base64");
    // Use base64 buffers for timing-safe comparison
    const a = Buffer.from(expected, "base64");
    const b = Buffer.from(hmacHeader, "base64");
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      console.warn("Invalid webhook signature", { expected, header: hmacHeader });
      return res.status(401).send("Invalid signature");
    }

    // Parse JSON payload from raw body
    let payload: any;
    try {
      payload = JSON.parse(rawBody.toString("utf8"));
    } catch (err) {
      console.error("Failed to parse webhook JSON:", err);
      return res.status(400).send("Invalid JSON");
    }

    // Aggregate quantities per product_id
    const lineItems = Array.isArray(payload?.line_items) ? payload.line_items : [];
    if (lineItems.length === 0) return res.status(200).send("No line items");

    const counts = new Map<string, number>();
    for (const li of lineItems) {
      const productId = li?.product_id ?? li?.product?.id ?? null;
      const qty = Number(li?.quantity ?? 0);
      if (!productId || Number.isNaN(qty) || qty <= 0) continue;
      const key = String(productId);
      counts.set(key, (counts.get(key) ?? 0) + qty);
    }

    if (counts.size === 0) return res.status(200).send("No valid product ids");

    const items = Array.from(counts.entries()).map(([shopify_id, qty]) => ({ shopify_id, qty }));

    // Call Postgres function to update sales_count atomically (assumes function increment_product_sales exists)
    const { error } = await supabase.rpc("increment_product_sales", { items });

    if (error) {
      console.error("increment_product_sales rpc error:", error);
      return res.status(500).send("DB update error");
    }

    return res.status(200).send("OK");
  } catch (err) {
    console.error("shopify webhook unexpected error:", err);
    return res.status(500).send("Internal error");
  }
}