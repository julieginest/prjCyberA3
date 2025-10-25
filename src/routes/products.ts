import { Router } from "express";
import { getRestClient } from "../shopify";
import { supabase } from "../supabase";
import { validateBody } from "../middleware/validate";
import { createProductSchema } from "../zod-schemas/product";
import { authorizer } from "../middleware/authorizer";
import { requirePermission } from "../middleware/permissions";
//import { authorizerWithApiKey } from "../middleware/authorizerWithApiKey";

const router = Router();

/**
 * POST /products
 * - Protected: authorizer + requirePermission('can_post_products')
 * - Uses @shopify/shopify-api REST client to create product
 */
router.post(
  "/",
  authorizer,
  requirePermission("can_post_products"),
  validateBody(createProductSchema),
  async (req, res) => {
    const { name, price } = req.body as { name: string; price: number };
    const user = (req as any).user;
    if (!user || !user.id) return res.status(401).json({ error: "Unauthorized" });

    try {
      const client = getRestClient();

      // Create product in Shopify Admin via REST client
      const response = await client.post({
        path: "products",
        data: {
          product: {
            title: name,
            variants: [{ price: String(price) }],
          },
        },
        type: "application/json",
      });

      const createdProduct = (response.body as any)?.product;
      if (!createdProduct || !createdProduct.id) {
        console.error("Shopify returned unexpected response:", response.body);
        return res.status(502).json({ error: "Shopify API error" });
      }

      const shopifyId = String(createdProduct.id);

      // Save to our DB
      const { data, error: insertError } = await supabase
        .from("products")
        .insert({
          shopify_id: shopifyId,
          created_by: user.id,
        })
        .select("id, shopify_id, created_by, sales_count, created_at")
        .single();

      if (insertError) {
        console.error("supabase insert (products) error:", insertError);
        return res.status(500).json({ error: "Internal server error" });
      }

      return res.status(201).json({ product: data, shopify_product: createdProduct });
    } catch (err: any) {
      // shopify-api throws with response details sometimes, handle gracefully
      console.error("POST /products error:", err?.response?.body ?? err);
      return res.status(502).json({ error: "Shopify API error", details: err?.response?.body ?? err?.message });
    }
  }
);

/**
 * GET /products
 * - If user is ADMIN => return all products
 * - Otherwise => return only products created by the authenticated user
 */
router.get("/", authorizer, async (req, res) => {
  const user = (req as any).user;
  if (!user) return res.status(401).json({ error: "Unauthorized" });

  // Determine role name: prefer role object, fallback to raw roleName
  const roleName = user.role?.name ?? user.roleName ?? null;

  try {
    let query;
    if (roleName === "ADMIN") {
      // Admin: return all products
      query = supabase
        .from("products")
        .select("id, shopify_id, created_by, sales_count, created_at")
        .order("created_at", { ascending: false });
    } else {
      // Non-admin: only their own products
      query = supabase
        .from("products")
        .select("id, shopify_id, created_by, sales_count, created_at")
        .eq("created_by", user.id)
        .order("created_at", { ascending: false });
    }

    const { data, error } = await query;
    if (error) {
      console.error("GET /products supabase error:", error);
      return res.status(500).json({ error: "Internal server error" });
    }

    return res.json({ products: data ?? [] });
  } catch (err) {
    console.error("GET /products unexpected:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * GET /products/my
 * - Authenticated (authorizer)
 * - Returns products created by the authenticated user
 */
router.get("/my", authorizer, async (req, res) => {
  const user = (req as any).user;
  if (!user) return res.status(401).json({ error: "Unauthorized" });

  try {
    const { data, error } = await supabase
      .from("products")
      .select("id, shopify_id, created_by, sales_count, created_at")
      .eq("created_by", user.id)
      .order("created_at", { ascending: false });

    if (error) {
      console.error("GET /products/my supabase error:", error);
      return res.status(500).json({ error: "Internal server error" });
    }

    return res.json({ products: data ?? [] });
  } catch (err) {
    console.error("GET /products/my unexpected:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

export default router;