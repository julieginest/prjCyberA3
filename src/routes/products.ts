import express, { Router, Request, Response } from "express";
import multer from "multer";
import { getRestClient } from "../shopify";
import { supabase } from "../supabase";
import { createProductSchema } from "../zod-schemas/product";
import { authorizer } from "../middleware/authorizer";
import { requirePermission } from "../middleware/permissions";

/**
 * products routes
 *
 * - GET /products        : admin => all products, otherwise only products created by the authenticated user
 * - GET /products/my     : explicit per-user list
 * - POST /products       : create product (JSON or multipart/form-data)
 *
 * This file accepts:
 * - JSON with image (image: URL) OR image_base64 (data URI or raw base64) in body
 * - multipart/form-data with file field `image`
 *
 * Images (file or image_base64 or image URL) are allowed ONLY for users with roleName === "PREMIUM"
 */

// Multer in-memory storage for file uploads (multipart)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 25 * 1024 * 1024, // 25 MB
  },
  fileFilter: (_req, file, cb) => {
    if (!file.mimetype.startsWith("image/")) {
      return cb(new Error("Only image files are allowed"));
    }
    cb(null, true);
  },
});

const router = Router();

// Route-level JSON parser with increased limit so clients can send base64 in JSON
// Note: If you also have app.use(express.json({ limit: '1mb' })) globally, ensure it does not reject large JSON
router.use(express.json({ limit: "25mb" }));

/**
 * GET /products
 */
router.get("/", authorizer, async (req: Request, res: Response) => {
  try {
    const user = (req as any).user;
    if (!user) return res.status(401).json({ error: "Unauthorized" });

    const roleName = user.role?.name ?? user.roleName ?? null;

    let query;
    if (roleName === "ADMIN") {
      query = supabase
        .from("products")
        .select("id, shopify_id, created_by, sales_count, metadata, created_at")
        .order("created_at", { ascending: false });
    } else {
      query = supabase
        .from("products")
        .select("id, shopify_id, created_by, sales_count, metadata, created_at")
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
 */
router.get("/my", authorizer, async (req: Request, res: Response) => {
  try {
    const user = (req as any).user;
    if (!user) return res.status(401).json({ error: "Unauthorized" });

    const { data, error } = await supabase
      .from("products")
      .select("id, shopify_id, created_by, sales_count, metadata, created_at")
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

/**
 * POST /products
 *
 * Accepts:
 * - JSON body: { name, price, image?: url, image_base64?: string (data URI or raw base64) }
 * - multipart/form-data: fields name, price and file field 'image'
 *
 * Permissions:
 * - require can_post_products
 * - images (file or image URL or image_base64) allowed ONLY for PREMIUM users
 */
router.post(
  "/",
  authorizer,
  requirePermission("can_post_products"),
  // Dispatch multer only for multipart/form-data requests
  async (req: Request, res: Response, next) => {
    const contentType = (req.headers["content-type"] || "").toString();
    if (contentType.startsWith("multipart/form-data")) {
      return upload.single("image")(req as any, res as any, (err: any) => {
        if (err) {
          console.error("multer error:", err);
          if (err.code === "LIMIT_FILE_SIZE") {
            return res.status(413).json({ error: "Uploaded file too large (max 25MB)" });
          }
          return res.status(400).json({ error: err.message || "Invalid file upload" });
        }
        return next();
      });
    }
    return next();
  },
  // Main handler
  async (req: Request, res: Response) => {
    const contentType = (req.headers["content-type"] || "").toString();
    let name: string | undefined;
    let priceRaw: any;
    let fileBuffer: Buffer | undefined;
    let imageUrlProvided = false;
    let imageBase64Provided = false;
    let imageBase64Value: string | undefined;

    // Debug - show resolved user/role
    const dbgUser = (req as any).user;
    console.debug("POST /products invoked - resolved user:", {
      id: dbgUser?.id,
      roleName: dbgUser?.roleName,
      roleObject: dbgUser?.role,
      authMethod: (req as any).authMethod,
      contentType,
    });

    if (contentType.startsWith("multipart/form-data")) {
      name = (req.body?.name as string) ?? undefined;
      priceRaw = req.body?.price ?? undefined;
      if ((req as any).file) {
        fileBuffer = (req as any).file.buffer as Buffer;
      }
    } else {
      // JSON path; body has already been parsed by router-level express.json({ limit: '25mb' })
      name = req.body?.name;
      priceRaw = req.body?.price;
      if (req.body?.image) imageUrlProvided = true;
      if (req.body?.image_base64) {
        imageBase64Provided = true;
        imageBase64Value = req.body?.image_base64 as string;
      } else if (typeof req.body?.image === "string") {
        // If client sent a data URI in image field (data:...base64,...), accept it as base64
        const maybeDataUri = req.body.image as string;
        if (maybeDataUri.startsWith("data:") && maybeDataUri.includes(";base64,")) {
          imageBase64Provided = true;
          imageBase64Value = maybeDataUri.split(",")[1];
        }
      }
    }

    // Validation
    if (!contentType.startsWith("multipart/form-data")) {
      try {
        // createProductSchema includes image_base64 validation and mutual-exclusion guard
        createProductSchema.parse(req.body);
      } catch (err: any) {
        return res.status(400).json({ error: err?.errors ?? "Invalid body" });
      }
    } else {
      // multipart manual validation
      if (!name || typeof name !== "string" || name.trim().length === 0) {
        return res.status(400).json({ error: "name is required" });
      }
      const parsedPrice = typeof priceRaw === "string" ? parseFloat(priceRaw) : priceRaw;
      if (parsedPrice === undefined || Number.isNaN(parsedPrice) || parsedPrice <= 0) {
        return res.status(400).json({ error: "price must be a positive number" });
      }
      priceRaw = parsedPrice;
    }

    const nameVal = name!.trim();
    const priceVal = typeof priceRaw === "string" ? parseFloat(priceRaw) : priceRaw;

    const user = (req as any).user;
    if (!user || !user.id) return res.status(401).json({ error: "Unauthorized" });

    // Enforce PREMIUM-only image rule
    const roleName = user.role?.name ?? (user.roleName as string | undefined) ?? null;
    const imagePresent = Boolean(fileBuffer) || imageUrlProvided || imageBase64Provided;

    if (imagePresent) {
      if (roleName !== "PREMIUM") {
        return res.status(403).json({ error: "Forbidden: requires PREMIUM access to include an image" });
      }
    }

    try {
      const client = getRestClient();

      const productPayload: any = {
        product: {
          title: nameVal,
          variants: [{ price: String(priceVal) }],
        },
      };

      // Priority for image sources:
      // 1) multipart fileBuffer (highest)
      // 2) image_base64 provided in JSON (data URI or raw base64)
      // 3) image URL in JSON (src)
      if (fileBuffer) {
        const base64 = fileBuffer.toString("base64");
        productPayload.product.images = [{ attachment: base64 }];
      } else if (imageBase64Provided && imageBase64Value) {
        // ensure no data: prefix is present; imageBase64Value should be raw base64 string (schema validated)
        const base64 = imageBase64Value;
        // double-check size (defensive)
        const buf = Buffer.from(base64, "base64");
        if (buf.length > 25 * 1024 * 1024) {
          return res.status(413).json({ error: "Decoded image too large (max 25MB)" });
        }
        productPayload.product.images = [{ attachment: base64 }];
      } else if (imageUrlProvided) {
        productPayload.product.images = [{ src: req.body.image }];
      }

      const response = await client.post({
        path: "products",
        data: productPayload,
        type: "application/json",
      });

      const createdProduct = (response.body as any)?.product;
      if (!createdProduct || !createdProduct.id) {
        console.error("Shopify returned unexpected response:", response.body);
        return res.status(502).json({ error: "Shopify API error" });
      }

      const shopifyId = String(createdProduct.id);

      const { data, error: insertError } = await supabase
        .from("products")
        .insert({
          shopify_id: shopifyId,
          created_by: user.id,
          metadata: createdProduct,
        })
        .select("id, shopify_id, created_by, sales_count, metadata, created_at")
        .single();

      if (insertError) {
        console.error("supabase insert (products) error:", insertError);
        return res.status(500).json({ error: "Internal server error" });
      }

      return res.status(201).json({ product: data, shopify_product: createdProduct });
    } catch (err: any) {
      console.error("POST /products error:", err?.response?.body ?? err);
      if (err?.response?.body) {
        return res.status(502).json({ error: "Shopify API error", details: err.response.body });
      }
      return res.status(500).json({ error: "Internal server error" });
    }
  }
);

export default router;