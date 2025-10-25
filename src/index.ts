import express from "express";
import dotenv from "dotenv";
import authRoutes from "./routes/auth";
import userRoutes from "./routes/user";
import productsRoutes from "./routes/products";
import apiKeysRoutes from "./routes/apiKeys";
import shopifyWebhookHandler from "./routes/webhooks";
import { sizeLimiter } from "./middleware/sizeLimiter";

dotenv.config();

const app = express();

// Mount size limiter early (checks Content-Length if present)
// Note: keep webhook route mounted before express.json so raw body verification works.
app.use(sizeLimiter);

// Webhook route: raw parser with 1MB limit (Shopify webhook bodies are typically small)
app.post(
  "/webhooks/shopify-sales",
  express.raw({ type: "application/json", limit: "1mb" }),
  shopifyWebhookHandler
);

// JSON and URL-encoded parsers: limit 1MB
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));

app.use("/", userRoutes);
app.use("/auth", authRoutes);
app.use("/products", productsRoutes);
app.use("/api", apiKeysRoutes);

// healthcheck
app.get("/health", (_, res) => res.json({ status: "ok" }));

const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;
app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});