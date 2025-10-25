import express from "express";
import dotenv from "dotenv";
import authRoutes from "./routes/auth";
import userRoutes from "./routes/user";
import productsRoutes from "./routes/products";

dotenv.config();

const app = express();
app.use(express.json());

// Routes
app.use("/auth", authRoutes);
app.use("/users", userRoutes); // GET /users and /my-user are in routes/user.ts
app.use("/products", productsRoutes);

// Basic healthcheck
app.get("/health", (_, res) => res.json({ status: "ok" }));

const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;
app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});