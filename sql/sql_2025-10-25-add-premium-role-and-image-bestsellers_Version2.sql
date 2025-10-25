-- Migration: add permissions for product images and bestsellers, create PREMIUM role
-- Run in Supabase SQL editor. Idempotent.

BEGIN;

-- 1) Add new permission columns to roles table (if not exists)
ALTER TABLE roles
  ADD COLUMN IF NOT EXISTS can_post_product_images boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS can_get_my_bestsellers boolean NOT NULL DEFAULT false;

-- 2) Ensure PREMIUM role exists with appropriate permissions
INSERT INTO roles (name, can_post_login, can_get_my_user, can_get_users, can_post_products, can_post_product_images, can_get_my_bestsellers)
VALUES (
  'PREMIUM',
  true,   -- can log in
  true,   -- can get own user
  false,  -- cannot list all users
  true,   -- can post products
  true,   -- can post product images (new)
  true    -- can access my-bestsellers (new)
)
ON CONFLICT (name) DO UPDATE
SET
  can_post_login = EXCLUDED.can_post_login,
  can_get_my_user = EXCLUDED.can_get_my_user,
  can_get_users = EXCLUDED.can_get_users,
  can_post_products = EXCLUDED.can_post_products,
  can_post_product_images = EXCLUDED.can_post_product_images,
  can_get_my_bestsellers = EXCLUDED.can_get_my_bestsellers;

-- 3) Optionally, adjust ADMIN to have all these permissions
UPDATE roles
SET can_post_product_images = true, can_get_my_bestsellers = true
WHERE name = 'ADMIN';

COMMIT;