import { Request, Response, NextFunction } from "express";

/**
 * Permissions disponibles sur le rôle (nommage conforme à la BD)
 */
type PermissionKey =
    | "can_post_login"
    | "can_get_my_user"
    | "can_get_users"
    | "can_post_products"
    | "can_post_product_images"   // nouvelle permission
    | "can_get_my_bestsellers";   // nouvelle permission

/**
 * Middleware factory: requirePermission('can_post_products') -> vérifie req.user.role.can_post_products === true
 */
export function requirePermission(permission: PermissionKey) {
    return (req: Request, res: Response, next: NextFunction) => {
        const user = (req as any).user;
        if (!user) {
            return res.status(401).json({ error: "Unauthorized" });
        }

        const role = user.role;
        // If no role object found => no permissions
        if (!role) {
            return res.status(403).json({ error: "Forbidden: no role assigned" });
        }

        if (!role[permission]) {
            return res.status(403).json({ error: "Forbidden: insufficient permissions" });
        }

        return next();
    };
}