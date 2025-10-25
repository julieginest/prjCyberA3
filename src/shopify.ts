import dotenv from "dotenv";
import axios from "axios";

dotenv.config();

const SHOP = process.env.SHOPIFY_SHOP;
const TOKEN = process.env.SHOPIFY_ACCESS_TOKEN;
const API_VERSION = process.env.SHOPIFY_API_VERSION ?? "2025-01";

/**
 * Minimal axios-based fallback client implementing the small subset we need:
 * post({ path, data, type }) -> { body }
 */
function makeFallbackClient(shop: string, token: string) {
  const base = `https://${shop}/admin/api/${API_VERSION}`;
  return {
    async post(opts: { path: string; data?: any; type?: string }) {
      const url = `${base}/${opts.path}.json`;
      try {
        const resp = await axios.post(url, opts.data ?? {}, {
          headers: {
            "X-Shopify-Access-Token": token,
            "Content-Type": opts.type ?? "application/json",
          },
          timeout: 10_000,
        });
        return { body: resp.data };
      } catch (err: any) {
        const message = err?.response?.data ?? err?.message ?? String(err);
        const e: any = new Error("Shopify axios request failed: " + String(message));
        e.response = { body: err?.response?.data, status: err?.response?.status };
        throw e;
      }
    },
    async get(opts: { path: string; params?: any }) {
      const url = `${base}/${opts.path}.json`;
      try {
        const resp = await axios.get(url, {
          headers: {
            "X-Shopify-Access-Token": token,
            "Content-Type": "application/json",
          },
          params: opts.params,
          timeout: 10_000,
        });
        return { body: resp.data };
      } catch (err: any) {
        const message = err?.response?.data ?? err?.message ?? String(err);
        const e: any = new Error("Shopify axios request failed: " + String(message));
        e.response = { body: err?.response?.data, status: err?.response?.status };
        throw e;
      }
    },
  };
}

/**
 * Return a REST client compatible object for our usage.
 * Strategy:
 * - try to load @shopify/shopify-api and find a Rest client constructor
 * - try several constructor signatures, but if any attempt throws, fallback to axios client
 */
export function getRestClient(shop: string = SHOP!, token: string = TOKEN!) {
  if (!shop || !token) {
    throw new Error("SHOPIFY_SHOP and SHOPIFY_ACCESS_TOKEN must be set in environment");
  }

  // Try to load the official package
  let pkg: any;
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    pkg = require("@shopify/shopify-api");
  } catch (err) {
    console.warn("Shopify package not installed or failed to load, using fallback axios client.");
    return makeFallbackClient(shop, token);
  }

  // Candidate constructors/locations observed in different versions/builds
  const RestCtorCandidates: Array<any> = [
    pkg?.RestClient,
    pkg?.Clients?.Rest,
    pkg?.Shopify?.Clients?.Rest,
    pkg?.default?.Clients?.Rest,
    pkg?.default?.RestClient,
    pkg?.shopifyApi?.RestClient,
    pkg?.Rest,
    pkg?.default?.Rest,
  ].filter(Boolean);

  if (RestCtorCandidates.length === 0) {
    console.warn("Shopify package loaded but no Rest client constructor found; using fallback axios client.");
    console.debug("shopify package top-level keys:", Object.keys(pkg || {}));
    return makeFallbackClient(shop, token);
  }

  // Try to construct the client with several signatures. If any attempt succeeds and
  // the result exposes a .post function, return it. If all attempts throw, fallback.
  for (const RestCtor of RestCtorCandidates) {
    const attempts = [
      () => new RestCtor(shop, token, { apiVersion: API_VERSION }),
      () => new RestCtor(shop, token),
      () => new RestCtor({ domain: shop, accessToken: token, apiVersion: API_VERSION }),
      () => new RestCtor({ domain: shop, accessToken: token }),
    ];
    for (const attempt of attempts) {
      try {
        const client = attempt();
        if (client && typeof client.post === "function") {
          return client;
        }
        // Some builds may return a namespace where methods are static; attempt to adapt:
        if (RestCtor && typeof RestCtor.post === "function") {
          // static post available, wrap into object shape we expect
          return {
            post: (opts: any) => RestCtor.post(opts),
            get: (opts: any) => RestCtor.get(opts),
          };
        }
      } catch (err) {
        // constructor attempt failed; continue to next attempt
        console.debug("shopify RestCtor attempt failed, will try fallback if all attempts fail:", String(err));
      }
    }
  }

  // If we reach here, all constructor attempts failed -> use axios fallback
  console.warn("All attempts to construct Shopify Rest client failed; using axios fallback client.");
  console.debug("shopify package top-level keys:", Object.keys(pkg || {}));
  return makeFallbackClient(shop, token);
}