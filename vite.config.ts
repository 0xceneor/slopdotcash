/**
 * Builds the static slop.cash contribution surface for Cloudflare Pages.
 */

import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [
    react(),
    {
      // The browser lists projects from the D1 registry at runtime. Only
      // projects.mjs swaps the committed snapshot for the runtime registry;
      // ingestion validation keeps the snapshot the ledger was built from.
      name: "runtime-project-registry",
      enforce: "pre",
      resolveId(source, importer) {
        if (
          source === "./project-registry.generated.mjs" &&
          importer?.replaceAll("\\", "/").endsWith("/src/lib/projects.mjs")
        )
          return fileURLToPath(
            new URL("./src/lib/project-registry.runtime.mjs", import.meta.url),
          );
        return null;
      },
    },
    {
      name: "staging-security-headers",
      closeBundle() {
        if (process.env.VITE_SLOP_ENVIRONMENT !== "staging") return;
        const path = "dist/_headers";
        writeFileSync(
          path,
          readFileSync(path, "utf8")
            .replaceAll("https://api.slop.cash", "https://staging.slop.cash")
            .replaceAll(
              "https://identity.slop.cash",
              "https://identity-staging.slop.cash",
            )
            .replace("/*\n", "/*\n  X-Robots-Tag: noindex, nofollow\n"),
        );
      },
    },
  ],
  // Local UI development reads the public staging registry, independently of
  // build outputs. The legacy file URL is also supported for existing sessions.
  server: {
    proxy: {
      "^/(?:api/v1/projects|data/project-registry\\.json)(?:\\?.*)?$": {
        target: "https://staging.slop.cash",
        changeOrigin: true,
        rewrite: (path) =>
          path.replace(/^\/data\/project-registry\.json/, "/api/v1/projects"),
        bypass: (request) =>
          request.method === "GET" || request.method === "HEAD"
            ? undefined
            : false,
        configure: (proxy) => {
          proxy.on("proxyReq", (request) => {
            request.removeHeader("cookie");
            request.removeHeader("authorization");
          });
        },
      },
    },
  },
  build: {
    target: "es2022",
    // The production CSP sets font-src 'self', which blocks data: URIs, so
    // self-hosted font subsets must ship as files rather than inlined assets.
    assetsInlineLimit: (filePath) =>
      /\.(woff2?|ttf|otf)$/.test(filePath) ? false : undefined,
  },
  // Cloudflare Pages serves /data/* with Access-Control-Allow-Origin: *
  // (public/_headers) so other program surfaces (e.g. the Eliza Hub landing
  // page) can read the published snapshot. Mirror that in local preview.
  preview: {
    // Preview must serve the built registry snapshot, not the dev API proxy.
    proxy: {},
    cors: true,
  },
});
