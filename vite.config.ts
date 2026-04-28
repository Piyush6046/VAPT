import path from "path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react-swc";
import { tempo } from "tempo-devtools/dist/vite";

// https://vitejs.dev/config/
export default defineConfig({
  base: process.env.NODE_ENV === "development" ? "/" : process.env.VITE_BASE_PATH || "/",
  optimizeDeps: {
    entries: ["src/main.tsx", "src/tempobook/**/*"],
  },
  plugins: [react(), tempo()],
  resolve: {
    preserveSymlinks: true,
    alias: { "@": path.resolve(__dirname, "./src") },
  },
  server: {
    // @ts-ignore
    allowedHosts: true,
    proxy: {
      // /api/audit?url=https://target — performs real HEAD request server-side (no CORS)
      "/api/audit": {
        target: "http://localhost:5173",
        bypass(req, res) {
          const searchStart = req.url!.indexOf("?");
          const params = new URLSearchParams(searchStart >= 0 ? req.url!.slice(searchStart) : "");
          const rawUrl = params.get("url");
          if (!rawUrl) {
            res!.writeHead(400, { "Content-Type": "application/json" });
            res!.end(JSON.stringify({ error: "Missing url parameter" }));
            return false;
          }
          let targetUrl: URL;
          try {
            targetUrl = new URL(rawUrl.startsWith("http") ? rawUrl : `https://${rawUrl}`);
          } catch {
            res!.writeHead(400, { "Content-Type": "application/json" });
            res!.end(JSON.stringify({ error: "Invalid URL" }));
            return false;
          }
          // Use Node built-in https to HEAD the target
          // Dynamic require so Vite doesn't try to bundle it
          const https = require("https") as typeof import("https");
          const options: import("https").RequestOptions = {
            hostname: targetUrl.hostname,
            port: targetUrl.port ? parseInt(targetUrl.port) : 443,
            path: targetUrl.pathname || "/",
            method: "HEAD",
            timeout: 8000,
            headers: {
              "User-Agent": "VAPT-Framework/1.0 (Educational Security Scanner)",
              "Accept": "*/*",
            },
            rejectUnauthorized: false, // needed for self-signed certs on vuln labs
          };
          const request = https.request(options, (response) => {
            const hdrs: Record<string, string> = {};
            for (const [k, v] of Object.entries(response.headers)) {
              if (v) hdrs[k.toLowerCase()] = Array.isArray(v) ? v[0] : (v as string);
            }
            const result = {
              reachable: true,
              statusCode: response.statusCode,
              headers: hdrs,
              server: hdrs["server"] || null,
              poweredBy: hdrs["x-powered-by"] || null,
            };
            res!.writeHead(200, {
              "Content-Type": "application/json",
              "Access-Control-Allow-Origin": "*",
            });
            res!.end(JSON.stringify(result));
          });
          request.on("error", (err) => {
            res!.writeHead(503, { "Content-Type": "application/json" });
            res!.end(JSON.stringify({ reachable: false, error: err.message, headers: {} }));
          });
          request.on("timeout", () => {
            request.destroy();
            res!.writeHead(504, { "Content-Type": "application/json" });
            res!.end(JSON.stringify({ reachable: false, error: "Timeout", headers: {} }));
          });
          request.end();
          return false; // signal that we handled the request
        },
      },
    },
  },
});
