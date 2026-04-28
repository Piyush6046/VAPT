import path from "path";
import { defineConfig, Plugin } from "vite";
import react from "@vitejs/plugin-react-swc";
import { tempo } from "tempo-devtools/dist/vite";
import type { IncomingMessage } from "node:http";
import type { RequestOptions } from "node:https";

// ── Helper: one-shot JSON responder with double-send guard ─────────────────────
function makeResponder(res: any) {
  let sent = false;
  return (status: number, data: object) => {
    if (sent) return;
    sent = true;
    res.writeHead(status, { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" });
    res.end(JSON.stringify(data));
  };
}

// ── /api/audit?url=<url>  ── real HTTPS HEAD for header analysis ───────────────
function auditHeaderPlugin(): Plugin {
  return {
    name: "vapt-audit-headers",
    configureServer(server) {
      server.middlewares.use("/api/audit", (req, res) => {
        const params = new URLSearchParams(req.url?.split("?")[1] ?? "");
        const rawUrl = params.get("url");
        const send = makeResponder(res);

        if (!rawUrl) return send(400, { reachable: false, error: "Missing url", headers: {} });

        let targetUrl: URL;
        try { targetUrl = new URL(rawUrl.startsWith("http") ? rawUrl : `https://${rawUrl}`); }
        catch { return send(400, { reachable: false, error: "Invalid URL", headers: {} }); }

        const options: RequestOptions = {
          hostname: targetUrl.hostname,
          port: targetUrl.port ? parseInt(targetUrl.port, 10) : 443,
          path: targetUrl.pathname || "/",
          method: "HEAD",
          timeout: 9000,
          headers: { "User-Agent": "VAPT-Framework/1.0 (Educational Security Scanner)", Accept: "*/*" },
          rejectUnauthorized: false,
        };

        import("node:https").then(({ request }) => {
          const r = request(options, (response: IncomingMessage) => {
            const hdrs: Record<string, string> = {};
            for (const [k, v] of Object.entries(response.headers)) {
              if (v !== undefined) hdrs[k.toLowerCase()] = Array.isArray(v) ? v[0] : String(v);
            }
            send(200, {
              reachable: true, statusCode: response.statusCode, headers: hdrs,
              server: hdrs["server"] ?? null, poweredBy: hdrs["x-powered-by"] ?? null,
            });
          });
          r.on("timeout", () => { r.destroy(); send(504, { reachable: false, error: "Timeout", headers: {} }); });
          r.on("error", (e: Error) => send(503, { reachable: false, error: e.message, headers: {} }));
          r.end();
        }).catch((e: Error) => send(500, { reachable: false, error: e.message, headers: {} }));
      });
    },
  };
}

// ── /api/dns?hostname=<hostname>  ── real DNS resolution via Node dns module ───
function auditDNSPlugin(): Plugin {
  return {
    name: "vapt-audit-dns",
    configureServer(server) {
      server.middlewares.use("/api/dns", (req, res) => {
        const params = new URLSearchParams(req.url?.split("?")[1] ?? "");
        const hostname = params.get("hostname");
        const send = makeResponder(res);
        if (!hostname) return send(400, { error: "Missing hostname" });

        import("node:dns/promises").then(async (dns) => {
          const result: Record<string, any> = {};
          await Promise.allSettled([
            dns.resolve4(hostname).then(a => { result.A = a; }).catch(() => {}),
            dns.resolveMx(hostname).then(m => { result.MX = m.map((r: any) => `${r.priority} ${r.exchange}`); }).catch(() => {}),
            dns.resolveNs(hostname).then(n => { result.NS = n; }).catch(() => {}),
            dns.resolveTxt(hostname).then(t => { result.TXT = t.flat(); }).catch(() => {}),
            dns.resolveCname(hostname).then(c => { result.CNAME = c; }).catch(() => {}),
          ]);
          
          console.log(`\x1b[36m[DNS Recon]\x1b[0m Resolved ${hostname}: \x1b[32m${result.A ? result.A.join(", ") : "No A records"}\x1b[0m`);
          send(200, { hostname, records: result });
        }).catch((e: Error) => send(500, { error: e.message }));
      });
    },
  };
}

// ── /api/ports?hostname=<hostname>&ports=<csv>  ── TCP port probe via net ───────
function auditPortPlugin(): Plugin {
  return {
    name: "vapt-audit-ports",
    configureServer(server) {
      server.middlewares.use("/api/ports", (req, res) => {
        const params = new URLSearchParams(req.url?.split("?")[1] ?? "");
        const hostname = params.get("hostname");
        const portsParam = params.get("ports") ?? "80,443,22,21,25,8080,8443,3306,5432,6379,27017";
        const send = makeResponder(res);
        if (!hostname) return send(400, { error: "Missing hostname" });

        const ports = portsParam.split(",").map(Number).filter(n => n > 0 && n < 65536).slice(0, 30);

        import("node:net").then(({ createConnection }) => {
          const results: { port: number; open: boolean; banner?: string }[] = [];
          let done = 0;

          for (const port of ports) {
            const sock = createConnection({ host: hostname, port, timeout: 2500 });
            let banner = "";

            sock.once("connect", () => {
              results.push({ port, open: true, banner: banner.trim() || undefined });
              console.log(`\x1b[32m[+] PORT OPEN:\x1b[0m ${hostname}:${port}/tcp`);
              sock.destroy();
              if (++done === ports.length) send(200, { hostname, results });
            });
            sock.once("data", (d: Buffer) => { banner = d.toString("utf8", 0, 80).trim(); });
            sock.once("timeout", () => {
              sock.destroy();
              results.push({ port, open: false });
              if (++done === ports.length) send(200, { hostname, results });
            });
            sock.once("error", () => {
              results.push({ port, open: false });
              if (++done === ports.length) send(200, { hostname, results });
            });
          }
        }).catch((e: Error) => send(500, { error: e.message }));
      });
    },
  };
}

// ── /api/fuzz?url=<url>&paths=<csv>  ── Real directory fuzzing ───────────────────
function auditFuzzPlugin(): Plugin {
  return {
    name: "vapt-audit-fuzz",
    configureServer(server) {
      server.middlewares.use("/api/fuzz", (req, res) => {
        const params = new URLSearchParams(req.url?.split("?")[1] ?? "");
        const rawUrl = params.get("url");
        const pathsParam = params.get("paths") ?? "/admin,/login,/.git/config,/.env,/backup.zip";
        const send = makeResponder(res);

        if (!rawUrl) return send(400, { error: "Missing url" });
        const targetUrl = rawUrl.startsWith("http") ? rawUrl : `https://${rawUrl}`;
        const paths = pathsParam.split(",").filter(Boolean);

        import("node:https").then((https) => {
          import("node:http").then((http) => {
            const results: { path: string; status: number; }[] = [];
            let done = 0;
            const u = new URL(targetUrl);
            const client = u.protocol === "http:" ? http : https;

            for (const p of paths) {
              const reqUrl = new URL(p.startsWith('/') ? p : `/${p}`, targetUrl);
              const requestOptions: RequestOptions = {
                method: "HEAD",
                timeout: 3000,
                rejectUnauthorized: false
              };
              
              const request = client.request(reqUrl, requestOptions, (response) => {
                if (response.statusCode === 200 || response.statusCode === 403 || response.statusCode === 401) {
                  console.log(`\x1b[33m[FUZZ HIT]\x1b[0m Discovered sensitive endpoint: \x1b[31m${targetUrl}${p}\x1b[0m (HTTP ${response.statusCode})`);
                }
                results.push({ path: p, status: response.statusCode || 0 });
                if (++done === paths.length) send(200, { url: targetUrl, results });
              });

              request.on("error", () => {
                results.push({ path: p, status: 0 });
                if (++done === paths.length) send(200, { url: targetUrl, results });
              });

              request.on("timeout", () => {
                request.destroy();
              });

              request.end();
            }
          });
        }).catch((e: Error) => send(500, { error: e.message }));
      });
    },
  };
}

// ── /api/sqli?url=<url>  ── Real Active SQL Injection Probe ────────────────────
function auditSqliPlugin(): Plugin {
  return {
    name: "vapt-audit-sqli",
    configureServer(server) {
      server.middlewares.use("/api/sqli", (req, res) => {
        const params = new URLSearchParams(req.url?.split("?")[1] ?? "");
        const rawUrl = params.get("url");
        const send = makeResponder(res);

        if (!rawUrl) return send(400, { error: "Missing url" });
        const targetUrl = rawUrl.startsWith("http") ? rawUrl : `https://${rawUrl}`;

        import("node:https").then((https) => {
          import("node:http").then((http) => {
            const u = new URL(targetUrl);
            const client = u.protocol === "http:" ? http : https;
            
            // Known test endpoint for demonstration
            const payload = "1%27"; // basic single quote injection
            const reqUrl = new URL(`/listproducts.php?cat=${payload}`, targetUrl);
            const requestOptions: RequestOptions = { method: "GET", timeout: 4000, rejectUnauthorized: false };
            
            console.log(`\x1b[35m[ATTACK]\x1b[0m Firing SQLi payload: \x1b[31m${targetUrl}/listproducts.php?cat=1'\x1b[0m`);

            const request = client.request(reqUrl, requestOptions, (response) => {
              let body = "";
              response.on("data", (chunk) => { body += chunk.toString(); });
              response.on("end", () => {
                const isVuln = body.includes("mysql_fetch_array()") || body.includes("You have an error in your SQL syntax");
                if (isVuln) {
                  console.log(`\x1b[41m\x1b[37m[EXPLOIT SUCCESS]\x1b[0m SQL Injection confirmed at ${targetUrl}`);
                } else {
                  console.log(`\x1b[36m[SAFE]\x1b[0m SQLi payload blocked or failed at ${targetUrl}`);
                }
                send(200, { url: targetUrl, vulnerable: isVuln, payload: "1'", endpoint: reqUrl.pathname });
              });
            });

            request.on("error", () => send(200, { url: targetUrl, vulnerable: false }));
            request.on("timeout", () => request.destroy());
            request.end();
          });
        }).catch((e: Error) => send(500, { error: e.message }));
      });
    },
  };
}

// https://vitejs.dev/config/
export default defineConfig({
  base: process.env.NODE_ENV === "development" ? "/" : process.env.VITE_BASE_PATH || "/",
  optimizeDeps: { entries: ["src/main.tsx", "src/tempobook/**/*"] },
  plugins: [
    react(),
    tempo(),
    auditHeaderPlugin(),
    auditDNSPlugin(),
    auditPortPlugin(),
    auditFuzzPlugin(),
    auditSqliPlugin(),
  ],
  resolve: {
    preserveSymlinks: true,
    alias: { "@": path.resolve(__dirname, "./src") },
  },
  server: {
    // @ts-ignore
    allowedHosts: true,
  },
});
