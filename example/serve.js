// A page that sends every header, for trying the CLI or the action by hand:
//   node example/serve.js 8787 &
//   node bin/keybrum-headers.js localhost:8787
import { createServer } from "node:http";

const port = Number(process.argv[2] ?? 8787);
createServer((_req, res) => {
  res.writeHead(200, {
    "content-type": "text/html; charset=utf-8",
    "content-security-policy": "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
    "cross-origin-opener-policy": "same-origin",
  });
  res.end("<!doctype html><title>ok</title>");
}).listen(port, "127.0.0.1", () => console.log(`http://127.0.0.1:${port}`));
