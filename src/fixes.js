// The config that adds the missing headers, for the host or framework that serves the app.

import { headersToSet } from "./analyze.js";

export const STACKS = {
  nextjs: "Next.js",
  vercel: "Vercel (vercel.json)",
  netlify: "Netlify (_headers)",
  cloudflare: "Cloudflare Pages (_headers)",
  nginx: "nginx",
};

// A policy is full of single quotes ('self'), so it goes between double quotes.
const js = (s) => (s.includes("'") && !/["\\]/.test(s) ? `"${s}"` : `'${s.replace(/\\/g, "\\\\").replace(/'/g, "\\'")}'`);

function nextjs(lines, removePoweredBy) {
  return `// next.config.ts
import type { NextConfig } from 'next'

const securityHeaders = [
${lines.map((l) => `  { key: ${js(l.name)}, value: ${js(l.value)} },`).join("\n")}
]

const nextConfig: NextConfig = {${removePoweredBy ? "\n  poweredByHeader: false," : ""}
  async headers() {
    return [{ source: '/:path*', headers: securityHeaders }]
  },
}

export default nextConfig`;
}

function vercel(lines) {
  return JSON.stringify({ headers: [{ source: "/(.*)", headers: lines.map((l) => ({ key: l.name, value: l.value })) }] }, null, 2);
}

function headersFile(lines) {
  return `/*\n${lines.map((l) => `  ${l.name}: ${l.value}`).join("\n")}`;
}

function nginx(lines, removeServerVersion) {
  return `${removeServerVersion ? "server_tokens off;\n" : ""}${lines.map((l) => `add_header ${l.name} "${l.value.replace(/"/g, '\\"')}" always;`).join("\n")}`;
}

/**
 * @param {ReturnType<import("./analyze.js").analyze>} report
 * @param {keyof typeof STACKS} stack
 * @returns {{file: string, code: string, notes: string[]} | null}  null when there is no header to add.
 */
export function fixFor(report, stack) {
  const lines = headersToSet(report, stack);
  const leaks = new Set(report.findings.filter((f) => f.remove).map((f) => f.remove.toLowerCase()));
  const removePoweredBy = stack === "nextjs" && leaks.has("x-powered-by");
  const removeServerVersion = stack === "nginx" && leaks.has("server");
  if (!lines.length && !removePoweredBy && !removeServerVersion) return null;
  const notes = [];
  if (lines.some((l) => l.name === "Content-Security-Policy-Report-Only")) notes.push("The Content-Security-Policy starts in Report-Only: it blocks nothing. Read the reports in the browser console, add the hosts your app uses, then rename the header to Content-Security-Policy.");
  if (lines.some((l) => l.name === "Strict-Transport-Security" && /includeSubDomains/.test(l.value))) notes.push("includeSubDomains makes browsers refuse plain HTTP on every subdomain. Remove it if one of them does not serve HTTPS yet.");
  if (stack === "netlify" || stack === "cloudflare") notes.push("A _headers file covers static files only. Functions and server-rendered pages must set their own headers.");
  switch (stack) {
    case "nextjs":
      return { file: "next.config.ts", code: nextjs(lines, removePoweredBy), notes };
    case "vercel":
      return { file: "vercel.json", code: vercel(lines), notes };
    case "netlify":
      return { file: "_headers (in the publish directory)", code: headersFile(lines), notes };
    case "cloudflare":
      return { file: "_headers (in the build output, public/ for a Vite app)", code: headersFile(lines), notes };
    case "nginx":
      return { file: "the server block of your site", code: nginx(lines, removeServerVersion), notes };
    default:
      throw new Error(`Unknown stack "${stack}". Use one of: ${Object.keys(STACKS).join(", ")}.`);
  }
}
