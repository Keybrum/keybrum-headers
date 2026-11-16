// The network side: one GET of the address (redirects followed), one GET of its http:// version,
// one GET with an Origin header for CORS. Three ordinary requests, nothing else.

import { CORS_PROBE_ORIGIN, findMetaCsp, hideCookieValue } from "./analyze.js";

// An honest name, and the Accept header of a browser opening a page, so frameworks answer with the page.
// Each request closes its connection: three requests gain nothing from keep-alive, and an idle
// socket would keep the process waiting after the report is printed.
const BROWSER_LIKE = {
  "user-agent": "Mozilla/5.0 (compatible; keybrum-headers/1.0; +https://github.com/tlouvart/keybrum-headers)",
  accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
  connection: "close",
};

const MAX_BODY = 64_000;

/** localhost, a loopback or private IPv4 address, or a .local / .internal / .test name. */
export function isLocalHost(hostname) {
  const name = hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (name === "localhost" || name.endsWith(".localhost") || name === "::1") return true;
  if (/\.(local|internal|test|lan)$/.test(name)) return true;
  const m = /^(\d+)\.(\d+)\.\d+\.\d+$/.exec(name);
  if (!m) return false;
  const a = Number(m[1]);
  const b = Number(m[2]);
  return a === 127 || a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

/**
 * The address to grade. A bare domain gets https://. A public http:// address is graded over HTTPS
 * (its plain version is what the redirect check looks at); a local http:// address is kept as typed.
 */
export function normalize(input) {
  const raw = input.trim();
  const u = new URL(/^https?:\/\//i.test(raw) ? raw : isLocalHost(raw.split(/[/:]/)[0]) ? `http://${raw}` : `https://${raw}`);
  u.username = "";
  u.password = "";
  u.hash = "";
  const local = isLocalHost(u.hostname);
  if (!local && !u.hostname.includes(".")) throw new Error(`"${input}" does not look like a web address.`);
  if (!local) u.protocol = "https:";
  return { url: u.toString(), local: local && u.protocol === "http:" };
}

const reason = (err) => {
  const cause = err?.cause;
  if (err?.name === "TimeoutError" || err?.name === "AbortError") return "it took too long to answer";
  if (cause?.code === "ENOTFOUND") return "the name does not resolve";
  if (cause?.code === "ECONNREFUSED") return "the connection was refused";
  if (cause?.code) return String(cause.code);
  return cause?.message ?? err?.message ?? "no answer";
};

async function get(url, { redirect, headers = BROWSER_LIKE, timeoutMs }) {
  return fetch(url, { method: "GET", redirect, headers, signal: AbortSignal.timeout(timeoutMs) });
}

/** The start of the body as text, then the connection is dropped. */
async function head64k(res) {
  if (!res.body) return "";
  const reader = res.body.getReader();
  const chunks = [];
  let size = 0;
  while (size < MAX_BODY) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    size += value.length;
  }
  await reader.cancel().catch(() => {});
  return Buffer.concat(chunks).toString("utf8").slice(0, MAX_BODY);
}

const drop = (res) => res.body?.cancel().catch(() => {});

/** Where http:// leads: to HTTPS (good), to a page over HTTP (bad), or nowhere (fine). */
async function checkPlainHttp(start, timeoutMs) {
  let current = start;
  for (let hop = 0; hop < 3; hop++) {
    let res;
    try {
      res = await get(current, { redirect: "manual", timeoutMs });
    } catch (err) {
      return { kind: "closed", error: reason(err) };
    }
    drop(res);
    const location = res.headers.get("location");
    if (res.status >= 300 && res.status < 400 && location) {
      const next = new URL(location, current);
      if (next.protocol === "https:") return { kind: "redirects", to: next.toString(), status: res.status };
      current = next.toString();
      continue;
    }
    return { kind: "serves", status: res.status };
  }
  return { kind: "serves", status: 0 };
}

/**
 * Fetches what analyze() needs.
 * @param {string} input  An address as typed: example.com, https://example.com/app, localhost:3000.
 * @param {{timeoutMs?: number}} [options]
 */
export async function fetchHeaders(input, { timeoutMs = 10_000 } = {}) {
  const started = Date.now();
  const { url, local } = normalize(input);
  const plainUrl = Object.assign(new URL(url), { protocol: "http:" }).toString();
  const plainCheck = local ? Promise.resolve({ kind: "same" }) : checkPlainHttp(plainUrl, timeoutMs);

  let main;
  let httpsError;
  try {
    main = await get(url, { redirect: "follow", timeoutMs });
  } catch (err) {
    // No HTTPS at all? Grade what plain HTTP serves, and say why.
    const plain = await plainCheck;
    if (local || plain.kind !== "serves" || plain.status < 200 || plain.status >= 400) throw new Error(`Could not load ${new URL(url).host}: ${reason(err)}.`);
    httpsError = reason(err);
    main = await get(plainUrl, { redirect: "follow", timeoutMs });
  }

  const headers = {};
  for (const [k, v] of main.headers) if (k !== "set-cookie") headers[k] = v;
  const html = !headers["content-type"] || /html/i.test(headers["content-type"]);
  const text = html ? await head64k(main) : (drop(main), "");

  const probe = get(main.url, { redirect: "manual", headers: { ...BROWSER_LIKE, origin: CORS_PROBE_ORIGIN }, timeoutMs }).then(
    (res) => {
      drop(res);
      return { allowOrigin: res.headers.get("access-control-allow-origin")?.trim() ?? null, allowCredentials: (res.headers.get("access-control-allow-credentials") ?? "").trim().toLowerCase() === "true" };
    },
    () => null,
  );
  const [http, cors] = await Promise.all([plainCheck, probe]);

  return {
    requestedUrl: url,
    finalUrl: main.url,
    status: main.status,
    headers,
    setCookie: main.headers.getSetCookie().map(hideCookieValue),
    metaCsp: html ? findMetaCsp(text) : null,
    httpsError,
    http: httpsError ? { kind: "same" } : http,
    cors,
    local,
    ms: Date.now() - started,
  };
}
