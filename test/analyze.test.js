import assert from "node:assert/strict";
import { test } from "node:test";
import { CORS_PROBE_ORIGIN, analyze, effectiveReferrer, findMetaCsp, framing, headersToSet, hideCookieValue, meets, parseHsts, scriptEval, tightenCsp } from "../src/analyze.js";
import { fixFor } from "../src/fixes.js";
import { toJson, toMarkdown, toText } from "../src/report.js";

const GOOD = {
  "content-type": "text/html; charset=utf-8",
  "strict-transport-security": "max-age=63072000; includeSubDomains",
  "content-security-policy": "default-src 'self'; script-src 'self' 'nonce-abc' 'strict-dynamic'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
  "x-frame-options": "DENY",
  "x-content-type-options": "nosniff",
  "referrer-policy": "strict-origin-when-cross-origin",
  "permissions-policy": "camera=(), microphone=(), geolocation=()",
  "cross-origin-opener-policy": "same-origin-allow-popups",
};

const page = (headers, extra = {}) => ({
  requestedUrl: "https://app.example.com/",
  finalUrl: "https://app.example.com/",
  status: 200,
  headers,
  setCookie: [],
  metaCsp: null,
  http: { kind: "redirects", to: "https://app.example.com/", status: 301 },
  cors: { allowOrigin: null, allowCredentials: false },
  ...extra,
});

const ids = (report) => report.findings.map((f) => f.id);

test("a page with every header gets A+", () => {
  const r = analyze(page(GOOD));
  assert.equal(r.grade, "A+");
  assert.equal(r.score, 100);
  assert.deepEqual(r.findings, []);
});

test("a page with no security header gets F, the serious gaps first", () => {
  const r = analyze(page({ "content-type": "text/html", "x-powered-by": "Next.js" }));
  assert.equal(r.grade, "F");
  assert.equal(r.score, 100 - 25 - 20 - 15 - 5 - 3 - 3 - 2 - 3);
  assert.deepEqual(ids(r).slice(0, 3), ["csp-missing", "hsts", "frame"]);
  assert.ok(ids(r).includes("leak-x-powered-by"));
});

test("no HTTPS is an F whatever else is set", () => {
  const r = analyze(page(GOOD, { requestedUrl: "https://app.example.com/", finalUrl: "http://app.example.com/", http: { kind: "same" }, httpsError: "certificate has expired" }));
  assert.equal(r.grade, "F");
  assert.equal(r.findings[0].id, "https");
});

test("plain HTTP that serves the page is a fix-first finding", () => {
  const r = analyze(page(GOOD, { http: { kind: "serves", status: 200 } }));
  assert.deepEqual(ids(r), ["redirect"]);
  assert.equal(r.findings[0].priority, "first");
  assert.equal(r.grade, "B");
});

test("a local http address leaves transport out of the grade", () => {
  const { "strict-transport-security": _, ...headers } = GOOD;
  const r = analyze(page(headers, { requestedUrl: "http://localhost:3000/", finalUrl: "http://localhost:3000/", http: { kind: "same" }, local: true, setCookie: ["session=[hidden]; HttpOnly; SameSite=Lax"] }));
  assert.equal(r.grade, "A+");
  assert.ok(r.notes.some((n) => n.startsWith("Local address")));
});

test("HSTS: short, switched off, and without subdomains", () => {
  assert.equal(analyze(page({ ...GOOD, "strict-transport-security": "max-age=3600" })).findings[0].id, "hsts-short");
  assert.equal(analyze(page({ ...GOOD, "strict-transport-security": "max-age=0" })).findings[0].id, "hsts");
  // Asked of the apex (or www) only: a subdomain cannot speak for its siblings.
  assert.deepEqual(ids(analyze(page({ ...GOOD, "strict-transport-security": "max-age=31536000" }))), []);
  const apex = { requestedUrl: "https://example.com/", finalUrl: "https://example.com/" };
  const noSub = analyze(page({ ...GOOD, "strict-transport-security": "max-age=31536000" }, apex));
  assert.deepEqual(ids(noSub), ["hsts-subdomains"]);
  assert.equal(noSub.grade, "A+");
  assert.equal(analyze(page({ ...GOOD, "strict-transport-security": "max-age=3600" })).findings[0].title, "Strict-Transport-Security lasts only 3600 seconds");
  assert.deepEqual(parseHsts("max-age=31536000; includeSubDomains; preload"), { maxAge: 31536000, includeSubDomains: true, preload: true });
});

test("CSP: unsafe-inline counts unless a nonce or a hash is there", () => {
  assert.equal(scriptEval("script-src 'self' 'unsafe-inline'").points, 10);
  assert.equal(scriptEval("script-src 'self' 'unsafe-inline' 'nonce-x'").points, 0);
  assert.equal(scriptEval("script-src 'nonce-x' 'strict-dynamic' https:").points, 0);
  assert.equal(scriptEval("script-src 'self' https: 'unsafe-eval'").points, 15);
  assert.equal(scriptEval("img-src 'self'").restricts, false);
});

test("CSP: a weak policy is reported with a tightened Report-Only policy", () => {
  const r = analyze(page({ ...GOOD, "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline' https:; frame-ancestors 'none'" }));
  const f = r.findings.find((x) => x.id === "csp-weak");
  assert.equal(f.title, "The Content-Security-Policy lets any script run");
  assert.equal(f.priority, "first");
  assert.deepEqual(f.set, [{ name: "Content-Security-Policy-Report-Only", value: "default-src 'self'; script-src 'self'; frame-ancestors 'none'" }]);
  assert.equal(tightenCsp("default-src 'self' 'unsafe-inline'"), "default-src 'self' 'unsafe-inline'; script-src 'self'");
});

test("CSP: report-only alone, and a policy in a meta tag", () => {
  const { "content-security-policy": csp, ...rest } = GOOD;
  assert.equal(analyze(page({ ...rest, "content-security-policy-report-only": csp })).findings[0].id, "csp-report-only");
  const meta = analyze(page(rest, { metaCsp: "default-src 'self'" }));
  assert.ok(!ids(meta).includes("csp-missing"));
  assert.ok(meta.notes.some((n) => n.includes("<meta> tag")));
  assert.equal(findMetaCsp(`<head><meta http-equiv="Content-Security-Policy" content="default-src &#39;self&#39;"></head>`), "default-src 'self'");
});

test("framing: frame-ancestors wins over X-Frame-Options", () => {
  assert.equal(framing({ "content-security-policy": "frame-ancestors 'self'" }).protected, true);
  assert.equal(framing({ "content-security-policy": "frame-ancestors *", "x-frame-options": "DENY" }).problem, "open-ancestors");
  assert.equal(framing({ "x-frame-options": "ALLOW-FROM https://a.example" }).problem, "allow-from");
  assert.equal(framing({}).problem, "missing");
});

test("referrer: the last value a browser understands applies", () => {
  assert.equal(effectiveReferrer("no-referrer, strict-origin-when-cross-origin"), "strict-origin-when-cross-origin");
  assert.equal(effectiveReferrer("made-up"), null);
  assert.equal(analyze(page({ ...GOOD, "referrer-policy": "unsafe-url" })).findings[0].id, "referrer-weak");
});

test("cookies: session cookies are graded, analytics and cleared cookies are not", () => {
  const r = analyze(page(GOOD, { setCookie: ["session=[hidden]; Path=/", "_ga=[hidden]; Path=/", "auth=; Max-Age=0"] }));
  assert.deepEqual(ids(r), ["cookie-session"]);
  assert.equal(r.findings[0].title, "The session cookie is missing HttpOnly, Secure, SameSite=Lax");
  assert.equal(r.findings[0].points, 19);
  assert.equal(r.score, 85);
  assert.equal(r.grade, "B");
});

test("cookies: Supabase auth and CSRF cookies are not asked for HttpOnly", () => {
  const r = analyze(page(GOOD, { setCookie: ["sb-abcd-auth-token=[hidden]; Secure; SameSite=Lax", "XSRF-TOKEN=[hidden]; Secure; SameSite=Lax"] }));
  assert.deepEqual(r.findings, []);
  assert.equal(hideCookieValue("session=abc123; HttpOnly"), "session=[hidden]; HttpOnly");
});

test("CORS: a reflected origin with credentials caps the grade at D", () => {
  const r = analyze(page(GOOD, { cors: { allowOrigin: CORS_PROBE_ORIGIN, allowCredentials: true } }));
  assert.equal(r.findings[0].id, "cors-reflect");
  assert.equal(r.grade, "D");
  const open = analyze(page({ ...GOOD, "access-control-allow-origin": "*" }, { cors: { allowOrigin: "*", allowCredentials: false } }));
  assert.equal(open.grade, "A+");
});

test("a JSON address skips the page-only checks", () => {
  const r = analyze(page({ "content-type": "application/json", "strict-transport-security": GOOD["strict-transport-security"], "x-content-type-options": "nosniff", "referrer-policy": "no-referrer" }));
  assert.equal(r.grade, "A+");
  assert.ok(r.notes.some((n) => n.includes("application/json")));
});

test("obsolete headers are noted, not graded", () => {
  const r = analyze(page({ ...GOOD, "x-xss-protection": "1; mode=block", "expect-ct": "max-age=0" }));
  assert.equal(r.grade, "A+");
  assert.equal(r.notes.length, 2);
  assert.equal(analyze(page({ ...GOOD, "x-xss-protection": "0" })).notes.length, 0);
});

test("a bot challenge is said in the notes", () => {
  const r = analyze(page({ "content-type": "text/html", "cf-mitigated": "challenge" }, { status: 403 }));
  assert.equal(r.challenge, true);
  assert.ok(r.notes[0].startsWith("Cloudflare answered with a bot challenge"));
});

test("meets() orders grades from A+ down to F", () => {
  assert.equal(meets("A+", "A"), true);
  assert.equal(meets("B", "B"), true);
  assert.equal(meets("C", "B"), false);
  assert.equal(meets("F", "D"), false);
});

test("fixes: one config per stack, with the starter CSP in Report-Only", () => {
  const r = analyze(page({ "content-type": "text/html", "x-powered-by": "Next.js", server: "nginx/1.24.0" }));
  const names = headersToSet(r, "nextjs").map((l) => l.name);
  assert.deepEqual(names, ["Content-Security-Policy-Report-Only", "Strict-Transport-Security", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy", "Cross-Origin-Opener-Policy"]);
  const next = fixFor(r, "nextjs");
  assert.match(next.code, /poweredByHeader: false/);
  assert.match(next.code, /script-src 'self' 'unsafe-inline'/);
  assert.match(next.code, /\{ key: 'X-Frame-Options', value: 'DENY' \}/);
  const vercel = JSON.parse(fixFor(r, "vercel").code);
  assert.equal(vercel.headers[0].source, "/(.*)");
  assert.equal(vercel.headers[0].headers.length, 7);
  assert.match(fixFor(r, "netlify").code, /^\/\*\n {2}Content-Security-Policy-Report-Only: default-src 'self'; script-src 'self';/);
  const nginx = fixFor(r, "nginx").code;
  assert.match(nginx, /^server_tokens off;\nadd_header Content-Security-Policy-Report-Only "default-src 'self';/);
  assert.match(nginx, /add_header X-Content-Type-Options "nosniff" always;/);
  assert.equal(fixFor(analyze(page(GOOD)), "nextjs"), null);
  assert.throws(() => fixFor(r, "apache"), /Unknown stack/);
});

test("reports: text, Markdown and JSON carry the grade and the findings", () => {
  const r = analyze(page({ "content-type": "text/html" }));
  const text = toText(r);
  assert.match(text, /Grade F {3}score 27\/100 {3}HTTP 200/);
  assert.match(text, /Fix first\n {4}x No Content-Security-Policy \(-25\)/);
  assert.match(text, /Headers to add/);
  assert.doesNotMatch(text, /\x1b\[/);
  assert.match(toText(r, { color: true }), /\x1b\[/);
  assert.match(toText(r, { stack: "nginx" }), /Fix for nginx/);
  const md = toMarkdown(r, { stack: "vercel" });
  assert.match(md, /^## Security headers: grade F \(27\/100\)/);
  assert.match(md, /\| Fix first \| No Content-Security-Policy \|/);
  const json = toJson(r);
  assert.equal(json.grade, "F");
  assert.equal(json.findings[0].id, "csp-missing");
  assert.equal("starterCsp" in json.findings[0], false);
  assert.equal(json.headersToSet[0].name, "Content-Security-Policy-Report-Only");
});
