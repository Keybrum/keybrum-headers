import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { check } from "../src/index.js";
import { isLocalHost, normalize } from "../src/fetch.js";

const CLI = fileURLToPath(new URL("../bin/keybrum-headers.js", import.meta.url));
const ACTION = fileURLToPath(new URL("../bin/action.js", import.meta.url));

const HARDENED = {
  "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
  "x-content-type-options": "nosniff",
  "referrer-policy": "strict-origin-when-cross-origin",
  "permissions-policy": "camera=()",
  "cross-origin-opener-policy": "same-origin",
};

// A local app with three faces: no header at all, every header, and an API that copies the Origin back.
const server = createServer((req, res) => {
  if (req.url === "/hardened") {
    res.writeHead(200, { "content-type": "text/html", ...HARDENED, "set-cookie": ["session=abc123; HttpOnly; SameSite=Lax"] });
    return res.end("<html></html>");
  }
  if (req.url === "/reflect") {
    res.writeHead(200, { "content-type": "text/html", ...HARDENED, ...(req.headers.origin ? { "access-control-allow-origin": req.headers.origin, "access-control-allow-credentials": "true" } : {}) });
    return res.end("<html></html>");
  }
  if (req.url === "/moved") {
    res.writeHead(302, { location: "/hardened" });
    return res.end();
  }
  res.writeHead(200, { "content-type": "text/html", "x-powered-by": "Next.js", "set-cookie": ["session=abc123; Path=/"] });
  res.end(`<html><head><meta charset="utf-8"></head></html>`);
});

// Unref'd: the server never keeps the test process alive once the tests are done.
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
server.unref();
const base = `http://127.0.0.1:${server.address().port}`;

const run = (file, args, env = {}) =>
  new Promise((resolve) => {
    execFile(process.execPath, [file, ...args], { env: { ...process.env, NO_COLOR: "1", ...env } }, (error, stdout, stderr) => resolve({ code: error?.code ?? 0, stdout, stderr }));
  });

test("normalize: bare domains get https, local addresses keep http", () => {
  assert.deepEqual(normalize("your-app.com"), { url: "https://your-app.com/", local: false });
  assert.deepEqual(normalize("http://your-app.com/login#x"), { url: "https://your-app.com/login", local: false });
  assert.deepEqual(normalize("localhost:3000"), { url: "http://localhost:3000/", local: true });
  assert.deepEqual(normalize("https://localhost:3000"), { url: "https://localhost:3000/", local: false });
  assert.throws(() => normalize("not a url"));
  assert.throws(() => normalize("intranet"));
  assert.equal(isLocalHost("192.168.1.20"), true);
  assert.equal(isLocalHost("172.32.0.1"), false);
  assert.equal(isLocalHost("app.internal"), true);
});

test("check(): a bare local app", async () => {
  const r = await check(base);
  assert.equal(r.local, true);
  assert.equal(r.grade, "D");
  assert.deepEqual(r.findings.map((f) => f.id).slice(0, 3), ["csp-missing", "frame", "cookie-session"]);
  assert.ok(!r.findings.some((f) => f.check === "hsts" || f.check === "https" || f.check === "redirect"));
  assert.match(r.findings.find((f) => f.id === "cookie-session").seen, /^session=\[hidden\]/);
});

test("check(): a hardened local app, reached through a redirect", async () => {
  const r = await check(`${base}/moved`);
  assert.equal(r.url, `${base}/hardened`);
  assert.equal(r.grade, "A+");
  assert.ok(r.notes[0].startsWith("The address redirected to"));
});

test("check(): an origin copied back with credentials", async () => {
  const r = await check(`${base}/reflect`);
  assert.equal(r.findings[0].id, "cors-reflect");
  assert.equal(r.grade, "D");
});

test("cli: text report, exit 0 without --min-grade", async () => {
  const { code, stdout } = await run(CLI, [base]);
  assert.equal(code, 0);
  assert.match(stdout, /Grade D/);
  assert.match(stdout, /x No Content-Security-Policy \(-25\)/);
  assert.match(stdout, /Headers to add/);
});

test("cli: --min-grade fails below the grade and passes at it", async () => {
  const low = await run(CLI, [base, "--min-grade", "B"]);
  assert.equal(low.code, 1);
  assert.match(low.stderr, /grade D is below the minimum B/);
  assert.equal((await run(CLI, [`${base}/hardened`, "--min-grade=A"])).code, 0);
});

test("cli: --json and --fix", async () => {
  const { code, stdout } = await run(CLI, [base, "--json", "--fix", "nextjs"]);
  assert.equal(code, 0);
  const json = JSON.parse(stdout);
  assert.equal(json.grade, "D");
  assert.equal(json.fix.file, "next.config.ts");
  assert.match(json.fix.code, /poweredByHeader: false/);
  assert.match((await run(CLI, [base, "--fix", "netlify"])).stdout, /Fix for Netlify/);
});

test("cli: usage errors and unreachable addresses exit 2", async () => {
  assert.equal((await run(CLI, [])).code, 2);
  assert.equal((await run(CLI, [base, "--fix", "apache"])).code, 2);
  assert.equal((await run(CLI, [base, "--min-grade", "Z"])).code, 2);
  assert.equal((await run(CLI, [base, "--nope"])).code, 2);
  const dead = await run(CLI, ["http://127.0.0.1:9", "--timeout", "2000"]);
  assert.equal(dead.code, 2);
  assert.match(dead.stderr, /Could not load 127\.0\.0\.1:9/);
  assert.equal((await run(CLI, ["--help"])).code, 0);
  assert.match((await run(CLI, ["--version"])).stdout, /^\d+\.\d+\.\d+\n$/);
});

test("action: writes the summary and the outputs, fails below min-grade", async () => {
  const dir = mkdtempSync(join(tmpdir(), "keybrum-headers-"));
  const env = { INPUT_URL: `${base}/hardened`, INPUT_MIN_GRADE: "A", GITHUB_STEP_SUMMARY: join(dir, "summary.md"), GITHUB_OUTPUT: join(dir, "output") };
  const ok = await run(ACTION, [], env);
  assert.equal(ok.code, 0);
  assert.equal(readFileSync(env.GITHUB_OUTPUT, "utf8"), "grade=A+\nscore=100\n");
  assert.match(readFileSync(env.GITHUB_STEP_SUMMARY, "utf8"), /^## Security headers: grade A\+ \(100\/100\)/);
  const bad = await run(ACTION, [], { ...env, INPUT_URL: base, INPUT_MIN_GRADE: "B", INPUT_FIX: "vercel" });
  assert.equal(bad.code, 1);
  assert.match(bad.stdout, /::error::Security headers grade D is below the minimum B/);
  assert.equal((await run(ACTION, [], { INPUT_URL: "" })).code, 1);
});
