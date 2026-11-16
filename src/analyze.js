// The rules: which response headers matter, what each gap costs, and the grade from A+ to F.
// Pure functions, no network. The rules and weights are the ones of the web checker at
// https://keybrum.com/tools/security-headers-checker, so both give the same grade.

/** The most each check can take off the score of 100. */
export const WEIGHTS = {
  https: 60,
  cors: 40,
  csp: 25,
  hsts: 20,
  frame: 15,
  redirect: 15,
  cookies: 15,
  nosniff: 5,
  referrer: 5,
  leak: 6,
  permissions: 3,
  coop: 2,
};

export const GRADES = ["A+", "A", "B", "C", "D", "F"];

/** The Origin sent once to see whether CORS hands responses to any site. */
export const CORS_PROBE_ORIGIN = "https://keybrum-cors-check.example";

export const RECOMMENDED = {
  hsts: "max-age=63072000; includeSubDomains",
  frame: "DENY",
  nosniff: "nosniff",
  referrer: "strict-origin-when-cross-origin",
  permissions: "camera=(), microphone=(), geolocation=(), browsing-topics=()",
  coop: "same-origin-allow-popups",
};

/** A first policy to run in Report-Only. Next.js needs inline scripts unless it sends a nonce. */
export function starterCsp(stack) {
  return [
    "default-src 'self'",
    stack === "nextjs" ? "script-src 'self' 'unsafe-inline'" : "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob: https:",
    "font-src 'self' data: https:",
    "connect-src 'self' https: wss:",
    "frame-src 'self' https:",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join("; ");
}

// Google Registry TLDs that are on the browsers' HSTS preload list as a whole: a browser never
// loads an http:// page on them, header or not.
const PRELOADED_TLDS = new Set(["app", "dev", "page", "new", "day", "foo"]);

const SESSION_COOKIE = /session|sess|auth|token|jwt|sid|refresh|connect\.sid|laravel_session|__session|next-auth|__Host-|__Secure-|sb-[\w-]+/i;
const ANALYTICS_COOKIE = /^(_ga|_gid|_gat|_gcl|_fbp|_hjid|mp_|amplitude|plausible|ph_|_uetsid|_uetvid|clck|clsk)/i;
// Supabase's SSR helpers keep the auth cookie readable by the browser on purpose.
const SUPABASE_AUTH_COOKIE = /^sb-[\w-]+-auth-token(\.\d+)?$/i;
// Double-submit CSRF cookies are read by the page's own script on purpose.
const CSRF_COOKIE = /csrf|xsrf/i;

const ONE_YEAR = 31_536_000;

// ------------------------------------------------------------------------------------ parsing

/** One header value split into the policies it holds (several CSP headers arrive comma-joined). */
function policies(value) {
  return (value ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

/** CSP directives of one policy, lowercase names, first occurrence wins (as in browsers). */
export function directives(policy) {
  const out = new Map();
  for (const part of policy.split(";")) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    const name = tokens[0]?.toLowerCase();
    if (!name || out.has(name)) continue;
    out.set(name, tokens.slice(1));
  }
  return out;
}

const WIDE_SOURCES = new Set(["*", "http:", "https:", "data:", "http://*", "https://*", "*:*"]);
const isWide = (token) => WIDE_SOURCES.has(token.toLowerCase().replace(/\/$/, ""));
const hasNonceOrHash = (tokens) => tokens.some((t) => /^'(nonce|sha256|sha384|sha512)-/i.test(t));

/** How well one policy limits where scripts come from. */
export function scriptEval(policy) {
  const d = directives(policy);
  const from = d.has("script-src") ? "script-src" : d.has("default-src") ? "default-src" : undefined;
  // Points here only rank policies against each other: a policy with no script rule ranks last.
  if (!from) return { policy, restricts: false, problems: [], points: 25 };
  const src = (d.get(from) ?? []).map((t) => t.toLowerCase());
  const nonceOrHash = hasNonceOrHash(src);
  const strictDynamic = nonceOrHash && src.includes("'strict-dynamic'");
  const problems = [];
  // With a nonce or a hash, browsers ignore 'unsafe-inline'; with 'strict-dynamic', host and scheme sources too.
  if (src.includes("'unsafe-inline'") && !nonceOrHash) problems.push({ token: "'unsafe-inline'", text: "lets any inline script run, including one an attacker manages to inject", points: 10 });
  const wide = strictDynamic ? [] : src.filter(isWide);
  if (wide.length) problems.push({ token: wide.join(" "), text: `lets scripts load from ${wide.every((t) => t === "data:") ? "data: URLs, which an attacker can write" : "any website"}`, points: 10 });
  if (src.includes("'unsafe-eval'")) problems.push({ token: "'unsafe-eval'", text: "lets scripts turn text into code with eval()", points: 5 });
  return { policy, restricts: true, from, problems, points: Math.min(20, problems.reduce((s, p) => s + p.points, 0)) };
}

/** The same policy with the weak script sources removed, to test as Report-Only next to the current one. */
export function tightenCsp(policy) {
  const d = directives(policy);
  const ev = scriptEval(policy);
  const parts = policy
    .split(";")
    .map((p) => p.trim())
    .filter(Boolean);
  const clean = (tokens) => {
    const nonceOrHash = hasNonceOrHash(tokens);
    const kept = tokens.filter((t) => {
      const l = t.toLowerCase();
      if (l === "'unsafe-eval'" || isWide(l)) return false;
      if (l === "'unsafe-inline'" && !nonceOrHash) return false;
      return true;
    });
    return kept.length ? kept : ["'self'"];
  };
  if (!ev.restricts) {
    const extra = ["script-src 'self'"];
    if (!d.has("object-src")) extra.push("object-src 'none'");
    if (!d.has("base-uri")) extra.push("base-uri 'self'");
    return [...parts, ...extra].join("; ");
  }
  // Narrowing default-src would also narrow images, fonts and the rest: add a script-src instead.
  if (ev.from === "default-src") return [...parts, `script-src ${clean(d.get("default-src") ?? []).join(" ")}`].join("; ");
  return parts
    .map((p) => {
      const tokens = p.split(/\s+/);
      if (tokens[0]?.toLowerCase() !== "script-src") return p;
      return ["script-src", ...clean(tokens.slice(1))].join(" ");
    })
    .join("; ");
}

const openAncestors = (tokens) => tokens.some((t) => t === "*" || /^https?:(\/\/\*)?$/i.test(t));

/** Clickjacking: CSP frame-ancestors wins over X-Frame-Options when both are set (CSP Level 2). */
export function framing(headers) {
  let open = false;
  for (const p of policies(headers["content-security-policy"])) {
    const fa = directives(p).get("frame-ancestors");
    if (!fa) continue;
    if (openAncestors(fa)) open = true;
    else return { protected: true, via: `frame-ancestors ${fa.join(" ")}` };
  }
  if (open) return { protected: false, problem: "open-ancestors" };
  const xfo = (headers["x-frame-options"] ?? "").trim();
  if (!xfo) return { protected: false, problem: "missing" };
  const values = xfo
    .split(",")
    .map((v) => v.trim().toLowerCase())
    .filter(Boolean);
  if (values.length && values.every((v) => v === "deny" || v === "sameorigin")) return { protected: true, via: `X-Frame-Options: ${xfo}` };
  if (values.some((v) => v.startsWith("allow-from"))) return { protected: false, problem: "allow-from" };
  return { protected: false, problem: "invalid" };
}

/** A policy with a nonce is built per response by the app's code; it must never be pasted as a fixed value. */
const nonced = (policy) => !!policy && /'nonce-/i.test(policy);
const NONCE_NOTE = "The policy uses a nonce, so your own code builds it for each response (proxy.ts, middleware or the server). Make the change there, not in a static headers file: a fixed nonce would let any script in.";

export function parseHsts(value) {
  if (!value) return null;
  // Browsers read only the first header when several arrive.
  const first = value.split(",")[0] ?? "";
  const m = /max-age\s*=\s*"?(\d+)"?/i.exec(first);
  return { maxAge: m ? Number(m[1]) : null, includeSubDomains: /includesubdomains/i.test(first), preload: /(^|;)\s*preload\s*(;|$)/i.test(first) };
}

const REFERRER_VALUES = new Set(["no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin", "same-origin", "strict-origin", "strict-origin-when-cross-origin", "unsafe-url"]);

/** The policy a browser applies: the last value it understands. */
export function effectiveReferrer(value) {
  const known = (value ?? "")
    .split(",")
    .map((v) => v.trim().toLowerCase())
    .filter((v) => REFERRER_VALUES.has(v));
  return known[known.length - 1] ?? null;
}

export function parseCookies(lines) {
  const out = [];
  for (const line of lines) {
    const first = line.split(";")[0] ?? "";
    const eq = first.indexOf("=");
    if (eq <= 0) continue;
    const name = first.slice(0, eq).trim();
    if (!name) continue;
    const attrs = line.toLowerCase();
    const value = first.slice(eq + 1).trim().replace(/^"|"$/g, "");
    const maxAge = /;\s*max-age\s*=\s*(-?\d+)/.exec(attrs);
    const expires = /;\s*expires\s*=\s*([^;]+)/.exec(attrs);
    const expiresAt = expires?.[1] ? Date.parse(expires[1]) : Number.NaN;
    out.push({
      name,
      line,
      // A Set-Cookie that clears the cookie has nothing to protect.
      deletes: !value || (maxAge ? Number(maxAge[1]) <= 0 : Number.isFinite(expiresAt) && expiresAt < Date.UTC(2000, 0, 1)),
      secure: /;\s*secure\b/.test(attrs),
      httpOnly: /;\s*httponly\b/.test(attrs),
      sameSite: /;\s*samesite\s*=\s*none/.test(attrs) ? "none" : /;\s*samesite\s*=\s*lax/.test(attrs) ? "lax" : /;\s*samesite\s*=\s*strict/.test(attrs) ? "strict" : null,
      sessionLike: SESSION_COOKIE.test(name) && !ANALYTICS_COOKIE.test(name),
    });
  }
  return out;
}

/** A Content-Security-Policy set with <meta http-equiv>, read from the start of an HTML page. */
export function findMetaCsp(html) {
  for (const m of html.matchAll(/<meta\b[^>]*>/gi)) {
    const tag = m[0];
    if (!/http-equiv\s*=\s*["']?content-security-policy["'\s/>]/i.test(tag)) continue;
    const c = /content\s*=\s*"([^"]*)"/i.exec(tag) ?? /content\s*=\s*'([^']*)'/i.exec(tag);
    if (!c?.[1]) continue;
    return c[1]
      .replace(/&#39;|&#x27;|&apos;/gi, "'")
      .replace(/&quot;/gi, '"')
      .replace(/&amp;/gi, "&")
      .trim();
  }
  return null;
}

/** Cookie values can be session identifiers: keep the name and the flags, never the value. */
export function hideCookieValue(line) {
  const eq = line.indexOf("=");
  const semi = line.indexOf(";");
  const end = semi === -1 ? line.length : semi;
  if (eq <= 0 || eq > end) return line;
  return eq + 1 === end ? line : `${line.slice(0, eq + 1)}[hidden]${line.slice(end)}`;
}

// ------------------------------------------------------------------------------------- analysis

const isHtml = (headers) => !headers["content-type"] || /html/i.test(headers["content-type"]);
const tldOf = (host) => host.replace(/:\d+$/, "").split(".").pop()?.toLowerCase() ?? "";
// The apex of a domain (or its www), where includeSubDomains is the owner's call. A subdomain
// such as app.example.com cannot speak for its siblings.
const registrable = (host) => {
  const labels = host.replace(/:\d+$/, "").split(".");
  return labels.length === 2 || (labels.length === 3 && labels[0] === "www");
};
const serverVersion = (value) => !!value && /(^|[\s/(])v?\d+\.\d+/.test(value) && !/^awselb\//i.test(value.trim());
const days = (s) => {
  if (s < 86_400) return `${s} second${s === 1 ? "" : "s"}`;
  const d = Math.round(s / 86_400);
  return d >= 730 ? `${Math.round(d / 365)} years` : d >= 365 ? "1 year" : `${d} day${d === 1 ? "" : "s"}`;
};

// Headers browsers dropped or renamed. Not graded: a note says to remove them.
const OBSOLETE = [
  { header: "x-xss-protection", when: (v) => v.trim() !== "0", note: "X-XSS-Protection is obsolete and can create cross-site scripting holes in otherwise safe pages (MDN). Remove it, or send the value 0." },
  { header: "expect-ct", when: () => true, note: "Expect-CT is obsolete: browsers enforce Certificate Transparency by themselves. Remove it." },
  { header: "public-key-pins", when: () => true, note: "Public-Key-Pins is obsolete and no browser reads it. Remove it." },
  { header: "feature-policy", when: () => true, note: "Feature-Policy was renamed Permissions-Policy, with a different syntax. Send Permissions-Policy and remove the old header." },
];

/**
 * Grades one fetch.
 * @param {object} f
 * @param {string} f.requestedUrl
 * @param {string} f.finalUrl          After redirects.
 * @param {number} f.status
 * @param {Record<string,string>} f.headers   Lowercase names, without set-cookie.
 * @param {string[]} f.setCookie       One line per cookie, values hidden.
 * @param {string|null} f.metaCsp      A policy found in a <meta> tag.
 * @param {string} [f.httpsError]      Why HTTPS failed, when the page was graded over plain HTTP.
 * @param {{kind:"redirects",to:string,status:number}|{kind:"serves",status:number}|{kind:"closed",error:string}|{kind:"same"}} f.http
 * @param {{allowOrigin:string|null,allowCredentials:boolean}|null} f.cors
 * @param {boolean} [f.local]          localhost or a private address over http://: transport checks are left out.
 */
export function analyze(f) {
  const h = f.headers;
  const final = new URL(f.finalUrl);
  const host = final.host;
  const https = final.protocol === "https:";
  const local = !!f.local && !https;
  const html = isHtml(h);
  const preloaded = PRELOADED_TLDS.has(tldOf(host));
  const findings = [];
  const passed = [];
  const notes = [];

  if (!f.httpsError && f.finalUrl.replace(/\/$/, "") !== f.requestedUrl.replace(/\/$/, "")) notes.push(`The address redirected to ${f.finalUrl}; these are the headers of that page.`);
  const challenge = (h["cf-mitigated"] ?? "").toLowerCase() === "challenge" ? "Cloudflare" : (h["x-vercel-mitigated"] ?? "").toLowerCase() === "challenge" ? "Vercel" : null;
  if (challenge) notes.push(`${challenge} answered with a bot challenge, so these are the challenge page's headers, not your app's. Check the raw headers of your page in your browser's network tab as well.`);
  else if (f.status >= 400) notes.push(`The page answered with status ${f.status}. Hosts often send different headers on error pages: check the page your visitors actually land on.`);
  if (!html) notes.push(`This address answered with ${h["content-type"]}, not a web page, so the page-only checks (Content-Security-Policy, framing, Permissions-Policy, Cross-Origin-Opener-Policy) were left out of the grade.`);
  if (local) notes.push("Local address over http://: HTTPS, the HTTP redirect, Strict-Transport-Security and the Secure cookie flag were left out of the grade. Check them on the published address.");

  // ---- HTTPS and the http:// redirect
  if (local) {
    // Nothing to say about transport on a development address.
  } else if (!https) {
    findings.push({
      id: "https",
      check: "https",
      header: "HTTPS",
      title: "The site does not use HTTPS",
      why: "Without HTTPS, anyone on the same network (public Wi-Fi, a hostile router) can read and change every page, password and cookie on the way.",
      detail: f.httpsError ? `The HTTPS version failed: ${f.httpsError.replace(/\.$/, "")}.` : f.requestedUrl.startsWith("https:") ? "The https:// address redirects to plain http://." : "The page was served over plain HTTP.",
      priority: "first",
      points: WEIGHTS.https,
      note: "Turn on HTTPS at your host or proxy. Vercel, Netlify, Cloudflare and most hosts issue the certificate for free.",
    });
  } else if (f.http.kind === "serves") {
    const servesPage = f.http.status >= 200 && f.http.status < 300;
    findings.push({
      id: "redirect",
      check: "redirect",
      header: "HTTP to HTTPS",
      title: servesPage ? "Plain HTTP serves the page instead of redirecting" : "Plain HTTP does not redirect to HTTPS",
      why: preloaded
        ? `Browsers never load http:// pages on .${tldOf(host)} domains, so visitors are covered; other HTTP clients and links still land on the unencrypted version.`
        : "A visitor who types the address or follows an old http:// link gets an unencrypted page that anyone on the network can read or change.",
      detail: f.http.status ? `http://${final.hostname}/ answered with status ${f.http.status} and no redirect to https://.` : `http://${final.hostname}/ kept redirecting to other http:// addresses without reaching https://.`,
      priority: preloaded || !servesPage ? "later" : "first",
      points: preloaded ? 2 : servesPage ? WEIGHTS.redirect : 5,
      note: "Redirect every http:// request to https:// with a 301, at the host or the proxy.",
    });
  } else if (f.http.kind === "redirects") {
    passed.push({ check: "redirect", header: "HTTP to HTTPS", title: "Plain HTTP redirects to HTTPS", seen: `${f.http.status} to ${f.http.to}` });
  } else if (f.http.kind === "closed") {
    passed.push({ check: "redirect", header: "HTTP to HTTPS", title: "Plain HTTP is not served" });
  } else {
    passed.push({ check: "redirect", header: "HTTP to HTTPS", title: "The http:// address redirects to HTTPS", seen: f.finalUrl });
  }

  // ---- Strict-Transport-Security (only means something over HTTPS)
  if (https) {
    const raw = h["strict-transport-security"];
    const hsts = parseHsts(raw);
    const missingWhy = preloaded
      ? `Browsers already force HTTPS on every .${tldOf(host)} domain, so this matters less here; it still protects visitors if the app moves to another domain.`
      : "Without it, a visitor's first request can go over plain HTTP, where someone on the same network can redirect them to a fake copy of the site.";
    if (!hsts || hsts.maxAge === null || hsts.maxAge === 0) {
      findings.push({
        id: "hsts",
        check: "hsts",
        header: "Strict-Transport-Security",
        title: !hsts ? "No Strict-Transport-Security header" : hsts.maxAge === 0 ? "Strict-Transport-Security is switched off (max-age=0)" : "Strict-Transport-Security has no max-age, so browsers ignore it",
        why: missingWhy,
        seen: raw,
        priority: preloaded ? "later" : "first",
        points: preloaded ? 5 : WEIGHTS.hsts,
        set: [{ name: "Strict-Transport-Security", value: RECOMMENDED.hsts }],
        note: "Only add includeSubDomains once every subdomain of this domain serves HTTPS. Add preload only when you also submit the domain at hstspreload.org.",
      });
    } else if (hsts.maxAge < ONE_YEAR) {
      findings.push({
        id: "hsts-short",
        check: "hsts",
        header: "Strict-Transport-Security",
        title: `Strict-Transport-Security lasts only ${days(hsts.maxAge)}`,
        why: "Browsers forget the HTTPS-only rule after max-age; a year (31536000 seconds) is the usual minimum and the one the preload list asks for.",
        seen: raw,
        priority: preloaded ? "later" : "next",
        points: preloaded ? 2 : 8,
        set: [{ name: "Strict-Transport-Security", value: `max-age=63072000${hsts.includeSubDomains ? "; includeSubDomains" : ""}${hsts.preload ? "; preload" : ""}` }],
      });
    } else {
      const extras = [hsts.includeSubDomains ? "includeSubDomains" : null, hsts.preload ? "preload" : null].filter(Boolean).join(", ");
      passed.push({ check: "hsts", header: "Strict-Transport-Security", title: `HTTPS is enforced for ${days(hsts.maxAge)}${extras ? ` (${extras})` : ""}`, seen: raw });
      if (!hsts.includeSubDomains && registrable(host) && !preloaded) {
        findings.push({
          id: "hsts-subdomains",
          check: "hsts",
          header: "Strict-Transport-Security",
          title: "Strict-Transport-Security does not cover subdomains",
          why: "A subdomain that still answers over HTTP can be used to plant cookies for the main domain; includeSubDomains closes that once every subdomain serves HTTPS.",
          seen: raw,
          priority: "later",
          points: 1,
          set: [{ name: "Strict-Transport-Security", value: `max-age=${hsts.maxAge}; includeSubDomains${hsts.preload ? "; preload" : ""}` }],
          note: "Check first that every subdomain of this domain serves HTTPS: browsers will refuse plain HTTP on all of them.",
        });
      }
    }
  }

  // ---- Content-Security-Policy
  if (html) {
    const headerPolicies = policies(h["content-security-policy"]);
    const metaPolicies = policies(f.metaCsp);
    const enforced = [...headerPolicies, ...metaPolicies];
    const reportOnly = h["content-security-policy-report-only"];
    const shown = h["content-security-policy"] ?? (f.metaCsp ? `${f.metaCsp} (in a <meta> tag)` : undefined);
    if (!enforced.length && reportOnly) {
      const ev = scriptEval(reportOnly);
      findings.push({
        id: "csp-report-only",
        check: "csp",
        header: "Content-Security-Policy",
        title: "The policy only reports, it blocks nothing yet",
        why: "Content-Security-Policy-Report-Only is the right first step, but until the same policy is sent as Content-Security-Policy an injected script still runs.",
        detail: ev.problems.length ? `The report-only policy also ${ev.problems.map((p) => `has ${p.token}, which ${p.text}`).join("; ")}.` : undefined,
        seen: reportOnly,
        priority: "next",
        points: 20,
        note: `${nonced(reportOnly) ? `${NONCE_NOTE} ` : ""}When the reports are clean, send the same policy as Content-Security-Policy. Anything the reports list will be blocked once you switch.`,
      });
    } else if (!enforced.length) {
      findings.push({
        id: "csp-missing",
        check: "csp",
        header: "Content-Security-Policy",
        title: "No Content-Security-Policy",
        why: "It is the browser's last line of defense against cross-site scripting: without it, a script an attacker slips into a page can read everything the visitor sees and act as them.",
        priority: "first",
        points: WEIGHTS.csp,
        starterCsp: true,
        note: "Start in Report-Only: the browser blocks nothing and reports what it would block. Add the hosts your app really uses (Supabase, Stripe, analytics), then enforce it.",
      });
    } else {
      const evals = enforced.map(scriptEval);
      // A script must pass every policy, so the strictest one decides.
      const best = evals.reduce((a, b) => (b.points < a.points ? b : a));
      if (!best.restricts) {
        findings.push({
          id: "csp-no-scripts",
          check: "csp",
          header: "Content-Security-Policy",
          title: "The Content-Security-Policy does not limit scripts",
          why: "The policy has no script-src or default-src, so it does nothing against injected scripts, the main thing it is for.",
          seen: shown,
          priority: "first",
          points: 20,
          set: [{ name: "Content-Security-Policy-Report-Only", value: tightenCsp(best.policy) }],
          note: "Your policy plus a script rule, in Report-Only next to the current header. When the reports are clean, merge it into Content-Security-Policy.",
        });
      } else if (best.problems.length) {
        const inline = best.problems.some((p) => p.token === "'unsafe-inline'");
        const anySite = best.problems.some((p) => p.text.endsWith("any website"));
        // Inline scripts and scripts from anywhere: the policy no longer stops an injected script at all.
        const useless = inline && anySite;
        const tokens = best.problems.map((p) => p.token).join(" and ");
        findings.push({
          id: "csp-weak",
          check: "csp",
          header: "Content-Security-Policy",
          title: useless ? "The Content-Security-Policy lets any script run" : `The Content-Security-Policy allows ${tokens}`,
          why: useless
            ? "With inline scripts and scripts from any site both allowed, the policy no longer stops an injected script, which is the main thing it is for."
            : inline || anySite
              ? "A policy that allows inline or any-origin scripts no longer stops most cross-site scripting, which is what it is there for."
              : "eval() turns text into code, so a bug that lets an attacker pass text to it becomes a script running in your page.",
          detail: `In ${best.from}: ${best.problems.map((p) => `${p.token} ${p.text}`).join("; ")}.`,
          seen: shown,
          priority: useless ? "first" : "next",
          points: best.points,
          ...(nonced(best.policy)
            ? { note: `${NONCE_NOTE} Remove ${tokens} from ${best.from}${anySite ? ", or add 'strict-dynamic' so browsers ignore host sources" : ""}, and try it in Content-Security-Policy-Report-Only first.` }
            : {
                set: [{ name: "Content-Security-Policy-Report-Only", value: tightenCsp(best.policy) }],
                note: "Keep your current policy and add this stricter one in Report-Only beside it: it blocks nothing, and the browser reports what it would block. When the reports are clean, make it the Content-Security-Policy.",
              }),
        });
      } else {
        passed.push({ check: "csp", header: "Content-Security-Policy", title: "Scripts are limited by a Content-Security-Policy", seen: shown });
      }
      if (!headerPolicies.length && metaPolicies.length) notes.push("The Content-Security-Policy is set in a <meta> tag. It works for scripts, but browsers ignore frame-ancestors there: send it as a header when your host allows it.");
    }
  }

  // ---- Clickjacking
  if (html) {
    const fr = framing(h);
    if (fr.protected) {
      passed.push({ check: "frame", header: fr.via.startsWith("frame-ancestors") ? "Content-Security-Policy" : "X-Frame-Options", title: "Other sites cannot frame the page", seen: fr.via });
    } else {
      const open = fr.problem === "open-ancestors";
      findings.push({
        id: "frame",
        check: "frame",
        header: open ? "Content-Security-Policy" : "X-Frame-Options",
        title:
          fr.problem === "open-ancestors"
            ? "frame-ancestors lets any site frame the page"
            : fr.problem === "allow-from"
              ? "X-Frame-Options uses ALLOW-FROM, which browsers ignore"
              : fr.problem === "invalid"
                ? "X-Frame-Options has a value browsers do not understand"
                : "Any site can put this page in a frame",
        why: "Another site can load the page in an invisible frame and trick a signed-in visitor into clicking its buttons (clickjacking).",
        detail: open && h["x-frame-options"] ? "Browsers ignore X-Frame-Options when the policy has a frame-ancestors rule, so the open rule wins." : undefined,
        seen: open ? h["content-security-policy"] : h["x-frame-options"],
        priority: "first",
        points: WEIGHTS.frame,
        ...(open
          ? { note: "Set frame-ancestors 'none' in your Content-Security-Policy, 'self' if your own pages frame each other, or list the sites that may embed the page." }
          : {
              set: [{ name: "X-Frame-Options", value: RECOMMENDED.frame }],
              note: "Use SAMEORIGIN instead of DENY if your own pages frame each other. Your Content-Security-Policy can say the same with frame-ancestors 'none' (or 'self'), which modern browsers prefer.",
            }),
      });
    }
  }

  // ---- X-Content-Type-Options
  const xcto = h["x-content-type-options"];
  if ((xcto ?? "").split(",")[0]?.trim().toLowerCase() === "nosniff") {
    passed.push({ check: "nosniff", header: "X-Content-Type-Options", title: "Browsers will not guess file types", seen: xcto });
  } else {
    findings.push({
      id: "nosniff",
      check: "nosniff",
      header: "X-Content-Type-Options",
      title: xcto ? "X-Content-Type-Options has a value other than nosniff" : "No X-Content-Type-Options: nosniff",
      why: "Without it, a browser may run an uploaded file or a text response as a script or a page if its content looks like one.",
      seen: xcto,
      priority: "next",
      points: WEIGHTS.nosniff,
      set: [{ name: "X-Content-Type-Options", value: RECOMMENDED.nosniff }],
    });
  }

  // ---- Referrer-Policy
  const refRaw = h["referrer-policy"];
  const ref = effectiveReferrer(refRaw);
  if (ref === "unsafe-url" || ref === "no-referrer-when-downgrade") {
    findings.push({
      id: "referrer-weak",
      check: "referrer",
      header: "Referrer-Policy",
      title: `Referrer-Policy is ${ref}`,
      why: "Every link to another site sends it the full address of the page, with any token, email or id that sits in the path or the query string.",
      seen: refRaw,
      priority: ref === "unsafe-url" ? "next" : "later",
      points: ref === "unsafe-url" ? 5 : 3,
      set: [{ name: "Referrer-Policy", value: RECOMMENDED.referrer }],
    });
  } else if (!ref) {
    findings.push({
      id: "referrer",
      check: "referrer",
      header: "Referrer-Policy",
      title: refRaw ? "Referrer-Policy has no value browsers understand" : "No Referrer-Policy",
      why: "Current browsers default to sending only your domain to other sites, so this mostly protects older browsers and makes the choice explicit.",
      seen: refRaw,
      priority: "later",
      points: 3,
      set: [{ name: "Referrer-Policy", value: RECOMMENDED.referrer }],
    });
  } else {
    passed.push({ check: "referrer", header: "Referrer-Policy", title: "Other sites get at most your domain as referrer", seen: refRaw });
  }

  // ---- Permissions-Policy and Cross-Origin-Opener-Policy (pages only)
  if (html) {
    const pp = h["permissions-policy"];
    if (pp?.trim()) {
      passed.push({ check: "permissions", header: "Permissions-Policy", title: "Browser features are restricted", seen: pp });
    } else {
      findings.push({
        id: "permissions",
        check: "permissions",
        header: "Permissions-Policy",
        title: h["feature-policy"] ? "Only the old Feature-Policy header is set" : "No Permissions-Policy",
        why: "It switches off the camera, microphone and location for the page and anything embedded in it, so an injected script or a third-party widget cannot ask for them.",
        seen: h["feature-policy"],
        priority: "later",
        points: h["feature-policy"] ? 2 : WEIGHTS.permissions,
        set: [{ name: "Permissions-Policy", value: RECOMMENDED.permissions }],
        note: "If the app uses the camera, the microphone or the location, write (self) instead of () for that feature.",
      });
    }
    // The value can carry parameters, as in same-origin; report-to="coop".
    const coop = (h["cross-origin-opener-policy"] ?? "").split(";")[0]?.trim().toLowerCase() ?? "";
    if (coop === "same-origin" || coop === "same-origin-allow-popups" || coop === "noopener-allow-popups") {
      passed.push({ check: "coop", header: "Cross-Origin-Opener-Policy", title: "Other windows cannot reach this one", seen: h["cross-origin-opener-policy"] });
    } else {
      findings.push({
        id: "coop",
        check: "coop",
        header: "Cross-Origin-Opener-Policy",
        title: coop ? `Cross-Origin-Opener-Policy is ${coop}` : "No Cross-Origin-Opener-Policy",
        why: "A site that opens yours in a pop-up or tab keeps a handle on the window, which some cross-site leaks and phishing tricks rely on.",
        seen: h["cross-origin-opener-policy"],
        priority: "later",
        points: WEIGHTS.coop,
        set: [{ name: "Cross-Origin-Opener-Policy", value: RECOMMENDED.coop }],
        note: "same-origin is stricter, but it breaks sign-in pop-ups (Google or Firebase signInWithPopup). same-origin-allow-popups keeps them working.",
      });
    }
  }

  // ---- Information leaks
  const leaks = [
    { header: "Server", value: h["server"], when: serverVersion(h["server"]), title: `The Server header names a version: ${h["server"]}` },
    { header: "X-Powered-By", value: h["x-powered-by"], when: !!h["x-powered-by"], title: `X-Powered-By says ${h["x-powered-by"]}` },
    { header: "X-AspNet-Version", value: h["x-aspnet-version"], when: !!h["x-aspnet-version"], title: `X-AspNet-Version says ${h["x-aspnet-version"]}` },
    { header: "X-AspNetMvc-Version", value: h["x-aspnetmvc-version"], when: !!h["x-aspnetmvc-version"], title: `X-AspNetMvc-Version says ${h["x-aspnetmvc-version"]}` },
  ].filter((l) => l.when && l.value);
  for (const l of leaks) {
    findings.push({
      id: `leak-${l.header.toLowerCase()}`,
      check: "leak",
      header: l.header,
      title: l.title,
      why: "It tells an attacker which software, and often which version, to look up known flaws for. Hiding it fixes nothing by itself, but it costs one line.",
      seen: l.value,
      priority: "later",
      points: 3,
      remove: l.header,
    });
  }
  if (!leaks.length) passed.push({ check: "leak", header: "Server", title: "No software versions in the headers", seen: h["server"] ? `Server: ${h["server"]}` : undefined });

  // ---- Cookies
  const cookies = parseCookies(f.setCookie).filter((c) => !c.deletes);
  const session = cookies.filter((c) => c.sessionLike);
  let cookieProblems = 0;
  for (const c of session) {
    const flags = [];
    const issues = [];
    let points = 0;
    let first = false;
    const supabase = SUPABASE_AUTH_COOKIE.test(c.name);
    const csrf = CSRF_COOKIE.test(c.name);
    if (!c.httpOnly && !supabase && !csrf) {
      flags.push("HttpOnly");
      issues.push("no HttpOnly, so any script on the page can read it");
      points += 8;
      first = true;
    }
    if (https && !c.secure) {
      flags.push("Secure");
      issues.push(c.sameSite === "none" ? "SameSite=None without Secure, which browsers reject" : "no Secure, so it can travel over plain HTTP");
      points += c.sameSite === "none" ? 5 : 8;
      first = first || c.sameSite !== "none";
    }
    if (c.sameSite === null) {
      flags.push("SameSite=Lax");
      issues.push("no SameSite, so some browsers send it with requests from other sites");
      points += 3;
    }
    if (!issues.length) continue;
    cookieProblems++;
    const text = issues.join("; ");
    findings.push({
      id: `cookie-${c.name}`,
      check: "cookies",
      header: "Set-Cookie",
      title: `The ${c.name} cookie is missing ${flags.join(", ")}`,
      why: csrf ? "It looks like an anti-forgery (CSRF) token: if it leaks over plain HTTP or travels with requests from other sites, it stops protecting forms." : "It looks like a session cookie: whoever reads or replays it is signed in as the visitor.",
      detail: `${text.charAt(0).toUpperCase()}${text.slice(1)}.`,
      seen: c.line,
      priority: first ? "first" : "next",
      points,
      note: `Add ${flags.join("; ")} where your code or your auth library sets the cookie.`,
    });
  }
  if (!cookieProblems) {
    passed.push({
      check: "cookies",
      header: "Set-Cookie",
      title: session.length ? `Session cookie flags are set (${session.map((c) => c.name).join(", ")})` : cookies.length ? "No session cookie on this page" : "No cookies set on this page",
    });
  }

  // ---- CORS
  const acao = (h["access-control-allow-origin"] ?? "").trim();
  const acac = (h["access-control-allow-credentials"] ?? "").trim().toLowerCase() === "true";
  const nullOrigin = acao.toLowerCase() === "null" && acac;
  const reflected = (f.cors?.allowOrigin === CORS_PROBE_ORIGIN && f.cors.allowCredentials) || nullOrigin;
  const corsNote = `Answer with one origin from a list you control (for this page: ${final.origin}). Never copy the Origin header back while Access-Control-Allow-Credentials is true.`;
  if (nullOrigin) {
    findings.push({
      id: "cors-null",
      check: "cors",
      header: "Access-Control-Allow-Origin",
      title: "CORS lets the null origin read this address with the visitor's cookies",
      why: "A page on any site can put a sandboxed frame on itself, whose origin is null, and fetch this address as the signed-in visitor and read the answer.",
      seen: `Access-Control-Allow-Origin: ${acao}; Access-Control-Allow-Credentials: true`,
      priority: "first",
      points: WEIGHTS.cors,
      note: corsNote,
    });
  } else if (reflected) {
    findings.push({
      id: "cors-reflect",
      check: "cors",
      header: "Access-Control-Allow-Origin",
      title: "Any website can read this address with the visitor's cookies",
      why: "The server copies whatever Origin it is sent into Access-Control-Allow-Origin and allows credentials, so a page on any site can fetch this address as the signed-in visitor and read the answer.",
      detail: `Asked with Origin: ${CORS_PROBE_ORIGIN}, it answered Access-Control-Allow-Origin: ${CORS_PROBE_ORIGIN} and Access-Control-Allow-Credentials: true.`,
      priority: "first",
      points: WEIGHTS.cors,
      note: corsNote,
    });
  } else if (acao === "*" && acac) {
    findings.push({
      id: "cors-wildcard",
      check: "cors",
      header: "Access-Control-Allow-Origin",
      title: "CORS allows any origin and credentials together",
      why: "Browsers refuse this pair, so it leaks nothing yet, but it shows CORS set by hand, and the usual next step (copying the Origin back) opens the data to every site.",
      seen: `Access-Control-Allow-Origin: ${acao}; Access-Control-Allow-Credentials: true`,
      priority: "next",
      points: 10,
      note: corsNote,
    });
  } else {
    passed.push({
      check: "cors",
      header: "Access-Control-Allow-Origin",
      title: acao === "*" || f.cors?.allowOrigin === CORS_PROBE_ORIGIN ? "Other sites can read it only without the visitor's cookies" : "Other sites cannot read it with the visitor's cookies",
      seen: acao ? `Access-Control-Allow-Origin: ${acao}` : undefined,
    });
  }

  // ---- Obsolete headers: said, not graded
  for (const o of OBSOLETE) if (h[o.header] !== undefined && o.when(h[o.header])) notes.push(o.note);

  // ---- Score and grade
  const byCheck = new Map();
  for (const x of findings) byCheck.set(x.check, (byCheck.get(x.check) ?? 0) + x.points);
  let lost = 0;
  for (const [check, pts] of byCheck) lost += Math.min(WEIGHTS[check], pts);
  const score = Math.max(0, 100 - lost);
  const serious = findings.some((x) => x.priority !== "later");
  let grade = score >= 97 && !serious ? "A+" : score >= 85 ? "A" : score >= 70 ? "B" : score >= 50 ? "C" : score >= 30 ? "D" : "F";
  // "Fix first" means a gap a stranger can use today: no A while one is open.
  if ((grade === "A+" || grade === "A") && findings.some((x) => x.priority === "first")) grade = "B";
  if (!https && !local) grade = "F";
  if (reflected && ["A+", "A", "B", "C"].includes(grade)) grade = "D";

  const order = { first: 0, next: 1, later: 2 };
  findings.sort((a, b) => order[a.priority] - order[b.priority] || b.points - a.points);
  return { url: f.finalUrl, host, status: f.status, html, local, challenge: !!challenge, grade, score, findings, passed, notes };
}

/** True when `grade` is at least `min` (A+ is the best, F the worst). */
export function meets(grade, min) {
  return GRADES.indexOf(grade) <= GRADES.indexOf(min);
}

/** The headers to add, one line per header, in the order of the findings. Later findings on the same header are dropped. */
export function headersToSet(report, stack) {
  const lines = [];
  const seen = new Set();
  for (const f of report.findings) {
    const set = f.starterCsp ? [{ name: "Content-Security-Policy-Report-Only", value: starterCsp(stack) }] : (f.set ?? []);
    for (const s of set) {
      const key = s.name.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      lines.push(s);
    }
  }
  return lines;
}
