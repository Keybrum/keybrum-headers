# keybrum-headers

Grade the HTTP security headers of a web address from A+ to F, from your terminal or your CI. It works on `localhost`, on a staging address behind your VPN and on the published app, and it prints the config that adds what is missing for Next.js, Vercel, Netlify, Cloudflare Pages or nginx.

No dependency, no account, no API key. It sends three ordinary GET requests to the address you give it and nothing anywhere else.

It applies the same rules as the [security headers checker on keybrum.com](https://keybrum.com/tools/security-headers-checker), so the terminal and the web page give the same grade. The web version only reaches public addresses. This one reaches whatever your machine reaches.

## Run it

Node 20 or later.

```bash
npx github:tlouvart/keybrum-headers your-app.com
npx github:tlouvart/keybrum-headers localhost:3000 --fix nextjs
```

Or install it once:

```bash
npm install -g github:tlouvart/keybrum-headers
keybrum-headers your-app.com
```

## What you get

A Next.js app on `localhost:3000`, before anyone set a header:

```text
  http://localhost:3000/
  Grade D   score 33/100   HTTP 200

  Fix first
    x No Content-Security-Policy (-25)
      It is the browser's last line of defense against cross-site scripting: without it, a
      script an attacker slips into a page can read everything the visitor sees and act as them.
    x Any site can put this page in a frame (-15)
      Another site can load the page in an invisible frame and trick a signed-in visitor into
      clicking its buttons (clickjacking).
    x The session cookie is missing HttpOnly, SameSite=Lax (-11)
      It looks like a session cookie: whoever reads or replays it is signed in as the visitor.
      No HttpOnly, so any script on the page can read it; no SameSite, so some browsers send it
      with requests from other sites.

  Fix next
    x No X-Content-Type-Options: nosniff (-5)
      Without it, a browser may run an uploaded file or a text response as a script or a page if
      its content looks like one.

  Later
    x No Referrer-Policy (-3)
    x No Permissions-Policy (-3)
    x X-Powered-By says Next.js (-3)
    x No Cross-Origin-Opener-Policy (-2)

  In place
    + Other sites cannot read it with the visitor's cookies

  Notes
    - Local address over http://: HTTPS, the HTTP redirect, Strict-Transport-Security and the
      Secure cookie flag were left out of the grade. Check them on the published address.
```

(The "Later" findings are shortened here. The tool prints the reason under each one.)

## Print the fix for your stack

`--fix` turns the missing headers into the file your host reads:

```bash
keybrum-headers localhost:3000 --fix nextjs
```

```ts
// next.config.ts
import type { NextConfig } from 'next'

const securityHeaders = [
  { key: 'Content-Security-Policy-Report-Only', value: "default-src 'self'; script-src 'self' 'unsafe-inline'; ..." },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=(), browsing-topics=()' },
  { key: 'Cross-Origin-Opener-Policy', value: 'same-origin-allow-popups' },
]

const nextConfig: NextConfig = {
  poweredByHeader: false,
  async headers() {
    return [{ source: '/:path*', headers: securityHeaders }]
  },
}

export default nextConfig
```

| `--fix` | File it writes for |
|---|---|
| `nextjs` | `next.config.ts` |
| `vercel` | `vercel.json` |
| `netlify` | `_headers` |
| `cloudflare` | `_headers` for Cloudflare Pages |
| `nginx` | `add_header` lines for the server block |

A new Content-Security-Policy always starts as `Content-Security-Policy-Report-Only`. It blocks nothing and the browser reports what it would block. Add the hosts your app really calls, then rename the header. The reasoning, with a policy for Supabase, Stripe and analytics, is in the [security headers guide](https://keybrum.com/guides/security-headers).

## What it checks

| Check | What it looks at | Most it can cost |
|---|---|---|
| HTTPS | The page is served over HTTPS | 60, and the grade is F |
| CORS | The server does not copy any `Origin` back with credentials allowed | 40, and the grade is D at best |
| Content-Security-Policy | A policy exists, limits scripts, and does not allow `'unsafe-inline'`, `'unsafe-eval'` or any site | 25 |
| Strict-Transport-Security | Present, at least one year, subdomains covered | 20 |
| Framing | `frame-ancestors` or `X-Frame-Options` stops other sites from framing the page | 15 |
| HTTP redirect | `http://` redirects to `https://` | 15 |
| Cookies | Session cookies carry `HttpOnly`, `Secure` and `SameSite` | 15 |
| X-Content-Type-Options | `nosniff` | 5 |
| Referrer-Policy | Other sites get at most your domain | 5 |
| Version leaks | `Server` with a version, `X-Powered-By`, `X-AspNet-Version` | 6 |
| Permissions-Policy | Camera, microphone and location are switched off unless used | 3 |
| Cross-Origin-Opener-Policy | Other windows keep no handle on yours | 2 |

A few rules that differ from older scanners:

- `frame-ancestors` wins over `X-Frame-Options` when both are set, as in browsers.
- `'unsafe-inline'` does not count when the policy has a nonce or a hash, because browsers ignore it then.
- `X-XSS-Protection`, `Expect-CT`, `Public-Key-Pins` and `Feature-Policy` are obsolete. They are never asked for. If you send one, a note tells you to remove it.
- Supabase's SSR auth cookie and CSRF token cookies are not asked for `HttpOnly`: your own script reads them on purpose.
- Analytics cookies and cookies being cleared are not graded.
- An address that answers with JSON skips the checks that only mean something for a page.

## The grade

The score starts at 100 and each finding takes points off, up to the limit of its check. A+ needs 97 and nothing left to fix but "Later" items. A starts at 85, B at 70, C at 50, D at 30.

Two rules sit on top of the score. No A while a "Fix first" finding is open, because that label means a gap a stranger can use today. No HTTPS is always an F.

## In CI

### GitHub Action

```yaml
- uses: tlouvart/keybrum-headers@v1
  with:
    url: ${{ steps.deploy.outputs.preview-url }}
    min-grade: B
    fix: nextjs
```

The report goes to the job log and to the job summary. The job fails when the grade is below `min-grade`. Leave `min-grade` out to report without failing.

| Input | |
|---|---|
| `url` | The address to check. Required. |
| `min-grade` | `A+`, `A`, `B`, `C` or `D`. Optional. |
| `fix` | `nextjs`, `vercel`, `netlify`, `cloudflare` or `nginx`. Adds the config to the report. Optional. |
| `timeout` | Milliseconds per request. Default `10000`. |

Outputs: `grade` and `score`.

### Any other CI

```bash
npx github:tlouvart/keybrum-headers https://staging.your-app.com --min-grade B
```

Exit code 0 when the grade is at least `--min-grade`, 1 when it is below, 2 when the address could not be loaded.

`--json` prints the report as JSON and `--markdown` as Markdown, for a pull request comment.

## As a library

```js
import { check } from "keybrum-headers";

const report = await check("https://your-app.com");
console.log(report.grade, report.score);
for (const f of report.findings) console.log(f.priority, f.title);
```

## The requests it sends

1. One GET of the address, redirects followed. Only the first 64 KB of the page are read, to find a policy set in a `<meta>` tag.
2. One GET of the `http://` version, to see where it leads.
3. One GET with an `Origin` header from a domain that does not exist, to see whether CORS copies it back.

Cookie values never appear in the report: only the name and the flags.

Run it on your own apps. It is as gentle as opening the page in a browser, but a report about someone else's site is theirs to ask for.

## What headers do not tell you

Headers are instructions to a browser. A stranger who calls your API with curl never reads them. A page can get an A+ here while a table has row level security off, a secret key sits in the JavaScript bundle or an API route answers without a session.

That part needs a look at the app itself. [Keybrum's free check](https://keybrum.com/check) reads what any visitor's browser already downloads from your app (the backend it talks to, the keys in the bundle, the tables it names) in about ten seconds, with no account. The paid attack run then tries what a stranger would try and shows the request that worked for each finding.

The small free tools next to it run in the browser: a [Supabase RLS checker](https://keybrum.com/tools/supabase-rls-checker), an [API key leak checker](https://keybrum.com/tools/api-key-leak-checker), a [Next.js CVE checker](https://keybrum.com/tools/nextjs-cve-checker) and [the others](https://keybrum.com/tools).

This tool is complete without any of them.

## Development

```bash
npm test
```

The tests use Node's own test runner and a local server. There is nothing to install.

## Licence

MIT. Built by [Keybrum](https://keybrum.com).
