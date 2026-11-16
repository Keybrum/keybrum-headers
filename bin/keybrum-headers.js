#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { GRADES, analyze, meets } from "../src/analyze.js";
import { fetchHeaders } from "../src/fetch.js";
import { STACKS } from "../src/fixes.js";
import { toJson, toMarkdown, toText } from "../src/report.js";

const HELP = `keybrum-headers: grade the HTTP security headers of a web address, A+ to F.

Usage
  keybrum-headers <address> [options]

  The address can be public (your-app.com), a staging address behind your VPN,
  or local (localhost:3000). Three ordinary GET requests are sent, nothing else.

Options
  --fix <stack>      Print the config that adds the missing headers.
                     Stacks: ${Object.keys(STACKS).join(", ")}
  --min-grade <g>    Exit with code 1 when the grade is below <g> (${GRADES.slice(0, -1).join(", ")}). For CI.
  --json             Print the report as JSON.
  --markdown         Print the report as Markdown.
  --verbose          Show the header values that were sent and the note for each fix.
  --timeout <ms>     Time allowed per request. Default: 10000.
  --no-color         No colors (also off when NO_COLOR is set or the output is not a terminal).
  -h, --help         Show this help.
  -v, --version      Show the version.

Exit codes
  0  the check ran (and the grade is at least --min-grade, when given)
  1  the grade is below --min-grade
  2  wrong usage, or the address could not be loaded

Examples
  keybrum-headers your-app.com
  keybrum-headers localhost:3000 --fix nextjs
  keybrum-headers https://staging.your-app.com --min-grade B
`;

function fail(message) {
  process.stderr.write(`keybrum-headers: ${message}\n`);
  process.exit(2);
}

function parse(argv) {
  const opts = { color: process.stdout.isTTY && !process.env.NO_COLOR, timeoutMs: 10_000 };
  const rest = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const value = () => {
      const eq = a.indexOf("=");
      const v = eq !== -1 ? a.slice(eq + 1) : argv[++i];
      if (v === undefined || v === "") fail(`${a.split("=")[0]} needs a value. See --help.`);
      return v;
    };
    const flag = a.split("=")[0];
    if (flag === "-h" || flag === "--help") opts.help = true;
    else if (flag === "-v" || flag === "--version") opts.version = true;
    else if (flag === "--json") opts.format = "json";
    else if (flag === "--markdown") opts.format = "markdown";
    else if (flag === "--verbose") opts.verbose = true;
    else if (flag === "--no-color") opts.color = false;
    else if (flag === "--fix") opts.stack = value().toLowerCase();
    else if (flag === "--min-grade") opts.minGrade = value().toUpperCase();
    else if (flag === "--timeout") opts.timeoutMs = Number(value());
    else if (a.startsWith("-")) fail(`unknown option ${a}. See --help.`);
    else rest.push(a);
  }
  return { opts, rest };
}

const { opts, rest } = parse(process.argv.slice(2));

if (opts.version) {
  const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  process.stdout.write(`${pkg.version}\n`);
  process.exit(0);
}
if (opts.help || !rest.length) {
  process.stdout.write(HELP);
  process.exit(opts.help ? 0 : 2);
}
if (rest.length > 1) fail("one address at a time.");
if (opts.stack && !(opts.stack in STACKS)) fail(`unknown stack "${opts.stack}". Use one of: ${Object.keys(STACKS).join(", ")}.`);
if (opts.minGrade && (!GRADES.includes(opts.minGrade) || opts.minGrade === "F")) fail(`--min-grade takes one of: ${GRADES.slice(0, -1).join(", ")}.`);
if (!Number.isFinite(opts.timeoutMs) || opts.timeoutMs <= 0) fail("--timeout takes a number of milliseconds.");

let report;
try {
  report = analyze(await fetchHeaders(rest[0], { timeoutMs: opts.timeoutMs }));
} catch (err) {
  fail(err instanceof Error ? err.message : String(err));
}

if (opts.format === "json") process.stdout.write(`${JSON.stringify(toJson(report, opts), null, 2)}\n`);
else if (opts.format === "markdown") process.stdout.write(toMarkdown(report, opts));
else process.stdout.write(toText(report, { ...opts, width: process.stdout.columns ?? 96 }));

if (opts.minGrade && !meets(report.grade, opts.minGrade)) {
  process.stderr.write(`keybrum-headers: grade ${report.grade} is below the minimum ${opts.minGrade}.\n`);
  process.exit(1);
}
