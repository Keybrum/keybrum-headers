// The report as terminal text and as Markdown (for a pull request comment or a CI job summary).

import { headersToSet } from "./analyze.js";
import { STACKS, fixFor } from "./fixes.js";

const GROUPS = [
  ["first", "Fix first"],
  ["next", "Fix next"],
  ["later", "Later"],
];

const MORE = "Headers act in the browser. They say nothing about what your database, storage or API hand to a stranger. Free check of the live app: https://keybrum.com/check";

function wrap(text, width, indent) {
  const out = [];
  let line = "";
  for (const word of text.split(/\s+/)) {
    if (line && line.length + word.length + 1 > width) {
      out.push(line);
      line = word;
    } else line = line ? `${line} ${word}` : word;
  }
  if (line) out.push(line);
  return out.map((l) => indent + l).join("\n");
}

/**
 * @param {ReturnType<import("./analyze.js").analyze>} report
 * @param {{color?: boolean, stack?: string, verbose?: boolean, width?: number}} [options]
 */
export function toText(report, { color = false, stack, verbose = false, width = 96 } = {}) {
  const paint = (code) => (s) => (color ? `\x1b[${code}m${s}\x1b[0m` : s);
  const bold = paint(1);
  const dim = paint(2);
  const red = paint(31);
  const green = paint(32);
  const yellow = paint(33);
  const tone = report.grade.startsWith("A") ? green : report.grade === "B" || report.grade === "C" ? yellow : red;
  const w = Math.max(40, width - 6);
  const lines = [];

  lines.push("", `  ${bold(report.url)}`, `  Grade ${tone(bold(report.grade))}   score ${report.score}/100   HTTP ${report.status}`, "");

  for (const [priority, label] of GROUPS) {
    const list = report.findings.filter((f) => f.priority === priority);
    if (!list.length) continue;
    lines.push(`  ${bold(label)}`);
    for (const f of list) {
      lines.push(`    ${(priority === "later" ? yellow : red)("x")} ${f.title} ${dim(`(-${f.points})`)}`);
      lines.push(dim(wrap(f.why, w, "      ")));
      if (f.detail) lines.push(dim(wrap(f.detail, w, "      ")));
      if (verbose && f.seen) lines.push(dim(wrap(`Sent: ${f.seen}`, w, "      ")));
      if (verbose && f.note) lines.push(dim(wrap(f.note, w, "      ")));
    }
    lines.push("");
  }

  if (report.passed.length) {
    lines.push(`  ${bold("In place")}`);
    for (const p of report.passed) {
      lines.push(`    ${green("+")} ${p.title}`);
      if (verbose && p.seen) lines.push(dim(wrap(`Sent: ${p.seen}`, w, "      ")));
    }
    lines.push("");
  }

  if (report.notes.length) {
    lines.push(`  ${bold("Notes")}`);
    for (const n of report.notes) lines.push(wrap(n, w, "    - ").replace(/\n {4}- /g, "\n      "));
    lines.push("");
  }

  if (stack) {
    const fix = fixFor(report, stack);
    if (fix) {
      lines.push(`  ${bold(`Fix for ${STACKS[stack]}`)}  ${dim(fix.file)}`, "");
      lines.push(fix.code.split("\n").map((l) => `    ${l}`).join("\n"), "");
      for (const n of fix.notes) lines.push(dim(wrap(n, w, "    - ").replace(/\n {4}- /g, "\n      ")));
      if (fix.notes.length) lines.push("");
    }
  } else {
    const set = headersToSet(report);
    if (set.length) {
      lines.push(`  ${bold("Headers to add")}  ${dim(`(--fix ${Object.keys(STACKS).join("|")} prints the config)`)}`);
      for (const s of set) lines.push(`    ${s.name}: ${s.value}`);
      lines.push("");
    }
  }

  lines.push(dim(wrap(MORE, w, "  ")), "");
  return lines.join("\n");
}

const cell = (s) => String(s).replace(/\|/g, "\\|").replace(/\n/g, " ");

/** @param {ReturnType<import("./analyze.js").analyze>} report */
export function toMarkdown(report, { stack } = {}) {
  const out = [`## Security headers: grade ${report.grade} (${report.score}/100)`, "", `\`${report.url}\`, HTTP ${report.status}`, ""];
  if (report.findings.length) {
    out.push("| Priority | Finding | Why it matters | Points |", "|---|---|---|---|");
    const label = { first: "Fix first", next: "Fix next", later: "Later" };
    for (const f of report.findings) out.push(`| ${label[f.priority]} | ${cell(f.title)} | ${cell(f.why)} | -${f.points} |`);
    out.push("");
  }
  if (report.passed.length) out.push("**In place:** " + report.passed.map((p) => p.title).join("; ") + ".", "");
  for (const n of report.notes) out.push(`> ${n}`, "");
  const fix = stack ? fixFor(report, stack) : null;
  const set = headersToSet(report, stack);
  if (fix) {
    out.push(`### Fix for ${STACKS[stack]}`, "", `\`${fix.file}\``, "", "```", fix.code, "```", "");
    for (const n of fix.notes) out.push(`- ${n}`);
    if (fix.notes.length) out.push("");
  } else if (set.length) {
    out.push("### Headers to add", "", "```", ...set.map((s) => `${s.name}: ${s.value}`), "```", "");
  }
  out.push(`<sub>${MORE.replace("https://keybrum.com/check", "[keybrum.com/check](https://keybrum.com/check)")}</sub>`, "");
  return out.join("\n");
}

/** The report without presentation fields, for --json. */
export function toJson(report, { stack } = {}) {
  const strip = ({ starterCsp, ...f }) => f;
  return {
    url: report.url,
    status: report.status,
    grade: report.grade,
    score: report.score,
    findings: report.findings.map(strip),
    passed: report.passed,
    notes: report.notes,
    headersToSet: headersToSet(report, stack),
    ...(stack ? { fix: fixFor(report, stack) } : {}),
  };
}
