#!/usr/bin/env node
// The GitHub Action entry: reads its inputs from the environment, prints the report in the job
// log, writes it to the job summary, sets the grade and score outputs, and fails below min-grade.
import { appendFileSync } from "node:fs";
import { GRADES, analyze, meets } from "../src/analyze.js";
import { fetchHeaders } from "../src/fetch.js";
import { STACKS } from "../src/fixes.js";
import { toMarkdown, toText } from "../src/report.js";

const input = (name) => (process.env[`INPUT_${name}`] ?? "").trim();

function stop(message) {
  process.stdout.write(`::error::${message}\n`);
  process.exit(1);
}

const url = input("URL");
const minGrade = input("MIN_GRADE").toUpperCase();
const stack = input("FIX").toLowerCase() || undefined;
const timeoutMs = Number(input("TIMEOUT") || 10_000);

if (!url) stop("The url input is required.");
if (minGrade && (!GRADES.includes(minGrade) || minGrade === "F")) stop(`min-grade takes one of: ${GRADES.slice(0, -1).join(", ")}.`);
if (stack && !(stack in STACKS)) stop(`fix takes one of: ${Object.keys(STACKS).join(", ")}.`);
if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) stop("timeout takes a number of milliseconds.");

let report;
try {
  report = analyze(await fetchHeaders(url, { timeoutMs }));
} catch (err) {
  stop(err instanceof Error ? err.message : String(err));
}

process.stdout.write(toText(report, { stack, verbose: true }));
if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, toMarkdown(report, { stack }));
if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `grade=${report.grade}\nscore=${report.score}\n`);

if (minGrade && !meets(report.grade, minGrade)) stop(`Security headers grade ${report.grade} is below the minimum ${minGrade}.`);
