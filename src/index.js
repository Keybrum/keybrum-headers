// Library entry: the same check as the CLI, for a script or a test.
//
//   import { check } from "keybrum-headers";
//   const report = await check("https://your-app.com");
//   if (report.grade === "F") throw new Error("Security headers regressed");

import { analyze } from "./analyze.js";
import { fetchHeaders } from "./fetch.js";

export { GRADES, WEIGHTS, RECOMMENDED, analyze, headersToSet, meets, starterCsp } from "./analyze.js";
export { fetchHeaders } from "./fetch.js";
export { STACKS, fixFor } from "./fixes.js";
export { toJson, toMarkdown, toText } from "./report.js";

/**
 * Fetches an address and grades its security headers.
 * @param {string} address
 * @param {{timeoutMs?: number}} [options]
 */
export async function check(address, options) {
  return analyze(await fetchHeaders(address, options));
}
