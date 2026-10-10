// Fails the build if any page in dist/ links to a path under the base that does not exist.
// Internal links are rewritten by sync-docs.mjs, so a missed rewrite shows up here, not as a
// 404 on the published site. External links are not fetched.
import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const DIST = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../dist");
const BASE = (process.env.SITE_BASE ?? "/mysql-gcm").replace(/\/$/, "");

async function* html(dir) {
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) yield* html(full);
    else if (entry.name.endsWith(".html")) yield full;
  }
}

async function exists(urlPath) {
  const rel = decodeURIComponent(urlPath.slice(BASE.length)).replace(/^\//, "");
  for (const candidate of [rel, path.join(rel, "index.html")]) {
    try {
      if ((await stat(path.join(DIST, candidate))).isFile()) return true;
    } catch {}
  }
  return false;
}

const broken = [];
let checked = 0;
for await (const file of html(DIST)) {
  const text = await readFile(file, "utf8");
  for (const [, url] of text.matchAll(/(?:href|src|srcset)="([^"#?]+)/g)) {
    if (!url.startsWith(`${BASE}/`) || url.startsWith(`${BASE}/_astro/`) || url.startsWith(`${BASE}/pagefind/`)) continue;
    checked++;
    if (!(await exists(url))) broken.push(`${path.relative(DIST, file)}: ${url}`);
  }
}
for (const b of broken) console.error(`broken link ${b}`);
console.log(`checked ${checked} internal links, ${broken.length} broken`);
process.exit(broken.length ? 1 : 0);
