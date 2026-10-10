// Fails the build if any page in dist/ links to a page or file of this site that does not exist.
// Absolute links under the base and relative links are both resolved against the page that holds
// them, so a missed rewrite in sync-docs.mjs, or a relative link that only works under one base,
// shows up here rather than as a 404 on the published site. External links are not fetched.
import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const DIST = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../dist");
const BASE = (process.env.SITE_BASE ?? "/mysql-gcm").replace(/\/$/, "");
const ORIGIN = "https://site.invalid";

async function* html(dir) {
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) yield* html(full);
    else if (entry.name.endsWith(".html")) yield full;
  }
}

async function exists(pathname) {
  if (!pathname.startsWith(`${BASE}/`) && pathname !== `${BASE}/`) return false;
  const rel = decodeURIComponent(pathname.slice(BASE.length)).replace(/^\//, "");
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
  const rel = path.relative(DIST, file).split(path.sep).join("/");
  const pageDir = rel.endsWith("index.html") ? rel.slice(0, -"index.html".length) : rel;
  const pageUrl = new URL(`${BASE}/${pageDir}`, ORIGIN);
  const text = await readFile(file, "utf8");
  for (const [, raw] of text.matchAll(/(?:href|src|srcset)="([^"]+)"/g)) {
    const target = raw.split(/\s+/)[0];
    if (/^(#|mailto:|data:|javascript:)/.test(target)) continue;
    const url = new URL(target, pageUrl);
    if (url.origin !== ORIGIN) continue;
    if (url.pathname.startsWith(`${BASE}/_astro/`) || url.pathname.startsWith(`${BASE}/pagefind/`)) {
      continue;
    }
    checked++;
    if (!(await exists(url.pathname))) broken.push(`${rel}: ${target}`);
  }
}
for (const b of broken) console.error(`broken link ${b}`);
console.log(`checked ${checked} internal links under base "${BASE || "/"}", ${broken.length} broken`);
process.exit(broken.length ? 1 : 0);
