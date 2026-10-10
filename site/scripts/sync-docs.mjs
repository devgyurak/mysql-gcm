// Copies the repository's own Markdown into the site at build time, so every page has one
// source: README.md, docs/ and spec/ stay canonical and nothing here is edited by hand.
// The generated files are gitignored. What this does to each file:
//   - front matter from its first H1, which is then dropped (Starlight renders the title);
//   - the README's banner, link row and badges (the HTML before "# mysql-gcm") removed;
//   - repository links rewritten: a page the site carries -> its route under the base path,
//     an asset -> public/, anything else -> the file on GitHub.
import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SITE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const REPO = path.resolve(SITE, "..");
const BASE = (process.env.SITE_BASE ?? "/").replace(/\/$/, "");
const GITHUB = "https://github.com/devgyurak/mysql-gcm/blob/main";

// Repository file -> site route. The page list, in one place.
const PAGES = {
  "README.md": { route: "/overview/", out: "overview.md", title: "Overview" },
  "README-KO.md": { route: "/ko/overview/", out: "ko/overview.md", title: "개요" },
  "docs/ops-constraints.md": { route: "/ops-constraints/", out: "ops-constraints.md" },
  "spec/envelope.md": { route: "/envelope/", out: "envelope.md" },
  "docs/design.md": { route: "/design/", out: "design.md" },
  "docs/design-KO.md": { route: "/ko/design/", out: "ko/design.md" },
  "docs/perf.md": { route: "/performance/", out: "performance.md" },
  "CHANGELOG.md": { route: "/changelog/", out: "changelog.md" },
};
const ASSETS = "docs/assets";
const CONTENT = path.join(SITE, "src/content/docs");

function rewriteTarget(target, fromFile) {
  if (/^([a-z]+:|#|mailto:)/i.test(target)) return target;
  const [file, hash] = target.split("#");
  const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(fromFile), file));
  const anchor = hash ? `#${hash}` : "";
  if (PAGES[resolved]) {
    // A Korean page keeps the reader in the Korean site: every route has a /ko/ counterpart,
    // translated or shown in English with Starlight's fallback notice.
    const route = PAGES[resolved].route;
    const korean = fromFile.endsWith("-KO.md") && !route.startsWith("/ko/");
    return `${BASE}${korean ? `/ko${route}` : route}${anchor}`;
  }
  if (resolved.startsWith(`${ASSETS}/`)) return `${BASE}/${resolved.slice("docs/".length)}`;
  return `${GITHUB}/${resolved}${anchor}`;
}

function transform(text, fromFile, titleOverride) {
  let body = text.replace(/\r\n/g, "\n");
  if (fromFile.startsWith("README")) body = body.slice(body.indexOf("\n# ") + 1);
  const h1 = body.match(/^# (.+)$/m);
  const title = titleOverride ?? (h1 ? h1[1].replace(/`/g, "").trim() : path.basename(fromFile, ".md"));
  if (h1) body = body.replace(h1[0], "");
  // Markdown links and images: [text](target) — not inside code fences.
  const parts = body.split(/(^```[\s\S]*?^```)/m);
  body = parts
    .map((part, i) =>
      i % 2 === 1
        ? part
        : part
            .replace(/\]\(([^)\s]+)\)/g, (_, t) => `](${rewriteTarget(t, fromFile)})`)
            .replace(/\b(src|srcset|href)="([^"]+)"/g, (_, a, t) => `${a}="${rewriteTarget(t, fromFile)}"`),
    )
    .join("");
  const front = `---\ntitle: ${JSON.stringify(title)}\neditUrl: ${JSON.stringify(`https://github.com/devgyurak/mysql-gcm/edit/develop/${fromFile}`)}\n---\n`;
  return front + body.replace(/^\n+/, "\n");
}

for (const [from, { out, title }] of Object.entries(PAGES)) {
  const dest = path.join(CONTENT, out);
  await mkdir(path.dirname(dest), { recursive: true });
  await writeFile(dest, transform(await readFile(path.join(REPO, from), "utf8"), from, title));
}
await rm(path.join(SITE, "public/assets"), { recursive: true, force: true });
await cp(path.join(REPO, ASSETS), path.join(SITE, "public/assets"), { recursive: true });
console.log(`synced ${Object.keys(PAGES).length} pages and ${ASSETS}/ (base ${BASE || "/"})`);
